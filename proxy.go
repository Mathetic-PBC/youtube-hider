package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var webFS embed.FS

var (
	pages     = template.Must(template.ParseFS(webFS, "web/*.html"))
	injectCSS = mustAsset("web/inject.css")
	injectJS  = mustAsset("web/inject.js")
)

func mustAsset(name string) []byte {
	b, err := webFS.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return b
}

// gotoHeader tells the injected script to leave YouTube's in-page navigation
// and load a URL from the proxy instead. Enforcement never depends on it:
// the request carrying it has already been refused.
const gotoHeader = "X-Hider-Goto"

const (
	// A block the model is less sure of than this can be appealed.
	appealBelow = 95
	// An appeal has to say something: this many characters, this many words.
	appealMinChars = 250
	appealMinWords = 20
)

// Feeds that exist to recommend. Navigating to them lands on the search bar.
var blockedPaths = []string{"/shorts", "/feed/trending", "/feed/subscriptions", "/feed/explore", "/feed/news_destination", "/feed/storefront", "/gaming", "/hashtag"}

var blockedBrowseIDs = map[string]bool{
	"FEwhat_to_watch": true,
	"FEsubscriptions": true,
	"FEshorts":        true,
	"FEtrending":      true,
	"FEexplore":       true,
}

type server struct {
	store *store
	cls   classifier
	proxy *httputil.ReverseProxy

	mu      sync.RWMutex
	policy  policy
	memo    map[string]judged  // verdicts by item key, for the current policy
	grants  map[string]grant   // accepted appeals by item key
	pending map[string]pending // blocks that may be appealed, by token
}

// judged is a verdict together with what was judged.
type judged struct {
	verdict
	item item
}

// grant is an accepted appeal. Grants are kept, with the text, so that what
// was let through and why can be read back later.
type grant struct {
	Key  string    `json:"key"`
	What string    `json:"what"`
	Why  string    `json:"why"`
	At   time.Time `json:"at"`
}

type pending struct {
	item item
	back string
}

// plan is what the response handler should do with an upstream response.
type plan struct {
	mode  pruneMode
	judge bool   // classify the video, channel or playlist the response carries
	back  string // in-page request: the page to load if it is blocked
	watch bool   // in-page request for a video: the page is its watch URL
}

type planKey struct{}

func newServer(st *store, cls classifier, upstream http.RoundTripper) *server {
	s := &server{
		store: st, cls: cls, policy: st.policy(),
		memo: map[string]judged{}, grants: map[string]grant{}, pending: map[string]pending{},
	}
	var saved []grant
	st.read("appeals.json", &saved)
	for _, g := range saved {
		s.grants[g.Key] = g
	}
	s.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = pr.In.Host
			pr.Out.Host = pr.In.Host
			if _, ok := pr.In.Context().Value(planKey{}).(plan); ok {
				// Let the transport negotiate gzip so the body can be rewritten.
				pr.Out.Header.Del("Accept-Encoding")
			}
		},
		Transport:      upstream,
		FlushInterval:  -1,
		ModifyResponse: s.modifyResponse,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				return // the browser gave up on the request
			}
			log.Printf("upstream %s: %v", r.URL.Path, err)
			http.Error(w, "youtube-hider: upstream unreachable", http.StatusBadGateway)
		},
	}
	return s
}

func upstreamTransport(res *resolver) *http.Transport {
	return &http.Transport{
		DialContext:           res.dial,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
}

func (s *server) currentPolicy() policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy
}

func isNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	mode := r.Header.Get("Sec-Fetch-Mode")
	// Every current browser sends Sec-Fetch-Mode; a client that omits it is
	// treated as navigating so that the gates below still apply.
	return mode == "navigate" || mode == ""
}

func hasPathPrefix(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !intercepted(host) {
		http.Error(w, "youtube-hider: not an intercepted host", http.StatusMisdirectedRequest)
		return
	}
	r.Host = host
	if host == "youtube.com" || host == "m.youtube.com" {
		http.Redirect(w, r, "https://www.youtube.com"+r.URL.RequestURI(), http.StatusTemporaryRedirect)
		return
	}
	path := r.URL.Path
	switch path {
	case "/__hider/onboard":
		s.onboard(w, r)
		return
	case "/__hider/appeal":
		s.appeal(w, r)
		return
	}
	nav := isNavigation(r)
	top := nav && r.Header.Get("Sec-Fetch-Dest") != "iframe"

	if s.currentPolicy().empty() {
		if top {
			http.Redirect(w, r, "https://www.youtube.com/__hider/onboard", http.StatusSeeOther)
		} else {
			http.Error(w, "youtube-hider: not set up yet", http.StatusForbidden)
		}
		return
	}

	var pl plan
	rewrite := false
	switch {
	case top && path == "/" && host == "www.youtube.com":
		s.page(w, http.StatusOK, "home.html", nil)
		return
	case nav && blockedPath(path):
		http.Redirect(w, r, "https://www.youtube.com/", http.StatusSeeOther)
		return
	case nav && path == "/results":
		q := r.URL.Query().Get("search_query")
		if q == "" {
			q = r.URL.Query().Get("q")
		}
		if strings.TrimSpace(q) == "" {
			http.Redirect(w, r, "https://www.youtube.com/", http.StatusSeeOther)
			return
		}
		if !s.gateSearch(w, r, q, false) {
			return
		}
		pl, rewrite = plan{mode: pruneSearch}, true
	case nav && path == "/watch":
		// A video already judged and blocked never reaches YouTube again.
		if j, ok := s.remembered("video:" + r.URL.Query().Get("v")); ok && !j.Allow {
			s.blocked(w, j.item, j.verdict, nil, r.URL.RequestURI())
			return
		}
		pl, rewrite = plan{mode: pruneWatch, judge: true}, true
	case nav:
		// Channel pages, playlists, and anything else that embeds a video.
		pl, rewrite = plan{judge: true}, true
	case path == "/sw.js":
		// YouTube's service worker could answer navigations from its own
		// cache, bypassing the proxy. Replace it with one that removes itself.
		w.Header().Set("Content-Type", "text/javascript")
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, "self.addEventListener('install',()=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil(self.registration.unregister()));")
		return
	case adPath(path):
		// Ad fetches, ad breaks and ad tracking. Answered empty, never sent.
		w.WriteHeader(http.StatusNoContent)
		return
	case path == "/complete/search":
		// Search suggestions: the box takes what is typed and proposes nothing.
		w.WriteHeader(http.StatusNoContent)
		return
	case r.Method == http.MethodPost && path == "/youtubei/v1/guide":
		// The side navigation's contents: subscriptions, feeds, "Explore".
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"items":[]}`)
		return
	case hasPathPrefix(path, "/youtubei/v1/reel"):
		refuse(w, "/")
		return
	case r.Method == http.MethodPost && path == "/youtubei/v1/search":
		var body struct {
			Query string `json:"query"`
		}
		if !peekJSON(r, &body) {
			http.Error(w, "youtube-hider: unreadable request", http.StatusBadRequest)
			return
		}
		// Requests without a query page through a search that already passed.
		if body.Query != "" && !s.gateSearch(w, r, body.Query, true) {
			return
		}
		pl, rewrite = plan{mode: pruneSearch}, true
	case r.Method == http.MethodPost && path == "/youtubei/v1/browse":
		var body struct {
			BrowseID string `json:"browseId"`
		}
		if !peekJSON(r, &body) {
			http.Error(w, "youtube-hider: unreadable request", http.StatusBadRequest)
			return
		}
		if blockedBrowseIDs[body.BrowseID] {
			refuse(w, "/")
			return
		}
		// In-page navigation to a channel or playlist.
		pl, rewrite = plan{judge: true, back: browsePage(body.BrowseID)}, true
	case r.Method == http.MethodPost && path == "/youtubei/v1/get_watch":
		// In-page navigation to a video: player data and watch-page data.
		pl, rewrite = plan{mode: pruneWatch, judge: true, watch: true}, true
	case r.Method == http.MethodPost && path == "/youtubei/v1/navigation/resolve_url":
		// Resolving a link can come back with the video's player data
		// attached, ads included.
		pl, rewrite = plan{judge: true}, true
	case r.Method == http.MethodPost && path == "/youtubei/v1/player":
		// Player data on its own: embeds, hover previews. No video plays
		// without one of these responses, so judging them covers every route.
		pl, rewrite = plan{judge: true}, true
	case r.Method == http.MethodPost && path == "/youtubei/v1/next":
		pl, rewrite = plan{mode: pruneWatch}, true
	}

	if rewrite {
		r = r.WithContext(context.WithValue(r.Context(), planKey{}, pl))
	}
	s.proxy.ServeHTTP(w, r)
}

// Paths on YouTube's own hostnames that exist only to serve or count ads.
var adPaths = []string{"/pagead", "/ptracking", "/api/stats/ads", "/get_midroll_info", "/youtubei/v1/player/ad_break"}

func adPath(path string) bool {
	for _, p := range adPaths {
		if hasPathPrefix(path, p) {
			return true
		}
	}
	return false
}

func blockedPath(path string) bool {
	for _, p := range blockedPaths {
		if hasPathPrefix(path, p) {
			return true
		}
	}
	return false
}

// browsePage maps the id of an in-page browse request to the page it stands
// for, so a blocked one can be reloaded as a page that says so.
func browsePage(id string) string {
	switch {
	case strings.HasPrefix(id, "UC"):
		return "/channel/" + id
	case strings.HasPrefix(id, "VL"):
		return "/playlist?list=" + strings.TrimPrefix(id, "VL")
	}
	return ""
}

const refusal = `{"error":{"code":403,"message":"youtube-hider"}}`

// refuse answers an in-page API call that will not be served, pointing the
// injected script at the page to load instead.
func refuse(w http.ResponseWriter, to string) {
	if to != "" {
		w.Header().Set(gotoHeader, to)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	io.WriteString(w, refusal)
}

// peekJSON decodes a request body and puts it back, untouched, for the
// upstream request. YouTube's page gzips the bodies of its API calls.
func peekJSON(r *http.Request, v any) bool {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	r.Body.Close()
	if err != nil {
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	r.ContentLength = int64(len(raw))
	plain := raw
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return false
		}
		if plain, err = io.ReadAll(io.LimitReader(zr, 16<<20)); err != nil {
			return false
		}
	}
	return json.Unmarshal(plain, v) == nil
}

// remembered returns a stored verdict for an item that has no accepted appeal.
func (s *server) remembered(key string) (judged, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.grants[key]; ok {
		return judged{}, false
	}
	j, ok := s.memo[key]
	return j, ok
}

// judge classifies an item once per policy and remembers the verdict, so
// every route to the same thing gets the same answer. An accepted appeal
// overrides the model.
func (s *server) judge(ctx context.Context, it item) (verdict, error) {
	key := it.key()
	s.mu.RLock()
	_, granted := s.grants[key]
	j, known := s.memo[key]
	s.mu.RUnlock()
	if granted {
		return verdict{Allow: true, Confidence: 100, Reason: "Let through on appeal."}, nil
	}
	if known {
		return j.verdict, nil
	}
	start := time.Now()
	v, err := s.cls.classify(ctx, s.currentPolicy(), it.subject())
	if err != nil {
		return v, err
	}
	word := "blocked"
	if v.Allow {
		word = "allowed"
	}
	log.Printf("%s %s (confidence %d) in %s", it.Kind, word, v.Confidence, time.Since(start).Round(time.Millisecond))
	s.mu.Lock()
	if len(s.memo) > 5000 {
		clear(s.memo)
	}
	s.memo[key] = judged{verdict: v, item: it}
	s.mu.Unlock()
	return v, nil
}

// gateSearch classifies a query and reports whether the search may proceed.
// When it may not, the response has been written. The proxy fails closed: a
// classifier that cannot answer blocks the search.
func (s *server) gateSearch(w http.ResponseWriter, r *http.Request, q string, api bool) bool {
	it := searchItem(q)
	v, err := s.judge(r.Context(), it)
	if err == nil && v.Allow {
		return true
	}
	if err != nil {
		log.Printf("classifier: %v", err)
	}
	back := "/results?search_query=" + queryEscape(it.Title)
	if api {
		refuse(w, back)
	} else {
		s.blocked(w, it, v, err, back)
	}
	return false
}

// blockedPage renders the page shown in place of something not approved.
// When the model was unsure, the page carries an appeal form.
func (s *server) blockedPage(it item, v verdict, err error, back string, form map[string]any) (int, []byte) {
	data := map[string]any{
		"Kind": it.Kind, "Title": it.Title, "Channel": it.Channel,
		"Reason": v.Reason, "Confidence": v.Confidence, "MinChars": appealMinChars,
	}
	status := http.StatusForbidden
	switch {
	case err != nil:
		status = http.StatusServiceUnavailable
		data["Error"] = err.Error()
	case form != nil:
		// Re-rendering a submitted appeal: keep its token.
	case v.Confidence < appealBelow:
		data["Token"] = s.offerAppeal(it, back)
	}
	for k, val := range form {
		data[k] = val
	}
	body, _ := renderPage("blocked.html", data)
	return status, body
}

func (s *server) blocked(w http.ResponseWriter, it item, v verdict, err error, back string) {
	status, body := s.blockedPage(it, v, err, back, nil)
	setPageHeaders(w.Header())
	w.WriteHeader(status)
	w.Write(body)
}

func (s *server) offerAppeal(it item, back string) string {
	var b [16]byte
	rand.Read(b[:])
	token := hex.EncodeToString(b[:])
	s.mu.Lock()
	if len(s.pending) > 500 {
		clear(s.pending)
	}
	s.pending[token] = pending{item: it, back: back}
	s.mu.Unlock()
	return token
}

// appeal accepts a written case for something the model blocked without
// being sure. The friction is the point: the text has to be long enough to
// have been thought about, and it is kept.
func (s *server) appeal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Header.Get("Sec-Fetch-Site") != "same-origin" {
		http.Error(w, "youtube-hider: appeals come from the blocked page", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	token := r.PostFormValue("token")
	why := strings.TrimSpace(r.PostFormValue("why"))
	s.mu.RLock()
	p, ok := s.pending[token]
	j, judgedBefore := s.memo[p.item.key()]
	s.mu.RUnlock()
	if !ok || !judgedBefore || j.Allow || j.Confidence >= appealBelow {
		http.Redirect(w, r, "https://www.youtube.com/", http.StatusSeeOther)
		return
	}
	if problem := appealProblem(why); problem != "" {
		status, body := s.blockedPage(p.item, j.verdict, nil, p.back, map[string]any{"Token": token, "Why": why, "AppealError": problem})
		setPageHeaders(w.Header())
		w.WriteHeader(status)
		w.Write(body)
		return
	}
	g := grant{Key: p.item.key(), What: p.item.label(), Why: why, At: time.Now()}
	s.mu.Lock()
	s.grants[g.Key] = g
	delete(s.pending, token)
	all := make([]grant, 0, len(s.grants))
	for _, each := range s.grants {
		all = append(all, each)
	}
	s.mu.Unlock()
	if err := s.store.write("appeals.json", all); err != nil {
		log.Printf("appeals: %v", err)
	}
	log.Printf("%s let through on appeal", p.item.Kind)
	http.Redirect(w, r, "https://www.youtube.com"+p.back, http.StatusSeeOther)
}

func appealProblem(why string) string {
	if n := len([]rune(why)); n < appealMinChars {
		return "That is " + strconv.Itoa(n) + " characters. An appeal needs at least " + strconv.Itoa(appealMinChars) + "."
	}
	words := map[string]bool{}
	for _, w := range strings.Fields(strings.ToLower(why)) {
		words[w] = true
	}
	if len(words) < appealMinWords {
		return "Say why you want this and what you are looking for, in your own words."
	}
	return ""
}

func renderPage(name string, data any) ([]byte, error) {
	var buf bytes.Buffer
	err := pages.ExecuteTemplate(&buf, name, data)
	return buf.Bytes(), err
}

func setPageHeaders(h http.Header) {
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
}

func (s *server) page(w http.ResponseWriter, status int, name string, data any) {
	body, err := renderPage(name, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	setPageHeaders(w.Header())
	w.WriteHeader(status)
	w.Write(body)
}

// onboard serves the policy page. The first save writes both descriptions.
// After that, adding to either one is open, and rewriting or removing
// anything needs the unlock password.
func (s *server) onboard(w http.ResponseWriter, r *http.Request) {
	current := s.currentPolicy()
	lk, lockErr := s.store.lock()
	locked := lk != nil || lockErr != nil
	data := map[string]any{
		"Policy": current, "Rewrite": current, "Exists": !current.empty(), "Locked": locked,
		"AllowPills": allowPills, "BlockPills": blockPills,
	}
	if r.Method != http.MethodPost {
		s.page(w, http.StatusOK, "onboard.html", data)
		return
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "same-origin" {
		http.Error(w, "youtube-hider: cross-site request refused", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	field := func(name string) string { return strings.TrimSpace(r.PostFormValue(name)) }

	next := current
	if !current.empty() && r.PostFormValue("action") != "rewrite" {
		// Adding only ever appends; nothing already written can be lost.
		addAllowed, addBlocked := field("add_allowed"), field("add_blocked")
		if addAllowed == "" && addBlocked == "" {
			data["Error"] = "Nothing to add."
		}
		next.Allowed = appendLine(current.Allowed, addAllowed)
		next.Blocked = appendLine(current.Blocked, addBlocked)
	} else {
		next = policy{Allowed: field("allowed"), Blocked: field("blocked")}
		data["Rewrite"], data["Rewriting"] = next, true
		switch {
		case next.Allowed == "" || next.Blocked == "":
			data["Error"] = "Both descriptions are needed. The model has nothing else to go on."
		case !current.empty() && locked && (lk == nil || !lk.verify(r.PostFormValue("password"))):
			time.Sleep(time.Second)
			data["Error"] = "Wrong password. Rewriting or removing needs the unlock password."
		}
	}
	if data["Error"] != nil {
		s.page(w, http.StatusBadRequest, "onboard.html", data)
		return
	}
	if err := s.store.write("policy.json", next); err != nil {
		data["Error"] = "Could not save: " + err.Error()
		s.page(w, http.StatusInternalServerError, "onboard.html", data)
		return
	}
	s.mu.Lock()
	s.policy = next
	clear(s.memo)
	s.mu.Unlock()
	go s.warm()
	http.Redirect(w, r, "https://www.youtube.com/", http.StatusSeeOther)
}

func appendLine(text, add string) string {
	if add == "" {
		return text
	}
	return strings.TrimSpace(text + "\n" + add)
}

// warm loads the model into memory so the first real search is fast.
func (s *server) warm() {
	p := s.currentPolicy()
	if p.empty() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := s.cls.classify(ctx, p, searchItem("warm up").subject()); err != nil {
		log.Printf("classifier warm-up: %v", err)
	}
}

func (s *server) modifyResponse(resp *http.Response) error {
	// HTTP/3 would be attempted against loopback, where nothing listens.
	resp.Header.Del("Alt-Svc")
	pl, ok := resp.Request.Context().Value(planKey{}).(plan)
	if !ok || resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "" {
		return nil
	}
	ct := resp.Header.Get("Content-Type")
	isHTML := strings.HasPrefix(ct, "text/html")
	if !isHTML && !strings.HasPrefix(ct, "application/json") {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	setBody := func(b []byte) {
		resp.Body = io.NopCloser(bytes.NewReader(b))
		resp.ContentLength = int64(len(b))
		resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
	}

	if pl.judge {
		it, found, err := findItem(body, isHTML)
		var v verdict
		if err == nil && found {
			v, err = s.judge(resp.Request.Context(), it)
		}
		if err != nil || (found && !v.Allow) {
			// Fail closed: something that cannot be judged is not shown.
			if err != nil {
				log.Printf("check: %v", err)
			}
			resp.Header = http.Header{}
			if isHTML {
				status, page := s.blockedPage(it, v, err, resp.Request.URL.RequestURI(), nil)
				resp.StatusCode, resp.Status = status, http.StatusText(status)
				setPageHeaders(resp.Header)
				setBody(page)
				return nil
			}
			back := pl.back
			if pl.watch && it.ID != "" {
				back = "/watch?v=" + queryEscape(it.ID)
			}
			resp.StatusCode, resp.Status = http.StatusForbidden, http.StatusText(http.StatusForbidden)
			resp.Header.Set("Content-Type", "application/json")
			if back != "" {
				resp.Header.Set(gotoHeader, back)
			}
			setBody([]byte(refusal))
			return nil
		}
	}

	if isHTML {
		body = rewriteHTML(body, pl.mode, injectCSS, injectJS)
	} else {
		body = pruneJSON(body, pl.mode)
	}
	setBody(body)
	return nil
}

func (s *server) listenAndServe(addrs []string, ca *authority) error {
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 15 * time.Second,
		TLSConfig:         &tls.Config{GetCertificate: ca.getCertificate, MinVersion: tls.VersionTLS12},
	}
	errc := make(chan error, len(addrs))
	for _, addr := range addrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		go func() { errc <- srv.ServeTLS(ln, "", "") }()
	}
	return <-errc
}

// Suggestions offered on the policy page. They are prompts for the user's
// own writing, not a default policy: nothing is allowed or blocked until saved.
var (
	allowPills = []string{"Talks", "Lectures", "Math", "Computer science", "History of computing", "Research seminars", "Science", "Philosophy", "Programming tutorials", "Long interviews with researchers"}
	blockPills = []string{"Politics", "News", "Vlogs", "Challenge videos", "Tech reviews", "Gaming", "Celebrity gossip", "Sports highlights", "Reaction videos", "Infotainment documentaries"}
)
