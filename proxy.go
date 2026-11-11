package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
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

	mu     sync.RWMutex
	policy policy
}

type modeKey struct{}

func newServer(st *store, cls classifier, upstream http.RoundTripper) *server {
	s := &server{store: st, cls: cls, policy: st.policy()}
	s.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = pr.In.Host
			pr.Out.Host = pr.In.Host
			if _, ok := pr.In.Context().Value(modeKey{}).(pruneMode); ok {
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
	if path == "/__hider/onboard" {
		s.onboard(w, r)
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

	mode, rewrite := pruneNone, false
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
		mode, rewrite = pruneSearch, true
	case nav && path == "/watch":
		mode, rewrite = pruneWatch, true
	case nav:
		rewrite = true
	case path == "/sw.js":
		// YouTube's service worker could answer navigations from its own
		// cache, bypassing the proxy. Replace it with one that removes itself.
		w.Header().Set("Content-Type", "text/javascript")
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, "self.addEventListener('install',()=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil(self.registration.unregister()));")
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
		mode, rewrite = pruneSearch, true
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
	case r.Method == http.MethodPost && (path == "/youtubei/v1/next" || path == "/youtubei/v1/get_watch"):
		// The two calls that deliver watch-page data during in-page navigation.
		mode, rewrite = pruneWatch, true
	}

	if rewrite {
		r = r.WithContext(context.WithValue(r.Context(), modeKey{}, mode))
	}
	s.proxy.ServeHTTP(w, r)
}

func blockedPath(path string) bool {
	for _, p := range blockedPaths {
		if hasPathPrefix(path, p) {
			return true
		}
	}
	return false
}

// refuse answers an in-page API call that will not be served, pointing the
// injected script at the page to load instead.
func refuse(w http.ResponseWriter, to string) {
	w.Header().Set(gotoHeader, to)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	io.WriteString(w, `{"error":{"code":403,"message":"youtube-hider"}}`)
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

// gateSearch classifies a query and reports whether the search may proceed.
// When it may not, the response has been written. The proxy fails closed: a
// classifier that cannot answer blocks the search.
func (s *server) gateSearch(w http.ResponseWriter, r *http.Request, q string, api bool) bool {
	start := time.Now()
	v, err := s.cls.classify(r.Context(), s.currentPolicy(), q)
	if err == nil && v.Allow {
		log.Printf("search allowed in %s", time.Since(start).Round(time.Millisecond))
		return true
	}
	if err != nil {
		log.Printf("classifier: %v", err)
	} else {
		log.Printf("search blocked in %s", time.Since(start).Round(time.Millisecond))
	}
	if api {
		refuse(w, "/results?search_query="+url.QueryEscape(q))
		return false
	}
	data := map[string]any{"Query": q, "Reason": v.Reason}
	if err != nil {
		data["Error"] = err.Error()
		s.page(w, http.StatusServiceUnavailable, "blocked.html", data)
		return false
	}
	s.page(w, http.StatusForbidden, "blocked.html", data)
	return false
}

func (s *server) page(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := pages.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// onboard serves the form where the user writes their own policy. The first
// save is open; every later change needs the unlock password.
func (s *server) onboard(w http.ResponseWriter, r *http.Request) {
	current := s.currentPolicy()
	lk, lockErr := s.store.lock()
	locked := !current.empty() && (lk != nil || lockErr != nil)
	data := map[string]any{
		"Policy": current, "Locked": locked,
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
	next := policy{
		Allowed: strings.TrimSpace(r.PostFormValue("allowed")),
		Blocked: strings.TrimSpace(r.PostFormValue("blocked")),
	}
	data["Policy"] = next
	switch {
	case next.Allowed == "" || next.Blocked == "":
		data["Error"] = "Both descriptions are needed. The model has nothing else to go on."
	case locked && (lk == nil || !lk.verify(r.PostFormValue("password"))):
		time.Sleep(time.Second)
		data["Error"] = "Wrong password. Changing the policy needs the unlock password."
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
	s.mu.Unlock()
	go s.warm()
	http.Redirect(w, r, "https://www.youtube.com/", http.StatusSeeOther)
}

// warm loads the model into memory so the first real search is fast.
func (s *server) warm() {
	p := s.currentPolicy()
	if p.empty() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := s.cls.classify(ctx, p, "warm up"); err != nil {
		log.Printf("classifier warm-up: %v", err)
	}
}

func (s *server) modifyResponse(resp *http.Response) error {
	// HTTP/3 would be attempted against loopback, where nothing listens.
	resp.Header.Del("Alt-Svc")
	mode, ok := resp.Request.Context().Value(modeKey{}).(pruneMode)
	if !ok || resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "" {
		return nil
	}
	ct := resp.Header.Get("Content-Type")
	isHTML := strings.HasPrefix(ct, "text/html")
	isJSON := strings.HasPrefix(ct, "application/json")
	if !isHTML && !(isJSON && mode != pruneNone) {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	if isHTML {
		body = rewriteHTML(body, mode, injectCSS, injectJS)
	} else {
		body = pruneJSON(body, mode)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
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

// Suggestions offered during onboarding. They are prompts for the user's own
// writing, not a default policy: nothing is allowed or blocked until saved.
var (
	allowPills = []string{"Talks", "Lectures", "Math", "Computer science", "History of computing", "Research seminars", "Science", "Philosophy", "Programming tutorials", "Long interviews with researchers"}
	blockPills = []string{"Politics", "News", "Vlogs", "Challenge videos", "Tech reviews", "Gaming", "Celebrity gossip", "Sports highlights", "Reaction videos", "Infotainment documentaries"}
)
