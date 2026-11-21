package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeClassifier blocks anything mentioning "junk" (unsure, so appealable)
// or "banned" (certain), and fails on "broken".
type fakeClassifier struct{}

func (fakeClassifier) classify(_ context.Context, _ policy, subject string) (verdict, error) {
	switch {
	case strings.Contains(subject, "broken"):
		return verdict{}, errors.New("model offline")
	case strings.Contains(subject, "banned"):
		return verdict{Reason: "named", Confidence: 100}, nil
	case strings.Contains(subject, "junk"):
		return verdict{Reason: "resembles junk", Confidence: 80}, nil
	}
	return verdict{Allow: true, Confidence: 95}, nil
}

const plainPage = `<html><head><script nonce="N0nce">var ytInitialData = {"contents":{"twoColumnWatchNextResults":{"results":{"a":1},"secondaryResults":{"x":[1]},"autoplay":{"y":1}}}};</script></head><body></body></html>`

func videoPage(id, title string) string {
	return `<html><head><script nonce="N0nce">var ytInitialPlayerResponse = ` + playerJSON(id, title) + `;</script></head><body></body></html>`
}

func playerJSON(id, title string) string {
	return `{"videoDetails":{"videoId":"` + id + `","title":"` + title + `","author":"Some Channel"},"microformat":{"playerMicroformatRenderer":{"category":"Education"}}}`
}

// upstream records what reached "YouTube" and answers with canned bodies.
type upstream struct {
	paths []string
	html  string // GET responses; plainPage when empty
	json  string // POST responses
}

func (u *upstream) RoundTrip(r *http.Request) (*http.Response, error) {
	u.paths = append(u.paths, r.URL.Path)
	body, ct := u.json, "application/json"
	if body == "" {
		body = `{"ok":true}`
	}
	if r.Method == http.MethodGet {
		ct, body = "text/html; charset=utf-8", u.html
		if body == "" {
			body = plainPage
		}
	}
	return &http.Response{
		StatusCode: 200, Header: http.Header{"Content-Type": {ct}, "Alt-Svc": {`h3=":443"`}},
		Body: io.NopCloser(strings.NewReader(body)), Request: r,
	}, nil
}

func testServer(t *testing.T, p policy) (*server, *upstream) {
	t.Helper()
	st := &store{dir: t.TempDir()}
	if !p.empty() {
		if err := st.write("policy.json", p); err != nil {
			t.Fatal(err)
		}
	}
	up := &upstream{}
	return newServer(st, fakeClassifier{}, up), up
}

func do(s *server, method, target, body string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://www.youtube.com"+target, strings.NewReader(body))
	if method == http.MethodGet {
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Fetch-Dest", "document")
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

var somePolicy = policy{Allowed: "good things", Blocked: "junk"}

func TestHomeIsOnlyASearchBar(t *testing.T) {
	s, up := testServer(t, somePolicy)
	w := do(s, "GET", "/", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `name="search_query"`) {
		t.Fatalf("home: %d %q", w.Code, w.Body.String())
	}
	if len(up.paths) != 0 {
		t.Fatalf("home page reached YouTube: %v", up.paths)
	}
}

func TestFeedsRedirectToSearchBar(t *testing.T) {
	s, up := testServer(t, somePolicy)
	for _, p := range []string{"/shorts/abc", "/feed/subscriptions", "/feed/trending", "/gaming"} {
		if w := do(s, "GET", p, "", nil); w.Code != http.StatusSeeOther {
			t.Errorf("%s: got %d, want redirect", p, w.Code)
		}
	}
	if len(up.paths) != 0 {
		t.Fatalf("feed requests reached YouTube: %v", up.paths)
	}
}

func TestSearchGate(t *testing.T) {
	s, up := testServer(t, somePolicy)

	if w := do(s, "GET", "/results?search_query=junk+food", "", nil); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Not approved") {
		t.Fatalf("blocked search: %d", w.Code)
	}
	// Fail closed when the model cannot answer.
	if w := do(s, "GET", "/results?search_query=broken", "", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("classifier error: got %d, want 503", w.Code)
	}
	if len(up.paths) != 0 {
		t.Fatalf("blocked searches reached YouTube: %v", up.paths)
	}
	if w := do(s, "GET", "/results?search_query=lecture", "", nil); w.Code != 200 || len(up.paths) != 1 {
		t.Fatalf("allowed search: %d, upstream %v", w.Code, up.paths)
	}
}

func gz(s string) string {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Write([]byte(s))
	zw.Close()
	return b.String()
}

func TestInPageSearchGateReadsGzippedBodies(t *testing.T) {
	s, up := testServer(t, somePolicy)
	hdr := map[string]string{"Content-Encoding": "gzip", "Sec-Fetch-Mode": "same-origin"}

	w := do(s, "POST", "/youtubei/v1/search", gz(`{"query":"junk food"}`), hdr)
	if w.Code != http.StatusForbidden || w.Header().Get(gotoHeader) != "/results?search_query="+url.QueryEscape("junk food") {
		t.Fatalf("blocked in-page search: %d goto=%q", w.Code, w.Header().Get(gotoHeader))
	}
	if w := do(s, "POST", "/youtubei/v1/search", "\x1f\x8bnot gzip", hdr); w.Code != http.StatusBadRequest {
		t.Fatalf("unreadable body: got %d, want 400", w.Code)
	}
	if len(up.paths) != 0 {
		t.Fatalf("refused searches reached YouTube: %v", up.paths)
	}
	if w := do(s, "POST", "/youtubei/v1/search", gz(`{"query":"lecture"}`), hdr); w.Code != 200 {
		t.Fatalf("allowed in-page search: %d", w.Code)
	}
}

func TestHomeFeedAPIRefused(t *testing.T) {
	s, up := testServer(t, somePolicy)
	hdr := map[string]string{"Sec-Fetch-Mode": "same-origin"}
	w := do(s, "POST", "/youtubei/v1/browse", `{"browseId":"FEwhat_to_watch"}`, hdr)
	if w.Code != http.StatusForbidden || w.Header().Get(gotoHeader) != "/" {
		t.Fatalf("home feed: %d goto=%q", w.Code, w.Header().Get(gotoHeader))
	}
	if w := do(s, "POST", "/youtubei/v1/browse", `{"browseId":"UCsomechannel"}`, hdr); w.Code != 200 || len(up.paths) != 1 {
		t.Fatalf("channel browse: %d, upstream %v", w.Code, up.paths)
	}
}

func TestWatchPageIsStripped(t *testing.T) {
	s, _ := testServer(t, somePolicy)
	w := do(s, "GET", "/watch?v=abc", "", nil)
	body := w.Body.String()
	for _, gone := range []string{`"x":[1]`, `"y":1`} {
		if strings.Contains(body, gone) {
			t.Errorf("watch page still carries recommendation data %s", gone)
		}
	}
	if !strings.Contains(body, `"results":{"a":1}`) {
		t.Error("watch page lost the video's own data")
	}
	if !strings.Contains(body, `<style nonce="N0nce">`) || !strings.Contains(body, `<script nonce="N0nce">`) {
		t.Error("stylesheet and script were not injected with the page's nonce")
	}
	if w.Header().Get("Alt-Svc") != "" {
		t.Error("Alt-Svc was passed through")
	}
}

// Inside a playlist the "next" data is the playlist's own, and is kept.
func TestPlaylistKeepsItsQueue(t *testing.T) {
	in := `{"twoColumnWatchNextResults":{"playlist":{"p":1},"autoplay":{"y":1},"secondaryResults":{"x":[1]}}}`
	out := string(pruneJSON([]byte(in), pruneWatch))
	if !strings.Contains(out, `"autoplay":{"y":1}`) || strings.Contains(out, `"x":[1]`) {
		t.Fatalf("got %s", out)
	}
}

func TestSuggestionsAndSideNavigationAreEmpty(t *testing.T) {
	s, up := testServer(t, somePolicy)
	if w := do(s, "GET", "/complete/search?q=mr", "", map[string]string{"Sec-Fetch-Mode": "cors"}); w.Code != http.StatusNoContent {
		t.Errorf("suggestions: got %d, want 204", w.Code)
	}
	if w := do(s, "POST", "/youtubei/v1/guide", "{}", map[string]string{"Sec-Fetch-Mode": "same-origin"}); w.Body.String() != `{"items":[]}` {
		t.Errorf("side navigation: got %s", w.Body.String())
	}
	if len(up.paths) != 0 {
		t.Fatalf("reached YouTube: %v", up.paths)
	}
}

func TestAdsAreStripped(t *testing.T) {
	s, up := testServer(t, somePolicy)
	api := map[string]string{"Sec-Fetch-Mode": "same-origin"}
	const ads = `"adPlacements":[{"adPlacementRenderer":{}}],"playerAds":[{}],"adSlots":[{}],"adBreakHeartbeatParams":"x"`
	const video = `"videoDetails":{"videoId":"v1","title":"a lecture","author":"c"},"streamingData":{"serverAbrStreamingUrl":"https://example/a?b=1\u0026c=2"}`

	// Player data fetched by the page.
	up.json = `{` + ads + `,` + video + `}`
	w := do(s, "POST", "/youtubei/v1/player", "{}", api)
	for _, key := range []string{"adPlacements", "playerAds", "adSlots", "adBreakHeartbeatParams"} {
		if strings.Contains(w.Body.String(), key) {
			t.Errorf("player response still carries %s", key)
		}
	}
	var got struct {
		StreamingData struct{ ServerAbrStreamingUrl string }
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.StreamingData.ServerAbrStreamingUrl != "https://example/a?b=1&c=2" {
		t.Errorf("the video's own stream data did not survive: %v %+v", err, got)
	}

	// Player data embedded in a page.
	up.html = `<html><head><script>var ytInitialPlayerResponse = {` + ads + `,` + video + `};</script></head></html>`
	if body := do(s, "GET", "/watch?v=v1", "", nil).Body.String(); strings.Contains(body, "adPlacements") || !strings.Contains(body, `"videoId":"v1"`) {
		t.Errorf("page still carries its ad schedule, or lost the video")
	}

	// Ad entries mixed into a list of results.
	up.json = `{"contents":[{"adSlotRenderer":{}},{"videoRenderer":{"id":"keep"}},{"promotedSparklesWebRenderer":{}}]}`
	if body := do(s, "POST", "/youtubei/v1/browse", `{"browseId":"UCx"}`, api).Body.String(); body != `{"contents":[{"videoRenderer":{"id":"keep"}}]}` {
		t.Errorf("list ads: got %s", body)
	}

	// Ad endpoints are answered empty and never reach YouTube.
	before := len(up.paths)
	for _, p := range []string{"/pagead/adview?x=1", "/ptracking?y", "/api/stats/ads?z", "/youtubei/v1/player/ad_break"} {
		method := "GET"
		if strings.HasPrefix(p, "/youtubei") {
			method = "POST"
		}
		if w := do(s, method, p, "", api); w.Code != http.StatusNoContent {
			t.Errorf("%s: got %d, want 204", p, w.Code)
		}
	}
	if len(up.paths) != before {
		t.Errorf("ad requests reached YouTube: %v", up.paths[before:])
	}
}

func TestEveryRouteToAVideoIsJudged(t *testing.T) {
	s, up := testServer(t, somePolicy)
	api := map[string]string{"Sec-Fetch-Mode": "same-origin"}

	// A direct link.
	up.html = videoPage("vid1", "pure junk")
	w := do(s, "GET", "/watch?v=vid1", "", nil)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "pure junk") {
		t.Fatalf("direct link to a blocked video: %d", w.Code)
	}
	// The same video again is refused without asking YouTube.
	before := len(up.paths)
	if w := do(s, "GET", "/watch?v=vid1", "", nil); w.Code != http.StatusForbidden || len(up.paths) != before {
		t.Fatalf("remembered block: %d, upstream calls %d -> %d", w.Code, before, len(up.paths))
	}
	// A click inside the page: refused, and pointed at the page that says why.
	up.json = `[` + playerJSON("vid2", "more junk") + `]`
	w = do(s, "POST", "/youtubei/v1/get_watch", "{}", api)
	if w.Code != http.StatusForbidden || w.Header().Get(gotoHeader) != "/watch?v=vid2" {
		t.Fatalf("in-page navigation: %d goto=%q", w.Code, w.Header().Get(gotoHeader))
	}
	// Player data alone (embeds, previews): refused, but the page stays put.
	w = do(s, "POST", "/youtubei/v1/player", "{}", api)
	if w.Code != http.StatusForbidden || w.Header().Get(gotoHeader) != "" {
		t.Fatalf("player request: %d goto=%q", w.Code, w.Header().Get(gotoHeader))
	}
	// An allowed video passes through byte for byte.
	up.json = playerJSON("vid3", "a lecture")
	if w := do(s, "POST", "/youtubei/v1/player", "{}", api); w.Code != 200 || w.Body.String() != up.json {
		t.Fatalf("allowed player response was altered: %d %s", w.Code, w.Body.String())
	}
	// Video data that cannot be read is not shown.
	up.html = `<html><head></head><body><script>var other = {"videoDetails":{"title":"x"}};</script></body></html>`
	if w := do(s, "GET", "/watch?v=vid4", "", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unreadable video data: got %d, want 503", w.Code)
	}
}

func TestChannelsAndPlaylistsAreJudged(t *testing.T) {
	s, up := testServer(t, somePolicy)
	up.html = `<html><head><script>var ytInitialData = {"metadata":{"channelMetadataRenderer":{"title":"junk central","description":"daily","externalId":"UC123"}}};</script></head></html>`
	if w := do(s, "GET", "/@junkcentral", "", nil); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "junk central") {
		t.Fatalf("blocked channel page: %d", w.Code)
	}
	up.json = `{"metadata":{"playlistMetadataRenderer":{"title":"banned mix"}}}`
	w := do(s, "POST", "/youtubei/v1/browse", `{"browseId":"VLPL999"}`, map[string]string{"Sec-Fetch-Mode": "same-origin"})
	if w.Code != http.StatusForbidden || w.Header().Get(gotoHeader) != "/playlist?list=PL999" {
		t.Fatalf("in-page playlist: %d goto=%q", w.Code, w.Header().Get(gotoHeader))
	}
}

var tokenRe = regexp.MustCompile(`name="token" value="([0-9a-f]+)"`)

func TestAppeal(t *testing.T) {
	s, _ := testServer(t, somePolicy)
	post := func(token, why string) *httptest.ResponseRecorder {
		body := url.Values{"token": {token}, "why": {why}}.Encode()
		return do(s, "POST", "/__hider/appeal", body, map[string]string{
			"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin",
		})
	}

	// A block the model is certain of offers no appeal.
	if w := do(s, "GET", "/results?search_query=banned+thing", "", nil); tokenRe.MatchString(w.Body.String()) {
		t.Fatal("a certain block offered an appeal")
	}
	// One it is unsure of does.
	w := do(s, "GET", "/results?search_query=junk+history", "", nil)
	m := tokenRe.FindStringSubmatch(w.Body.String())
	if w.Code != http.StatusForbidden || m == nil {
		t.Fatalf("unsure block: %d, appeal offered: %v", w.Code, m != nil)
	}
	token := m[1]

	if w := post(token, "because"); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "at least 250") {
		t.Fatalf("short appeal: %d", w.Code)
	}
	if w := post(token, strings.Repeat("a", 300)); w.Code != http.StatusForbidden {
		t.Fatalf("300 characters of nothing was accepted: %d", w.Code)
	}
	if w := do(s, "GET", "/results?search_query=junk+history", "", nil); w.Code != http.StatusForbidden {
		t.Fatal("a rejected appeal opened the search")
	}

	var words []string
	for i := range 60 {
		words = append(words, "reason"+strconv.Itoa(i))
	}
	w = post(token, strings.Join(words, " "))
	if w.Code != http.StatusSeeOther || !strings.HasSuffix(w.Header().Get("Location"), "/results?search_query=junk+history") {
		t.Fatalf("good appeal: %d -> %q", w.Code, w.Header().Get("Location"))
	}
	if w := do(s, "GET", "/results?search_query=junk+history", "", nil); w.Code != 200 {
		t.Fatalf("after appeal: %d", w.Code)
	}
	// The grant and its text survive a restart.
	restarted := newServer(s.store, fakeClassifier{}, &upstream{})
	if w := do(restarted, "GET", "/results?search_query=junk+history", "", nil); w.Code != 200 {
		t.Fatalf("after restart: %d", w.Code)
	}
	if g := restarted.grants["search:junk history"]; !strings.HasPrefix(g.Why, "reason0 ") {
		t.Fatalf("appeal text was not kept: %+v", g)
	}
	// A token cannot be forged for something certain.
	if w := post("deadbeef", strings.Join(words, " ")); w.Code != http.StatusSeeOther || do(s, "GET", "/results?search_query=banned+thing", "", nil).Code != http.StatusForbidden {
		t.Fatalf("unknown token: %d", w.Code)
	}
}

func TestUnconfiguredSendsEverythingToOnboarding(t *testing.T) {
	s, up := testServer(t, policy{})
	w := do(s, "GET", "/watch?v=abc", "", nil)
	if w.Code != http.StatusSeeOther || !strings.HasSuffix(w.Header().Get("Location"), "/__hider/onboard") {
		t.Fatalf("got %d -> %q", w.Code, w.Header().Get("Location"))
	}
	if len(up.paths) != 0 {
		t.Fatal("request reached YouTube before a policy existed")
	}
}

func TestAddingIsOpenRemovingNeedsThePassword(t *testing.T) {
	s, _ := testServer(t, policy{})
	form := func(v url.Values) *httptest.ResponseRecorder {
		return do(s, "POST", "/__hider/onboard", v.Encode(), map[string]string{
			"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin",
		})
	}
	rewrite := func(allowed, password string) *httptest.ResponseRecorder {
		return form(url.Values{"action": {"rewrite"}, "allowed": {allowed}, "blocked": {"junk"}, "password": {password}})
	}
	if w := rewrite("first", ""); w.Code != http.StatusSeeOther || s.currentPolicy().Allowed != "first" {
		t.Fatalf("first save: %d", w.Code)
	}
	lk, err := newLock("abcd-efgh-ijkl-mnop", time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.write("lock.json", lk); err != nil {
		t.Fatal(err)
	}

	// Adding needs no password and loses nothing.
	if w := form(url.Values{"add_allowed": {"talks"}, "add_blocked": {"vlogs"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("add: %d", w.Code)
	}
	if p := s.currentPolicy(); p.Allowed != "first\ntalks" || p.Blocked != "junk\nvlogs" {
		t.Fatalf("after add: %+v", p)
	}
	// A form that tries to replace the text without the rewrite action only adds nothing.
	if w := form(url.Values{"allowed": {"everything"}, "blocked": {"nothing"}}); w.Code != http.StatusBadRequest || s.currentPolicy().Allowed != "first\ntalks" {
		t.Fatalf("replacement without password: %d %+v", w.Code, s.currentPolicy())
	}
	if w := rewrite("everything", "wrong"); w.Code != http.StatusBadRequest || s.currentPolicy().Allowed != "first\ntalks" {
		t.Fatalf("wrong password rewrote the policy: %d", w.Code)
	}
	if w := rewrite("second", "ABCD efgh-ijkl-mnop"); w.Code != http.StatusSeeOther || s.currentPolicy().Allowed != "second" {
		t.Fatalf("right password: %d", w.Code)
	}
	cross := do(s, "POST", "/__hider/onboard", "add_allowed=x", map[string]string{
		"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "cross-site",
	})
	if cross.Code != http.StatusForbidden {
		t.Fatalf("cross-site save: got %d, want 403", cross.Code)
	}
}

func TestPruneSearchDropsShelvesOnly(t *testing.T) {
	in := `{"contents":[{"videoRenderer":{"id":"keep"}},{"reelShelfRenderer":{"x":1}},{"shelfRenderer":{"x":1}},{"adSlotRenderer":{}}]}`
	out := string(pruneJSON([]byte(in), pruneSearch))
	if out != `{"contents":[{"videoRenderer":{"id":"keep"}}]}` {
		t.Fatalf("got %s", out)
	}
	if got := pruneJSON([]byte("not json"), pruneSearch); string(got) != "not json" {
		t.Fatalf("unparseable body was altered: %s", got)
	}
}

func TestLockCooloff(t *testing.T) {
	pw := newPassword()
	lk, err := newLock(pw, 24*time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if !lk.verify(pw) || lk.verify(newPassword()) {
		t.Fatal("password verification is wrong")
	}
	now := time.Now()
	if _, err := lk.remaining(now); err == nil {
		t.Fatal("reveal allowed without a request")
	}
	lk.RequestedAt = &now
	if left, _ := lk.remaining(now.Add(23 * time.Hour)); left != time.Hour {
		t.Fatalf("after 23h: %s left, want 1h", left)
	}
	if left, err := lk.remaining(now.Add(25 * time.Hour)); err != nil || left != 0 {
		t.Fatalf("after 25h: %s, %v", left, err)
	}

	sealed, _ := newLock(pw, 0, true)
	sealed.RequestedAt = &now
	if _, err := sealed.remaining(now.Add(1000 * time.Hour)); err == nil || sealed.Sealed != "" {
		t.Fatal("a sealed lock kept or revealed the password")
	}
}

func TestHostsBlock(t *testing.T) {
	orig := "127.0.0.1 localhost\n142.250.0.1 www.youtube.com # sneaky\n10.0.0.2 nas.local\n"
	on := hostsWith(orig, true)
	if strings.Contains(on, "142.250.0.1") {
		t.Error("a competing youtube entry survived")
	}
	if !strings.Contains(on, "127.0.0.1 www.youtube.com") || !strings.Contains(on, "nas.local") {
		t.Errorf("unexpected hosts:\n%s", on)
	}
	if hostsWith(on, true) != on {
		t.Error("not idempotent")
	}
	if off := hostsWith(on, false); off != "127.0.0.1 localhost\n10.0.0.2 nas.local\n" {
		t.Errorf("removal left:\n%s", off)
	}
}

// The trusted root must be useless for anything but YouTube.
func TestAuthorityIsConstrainedToYouTube(t *testing.T) {
	dir := t.TempDir()
	if err := createAuthority(dir); err != nil {
		t.Fatal(err)
	}
	ca, err := loadAuthority(dir)
	if err != nil {
		t.Fatal(err)
	}
	rootDER, _ := readPEM(dir + "/root.pem")
	root, _ := x509.ParseCertificate(rootDER)
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	inters.AddCert(ca.inter)
	opts := func(name string) x509.VerifyOptions {
		return x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: name}
	}

	leaf, err := ca.getCertificate(&tls.ClientHelloInfo{ServerName: "www.youtube.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Leaf.Verify(opts("www.youtube.com")); err != nil {
		t.Fatalf("youtube leaf does not verify: %v", err)
	}
	if _, err := ca.getCertificate(&tls.ClientHelloInfo{ServerName: "bank.example"}); err == nil {
		t.Fatal("minted a certificate for a host that is not intercepted")
	}

	// Even with the intermediate key in hand, other domains do not verify.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "bank.example"}, DNSNames: []string{"bank.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.inter, &key.PublicKey, ca.interKey)
	if err != nil {
		t.Fatal(err)
	}
	forged, _ := x509.ParseCertificate(der)
	if _, err := forged.Verify(opts("bank.example")); err == nil {
		t.Fatal("a certificate for another domain verified against the local root")
	}
}
