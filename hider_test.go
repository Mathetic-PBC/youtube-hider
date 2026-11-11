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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeClassifier blocks any query containing "junk" and fails on "broken".
type fakeClassifier struct{}

func (fakeClassifier) classify(_ context.Context, _ policy, q string) (verdict, error) {
	switch {
	case strings.Contains(q, "broken"):
		return verdict{}, errors.New("model offline")
	case strings.Contains(q, "junk"):
		return verdict{Reason: "junk"}, nil
	}
	return verdict{Allow: true}, nil
}

// upstream records what reached "YouTube" and answers with canned pages.
type upstream struct{ paths []string }

func (u *upstream) RoundTrip(r *http.Request) (*http.Response, error) {
	u.paths = append(u.paths, r.URL.Path)
	body, ct := `{"ok":true}`, "application/json"
	if r.Method == http.MethodGet {
		ct = "text/html; charset=utf-8"
		body = `<html><head><script nonce="N0nce">var ytInitialData = {"contents":{"twoColumnWatchNextResults":{"results":{"a":1},"secondaryResults":{"x":[1]},"autoplay":{"y":1}}}};</script></head><body></body></html>`
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
	for _, gone := range []string{`"secondaryResults":`, `"autoplay":`} {
		if strings.Contains(body, gone) {
			t.Errorf("watch page still carries %s", gone)
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

func TestPolicyChangesNeedThePassword(t *testing.T) {
	s, _ := testServer(t, policy{})
	form := func(allowed, password string) *httptest.ResponseRecorder {
		body := url.Values{"allowed": {allowed}, "blocked": {"junk"}, "password": {password}}.Encode()
		return do(s, "POST", "/__hider/onboard", body, map[string]string{
			"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin",
		})
	}
	if w := form("first", ""); w.Code != http.StatusSeeOther || s.currentPolicy().Allowed != "first" {
		t.Fatalf("first save: %d", w.Code)
	}
	lk, err := newLock("abcd-efgh-ijkl-mnop", time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.write("lock.json", lk); err != nil {
		t.Fatal(err)
	}
	if w := form("everything", "wrong"); w.Code != http.StatusBadRequest || s.currentPolicy().Allowed != "first" {
		t.Fatalf("wrong password changed the policy: %d %q", w.Code, s.currentPolicy().Allowed)
	}
	if w := form("second", "ABCD efgh-ijkl-mnop"); w.Code != http.StatusSeeOther || s.currentPolicy().Allowed != "second" {
		t.Fatalf("right password: %d", w.Code)
	}
	cross := do(s, "POST", "/__hider/onboard", "allowed=x&blocked=y", map[string]string{
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

	never, _ := newLock(pw, 0, true)
	never.RequestedAt = &now
	if _, err := never.remaining(now.Add(1000 * time.Hour)); err == nil || never.Sealed != "" {
		t.Fatal("--cooloff never kept or revealed the password")
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
