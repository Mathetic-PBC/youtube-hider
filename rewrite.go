package main

import (
	"bytes"
	"encoding/json"
	"regexp"
)

// pruneMode selects which recommendation data is removed from a response.
type pruneMode int

const (
	pruneNone pruneMode = iota
	pruneWatch
	pruneSearch
)

// Object keys deleted wherever they appear in watch-page data: the "up next"
// column, the end-of-video wall and the autoplay queue.
var watchKeys = map[string]bool{
	"secondaryResults": true,
	"endScreen":        true,
	"autoplay":         true,
}

// Renderers dropped from search results: Shorts shelves, "people also
// watched" style shelves, and ads. Ordinary results are left alone.
var searchRenderers = map[string]bool{
	"reelShelfRenderer":          true,
	"shelfRenderer":              true,
	"richShelfRenderer":          true,
	"gridShelfViewModel":         true,
	"horizontalCardListRenderer": true,
	"adSlotRenderer":             true,
}

// prune walks decoded JSON and removes recommendation data in place.
func prune(v any, mode pruneMode) any {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if mode == pruneWatch && watchKeys[k] {
				if _, isObj := child.(map[string]any); isObj {
					delete(t, k)
					continue
				}
			}
			t[k] = prune(child, mode)
		}
		return t
	case []any:
		out := t[:0]
		for _, el := range t {
			if mode == pruneSearch && isRenderer(el, searchRenderers) {
				continue
			}
			out = append(out, prune(el, mode))
		}
		return out
	}
	return v
}

func isRenderer(v any, names map[string]bool) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return false
	}
	for k := range m {
		return names[k]
	}
	return false
}

// pruneJSON rewrites a youtubei API response body. On any parse failure the
// body is returned unchanged: the injected stylesheet still hides the same
// regions, so a schema surprise degrades to hidden rather than broken.
func pruneJSON(body []byte, mode pruneMode) []byte {
	if mode == pruneNone {
		return body
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return body
	}
	out, err := json.Marshal(prune(v, mode))
	if err != nil {
		return body
	}
	return out
}

var (
	headRe          = regexp.MustCompile(`(?i)<head[^>]*>`)
	nonceRe         = regexp.MustCompile(`<script[^>]*\snonce="([^"]+)"`)
	initialDataMark = []byte("var ytInitialData = ")
)

// rewriteHTML injects the hiding stylesheet and script into a YouTube page
// and prunes the recommendation data embedded in it.
func rewriteHTML(body []byte, mode pruneMode, css, js []byte) []byte {
	if mode != pruneNone {
		body = pruneInitialData(body, mode)
	}
	loc := headRe.FindIndex(body)
	if loc == nil {
		return body
	}
	nonce := ""
	if m := nonceRe.FindSubmatch(body); m != nil {
		nonce = ` nonce="` + string(m[1]) + `"`
	}
	var inj bytes.Buffer
	inj.WriteString("<style" + nonce + ">")
	inj.Write(css)
	inj.WriteString("</style><script" + nonce + ">")
	inj.Write(js)
	inj.WriteString("</script>")

	out := make([]byte, 0, len(body)+inj.Len())
	out = append(out, body[:loc[1]]...)
	out = append(out, inj.Bytes()...)
	out = append(out, body[loc[1]:]...)
	return out
}

func pruneInitialData(body []byte, mode pruneMode) []byte {
	i := bytes.Index(body, initialDataMark)
	if i < 0 {
		return body
	}
	start := i + len(initialDataMark)
	if start >= len(body) || body[start] != '{' {
		return body
	}
	dec := json.NewDecoder(bytes.NewReader(body[start:]))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return body
	}
	end := start + int(dec.InputOffset())
	// json.Marshal escapes <, > and &, so the result is safe inside <script>.
	pruned, err := json.Marshal(prune(v, mode))
	if err != nil {
		return body
	}
	out := make([]byte, 0, len(body))
	out = append(out, body[:start]...)
	out = append(out, pruned...)
	out = append(out, body[end:]...)
	return out
}
