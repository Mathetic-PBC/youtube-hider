package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
)

// pruneMode selects which recommendation data is removed from a response.
type pruneMode int

const (
	pruneNone pruneMode = iota
	pruneWatch
	pruneSearch
)

// Object keys emptied wherever they appear in watch-page data: the "up next"
// column, the end-of-video wall and the autoplay queue.
var watchKeys = map[string]bool{
	"secondaryResults": true,
	"endScreen":        true,
	"autoplay":         true,
}

// Renderers dropped from search results: Shorts shelves and "people also
// watched" style shelves. Ordinary results are left alone.
var searchRenderers = map[string]bool{
	"reelShelfRenderer":          true,
	"shelfRenderer":              true,
	"richShelfRenderer":          true,
	"gridShelfViewModel":         true,
	"horizontalCardListRenderer": true,
}

// Ads are removed from every response, whatever the mode.
//
// adKeys are the fields of a player response that tell the player which ads
// to fetch and when to play them. With them gone the player has no ad to
// request: nothing is skipped or hidden, because nothing was scheduled.
var adKeys = map[string]bool{
	"adPlacements":           true,
	"playerAds":              true,
	"adSlots":                true,
	"adBreakHeartbeatParams": true,
}

// adRenderers are the ad and promotion entries mixed into lists of results.
var adRenderers = map[string]bool{
	"adSlotRenderer":                      true,
	"inFeedAdLayoutRenderer":              true,
	"searchPyvRenderer":                   true,
	"promotedSparklesWebRenderer":         true,
	"promotedVideoRenderer":               true,
	"compactPromotedVideoRenderer":        true,
	"playerLegacyDesktopWatchAdsRenderer": true,
	"merchandiseShelfRenderer":            true,
}

// adMarkers decide whether a body is worth decoding when nothing else in it
// needs rewriting.
var adMarkers = [][]byte{
	[]byte(`"adPlacements"`), []byte(`"playerAds"`), []byte(`"adSlots"`), []byte(`"adBreakHeartbeatParams"`),
	[]byte(`"adSlotRenderer"`), []byte(`"inFeedAdLayoutRenderer"`), []byte(`"searchPyvRenderer"`),
	[]byte(`romotedSparklesWebRenderer"`), []byte(`romotedVideoRenderer"`),
	[]byte(`"playerLegacyDesktopWatchAdsRenderer"`), []byte(`"merchandiseShelfRenderer"`),
}

func hasAds(body []byte) bool {
	for _, m := range adMarkers {
		if bytes.Contains(body, m) {
			return true
		}
	}
	return false
}

// prune walks decoded JSON and removes ads and recommendation data in place.
func prune(v any, mode pruneMode) any {
	switch t := v.(type) {
	case map[string]any:
		// Inside a playlist, "next" is the playlist's own next video, and the
		// playlist panel does not render without it.
		_, inPlaylist := t["playlist"]
		for k, child := range t {
			if adKeys[k] {
				delete(t, k)
				continue
			}
			if mode == pruneWatch && watchKeys[k] && !(k == "autoplay" && inPlaylist) {
				if _, isObj := child.(map[string]any); isObj {
					// Emptied, not deleted: the page expects the key to exist.
					t[k] = map[string]any{}
					continue
				}
			}
			t[k] = prune(child, mode)
		}
		return t
	case []any:
		out := t[:0]
		for _, el := range t {
			if isRenderer(el, adRenderers) || (mode == pruneSearch && isRenderer(el, searchRenderers)) {
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
	if mode == pruneNone && !hasAds(body) {
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
// and prunes the ads and recommendation data embedded in it.
func rewriteHTML(body []byte, mode pruneMode, css, js []byte) []byte {
	if mode != pruneNone || hasAds(body) {
		body = pruneEmbedded(body, initialDataMark, mode)
		body = pruneEmbedded(body, playerMark, pruneNone)
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

// pruneEmbedded prunes the JSON object a page assigns after mark: the page
// data (ytInitialData) or the player data (ytInitialPlayerResponse).
func pruneEmbedded(body, mark []byte, mode pruneMode) []byte {
	i := bytes.Index(body, mark)
	if i < 0 {
		return body
	}
	start := i + len(mark)
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

var (
	playerMark    = []byte("var ytInitialPlayerResponse = ")
	detailsMark   = []byte(`"videoDetails":{`)
	channelMark   = []byte(`"channelMetadataRenderer":{`)
	playlistMark  = []byte(`"playlistMetadataRenderer":{`)
	errUnreadable = errors.New("this page carries something the proxy could not read")
)

// findItem extracts what a response is about: a video (a page with embedded
// player data, or a player API response), or else a channel or playlist.
// found is false when the response carries none of these. A response that
// mentions one but cannot be parsed is an error, so that a format change on
// YouTube's side blocks rather than leaks.
func findItem(body []byte, isHTML bool) (it item, found bool, err error) {
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }

	if bytes.Contains(body, detailsMark) {
		v, err := embedded(body, isHTML, playerMark)
		if err != nil {
			return item{}, false, err
		}
		details := findObject(v, "videoDetails")
		if details == nil {
			return item{}, false, errUnreadable
		}
		it = item{Kind: "video", ID: str(details, "videoId"), Title: str(details, "title"), Channel: str(details, "author")}
		if micro := findObject(v, "playerMicroformatRenderer"); micro != nil {
			it.Detail = str(micro, "category")
		}
		if it.ID == "" || it.Title == "" {
			return item{}, false, errUnreadable
		}
		return it, true, nil
	}

	isChannel := bytes.Contains(body, channelMark)
	if !isChannel && !bytes.Contains(body, playlistMark) {
		return item{}, false, nil
	}
	v, err := embedded(body, isHTML, initialDataMark)
	if err != nil {
		return item{}, false, err
	}
	kind, key := "playlist", "playlistMetadataRenderer"
	if isChannel {
		kind, key = "channel", "channelMetadataRenderer"
	}
	meta := findObject(v, key)
	if meta == nil || str(meta, "title") == "" {
		return item{}, false, errUnreadable
	}
	it = item{Kind: kind, ID: str(meta, "externalId"), Title: str(meta, "title"), Detail: str(meta, "description")}
	if it.ID == "" {
		it.ID = it.Title
	}
	if r := []rune(it.Detail); len(r) > 300 {
		it.Detail = string(r[:300])
	}
	return it, true, nil
}

// embedded decodes the JSON a response carries: the whole body of an API
// response, or the object assigned after mark in a page.
func embedded(body []byte, isHTML bool, mark []byte) (any, error) {
	src := body
	if isHTML {
		i := bytes.Index(body, mark)
		if i < 0 {
			return nil, errUnreadable
		}
		src = body[i+len(mark):]
	}
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, errUnreadable
	}
	return v, nil
}

// findObject returns the first object stored under key anywhere in v.
func findObject(v any, key string) map[string]any {
	switch t := v.(type) {
	case map[string]any:
		if m, ok := t[key].(map[string]any); ok {
			return m
		}
		for _, child := range t {
			if m := findObject(child, key); m != nil {
				return m
			}
		}
	case []any:
		for _, el := range t {
			if m := findObject(el, key); m != nil {
				return m
			}
		}
	}
	return nil
}
