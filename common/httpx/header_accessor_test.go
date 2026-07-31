package httpx

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

const headerAccessorBody = "header accessor body"

// headerAccessorResponse performs one mocked GET and returns the parsed response for
// hdr. The 200 status intentionally prevents a Location fixture from being followed.
func headerAccessorResponse(t *testing.T, hdr http.Header) *Response {
	t.Helper()

	mt := newMockTransport(t, func(r *http.Request) (*http.Response, error) {
		return mockResponse(r, http.StatusOK, hdr, headerAccessorBody), nil
	})
	ht := newMockHTTPX(t, nil, mt)

	req, err := retryablehttp.NewRequest(http.MethodGet, "http://origin.example/", nil)
	require.NoError(t, err, "the fixture target must parse, otherwise the case never reaches the accessors")

	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err, "the mocked round trip must succeed, so a header miss below cannot be a failed request in disguise")
	require.Equal(t, 1, mt.callCount(),
		"exactly one round trip must reach the transport, so no retry or redirect can have replaced the response under test")
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"the accessors must be reading the mock's own response, not a follow-up one")

	return resp
}

// TestGetHeaderJoinsMultiValuesWithSpace pins the accessor's exact single-space join
// for repeated values, strings.Join(v, " ") at common/httpx/response.go:45. Set-Cookie
// is used because it preserves distinct field lines and, unlike combinable list fields,
// must not itself be comma-combined. The delimiter is pinned as observed: the runner
// renders header-derived output through this accessor, so changing it would change
// every consumer's output.
func TestGetHeaderJoinsMultiValuesWithSpace(t *testing.T) {
	// Set-Cookie is the canonical field that legitimately repeats and must never be
	// comma-joined: RFC 6265 §4.1.1 permits a comma inside an Expires attribute, so a
	// comma-joined pair could not be split back apart unambiguously.
	hdr := http.Header{}
	hdr.Add("Set-Cookie", "a=1; Path=/")
	hdr.Add("Set-Cookie", "b=2; Path=/")

	resp := headerAccessorResponse(t, hdr)

	require.Len(t, resp.Headers["Set-Cookie"], 2,
		"both field lines must reach Response.Headers, otherwise the join under test would have nothing to join")

	// RawHeaders confirms that response serialization preserved two distinct field
	// lines before GetHeader joined their values.
	require.Contains(t, resp.RawHeaders, "Set-Cookie: a=1; Path=/\r\nSet-Cookie: b=2; Path=/\r\n",
		"the origin's two Set-Cookie field lines must appear separately, and in order, in the raw response")

	got := resp.GetHeader("Set-Cookie")
	require.Equal(t, "a=1; Path=/ b=2; Path=/", got,
		"GetHeader joins the value slice with a single space (response.go:45), not with the RFC 9110 §5.3 comma")
	require.NotContains(t, got, ", ",
		"a comma-space delimiter would mean the RFC join had been adopted; the pinned contract is the space join")
}

// TestGetHeaderIsCaseSensitive pins that both accessors look up the supplied key
// directly in Response.Headers, which is a plain map[string][]string
// (common/httpx/response.go:15). net/http normally canonicalizes parsed header names
// before they are cloned into that map, but the accessors do not canonicalize the
// lookup argument; production callers therefore must use the stored MIME spelling, such
// as "Etag". The case-sensitive read is pinned as observed because it is the accessor's
// long-standing contract.
func TestGetHeaderIsCaseSensitive(t *testing.T) {
	// Built through Header.Set, which applies textproto.CanonicalMIMEHeaderKey exactly
	// as net/http's response reader does, so the stored spelling is the canonical one a
	// real origin's field name would land under - even though the input here is
	// lowercase.
	hdr := http.Header{}
	hdr.Set("content-type", "text/html; charset=utf-8")

	resp := headerAccessorResponse(t, hdr)

	require.Equal(t, []string{"text/html; charset=utf-8"}, resp.Headers["Content-Type"],
		"the value must be stored under the canonical spelling, because Header.Set canonicalized the field name")
	require.NotContains(t, resp.Headers, "content-type",
		"the lowercase spelling must not be a key at all, which is precisely why the mis-cased reads below miss")

	require.Equal(t, "text/html; charset=utf-8", resp.GetHeader("Content-Type"),
		"the canonical spelling is the one spelling that hits the raw map read")
	require.Equal(t, "", resp.GetHeader("content-type"),
		"a lowercase field name misses (response.go:43) even though RFC 9110 §5.1 makes field names case-insensitive")
	require.Equal(t, "", resp.GetHeader("CONTENT-TYPE"),
		"an uppercase field name misses for the same reason: the lookup is a raw map read, not a canonicalizing one")

	require.Equal(t, "", resp.GetHeaderPart("content-type", ";"),
		"GetHeaderPart repeats the same raw read at response.go:52, so it is case-sensitive too")
	require.Equal(t, "text/html", resp.GetHeaderPart("Content-Type", ";"),
		"the canonical spelling still yields the media type, proving the value was present throughout")
}

// TestGetHeaderPartSplitsOnSeparator pins that GetHeaderPart space-joins all values,
// splits on sep, and returns the first token (common/httpx/response.go:54-55). Each
// case also asserts GetHeader so any truncation is attributable to the split.
//
// SECURITY DISPOSITION for the Location row. A semicolon is legal inside a URI query
// (RFC 3986 section 3.4), and the runner emits its Location field through this accessor, so a
// redirect target containing one is reported to the operator SHORTER than the target the
// client would actually follow - silently, with no error and no marker. An operator triaging
// an open-redirect or an SSRF finding from that output is therefore reading a different URL
// from the one on the wire, and the discarded remainder is exactly where a payload would sit.
//
// PINNED AS MEASURED AND NOT FIXED. Narrowing the split would mean editing
// common/httpx/response.go, a source file this work may not modify at all - its only
// permitted non-test change is the two minimal, separately disclosed fixes in httpx.go - and
// the split-and-take-first contract is what the media-type and cookie rows above depend on,
// so it cannot be changed for one caller only. The row below pins the truncated value
// exactly, so the loss is documented rather than latent.
func TestGetHeaderPartSplitsOnSeparator(t *testing.T) {
	cases := []struct {
		name      string
		key       string
		values    []string
		sep       string
		wantWhole string
		wantPart  string
		reason    string
	}{
		{
			name:      "cookie pair before attributes",
			key:       "Set-Cookie",
			values:    []string{"a=1; Path=/; HttpOnly"},
			sep:       ";",
			wantWhole: "a=1; Path=/; HttpOnly",
			wantPart:  "a=1",
			reason:    "the leading name=value pair is the first token, with every RFC 6265 §4.1.1 attribute dropped",
		},
		{
			// Runner output and title extraction depend on this parameter-free media type.
			name:      "media type without parameters",
			key:       "Content-Type",
			values:    []string{"text/html; charset=utf-8"},
			sep:       ";",
			wantWhole: "text/html; charset=utf-8",
			wantPart:  "text/html",
			reason:    "the media type is the first token, with the RFC 9110 §8.3 charset parameter dropped",
		},
		{
			// A semicolon is legal in a URI query (RFC 3986 §3.4), so the unconditional
			// tokens[0] at common/httpx/response.go:55 truncates a valid Location. Runner
			// location output uses this accessor, making the loss caller-visible; the
			// split-and-take-first contract is pinned as observed rather than narrowed.
			name:      "location truncated at semicolon inside query",
			key:       "Location",
			values:    []string{"/next?q=1;drop"},
			sep:       ";",
			wantWhole: "/next?q=1;drop",
			wantPart:  "/next?q=1",
			reason:    "the query's second parameter is discarded even though ';' is legal there (RFC 3986 §3.4)",
		},
		{
			name:      "separator inside the first of two field lines",
			key:       "Set-Cookie",
			values:    []string{"a=1; Path=/", "b=2; Path=/"},
			sep:       ";",
			wantWhole: "a=1; Path=/ b=2; Path=/",
			wantPart:  "a=1",
			reason:    "only the first field line's leading token survives, so the second cookie is unreachable through this accessor",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hdr := http.Header{}
			for _, value := range tc.values {
				hdr.Add(tc.key, value)
			}

			resp := headerAccessorResponse(t, hdr)

			require.Len(t, resp.Headers[tc.key], len(tc.values),
				"every field line must reach Response.Headers before the split is exercised")
			require.Equal(t, tc.wantWhole, resp.GetHeader(tc.key),
				"GetHeader must return the space-joined value untruncated, so any loss below is the split's doing")
			require.Equal(t, tc.wantPart, resp.GetHeaderPart(tc.key, tc.sep), tc.reason)
		})
	}
}

// TestGetHeaderMissingReturnsEmpty pins the empty-string miss value of both accessors.
// A present header is included as a control so empty results cannot be attributed to an
// empty response map.
func TestGetHeaderMissingReturnsEmpty(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Content-Type", "text/plain")

	resp := headerAccessorResponse(t, hdr)

	require.Equal(t, "text/plain", resp.GetHeader("Content-Type"),
		"control: the response does carry a readable header, so every empty string below is a genuine miss")

	require.NotContains(t, resp.Headers, "X-Does-Not-Exist",
		"the field must genuinely be absent from the map, not merely empty-valued")
	require.Equal(t, "", resp.GetHeader("X-Does-Not-Exist"),
		"an absent field reads back as the empty string (response.go:47), never as a nil or a sentinel")
	require.Equal(t, "", resp.GetHeaderPart("X-Does-Not-Exist", ";"),
		"an absent field yields the empty string from the guarded branch too (response.go:53, :58)")

	require.Equal(t, "", resp.GetHeader("X-Also-Absent"),
		"a second absent field behaves identically, so the empty result is the contract and not an artifact of one name")
	require.Equal(t, "", resp.GetHeaderPart("X-Also-Absent", ";"),
		"the separator is irrelevant on a miss: the split is never reached")

	// A present field read with the wrong case is indistinguishable from an absent one,
	// which is the practical consequence of the case-sensitive lookup pinned in
	// TestGetHeaderIsCaseSensitive.
	require.Equal(t, "", resp.GetHeader("content-type"),
		"a mis-cased read of a PRESENT field is indistinguishable from a miss")
	require.Equal(t, "", resp.GetHeaderPart("content-type", ";"),
		"the same holds for the part accessor, so canonical spellings are mandatory in every assertion")
}
