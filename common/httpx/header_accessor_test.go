package httpx

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// This file pins Response.GetHeader and Response.GetHeaderPart
// (common/httpx/response.go:42-59), the two accessors that every other header
// assertion in this package flows through.
//
// That is the reason it exists. Redirect, cookie, auth, timeout and body tests all
// state their expectations as "this header read back as exactly this string", so a
// defect in an accessor would not merely go undetected - it would silently weaken
// every one of those assertions at once. Pinning the accessors themselves closes that
// hole: the join delimiter, the key-lookup semantics, the split-and-take-first rule
// and the miss value are each asserted here as an exact string.
//
// Both accessors are deliberately narrower than HTTP field semantics, and both
// divergences are asserted AS MEASURED rather than corrected. Each carries an inline
// provenance comment naming the divergence, the response.go line that causes it and
// why it is pinned, so a future failure here explains itself instead of looking like a
// mystery.
//
// Everything is hermetic: the recording transport from
// common/httpx/mocktransport_test.go answers in process, so the synthetic authority
// origin.example is never resolved or dialled and no socket is bound at all. No test
// here uses t.Parallel(), matching the package convention and required because New sets
// the process-global GODEBUG variable on the HTTP/1.1 path.

// headerAccessorBody is the payload every response in this file carries. It is
// deliberately non-empty, so a header that reads back as the empty string cannot be
// confused with a response that failed to arrive, and it is a fixed literal, so the raw
// response dump the join test reads stays byte-for-byte deterministic.
const headerAccessorBody = "header accessor body"

// headerAccessorResponse drives exactly one hermetic GET through the shared recording
// transport and returns the parsed Response whose Headers are a clone of hdr.
//
// Each call builds its own client and its own transport, so no case can inherit or
// corrupt another case's header fixture - which matters because several cases below
// deliberately reuse the same field name with a different value shape. hdr is cloned by
// mockResponse, so the caller's map is never mutated either.
//
// The two assertions here are invariants of the drive rather than of the accessors: a
// single round trip proves no retry or redirect intervened, and a 200 proves the
// response the accessors are reading is the one the mock returned. The latter is load
// bearing for the Location case, which pairs a redirect header with a non-redirect
// status precisely so net/http leaves it alone.
func headerAccessorResponse(t *testing.T, hdr http.Header) *Response {
	t.Helper()

	mt := newMockTransport(t, func(r *http.Request) (*http.Response, error) {
		return mockResponse(r, http.StatusOK, hdr, headerAccessorBody), nil
	})
	ht := newMockHTTPX(t, nil, mt)

	// Intercepted at the transport, so this authority is never resolved or dialled.
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

// TestGetHeaderJoinsMultiValuesWithSpace pins how GetHeader collapses a repeated
// response header field into one string.
//
// PINNED DIVERGENCE - do not "fix" this. GetHeader joins the value slice with a single
// space: `strings.Join(v, " ")` at common/httpx/response.go:45. RFC 9110 §5.3 instead
// makes a repeated field equivalent to one field whose value is the COMMA-separated
// concatenation of its members, so the space join is a deliberate divergence from the
// specification. It is asserted as measured rather than corrected because it is a
// long-standing accessor contract that callers already depend on - the runner renders
// header-derived output through these very accessors (runner/runner.go:2155 reads Server
// this way) - so changing the delimiter would silently change every consumer's output.
// The expected string below was measured against the code as it stands, not copied from
// the implementation's algorithm.
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

	// Protocol-visible evidence that the wire really carried two separate field lines
	// while the accessor returns one string. The dump writes header keys in sorted order
	// and preserves each key's value order, so this substring is deterministic.
	require.Contains(t, resp.RawHeaders, "Set-Cookie: a=1; Path=/\r\nSet-Cookie: b=2; Path=/\r\n",
		"the origin's two Set-Cookie field lines must appear separately, and in order, in the raw response")

	got := resp.GetHeader("Set-Cookie")
	require.Equal(t, "a=1; Path=/ b=2; Path=/", got,
		"GetHeader joins the value slice with a single space (response.go:45), not with the RFC 9110 §5.3 comma")
	require.NotContains(t, got, ", ",
		"a comma-space delimiter would mean the RFC join had been adopted; the pinned contract is the space join")
}

// TestGetHeaderIsCaseSensitive pins that both accessors are raw, case-sensitive map
// reads rather than HTTP-aware field lookups.
//
// PINNED DIVERGENCE - do not "fix" this. Response.Headers is a plain
// map[string][]string (common/httpx/response.go:15), not an http.Header, and GetHeader
// reads it directly with `v, ok := r.Headers[name]` (response.go:43). No
// textproto.CanonicalMIMEHeaderKey is applied on the way in, so the case-insensitive
// field-name matching that RFC 9110 §5.1 requires - and that http.Header.Get provides -
// does not hold here. The map is populated from httpresp.Header.Clone()
// (common/httpx/httpx.go:275), whose keys the wire reader has already canonicalized, so
// the canonical MIME spelling is the only spelling that can hit. Asserted as measured
// rather than corrected: the case-sensitive read is a long-standing contract and every
// caller passes canonical keys today.
//
// This test is therefore the guarantee behind invariant 4 of the shared harness
// (common/httpx/mocktransport_test.go): every header assertion in this package must use
// the canonical MIME spelling - "Etag", never "ETag" or "etag".
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

// TestGetHeaderPartSplitsOnSeparator pins GetHeaderPart's split-and-take-first
// contract: it space-joins the value slice, splits that string on the caller's
// separator, and returns the FIRST token only
// (`strings.Split(strings.Join(v, " "), sep)` then `tokens[0]`,
// common/httpx/response.go:54-55).
//
// Each case asserts the un-split value through GetHeader as well, so the difference
// between the two results is unambiguously attributable to the split rather than to a
// value that arrived already truncated. Every expected string was measured against the
// code as it stands.
func TestGetHeaderPartSplitsOnSeparator(t *testing.T) {
	cases := []struct {
		name string
		// key is the canonical MIME field name; values are added under it in order with
		// Header.Add, so a repeated field is expressed the way the wire expresses it.
		key    string
		values []string
		sep    string
		// wantWhole is the GetHeader result: the space-joined value, untruncated.
		wantWhole string
		// wantPart is the GetHeaderPart result for sep.
		wantPart string
		reason   string
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
			// The production media-type read: runner/runner.go:2111 and :2113 render it,
			// :2658 records it, and :2119 gates title extraction on it, so the exact
			// token this returns decides observable output.
			name:      "media type without parameters",
			key:       "Content-Type",
			values:    []string{"text/html; charset=utf-8"},
			sep:       ";",
			wantWhole: "text/html; charset=utf-8",
			wantPart:  "text/html",
			reason:    "the media type is the first token, with the RFC 9110 §8.3 charset parameter dropped",
		},
		{
			// PINNED DIVERGENCE - do not "fix" this. A semicolon is a legal query
			// character (RFC 3986 §3.4 defines query as *( pchar / "/" / "?" ), and
			// pchar admits the sub-delim ";"), so splitting a Location on ";" truncates
			// a perfectly valid URL: everything from the semicolon onwards is discarded.
			// The cause is the unconditional `tokens[0]` at response.go:55, and the
			// hazard is real rather than theoretical because the runner emits its
			// Location output field through exactly this call - runner/runner.go:2081
			// and :2083 for the CLI line, :2657 for the structured record. It is
			// asserted as measured rather than corrected: the split-and-take-first
			// behaviour is the accessor's long-standing contract, and narrowing it would
			// change output for every consumer. Documenting the hazard in the test is
			// the smaller, more honest change.
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
		{
			// The discriminating case for the join order. The separator occurs only in
			// the SECOND field line, so the first token spans both lines and contains
			// the space the join introduced. An implementation that split v[0] alone
			// would return "first" instead, which is what makes this assertion proof
			// that strings.Join precedes strings.Split at response.go:54.
			name:      "separator only in the second field line spans the space join",
			key:       "X-Accessor-Probe",
			values:    []string{"first", "second;third"},
			sep:       ";",
			wantWhole: "first second;third",
			wantPart:  "first second",
			reason:    "the token spans both field lines, proving the space join happens before the split",
		},
		{
			name:      "separator absent from the joined value returns it whole",
			key:       "X-Accessor-Probe",
			values:    []string{"first", "second;third"},
			sep:       "|",
			wantWhole: "first second;third",
			wantPart:  "first second;third",
			reason:    "strings.Split yields a single-element slice when the separator is absent, so tokens[0] is the entire joined value",
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

// TestGetHeaderMissingReturnsEmpty pins the miss value of both accessors: the empty
// string, from `return ""` at common/httpx/response.go:47 for GetHeader and :58 for
// GetHeaderPart, the latter additionally guarded by `ok && len(v) > 0` at :53.
//
// Because a miss is a value and not an error, absence is asserted throughout this
// package as empty-string equality THROUGH the accessor - never as a nil check and never
// as a bare non-emptiness assertion, either of which would pass under a defect that
// returned a wrong-but-non-empty string. This test is the reference for that idiom, and
// it includes a hit as a control so the empty strings below cannot be explained away by
// an empty header map.
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
