package httpx

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// defaultUserAgentLiteral is the exact User-Agent string that
// DefaultOptions.DefaultUserAgent carries (common/httpx/option.go:95). It is
// spelled out here rather than referenced through DefaultOptions so that a
// silent edit to the option default is caught by these tests instead of being
// absorbed by them: comparing the header against the very constant that
// produced it would assert nothing about the client's identity on the wire.
const defaultUserAgentLiteral = "httpx - Open-source project (github.com/projectdiscovery/httpx)"

// newRequestFixture builds the minimal HTTPX receiver that the two request
// constructors actually need.
//
// NewRequest (common/httpx/httpx.go:456-459) and NewRequestWithContext
// (:462-480) read exactly two option fields — Options.Unsafe (:463, :473) and
// Options.DefaultUserAgent (:475). They never touch the transport, the dialer,
// the CDN client or the network, so the receiver is constructed as a literal
// instead of through New(). That is the idiom already used at
// common/httpx/httpx_test.go:34 (&HTTPX{Options: &Options{}}), it keeps this
// whole file free of I/O, and it avoids allocating a fastdialer that nothing
// here would use.
//
// It also makes the User-Agent assertions DETERMINISTIC. DefaultOptions.RandomAgent
// is true (common/httpx/option.go:79), but RandomAgent is consumed only inside
// SetCustomHeaders (common/httpx/httpx.go:510-513) and is never read by either
// constructor, so the injected agent is always Options.DefaultUserAgent verbatim.
// Building the receiver literally guarantees no other default can perturb that.
func newRequestFixture(t *testing.T, unsafe bool) *HTTPX {
	t.Helper()
	return &HTTPX{Options: &Options{
		Unsafe:           unsafe,
		DefaultUserAgent: defaultUserAgentLiteral,
	}}
}

// TestNewRequestURLEncoding pins the protocol-visible request target that
// HTTPX.NewRequest produces for six URL shapes where a naive re-encode is a
// plausible regression: a space in the path versus a space in the query, a
// percent-encoded slash, empty path segments, an empty parameter value, an
// explicit port with a literal '+', and a fragment.
//
// The load-bearing assertion in every case is URL.RequestURI(): that is the
// request-target that net/http writes onto the request line, so it is exactly
// what an observer on the wire sees. RawQuery, the decoded Path and the
// authority are asserted alongside it because the same defect class (a lossy
// re-encode) shows up differently in each of them — a probe of one endpoint
// silently becoming a probe of another is the failure this test exists to catch.
//
// Every expected value below was measured against the current code before it
// was written here; where the measured value diverges from the specification
// the divergence is named inline rather than smoothed over.
func TestNewRequestURLEncoding(t *testing.T) {
	h := newRequestFixture(t, false)

	cases := []struct {
		name           string
		input          string
		wantRequestURI string
		wantRawQuery   string
		wantPath       string
		wantHost       string
		// wantURLString is asserted only when non-empty. It pins
		// urlutil.URL.String(), which is a DISPLAY form, not the wire form:
		// it is rebuilt from the decoded Path and it re-appends the fragment
		// (github.com/projectdiscovery/utils@v0.11.1/url/url.go:96-108). The
		// runner logs that form while the transport sends RequestURI(), so the
		// two are pinned together where they deliberately disagree.
		wantURLString string
	}{
		{
			// A space is percent-encoded in the path but '+'-encoded in the
			// query, because the two components use different encodings
			// (RFC 3986 §3.3 path vs. application/x-www-form-urlencoded query).
			// Path stays decoded for callers while the wire form is escaped.
			name:           "space is percent-encoded in the path and plus-encoded in the query",
			input:          "http://example.com/a b?x=1&y=hello world",
			wantRequestURI: "/a%20b?x=1&y=hello+world",
			wantRawQuery:   "x=1&y=hello+world",
			wantPath:       "/a b",
			wantHost:       "example.com",
		},
		{
			// The whole point of this case: a pre-encoded slash MUST survive on
			// the wire as %2F (RFC 3986 §2.2 — a percent-encoded reserved
			// character is not equivalent to its decoded form), while the
			// caller-facing Path is the decoded "/p/q". A naive re-encode would
			// flatten one into the other and change the resource requested.
			// The repeated key "z" keeps its original order, and %20 inside a
			// query value is left as-is rather than rewritten to '+'.
			name:           "percent-encoded slash is preserved on the wire but decoded in path",
			input:          "http://example.com/p%2Fq?z=%20&z=2",
			wantRequestURI: "/p%2Fq?z=%20&z=2",
			wantRawQuery:   "z=%20&z=2",
			wantPath:       "/p/q",
			wantHost:       "example.com",
			// String() is built from the DECODED path, so it loses the %2F that
			// the request line keeps. Pinned so the display/wire split stays visible.
			wantURLString: "http://example.com/p/q?z=%20&z=2",
		},
		{
			// Empty path segments are significant to an origin server and must
			// not be normalized away (RFC 3986 §3.3 permits empty segments;
			// §6.2.2 dot-segment removal does not collapse "//").
			name:           "empty path segments are not collapsed",
			input:          "http://example.com//double//slash?a=1&a=2",
			wantRequestURI: "//double//slash?a=1&a=2",
			wantRawQuery:   "a=1&a=2",
			wantPath:       "//double//slash",
			wantHost:       "example.com",
		},
		{
			// DIVERGENCE (pinned as measured, deliberately NOT fixed).
			//
			// "?empty=&flag" is normalized to "?empty&flag": the '=' that
			// separates the key from its explicitly empty value is DROPPED.
			// RFC 3986 §3.4 places no such restriction on a query component, and
			// an origin server is entitled to distinguish "empty=" from "empty",
			// so this is a genuine, lossy divergence and not merely a stylistic one.
			//
			// Cause: it happens upstream, inside urlutil.ParseURL
			// (common/httpx/httpx.go:463) — specifically
			// github.com/projectdiscovery/utils@v0.11.1/url/orderedparams.go:108-112,
			// where the encoder guards the '=' with
			// `if o.IncludeEquals || value != ""` under the comment
			// "donot specify = if parameter has no value". It is therefore a
			// deliberate behavior of a PINNED dependency (go.mod:38), not of this
			// repository, and fixing it is out of scope: the engagement forbids
			// modifying non-test source, and this code is not even in this module.
			//
			// It is asserted as measured so that a future upstream correction (or
			// a dependency bump that changes the default) fails loudly here
			// instead of being silently absorbed.
			name:           "empty parameter value loses its equals sign",
			input:          "http://example.com/?empty=&flag",
			wantRequestURI: "/?empty&flag",
			wantRawQuery:   "empty&flag",
			wantPath:       "/",
			wantHost:       "example.com",
		},
		{
			// An explicit non-default port is part of the origin (RFC 9110
			// §4.3.1) and must be retained in the authority. A literal '+' in a
			// query value is a legal sub-delim (RFC 3986 §3.4) and must not be
			// re-escaped to %2B, which would change the value the server decodes.
			name:           "explicit port is retained and a literal plus survives in the query",
			input:          "http://example.com:8080/path?q=a+b",
			wantRequestURI: "/path?q=a+b",
			wantRawQuery:   "q=a+b",
			wantPath:       "/path",
			wantHost:       "example.com:8080",
		},
		{
			// A fragment is client-side only and is never transmitted
			// (RFC 9110 §7.1 — the request target carries no fragment), so the
			// request line collapses to "/" with an empty query. The parsed URL
			// still remembers it, which is why the display form below retains
			// "#frag": the assertion pair proves the fragment is dropped from the
			// wire WITHOUT being lost from the object.
			name:           "fragment is not transmitted in the request line",
			input:          "http://example.com/#frag",
			wantRequestURI: "/",
			wantRawQuery:   "",
			wantPath:       "/",
			wantHost:       "example.com",
			wantURLString:  "http://example.com/#frag",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The context-free constructor is used deliberately: it is pure
			// delegation (common/httpx/httpx.go:456-459), so driving the table
			// through it exercises both constructors at once.
			req, err := h.NewRequest(http.MethodGet, tc.input)
			require.NoError(t, err, "constructing a request for %q must succeed", tc.input)

			// retryablehttp.Request embeds BOTH *http.Request and *urlutil.URL
			// (retryablehttp-go@v1.3.18/request.go:24-37), so req.URL is the urlutil
			// wrapper, which in turn embeds the standard library's *url.URL. Binding
			// it once keeps the assertions below reading from one unambiguous object.
			parsed := req.URL

			require.Equal(t, tc.wantRequestURI, parsed.RequestURI(),
				"request-target written on the wire for %q", tc.input)
			require.Equal(t, tc.wantRawQuery, parsed.RawQuery,
				"raw query sent verbatim for %q (absence is asserted as the empty string)", tc.input)
			require.Equal(t, tc.wantPath, parsed.Path,
				"decoded path exposed to callers for %q", tc.input)
			require.Equal(t, tc.wantHost, parsed.Host,
				"authority targeted for %q (host plus explicit port)", tc.input)

			if tc.wantURLString != "" {
				require.Equal(t, tc.wantURLString, parsed.String(),
					"display form for %q, which deliberately differs from the request-target", tc.input)
			}

			// NewRequestFromURLWithContext assigns httpReq.URL = urlx.URL
			// (request.go:349), which makes the urlutil wrapper and the embedded
			// *http.Request share ONE *url.URL. Pinning that aliasing proves the
			// object asserted above is the object net/http serializes; without it a
			// future upstream change could decouple them and leave every assertion
			// in this table inspecting a URL that is never sent.
			require.Same(t, req.Request.URL, parsed.URL,
				"the inspected *url.URL must be the same instance net/http writes on the wire")
		})
	}
}

// TestNewRequestInjectsUserAgentAndAcceptCharset pins the default headers that
// NewRequestWithContext stamps onto every non-raw request
// (common/httpx/httpx.go:473-478) — the client's identity on the wire.
//
// Two facts are asserted as protocol-visible outcomes rather than as "a header
// exists":
//
//   - ARITY. Each header must carry EXACTLY ONE value, so the whole value slice
//     is asserted rather than just Get(). Get() returns the first value and would
//     stay green if a second User-Agent or Accept-Charset were appended anywhere
//     in the construction path, while a duplicated header is very much visible on
//     the wire. Measured note: on a freshly built request the header map starts
//     empty (see the unsafe sub-test below), so Set (:475) and Add (:477) are
//     observationally equivalent here — which is precisely why these assertions
//     pin arity and exact bytes rather than claiming to identify which method ran.
//   - EXACT BYTES. Accept-Charset's value is the LOWERCASE literal "utf-8", not
//     "UTF-8". Charset names are case-insensitive per RFC 2978 §2.3, but the bytes
//     placed on the wire are not, and this pins the bytes.
//
// The agent string itself is DETERMINISTIC here even though
// DefaultOptions.RandomAgent is true (common/httpx/option.go:79): RandomAgent is
// read only by SetCustomHeaders (common/httpx/httpx.go:510-513), never by either
// constructor. The expected value is the exact literal from
// common/httpx/option.go:95.
//
// The negative case pins the other side of the :473 guard: in unsafe mode the
// injection is skipped entirely, so the header set is empty. Absence is asserted
// as an exact empty value rather than as a nil check. Only construction happens
// — an unsafe request is never issued, because sending one would leave this
// package's transport seam and reach the network.
func TestNewRequestInjectsUserAgentAndAcceptCharset(t *testing.T) {
	t.Run("safe requests carry the default user agent and charset", func(t *testing.T) {
		h := newRequestFixture(t, false)

		req, err := h.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/")
		require.NoError(t, err)

		require.Equal(t, defaultUserAgentLiteral, req.Header.Get("User-Agent"),
			"the exact default agent from option.go:95 must reach the wire")
		require.Equal(t, []string{defaultUserAgentLiteral}, req.Header.Values("User-Agent"),
			"User-Agent is applied once with Set (httpx.go:475), so exactly one value may reach the wire")
		require.Equal(t, []string{"utf-8"}, req.Header.Values("Accept-Charset"),
			`Accept-Charset is added as the lowercase literal "utf-8" (httpx.go:477)`)
		require.Equal(t, http.MethodGet, req.Method,
			"the requested method must be forwarded unchanged")
		require.Equal(t, "/", req.URL.RequestURI(),
			"a bare root URL must produce the root request-target")
	})

	t.Run("unsafe requests receive no default headers", func(t *testing.T) {
		// Construction only: httpx.go:473 skips the injection when Unsafe is set.
		// The unsafe SEND path (doUnsafeWithOptions, httpx.go:420-428) goes out to
		// the network and is deliberately never invoked here.
		h := newRequestFixture(t, true)

		req, err := h.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/")
		require.NoError(t, err)

		require.Empty(t, req.Header.Values("User-Agent"),
			"unsafe mode must not inject a User-Agent (httpx.go:473 guard)")
		require.Empty(t, req.Header.Values("Accept-Charset"),
			"unsafe mode must not inject an Accept-Charset (httpx.go:473 guard)")
		require.Equal(t, "", req.Header.Get("User-Agent"),
			"absence is pinned as the empty string, not as a nil check")
		require.Empty(t, req.Header,
			"no default header at all is stamped on a raw request")
		require.Equal(t, "/", req.URL.RequestURI(),
			"the request-target is still built normally in unsafe mode")
	})
}

// TestNewRequestContextVariantParity pins the parity axis this client actually
// exposes. It has no async duplicate of its request API — Go does not need one —
// so the two variants of the same operation are the context-free constructor
// (common/httpx/httpx.go:456-459) and the context-bearing one (:462-480).
//
// NewRequest is pure delegation to NewRequestWithContext(context.Background(), …),
// so parity is structural today. This test pins that structure: if a future change
// gave one variant its own construction path — a different parse mode, a skipped
// default-header injection, a rewritten target — the divergence fails here
// immediately instead of shipping as a silently different request on the wire.
//
// Anti-vacuity: comparing variant A against variant B alone would pass if both
// produced nothing at all. Every parity comparison below is therefore paired
// with the literal expected value, so the test cannot succeed vacuously.
//
// Context CANCELLATION behavior is deliberately not asserted here; that axis
// belongs to the timeout tests, and duplicating it would add no sensitivity.
func TestNewRequestContextVariantParity(t *testing.T) {
	h := newRequestFixture(t, false)
	const target = "http://example.com/path?a=1&a=2"

	reqA, err := h.NewRequest(http.MethodGet, target)
	require.NoError(t, err, "context-free constructor must succeed")

	reqB, err := h.NewRequestWithContext(context.Background(), http.MethodGet, target)
	require.NoError(t, err, "context-bearing constructor must succeed")

	// Bind each variant's parsed URL once, for the same reason as in
	// TestNewRequestURLEncoding: req.URL is the *urlutil.URL wrapper that
	// retryablehttp.Request embeds alongside *http.Request.
	parsedA, parsedB := reqA.URL, reqB.URL

	// Method: pinned to the literal on both sides, then compared.
	require.Equal(t, http.MethodGet, reqA.Method, "context-free variant method")
	require.Equal(t, http.MethodGet, reqB.Method, "context-bearing variant method")
	require.Equal(t, reqB.Method, reqA.Method, "both variants must forward the same method")

	// Request-target: the repeated key "a" keeps its order in both variants.
	require.Equal(t, "/path?a=1&a=2", parsedA.RequestURI(), "context-free variant request-target")
	require.Equal(t, "/path?a=1&a=2", parsedB.RequestURI(), "context-bearing variant request-target")
	require.Equal(t, parsedB.RequestURI(), parsedA.RequestURI(),
		"both variants must produce a byte-identical request-target")

	require.Equal(t, "a=1&a=2", parsedA.RawQuery, "context-free variant raw query")
	require.Equal(t, "a=1&a=2", parsedB.RawQuery, "context-bearing variant raw query")

	// Authority.
	require.Equal(t, "example.com", parsedA.Host, "context-free variant authority")
	require.Equal(t, "example.com", parsedB.Host, "context-bearing variant authority")
	require.Equal(t, parsedB.Host, parsedA.Host, "both variants must target the same authority")

	// Default header injection must happen on BOTH paths, with identical values.
	require.Equal(t, []string{defaultUserAgentLiteral}, reqA.Header.Values("User-Agent"),
		"context-free variant must inject the default agent exactly once")
	require.Equal(t, []string{defaultUserAgentLiteral}, reqB.Header.Values("User-Agent"),
		"context-bearing variant must inject the default agent exactly once")
	require.Equal(t, []string{"utf-8"}, reqA.Header.Values("Accept-Charset"),
		"context-free variant must add the lowercase charset")
	require.Equal(t, []string{"utf-8"}, reqB.Header.Values("Accept-Charset"),
		"context-bearing variant must add the lowercase charset")
	require.Equal(t, http.Header{
		"User-Agent":     {defaultUserAgentLiteral},
		"Accept-Charset": {"utf-8"},
	}, reqA.Header, "the context-free variant's complete header set, pinned literally")
	require.Equal(t, reqB.Header, reqA.Header,
		"both constructors must inject the identical default header set")
}
