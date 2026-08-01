package httpx

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// defaultUserAgentLiteral is an independent expectation for the client's default
// wire identity. Do not derive it from DefaultOptions, or a configuration change
// would update both input and expectation.
const defaultUserAgentLiteral = "httpx - Open-source project (github.com/projectdiscovery/httpx)"

// newRequestFixture returns a minimal HTTPX whose Options are a value copy of
// DefaultOptions. Request construction reads only Unsafe and DefaultUserAgent;
// RandomAgent is applied by SetCustomHeaders, so constructor User-Agent values
// remain deterministic.
func newRequestFixture(t *testing.T, unsafe bool) *HTTPX {
	t.Helper()
	options := DefaultOptions
	options.Unsafe = unsafe
	return &HTTPX{Options: &options}
}

// TestNewRequestURLEncoding verifies the exact request target, decoded path, query,
// and authority for URL forms prone to lossy re-encoding.
func TestNewRequestURLEncoding(t *testing.T) {
	h := newRequestFixture(t, false)

	cases := []struct {
		name           string
		input          string
		wantRequestURI string
		wantRawQuery   string
		wantPath       string
		wantHost       string
		// wantURLString is asserted only when non-empty. It is the optional display
		// form, which may differ from RequestURI by retaining a fragment or a
		// decoded path.
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
			// Preserve %2F in RequestURI while Path exposes /p/q (RFC 3986 §2.2 — a
			// percent-encoded reserved character is not equivalent to its decoded
			// form); also preserve repeated-key order and the original query encoding.
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
			// projectdiscovery/utils v0.11.1 omits '=' for empty values unless
			// IncludeEquals is set, so "?empty=&flag" becomes "?empty&flag". RFC 3986
			// §3.4 permits the explicit empty value; this test pins the dependency's
			// current lossy behavior so an upstream change is visible.
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
			// Fragments are not sent in the request target (RFC 9110 §7.1), but the
			// parsed URL retains #frag in its display form.
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
			req, err := h.NewRequest(http.MethodGet, tc.input)
			require.NoError(t, err, "constructing a request for %q must succeed", tc.input)

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

			// NewRequestFromURLWithContext shares one *url.URL between its wrappers;
			// pin that alias so these assertions inspect the object net/http sends.
			require.Same(t, req.Request.URL, parsed.URL,
				"the inspected *url.URL must be the same instance net/http writes on the wire")
		})
	}
}

// TestNewRequestInjectsUserAgentAndAcceptCharset verifies the exact single-value
// default headers on safe requests and their absence on unsafe requests. The
// User-Agent expectation is independent of DefaultOptions; RandomAgent does not
// affect constructors because it is applied only by SetCustomHeaders. Accept-Charset
// is pinned as lowercase "utf-8" (charset names are case-insensitive per RFC 2978
// §2.3, but the bytes on the wire are not).
func TestNewRequestInjectsUserAgentAndAcceptCharset(t *testing.T) {
	t.Run("safe requests carry the default user agent and charset", func(t *testing.T) {
		h := newRequestFixture(t, false)

		require.Equal(t, defaultUserAgentLiteral, DefaultOptions.DefaultUserAgent,
			"the configured default agent must still be the identity this client advertises")
		require.Equal(t, defaultUserAgentLiteral, h.Options.DefaultUserAgent,
			"the fixture must carry the configured default through unchanged, not a value of its own")

		req, err := h.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/")
		require.NoError(t, err)

		require.Equal(t, defaultUserAgentLiteral, req.Header.Get("User-Agent"),
			"the exact configured default agent must reach the wire")
		require.Equal(t, []string{defaultUserAgentLiteral}, req.Header.Values("User-Agent"),
			"User-Agent is applied with Set, so exactly one value may reach the wire")
		require.Equal(t, []string{"utf-8"}, req.Header.Values("Accept-Charset"),
			`Accept-Charset is added as the lowercase literal "utf-8"`)
		require.Equal(t, http.MethodGet, req.Method,
			"the requested method must be forwarded unchanged")
		require.Equal(t, "/", req.URL.RequestURI(),
			"a bare root URL must produce the root request-target")
	})

	t.Run("unsafe requests receive no default headers", func(t *testing.T) {
		// Construct only; sending an unsafe request bypasses the safe client path and
		// may reach the network.
		h := newRequestFixture(t, true)

		req, err := h.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/")
		require.NoError(t, err)

		require.Empty(t, req.Header.Values("User-Agent"),
			"unsafe mode must not inject a User-Agent")
		require.Empty(t, req.Header.Values("Accept-Charset"),
			"unsafe mode must not inject an Accept-Charset")
		require.Equal(t, "", req.Header.Get("User-Agent"),
			"absence is pinned as the empty string, not as a nil check")
		require.Empty(t, req.Header,
			"no default header at all is stamped on a raw request")
		require.Equal(t, "/", req.URL.RequestURI(),
			"the request-target is still built normally in unsafe mode")
	})
}

// TestNewRequestContextVariantParity verifies that the context-free constructor
// produces the same method, request target, authority, and default headers as
// NewRequestWithContext. Literal expectations on both variants prevent vacuous
// equality.
func TestNewRequestContextVariantParity(t *testing.T) {
	h := newRequestFixture(t, false)
	const target = "http://example.com/path?a=1&a=2"

	reqA, err := h.NewRequest(http.MethodGet, target)
	require.NoError(t, err, "context-free constructor must succeed")

	reqB, err := h.NewRequestWithContext(context.Background(), http.MethodGet, target)
	require.NoError(t, err, "context-bearing constructor must succeed")

	parsedA, parsedB := reqA.URL, reqB.URL

	require.Equal(t, http.MethodGet, reqA.Method, "context-free variant method")
	require.Equal(t, http.MethodGet, reqB.Method, "context-bearing variant method")
	require.Equal(t, reqB.Method, reqA.Method, "both variants must forward the same method")

	require.Equal(t, "/path?a=1&a=2", parsedA.RequestURI(), "context-free variant request-target")
	require.Equal(t, "/path?a=1&a=2", parsedB.RequestURI(), "context-bearing variant request-target")
	require.Equal(t, parsedB.RequestURI(), parsedA.RequestURI(),
		"both variants must produce a byte-identical request-target")

	require.Equal(t, "a=1&a=2", parsedA.RawQuery, "context-free variant raw query")
	require.Equal(t, "a=1&a=2", parsedB.RawQuery, "context-bearing variant raw query")

	require.Equal(t, "example.com", parsedA.Host, "context-free variant authority")
	require.Equal(t, "example.com", parsedB.Host, "context-bearing variant authority")
	require.Equal(t, parsedB.Host, parsedA.Host, "both variants must target the same authority")

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

	// Failure propagation belongs to the same delegation contract: NewRequest returns
	// whatever NewRequestWithContext produced, so a construction failure must surface
	// identically through both variants and must never be paired with a usable request.
	// These two inputs reach the constructor's only error returns - URL parsing
	// (common/httpx/httpx.go:467) and request construction (:472) - which no encoding
	// case can trigger, and their distinct concrete types identify which step failed.
	t.Run("both variants propagate construction failures identically", func(t *testing.T) {
		failures := []struct {
			name      string
			method    string
			target    string
			wantType  string
			wantError string
		}{
			{
				// An unterminated IPv6 literal cannot be parsed, so urlutil.ParseURL
				// fails before a request object exists. It reports through
				// projectdiscovery/utils errkit, which renders the net/url cause
				// alongside its own chain label; both are pinned as measured because the
				// dependency version is fixed.
				name:      "unparseable authority fails url parsing",
				method:    http.MethodGet,
				target:    "http://[::1",
				wantType:  "*errkit.ErrorX",
				wantError: `cause="missing ']' in host" chain="failed to parse url"`,
			},
			{
				// A method carrying a space is not a valid token (RFC 9110 §9.1), so the
				// URL parses cleanly and retryablehttp rejects the method instead. The
				// plain error type is what distinguishes this return from the one above.
				name:      "method with a space fails request construction",
				method:    "BAD METHOD",
				target:    "http://example.com/",
				wantType:  "*errors.errorString",
				wantError: `net/http: invalid method "BAD METHOD"`,
			},
		}

		for _, fc := range failures {
			t.Run(fc.name, func(t *testing.T) {
				reqCtx, errCtx := h.NewRequestWithContext(context.Background(), fc.method, fc.target)
				require.Nil(t, reqCtx, "no request may be handed back alongside an error")
				require.EqualError(t, errCtx, fc.wantError,
					"the context-bearing variant must report the exact construction failure")
				require.Equal(t, fc.wantType, fmt.Sprintf("%T", errCtx),
					"the concrete error type names which constructor step rejected the input")

				reqFree, errFree := h.NewRequest(fc.method, fc.target)
				require.Nil(t, reqFree, "the delegating variant must not return a request either")
				require.EqualError(t, errFree, fc.wantError,
					"the context-free variant must propagate the identical failure text")
				require.Equal(t, fc.wantType, fmt.Sprintf("%T", errFree),
					"delegation must forward the error untouched rather than rewrap it")
			})
		}
	})
}
