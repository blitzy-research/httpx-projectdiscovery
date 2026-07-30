package httpx

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/httpx/common/authprovider/authx"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestDo(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	t.Run("content-length in header", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://scanme.sh", nil)
		require.Nil(t, err)
		resp, err := ht.Do(req, UnsafeOptions{})
		require.Nil(t, err)
		require.Equal(t, 2, resp.ContentLength)
	})

	t.Run("content-length with binary body", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://www.w3schools.com/images/favicon.ico", nil)
		require.Nil(t, err)
		resp, err := ht.Do(req, UnsafeOptions{})
		require.Nil(t, err)
		require.Greater(t, len(resp.Raw), 800)
	})
}

func TestSetCustomHeaders(t *testing.T) {
	h := &HTTPX{Options: &Options{}}

	t.Run("duplicate values preserved in order", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		h.SetCustomHeaders(req, map[string][]string{"X-Test": {"one", "two"}})
		require.Equal(t, []string{"one", "two"}, req.Header.Values("X-Test"))
	})

	t.Run("case-variant duplicates are coalesced", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		h.SetCustomHeaders(req, map[string][]string{"X-Test": {"one"}, "x-test": {"two"}})
		require.ElementsMatch(t, []string{"one", "two"}, req.Header.Values("X-Test"))
	})

	t.Run("custom header replaces existing value", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		req.Header.Set("User-Agent", "default-agent")
		h.SetCustomHeaders(req, map[string][]string{"User-Agent": {"custom-agent"}})
		require.Equal(t, []string{"custom-agent"}, req.Header.Values("User-Agent"))
	})

	t.Run("host header sets request host", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		h.SetCustomHeaders(req, map[string][]string{"Host": {"custom.host"}})
		require.Equal(t, "custom.host", req.Host)
		require.Empty(t, req.Header.Values("Host"))
	})

	t.Run("multiple distinct headers preserved", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		h.SetCustomHeaders(req, map[string][]string{"X-One": {"1"}, "X-Two": {"2"}})
		require.Equal(t, []string{"1"}, req.Header.Values("X-One"))
		require.Equal(t, []string{"2"}, req.Header.Values("X-Two"))
	})

	t.Run("multiple cookie values preserved", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		h.SetCustomHeaders(req, map[string][]string{"Cookie": {"a=1", "b=2"}})
		require.Equal(t, []string{"a=1", "b=2"}, req.Header.Values("Cookie"))
	})

	t.Run("empty value applied as-is", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		h.SetCustomHeaders(req, map[string][]string{"X-Empty": {""}})
		require.Equal(t, []string{""}, req.Header.Values("X-Empty"))
	})

	t.Run("unsafe raw header line stored verbatim as key", func(t *testing.T) {
		hu := &HTTPX{Options: &Options{Unsafe: true}}
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		// in unsafe mode the runner stores the whole raw header line as the key
		// with an empty value; it must survive canonicalization untouched
		hu.SetCustomHeaders(req, map[string][]string{"X-Test: one": {""}})
		require.Equal(t, []string{""}, req.Header.Values("X-Test: one"))
	})
}

func TestParseCustomCookies(t *testing.T) {
	options := &Options{CustomHeaders: map[string][]string{"Cookie": {"a=1", "b=2"}}}
	options.parseCustomCookies()
	require.True(t, options.hasCustomCookies())
	require.Len(t, options.customCookies, 2)
}

func TestHTTP11DisablesRetryableHTTP2FallbackClient(t *testing.T) {
	options := DefaultOptions
	options.Protocol = HTTP11

	ht, err := New(&options)
	require.NoError(t, err)
	require.NotNil(t, ht.client)
	require.Same(t, ht.client.HTTPClient, ht.client.HTTPClient2)
}

func TestDefaultProtocolKeepsRetryableHTTP2FallbackClient(t *testing.T) {
	options := DefaultOptions

	ht, err := New(&options)
	require.NoError(t, err)
	require.NotNil(t, ht.client)
	require.NotSame(t, ht.client.HTTPClient, ht.client.HTTPClient2)
}

type blockingReadCloser struct{}

func (*blockingReadCloser) Read([]byte) (int, error) {
	select {}
}

func (*blockingReadCloser) Close() error {
	return nil
}

type switchingProtocolsRoundTripper struct{}

func (switchingProtocolsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		Status:     "101 Switching Protocols",
		StatusCode: http.StatusSwitchingProtocols,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Upgrade":    {"websocket"},
			"Connection": {"Upgrade"},
		},
		Body:    &blockingReadCloser{},
		Request: req,
	}, nil
}

func TestDoSwitchingProtocolsDoesNotHang(t *testing.T) {
	options := DefaultOptions
	options.CdnCheck = "false"
	options.Timeout = 2 * time.Second
	options.RetryMax = 0

	ht, err := New(&options)
	require.NoError(t, err)

	rt := switchingProtocolsRoundTripper{}
	ht.client.HTTPClient.Transport = rt
	ht.client.HTTPClient2.Transport = rt

	req, err := retryablehttp.NewRequest(http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		_, _ = ht.Do(req, UnsafeOptions{})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("Do hung on 101 Switching Protocols response")
	}
}

// TestDoSwitchingProtocolsProtocolVisibleOutcome verifies that a 101 response
// preserves its status and upgrade headers while exposing no HTTP response body.
func TestDoSwitchingProtocolsProtocolVisibleOutcome(t *testing.T) {
	options := DefaultOptions
	options.CdnCheck = "false"
	options.Timeout = 2 * time.Second
	options.RetryMax = 0

	ht, err := New(&options)
	require.NoError(t, err)

	// Install the mock on both retryable transports because malformed HTTP/1.x
	// responses may fall back to HTTPClient2.
	rt := switchingProtocolsRoundTripper{}
	ht.client.HTTPClient.Transport = rt
	ht.client.HTTPClient2.Transport = rt

	// Intercepted by the round tripper above, so this host is never resolved or dialled.
	req, err := retryablehttp.NewRequest(http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)

	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err)

	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode,
		"the 101 must reach the caller verbatim, not be normalized to 200 or dropped")

	// After the 101 headers, subsequent bytes belong to the upgraded protocol, not an
	// HTTP response body.
	require.Empty(t, resp.Data, "no body may be read for a protocol switch")
	require.Empty(t, resp.RawData, "no undecoded body may be retained for a protocol switch")
	require.Equal(t, 0, resp.ContentLength,
		"with no Content-Length header and no body the recomputation must leave the length at 0")
	require.Equal(t, 0, resp.Words, "word count is derived from the body, which was never read")
	require.Equal(t, 0, resp.Lines, "line count is derived from the body, which was never read")

	require.Equal(t, "websocket", resp.GetHeader("Upgrade"),
		"the negotiated protocol must survive to the caller")
	require.Equal(t, "Upgrade", resp.GetHeader("Connection"),
		"the hop-by-hop upgrade signal must survive to the caller")
	require.Equal(t, "", resp.GetHeader("Content-Length"),
		"a header the origin never sent must read back as the empty string")

	// projectdiscovery/utils v0.11.1 synthesizes 100-103 dumps from resp.Status and a
	// map iteration over headers, using LF separators and Go slice formatting. Header
	// order is nondeterministic, so assert the status line and header set separately;
	// Raw and RawHeaders are identical because the helper returns the same buffer for
	// both.
	require.Equal(t, 67, len(resp.Raw),
		"24-byte status line plus 21-byte Upgrade line plus 22-byte Connection line")
	require.Equal(t, resp.RawHeaders, resp.Raw,
		"the 1xx branch returns a single buffer for both, so Raw carries no body section")

	rawLines := strings.Split(strings.TrimSuffix(resp.Raw, "\n"), "\n")
	require.Len(t, rawLines, 3, "one status line plus exactly the two headers the origin sent")
	require.Equal(t, "101 Switching Protocols", rawLines[0],
		"the first line is the Status field verbatim, without the protocol version prefix")
	require.ElementsMatch(t, []string{"Upgrade: [websocket]", "Connection: [Upgrade]"}, rawLines[1:],
		"each header line is rendered with Go slice syntax around the value")
	require.NotContains(t, resp.Raw, "HTTP/1.1 101",
		"proves the dump is the synthetic 1xx rendering, not a real HTTP status line")
	require.NotContains(t, resp.Raw, "\r\n",
		"the synthetic dump is LF-joined, unlike the CRLF framing of real wire format")
}

// TestSetCustomCookiesPreservesUnrelatedCookiesAcrossRedirect pins the credential
// integrity contract of setCustomCookies (common/httpx/httpx.go:522-549): the configured
// cookies are applied exactly once per hop, and every OTHER cookie the request already
// carries survives that application.
//
// This is a security regression test, and the scenario it drives is the production one.
// Both follow closures call the cookie injector on every redirected request
// (common/httpx/httpx.go:101 for FollowRedirects, :120 for FollowHostRedirects), and
// net/http's makeHeadersCopier (net/http/client.go:809-830) copies the initial request's
// Cookie header onto every hop whose target is the same host or a subdomain
// (shouldCopyHeaderOnRedirect, net/http/client.go:1005-1022). Production builds that
// header in two steps - SetCustomHeaders writes the configured cookies
// (runner/runner.go:1900) and then a URL-scoped auth strategy appends its own
// (runner/runner.go:1902-1907) - so an injector that cleared the whole Cookie header
// before re-adding only Options.customCookies would silently drop the auth cookie and
// send the redirected request unauthenticated, reporting protected content as
// unprotected.
//
// Replacing by cookie name and preserving the rest is already this repository's contract
// for cookie replacement: authx.CookiesAuthStrategy.ApplyOnRR
// (common/authprovider/authx/cookies_auth.go:35-60) filters by name before its own
// Header.Del, and common/authprovider/authx/strategy_test.go:148-172 asserts that an
// unrelated cookie survives it.
//
// Every expectation below is an exact Cookie header string observed on the wire through
// the recording transport - never a "contains", never a non-nil check.
func TestSetCustomCookiesPreservesUnrelatedCookiesAcrossRedirect(t *testing.T) {
	// runScenario drives one two-hop chain whose first hop is a 302 to redirectTo,
	// rebuilding the outgoing request exactly the way production does, and returns the
	// per-hop snapshots the recording transport captured.
	runScenario := func(t *testing.T, redirectTo, wantBody string) []recordedRequest {
		t.Helper()

		// Synthetic authorities: they live only inside the scripted transport and are
		// never resolved or dialled. Two loopback servers could not express the
		// cross-origin case at all, because both would bind 127.0.0.1.
		mt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
			"origin.example/start": {status: http.StatusFound, location: redirectTo},
			"origin.example/next":  {status: http.StatusOK, body: "same origin target"},
			"other.example/next":   {status: http.StatusOK, body: "cross origin target"},
		}))

		ht := newMockHTTPX(t, func(options *Options) {
			options.FollowRedirects = true
			options.MaxRedirects = 10
			// Two configured cookies, supplied the way the CLI supplies them: as
			// repeated Cookie values on CustomHeaders. New turns them into
			// Options.customCookies via parseCustomCookies (common/httpx/httpx.go:78),
			// which is why the mutator must run before construction.
			options.CustomHeaders = map[string][]string{"Cookie": {"sess=abc", "id=1"}}
		}, mt)

		req, err := retryablehttp.NewRequest(http.MethodGet, "http://origin.example/start", nil)
		require.NoError(t, err)

		// Production ordering, verbatim. First the configured headers
		// (runner/runner.go:1900), which write Cookie as two separate header values.
		ht.SetCustomHeaders(req, ht.CustomHeaders)
		// Then the URL-scoped auth strategy (runner/runner.go:1902-1907). The real
		// strategy is used rather than a hand-rolled equivalent because its own
		// filter-then-re-add collapses those two values into the single header line
		// that the redirect flow later inherits - that collapsing is part of the
		// scenario, not an incidental detail.
		authx.NewCookiesAuthStrategy(&authx.Secret{
			Cookies: []authx.Cookie{{Key: "auth", Value: "token"}},
		}).ApplyOnRR(req)
		require.Equal(t, "sess=abc; id=1; auth=token", req.Header.Get("Cookie"),
			"the request must leave the production build-up carrying both configured cookies and the auth cookie")

		resp, err := ht.Do(req, UnsafeOptions{})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, "the 302 must be followed through to its target")
		require.Equal(t, []byte(wantBody), resp.Data, "the body of the redirect target must reach the caller")

		hops := mt.requests()
		require.Len(t, hops, 2, "exactly one round trip for the 302 and one for its target")
		require.Equal(t, "http://origin.example/start", hops[0].URL, "hop 1 is the original target")
		require.Equal(t, "sess=abc; id=1; auth=token", hops[0].Header.Get("Cookie"),
			"hop 1 must go out with the header exactly as the caller built it")
		return hops
	}

	t.Run("same origin redirect keeps a separately applied auth cookie", func(t *testing.T) {
		hops := runScenario(t, "/next", "same origin target")

		require.Equal(t, "http://origin.example/next", hops[1].URL,
			"the relative Location must resolve against the first hop's origin")

		// Pre-fix this read "sess=abc; id=1": the wholesale Cookie reset deleted the
		// auth cookie net/http had copied onto the same-origin hop, and the injection
		// loop restored only the configured pair. Post-fix the preserved cookie is
		// re-added first, then the two configured cookies, each exactly once.
		require.Equal(t, "auth=token; sess=abc; id=1", hops[1].Header.Get("Cookie"),
			"the unrelated auth cookie must survive the reset and the configured cookies must be applied once")
		require.Len(t, hops[1].Header.Values("Cookie"), 1,
			"AddCookie must leave a single Cookie header line, not one line per cookie")
		require.Equal(t, 1, strings.Count(hops[1].Header.Get("Cookie"), "sess=abc"),
			"the first configured cookie must appear exactly once, not be duplicated per hop")
		require.Equal(t, 1, strings.Count(hops[1].Header.Get("Cookie"), "id=1"),
			"the second configured cookie must appear exactly once")
		require.Equal(t, 1, strings.Count(hops[1].Header.Get("Cookie"), "auth=token"),
			"the preserved auth cookie must appear exactly once")
	})

	t.Run("cross origin redirect is not widened", func(t *testing.T) {
		hops := runScenario(t, "http://other.example/next", "cross origin target")

		require.Equal(t, "http://other.example/next", hops[1].URL,
			"the absolute Location must be taken verbatim, origin change included")

		// net/http strips Cookie when the redirect leaves the origin
		// (shouldCopyHeaderOnRedirect, net/http/client.go:1005-1022), so there is
		// nothing to preserve and only the configured cookies are injected. Preserving
		// unrelated cookies must not resurrect a credential the standard library
		// deliberately withheld from the new origin.
		require.Equal(t, "sess=abc; id=1", hops[1].Header.Get("Cookie"),
			"only the configured cookies may be re-injected across an origin change")
		require.NotContains(t, hops[1].Header.Get("Cookie"), "auth=token",
			"the stripped auth cookie must not be restored on a different origin")
		require.Equal(t, "", hops[1].Header.Get("Authorization"),
			"credential headers stripped by the standard library stay stripped")
	})
}

// TestMockTransportDiagnosticsRedactURLUserinfo pins the redaction contract of the
// hermetic harness in common/httpx/mocktransport_test.go: no diagnostic it produces may
// render a URL's userinfo password, because those strings become returned errors and
// test-log lines that a CI system retains (CWE-532).
//
// url.URL.String() serializes the userinfo component verbatim, so formatting r.URL into
// a message would copy the password of a target such as
// "http://alice:s3cr3t-password@origin.example/missing" straight into the log.
// url.URL.Redacted() substitutes the literal "xxxxx" for the password and leaves the
// scheme, user name, host and path readable, so the diagnostic stays useful.
//
// Each sub-test asserts the exact redacted string AND, independently, that the password
// literal is absent - the second assertion is what fails if a future edit reverts a
// single site to formatting r.URL, even if the message still happens to contain "xxxxx"
// somewhere. All four reachable diagnostic paths of the harness are covered: the shared
// formatter, the unscripted-route builder, the missing-handler guard and the
// body-snapshot failure. Redaction is confined to messages: recordedRequest.URL still
// holds the exact URL that went on the wire, which the last sub-test verifies.
func TestMockTransportDiagnosticsRedactURLUserinfo(t *testing.T) {
	const (
		credentialURL = "http://alice:s3cr3t-password@origin.example/missing?q=1"
		redactedURL   = "http://alice:xxxxx@origin.example/missing?q=1"
		password      = "s3cr3t-password"
	)

	// newCredentialRequest builds a request whose URL carries userinfo. Nothing is ever
	// sent: every sub-test either formats the request or hands it to a transport that
	// fails before delegating, so no host is resolved or dialled.
	newCredentialRequest := func(t *testing.T) *http.Request {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, credentialURL, nil)
		require.NoError(t, err)
		return req
	}

	t.Run("shared formatter redacts the password", func(t *testing.T) {
		req := newCredentialRequest(t)

		require.Equal(t, "GET "+redactedURL, redactedRequestLine(req),
			"the diagnostic request line must name the method and the redacted URL exactly")
		require.NotContains(t, redactedRequestLine(req), password,
			"the password must not survive anywhere in the request line")
		require.Equal(t, credentialURL, req.URL.String(),
			"redaction is for output only: the request itself must be left untouched")
	})

	t.Run("unscripted route error redacts the password", func(t *testing.T) {
		req := newCredentialRequest(t)

		err := unscriptedRouteError(req, "origin.example/missing", "/missing")
		require.EqualError(t, err,
			`scriptedRedirects: no route scripted for GET `+redactedURL+` (tried "origin.example/missing" then "/missing")`,
			"the miss diagnostic must name both looked-up keys and the redacted URL")
		require.NotContains(t, err.Error(), password,
			"the single builder feeds both t.Error and the returned error, so neither may leak the password")
	})

	t.Run("missing handler guard redacts the password", func(t *testing.T) {
		// Constructed directly rather than through newMockTransport, which rejects a nil
		// handler: this is the defensive guard behind that constructor.
		mt := &mockTransport{}

		resp, err := mt.RoundTrip(newCredentialRequest(t))
		require.Nil(t, resp, "a transport with no handler cannot produce a response")
		require.EqualError(t, err, "mockTransport: no handler configured for GET "+redactedURL)
		require.NotContains(t, err.Error(), password)

		// The guard runs after the counter and the snapshot, and the recording keeps the
		// exact wire URL so consumers can still assert it byte for byte.
		require.Equal(t, 1, mt.callCount(), "the attempt must be counted even though it produced no response")
		recorded := mt.requests()
		require.Len(t, recorded, 1, "the failed attempt must still be recorded")
		require.Equal(t, credentialURL, recorded[0].URL,
			"the snapshot holds the unredacted target, which is what per-hop URL assertions compare against")
		require.Equal(t, "GET "+redactedURL+` (host "origin.example", 0 header keys, 0 body bytes)`,
			recorded[0].String(),
			"printing a snapshot must redact the password while still naming the target")
		require.NotContains(t, recorded[0].String(), password)
	})

	t.Run("body snapshot failure redacts the password", func(t *testing.T) {
		req := newCredentialRequest(t)
		// http.NewRequest with a nil body leaves both Body and GetBody nil, so installing
		// a failing reader here drives snapshotRequestBody down its drain-r.Body branch.
		req.Body = &errReadCloser{err: errBodySnapshotFailure}

		mt := newMockTransport(t, func(r *http.Request) (*http.Response, error) {
			t.Error("the handler must not run once the body could not be recorded")
			return nil, nil
		})

		resp, err := mt.RoundTrip(req)
		require.Nil(t, resp, "an unrecordable body must fail the round trip")
		require.EqualError(t, err,
			"mockTransport: GET "+redactedURL+": draining the request body: "+errBodySnapshotFailure.Error())
		require.NotContains(t, err.Error(), password)
		require.ErrorIs(t, err, errBodySnapshotFailure,
			"the underlying read failure must stay unwrapped-to so a caller can identify it")
	})
}

// errBodySnapshotFailure is the read failure injected into a request body by
// TestMockTransportDiagnosticsRedactURLUserinfo. It is a package-level sentinel so the
// test can assert the wrapped chain with errors.Is rather than by string comparison.
var errBodySnapshotFailure = errors.New("blitzy: injected request body read failure")
