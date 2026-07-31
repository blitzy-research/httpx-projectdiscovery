package httpx

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// These tests cover the CheckRedirect closures selected by New. Redirect mode must be
// set before construction because New selects the closure during construction.
// Cross-host cases use the scripted transport because loopback servers share hostname
// 127.0.0.1 while FollowHostRedirects compares URL.Hostname(). Tests remain sequential
// because New mutates process-wide GODEBUG on the HTTP/1.1 path.

// TestRedirectDefaultDoesNotFollow verifies that the default closure returns
// http.ErrUseLastResponse: the first 3xx, its Location, and its body are returned
// without issuing the target request.
func TestRedirectDefaultDoesNotFollow(t *testing.T) {
	const redirectBody = "redirect body"
	require.Len(t, redirectBody, 13, "precondition: the redirect payload is exactly 13 bytes")

	rt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
		"origin.example/a": {status: http.StatusFound, location: "/b", body: redirectBody},
		// /b is scripted even though it must never be requested, so a defect that
		// followed the redirect fails on the protocol assertions below rather than
		// on an unscripted-route error that says nothing about redirect policy.
		"origin.example/b": {status: http.StatusOK, body: "final"},
	}))

	// A nil mutator keeps DefaultOptions' FollowRedirects and FollowHostRedirects
	// false, which is exactly what selects the default closure inside New.
	ht := newMockHTTPX(t, nil, rt)

	req, err := retryablehttp.NewRequest(http.MethodGet, "http://origin.example/a", nil)
	require.NoError(t, err)

	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err)

	require.Equal(t, 1, rt.callCount(), "the default policy must not issue a second request")
	hops := rt.requests()
	require.Len(t, hops, 1)
	require.Equal(t, http.MethodGet, hops[0].Method)
	require.Equal(t, "http://origin.example/a", hops[0].URL,
		"the only request on the wire must be the caller's own target")

	require.Equal(t, http.StatusFound, resp.StatusCode,
		"the redirect itself is the result, not the redirect target")
	// The Location header is surfaced exactly as the origin wrote it, still
	// relative: nothing in the default path resolves it against the request URL.
	require.Equal(t, "/b", resp.GetHeader("Location"))
	require.Equal(t, "/b", resp.GetHeaderPart("Location", ";"))
	require.Equal(t, []byte(redirectBody), resp.Data,
		"the redirect response's own body is what the caller receives")
	require.Equal(t, 13, resp.ContentLength)

	require.Len(t, resp.Chain, 1, "a single request produces a single chain item")
	require.False(t, resp.HasChain(),
		"HasChain is len(Chain) > 1 (response.go:99-101), so one item is not a chain")
	require.Equal(t, "", resp.GetChainLastURL(),
		"GetChainLastURL returns the empty string when HasChain is false (response.go:104-110)")
	require.Equal(t, []int{http.StatusFound}, resp.GetChainStatusCodes())
}

// TestRedirectMaxRedirectsBudget verifies both follow closures at the >= boundary.
// previousRequests already contains the request that produced the current 3xx, so
// MaxRedirects values 0 and 1 follow no redirect and the effective number followed is
// max(0, MaxRedirects-1). This matches Go's len(via) >= limit convention, although the
// -maxr help text describes MaxRedirects as redirects to follow.
func TestRedirectMaxRedirectsBudget(t *testing.T) {
	cases := []struct {
		name string
		// followHostRedirects selects which closure is under test. Exactly one is
		// enabled per row: they are mutually exclusive, and because
		// FollowHostRedirects is installed last it would win if both were set,
		// silently changing which guard the row exercises.
		followHostRedirects bool
		maxRedirects        int
		wantHopURLs         []string
		wantStatus          int
		wantData            string
		wantChainLen        int
		wantHasChain        bool
		wantLastURL         string
		wantStatusCodes     []int
	}{
		{
			name:            "budget 0 follows no hop",
			maxRedirects:    0,
			wantHopURLs:     []string{"http://origin.example/0"},
			wantStatus:      http.StatusFound,
			wantData:        "hop0",
			wantChainLen:    1,
			wantHasChain:    false,
			wantLastURL:     "",
			wantStatusCodes: []int{http.StatusFound},
		},
		{
			name:            "budget 1 still follows no hop",
			maxRedirects:    1,
			wantHopURLs:     []string{"http://origin.example/0"},
			wantStatus:      http.StatusFound,
			wantData:        "hop0",
			wantChainLen:    1,
			wantHasChain:    false,
			wantLastURL:     "",
			wantStatusCodes: []int{http.StatusFound},
		},
		{
			name:            "budget 2 follows one hop",
			maxRedirects:    2,
			wantHopURLs:     []string{"http://origin.example/0", "http://origin.example/1"},
			wantStatus:      http.StatusFound,
			wantData:        "hop1",
			wantChainLen:    2,
			wantHasChain:    true,
			wantLastURL:     "http://origin.example/1",
			wantStatusCodes: []int{http.StatusFound, http.StatusFound},
		},
		{
			name:         "budget 3 follows two hops",
			maxRedirects: 3,
			wantHopURLs: []string{
				"http://origin.example/0",
				"http://origin.example/1",
				"http://origin.example/2",
			},
			wantStatus:      http.StatusFound,
			wantData:        "hop2",
			wantChainLen:    3,
			wantHasChain:    true,
			wantLastURL:     "http://origin.example/2",
			wantStatusCodes: []int{http.StatusFound, http.StatusFound, http.StatusFound},
		},
		{
			name:         "budget above the chain length reaches the final response",
			maxRedirects: 10,
			wantHopURLs: []string{
				"http://origin.example/0",
				"http://origin.example/1",
				"http://origin.example/2",
				"http://origin.example/3",
			},
			wantStatus:      http.StatusOK,
			wantData:        "final",
			wantChainLen:    4,
			wantHasChain:    true,
			wantLastURL:     "http://origin.example/3",
			wantStatusCodes: []int{http.StatusFound, http.StatusFound, http.StatusFound, http.StatusOK},
		},
		{
			// The host-scoped closure has its own budget guard at httpx.go:133;
			// same-host hops isolate that guard from the hostname check.
			name:                "host-scoped budget 1 still follows no hop",
			followHostRedirects: true,
			maxRedirects:        1,
			wantHopURLs:         []string{"http://origin.example/0"},
			wantStatus:          http.StatusFound,
			wantData:            "hop0",
			wantChainLen:        1,
			wantHasChain:        false,
			wantLastURL:         "",
			wantStatusCodes:     []int{http.StatusFound},
		},
		{
			name:                "host-scoped budget 2 follows one hop",
			followHostRedirects: true,
			maxRedirects:        2,
			wantHopURLs:         []string{"http://origin.example/0", "http://origin.example/1"},
			wantStatus:          http.StatusFound,
			wantData:            "hop1",
			wantChainLen:        2,
			wantHasChain:        true,
			wantLastURL:         "http://origin.example/1",
			wantStatusCodes:     []int{http.StatusFound, http.StatusFound},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A FRESH transport per row is mandatory: callCount and the recorded
			// slice are per-transport, so a shared one would accumulate across rows
			// and every count below would be silently wrong.
			rt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
				"origin.example/0": {status: http.StatusFound, location: "/1", body: "hop0"},
				"origin.example/1": {status: http.StatusFound, location: "/2", body: "hop1"},
				"origin.example/2": {status: http.StatusFound, location: "/3", body: "hop2"},
				"origin.example/3": {status: http.StatusOK, body: "final"},
			}))

			ht := newMockHTTPX(t, func(options *Options) {
				if tc.followHostRedirects {
					options.FollowHostRedirects = true
				} else {
					options.FollowRedirects = true
				}
				options.MaxRedirects = tc.maxRedirects
			}, rt)

			req, err := retryablehttp.NewRequest(http.MethodGet, "http://origin.example/0", nil)
			require.NoError(t, err)

			resp, err := ht.Do(req, UnsafeOptions{})
			require.NoError(t, err)

			gotHopURLs := make([]string, 0, len(rt.requests()))
			for _, rec := range rt.requests() {
				gotHopURLs = append(gotHopURLs, rec.URL)
			}
			require.Equal(t, tc.wantHopURLs, gotHopURLs,
				"the exact request stream on the wire pins both the hop count and the stopping point")
			require.Equal(t, len(tc.wantHopURLs), rt.callCount(),
				"the transport invocation count must match the recorded stream exactly")

			require.Equal(t, tc.wantStatus, resp.StatusCode)
			require.Equal(t, []byte(tc.wantData), resp.Data,
				"the body delivered is the one from the hop the budget stopped at")
			require.Len(t, resp.Chain, tc.wantChainLen)
			require.Equal(t, tc.wantHasChain, resp.HasChain())
			require.Equal(t, tc.wantLastURL, resp.GetChainLastURL())
			require.Equal(t, tc.wantStatusCodes, resp.GetChainStatusCodes())
		})
	}
}

// TestRedirectFollowHostRedirectsComparesHostnameOnly verifies that
// FollowHostRedirects compares URL.Hostname() for the new target and initial request.
// The comparison intentionally ignores scheme and port, so same-host upgrades and port
// changes are followed while a different hostname is rejected. A scripted transport is
// required because distinct loopback servers still share hostname 127.0.0.1.
//
// SECURITY DISPOSITION. RFC 9110 section 4.3.1 defines an origin as scheme, host AND port,
// so a comparison of the hostname alone admits two destinations the operator did not
// authorise by naming -fhr: a different port on the same name, which is a different service,
// and a different scheme on the same name, which is a downgrade to cleartext carrying
// whatever credential state the hop inherited. The cleartext case and its exact headers are
// pinned separately by assertRedirectFollowHostRedirectsAllowsCleartextDowngrade.
//
// PINNED AS MEASURED AND NOT FIXED. Comparing the full origin would stop following hops that
// -fhr follows today, changing the result set of every scan that uses the flag, which is a
// production behaviour change to an existing option rather than a defect with a bounded fix.
// The rows below therefore pin the admitted and rejected destinations exactly, so a change to
// the comparison in either direction fails here.
func TestRedirectFollowHostRedirectsComparesHostnameOnly(t *testing.T) {
	cases := []struct {
		name            string
		location        string
		wantHopURLs     []string
		wantStatus      int
		wantData        string
		wantChainLen    int
		wantHasChain    bool
		wantLastURL     string
		wantStatusCodes []int
	}{
		{
			name:            "cross-host redirect is not followed",
			location:        "http://other.example/final",
			wantHopURLs:     []string{"http://origin.example/start"},
			wantStatus:      http.StatusFound,
			wantData:        "redirect",
			wantChainLen:    1,
			wantHasChain:    false,
			wantLastURL:     "",
			wantStatusCodes: []int{http.StatusFound},
		},
		{
			name:     "same-host redirect is followed",
			location: "http://origin.example/final",
			wantHopURLs: []string{
				"http://origin.example/start",
				"http://origin.example/final",
			},
			wantStatus:      http.StatusOK,
			wantData:        "same host",
			wantChainLen:    2,
			wantHasChain:    true,
			wantLastURL:     "http://origin.example/final",
			wantStatusCodes: []int{http.StatusFound, http.StatusOK},
		},
		{
			// URL.Hostname() strips the port, so a different port is the same host
			// to this policy even though RFC 9110 §4.3.1 makes it a new origin.
			name:     "different port is followed because the port is ignored",
			location: "http://origin.example:8080/final",
			wantHopURLs: []string{
				"http://origin.example/start",
				"http://origin.example:8080/final",
			},
			wantStatus:      http.StatusOK,
			wantData:        "same host other port",
			wantChainLen:    2,
			wantHasChain:    true,
			wantLastURL:     "http://origin.example:8080/final",
			wantStatusCodes: []int{http.StatusFound, http.StatusOK},
		},
		{
			// The comparison never reads URL.Scheme, so an http-to-https upgrade is
			// followed. This is the case that makes the hostname-only rule useful.
			name:     "different scheme is followed because the scheme is ignored",
			location: "https://origin.example/final",
			wantHopURLs: []string{
				"http://origin.example/start",
				"https://origin.example/final",
			},
			wantStatus:      http.StatusOK,
			wantData:        "same host",
			wantChainLen:    2,
			wantHasChain:    true,
			wantLastURL:     "https://origin.example/final",
			wantStatusCodes: []int{http.StatusFound, http.StatusOK},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Use a fresh recorder per row. scriptedRedirects keys include host and
			// port but not scheme, so the port case needs its own route while the
			// HTTPS case reuses origin.example/final.
			rt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
				"origin.example/start":      {status: http.StatusFound, location: tc.location, body: "redirect"},
				"origin.example/final":      {status: http.StatusOK, body: "same host"},
				"origin.example:8080/final": {status: http.StatusOK, body: "same host other port"},
				"other.example/final":       {status: http.StatusOK, body: "cross host"},
			}))

			ht := newMockHTTPX(t, func(options *Options) {
				// FollowHostRedirects only - setting FollowRedirects as well would
				// still land here, since the host closure is installed last and
				// overwrites it, but it would obscure which closure is under test.
				options.FollowHostRedirects = true
				options.MaxRedirects = 10
			}, rt)

			req, err := retryablehttp.NewRequest(http.MethodGet, "http://origin.example/start", nil)
			require.NoError(t, err)

			resp, err := ht.Do(req, UnsafeOptions{})
			require.NoError(t, err)

			gotHopURLs := make([]string, 0, len(rt.requests()))
			for _, rec := range rt.requests() {
				gotHopURLs = append(gotHopURLs, rec.URL)
			}
			require.Equal(t, tc.wantHopURLs, gotHopURLs,
				"which authority received a request is the whole point of this policy")
			require.Equal(t, len(tc.wantHopURLs), rt.callCount())

			require.Equal(t, tc.wantStatus, resp.StatusCode)
			require.Equal(t, []byte(tc.wantData), resp.Data,
				"the body identifies which origin actually answered")
			require.Len(t, resp.Chain, tc.wantChainLen)
			require.Equal(t, tc.wantHasChain, resp.HasChain())
			require.Equal(t, tc.wantLastURL, resp.GetChainLastURL(),
				"the final URL is the operator-visible record of where the scan ended up")
			require.Equal(t, tc.wantStatusCodes, resp.GetChainStatusCodes())
		})
	}

	// The security consequence of comparing the hostname alone: a scheme change is
	// admitted, so an https target can be walked down to cleartext on the same host.
	t.Run("hostname match admits an https to http downgrade", assertRedirectFollowHostRedirectsAllowsCleartextDowngrade)
}

// TestRedirectMethodAndBodyRewriting verifies net/http's behavior for this POST: 301,
// 302, and 303 become bodyless GET requests, while 307 and 308 preserve POST and replay
// a rewindable body. The test records Method, body bytes, and Request.ContentLength;
// Content-Length is serialized from the field and is not stored in Request.Header.
func TestRedirectMethodAndBodyRewriting(t *testing.T) {
	const payload = "payload"
	require.Len(t, payload, 7, "precondition: the request payload is exactly 7 bytes")

	cases := []struct {
		name           string
		status         int
		wantHopMethods []string
		// wantHopBodies holds the exact bytes recorded per hop; an empty string
		// means the hop carried no body at all.
		wantHopBodies []string
		// wantHopLengths holds Request.ContentLength per hop: 7 when the payload is
		// present, 0 when the rewrite dropped it.
		wantHopLengths []int64
	}{
		{
			name:           "301 rewrites the method to GET and drops the body",
			status:         http.StatusMovedPermanently,
			wantHopMethods: []string{http.MethodPost, http.MethodGet},
			wantHopBodies:  []string{payload, ""},
			wantHopLengths: []int64{7, 0},
		},
		{
			name:           "302 rewrites the method to GET and drops the body",
			status:         http.StatusFound,
			wantHopMethods: []string{http.MethodPost, http.MethodGet},
			wantHopBodies:  []string{payload, ""},
			wantHopLengths: []int64{7, 0},
		},
		{
			name:           "303 rewrites the method to GET and drops the body",
			status:         http.StatusSeeOther,
			wantHopMethods: []string{http.MethodPost, http.MethodGet},
			wantHopBodies:  []string{payload, ""},
			wantHopLengths: []int64{7, 0},
		},
		{
			name:           "307 preserves the method and replays the body",
			status:         http.StatusTemporaryRedirect,
			wantHopMethods: []string{http.MethodPost, http.MethodPost},
			wantHopBodies:  []string{payload, payload},
			wantHopLengths: []int64{7, 7},
		},
		{
			name:           "308 preserves the method and replays the body",
			status:         http.StatusPermanentRedirect,
			wantHopMethods: []string{http.MethodPost, http.MethodPost},
			wantHopBodies:  []string{payload, payload},
			wantHopLengths: []int64{7, 7},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := scriptedRedirects(t, map[string]mockHop{
				"origin.example/a": {status: tc.status, location: "/b", body: "redirect"},
				"origin.example/b": {status: http.StatusOK, body: "final"},
			})

			// Capture ContentLength and TransferEncoding before the scripted handler
			// runs because recordedRequest intentionally stores headers and body, not
			// transport framing fields.
			var declaredLengths []int64
			var transferEncodings [][]string
			rt := newMockTransport(t, func(r *http.Request) (*http.Response, error) {
				declaredLengths = append(declaredLengths, r.ContentLength)
				transferEncodings = append(transferEncodings, r.TransferEncoding)
				return script(r)
			})

			ht := newMockHTTPX(t, func(options *Options) {
				options.FollowRedirects = true
				options.MaxRedirects = 10
			}, rt)

			req, err := retryablehttp.NewRequest(http.MethodPost, "http://origin.example/a", strings.NewReader(payload))
			require.NoError(t, err)

			resp, err := ht.Do(req, UnsafeOptions{})
			require.NoError(t, err)

			require.Equal(t, 2, rt.callCount(), "exactly one redirect must be followed")
			hops := rt.requests()
			require.Len(t, hops, 2)

			gotMethods := []string{hops[0].Method, hops[1].Method}
			require.Equal(t, tc.wantHopMethods, gotMethods,
				"the method forwarded on each hop is what the status code decides")
			require.Equal(t, http.MethodPost, hops[0].Method,
				"the caller's own request must always leave as a POST")

			gotBodies := []string{string(hops[0].Body), string(hops[1].Body)}
			require.Equal(t, tc.wantHopBodies, gotBodies,
				"the exact bytes on each hop prove the payload was replayed or dropped")
			require.Len(t, hops[0].Body, 7, "the first hop always carries the full payload")
			require.Len(t, hops[1].Body, len(tc.wantHopBodies[1]))

			require.Equal(t, tc.wantHopLengths, declaredLengths,
				"Request.ContentLength is the framing net/http will serialise per hop")
			require.Equal(t, [][]string{nil, nil}, transferEncodings,
				"the retry layer buffers every body, so a length is always declared and chunked never occurs")

			require.Equal(t, "", hops[0].Header.Get("Content-Length"))
			require.Equal(t, "", hops[1].Header.Get("Content-Length"))

			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, []byte("final"), resp.Data)
			require.Len(t, resp.Chain, 2)
			require.Equal(t, []int{tc.status, http.StatusOK}, resp.GetChainStatusCodes())
			require.Equal(t, "http://origin.example/b", resp.GetChainLastURL())
		})
	}

	// The same 307 method-and-body contract observed per DESTINATION rather than per
	// status code, which is what decides whether a credential crosses with the payload.
	t.Run("a 307 carries the method body and headers to whichever destination Location names", assertRedirectCrossOriginForwardsSecretsAndBody)
}

// TestRedirectSetsRefererPerHop verifies that each synthesized Referer names the
// immediate predecessor URL and that the initial request has none. The harness clones
// headers before invoking the scripted handler so each snapshot preserves the values
// presented to that RoundTrip. AutoReferer stays disabled to isolate net/http's
// synthesized value.
func TestRedirectSetsRefererPerHop(t *testing.T) {
	rt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
		"origin.example/a": {status: http.StatusFound, location: "/b", body: "one"},
		"origin.example/b": {status: http.StatusFound, location: "/c", body: "two"},
		"origin.example/c": {status: http.StatusOK, body: "three"},
	}))

	ht := newMockHTTPX(t, func(options *Options) {
		options.FollowRedirects = true
		options.MaxRedirects = 10
	}, rt)

	req, err := retryablehttp.NewRequest(http.MethodGet, "http://origin.example/a", nil)
	require.NoError(t, err)

	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err)

	require.Equal(t, 3, rt.callCount(), "both redirects must be followed to observe three hops")
	hops := rt.requests()
	require.Len(t, hops, 3)

	require.Equal(t, []string{
		"http://origin.example/a",
		"http://origin.example/b",
		"http://origin.example/c",
	}, []string{hops[0].URL, hops[1].URL, hops[2].URL}, "the chain must walk a, b, c in order")

	require.Equal(t, "", hops[0].Header.Get("Referer"),
		"the caller's own request has no predecessor, so it carries no Referer")
	require.Equal(t, "http://origin.example/a", hops[1].Header.Get("Referer"),
		"hop 2 must name hop 1's absolute URL")
	require.Equal(t, "http://origin.example/b", hops[2].Header.Get("Referer"),
		"hop 3 must name hop 2's absolute URL, not the original target")

	// Compare the full sequence to ensure each Referer names the immediate predecessor
	// rather than the original target.
	require.Equal(t, []string{"", hops[0].URL, hops[1].URL}, []string{
		hops[0].Header.Get("Referer"),
		hops[1].Header.Get("Referer"),
		hops[2].Header.Get("Referer"),
	}, "hop N's Referer must be hop N-1's URL")

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, []byte("three"), resp.Data)
	require.Equal(t, []int{http.StatusFound, http.StatusFound, http.StatusOK}, resp.GetChainStatusCodes())
	require.Equal(t, "http://origin.example/c", resp.GetChainLastURL())

	// Position in the chain decides the Referer above; confidentiality decides it once
	// the hop crosses an origin or drops to cleartext.
	t.Run("cross origin and downgrade hops decide the Referer by confidentiality", assertRedirectRefererCrossOriginConfidentiality)
}

// TestRedirectRespectHSTSUpgradesScheme verifies this client's RespectHSTS behavior:
// when the previous response contains Strict-Transport-Security, handleHSTS rewrites an
// admitted redirect request's scheme to https. The no-header case exercises the early
// return, and the host-scoped case covers the second call site. The transport URL and
// final RequestURL expose the rewrite; the chain Location remains the response-derived
// redirect location.
func TestRedirectRespectHSTSUpgradesScheme(t *testing.T) {
	cases := []struct {
		name          string
		respectHSTS   bool
		sendSTSHeader bool
		// followHostRedirects selects the host-scoped closure instead of the plain
		// one, so the second handleHSTS call site is exercised too. Exactly one
		// closure is enabled per row.
		followHostRedirects bool
		wantHopURL          string
		wantLastURL         string
	}{
		{
			name:          "option off keeps http",
			respectHSTS:   false,
			sendSTSHeader: true,
			wantHopURL:    "http://origin.example/final",
			wantLastURL:   "http://origin.example/final",
		},
		{
			name:          "option on upgrades to https",
			respectHSTS:   true,
			sendSTSHeader: true,
			wantHopURL:    "https://origin.example/final",
			wantLastURL:   "https://origin.example/final",
		},
		{
			// The early return at httpx.go:86-88: with no header advertised there is
			// no HSTS policy to honour, so the target must be left alone even though
			// the option is on.
			name:          "option on without an HSTS header keeps http",
			respectHSTS:   true,
			sendSTSHeader: false,
			wantHopURL:    "http://origin.example/final",
			wantLastURL:   "http://origin.example/final",
		},
		{
			// The host-scoped closure's own handleHSTS call (httpx.go:139). The
			// redirect stays on origin.example, so the host check passes and the
			// upgrade is what this row observes.
			name:                "host-scoped policy also upgrades to https",
			respectHSTS:         true,
			sendSTSHeader:       true,
			followHostRedirects: true,
			wantHopURL:          "https://origin.example/final",
			wantLastURL:         "https://origin.example/final",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var redirectHeader http.Header
			if tc.sendSTSHeader {
				redirectHeader = http.Header{"Strict-Transport-Security": {"max-age=31536000"}}
			}

			// The Location is cleartext on purpose: the upgrade must come from the
			// policy, not from the header. A script key is host+path with no scheme,
			// so this single entry answers the request whether it arrives as http or
			// as the upgraded https.
			rt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
				"origin.example/a": {
					status:   http.StatusFound,
					location: "http://origin.example/final",
					header:   redirectHeader,
					body:     "redirect",
				},
				"origin.example/final": {status: http.StatusOK, body: "final"},
			}))

			ht := newMockHTTPX(t, func(options *Options) {
				if tc.followHostRedirects {
					options.FollowHostRedirects = true
				} else {
					options.FollowRedirects = true
				}
				options.MaxRedirects = 10
				options.RespectHSTS = tc.respectHSTS
			}, rt)

			req, err := retryablehttp.NewRequest(http.MethodGet, "http://origin.example/a", nil)
			require.NoError(t, err)

			resp, err := ht.Do(req, UnsafeOptions{})
			require.NoError(t, err)

			require.Equal(t, 2, rt.callCount(), "the redirect must be followed exactly once")
			hops := rt.requests()
			require.Len(t, hops, 2)
			require.Equal(t, "http://origin.example/a", hops[0].URL,
				"the caller's own target is never rewritten")
			require.Equal(t, tc.wantHopURL, hops[1].URL,
				"the scheme the transport was asked to fetch is the protocol-visible outcome")

			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, []byte("final"), resp.Data)
			require.Len(t, resp.Chain, 2)
			require.Equal(t, tc.wantLastURL, resp.GetChainLastURL(),
				"the final URL reported to the operator must carry the effective scheme")
			require.Equal(t, []int{http.StatusFound, http.StatusOK}, resp.GetChainStatusCodes())

			// The first chain item's Location remains the cleartext absolute redirect
			// location; HSTS changes the follow-up request URL, not the
			// response-derived Location field.
			require.Equal(t, "http://origin.example/final", resp.GetChainAsSlice()[0].Location,
				"the recorded Location is the wire value, not the upgraded target")
		})
	}
}

// The security scenarios below use synthetic sentinels to show which request state
// reaches each redirect destination. They combine net/http body/header propagation with
// this client's configured-cookie reinjection. No sentinel is a real credential, and
// URL-bearing diagnostics use the shared harness's redaction path.
const (
	redirectSentinelBody = "SENTINEL-BODY-PAYLOAD"
	// redirectSentinelBearer is an Authorization value: net/http's enumerated
	// sensitive set, so it is stripped on an unrelated origin and kept on a subdomain.
	redirectSentinelBearer = "Bearer SENTINEL-BEARER-TOKEN"
	// redirectSentinelProxyCredential is a Proxy-Authorization value, the second
	// enumerated credential header, added to prove the strip decision is per-set and
	// not per-header.
	redirectSentinelProxyCredential = "Basic SENTINEL-PROXY-CREDENTIAL"
	// redirectSentinelAPIKeyHeader represents a non-enumerated credential header used to
	// observe net/http's default redirect copying.
	redirectSentinelAPIKeyHeader = "X-Api-Key"
	redirectSentinelAPIKey       = "SENTINEL-API-KEY"
	// redirectSentinelContentType is a body header, stripped only when the redirect
	// drops the body, so it survives a 307 and marks the replayed payload.
	redirectSentinelContentType = "application/x-sentinel"
	// redirectSentinelConfiguredCookie is supplied the way the CLI supplies -H "Cookie:",
	// so New parses it into Options.customCookies and the redirect closures re-inject it.
	redirectSentinelConfiguredCookie = "cfg=SENTINEL-CONFIGURED-COOKIE"
	// redirectSentinelSessionCookie stands for a cookie applied per target rather than
	// configured globally - an auth strategy's cookie in production. It is NOT in
	// customCookies, so it can only reach a later hop by being carried over.
	redirectSentinelSessionCookie = "sess=SENTINEL-SESSION-COOKIE"
)

const (
	redirectSentinelOriginStart = "http://origin.example/start"
	redirectSentinelReferer     = "http://origin.example/start"
)

// assertRedirectCrossOriginForwardsSecretsAndBody records a 307 redirect to an unrelated
// origin, a subdomain, and the original origin. net/http strips its enumerated
// sensitive headers only when shouldCopyHeaderOnRedirect rejects the destination, but
// preserves non-enumerated headers and replays a rewindable 307 body. The client's
// redirect closure independently reapplies the configured cookies on every admitted
// hop, replacing only the cookies it configures by name and preserving the rest, so the
// Cookie line on a hop states two things at once: which inherited cookies net/http let
// through, and which cookies the injector re-applied.
// Exact per-hop assertions distinguish those mechanisms.
//
// It runs as a sub-test of TestRedirectMethodAndBodyRewriting: the 307 method-and-body
// contract that test sweeps by status code is the same contract examined here per
// destination, so the two belong under one subject.
//
// SECURITY DISPOSITION. Two of the outcomes below are credential and payload disclosure
// to an origin the operator never named: the non-enumerated secret header reaches every
// destination including the unrelated one, and the 307 body is replayed there verbatim.
// Both are PINNED AS MEASURED AND NOT FIXED, for reasons that are not the same:
//
//   - The header copy is net/http's own redirect policy. It withholds exactly six
//     enumerated fields and copies everything else, so a credential carried in any other
//     header is forwarded by the standard library, not by this repository. There is
//     nothing here to change.
//   - The configured-cookie re-injection is this repository's deliberate behaviour: the
//     redirect closure calls setCustomCookies on every admitted hop (httpx.go:100-102,
//     :117-119), which is what makes a -H "Cookie:" value survive a hop whose inherited
//     Cookie header net/http had stripped. Scoping it to the initial origin would change
//     what every user of that flag observes - a production behaviour change outside the
//     two minimal, separately disclosed fixes this work may make to httpx.go, and outside
//     a testing engagement's remit.
//
// Pinning is therefore the remediation available here: an exact per-hop assertion means
// the disclosure cannot widen, and cannot silently narrow either, without failing.
func assertRedirectCrossOriginForwardsSecretsAndBody(t *testing.T) {
	require.Len(t, redirectSentinelBody, 21, "precondition: the sentinel payload is exactly 21 bytes")

	cases := []struct {
		name       string
		location   string
		wantHopURL string
		// wantAuthorization and wantProxyAuthorization are the exact values hop 2
		// receives: empty when net/http withheld the enumerated set, the sentinel when
		// it decided the destination was in the same trust domain.
		wantAuthorization      string
		wantProxyAuthorization string
		// wantCookie is the exact Cookie header hop 2 receives. It is a single line in
		// every case, because AddCookie appends to one line.
		wantCookie string
	}{
		{
			name:                   "unrelated origin receives the body the api key and the configured cookie",
			location:               "http://other.example/collect",
			wantHopURL:             "http://other.example/collect",
			wantAuthorization:      "",
			wantProxyAuthorization: "",
			// net/http stripped the inherited session cookie with the rest of the
			// enumerated set, so there is nothing for the injector to preserve and the
			// re-injected configured cookie is all that remains.
			wantCookie: redirectSentinelConfiguredCookie,
		},
		{
			// The subdomain: net/http's own "foo.com may talk to sub.foo.com"
			// allowance hands over the credentials too.
			name:                   "attacker controlled subdomain additionally receives both credential headers",
			location:               "http://sub.origin.example/collect",
			wantHopURL:             "http://sub.origin.example/collect",
			wantAuthorization:      redirectSentinelBearer,
			wantProxyAuthorization: redirectSentinelProxyCredential,
			// net/http copied the inherited session cookie here, and setCustomCookies
			// replaces by NAME: the session cookie is not configured, so it is
			// preserved and re-added first, then the configured cookie is applied
			// exactly once. Preserved-then-configured is the resulting order.
			wantCookie: redirectSentinelSessionCookie + "; " + redirectSentinelConfiguredCookie,
		},
		{
			name:                   "same origin receives everything which proves the stripping is destination scoped",
			location:               "http://origin.example/collect",
			wantHopURL:             "http://origin.example/collect",
			wantAuthorization:      redirectSentinelBearer,
			wantProxyAuthorization: redirectSentinelProxyCredential,
			// Same name-scoped replacement as the subdomain row: the two enumerated
			// credential headers are destination-scoped, and the Cookie line keeps the
			// inherited session cookie alongside the re-applied configured one.
			wantCookie: redirectSentinelSessionCookie + "; " + redirectSentinelConfiguredCookie,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Use a fresh recorder and script every candidate destination so the exact
			// outbound URL, not route availability, determines each result.
			rt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
				"origin.example/start":       {status: http.StatusTemporaryRedirect, location: tc.location, body: "redirect"},
				"other.example/collect":      {status: http.StatusOK, body: "exfiltrated"},
				"sub.origin.example/collect": {status: http.StatusOK, body: "exfiltrated"},
				"origin.example/collect":     {status: http.StatusOK, body: "exfiltrated"},
			}))

			ht := newMockHTTPX(t, func(options *Options) {
				options.FollowRedirects = true
				options.MaxRedirects = 10
				// The configured cookie has to be set through the mutator: New parses
				// CustomHeaders["Cookie"] into Options.customCookies, so a Cookie
				// added afterwards would never be re-injected and the cross-origin
				// assertion would pass vacuously.
				options.CustomHeaders = map[string][]string{"Cookie": {redirectSentinelConfiguredCookie}}
			}, rt)

			req, err := retryablehttp.NewRequest(http.MethodPost, redirectSentinelOriginStart, strings.NewReader(redirectSentinelBody))
			require.NoError(t, err)

			// Production build-up order, matching runner/runner.go: the configured
			// headers first, then the per-target credentials.
			ht.SetCustomHeaders(req, ht.CustomHeaders)
			req.AddCookie(&http.Cookie{Name: "sess", Value: "SENTINEL-SESSION-COOKIE"})
			req.Header.Set("Authorization", redirectSentinelBearer)
			req.Header.Set("Proxy-Authorization", redirectSentinelProxyCredential)
			req.Header.Set(redirectSentinelAPIKeyHeader, redirectSentinelAPIKey)
			req.Header.Set("Content-Type", redirectSentinelContentType)

			require.Equal(t, redirectSentinelConfiguredCookie+"; "+redirectSentinelSessionCookie, req.Header.Get("Cookie"),
				"the outgoing request must carry the configured cookie and the per-target session cookie on one line")

			resp, err := ht.Do(req, UnsafeOptions{})
			require.NoError(t, err)

			require.Equal(t, 2, rt.callCount(), "the 307 must be followed exactly once")
			hops := rt.requests()
			require.Len(t, hops, 2)

			require.Equal(t, http.MethodPost, hops[0].Method)
			require.Equal(t, redirectSentinelOriginStart, hops[0].URL)
			require.Equal(t, []byte(redirectSentinelBody), hops[0].Body)
			require.Equal(t, redirectSentinelBearer, hops[0].Header.Get("Authorization"))
			require.Equal(t, redirectSentinelProxyCredential, hops[0].Header.Get("Proxy-Authorization"))
			require.Equal(t, redirectSentinelConfiguredCookie+"; "+redirectSentinelSessionCookie, hops[0].Header.Get("Cookie"))
			require.Equal(t, redirectSentinelAPIKey, hops[0].Header.Get(redirectSentinelAPIKeyHeader))
			require.Equal(t, redirectSentinelContentType, hops[0].Header.Get("Content-Type"))
			require.Equal(t, "", hops[0].Header.Get("Referer"),
				"the caller's own request has no predecessor, so it carries no Referer")

			require.Equal(t, tc.wantHopURL, hops[1].URL,
				"the destination is whatever the malicious Location named")
			require.Equal(t, http.MethodPost, hops[1].Method,
				"a 307 preserves the method, so the destination receives the same verb")
			require.Equal(t, []byte(redirectSentinelBody), hops[1].Body,
				"a 307 replays the payload, so the destination receives the request body verbatim")
			require.Equal(t, hops[0].Body, hops[1].Body,
				"the bytes the destination receives must be exactly the bytes the caller sent")

			require.Equal(t, tc.wantAuthorization, hops[1].Header.Get("Authorization"),
				"Authorization is enumerated as sensitive, so whether it crosses is decided by the destination")
			require.Equal(t, tc.wantProxyAuthorization, hops[1].Header.Get("Proxy-Authorization"),
				"Proxy-Authorization is enumerated alongside Authorization and must follow the same decision")
			require.Equal(t, tc.wantCookie, hops[1].Header.Get("Cookie"),
				"the exact Cookie line on the hop states which cookies survived: the injector replaces the configured names and preserves every other cookie the hop inherited")
			require.Len(t, hops[1].Header.Values("Cookie"), 1,
				"the cookies must arrive as a single header line, never one line per cookie")
			require.Contains(t, hops[1].Header.Get("Cookie"), redirectSentinelConfiguredCookie,
				"PINNED: the configured cookie is re-injected on every destination, origin change included")
			require.NotContains(t, hops[1].Header.Get("Cookie"), redirectSentinelConfiguredCookie+"; "+redirectSentinelConfiguredCookie,
				"the configured cookie must be applied exactly once per hop, never appended to the value inherited from the previous hop")
			require.Equal(t, 1, strings.Count(hops[1].Header.Get("Cookie"), redirectSentinelConfiguredCookie),
				"the configured cookie must appear exactly once per hop, never re-appended on top of the inherited value")

			require.Equal(t, redirectSentinelAPIKey, hops[1].Header.Get(redirectSentinelAPIKeyHeader),
				"PINNED: a non-enumerated secret header is copied to every destination, including an unrelated origin")
			require.Equal(t, redirectSentinelContentType, hops[1].Header.Get("Content-Type"),
				"the body headers survive because the 307 kept the body they describe")
			require.Equal(t, redirectSentinelReferer, hops[1].Header.Get("Referer"),
				"the destination is additionally told which URL sent the client to it")

			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, []byte("exfiltrated"), resp.Data,
				"the destination's own body is what the caller receives")
			require.Len(t, resp.Chain, 2)
			require.Equal(t, []int{http.StatusTemporaryRedirect, http.StatusOK}, resp.GetChainStatusCodes())
			require.Equal(t, tc.wantHopURL, resp.GetChainLastURL(),
				"the final URL must name the destination that received the payload")
		})
	}
}

// Sentinels for the Referer confidentiality test. The query token stands for a
// capability token in a scanned URL, the fragment for anything a target carries after
// the hash, and the userinfo pair for credentials embedded in a target the operator
// supplied. The Basic value is base64("alice:s3cr3t-password"), which net/http derives
// from that userinfo and sends as an Authorization header - so the password is
// recoverable from anywhere that value is recorded.
const (
	redirectSentinelQueryToken   = "SENTINEL-QUERY-TOKEN"
	redirectSentinelFragment     = "SENTINEL-FRAGMENT"
	redirectSentinelURLPassword  = "s3cr3t-password"
	redirectSentinelBasicFromURL = "Basic YWxpY2U6czNjcjN0LXBhc3N3b3Jk"

	// The four caller targets. Each carries the query token; two carry userinfo; two
	// are https so the downgrade rule can be exercised.
	redirectSentinelQueryStart           = "http://origin.example/start?token=" + redirectSentinelQueryToken + "#" + redirectSentinelFragment
	redirectSentinelSecureStart          = "https://origin.example/start?token=" + redirectSentinelQueryToken
	redirectSentinelCredentialStart      = "http://alice:" + redirectSentinelURLPassword + "@origin.example/start?token=" + redirectSentinelQueryToken
	redirectSentinelSecureCredentialStar = "https://alice:" + redirectSentinelURLPassword + "@origin.example/start?token=" + redirectSentinelQueryToken

	// The two cross-origin destinations, differing only in scheme so a row can choose
	// whether the hop is a downgrade.
	redirectSentinelCleartextTarget = "http://other.example/collect"
	redirectSentinelSecureTarget    = "https://other.example/collect"
)

// assertRedirectRefererCrossOriginConfidentiality records the Referer received after
// cross-origin and HTTPS-to-HTTP redirects. net/http suppresses a synthesized Referer
// on HTTPS-to-HTTP, preserves an explicit Referer, and otherwise strips URL userinfo
// while retaining path, query, and fragment. AutoReferer supplies an explicit value
// before Do, so the table distinguishes synthesized and explicit behavior.
//
// It runs as a sub-test of TestRedirectSetsRefererPerHop, which establishes the per-hop
// Referer contract on a same-origin chain; this extends the same subject to the cases
// where confidentiality decides the value instead of position in the chain.
//
// SECURITY DISPOSITION. The AutoReferer rows record a real disclosure: SetCustomHeaders
// installs the Referer as r.String() (httpx.go:549-551), the caller's target URL in full,
// so a URL that carries userinfo, a capability token in its query, or a fragment hands all
// of it to whatever origin the redirect names. Because the value is EXPLICIT by the time
// net/http considers it, refererForURL takes its explicit-value branch and neither strips
// the userinfo nor suppresses the header on an HTTPS-to-HTTP hop - the two protections the
// synthesized rows below demonstrate are still in force. The contrast between the two row
// families is the finding, and the last assertion states it as an equality rather than a
// containment so it cannot pass by accident.
//
// PINNED AS MEASURED AND NOT FIXED. Sanitizing the value - stripping userinfo, dropping the
// query and fragment, or deferring to net/http's synthesis - changes the Referer every
// -auto-referer scan emits, which is a production behaviour change to an existing option
// outside the two minimal, separately disclosed fixes this work may make to httpx.go. What
// is in scope, and is what these rows do, is to pin the exact value each destination
// receives so the disclosure cannot grow and cannot be closed unnoticed.
func assertRedirectRefererCrossOriginConfidentiality(t *testing.T) {
	cases := []struct {
		name     string
		start    string
		location string
		// autoReferer selects whether SetCustomHeaders installs an explicit Referer
		// before the request leaves, which is what routes refererForURL down its
		// explicitRef branch.
		autoReferer            bool
		wantStartReferer       string
		wantCrossOriginReferer string
		// wantStartAuthorization is the Authorization on the caller's own request,
		// which net/http derives from URL userinfo when there is any.
		wantStartAuthorization string
	}{
		{
			// The synthesised value carries both the query and the fragment off the
			// origin they belong to.
			name:                   "synthesized referer forwards the query string and the fragment to an unrelated origin",
			start:                  redirectSentinelQueryStart,
			location:               redirectSentinelCleartextTarget,
			wantStartReferer:       "",
			wantCrossOriginReferer: redirectSentinelQueryStart,
			wantStartAuthorization: "",
		},
		{
			// The one control that works: RFC 9110 §10.1.3, implemented at
			// net/http/client.go:152-154.
			name:                   "https to http downgrade suppresses the referer entirely",
			start:                  redirectSentinelSecureStart,
			location:               redirectSentinelCleartextTarget,
			wantStartReferer:       "",
			wantCrossOriginReferer: "",
			wantStartAuthorization: "",
		},
		{
			// Not a downgrade, so the suppression does not apply and the query token
			// crosses the origin boundary.
			name:                   "https to https cross origin still forwards the query string",
			start:                  redirectSentinelSecureStart,
			location:               redirectSentinelSecureTarget,
			wantStartReferer:       "",
			wantCrossOriginReferer: redirectSentinelSecureStart,
			wantStartAuthorization: "",
		},
		{
			// The strip at net/http/client.go:160-169: the password is removed from
			// the synthesised value while the query token still travels.
			name:                   "synthesized referer removes url userinfo but keeps the query string",
			start:                  redirectSentinelCredentialStart,
			location:               redirectSentinelCleartextTarget,
			wantStartReferer:       "",
			wantCrossOriginReferer: "http://origin.example/start?token=" + redirectSentinelQueryToken,
			wantStartAuthorization: redirectSentinelBasicFromURL,
		},
		{
			// AutoReferer supplies an explicit Referer built from req.String(), so the
			// strip above never runs and the password crosses the boundary.
			name:                   "auto referer forwards url userinfo verbatim across the origin boundary",
			start:                  redirectSentinelCredentialStart,
			location:               redirectSentinelCleartextTarget,
			autoReferer:            true,
			wantStartReferer:       redirectSentinelCredentialStart,
			wantCrossOriginReferer: redirectSentinelCredentialStart,
			wantStartAuthorization: redirectSentinelBasicFromURL,
		},
		{
			// The compounding case: an explicit Referer is copied onto the hop before
			// the downgrade rule is consulted, so returning the empty string only
			// skips the overwrite and the secure URL - password and token included -
			// is disclosed over cleartext after all.
			name:                   "auto referer defeats the https to http suppression",
			start:                  redirectSentinelSecureCredentialStar,
			location:               redirectSentinelCleartextTarget,
			autoReferer:            true,
			wantStartReferer:       redirectSentinelSecureCredentialStar,
			wantCrossOriginReferer: redirectSentinelSecureCredentialStar,
			wantStartAuthorization: redirectSentinelBasicFromURL,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Script keys are host+path with no scheme, so one entry per route serves
			// the http and https variants of that route alike.
			rt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
				"origin.example/start":  {status: http.StatusFound, location: tc.location, body: "redirect"},
				"other.example/collect": {status: http.StatusOK, body: "collected"},
			}))

			ht := newMockHTTPX(t, func(options *Options) {
				options.FollowRedirects = true
				options.MaxRedirects = 10
				options.AutoReferer = tc.autoReferer
			}, rt)

			req, err := retryablehttp.NewRequest(http.MethodGet, tc.start, nil)
			require.NoError(t, err)
			// AutoReferer is applied by SetCustomHeaders (httpx.go:541-543), so call it
			// for every row before Do; only rows with AutoReferer enabled receive an
			// explicit value.
			ht.SetCustomHeaders(req, ht.CustomHeaders)
			require.Equal(t, tc.wantStartReferer, req.Header.Get("Referer"),
				"AutoReferer must have written exactly this Referer, or none at all, before the request leaves")

			resp, err := ht.Do(req, UnsafeOptions{})
			require.NoError(t, err)

			require.Equal(t, 2, rt.callCount(), "the redirect must be followed exactly once")
			hops := rt.requests()
			require.Len(t, hops, 2)
			require.Equal(t, tc.start, hops[0].URL,
				"the caller's own target must reach the transport exactly as supplied")
			require.Equal(t, tc.location, hops[1].URL,
				"the second hop must be the cross-origin destination the Location named")

			require.Equal(t, tc.wantCrossOriginReferer, hops[1].Header.Get("Referer"),
				"the Referer handed to the unrelated origin is the disclosure under test")
			// A suppressed Referer must be genuinely absent rather than present and
			// empty, because an empty header line is still a header a destination logs.
			wantRefererLines := 0
			if tc.wantCrossOriginReferer != "" {
				wantRefererLines = 1
			}
			require.Len(t, hops[1].Header.Values("Referer"), wantRefererLines,
				"a suppressed Referer must be absent from the header map, not present and empty")

			// URL credentials: net/http derives an Authorization header from userinfo
			// on the hop whose URL carries it, and that header IS enumerated as
			// sensitive, so it does not cross to the unrelated origin. The contrast
			// with the Referer above is the point: the same secret is withheld in one
			// header and, on the AutoReferer rows, forwarded in another.
			require.Equal(t, tc.wantStartAuthorization, hops[0].Header.Get("Authorization"),
				"userinfo in the target becomes a Basic credential on the caller's own request")
			require.Equal(t, "", hops[1].Header.Get("Authorization"),
				"the derived credential is enumerated as sensitive, so it must not reach the unrelated origin")

			crossOriginCarriesPassword := strings.Contains(hops[1].Header.Get("Referer"), redirectSentinelURLPassword)
			require.Equal(t, tc.autoReferer && strings.Contains(tc.start, redirectSentinelURLPassword), crossOriginCarriesPassword,
				"the URL password may cross the origin boundary only on the AutoReferer rows, which is exactly the pinned defect")

			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, []byte("collected"), resp.Data)
			require.Len(t, resp.Chain, 2)
			require.Equal(t, []int{http.StatusFound, http.StatusOK}, resp.GetChainStatusCodes())
			require.Equal(t, tc.location, resp.GetChainLastURL(),
				"the final URL must name the cross-origin destination that received the Referer")
		})
	}
}

// assertRedirectFollowHostRedirectsAllowsCleartextDowngrade shows that hostname-only
// matching admits HTTPS-to-HTTP redirects on the same hostname, including port changes.
// net/http suppresses Referer on the downgrade but preserves the configured credential
// state because the destination remains host-related. The test records the cleartext hop
// and its exact headers.
//
// It runs as a sub-test of TestRedirectFollowHostRedirectsComparesHostnameOnly, whose
// table establishes that the closure ignores scheme and port; this is the security
// consequence of that same comparison, so it belongs under the same subject.
//
// SECURITY DISPOSITION. This is the sharpest edge of the hostname-only comparison: a bearer
// token supplied for an https target is transmitted over cleartext on the downgraded hop,
// because net/http keeps the enumerated credential headers when it judges the destination
// host-related, and the closure judged it admissible. Nothing in the exchange announces the
// downgrade to the caller either - RespectHSTS would upgrade the scheme back, but only when
// the PREVIOUS response carried a Strict-Transport-Security field.
//
// PINNED AS MEASURED AND NOT FIXED, on the same grounds as the parent test: refusing the
// downgrade means changing which hops -fhr follows for every user. The remediation in scope
// is the exact assertion below, which states in one place that the token appears in the clear
// so the behaviour is documented rather than latent.
func assertRedirectFollowHostRedirectsAllowsCleartextDowngrade(t *testing.T) {
	const secureStart = "https://origin.example/private"

	cases := []struct {
		name       string
		location   string
		wantHopURL string
		wantData   string
	}{
		{
			// Scheme AND port both change, which is the shape a redirect to a
			// separate cleartext service takes.
			name:       "https to http on a non default port is followed with every credential intact",
			location:   "http://origin.example:8080/collect",
			wantHopURL: "http://origin.example:8080/collect",
			wantData:   "collected on 8080",
		},
		{
			// Only the scheme changes, which isolates the downgrade from the port
			// movement already pinned elsewhere.
			name:       "https to http on the default port is followed with every credential intact",
			location:   "http://origin.example/collect",
			wantHopURL: "http://origin.example/collect",
			wantData:   "collected on 80",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A fresh transport per row. The port is part of a script key, so the two
			// cleartext destinations need separate entries; the scheme is not, so one
			// entry answers /private whether it arrives as https or http.
			rt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
				"origin.example/private":      {status: http.StatusFound, location: tc.location, body: "redirect"},
				"origin.example:8080/collect": {status: http.StatusOK, body: "collected on 8080"},
				"origin.example/collect":      {status: http.StatusOK, body: "collected on 80"},
			}))

			ht := newMockHTTPX(t, func(options *Options) {
				// FollowHostRedirects only: this is the closure whose predicate is
				// under test, and it is installed last, so enabling FollowRedirects
				// too would obscure which one admitted the hop.
				options.FollowHostRedirects = true
				options.MaxRedirects = 10
				options.CustomHeaders = map[string][]string{"Cookie": {redirectSentinelConfiguredCookie}}
			}, rt)

			req, err := retryablehttp.NewRequest(http.MethodGet, secureStart, nil)
			require.NoError(t, err)
			ht.SetCustomHeaders(req, ht.CustomHeaders)
			req.AddCookie(&http.Cookie{Name: "sess", Value: "SENTINEL-SESSION-COOKIE"})
			req.Header.Set("Authorization", redirectSentinelBearer)
			req.Header.Set(redirectSentinelAPIKeyHeader, redirectSentinelAPIKey)

			resp, err := ht.Do(req, UnsafeOptions{})
			require.NoError(t, err)

			require.Equal(t, 2, rt.callCount(),
				"the downgrade must be followed: the hostname-only predicate admits it")
			hops := rt.requests()
			require.Len(t, hops, 2)

			require.Equal(t, secureStart, hops[0].URL)
			require.True(t, strings.HasPrefix(hops[0].URL, "https://"),
				"precondition: the operator's own target is an https URL")
			require.Equal(t, redirectSentinelBearer, hops[0].Header.Get("Authorization"))

			// Assert both the exact destination and its http scheme so the admitted hop
			// is unambiguously cleartext.
			require.Equal(t, tc.wantHopURL, hops[1].URL,
				"the exact URL the transport was asked to fetch names the cleartext destination")
			require.True(t, strings.HasPrefix(hops[1].URL, "http://"),
				"the second hop must be cleartext, which is what the hostname-only predicate permitted")
			require.False(t, strings.HasPrefix(hops[1].URL, "https://"),
				"the second hop must not have been silently kept on TLS: RespectHSTS is off in this test")

			require.Equal(t, redirectSentinelBearer, hops[1].Header.Get("Authorization"),
				"PINNED: the bearer token is transmitted in the clear, because the hostname matched")
			require.Equal(t, hops[0].Header.Get("Authorization"), hops[1].Header.Get("Authorization"),
				"the credential on the cleartext hop is byte for byte the one the TLS hop carried")
			require.Equal(t, redirectSentinelSessionCookie+"; "+redirectSentinelConfiguredCookie,
				hops[1].Header.Get("Cookie"),
				"every cookie reaches the cleartext hop: the hostname matched so net/http copied the inherited session cookie, and the injector preserved it while re-applying the configured one exactly once")
			require.Equal(t, redirectSentinelAPIKey, hops[1].Header.Get(redirectSentinelAPIKeyHeader),
				"the bespoke secret header is copied onto the cleartext hop as well")

			// The control that does fire, asserted as exact empty-string equality: the
			// standard library withholds the referring URL from a downgrade while this
			// policy hands the same hop the credentials above.
			require.Equal(t, "", hops[1].Header.Get("Referer"),
				"net/http suppresses the Referer on an https-to-http hop, which protects the URL but not the credentials")

			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, []byte(tc.wantData), resp.Data,
				"the body identifies which cleartext destination answered")
			require.Len(t, resp.Chain, 2)
			require.True(t, resp.HasChain())
			require.Equal(t, []int{http.StatusFound, http.StatusOK}, resp.GetChainStatusCodes())
			require.Equal(t, tc.wantHopURL, resp.GetChainLastURL(),
				"the operator-visible final URL must record that the scan ended on cleartext")
		})
	}
}

// TestRedirect307308ReplayRequiresRewindableBody pins net/http's documented rule for
// body-preserving redirects: at client.go:531 a 307 or 308 is followed only when the
// original request can reproduce its body, which the standard library decides by testing
// GetBody != nil whenever outgoingLength() is non-zero. When that test fails the library
// deliberately hands the 3xx back to the caller rather than erroring - the behaviour its
// own comment there traces to Go 1.7.
//
// Each status is therefore exercised through both construction paths that a caller can
// choose. Attaching a payload by direct Body/ContentLength assignment leaves GetBody nil
// and the redirect is not followed; building the request through retryablehttp's buffered
// constructor installs GetBody and the body is replayed byte for byte on the second hop.
// A 302 control shows the rule is scoped to body-preserving statuses: a method-rewriting
// redirect drops the body, so no rewind is needed and a nil GetBody is followed anyway.
//
// The assertions describe only the net/http contract and the request the test itself
// builds, so any caller in this repository that starts supplying a rewindable body simply
// matches the rewindable rows below.
func TestRedirect307308ReplayRequiresRewindableBody(t *testing.T) {
	const parityPayload = "payload"
	require.Len(t, parityPayload, 7, "precondition: the request payload is exactly 7 bytes")

	cases := []struct {
		name   string
		status int
		// rewindableBody selects the construction path: false attaches the payload by
		// direct field assignment (Body and ContentLength set, GetBody left nil), true
		// uses retryablehttp's buffered constructor, which installs GetBody.
		rewindableBody bool
		// wantGetBodyNil is the discriminator net/http reads, asserted before the call.
		wantGetBodyNil bool
		// wantHopURLs is the whole observed request stream, so "the redirect was not
		// followed" is stated as a one-entry stream rather than as a count alone.
		wantHopURLs    []string
		wantHopMethods []string
		wantHopBodies  []string
		wantStatus     int
		wantData       string
		// wantLocation is the Location the CALLER is left holding: non-empty exactly
		// when the client declined to follow it.
		wantLocation    string
		wantChainLen    int
		wantStatusCodes []int
		wantLastURL     string
	}{
		{
			name:            "307 with a non-rewindable body is not followed at all",
			status:          http.StatusTemporaryRedirect,
			rewindableBody:  false,
			wantGetBodyNil:  true,
			wantHopURLs:     []string{"http://origin.example/a"},
			wantHopMethods:  []string{http.MethodPost},
			wantHopBodies:   []string{parityPayload},
			wantStatus:      http.StatusTemporaryRedirect,
			wantData:        "redirect",
			wantLocation:    "/b",
			wantChainLen:    1,
			wantStatusCodes: []int{http.StatusTemporaryRedirect},
			wantLastURL:     "",
		},
		{
			// The same status, the same payload, the buffered constructor: followed and
			// replayed. This row is what proves the row above is a property of the
			// body's rewindability and not of the scenario.
			name:            "307 with a rewindable body is followed and replayed",
			status:          http.StatusTemporaryRedirect,
			rewindableBody:  true,
			wantGetBodyNil:  false,
			wantHopURLs:     []string{"http://origin.example/a", "http://origin.example/b"},
			wantHopMethods:  []string{http.MethodPost, http.MethodPost},
			wantHopBodies:   []string{parityPayload, parityPayload},
			wantStatus:      http.StatusOK,
			wantData:        "final",
			wantLocation:    "",
			wantChainLen:    2,
			wantStatusCodes: []int{http.StatusTemporaryRedirect, http.StatusOK},
			wantLastURL:     "http://origin.example/b",
		},
		{
			name:            "308 with a non-rewindable body is not followed at all",
			status:          http.StatusPermanentRedirect,
			rewindableBody:  false,
			wantGetBodyNil:  true,
			wantHopURLs:     []string{"http://origin.example/a"},
			wantHopMethods:  []string{http.MethodPost},
			wantHopBodies:   []string{parityPayload},
			wantStatus:      http.StatusPermanentRedirect,
			wantData:        "redirect",
			wantLocation:    "/b",
			wantChainLen:    1,
			wantStatusCodes: []int{http.StatusPermanentRedirect},
			wantLastURL:     "",
		},
		{
			name:            "308 with a rewindable body is followed and replayed",
			status:          http.StatusPermanentRedirect,
			rewindableBody:  true,
			wantGetBodyNil:  false,
			wantHopURLs:     []string{"http://origin.example/a", "http://origin.example/b"},
			wantHopMethods:  []string{http.MethodPost, http.MethodPost},
			wantHopBodies:   []string{parityPayload, parityPayload},
			wantStatus:      http.StatusOK,
			wantData:        "final",
			wantLocation:    "",
			wantChainLen:    2,
			wantStatusCodes: []int{http.StatusPermanentRedirect, http.StatusOK},
			wantLastURL:     "http://origin.example/b",
		},
		{
			// The 302 control rewrites to GET and drops the body, so no rewind is
			// required and the nil GetBody is irrelevant. This is what scopes the rule
			// above to the body-preserving statuses.
			name:            "302 with a non-rewindable body is followed because the body is dropped",
			status:          http.StatusFound,
			rewindableBody:  false,
			wantGetBodyNil:  true,
			wantHopURLs:     []string{"http://origin.example/a", "http://origin.example/b"},
			wantHopMethods:  []string{http.MethodPost, http.MethodGet},
			wantHopBodies:   []string{parityPayload, ""},
			wantStatus:      http.StatusOK,
			wantData:        "final",
			wantLocation:    "",
			wantChainLen:    2,
			wantStatusCodes: []int{http.StatusFound, http.StatusOK},
			wantLastURL:     "http://origin.example/b",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Script /b even for rows expected not to follow, so request-stream
			// assertions determine the outcome instead of route availability.
			rt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
				"origin.example/a": {status: tc.status, location: "/b", body: "redirect"},
				"origin.example/b": {status: http.StatusOK, body: "final"},
			}))

			ht := newMockHTTPX(t, func(options *Options) {
				options.FollowRedirects = true
				options.MaxRedirects = 10
			}, rt)

			var req *retryablehttp.Request
			var err error
			if tc.rewindableBody {
				// The buffered path: retryablehttp wraps the reader in a reusable
				// reader and installs GetBody alongside it.
				req, err = retryablehttp.NewRequest(http.MethodPost, "http://origin.example/a", strings.NewReader(parityPayload))
				require.NoError(t, err)
			} else {
				// The non-rewindable path: build a body-less request, then attach the
				// payload by direct field assignment. That sets Body and declares
				// ContentLength but never populates GetBody, which is the combination
				// net/http refuses to replay.
				req, err = ht.NewRequestWithContext(context.Background(), http.MethodPost, "http://origin.example/a")
				require.NoError(t, err)
				req.ContentLength = int64(len(parityPayload))
				req.Body = io.NopCloser(strings.NewReader(parityPayload))
			}

			// Both construction paths declare the same content length; GetBody is the
			// field that distinguishes whether net/http can replay a 307/308 body.
			require.Equal(t, tc.wantGetBodyNil, req.GetBody == nil,
				"whether GetBody is populated is the single field net/http consults at client.go:531")
			require.Equal(t, int64(7), req.ContentLength,
				"both construction paths declare the same 7-byte length, so the length cannot explain the difference")
			require.NotNil(t, req.Body,
				"both construction paths must actually carry the payload, otherwise outgoingLength() would be 0 and the rule would never be reached")

			resp, err := ht.Do(req, UnsafeOptions{})
			require.NoError(t, err,
				"a refused 307 is not an error: net/http returns the redirect response itself")

			require.Equal(t, len(tc.wantHopURLs), rt.callCount(),
				"the number of requests that reached the transport is whether the redirect was followed")
			hops := rt.requests()
			require.Len(t, hops, len(tc.wantHopURLs))

			gotHopURLs := make([]string, 0, len(hops))
			gotHopMethods := make([]string, 0, len(hops))
			gotHopBodies := make([]string, 0, len(hops))
			for _, rec := range hops {
				gotHopURLs = append(gotHopURLs, rec.URL)
				gotHopMethods = append(gotHopMethods, rec.Method)
				gotHopBodies = append(gotHopBodies, string(rec.Body))
			}
			require.Equal(t, tc.wantHopURLs, gotHopURLs,
				"the observed request stream states exactly which targets were contacted")
			require.Equal(t, tc.wantHopMethods, gotHopMethods,
				"the method on each hop is what the status code and the construction path decide")
			require.Equal(t, tc.wantHopBodies, gotHopBodies,
				"the exact bytes on each hop prove whether the payload was replayed, dropped, or never re-sent")

			require.Equal(t, tc.wantStatus, resp.StatusCode,
				"a refused redirect surfaces the 3xx itself as the caller's result")
			require.Equal(t, []byte(tc.wantData), resp.Data,
				"the body identifies which response the caller ended up with")
			require.Equal(t, tc.wantLocation, resp.GetHeader("Location"),
				"the Location the caller is left holding is the visible symptom of a redirect that was not followed")

			require.Len(t, resp.Chain, tc.wantChainLen)
			require.Equal(t, tc.wantChainLen > 1, resp.HasChain(),
				"HasChain is len(Chain) > 1, so a refused redirect reports no chain at all")
			require.Equal(t, tc.wantStatusCodes, resp.GetChainStatusCodes())
			require.Equal(t, tc.wantLastURL, resp.GetChainLastURL(),
				"the operator-visible final URL is empty for an unfollowed redirect, because a one-item chain has no last hop to report")
		})
	}
}

// STABLE TOP-LEVEL SELECTORS FOR THE REDIRECT SECURITY SCENARIOS
//
// The three scenarios below are written as assertRedirect* helpers and invoked as
// sub-tests of the policy test whose subject each one extends (:354, :476, :534), and the
// 307/308 body contract is stated by TestRedirect307308ReplayRequiresRewindableBody
// (:1165). That organization keeps each scenario next to the contract it belongs to, but
// it also means a targeted invocation of the scenario's own name - the way a security
// gate, a CI job or an operator reruns exactly one check - matched nothing: `go test -run
// '^TestRedirectCrossOriginForwardsSecretsAndBody$'` reported "[no tests to run]" and
// exited 0, reporting success for a check that never executed.
//
// The wrappers below restore those names as first-class selectors. Each one calls the
// same helper the sub-test calls, so a scenario keeps ONE set of assertions and cannot
// drift between its two entry points, and each is purely additive: no existing test,
// sub-test, helper, fixture or assertion is renamed, reordered, weakened or removed.
//
// None of them is a vacuous test. A wrapper contributes no assertion of its own precisely
// because it must not restate the delegate's; every assertion the selector runs is the
// delegate's exact per-hop request-stream and response evidence, described in the
// delegate's own doc comment.

// TestRedirectCrossOriginForwardsSecretsAndBody is the top-level selector for the
// cross-origin 307 credential-and-body scenario. It runs the same assertions as the
// "a 307 carries the method body and headers to whichever destination Location names"
// sub-test of TestRedirectMethodAndBodyRewriting (:476).
func TestRedirectCrossOriginForwardsSecretsAndBody(t *testing.T) {
	assertRedirectCrossOriginForwardsSecretsAndBody(t)
}

// TestRedirectRefererCrossOriginConfidentiality is the top-level selector for the
// cross-origin and downgrade Referer scenario. It runs the same assertions as the
// "cross origin and downgrade hops decide the Referer by confidentiality" sub-test of
// TestRedirectSetsRefererPerHop (:534).
func TestRedirectRefererCrossOriginConfidentiality(t *testing.T) {
	assertRedirectRefererCrossOriginConfidentiality(t)
}

// TestRedirectFollowHostRedirectsAllowsCleartextDowngrade is the top-level selector for
// the HTTPS-to-HTTP downgrade scenario admitted by hostname-only matching. It runs the
// same assertions as the "hostname match admits an https to http downgrade" sub-test of
// TestRedirectFollowHostRedirectsComparesHostnameOnly (:354).
func TestRedirectFollowHostRedirectsAllowsCleartextDowngrade(t *testing.T) {
	assertRedirectFollowHostRedirectsAllowsCleartextDowngrade(t)
}

// TestRedirectRunnerConstructedBodyIsNotReplayedOn307308 is the top-level selector for
// the non-rewindable half of the 307/308 body contract: a request that attaches its
// payload by direct Body/ContentLength assignment - the way this repository's runner
// builds one - leaves GetBody nil, and net/http therefore hands the 3xx back instead of
// replaying it.
//
// The full contract, including the rewindable counterpart that proves the outcome is a
// property of the body rather than of the scenario, is stated by
// TestRedirect307308ReplayRequiresRewindableBody (:1165), which this selector runs
// verbatim rather than restating a subset of.
func TestRedirectRunnerConstructedBodyIsNotReplayedOn307308(t *testing.T) {
	TestRedirect307308ReplayRequiresRewindableBody(t)
}
