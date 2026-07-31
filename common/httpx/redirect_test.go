package httpx

import (
	"net/http"
	"strings"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// Redirect policy tests: the three mutually exclusive CheckRedirect closures New
// builds (common/httpx/httpx.go:92-143), the redirect budget at its boundary, the
// host-scoping rule, per-status method and body rewriting, the per-hop Referer, and
// the HSTS scheme upgrade.
//
// The closures are built INSIDE New and are selected by option value, in the
// precedence order default < FollowRedirects < FollowHostRedirects. Every test here
// therefore configures them through newMockHTTPX's mutator, which runs before New;
// setting a redirect flag afterwards would leave the already-constructed closure
// untouched and the test would pass vacuously.
//
// The two follow closures duplicate their budget guard (httpx.go:103 and :132) and
// their handleHSTS call (:109 and :138), so those behaviours are swept under BOTH
// rather than under FollowRedirects alone. Each duplicated line was mutated
// independently to confirm the coverage is real: a defect in either copy now fails a
// case here, whereas exercising only one closure left the other silently defective.
//
// Interception is at the transport, never a loopback server, and that is a
// requirement rather than a preference: two httptest servers both bind 127.0.0.1
// while FollowHostRedirects compares URL.Hostname() (httpx.go:123-124), so a
// loopback setup cannot express a cross-host redirect at all. The synthetic
// authorities origin.example and other.example live only inside the scripted
// transport and are never resolved.
//
// Two divergences from documented or specified behaviour are PINNED as measured
// here rather than fixed, each with its reasoning at the test that pins it:
//
//   - the redirect budget is off by one, so the hops actually followed are
//     MaxRedirects-1 (TestRedirectMaxRedirectsBudget);
//   - host scoping compares the hostname only, ignoring port and scheme
//     (TestRedirectFollowHostRedirectsComparesHostnameOnly).
//
// Cookie propagation is deliberately absent: both follow closures call
// setCustomCookies (httpx.go:101 and :120), but no test here configures a cookie,
// so setCustomCookies' hasCustomCookies guard makes it a no-op and cannot perturb
// these assertions. Cookie behaviour is pinned in common/httpx/cookie_auth_test.go.
//
// No test here uses t.Parallel(): New sets the process-global GODEBUG environment
// variable on the HTTP/1.1 path (httpx.go:157), which is unsafe to race.

// TestRedirectDefaultDoesNotFollow pins the default policy, which is the one in
// force whenever neither FollowRedirects nor FollowHostRedirects is set.
//
// The default closure (httpx.go:92-95) returns http.ErrUseLastResponse
// unconditionally, so the 3xx response IS the result: the client stops at the
// redirect, hands back its status, its Location header and its body, and never
// issues a second request. Every value below was measured against the current code.
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

// TestRedirectMaxRedirectsBudget sweeps the redirect budget across its whole
// boundary, which makes it the most mutation-sensitive test in this file: an
// off-by-one in the guard changes the budget for every user of the tool and is
// invisible to a point sample.
//
// PINNED DIVERGENCE - the effective budget is one lower than MaxRedirects, so the
// hops actually followed are MaxRedirects-1 (and 0 for a MaxRedirects of 0 or 1).
// The cause is the guard itself, which is written
//
//	if len(previousRequests) >= options.MaxRedirects
//
// in BOTH follow closures (httpx.go:103 and :132), each annotated with
// https://github.com/golang/go/issues/10069. previousRequests already contains the
// request that produced the current 3xx, so on the first redirect its length is
// already 1 and a MaxRedirects of 1 stops immediately. The guard mirrors the
// standard library's own convention, whose default policy is likewise written
// `if len(via) >= 10`.
//
// This is NOT fixed here, for two reasons. It matches the platform convention the
// code deliberately cites, and the only thing genuinely inconsistent with it is the
// wording of the -maxr flag help text ("max number of redirects to follow per
// host"), which reads one higher than the effective budget. That is a
// DOCUMENTATION-WORDING divergence, not a defect: changing `>=` to `>` would
// silently increase the redirect budget for every existing user. The measured
// contract is pinned instead, so an intentional future correction shows up here as
// a deliberate test change rather than an unnoticed behaviour change.
//
// The guard is DUPLICATED, once per follow closure, so the table sweeps the boundary
// under BOTH. That is not redundancy: the two copies are independent code, and a
// defect introduced into httpx.go:132 alone is invisible to a table that only ever
// enables FollowRedirects - verified by mutating each guard separately and confirming
// each mutation now fails a case here.
func TestRedirectMaxRedirectsBudget(t *testing.T) {
	cases := []struct {
		name string
		// followHostRedirects selects which closure is under test. Exactly one is
		// enabled per row: they are mutually exclusive, and because
		// FollowHostRedirects is installed last it would win if both were set,
		// silently changing which guard the row exercises.
		followHostRedirects bool
		maxRedirects        int
		// wantHopURLs is the exact request stream observed at the transport, so the
		// count, the order and the stopping point are all pinned at once.
		wantHopURLs     []string
		wantStatus      int
		wantData        string
		wantChainLen    int
		wantHasChain    bool
		wantLastURL     string
		wantStatusCodes []int
	}{
		{
			// A budget of 0 can never be satisfied by `len(previousRequests) >= 0`,
			// so the very first redirect is refused.
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
			// The off-by-one made explicit: a budget of 1 follows nothing, because
			// previousRequests already holds 1 entry at the first redirect.
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
			// A budget above the chain length lets the chain run to completion, so
			// the terminal 200 and its body are what the caller sees.
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
			// The same boundary under the host-scoped closure, whose budget guard is
			// a SEPARATE copy at httpx.go:132. Every hop below is same-host, so the
			// host check passes and the budget is what decides. This row is the one
			// that fails if that copy alone is mutated.
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
			// The other side of the same boundary under the host-scoped closure, so
			// the pair pins the guard rather than just one side of it.
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

// TestRedirectFollowHostRedirectsComparesHostnameOnly pins the host-scoping rule,
// the mechanism that decides whether scan traffic - and the credentials travelling
// with it - may leave the target the operator named.
//
// The closure (httpx.go:118-142) compares
//
//	redirectedRequest.URL.Hostname()  vs  previousRequests[0].URL.Hostname()
//
// with a fallback to previousRequests[0].URL.Host when the hostname is empty
// (httpx.go:125-127), and refuses the hop when they differ (:128-131). Note the
// anchor is previousRequests[0], the ORIGINAL target rather than the previous hop;
// the two are observationally identical here, because a cross-host hop is never
// admitted to the chain in the first place.
//
// The empty-hostname fallback is the one branch in this region no case below reaches,
// and deliberately so: it is defensive. previousRequests[0] is a request the client
// actually dialled, so its URL is absolute and carries a host - Hostname() returns
// the empty string only when Host is empty too, which makes the fallback a no-op.
// Forcing it would mean building a request the client cannot send, which would assert
// nothing about real behaviour.
//
// PINNED DIVERGENCE - URL.Hostname() strips the port and the comparison never looks
// at the scheme, so this is a HOSTNAME-ONLY check, not an origin check. RFC 9110
// §4.3.1 defines an origin as the triple scheme + host + port, so a redirect from
// http://origin.example to http://origin.example:8080 or to https://origin.example
// crosses an origin boundary and is nonetheless followed. That is pinned as
// measured, NOT fixed: it is deliberate scanner behaviour - a host that redirects
// http to https, or to a non-default port, is the common case this policy exists to
// keep following - and tightening it to a full origin comparison would change the
// results of every scan that relies on -fhr. The port and scheme rows below exist
// precisely so that such a change cannot happen silently.
//
// This scenario is why the whole file uses a scripted transport: origin.example and
// other.example are distinct hostnames only because they are never resolved. Two
// loopback servers would both be 127.0.0.1 and the comparison above could not tell
// them apart, so the cross-host row could not be written at all.
func TestRedirectFollowHostRedirectsComparesHostnameOnly(t *testing.T) {
	cases := []struct {
		name     string
		location string
		// wantHopURLs is the whole observed request stream: one entry means the
		// redirect was refused, two mean it was followed and to exactly where.
		wantHopURLs     []string
		wantStatus      int
		wantData        string
		wantChainLen    int
		wantHasChain    bool
		wantLastURL     string
		wantStatusCodes []int
	}{
		{
			// The only refusal in this table, and the reason the policy exists.
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
			// A fresh transport per row keeps callCount and the recorded stream
			// scoped to this case. Every destination is scripted, including the
			// cross-host one that must never be requested, so an inverted
			// comparison fails on the assertions below rather than on a missing
			// route. The scheme is not part of a script key, so
			// "origin.example/final" serves the https row as well, while the port IS
			// part of it and needs its own entry.
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
}

// TestRedirectMethodAndBodyRewriting pins how a redirect rewrites the request it
// replays, which decides whether a POST-based probe reaches its target as a POST
// with its payload or as a bodyless GET.
//
// RFC 9110 §15.4 draws the line by status code, and the standard library implements
// it: 301, 302 and 303 may change the method, and net/http rewrites a POST to GET
// and drops the body; 307 and 308 must preserve both, so the buffered body is
// replayed byte for byte. Every value below was measured against the current code.
//
// Three independent axes are asserted per hop, because each fails under a different
// defect:
//
//   - Method, the rewrite decision itself;
//   - the recorded body bytes, which prove the payload was dropped or replayed;
//   - Request.ContentLength, the framing the transport will serialise.
//
// MEASURED CORRECTION, pinned deliberately: the Content-Length HEADER is absent from
// every recorded hop, including hop 1, which genuinely carries 7 bytes. net/http
// keeps the entity length in the Request.ContentLength FIELD and emits the header
// only while writing the request to the wire; it never populates Request.Header. The
// harness snapshots r.Header.Clone(), so the header map cannot carry it. That is an
// observability property of the request model, not a client defect, so the empty
// header is asserted as measured and the declared length is read from the field
// instead - which is also the stronger assertion, since it is the value net/http
// actually serialises.
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
			// RFC 9110 §15.4.2: 301 historically changes POST to GET, and net/http
			// does so, dropping the payload with it.
			name:           "301 rewrites the method to GET and drops the body",
			status:         http.StatusMovedPermanently,
			wantHopMethods: []string{http.MethodPost, http.MethodGet},
			wantHopBodies:  []string{payload, ""},
			wantHopLengths: []int64{7, 0},
		},
		{
			// RFC 9110 §15.4.3: the same historical rewrite for 302.
			name:           "302 rewrites the method to GET and drops the body",
			status:         http.StatusFound,
			wantHopMethods: []string{http.MethodPost, http.MethodGet},
			wantHopBodies:  []string{payload, ""},
			wantHopLengths: []int64{7, 0},
		},
		{
			// RFC 9110 §15.4.4: 303 mandates the change of method to GET.
			name:           "303 rewrites the method to GET and drops the body",
			status:         http.StatusSeeOther,
			wantHopMethods: []string{http.MethodPost, http.MethodGet},
			wantHopBodies:  []string{payload, ""},
			wantHopLengths: []int64{7, 0},
		},
		{
			// RFC 9110 §15.4.8: 307 exists precisely to forbid the rewrite, so the
			// payload must be replayed - which it can only be because the retry
			// layer buffered a rewindable body.
			name:           "307 preserves the method and replays the body",
			status:         http.StatusTemporaryRedirect,
			wantHopMethods: []string{http.MethodPost, http.MethodPost},
			wantHopBodies:  []string{payload, payload},
			wantHopLengths: []int64{7, 7},
		},
		{
			// RFC 9110 §15.4.9: 308 is the permanent counterpart of 307 and
			// preserves method and payload identically.
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

			// A thin recording wrapper around the scripted handler, capturing the
			// two framing fields the harness snapshot cannot expose. This uses the
			// handler hook the harness provides rather than reimplementing the
			// transport, and needs no synchronisation: Do is synchronous and
			// net/http drives the whole redirect loop, including every RoundTrip, on
			// this goroutine.
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

			// Pinned as measured, per the correction in this test's doc comment: the
			// length lives in the field above, never in the header map.
			require.Equal(t, "", hops[0].Header.Get("Content-Length"))
			require.Equal(t, "", hops[1].Header.Get("Content-Length"))

			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, []byte("final"), resp.Data)
			require.Len(t, resp.Chain, 2)
			require.Equal(t, []int{tc.status, http.StatusOK}, resp.GetChainStatusCodes())
			require.Equal(t, "http://origin.example/b", resp.GetChainLastURL())
		})
	}
}

// TestRedirectSetsRefererPerHop pins the Referer sent on each hop of a chain, the
// header that tells every origin in the chain which URL sent the client to it.
//
// net/http populates it on each redirect follow-up from the URL of the request that
// produced the 3xx, so hop N carries hop N-1's absolute URL and the caller's own
// first request carries none. Measured against the current code.
//
// This assertion is only possible because the harness clones the header before
// delegating: net/http mutates and reuses the request object across hops, so a
// stored pointer would report the final hop's Referer for every hop and the test
// would pass under a defect that sent the wrong value.
//
// Options.AutoReferer is deliberately left off. It is an unrelated mechanism applied
// in SetCustomHeaders, and enabling it would inject a Referer of its own and confound
// the value being measured here.
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

	// Absence is asserted as exact empty-string equality, never as a nil check: an
	// unset header reads as "" and that is the value being pinned.
	require.Equal(t, "", hops[0].Header.Get("Referer"),
		"the caller's own request has no predecessor, so it carries no Referer")
	require.Equal(t, "http://origin.example/a", hops[1].Header.Get("Referer"),
		"hop 2 must name hop 1's absolute URL")
	require.Equal(t, "http://origin.example/b", hops[2].Header.Get("Referer"),
		"hop 3 must name hop 2's absolute URL, not the original target")

	// Each hop names its immediate predecessor, so the Referer chain is exactly the
	// hop URLs shifted by one. Asserting the relationship as a whole is what kills a
	// defect that pinned every hop to the first URL.
	require.Equal(t, []string{"", hops[0].URL, hops[1].URL}, []string{
		hops[0].Header.Get("Referer"),
		hops[1].Header.Get("Referer"),
		hops[2].Header.Get("Referer"),
	}, "hop N's Referer must be hop N-1's URL")

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, []byte("three"), resp.Data)
	require.Equal(t, []int{http.StatusFound, http.StatusFound, http.StatusOK}, resp.GetChainStatusCodes())
	require.Equal(t, "http://origin.example/c", resp.GetChainLastURL())
}

// TestRedirectRespectHSTSUpgradesScheme pins the HSTS scheme upgrade, the branch
// that decides whether a redirect to a cleartext URL is dialled as cleartext.
//
// handleHSTS (httpx.go:84-90) rewrites the redirect target's scheme to https when
// the PREVIOUS response carried a Strict-Transport-Security header, and the follow
// closures invoke it only when Options.RespectHSTS is set (httpx.go:108-110). RFC
// 6797 §8.3 specifies exactly this transformation for a known HSTS host.
//
// The upgrade sits AFTER the budget check in both closures, but no test asserts that
// ordering, because it is not observable: handleHSTS mutates the redirect target's
// URL in place, and a hop the budget refuses never becomes a request, so rewriting
// its scheme before refusing it leaves nothing visible on the wire or in the chain.
// Moving the call above the guard was tried and changed no observable value. Pinning
// it would mean asserting something no observer can see, so it is recorded here
// instead.
//
// The third case is what makes this test resistant rather than merely
// demonstrative: it exercises handleHSTS' early return (httpx.go:85-87) with the
// option enabled but no header present. Without it, deleting that guard - a
// plausible one-line defect that would upgrade every redirect target regardless of
// what the origin advertised - would leave this file green.
//
// handleHSTS is likewise invoked from TWO call sites, one per follow closure
// (httpx.go:109 and :138), so the final row drives the host-scoped closure. Without
// it, deleting the call at httpx.go:138 alone would leave this file green - confirmed
// by mutating that line and watching the suite stay green before the row existed.
//
// The upgraded scheme is observable in two places, and both are asserted: the URL
// the transport was actually asked to fetch, and GetChainLastURL. The chain item's
// Location is NOT upgraded in any case, because it records the header as the origin
// wrote it.
func TestRedirectRespectHSTSUpgradesScheme(t *testing.T) {
	cases := []struct {
		name        string
		respectHSTS bool
		// sendSTSHeader controls whether the redirecting response advertises HSTS.
		sendSTSHeader bool
		// followHostRedirects selects the host-scoped closure instead of the plain
		// one, so the second handleHSTS call site is exercised too. Exactly one
		// closure is enabled per row.
		followHostRedirects bool
		wantHopURL          string
		wantLastURL         string
	}{
		{
			// The header is advertised but ignored, so the cleartext target stands.
			name:          "option off keeps http",
			respectHSTS:   false,
			sendSTSHeader: true,
			wantHopURL:    "http://origin.example/final",
			wantLastURL:   "http://origin.example/final",
		},
		{
			// RFC 6797 §8.3: a known HSTS host's http URL is rewritten to https
			// before the request is issued.
			name:          "option on upgrades to https",
			respectHSTS:   true,
			sendSTSHeader: true,
			wantHopURL:    "https://origin.example/final",
			wantLastURL:   "https://origin.example/final",
		},
		{
			// The early return at httpx.go:85-87: with no header advertised there is
			// no HSTS policy to honour, so the target must be left alone even though
			// the option is on.
			name:          "option on without an HSTS header keeps http",
			respectHSTS:   true,
			sendSTSHeader: false,
			wantHopURL:    "http://origin.example/final",
			wantLastURL:   "http://origin.example/final",
		},
		{
			// The host-scoped closure's own handleHSTS call (httpx.go:138). The
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
				// One year, the value RFC 6797 §6.1.1 uses as its example max-age.
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

			// The chain's Location is the header as the origin wrote it, so it stays
			// cleartext even when the request that followed it was upgraded.
			require.Equal(t, "http://origin.example/final", resp.GetChainAsSlice()[0].Location,
				"the recorded Location is the wire value, not the upgraded target")
		})
	}
}
