package httpx

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/projectdiscovery/httpx/common/authprovider/authx"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// These tests cover credential propagation: which cookies and which authentication material
// the client puts on the wire, on which hop, and what survives a redirect to a different
// host. That is the highest-consequence behaviour in the package, because a defect here does
// not produce a wrong result - it hands a credential to a host the operator never named.
//
// Two mechanisms decide the outcome and the tests keep them apart, because they behave
// differently and a single "the cookie arrived" assertion would conflate them:
//
//   - SetCustomHeaders applies the configured headers to the caller's own request, and its
//     "cookie" case falls through to the default branch, so each configured value is added
//     with Header.Add - one header LINE per value.
//   - setCustomCookies is invoked by both redirect closures on every hop they are handed.
//     It deletes the inherited Cookie header and rebuilds it from Options.customCookies with
//     AddCookie, which appends to a SINGLE line, so cookies not present in that option set do
//     not survive a redirect hop.
//
// Configuration therefore has to happen before construction: New parses
// CustomHeaders["Cookie"] into Options.customCookies, so a Cookie set after New leaves
// customCookies empty, hasCustomCookies false and setCustomCookies a silent no-op - every
// cookie assertion downstream would then pass vacuously. Every test here configures cookies
// through newMockHTTPX's option mutator, which the shared harness runs before New for exactly
// this reason.
//
// A different-host redirect is required to exercise net/http's credential-copy policy. Two
// loopback servers still share the hostname 127.0.0.1 even when their ports differ, so
// synthetic hostnames are used: origin.example and other.example live only inside the mock's
// route map and are never resolved.
//
// Absence is always asserted as an exact empty string through the header accessor, never as a
// nil check: an accessor that returned a wrong-but-present value would satisfy a nil check and
// leave the leak undetected.
//
// No test here opts into parallel execution, matching every other test in this package: New
// sets the process-global GODEBUG variable on the HTTP/1.1 path, which is unsafe to race.

// The scripted authorities and payloads. Both hosts exist only inside the route map, so
// no name here is ever resolved.
const (
	// cookieAuthOriginStart is the caller's own target for every redirect scenario.
	cookieAuthOriginStart = "http://origin.example/a"
	// cookieAuthOriginSecond and cookieAuthOriginFinal complete the same-origin chain
	// used by the duplication test, where staying on one origin is what keeps
	// net/http's own credential stripping out of the picture.
	cookieAuthOriginSecond = "http://origin.example/b"
	cookieAuthOriginFinal  = "http://origin.example/c"
	// cookieAuthCrossOriginFinal is a destination on an unrelated registrable domain, which is
	// what makes net/http's shouldCopyHeaderOnRedirect reject the sensitive headers it
	// enumerates.
	cookieAuthCrossOriginFinal = "http://other.example/final"
	// cookieAuthSingleTarget is the single-hop target: no redirect, so the only way a
	// cookie can reach the wire is SetCustomHeaders.
	cookieAuthSingleTarget = "http://origin.example/"

	cookieAuthRedirectBody = "redirect"
	cookieAuthFinalBody    = "final"
	cookieAuthSingleBody   = "ok"

	// cookieAuthMaxRedirects is comfortably above every chain length used here, so no
	// assertion in this file can be perturbed by the redirect budget: the budget
	// boundary itself is redirect_test.go's subject.
	cookieAuthMaxRedirects = 10
)

// The configured cookies, supplied the way the CLI supplies -H "Cookie: ...", plus the
// exact wire forms the two mechanisms produce.
const (
	cookieAuthSessionCookie = "sess=abc"
	cookieAuthIDCookie      = "id=1"
	// cookieAuthJoinedCookies is the single-line form AddCookie builds inside
	// setCustomCookies: "; " between pairs, per RFC 6265 section 5.4.
	cookieAuthJoinedCookies = cookieAuthSessionCookie + "; " + cookieAuthIDCookie
	// cookieAuthDuplicatedSession is the prefix a per-hop duplication defect produces. It is
	// asserted as an absence so the regression is named rather than merely implied by the
	// equality above it.
	cookieAuthDuplicatedSession = cookieAuthSessionCookie + "; " + cookieAuthSessionCookie
)

// cookieAuthCrossOriginTransport returns a FRESH recording transport scripting the
// two-hop cross-origin chain: cookieAuthOriginStart answers 302 with a Location on the
// other origin, and that destination answers 200.
//
// A fresh transport per call is required, not tidiness: callCount and the recorded
// snapshots accumulate, so a transport shared between two table rows would report the
// previous row's hops and make the exact per-hop assertions meaningless.
//
// http://origin.example/final is scripted although it must never be requested. Without
// it, a defect that resolved the absolute Location against the original origin would
// fail on scriptedRedirects' unscripted-route error, which says nothing about
// credential propagation; with it, the same defect fails on the exact URL assertion
// that names the origin change.
func cookieAuthCrossOriginTransport(t *testing.T) *mockTransport {
	t.Helper()
	return newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
		"origin.example/a":     {status: http.StatusFound, location: cookieAuthCrossOriginFinal, body: cookieAuthRedirectBody},
		"other.example/final":  {status: http.StatusOK, body: cookieAuthFinalBody},
		"origin.example/final": {status: http.StatusOK, body: "same origin"},
	}))
}

// TestCustomCookiesReachTheWire asserts that a configured cookie is actually sent.
// TestParseCustomCookies covers only the parsed option state - hasCustomCookies and
// len(Options.customCookies) - so it stays green whether or not the parsed cookies ever reach
// a request; this is the protocol-visible counterpart.
//
// On a single, non-redirected request the redirect closures never run, so the only path that
// can put the cookie on the wire is SetCustomHeaders, which the runner calls in the same
// position this test does.
//
// That path adds one header LINE per configured value (Header.Add in its default branch), so
// two configured cookies arrive as ["sess=abc", "id=1"] and Header.Get - which returns only
// the first line - yields "sess=abc". A header value count is a wire line count: net/http
// writes one "Cookie: ..." line per value in the map.
//
// RFC 6265 section 5.4 says a user agent MUST NOT attach more than one Cookie header field,
// i.e. the joined "sess=abc; id=1" single line. That joined form IS produced here, but only by
// setCustomCookies on a redirect hop, which TestCustomCookiesNotDuplicatedAcrossRedirects pins
// separately. The two mechanisms therefore frame the same configured cookies differently, and
// it is the caller's own request that diverges from the RFC; a recipient is under no obligation
// to interpret multiple Cookie field lines the way it interprets the joined form.
// assertCustomCookieFramingDivergesBetweenMechanisms pins the consequences of the divergence
// that are not merely cosmetic.
//
// The table sweeps one and two configured cookies: with one value both framings agree, so only
// the two-value row can distinguish them.
func TestCustomCookiesReachTheWire(t *testing.T) {
	cases := []struct {
		name       string
		configured []string
		// wantLines is the exact Cookie header as it reaches the transport, one entry
		// per header line.
		wantLines []string
		// wantGet is what Header.Get returns for that framing: the first line only.
		wantGet string
	}{
		{
			name:       "one configured cookie arrives as one line",
			configured: []string{cookieAuthSessionCookie},
			wantLines:  []string{cookieAuthSessionCookie},
			wantGet:    cookieAuthSessionCookie,
		},
		{
			name:       "two configured cookies arrive as one line each",
			configured: []string{cookieAuthSessionCookie, cookieAuthIDCookie},
			wantLines:  []string{cookieAuthSessionCookie, cookieAuthIDCookie},
			// Not the joined form: Header.Get reports the first line, so a caller
			// reading Get sees only the first configured cookie.
			wantGet: cookieAuthSessionCookie,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
				"origin.example/": {status: http.StatusOK, body: cookieAuthSingleBody},
			}))

			ht := newMockHTTPX(t, func(options *Options) {
				// Before New: parseCustomCookies runs inside it (httpx.go:78).
				options.CustomHeaders = map[string][]string{"Cookie": tc.configured}
			}, rt)

			require.True(t, ht.Options.hasCustomCookies(),
				"the cookies must be parsed during construction, otherwise every assertion below is vacuous")
			require.Len(t, ht.Options.customCookies, len(tc.configured),
				"parseCustomCookies must yield one cookie per configured pair (option.go:98-106)")

			req, err := retryablehttp.NewRequest(http.MethodGet, cookieAuthSingleTarget, nil)
			require.NoError(t, err)
			require.Equal(t, "", req.Header.Get("Cookie"),
				"precondition: the freshly built request carries no cookie, so whatever arrives on the wire came from SetCustomHeaders")

			// The production build-up order (runner/runner.go:1882-1900): construct,
			// then apply the configured headers.
			ht.SetCustomHeaders(req, ht.CustomHeaders)

			resp, err := ht.Do(req, UnsafeOptions{})
			require.NoError(t, err)

			require.Equal(t, 1, rt.callCount(), "a 200 must not produce a second request")
			hops := rt.requests()
			require.Len(t, hops, 1)
			require.Equal(t, cookieAuthSingleTarget, hops[0].URL)

			require.Equal(t, tc.wantLines, hops[0].Header.Values("Cookie"),
				"the configured cookies must reach the transport as exactly these header lines")
			require.Equal(t, tc.wantGet, hops[0].Header.Get("Cookie"),
				"Header.Get returns the first line only, so this is the value a single-line reader observes")

			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, []byte(cookieAuthSingleBody), resp.Data)
			require.Len(t, resp.Chain, 1, "a single request produces a single chain item")
			require.Equal(t, []int{http.StatusOK}, resp.GetChainStatusCodes())
		})
	}

	// The same configured cookies observed after the SECOND mechanism reframes them, which
	// is where the header lines above stop being byte-identical to what the wire carries.
	t.Run("the two injection mechanisms frame the same cookies differently", assertCustomCookieFramingDivergesBetweenMechanisms)
}

// TestCustomCookiesNotDuplicatedAcrossRedirects pins the contract that every configured cookie
// appears exactly once per redirect hop, on a single header line.
//
// The failure mode it guards against is specific. net/http copies the caller's multi-line
// Cookie header onto the redirect request; if the injector then merely calls AddCookie, that
// call's internal get-then-set collapses those lines into one and re-appends the first value
// ahead of them, so the duplicate grows with every further hop. The unconditional
// Header.Del("Cookie") that precedes the AddCookie loop in setCustomCookies is what prevents
// it - and it is also why a cookie the operator did not configure does not survive a hop.
//
// The chain stays on one host deliberately: net/http strips Cookie as one of the sensitive
// headers it withholds when the destination host changes, so a different-host chain would mask
// the duplication behind that strip and prove nothing about the injector.
func TestCustomCookiesNotDuplicatedAcrossRedirects(t *testing.T) {
	rt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
		"origin.example/a": {status: http.StatusFound, location: "/b", body: cookieAuthRedirectBody},
		"origin.example/b": {status: http.StatusFound, location: "/c", body: cookieAuthRedirectBody},
		"origin.example/c": {status: http.StatusOK, body: cookieAuthFinalBody},
	}))

	ht := newMockHTTPX(t, func(options *Options) {
		options.CustomHeaders = map[string][]string{"Cookie": {cookieAuthSessionCookie, cookieAuthIDCookie}}
		options.FollowRedirects = true
		options.MaxRedirects = cookieAuthMaxRedirects
	}, rt)

	require.Len(t, ht.Options.customCookies, 2,
		"both configured cookies must be parsed during construction, otherwise the injector has nothing to duplicate")

	req, err := retryablehttp.NewRequest(http.MethodGet, cookieAuthOriginStart, nil)
	require.NoError(t, err)
	ht.SetCustomHeaders(req, ht.CustomHeaders)

	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err)

	require.Equal(t, 3, rt.callCount(), "two redirects must be followed, producing three requests")
	hops := rt.requests()
	require.Len(t, hops, 3)
	require.Equal(t, []string{cookieAuthOriginStart, cookieAuthOriginSecond, cookieAuthOriginFinal},
		[]string{hops[0].URL, hops[1].URL, hops[2].URL},
		"the relative Locations must resolve against the previous hop, keeping the whole chain on one origin")

	// Hop 1 was built by SetCustomHeaders, which adds one line per configured value.
	require.Equal(t, []string{cookieAuthSessionCookie, cookieAuthIDCookie}, hops[0].Header.Values("Cookie"),
		"the caller's own request carries one header line per configured cookie")

	// Hops 2 and 3 were built by setCustomCookies, which resets and re-adds, producing one line
	// holding both pairs. BOTH redirect hops are asserted because a duplication defect grows
	// with each hop, so cleaning up only the first redirect would still be wrong. Iteration is
	// over a slice, so the hop numbers in the diagnostics are deterministic.
	redirectHops := []struct {
		number int
		rec    recordedRequest
	}{
		{number: 2, rec: hops[1]},
		{number: 3, rec: hops[2]},
	}
	for _, hop := range redirectHops {
		require.Equalf(t, cookieAuthJoinedCookies, hop.rec.Header.Get("Cookie"),
			"hop %d must carry each configured cookie exactly once, on one line", hop.number)
		require.Lenf(t, hop.rec.Header.Values("Cookie"), 1,
			"hop %d must carry the cookies as a single header line, never one line per cookie", hop.number)
		require.NotContainsf(t, hop.rec.Header.Get("Cookie"), cookieAuthDuplicatedSession,
			"hop %d: the inherited Cookie header must not be re-appended, which is what the delete before the AddCookie loop prevents", hop.number)
	}

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, []byte(cookieAuthFinalBody), resp.Data)
	require.Len(t, resp.Chain, 3, "three requests produce three chain items")
	require.Equal(t, []int{http.StatusFound, http.StatusFound, http.StatusOK}, resp.GetChainStatusCodes())
	require.Equal(t, cookieAuthOriginFinal, resp.GetChainLastURL(),
		"the final URL must name the last hop of the chain")

	// The reach of the same delete, observed against cookies the injector did NOT
	// configure: they are discarded with the rest of the inherited header.
	t.Run("the delete also discards the cookies the injector did not configure", assertCustomCookiesReplaceInheritedCookiesOnRedirectHops)
}

// TestAuthorizationStrippedOnCrossOriginRedirect asserts that an Authorization header set on
// the caller's request is NOT carried to a destination on a different host.
//
// The credential is set with req.Header.Set rather than through an auth strategy, so the
// assertion isolates net/http's redirect header policy from anything the strategies do;
// TestAuthStrategiesAppliedThroughRedirect covers the strategy-driven paths.
//
// net/http withholds six sensitive headers - Authorization, Www-Authenticate, Cookie, Cookie2,
// Proxy-Authorization and Proxy-Authenticate, listed together in the header-copy switch of
// Client.do (net/http/client.go:814-815 in Go 1.26) - whenever the destination host differs from
// the initial request's. That is the mitigation RFC 9110 section 15.4 calls for when a redirect
// target is not necessarily trusted with the original request's credentials. The set is
// enumerated exactly because a credential carried outside it can cross to the other host, which
// TestAuthStrategiesAppliedThroughRedirect pins for a custom auth header. Proxy-Authorization,
// the other request-side member, is asserted per destination in common/httpx/redirect_test.go.
//
// Absence is asserted as an exact empty string. A nil check would also be satisfied by a defect
// that forwarded a truncated or stale credential, which is the outcome this test exists to catch.
func TestAuthorizationStrippedOnCrossOriginRedirect(t *testing.T) {
	const bearer = "Bearer tok"

	rt := cookieAuthCrossOriginTransport(t)

	ht := newMockHTTPX(t, func(options *Options) {
		options.FollowRedirects = true
		options.MaxRedirects = cookieAuthMaxRedirects
	}, rt)

	require.False(t, ht.Options.hasCustomCookies(),
		"precondition: no cookie is configured here, so nothing re-injects one and the Cookie assertions below observe net/http alone")

	req, err := retryablehttp.NewRequest(http.MethodGet, cookieAuthOriginStart, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", bearer)

	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err)

	require.Equal(t, 2, rt.callCount(), "the 302 must be followed exactly once")
	hops := rt.requests()
	require.Len(t, hops, 2)

	require.Equal(t, cookieAuthOriginStart, hops[0].URL)
	require.Equal(t, http.MethodGet, hops[0].Method)
	require.Equal(t, bearer, hops[0].Header.Get("Authorization"),
		"the caller's own origin receives the credential verbatim")
	require.Equal(t, "", hops[0].Header.Get("Referer"),
		"the caller's own request has no predecessor, so it carries no Referer")

	require.Equal(t, cookieAuthCrossOriginFinal, hops[1].URL,
		"the second hop must be the absolute Location, on the other origin - that origin change is what triggers the strip")
	require.Equal(t, http.MethodGet, hops[1].Method,
		"a 302 with a GET leaves the method unchanged, so only the credential differs between the hops")
	require.Equal(t, "", hops[1].Header.Get("Authorization"),
		"Authorization is enumerated as sensitive, so the other origin must receive an empty value - not a truncated or stale one")
	require.Equal(t, "", hops[1].Header.Get("Cookie"),
		"no cookie was set or configured, so the other origin must receive no Cookie header either")
	require.Equal(t, cookieAuthOriginStart, hops[1].Header.Get("Referer"),
		"the destination is still told which URL sent the client to it, which is why the strip is the only thing protecting the credential")

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, []byte(cookieAuthFinalBody), resp.Data)
	require.Len(t, resp.Chain, 2, "two requests produce two chain items")
	require.True(t, resp.HasChain())
	require.Equal(t, []int{http.StatusFound, http.StatusOK}, resp.GetChainStatusCodes())
	require.Equal(t, cookieAuthCrossOriginFinal, resp.GetChainLastURL(),
		"the final URL must name the origin that answered, so a caller can see the request left the target it asked for")
}

// TestCustomCookieReinjectedAcrossOrigins pins a divergence: a CONFIGURED cookie is re-injected
// on a redirect hop even when that hop crosses to a different host.
//
// The cause is by design. Both follow closures call setCustomCookies unconditionally on every
// request net/http hands them, before any budget or host decision is taken, and that function
// deletes whatever Cookie header survived and re-adds Options.customCookies. The net effect is
// that net/http's strip is undone for the configured cookies specifically: an INHERITED cookie
// is gone, while a CONFIGURED one reappears on the new host.
//
// This diverges from RFC 6265 section 5.4, under which a user agent sends a cookie only to a
// host its Domain attribute covers. It is intentional scanner behaviour - an operator who passes
// -H "Cookie: ..." is asserting the cookie applies to the scan, and a redirect within a scanned
// application would otherwise lose the session - and it is pinned rather than changed because
// changing it would alter results for every user.
//
// The exact single-line value is what makes the pin meaningful: it distinguishes "re-injected
// once" from "re-injected on top of whatever was inherited".
func TestCustomCookieReinjectedAcrossOrigins(t *testing.T) {
	rt := cookieAuthCrossOriginTransport(t)

	ht := newMockHTTPX(t, func(options *Options) {
		options.CustomHeaders = map[string][]string{"Cookie": {cookieAuthSessionCookie}}
		options.FollowRedirects = true
		options.MaxRedirects = cookieAuthMaxRedirects
	}, rt)

	require.Len(t, ht.Options.customCookies, 1,
		"the configured cookie must be parsed during construction, otherwise the re-injection under test cannot happen")

	req, err := retryablehttp.NewRequest(http.MethodGet, cookieAuthOriginStart, nil)
	require.NoError(t, err)
	ht.SetCustomHeaders(req, ht.CustomHeaders)

	resp, err := ht.Do(req, UnsafeOptions{})
	require.NoError(t, err)

	require.Equal(t, 2, rt.callCount(), "the 302 must be followed exactly once")
	hops := rt.requests()
	require.Len(t, hops, 2)

	require.Equal(t, cookieAuthOriginStart, hops[0].URL)
	require.Equal(t, []string{cookieAuthSessionCookie}, hops[0].Header.Values("Cookie"),
		"the caller's own origin receives the configured cookie from SetCustomHeaders")

	require.Equal(t, cookieAuthCrossOriginFinal, hops[1].URL,
		"the second hop is on a different registrable domain, which is what makes the re-injection notable")
	require.Equal(t, cookieAuthSessionCookie, hops[1].Header.Get("Cookie"),
		"PINNED: the configured cookie is re-injected on the new host by setCustomCookies, although net/http had stripped the inherited Cookie header")
	require.Len(t, hops[1].Header.Values("Cookie"), 1,
		"PINNED: exactly one header line, so the cookie is re-injected once rather than layered onto an inherited value")

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, []byte(cookieAuthFinalBody), resp.Data)
	require.Len(t, resp.Chain, 2)
	require.Equal(t, []int{http.StatusFound, http.StatusOK}, resp.GetChainStatusCodes())
	require.Equal(t, cookieAuthCrossOriginFinal, resp.GetChainLastURL(),
		"the final URL names the origin that received the configured cookie")
}

// The credential values below are synthetic test fixtures for the five authentication
// strategies.
const (
	cookieAuthBasicUser     = "u"
	cookieAuthBasicPassword = "p"
	// cookieAuthBasicExpected is the exact Authorization value SetBasicAuth produces: the
	// "Basic " prefix of RFC 9110 section 11.7 followed by the base64 of "user:password". The
	// literal is asserted rather than recomputed at the assertion site so an encoding defect
	// cannot be masked by appearing on both sides; a precondition inside the test proves the
	// literal really is that encoding.
	cookieAuthBasicExpected = "Basic dTpw"

	cookieAuthBearerToken    = "tok"
	cookieAuthBearerExpected = "Bearer " + cookieAuthBearerToken

	// cookieAuthCustomHeaderKey is deliberately NOT in canonical MIME form. HeadersAuthStrategy
	// writes it into the header map directly, so the casing survives to the wire and
	// http.Header.Get - which canonicalizes its argument - cannot find it. Every assertion on
	// this key therefore reads the raw map.
	cookieAuthCustomHeaderKey   = "barAuthToken"
	cookieAuthCustomHeaderValue = "v1"

	cookieAuthStrategyCookieKey   = "sid"
	cookieAuthStrategyCookieValue = "s1"
	cookieAuthStrategyCookiePair  = cookieAuthStrategyCookieKey + "=" + cookieAuthStrategyCookieValue

	cookieAuthQueryParamKey   = "apikey"
	cookieAuthQueryParamValue = "k1"
	// cookieAuthQueryStart is the caller's target once QueryAuthStrategy has appended
	// its parameter: the credential lives in the request URI, not in a header.
	cookieAuthQueryStart = cookieAuthOriginStart + "?" + cookieAuthQueryParamKey + "=" + cookieAuthQueryParamValue
)

// TestAuthStrategiesAppliedThroughRedirect drives all five authentication strategies through a
// real client request that crosses to a different host. The strategy unit tests in
// common/authprovider/authx apply each strategy to a bare request and assert the header it
// wrote, so they cannot observe what happens to that header when the client follows a redirect -
// and that is the only moment at which a credential can reach a host the operator never named.
//
// Each row builds a real authx.Secret with the Type string spelled exactly as
// common/authprovider/authx/file.go defines it. The literals matter: three of the five Go
// identifiers differ from their string values (BearerTokenAuth is "BearerToken", HeadersAuth is
// "Header", CookiesAuth is "Cookie"), and GetStrategy dispatches on the string with
// strings.EqualFold, so pinning the literal is what catches a renamed constant. GetStrategy does
// not call Validate, so no Domains entry is needed to obtain a working strategy. ApplyOnRR is the
// method under test because the client works with *retryablehttp.Request, and it is applied in
// the production position, after SetCustomHeaders.
//
// The table states the FULL observable credential surface on both hops for every row, not just
// the field the row is about. A strategy that wrote into an extra header, or that leaked its
// material into the URL, therefore fails on a row that never mentions its own mechanism.
//
// Outcomes, two of which are security-relevant:
//
//   - Basic, Bearer and Cookie material is withheld from the other origin, because
//     Authorization and Cookie are both in net/http's enumerated sensitive set.
//   - Query material is not re-applied to the other host's URL, because the redirect target is
//     taken from the Location header verbatim and nothing appends the parameter again. It
//     nevertheless REACHES that host, in the Referer: net/http derives each hop's Referer from
//     the previous hop's URL, and Referer is not in the sensitive set, so the whole
//     credential-bearing request URI is disclosed. Asserting only the hop-2 URL would name
//     non-propagation while leaving the disclosure unobserved, so every row pins its exact hop-2
//     Referer and the query row pins the credential inside it. RFC 9110 section 10.1.3 warns
//     about exactly this. Credential-bearing URLs can leak through Referer; the mitigation is an
//     authentication mechanism with explicit redirect scoping rather than query parameters or
//     arbitrary headers. The general form, including a URL userinfo password crossing to another
//     host under AutoReferer, is pinned in common/httpx/redirect_test.go.
//   - The custom auth header SURVIVES, and is pinned rather than changed. For this redirect it
//     is outside the six cross-host sensitive headers enumerated in
//     TestAuthorizationStrippedOnCrossOriginRedirect, so it is copied to the destination; other
//     redirect rules can still suppress headers, notably the body-related ones the same switch
//     withholds when a redirect removes the body. HeadersAuthStrategy.ApplyOnRR writes
//     req.Header[header.Key] directly, bypassing canonicalization, which its own NOTE documents
//     as intentional so that case-sensitive APIs keep working. Neither half is this file's to
//     change: the strip list belongs to the standard library and the exact casing is a
//     documented feature of the strategy.
//
// AAP DISPOSITION for the two security-relevant outcomes above. Suppressing the Referer
// disclosure means rewriting the header on an admitted redirect inside
// common/httpx/httpx.go's CheckRedirect closure, or changing net/http's refererForURL;
// withholding the custom auth header means changing net/http's cross-host strip list or
// common/authprovider/authx. AAP section 0.8.1.3 authorises exactly two fixes in
// common/httpx/httpx.go and no change to any other source file, section 0.8.2.1 places
// anything further in httpx.go out of scope, section 0.8.2.6 puts standard-library behaviour
// in the "asserted, not fixed" category, and section 0.4.5.4 already lists "a custom auth
// header survives a cross-origin redirect" among the divergences deliberately not fixed.
// Section 0.10.1.1 prescribes precisely the treatment used here: pin the current behaviour and
// record the divergence rather than change it. A future engagement authorised to change the
// redirect closure should suppress or sanitise the Referer for a cross-origin hop and withhold
// non-allowlisted credential headers; the query and custom-header rows below then fail and
// state the new contract.
func TestAuthStrategiesAppliedThroughRedirect(t *testing.T) {
	require.Equal(t,
		"Basic "+base64.StdEncoding.EncodeToString([]byte(cookieAuthBasicUser+":"+cookieAuthBasicPassword)),
		cookieAuthBasicExpected,
		"precondition: the asserted Basic value must really be the base64 of the credential pair, so the expectation is derived from RFC 9110 section 11.7 rather than transcribed")

	cases := []struct {
		name   string
		secret *authx.Secret
		// The exact credential surface hop 1 - the caller's own origin - receives.
		wantHop1URL           string
		wantHop1Authorization string
		wantHop1Cookie        string
		// wantHop1CustomHeader is a raw-map read, so nil means the key is absent.
		wantHop1CustomHeader []string
		// The same surface after the redirect to the other origin. Every value here is
		// what the OTHER origin gets to see.
		wantHop2Authorization string
		wantHop2Cookie        string
		wantHop2CustomHeader  []string
		// wantHop2Referer is the exact Referer the other host receives. It belongs in the
		// credential surface because net/http builds it from the PREVIOUS hop's URL and Referer
		// is absent from the sensitive set, so whatever the caller's URI carried is handed to
		// the redirect target verbatim.
		wantHop2Referer string
		// wantHop2RefererDisclosesCredential marks the row whose credential lives in the request
		// URI rather than in a header: for that row the Referer above is itself the leak, and
		// asserting the clean hop-2 URL alone would miss it.
		wantHop2RefererDisclosesCredential bool
	}{
		{
			name:                  "basic auth credential withheld from the other origin",
			secret:                &authx.Secret{Type: "BasicAuth", Username: cookieAuthBasicUser, Password: cookieAuthBasicPassword},
			wantHop1URL:           cookieAuthOriginStart,
			wantHop1Authorization: cookieAuthBasicExpected,
			wantHop2Authorization: "",
			// The caller's own URI carried no credential material, so the Referer
			// discloses nothing beyond the path the operator already named.
			wantHop2Referer: cookieAuthOriginStart,
		},
		{
			name:                  "bearer token withheld from the other origin",
			secret:                &authx.Secret{Type: "BearerToken", Token: cookieAuthBearerToken},
			wantHop1URL:           cookieAuthOriginStart,
			wantHop1Authorization: cookieAuthBearerExpected,
			wantHop2Authorization: "",
			wantHop2Referer:       cookieAuthOriginStart,
		},
		{
			// The first security observation in this function's doc comment.
			name:                 "custom auth header survives to the other origin",
			secret:               &authx.Secret{Type: "Header", Headers: []authx.KV{{Key: cookieAuthCustomHeaderKey, Value: cookieAuthCustomHeaderValue}}},
			wantHop1URL:          cookieAuthOriginStart,
			wantHop1CustomHeader: []string{cookieAuthCustomHeaderValue},
			wantHop2CustomHeader: []string{cookieAuthCustomHeaderValue},
			wantHop2Referer:      cookieAuthOriginStart,
		},
		{
			name:           "strategy cookie withheld from the other origin",
			secret:         &authx.Secret{Type: "Cookie", Cookies: []authx.Cookie{{Key: cookieAuthStrategyCookieKey, Value: cookieAuthStrategyCookieValue}}},
			wantHop1URL:    cookieAuthOriginStart,
			wantHop1Cookie: cookieAuthStrategyCookiePair,
			// Withheld by net/http AND not restored: a strategy applies this cookie per target,
			// so it is absent from Options.customCookies and setCustomCookies has nothing to
			// re-inject - the contrast with TestCustomCookieReinjectedAcrossOrigins is the point.
			wantHop2Cookie:  "",
			wantHop2Referer: cookieAuthOriginStart,
		},
		{
			// The second security observation in this function's doc comment: the credential is
			// not re-applied to the other host's URL, yet that host still receives it, because
			// the Referer net/http synthesizes IS the caller's credential-bearing request URI.
			name:        "query credential is not re-applied to the other origin's URL but reaches it in the Referer",
			secret:      &authx.Secret{Type: "Query", Params: []authx.KV{{Key: cookieAuthQueryParamKey, Value: cookieAuthQueryParamValue}}},
			wantHop1URL: cookieAuthQueryStart,
			// Exactly the credential-bearing URI, asserted as an equality rather than a
			// substring so a defect that widened OR narrowed the disclosure is caught.
			wantHop2Referer:                    cookieAuthQueryStart,
			wantHop2RefererDisclosesCredential: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A fresh transport per row: callCount and the recorded snapshots
			// accumulate, so a shared one would let an earlier row's hops satisfy this
			// row's assertions.
			rt := cookieAuthCrossOriginTransport(t)

			ht := newMockHTTPX(t, func(options *Options) {
				options.FollowRedirects = true
				options.MaxRedirects = cookieAuthMaxRedirects
			}, rt)
			require.False(t, ht.Options.hasCustomCookies(),
				"precondition: no cookie is configured, so nothing re-injects one and each row observes its own strategy only")

			req, err := retryablehttp.NewRequest(http.MethodGet, cookieAuthOriginStart, nil)
			require.NoError(t, err)

			strategy := tc.secret.GetStrategy()
			require.NotNil(t, strategy,
				"GetStrategy dispatches on the Type string (authx/file.go:66-80) and returns nil for an unrecognized one, so a nil here means the literal no longer matches")
			strategy.ApplyOnRR(req)

			resp, err := ht.Do(req, UnsafeOptions{})
			require.NoError(t, err)

			require.Equal(t, 2, rt.callCount(), "the 302 must be followed exactly once")
			hops := rt.requests()
			require.Len(t, hops, 2)

			require.Equal(t, tc.wantHop1URL, hops[0].URL,
				"hop 1's request URI must carry exactly the credential material the strategy put there, and nothing more")
			require.Equal(t, tc.wantHop1Authorization, hops[0].Header.Get("Authorization"),
				"hop 1's Authorization must be exactly what this strategy writes - empty for the strategies that write elsewhere")
			require.Equal(t, tc.wantHop1Cookie, hops[0].Header.Get("Cookie"),
				"hop 1's Cookie must be exactly what this strategy writes - empty for the strategies that write elsewhere")
			// The raw map index is deliberate: HeadersAuthStrategy writes a non-canonical key
			// directly, so canonicalizing the lookup here would look for "Barauthtoken", find
			// nothing, and silently assert nothing.
			require.Equal(t, tc.wantHop1CustomHeader, hops[0].Header[cookieAuthCustomHeaderKey], //nolint:staticcheck // SA1008: the non-canonical key is the behaviour under test
				"hop 1's non-canonical key is read from the raw map, because Header.Get would canonicalize the lookup and miss the direct map write")

			require.Equal(t, cookieAuthCrossOriginFinal, hops[1].URL,
				"hop 2 must be the absolute Location verbatim: no query parameter is re-applied to it, which is why a query credential cannot propagate")
			require.NotContains(t, hops[1].URL, cookieAuthQueryParamKey,
				"the other origin must not receive the query credential, not even as a bare key")

			// The Referer is part of the credential surface, not a detail of it: derived from the
			// previous hop's URL and not enumerated as sensitive, it is the one header that
			// carries the caller's own URI - credentials included - to another host.
			require.Equal(t, tc.wantHop2Referer, hops[1].Header.Get("Referer"),
				"the other origin's Referer must be exactly this URI: it is the disclosure channel that survives the credential strip")
			require.Len(t, hops[1].Header.Values("Referer"), 1,
				"the Referer must arrive as exactly one header line, so the exact value above is the whole disclosure")
			if tc.wantHop2RefererDisclosesCredential {
				require.Contains(t, hops[1].Header.Get("Referer"), cookieAuthQueryParamKey+"="+cookieAuthQueryParamValue,
					"PINNED SECURITY OBSERVATION: a credential carried in the request URI is disclosed to the redirect target through the Referer (RFC 9110 section 10.1.3), even though hop 2's own URL is clean")
			} else {
				require.NotContains(t, hops[1].Header.Get("Referer"), cookieAuthQueryParamKey,
					"a strategy that writes into a header must leave no credential material in the URI, so nothing can reach the other origin through the Referer either")
			}
			require.Equal(t, tc.wantHop2Authorization, hops[1].Header.Get("Authorization"),
				"the other origin's Authorization must be exactly this value - an empty string means withheld, never merely absent from a nil check")
			require.Equal(t, tc.wantHop2Cookie, hops[1].Header.Get("Cookie"),
				"the other origin's Cookie must be exactly this value - an empty string means withheld, never merely absent from a nil check")
			require.Equal(t, tc.wantHop2CustomHeader, hops[1].Header[cookieAuthCustomHeaderKey], //nolint:staticcheck // SA1008: the non-canonical key is the behaviour under test
				"PINNED SECURITY OBSERVATION: this custom auth header is outside net/http's six cross-host sensitive headers (Authorization, Www-Authenticate, Cookie, Cookie2, Proxy-Authorization, Proxy-Authenticate), so for this redirect it is copied to the other host")
			require.Equal(t, "", hops[1].Header.Get(cookieAuthCustomHeaderKey),
				"Header.Get canonicalizes its argument, so it cannot observe the directly written key at all - which is exactly why a reviewer auditing with Get would miss the leak above")

			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, []byte(cookieAuthFinalBody), resp.Data)
			require.Len(t, resp.Chain, 2, "two requests produce two chain items")
			require.Equal(t, []int{http.StatusFound, http.StatusOK}, resp.GetChainStatusCodes(),
				"the status sequence is ordered, so the redirect must precede the final response")
			require.Equal(t, cookieAuthCrossOriginFinal, resp.GetChainLastURL(),
				"the final URL must name the other origin, so a caller can see which host the credential decision applied to")
		})
	}
}

// The cookies an unrelated mechanism puts on the caller's request, used below to observe what the
// configured-cookie path does to material it did not create.
const (
	// cookieAuthPlainCookie is set with a bare Header.Set, the way any caller or middleware that
	// is not cookie-aware would set one.
	cookieAuthPlainCookie = "extra=1"
	// cookieAuthAddedCookie is added with req.AddCookie, the cookie-aware API whose get-then-set
	// behaviour makes the multi-line framing lossy.
	cookieAuthAddedCookieName  = "extra"
	cookieAuthAddedCookieValue = "1"
)

// cookieAuthSameOriginChainTransport returns a FRESH recording transport scripting the three-hop
// same-host chain /a -> /b -> /c, the shape the duplication test uses.
//
// One host is deliberate for every scenario below: net/http withholds Cookie whenever the
// destination host changes, so a different-host chain could not tell "the client's own injector
// discarded this cookie" from "the standard library stripped it", and the injector is the subject.
func cookieAuthSameOriginChainTransport(t *testing.T) *mockTransport {
	t.Helper()
	return newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
		"origin.example/a": {status: http.StatusFound, location: "/b", body: cookieAuthRedirectBody},
		"origin.example/b": {status: http.StatusFound, location: "/c", body: cookieAuthRedirectBody},
		"origin.example/c": {status: http.StatusOK, body: cookieAuthFinalBody},
	}))
}

// assertCustomCookiesReplaceInheritedCookiesOnRedirectHops pins the REACH of the injector's
// delete: on every redirect hop the Cookie header is rebuilt from Options.customCookies alone,
// so a cookie the injector did not configure - a session cookie an authentication strategy
// applied included - does not survive the hop.
//
// Mechanism: setCustomCookies deletes the Cookie header once and then re-adds
// Options.customCookies, and the redirect closures call it on every hop. That delete is what
// stops the duplication TestCustomCookiesNotDuplicatedAcrossRedirects pins, and it is
// unconditional within the hasCustomCookies guard - it is not scoped to the configured names.
//
// The consequence is worth naming plainly, because it is invisible in a passing scan: with
// -H "Cookie: ..." supplied AND an authx Cookie secret in play, the first request is
// authenticated and every redirect hop is NOT, so an application answering 302 at its login gate
// is probed unauthenticated while the output still shows a 200. Narrowing the delete to the
// configured names would repair it - CookiesAuthStrategy.ApplyOnRR already filters
// req.Cookies() that way - but that is a change to client behaviour rather than to a test, so
// the loss is stated here per hop instead: it can neither widen nor be repaired silently.
//
// The two CONTROL rows keep the result attributable: with no cookie configured,
// hasCustomCookies is false, setCustomCookies returns without touching anything, and the hop
// carries the foreign cookie ALONE. The loss on the configured rows is therefore the injector's
// delete, not redirect handling dropping the header.
//
// AAP DISPOSITION. The delete is not incidental: AAP section 0.4.5.1 specifies FIX-1 verbatim as
// the single statement req.Header.Del("Cookie") placed before the injection loop, and section
// 0.8.1.3 caps the whole engagement's source change at that fix plus the read-cap guard. A
// name-scoped merge - preserving inherited cookies whose names do not collide with the
// configured set - was implemented earlier in this engagement (commits 3cfd5f4 and 0551435) and
// deliberately REVERTED (commit 86e17e2) precisely because it exceeded that authorised
// boundary, which section 0.8.2.1 states as "any change to common/httpx/httpx.go beyond the two
// documented five-line fixes". The result is a functional trade-off the AAP boundary forces:
// exact de-duplication, at the cost of inherited cookies the injector did not configure. It is
// credential LOSS rather than credential disclosure, so no boundary is weakened by pinning it.
// Reinstating the name-scoped merge requires an amended AAP; the exact per-hop rows below,
// together with the two controls, are what make either outcome impossible to change silently.
func assertCustomCookiesReplaceInheritedCookiesOnRedirectHops(t *testing.T) {
	authxCookieStrategy := func(t *testing.T, req *retryablehttp.Request) {
		t.Helper()
		secret := &authx.Secret{Type: "Cookie", Cookies: []authx.Cookie{{Key: cookieAuthStrategyCookieKey, Value: cookieAuthStrategyCookieValue}}}
		strategy := secret.GetStrategy()
		require.NotNil(t, strategy, "the Cookie strategy literal must still dispatch (authx/file.go:19-25)")
		// The production order: strategies are applied after SetCustomHeaders
		// (runner/runner.go:1900-1908).
		strategy.ApplyOnRR(req)
	}
	addedHeaderCookie := func(t *testing.T, req *retryablehttp.Request) {
		t.Helper()
		// Add appends a header line, so the configured lines SetCustomHeaders wrote survive
		// alongside it, proving the cookie existed on hop 1 before the redirect hops rebuilt it.
		req.Header.Add("Cookie", cookieAuthPlainCookie)
	}
	replacedHeaderCookie := func(t *testing.T, req *retryablehttp.Request) {
		t.Helper()
		// Set replaces every existing line, so the caller's own request loses the configured
		// cookies entirely, and the injector hands them back on the redirect hops.
		req.Header.Set("Cookie", cookieAuthPlainCookie)
	}

	cases := []struct {
		name string
		// configured is what -H "Cookie: ..." supplies; nil means none, which is the
		// control condition.
		configured []string
		// applyForeign puts a cookie on the request that setCustomCookies did not
		// configure.
		applyForeign func(*testing.T, *retryablehttp.Request)
		// wantHop1Lines is the exact Cookie header the caller's own request carries, one
		// entry per header line, so a row that changes the FRAMING as well as the value
		// is caught.
		wantHop1Lines []string
		// wantRedirectHopCookie is the exact value hops 2 AND 3 carry, always on one line because
		// setCustomCookies rebuilds the header with AddCookie: the configured cookies and nothing
		// else, or - on the control rows, where the injector never runs - the foreign cookie alone.
		wantRedirectHopCookie string
		// foreignPair is the "name=value" the foreign mechanism contributed, named so
		// the outcome can be asserted as a presence or an absence in its own right
		// rather than only as part of an equality.
		foreignPair string
		// wantForeignOnRedirectHops states whether that pair survives the hop: false on
		// every configured row, because the delete is not scoped to the configured names.
		wantForeignOnRedirectHops bool
	}{
		{
			name:         "an authx session cookie is dropped from every redirect hop",
			configured:   []string{cookieAuthSessionCookie},
			applyForeign: authxCookieStrategy,
			// One line: CookiesAuthStrategy.ApplyOnRR rebuilds the whole header from
			// req.Cookies(), so it re-frames the configured cookie as it merges its own.
			wantHop1Lines: []string{cookieAuthSessionCookie + "; " + cookieAuthStrategyCookiePair},
			// The strategy cookie is gone: setCustomCookies deleted the whole inherited
			// header and re-added only the configured cookie.
			wantRedirectHopCookie: cookieAuthSessionCookie,
			foreignPair:           cookieAuthStrategyCookiePair,
		},
		{
			name:                  "two configured cookies survive while the authx session cookie does not",
			configured:            []string{cookieAuthSessionCookie, cookieAuthIDCookie},
			applyForeign:          authxCookieStrategy,
			wantHop1Lines:         []string{cookieAuthJoinedCookies + "; " + cookieAuthStrategyCookiePair},
			wantRedirectHopCookie: cookieAuthJoinedCookies,
			foreignPair:           cookieAuthStrategyCookiePair,
		},
		{
			name:         "a caller cookie added alongside the configured one is dropped from every redirect hop",
			configured:   []string{cookieAuthSessionCookie},
			applyForeign: addedHeaderCookie,
			// Two lines, because Header.Add does not re-frame what is already there.
			wantHop1Lines: []string{cookieAuthSessionCookie, cookieAuthPlainCookie},
			// net/http joins the two lines onto the redirect hop, and the injector then
			// discards both before re-adding the configured cookie on its own.
			wantRedirectHopCookie: cookieAuthSessionCookie,
			foreignPair:           cookieAuthPlainCookie,
		},
		{
			// The mirror image: a caller who REPLACES the header still gets the configured cookie
			// back on every redirect hop, even though its own request never carried it, while its
			// own pair is discarded with the rest of the header.
			name:                  "a caller cookie that replaces the header yields the configured cookie alone on every redirect hop",
			configured:            []string{cookieAuthSessionCookie},
			applyForeign:          replacedHeaderCookie,
			wantHop1Lines:         []string{cookieAuthPlainCookie},
			wantRedirectHopCookie: cookieAuthSessionCookie,
			foreignPair:           cookieAuthPlainCookie,
		},
		{
			// CONTROL: no cookie configured, so setCustomCookies is a no-op and the
			// authx credential reaches every hop.
			name:                      "control: with no configured cookie the authx session cookie survives every hop alone",
			configured:                nil,
			applyForeign:              authxCookieStrategy,
			wantHop1Lines:             []string{cookieAuthStrategyCookiePair},
			wantRedirectHopCookie:     cookieAuthStrategyCookiePair,
			foreignPair:               cookieAuthStrategyCookiePair,
			wantForeignOnRedirectHops: true,
		},
		{
			// CONTROL: the same, for a cookie no cookie-aware API ever touched.
			name:                      "control: with no configured cookie a plain caller cookie survives every hop alone",
			configured:                nil,
			applyForeign:              addedHeaderCookie,
			wantHop1Lines:             []string{cookieAuthPlainCookie},
			wantRedirectHopCookie:     cookieAuthPlainCookie,
			foreignPair:               cookieAuthPlainCookie,
			wantForeignOnRedirectHops: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A fresh transport per row: callCount and the snapshots accumulate.
			rt := cookieAuthSameOriginChainTransport(t)

			ht := newMockHTTPX(t, func(options *Options) {
				if tc.configured != nil {
					// Before New: parseCustomCookies runs inside it (httpx.go:78).
					options.CustomHeaders = map[string][]string{"Cookie": tc.configured}
				}
				options.FollowRedirects = true
				options.MaxRedirects = cookieAuthMaxRedirects
			}, rt)

			require.Equal(t, len(tc.configured) > 0, ht.Options.hasCustomCookies(),
				"the configured/control condition must hold at construction time, because hasCustomCookies is the guard that decides whether setCustomCookies touches the header at all")
			require.Len(t, ht.Options.customCookies, len(tc.configured),
				"parseCustomCookies must yield exactly one cookie per configured pair, otherwise the re-add loop has a different input than this row describes")

			req, err := retryablehttp.NewRequest(http.MethodGet, cookieAuthOriginStart, nil)
			require.NoError(t, err)
			ht.SetCustomHeaders(req, ht.CustomHeaders)
			tc.applyForeign(t, req)

			resp, err := ht.Do(req, UnsafeOptions{})
			require.NoError(t, err)

			require.Equal(t, 3, rt.callCount(), "two redirects must be followed, producing three requests")
			hops := rt.requests()
			require.Len(t, hops, 3)
			require.Equal(t, []string{cookieAuthOriginStart, cookieAuthOriginSecond, cookieAuthOriginFinal},
				[]string{hops[0].URL, hops[1].URL, hops[2].URL},
				"the chain must stay on one origin, so net/http's own Cookie strip cannot be what removes anything here")

			require.Equal(t, tc.wantHop1Lines, hops[0].Header.Values("Cookie"),
				"the caller's own request must carry exactly these Cookie header lines: the rebuild under test happens on the REDIRECT hops, so hop 1 is what proves the foreign cookie existed to be carried over")

			for _, hop := range []struct {
				number int
				rec    recordedRequest
			}{{number: 2, rec: hops[1]}, {number: 3, rec: hops[2]}} {
				require.Equalf(t, tc.wantRedirectHopCookie, hop.rec.Header.Get("Cookie"),
					"hop %d must carry exactly this Cookie: setCustomCookies (httpx.go:522-529) deletes the whole inherited header and re-adds Options.customCookies, so nothing else can be on the line", hop.number)
				require.Lenf(t, hop.rec.Header.Values("Cookie"), 1,
					"hop %d must carry the cookies as a single header line", hop.number)
				// The fate of the FOREIGN cookie is asserted by name as well as by the exact
				// value above: stating the absence as an absence is what makes a later
				// name-scoped delete fail here and be read as a deliberate repair.
				if tc.wantForeignOnRedirectHops {
					require.Containsf(t, hop.rec.Header.Get("Cookie"), tc.foreignPair,
						"hop %d must still carry the foreign cookie %q: nothing is configured, so setCustomCookies never touches the header", hop.number, tc.foreignPair)
				} else {
					require.NotContainsf(t, hop.rec.Header.Get("Cookie"), tc.foreignPair,
						"PINNED: hop %d must NOT carry the foreign cookie %q - the delete is unconditional, so an authentication cookie the injector did not configure is lost on every admitted hop", hop.number, tc.foreignPair)
				}
				// And the configured cookies must still be applied - the delete must not
				// have come at the cost of the injection it exists to perform. The loop is
				// empty on the control rows, where nothing is configured.
				for _, configured := range tc.configured {
					require.Containsf(t, hop.rec.Header.Get("Cookie"), configured,
						"hop %d must also carry the configured cookie %q, which setCustomCookies re-adds after the delete", hop.number, configured)
				}
			}

			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, []byte(cookieAuthFinalBody), resp.Data)
			require.Equal(t, []int{http.StatusFound, http.StatusFound, http.StatusOK}, resp.GetChainStatusCodes())
			require.Equal(t, cookieAuthOriginFinal, resp.GetChainLastURL(),
				"the final URL must name the last hop, so the cookie values above are attributed to a chain that actually completed")
		})
	}
}

// assertCustomCookieFramingDivergesBetweenMechanisms pins the consequences of the two mechanisms
// framing the same configured cookies differently - the divergence TestCustomCookiesReachTheWire
// records. That test's table establishes the header LINES the configured cookies produce on the
// caller's own request; this extends the subject to what those lines become once the second
// mechanism reframes them.
//
// SetCustomHeaders adds each configured value verbatim as its own header line, while
// setCustomCookies rebuilds one line through http.Request.AddCookie, which sanitizes: net/http's
// readCookies drops a token whose name is not a valid cookie name, and sanitizeCookieValue
// double-quotes a value containing a space or a comma. Two consequences follow, neither
// cosmetic:
//
//   - A value carrying a separator or a space is not the same string on hop 1 as on hop 2. A
//     host that echoes or logs the cookie therefore sees two different values for one
//     configured input.
//   - A cookie added afterwards with the cookie-aware API silently DISCARDS all but the first
//     configured cookie from the caller's own request, because AddCookie reads the existing
//     header with Header.Get - which returns the first line only - and writes the result back
//     with Set, collapsing the rest. The redirect hops recover the lost CONFIGURED cookie,
//     because setCustomCookies re-adds every configured cookie there, but its delete removes the
//     whole inherited header first, so the cookie the caller added by hand is dropped from hop 2
//     onward. Each hop therefore loses a different cookie, and neither loss is visible in a
//     chain-level assertion.
//
// Both are pinned rather than changed: the framing lives in SetCustomHeaders' own fallthrough and
// the collapsing behaviour lives in net/http. No production path in this repository combines a
// configured cookie with a bare AddCookie - the authx cookie strategy rebuilds the whole header
// from req.Cookies() first, which is why the authx row of
// assertCustomCookiesReplaceInheritedCookiesOnRedirectHops keeps both cookies on hop 1 - but
// nothing prevents one, and an unpinned latent loss of a credential is exactly what these tests
// exist to make loud.
func assertCustomCookieFramingDivergesBetweenMechanisms(t *testing.T) {
	t.Run("sanitization differs between the caller's request and the redirect hops", func(t *testing.T) {
		cases := []struct {
			name string
			// configured is one raw -H "Cookie: ..." value.
			configured string
			// wantParsed is the name|value pair parseCustomCookies derives, stated so a
			// change in net/http's request-cookie parser is attributed here rather than
			// showing up only as a wire difference.
			wantParsed string
			// wantHop1 is the caller's own header line: the configured value verbatim.
			wantHop1 string
			// wantHop2 is what AddCookie re-emits on the redirect hop.
			wantHop2 string
		}{
			{
				// A ';' ends the first pair, so "c\"d" is parsed as a second cookie
				// whose name holds a quote and is rejected as invalid; the surviving
				// value keeps its space, which AddCookie then double-quotes.
				name:       "a value with a space and a separator is truncated and quoted on the redirect hop",
				configured: `weird=a b;c"d`,
				wantParsed: `weird|a b`,
				wantHop1:   `weird=a b;c"d`,
				wantHop2:   `weird="a b"`,
			},
			{
				// No '=' at all: the whole token becomes a name with an empty value, so
				// the redirect hop gains the '=' the caller never wrote.
				name:       "a bare cookie name gains an equals sign on the redirect hop",
				configured: "justname",
				wantParsed: "justname|",
				wantHop1:   "justname",
				wantHop2:   "justname=",
			},
			{
				// CONTROL: an ordinary pair is byte-identical on both hops, so the two
				// rows above are attributable to sanitization rather than to the
				// framing difference on its own.
				name:       "control: an ordinary pair is byte-identical on both hops",
				configured: cookieAuthSessionCookie,
				wantParsed: "sess|abc",
				wantHop1:   cookieAuthSessionCookie,
				wantHop2:   cookieAuthSessionCookie,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				rt := newMockTransport(t, scriptedRedirects(t, map[string]mockHop{
					"origin.example/a": {status: http.StatusFound, location: "/b", body: cookieAuthRedirectBody},
					"origin.example/b": {status: http.StatusOK, body: cookieAuthFinalBody},
				}))

				ht := newMockHTTPX(t, func(options *Options) {
					options.CustomHeaders = map[string][]string{"Cookie": {tc.configured}}
					options.FollowRedirects = true
					options.MaxRedirects = cookieAuthMaxRedirects
				}, rt)

				require.Len(t, ht.Options.customCookies, 1,
					"exactly one cookie must survive parsing, otherwise the hop values below describe a different input")
				require.Equal(t, tc.wantParsed,
					ht.Options.customCookies[0].Name+"|"+ht.Options.customCookies[0].Value,
					"parseCustomCookies must derive exactly this name and value from the configured string")

				req, err := retryablehttp.NewRequest(http.MethodGet, cookieAuthOriginStart, nil)
				require.NoError(t, err)
				ht.SetCustomHeaders(req, ht.CustomHeaders)

				resp, err := ht.Do(req, UnsafeOptions{})
				require.NoError(t, err)

				require.Equal(t, 2, rt.callCount(), "the redirect must be followed exactly once")
				hops := rt.requests()
				require.Len(t, hops, 2)

				require.Equal(t, []string{tc.wantHop1}, hops[0].Header.Values("Cookie"),
					"the caller's own request must carry the configured value verbatim: SetCustomHeaders adds it without parsing it")
				require.Equal(t, []string{tc.wantHop2}, hops[1].Header.Values("Cookie"),
					"the redirect hop must carry exactly what AddCookie re-emits, which is where sanitization is applied")

				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, []byte(cookieAuthFinalBody), resp.Data)
				require.Equal(t, []int{http.StatusFound, http.StatusOK}, resp.GetChainStatusCodes())
			})
		}
	})

	t.Run("a bare AddCookie discards all but the first configured cookie from the caller's request", func(t *testing.T) {
		rt := cookieAuthSameOriginChainTransport(t)

		ht := newMockHTTPX(t, func(options *Options) {
			options.CustomHeaders = map[string][]string{"Cookie": {cookieAuthSessionCookie, cookieAuthIDCookie}}
			options.FollowRedirects = true
			options.MaxRedirects = cookieAuthMaxRedirects
		}, rt)

		require.Len(t, ht.Options.customCookies, 2,
			"both configured cookies must be parsed, otherwise the loss under test cannot be observed")

		req, err := retryablehttp.NewRequest(http.MethodGet, cookieAuthOriginStart, nil)
		require.NoError(t, err)
		ht.SetCustomHeaders(req, ht.CustomHeaders)
		require.Equal(t, []string{cookieAuthSessionCookie, cookieAuthIDCookie}, req.Header.Values("Cookie"),
			"precondition: SetCustomHeaders leaves two header lines, which is the state AddCookie collapses")

		// The unsafe combination: a cookie-aware add on top of a multi-line header.
		req.AddCookie(&http.Cookie{Name: cookieAuthAddedCookieName, Value: cookieAuthAddedCookieValue})

		resp, err := ht.Do(req, UnsafeOptions{})
		require.NoError(t, err)

		require.Equal(t, 3, rt.callCount(), "two redirects must be followed, producing three requests")
		hops := rt.requests()
		require.Len(t, hops, 3)

		// PINNED: id=1 is gone from the caller's own request. AddCookie read only the
		// first line via Header.Get, appended to it, and wrote the result back with Set.
		require.Equal(t,
			[]string{cookieAuthSessionCookie + "; " + cookieAuthAddedCookieName + "=" + cookieAuthAddedCookieValue},
			hops[0].Header.Values("Cookie"),
			"PINNED: AddCookie collapses the multi-line Cookie header onto its first line, so the second configured cookie never reaches the caller's own target")
		require.NotContains(t, hops[0].Header.Get("Cookie"), cookieAuthIDCookie,
			"PINNED: the loss is exactly this - the second configured cookie is absent from hop 1, silently and without an error")

		// The redirect hops re-add every configured cookie, so the pair AddCookie collapsed off
		// hop 1 is back - but the injector's Header.Del("Cookie") clears the whole header first,
		// so the cookie the caller added by hand is discarded on every hop. Hops 2 and 3 carry
		// exactly the two configured cookies and nothing else: the hop-1 loss is traded for a
		// hop-2-onward loss of a different cookie, which is the compound divergence pinned here.
		for _, hop := range []struct {
			number int
			rec    recordedRequest
		}{{number: 2, rec: hops[1]}, {number: 3, rec: hops[2]}} {
			require.Equalf(t, cookieAuthJoinedCookies, hop.rec.Header.Get("Cookie"),
				"hop %d is rebuilt by setCustomCookies: the header is deleted and only the two configured cookies are re-added", hop.number)
			require.Containsf(t, hop.rec.Header.Get("Cookie"), cookieAuthIDCookie,
				"hop %d must carry the configured cookie that AddCookie collapsed off hop 1, which is precisely what makes the hop-1 loss survivable and easy to miss", hop.number)
			require.NotContainsf(t, hop.rec.Header.Get("Cookie"), cookieAuthAddedCookieName+"=",
				"PINNED: hop %d must NOT carry the manually added cookie - the injector deletes the inherited Cookie header outright rather than replacing only the configured names, so a credential the caller added by hand survives hop 1 and no other hop", hop.number)
		}

		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, []byte(cookieAuthFinalBody), resp.Data)
		require.Equal(t, cookieAuthOriginFinal, resp.GetChainLastURL())
	})
}
