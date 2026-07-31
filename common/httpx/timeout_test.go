package httpx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// These tests separate the two ways a request can fail on the clock and pin the
// IDENTITY of the error each one produces. Before this file nothing in the repository
// distinguished them: no test mentioned context.DeadlineExceeded, context.Canceled or
// errors.As at all, so a defect that collapsed the two categories - or swapped which
// sentinel came back - changed how every calling layer classifies a failure while the
// whole suite stayed green.
//
// "The specific exception class raised for each timeout category" has no literal
// equivalent in Go, so each category is pinned on FOUR independent axes, and it is the
// combination that carries the assertion power:
//
//  1. the concrete Go type of the returned error,
//  2. the errors.Is sentinel relationship, asserted in both directions - the sentinel
//     that must match AND the one that must not,
//  3. the net.Error-style Timeout() behaviour, reached with errors.As,
//  4. the presence or absence of the retry layer's exhaustion wrapper.
//
// Measured, the two categories differ on every one of them. A client-deadline failure
// arrives wrapped three deep (*fmt.wrapError -> *url.Error -> net/http's unexported
// timeoutError), reports Timeout() == true, matches context.DeadlineExceeded and
// carries "giving up after N attempts". A caller-driven cancellation arrives as the
// bare context.Canceled sentinel with nothing wrapped around it, exposes no Timeout()
// method at all, and carries no retry wrapper. Asserting only "an error occurred"
// would pass under a defect that returned either one for the other.
//
// Everything here is hermetic: interception happens at the http.RoundTripper boundary,
// above DNS, TCP and TLS, so slow.example is never resolved and there is no loopback
// server in this file at all - a sleeping in-process handler is both faster and
// stricter than a socket that would have to sleep for real. Time is deliberately NOT
// mocked; real short deadlines against a handler that never answers keep the whole
// file sub-second per case while exercising the production timer paths.
//
// No test here uses t.Parallel(), matching every other test in this package: New sets
// the process-global GODEBUG variable on the HTTP/1.1 path, and these assertions are
// wall-clock sensitive besides.

const (
	// timeoutTarget is a synthetic authority that exists only inside the scripted
	// transport. Nothing resolves or dials it, so no assertion below can depend on
	// name resolution, egress, or what a third party happens to serve.
	timeoutTarget = "http://slow.example/"

	// timeoutBudget is the client wall-clock deadline under test. It is long enough
	// that no assertion races the deadline on a loaded machine, and short enough
	// that six deliberately timed-out calls stay inside the file's runtime budget.
	timeoutBudget = 300 * time.Millisecond

	// timeoutCancelAfter is when the caller-driven cancellation fires. It sits two
	// orders of magnitude inside timeoutNoDeadline, so a defect that let the client
	// deadline cause that failure instead would blow the elapsed envelope rather
	// than passing quietly.
	timeoutCancelAfter = 200 * time.Millisecond

	// timeoutNoDeadline is the client timeout used by the cancellation test. It is
	// deliberately far larger than anything that test tolerates: the point is to
	// prove the client deadline provably cannot be the cause of the failure.
	timeoutNoDeadline = 10 * time.Second

	// timeoutTransportSleep outlasts every deadline here by an order of magnitude.
	// It never actually elapses - the handler's select returns as soon as the
	// request context ends - so it costs no wall time. It is the safety valve that
	// turns "the deadline never fired" into a named failure instead of a hang.
	timeoutTransportSleep = 3 * time.Second

	// timeoutEnvelopeFactor widens every elapsed assertion to this multiple of the
	// configured budget. Elapsed time is asserted as an inequality and never as an
	// exact value: an exact-duration assertion would flake under CI load, and a
	// generous upper bound still fails hard on the mutation that matters here,
	// because a per-attempt deadline multiplies the total rather than nudging it.
	timeoutEnvelopeFactor = 3
)

// timeoutError is the net.Error-shaped contract through which both net/http and net
// report that a deadline, rather than a peer, ended a request.
//
// It is declared locally and matched with errors.As rather than with a type assertion
// because the concrete types that implement it here cannot both be named from outside
// net/http: the deadline error is net/http's unexported timeoutError
// (net/http/transport.go), reached through the *url.Error that forwards Timeout() to
// it. Asserting the behaviour instead of the type is also what a caller does, so this
// pins the contract callers actually depend on.
type timeoutError interface {
	Timeout() bool
}

// timeoutSlowTransport returns a recording transport whose handler never answers: it
// blocks until the request context ends and then reports that context's error, exactly
// as a real transport does when a dial or a header read is cut short.
//
// A FRESH transport per case is mandatory rather than stylistic. mockTransport's call
// counter is cumulative, so sharing one instance across table rows would turn every
// "the transport was entered exactly once" assertion into a tautology that no defect
// could break. Each caller therefore builds its own through newTimeoutHTTPX.
//
// The sleep branch is unreachable in a correctly configured test and exists to name
// the misconfiguration if it ever becomes reachable. It reports through t.Error as
// well as through the returned error, following scriptedRedirects: a require call from
// a goroutine other than the test's own would Goexit and hang the test instead of
// failing it. The report cannot race the test's completion either, because net/http
// calls RoundTrip on the very goroutine that is blocked inside Do, so this handler can
// only still be selecting while that call has not returned. The diagnostic is built
// from redactedRequestLine so a URL userinfo password cannot reach a retained log
// (CWE-532).
func timeoutSlowTransport(t *testing.T) *mockTransport {
	t.Helper()

	return newMockTransport(t, func(r *http.Request) (*http.Response, error) {
		select {
		case <-r.Context().Done():
			// The production shape of a cut-short request: no response, and the
			// context's own error. Which error that is - a deadline or a
			// cancellation - is precisely what each test below discriminates.
			return nil, r.Context().Err()
		case <-time.After(timeoutTransportSleep):
			err := fmt.Errorf(
				"timeoutSlowTransport: %s was not cut short within %s (request context error: %v)",
				redactedRequestLine(r), timeoutTransportSleep, r.Context().Err())
			t.Error(err)
			return nil, err
		}
	})
}

// newTimeoutHTTPX builds a client whose transport never answers, with the given
// wall-clock budget and retry ceiling, and returns both so a test can assert on the
// caller-visible error and on what actually reached the wire.
//
// Both values are set through the option mutator because newMockHTTPX runs it BEFORE
// New, and New freezes Options.Timeout into two places - the *http.Client deadline
// (common/httpx/httpx.go:184) and the retry layer's overall budget (:81), which
// TestTimeoutIsHardDeadlineNotPerAttempt documents in full - as well as
// Options.RetryMax into the retry options (:82). Assigning either field after
// construction would leave the client on the harness's default budget and every
// elapsed envelope below would then pass for the wrong reason.
//
// newMockHTTPX installs the transport on BOTH of the retryable client's HTTP clients
// and registers the fastdialer cleanup, so nothing here can leak to the network or
// leave a disk-backed dialer store behind.
func newTimeoutHTTPX(t *testing.T, timeout time.Duration, retryMax int) (*HTTPX, *mockTransport) {
	t.Helper()

	rt := timeoutSlowTransport(t)
	ht := newMockHTTPX(t, func(options *Options) {
		options.Timeout = timeout
		options.RetryMax = retryMax
	}, rt)
	return ht, rt
}

// TestTimeoutClientTimeoutErrorIdentity pins the identity of the error produced when
// the client's own wall-clock deadline (common/httpx/httpx.go:184) fires, on every axis
// a caller can inspect.
//
// Provenance, all measured against this code and cross-checked against the mechanism in
// the dependencies: the deadline makes net/http replace the round-trip error with its
// unexported timeoutError (net/http/client.go, "Client.Timeout exceeded while awaiting
// headers"), whose Timeout() is true and whose custom Is method reports equality with
// context.DeadlineExceeded (net/http/transport.go) - which is why the sentinel matches
// even though nothing literally wraps it. net/http then wraps that in *url.Error, and
// retryablehttp wraps THAT with fmt.Errorf("... giving up after %d attempts: %w", ...)
// (retryablehttp-go/do.go), which is where the *fmt.wrapError at the outside comes
// from. Do surfaces the failure as (nil, err) because it returns early whenever the
// response is nil and the error is not (common/httpx/httpx.go:261-263).
func TestTimeoutClientTimeoutErrorIdentity(t *testing.T) {
	ht, rt := newTimeoutHTTPX(t, timeoutBudget, 0)

	req, err := retryablehttp.NewRequest(http.MethodGet, timeoutTarget, nil)
	require.NoError(t, err)

	start := time.Now()
	resp, err := ht.Do(req, UnsafeOptions{})
	elapsed := time.Since(start)

	require.Error(t, err, "a transport that never answers must fail the call")
	require.Nil(t, resp, "Do returns no response at all once the deadline fires (httpx.go:261-263)")

	// AXIS 1 - concrete type. *fmt.wrapError is unexported, so a type assertion is
	// impossible; the %T rendering is the only mechanism available and is still a
	// genuine identity assertion rather than a message comparison. It fails the
	// moment the retry layer stops wrapping, or starts wrapping with a custom type.
	require.Equal(t, "*fmt.wrapError", fmt.Sprintf("%T", err),
		"the deadline error must reach the caller wrapped by the retry layer's fmt.Errorf")

	// AXIS 2 - sentinel identity, asserted in BOTH directions. Matching
	// DeadlineExceeded alone would still pass under a defect that also made the
	// error match Canceled, which is what would collapse the two categories.
	require.ErrorIs(t, err, context.DeadlineExceeded,
		"a client-deadline failure must match context.DeadlineExceeded")
	require.False(t, errors.Is(err, context.Canceled),
		"a client-deadline failure must NOT match context.Canceled: the two categories have to stay separable")

	// AXIS 3 - Timeout() behaviour. Both that the contract is reachable and that it
	// answers true; reaching it and getting false would be a different bug.
	var deadlineErr timeoutError
	require.ErrorAs(t, err, &deadlineErr,
		"a client-deadline failure must expose the net.Error-style Timeout() contract")
	require.True(t, deadlineErr.Timeout(),
		"Timeout() must report true so callers classify this as a timeout rather than a transport fault")

	// AXIS 4 - the retry exhaustion wrapper is PRESENT. The noun is plural even for a
	// single attempt (retryablehttp-go/do.go formats retryMax+1 into a fixed
	// "attempts"), so the substring is asserted exactly as the code emits it.
	require.Contains(t, err.Error(), "giving up after 1 attempts:",
		"RetryMax 0 means one attempt, and the retry layer reports that count in the message")

	// Exported structural identity, which the four axes above cannot express: the
	// middle of the wrap chain is a *url.Error naming the exact operation and target
	// that failed, and forwarding the deadline nature of the error it carries.
	//
	// The inner error is asserted by CAUSE, not by exact text, because its concrete
	// identity is genuinely non-deterministic and measurably so. http.Client.Timeout
	// arms two timers on the same instant: the deadline it installs on the request
	// context, which is what this file's handler observes, and net/http's own timer
	// whose goroutine raises the flag that decides whether net/http substitutes its
	// "(Client.Timeout exceeded while awaiting headers)" error. When the context timer
	// wins that race the flag is still unset, so the raw context.DeadlineExceeded
	// propagates instead. Measured over 40 consecutive runs: 38 carried net/http's
	// substituted error and 2 carried the bare sentinel. Every assertion below held
	// 40/40, so they pin the behaviour callers depend on without encoding the race.
	var urlErr *url.Error
	require.ErrorAs(t, err, &urlErr,
		"net/http must report the failure as a *url.Error naming the operation and target")
	require.Equal(t, "Get", urlErr.Op)
	require.Equal(t, timeoutTarget, urlErr.URL)
	require.True(t, urlErr.Timeout(), "*url.Error must forward Timeout() from the error it wraps")
	require.ErrorIs(t, urlErr.Err, context.DeadlineExceeded,
		"whichever of net/http's two deadline timers wins, the cause it reports must be the deadline")
	require.Contains(t, urlErr.Err.Error(), "context deadline exceeded",
		"the inner error must name the deadline as the cause, not a cancellation or a transport fault")

	// Protocol-visible: exactly one request reached the wire, and it was the
	// caller's own target and method. A deadline must not retry onto the network.
	require.Equal(t, 1, rt.callCount(), "the deadline must not send a second request")
	hops := rt.requests()
	require.Len(t, hops, 1)
	require.Equal(t, http.MethodGet, hops[0].Method)
	require.Equal(t, timeoutTarget, hops[0].URL)

	// Elapsed is bounded on both sides and pinned to neither. The lower bound fails
	// if a defect shortens the budget the client actually waits; the upper bound
	// fails if it lengthens it. Neither is an exact duration.
	require.Less(t, timeoutBudget, elapsed,
		"the call must actually spend its configured budget rather than failing early")
	require.Less(t, elapsed, timeoutEnvelopeFactor*timeoutBudget,
		"the call must not overrun a generous multiple of its configured budget")
}

// TestTimeoutIsHardDeadlineNotPerAttempt establishes that Options.Timeout is one hard
// wall-clock deadline for the WHOLE call and not a per-attempt budget, which is the
// single most consequential thing this file records.
//
// The discovery, measured across RetryMax 0, 1 and 2: the transport is entered EXACTLY
// ONCE in every case, and the call always returns after roughly one budget - yet the
// error message's attempt count still reads RetryMax+1.
//
// Two budgets govern the call and both are fed from the same Options.Timeout, which is
// why they expire together instead of nesting. One is the deadline on the *http.Client,
// assigned inline at common/httpx/httpx.go:184 and then re-applied by the retry client's
// own constructor from retryablehttpOptions.Timeout (:81) - identical in production
// because both read Options.Timeout - and it is what cuts the single in-flight attempt
// short. The other is the retry layer's overall context, created from that same
// retryablehttpOptions.Timeout at the top of its Do. By the time the first attempt fails
// that overall context is ALREADY expired, so the retry loop's backoff select takes its
// "overall deadline done" branch and leaves the loop without dispatching another
// attempt. The count is then formatted unconditionally as RetryMax+1 on the way out, so
// the retry counter advances while the wire sees one request.
//
// DO NOT "CORRECT" THIS TEST TO EXPECT RetryMax+1 TRANSPORT INVOCATIONS. That would be
// false. The attempt count lives only in the error text; the number of requests that
// actually reach the transport is one, always. mockTransport counts at the very top of
// RoundTrip, ahead of every early return, which is exactly what makes "the transport
// was never reached again" distinguishable from "the transport answered again".
//
// The callCount assertion is the primary mutation killer here because it is exact
// rather than temporal: a deadline relocated into the transport, or made per-attempt,
// would dispatch RetryMax+1 requests and fail it immediately. The elapsed bounds are
// the secondary, timing-based confirmation of the same property.
func TestTimeoutIsHardDeadlineNotPerAttempt(t *testing.T) {
	cases := []struct {
		name     string
		retryMax int
		// wantAttemptPhrase is the retry layer's own report of how many attempts it
		// counted. It is always RetryMax+1 and the noun is always plural, even for a
		// single attempt, because the message is formatted from a fixed template.
		wantAttemptPhrase string
	}{
		{
			name:              "retrymax 0 hits the transport once",
			retryMax:          0,
			wantAttemptPhrase: "giving up after 1 attempts:",
		},
		{
			name:              "retrymax 1 still hits the transport once",
			retryMax:          1,
			wantAttemptPhrase: "giving up after 2 attempts:",
		},
		{
			name:              "retrymax 2 still hits the transport once",
			retryMax:          2,
			wantAttemptPhrase: "giving up after 3 attempts:",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// A fresh client AND a fresh transport per row: the call counter is
			// cumulative, so a shared transport would make "exactly once"
			// unfalsifiable from the second row onwards.
			ht, rt := newTimeoutHTTPX(t, timeoutBudget, c.retryMax)

			req, err := retryablehttp.NewRequest(http.MethodGet, timeoutTarget, nil)
			require.NoError(t, err)

			start := time.Now()
			resp, err := ht.Do(req, UnsafeOptions{})
			elapsed := time.Since(start)

			require.Error(t, err, "a transport that never answers must fail the call")
			require.Nil(t, resp, "an exhausted retry loop returns no response")

			// The load-bearing assertion of the whole file.
			require.Equal(t, 1, rt.callCount(),
				"the client deadline is one budget for the whole call: once it fires the retry loop's own overall context is already expired, so no further attempt is dispatched")
			hops := rt.requests()
			require.Len(t, hops, 1, "exactly one request may reach the wire regardless of RetryMax")
			require.Equal(t, http.MethodGet, hops[0].Method)
			require.Equal(t, timeoutTarget, hops[0].URL)

			// The retry counter still advances even though the wire did not. Both
			// halves matter: the count proves the retry layer ran, the callCount
			// above proves it ran without reaching the transport again.
			require.Contains(t, err.Error(), c.wantAttemptPhrase,
				"the retry layer reports RetryMax+1 attempts in its message even though only one reached the transport")

			// Sentinel identity is re-asserted per row, in both directions, so a
			// defect that swapped the category under retry pressure cannot hide
			// behind the timing assertions.
			require.ErrorIs(t, err, context.DeadlineExceeded,
				"every row must fail with the deadline sentinel, not a cancellation")
			require.False(t, errors.Is(err, context.Canceled),
				"a deadline must never be reported as a caller cancellation")

			// Bounded on both sides: roughly one budget, never RetryMax+1 of them.
			require.Less(t, timeoutBudget, elapsed,
				"the call must actually spend its configured budget rather than failing early")
			require.Less(t, elapsed, timeoutEnvelopeFactor*timeoutBudget,
				"the call must not overrun a generous multiple of a SINGLE budget")

			// The explicit anti-per-attempt bound. A per-attempt deadline would
			// allow (RetryMax+1) budgets in total, so elapsed must stay strictly
			// below that product. The row with no retries cannot express the
			// difference - the product equals one budget - so it is skipped rather
			// than asserted vacuously. For RetryMax 2 this bound coincides
			// numerically with the envelope above while asserting a different
			// property, and callCount remains the exact discriminator either way.
			if c.retryMax >= 1 {
				perAttemptBudget := time.Duration(c.retryMax+1) * timeoutBudget
				require.Less(t, elapsed, perAttemptBudget,
					"elapsed must not reach (RetryMax+1) budgets: the deadline is per call, not per attempt")
			}
		})
	}
}

// TestTimeoutContextCancellationIdentity pins the identity of the OTHER timeout
// category: a deadline the caller drives through the request context rather than one
// the client enforces.
//
// The two categories are separable on four independent axes - concrete type, sentinel
// identity, Timeout() result, and retry-wrapper presence - and this test asserts all
// four in the negative wherever the deadline test asserts them in the positive. That
// pairing is what "the specific exception class raised for each timeout category" means
// in a language with no exception classes: neither category can be substituted for the
// other without failing at least one assertion in one of the two tests.
//
// Provenance, measured: the client timeout is set two orders of magnitude beyond the
// cancellation instant, so the client deadline provably cannot be the cause. The retry
// layer checks the request context before classifying the failure and returns that
// context's error verbatim when it is set, deliberately not retrying a cancelled
// request (retryablehttp-go/retry.go, "do not retry on context.Canceled or
// context.DeadlineExceeded"). Returning it through that path bypasses the
// fmt.Errorf("giving up after ...") wrapper entirely, which is why the caller receives
// the bare context.Canceled sentinel - pointer-identical, with nothing wrapped around
// it - rather than the three-deep chain the client deadline produces. RetryMax is set
// to 2 precisely so that "no retry wrapper appeared" is a real finding: a retry budget
// exists and was deliberately not spent.
func TestTimeoutContextCancellationIdentity(t *testing.T) {
	ht, rt := newTimeoutHTTPX(t, timeoutNoDeadline, 2)

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel unconditionally on the way out as well as on the timer, so a failure
	// before the call cannot leak the context or the blocked handler.
	defer cancel()

	req, err := ht.NewRequestWithContext(ctx, http.MethodGet, timeoutTarget)
	require.NoError(t, err)

	// The clock is read BEFORE the timer is armed, deliberately. Arming first would
	// give the cancellation a head start over the measurement and could make elapsed
	// land marginally under timeoutCancelAfter, breaking the lower bound below for a
	// reason that has nothing to do with the client. This ordering makes the timer's
	// deadline provably later than start. Stopping the timer afterwards keeps the test
	// from holding a runtime timer past its own completion; cancel still runs from the
	// deferred call above.
	start := time.Now()
	cancelTimer := time.AfterFunc(timeoutCancelAfter, cancel)
	defer cancelTimer.Stop()

	resp, err := ht.Do(req, UnsafeOptions{})
	elapsed := time.Since(start)

	require.Error(t, err, "a cancelled request must fail the call")
	require.Nil(t, resp, "Do returns no response at all once the request is cancelled (httpx.go:261-263)")

	// AXIS 1 - concrete type. *errors.errorString is what errors.New produces, and
	// context.Canceled is exactly that: the error arrives unwrapped, in contrast to
	// the *fmt.wrapError of the deadline category. The type is unexported, so the %T
	// rendering is the available mechanism.
	require.Equal(t, "*errors.errorString", fmt.Sprintf("%T", err),
		"a cancellation must reach the caller unwrapped, unlike the deadline category's *fmt.wrapError")

	// The strongest form of identity available: not merely an error that matches the
	// sentinel, but the sentinel value itself. require.Same compares pointers, so a
	// distinct error carrying the same message would fail here even though
	// require.Equal, which compares pointed-to values, would not.
	require.Same(t, context.Canceled, err,
		"the caller must receive the context.Canceled sentinel itself, not a copy or a look-alike")
	require.Equal(t, "context canceled", err.Error(),
		"the message must be the sentinel's own, with nothing prefixed or appended")
	require.Nil(t, errors.Unwrap(err),
		"the cancellation error must be a leaf: anything wrapped around it would change how callers classify it")

	// AXIS 2 - sentinel identity, both directions, mirroring the deadline test.
	require.ErrorIs(t, err, context.Canceled,
		"a caller-driven cancellation must match context.Canceled")
	require.False(t, errors.Is(err, context.DeadlineExceeded),
		"a cancellation must NOT match context.DeadlineExceeded: swapping the two would mislead every calling layer")

	// AXIS 3 - Timeout() behaviour. Measured: errors.As FAILS outright, because
	// context.Canceled implements no Timeout method and nothing wraps it in a value
	// that does. That is a stronger statement than "Timeout() returned false" and is
	// asserted as the measured outcome rather than the weaker alternative.
	var cancellationErr timeoutError
	require.False(t, errors.As(err, &cancellationErr),
		"a cancellation must expose no Timeout() contract at all, so callers cannot misread it as a timeout")

	// The *url.Error wrapper net/http adds around a deadline is likewise absent,
	// which is the structural counterpart of the axis above.
	var urlErr *url.Error
	require.False(t, errors.As(err, &urlErr),
		"a cancellation short-circuits before net/http wraps the failure in a *url.Error")

	// AXIS 4 - the retry exhaustion wrapper is ABSENT. Asserted on the message as an
	// explicit absence, never as a nil check, and with RetryMax deliberately non-zero
	// so the absence is meaningful.
	require.NotContains(t, err.Error(), "giving up after",
		"context cancellation must not be wrapped by the retry-exhaustion message: the retry layer returns the context error verbatim instead")

	// Protocol-visible: the cancellation reached the wire once and was not retried.
	require.Equal(t, 1, rt.callCount(),
		"a cancelled request must not be retried onto the transport despite RetryMax being 2")
	hops := rt.requests()
	require.Len(t, hops, 1)
	require.Equal(t, http.MethodGet, hops[0].Method)
	require.Equal(t, timeoutTarget, hops[0].URL)

	// Elapsed tracks the CANCELLATION instant, not the client deadline. Bounded on
	// both sides by inequalities, never pinned to an exact duration.
	require.Less(t, timeoutCancelAfter, elapsed,
		"the call must last until the cancellation actually fires")
	require.Less(t, elapsed, timeoutEnvelopeFactor*timeoutCancelAfter,
		"elapsed must track the cancellation instant and stay far below the client deadline, which is the proof that the client deadline is not what ended this call")
}

// TestTimeoutContextVariantParity asserts that the client's two request constructors
// honour the deadline identically.
//
// This is the parity axis that stands in for "both sync and async variants" in this
// codebase: the client exposes no async duplicate of its request API - Go's concurrency
// model makes one unnecessary - but it does expose a context-free constructor beside a
// context-bearing one, and a defect could plausibly affect one and not the other.
// NewRequest (common/httpx/httpx.go:459-462) is pure delegation to
// NewRequestWithContext with context.Background(), which takes the context FIRST, so
// the two must be indistinguishable on the wire and in the error they produce.
//
// Both rows therefore assert the SAME expected values, and a projection of each row's
// observable outcome is compared across rows afterwards. Nothing about that comparison
// depends on which row ran first: divergence in either direction fails it.
func TestTimeoutContextVariantParity(t *testing.T) {
	// timeoutOutcome is the DETERMINISTIC projection of one variant's observable
	// result. The rendered error message is deliberately excluded: net/http races two
	// deadline timers, so the presence of its "(Client.Timeout exceeded while awaiting
	// headers)" suffix varies run to run (see TestTimeoutClientTimeoutErrorIdentity)
	// and comparing whole messages across the two rows would flake for a reason that
	// has nothing to do with constructor parity. The deterministic core of the message
	// is instead pinned per row inside the loop.
	type timeoutOutcome struct {
		ErrType          string
		IsDeadline       bool
		IsCanceled       bool
		ExposesTimeout   bool
		TimeoutValue     bool
		TransportCalls   int
		WireMethod       string
		WireURL          string
		ResponseReturned bool
	}

	cases := []struct {
		name string
		// newRequest exercises one constructor. Wrapping them in a closure of a
		// single shape is what lets both rows run byte-identical assertions, so a
		// behavioural difference between the constructors cannot hide behind a
		// difference between two hand-written test bodies.
		newRequest func(*testing.T, *HTTPX) (*retryablehttp.Request, error)
	}{
		{
			name: "context-free constructor honours the deadline",
			newRequest: func(t *testing.T, ht *HTTPX) (*retryablehttp.Request, error) {
				t.Helper()
				return ht.NewRequest(http.MethodGet, timeoutTarget)
			},
		},
		{
			name: "context-bearing constructor honours the deadline",
			newRequest: func(t *testing.T, ht *HTTPX) (*retryablehttp.Request, error) {
				t.Helper()
				return ht.NewRequestWithContext(context.Background(), http.MethodGet, timeoutTarget)
			},
		},
	}

	// Collected inside the sub-tests and compared afterwards. t.Run without
	// t.Parallel runs synchronously, so the appends are ordered and race-free.
	outcomes := make([]timeoutOutcome, 0, len(cases))

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ht, rt := newTimeoutHTTPX(t, timeoutBudget, 0)

			req, err := c.newRequest(t, ht)
			require.NoError(t, err)

			start := time.Now()
			resp, err := ht.Do(req, UnsafeOptions{})
			elapsed := time.Since(start)

			require.Error(t, err, "a transport that never answers must fail the call")
			require.Nil(t, resp, "neither constructor may yield a response once the deadline fires")

			// Identical identity assertions for both variants: the deadline sentinel
			// matches, the cancellation sentinel does not, and the Timeout() contract
			// is reachable and true.
			require.ErrorIs(t, err, context.DeadlineExceeded,
				"both constructors must surface the client deadline as context.DeadlineExceeded")
			require.False(t, errors.Is(err, context.Canceled),
				"neither constructor may report the client deadline as a caller cancellation")

			var deadlineErr timeoutError
			require.ErrorAs(t, err, &deadlineErr,
				"both constructors must surface an error exposing the Timeout() contract")
			require.True(t, deadlineErr.Timeout(),
				"both constructors must report Timeout() as true")

			// Identical wire outcome for both variants.
			require.Equal(t, 1, rt.callCount(), "neither constructor may retry onto the transport")
			hops := rt.requests()
			require.Len(t, hops, 1)
			require.Equal(t, http.MethodGet, hops[0].Method)
			require.Equal(t, timeoutTarget, hops[0].URL,
				"both constructors must put the caller's exact target on the wire")

			require.Less(t, timeoutBudget, elapsed,
				"both constructors must spend the configured budget rather than failing early")
			require.Less(t, elapsed, timeoutEnvelopeFactor*timeoutBudget,
				"neither constructor may overrun a generous multiple of the configured budget")

			// The deterministic core of the rendered message, pinned as exact text:
			// the attempt count, the operation, the target and the cause. Only the
			// optional trailing marker described above varies.
			require.Contains(t, err.Error(),
				`giving up after 1 attempts: Get "`+timeoutTarget+`": context deadline exceeded`,
				"both constructors must render the same attempt count, operation, target and cause")

			outcomes = append(outcomes, timeoutOutcome{
				ErrType:          fmt.Sprintf("%T", err),
				IsDeadline:       errors.Is(err, context.DeadlineExceeded),
				IsCanceled:       errors.Is(err, context.Canceled),
				ExposesTimeout:   errors.As(err, &deadlineErr),
				TimeoutValue:     deadlineErr.Timeout(),
				TransportCalls:   rt.callCount(),
				WireMethod:       hops[0].Method,
				WireURL:          hops[0].URL,
				ResponseReturned: resp != nil,
			})
		})
	}

	// The parity assertion proper. Both variants target the same URL with the same
	// method and the same budget, so every observable outcome must match; any
	// divergence means one constructor is taking a different path through the client.
	require.Len(t, outcomes, len(cases),
		"both constructor variants must have produced an outcome to compare")
	require.Equal(t, outcomes[0], outcomes[1],
		"the context-free and context-bearing constructors must produce identical observable outcomes")
}
