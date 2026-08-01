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

// These tests separate the two ways a request can fail on the clock and pin the IDENTITY of
// the error each one produces, so a defect that collapsed the categories - or swapped which
// sentinel came back - cannot pass as "an error occurred". Go has no exception classes, so
// each category is pinned on four axes whose combination carries the assertion power: the
// concrete error type, the errors.Is sentinel relationship in BOTH directions, the
// net.Error-style Timeout() behaviour reached with errors.As, and the presence or absence of
// the retry layer's exhaustion wrapper. The categories differ on every one: a client
// deadline arrives wrapped three deep (*fmt.wrapError -> *url.Error -> net/http's unexported
// timeoutError), reports Timeout() == true, matches context.DeadlineExceeded and carries
// "giving up after N attempts", while a caller cancellation arrives as the bare
// context.Canceled sentinel with no Timeout() method and no retry wrapper.
//
// Interception happens at the http.RoundTripper boundary, above DNS, TCP and TLS, so
// slow.example is never resolved and no socket is opened. Time is deliberately NOT mocked:
// real short deadlines against a handler that never answers exercise the production timer
// paths and keep every case sub-second.
//
// No test here uses t.Parallel(), matching every other test in this package: New sets the
// process-global GODEBUG variable on the HTTP/1.1 path, and these assertions are wall-clock
// sensitive besides.

const (
	// timeoutTarget is a synthetic authority that exists only inside the scripted
	// transport, so nothing here can depend on name resolution or egress.
	timeoutTarget = "http://slow.example/"

	// timeoutBudget is the client wall-clock deadline under test. It has to stay well
	// above the scheduling noise between the deadline firing and the elapsed measurement,
	// and well below timeoutTransportSleep, so every case fails on the deadline rather
	// than on the handler's safety valve. Every elapsed bound is expressed as a multiple
	// of this value, so the envelopes scale with it rather than having to be retuned.
	//
	// CALIBRATION. This value also sets the file's irreducible cost, because six sub-cases
	// each wait out one whole budget before asserting anything - one in
	// TestTimeoutClientTimeoutErrorIdentity, three across the RetryMax sweep and two across
	// the constructor parity rows - so 6*timeoutBudget + timeoutCancelAfter (about 0.66s
	// here) is deliberate sleeping that no amount of host quiet can remove. It is kept this
	// short so the file stays inside its runtime budget, and shortening it costs no
	// assertion power at all, because the deadline is a fixture SCALE and never an asserted
	// outcome: every elapsed bound is written relative to it, and the load-bearing
	// assertions are exact counts (callCount() == 1, len(hops) == 1), the four error
	// identity axes and the anti-per-attempt bound, all of which are scale-free. The floor
	// is the overhead the call cannot avoid - client construction, request building and
	// timer granularity, measured at 10-90ms even under 2-3x CPU oversubscription - which
	// the envelope above still clears comfortably. Do NOT buy margin by raising
	// timeoutEnvelopeFactor instead: that would weaken every upper bound in the file.
	timeoutBudget = 100 * time.Millisecond

	// timeoutCancelAfter is when the caller-driven cancellation fires, two orders of
	// magnitude inside timeoutNoDeadline so a defect that let the client deadline end that
	// call would blow the elapsed envelope rather than pass quietly. It also has to leave
	// the call enough time to reach the transport, which the call-count assertion checks.
	// Calibrated with timeoutBudget and for the same reason: it is the one remaining
	// deliberate wait in the file, and both its lower bound and its envelope are written
	// relative to it, so keeping it short loses nothing.
	timeoutCancelAfter = 60 * time.Millisecond

	// timeoutNoDeadline is the cancellation test's client timeout, deliberately far beyond
	// anything that test tolerates so the client deadline cannot be the cause.
	timeoutNoDeadline = 10 * time.Second

	// timeoutTransportSleep never actually elapses, because the handler's select returns
	// as soon as the request context ends. It is the safety valve that turns "the deadline
	// never fired" into a named failure instead of a hang.
	//
	// It therefore stays at 3s even though the deadlines above are deliberately short: it
	// is free in wall time, and the separation is what makes the diagnostic branch a
	// genuine safety valve rather than a race - 30x timeoutBudget and 50x
	// timeoutCancelAfter. It must not be reduced alongside them.
	timeoutTransportSleep = 3 * time.Second

	// timeoutEnvelopeFactor widens every elapsed assertion to this multiple of the budget.
	// Elapsed is an inequality, never an exact duration: exact would flake under load,
	// while a generous bound still fails a per-attempt deadline, which multiplies the total.
	timeoutEnvelopeFactor = 3
)

// timeoutError is the net.Error-shaped contract through which net/http reports that a
// deadline, rather than a peer, ended a request. It is declared locally and matched with
// errors.As because the implementing type is net/http's unexported timeoutError and cannot
// be named from here; asserting the behaviour also pins what callers depend on.
type timeoutError interface {
	Timeout() bool
}

// timeoutSlowTransport returns a recording transport whose handler never answers: it blocks
// until the request context ends and then reports that context's error, as a real transport
// does when a dial or a header read is cut short.
//
// A FRESH transport per case is mandatory: mockTransport's call counter is cumulative, so
// sharing one would turn every "entered exactly once" assertion into a tautology.
//
// The sleep branch is unreachable in a correctly configured test and names the
// misconfiguration if it becomes reachable. It reports through t.Error rather than require,
// following scriptedRedirects, because a require call from another goroutine would Goexit
// and hang the test. The diagnostic uses redactedRequestLine so a URL userinfo password
// cannot reach a retained log (CWE-532).
func timeoutSlowTransport(t *testing.T) *mockTransport {
	t.Helper()

	return newMockTransport(t, func(r *http.Request) (*http.Response, error) {
		select {
		case <-r.Context().Done():
			// The production shape of a cut-short request: no response and the context's
			// own error, whose identity is what each test below discriminates.
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

// newTimeoutHTTPX builds a client whose transport never answers, with the given wall-clock
// budget and retry ceiling, returning both so a test can assert on the caller-visible error
// and on what reached the wire.
//
// Both values go through the option mutator because newMockHTTPX runs it BEFORE New, and New
// freezes Options.Timeout into HTTPX.New's http.Client Timeout field and into the retry
// layer's overall budget, and Options.RetryMax into the retry options. Assigning either
// after construction would leave the client on the harness default and every elapsed
// envelope would pass for the wrong reason. newMockHTTPX also installs the transport on BOTH
// of the retryable client's HTTP clients and registers the fastdialer cleanup.
func newTimeoutHTTPX(t *testing.T, timeout time.Duration, retryMax int) (*HTTPX, *mockTransport) {
	t.Helper()

	rt := timeoutSlowTransport(t)
	ht := newMockHTTPX(t, func(options *Options) {
		options.Timeout = timeout
		options.RetryMax = retryMax
	}, rt)
	return ht, rt
}

// TestTimeoutClientTimeoutErrorIdentity pins the identity of the error produced when the
// deadline in HTTPX.New's http.Client Timeout field fires, on every axis a caller can
// inspect.
//
// Where the wrap chain comes from: the deadline makes net/http replace the round-trip
// error with its unexported timeoutError, whose Timeout() is true and whose custom Is
// method reports equality with context.DeadlineExceeded - which is why the sentinel
// matches even though nothing literally wraps it. net/http wraps that in *url.Error, and
// retryablehttp wraps THAT with fmt.Errorf("... giving up after %d attempts: %w", ...),
// which is the *fmt.wrapError on the outside. Do surfaces the failure as (nil, err)
// because it returns early whenever the response is nil and the error is not.
func TestTimeoutClientTimeoutErrorIdentity(t *testing.T) {
	ht, rt := newTimeoutHTTPX(t, timeoutBudget, 0)

	req, err := retryablehttp.NewRequest(http.MethodGet, timeoutTarget, nil)
	require.NoError(t, err)

	start := time.Now()
	resp, err := ht.Do(req, UnsafeOptions{})
	elapsed := time.Since(start)

	require.Error(t, err, "a transport that never answers must fail the call")
	require.Nil(t, resp, "Do returns no response at all once the deadline fires (httpx.go:261-263)")

	// AXIS 1 - concrete type. *fmt.wrapError is unexported, so %T is the only mechanism
	// available; it still fails the moment the retry layer stops wrapping.
	require.Equal(t, "*fmt.wrapError", fmt.Sprintf("%T", err),
		"the deadline error must reach the caller wrapped by the retry layer's fmt.Errorf")

	// AXIS 2 - sentinel identity, in BOTH directions. Matching DeadlineExceeded alone
	// would still pass under a defect that also made the error match Canceled.
	require.ErrorIs(t, err, context.DeadlineExceeded,
		"a client-deadline failure must match context.DeadlineExceeded")
	require.False(t, errors.Is(err, context.Canceled),
		"a client-deadline failure must NOT match context.Canceled: the two categories have to stay separable")

	// AXIS 3 - Timeout() behaviour: reachable AND true; reaching it and getting false
	// would be a different bug.
	var deadlineErr timeoutError
	require.ErrorAs(t, err, &deadlineErr,
		"a client-deadline failure must expose the net.Error-style Timeout() contract")
	require.True(t, deadlineErr.Timeout(),
		"Timeout() must report true so callers classify this as a timeout rather than a transport fault")

	// AXIS 4 - the retry exhaustion wrapper is PRESENT. The noun stays plural even for a
	// single attempt, so the substring is asserted exactly as the code emits it.
	require.Contains(t, err.Error(), "giving up after 1 attempts:",
		"RetryMax 0 means one attempt, and the retry layer reports that count in the message")

	// Exported structural identity, which the four axes cannot express: the middle of the
	// wrap chain is a *url.Error naming the operation and target that failed and
	// forwarding the deadline nature of the error it carries.
	//
	// The inner error text can vary depending on whether net/http substitutes its
	// client-timeout wrapper before the request context reports DeadlineExceeded, so
	// assertions use causal identity rather than an exact inner string.
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

	// Protocol-visible: one request reached the wire, with the caller's own target and
	// method. A deadline must not retry onto the network.
	require.Equal(t, 1, rt.callCount(), "the deadline must not send a second request")
	hops := rt.requests()
	require.Len(t, hops, 1)
	require.Equal(t, http.MethodGet, hops[0].Method)
	require.Equal(t, timeoutTarget, hops[0].URL)

	// Elapsed is bounded on both sides and pinned to neither: the lower bound fails if a
	// defect shortens the budget the client waits, the upper bound if it lengthens it.
	require.Less(t, timeoutBudget, elapsed,
		"the call must actually spend its configured budget rather than failing early")
	require.Less(t, elapsed, timeoutEnvelopeFactor*timeoutBudget,
		"the call must not overrun a generous multiple of its configured budget")
}

// TestTimeoutIsHardDeadlineNotPerAttempt establishes that Options.Timeout is one hard
// wall-clock deadline for the WHOLE call and not a per-attempt budget: across RetryMax 0, 1
// and 2 the transport is entered EXACTLY ONCE and the call returns after roughly one
// budget, yet the error message's attempt count still reads RetryMax+1.
//
// Two budgets govern the call and both are fed from the same Options.Timeout, which is why
// they expire together instead of nesting. One is HTTPX.New's http.Client Timeout field,
// re-applied by the retry client's own constructor from retryablehttpOptions.Timeout, and
// it is what cuts the single in-flight attempt short. The other is the retry layer's
// overall context, created from that same value at the top of its Do. By the time the
// first attempt fails that overall context is ALREADY expired, so the retry loop's backoff
// select takes its "overall deadline done" branch and leaves without dispatching another
// attempt. The count is formatted unconditionally as RetryMax+1 on the way out, so the
// retry counter advances while the wire sees one request.
//
// The attempt count therefore lives only in the error text, and callCount is the exact
// discriminator: mockTransport counts at the very top of RoundTrip, ahead of every early
// return, so a deadline relocated into the transport or made per-attempt would dispatch
// RetryMax+1 requests and fail it. The elapsed bounds confirm the same property in time.
func TestTimeoutIsHardDeadlineNotPerAttempt(t *testing.T) {
	cases := []struct {
		name     string
		retryMax int
		// wantAttemptPhrase is the retry layer's own attempt count: always RetryMax+1,
		// always plural, because the message comes from a fixed template.
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
			// A fresh client AND transport per row: the call counter is cumulative, so a
			// shared transport would make "exactly once" unfalsifiable after row one.
			ht, rt := newTimeoutHTTPX(t, timeoutBudget, c.retryMax)

			req, err := retryablehttp.NewRequest(http.MethodGet, timeoutTarget, nil)
			require.NoError(t, err)

			start := time.Now()
			resp, err := ht.Do(req, UnsafeOptions{})
			elapsed := time.Since(start)

			require.Error(t, err, "a transport that never answers must fail the call")
			require.Nil(t, resp, "an exhausted retry loop returns no response")

			require.Equal(t, 1, rt.callCount(),
				"the client deadline is one budget for the whole call: once it fires the retry loop's own overall context is already expired, so no further attempt is dispatched")
			hops := rt.requests()
			require.Len(t, hops, 1, "exactly one request may reach the wire regardless of RetryMax")
			require.Equal(t, http.MethodGet, hops[0].Method)
			require.Equal(t, timeoutTarget, hops[0].URL)

			// The retry counter advances even though the wire did not: the count proves
			// the retry layer ran, callCount that it never re-entered the transport.
			require.Contains(t, err.Error(), c.wantAttemptPhrase,
				"the retry layer reports RetryMax+1 attempts in its message even though only one reached the transport")

			// Sentinel identity per row, both directions, so a defect that swapped the
			// category under retry pressure cannot hide behind the timing assertions.
			require.ErrorIs(t, err, context.DeadlineExceeded,
				"every row must fail with the deadline sentinel, not a cancellation")
			require.False(t, errors.Is(err, context.Canceled),
				"a deadline must never be reported as a caller cancellation")

			// Bounded on both sides: roughly one budget, never RetryMax+1 of them.
			require.Less(t, timeoutBudget, elapsed,
				"the call must actually spend its configured budget rather than failing early")
			require.Less(t, elapsed, timeoutEnvelopeFactor*timeoutBudget,
				"the call must not overrun a generous multiple of a SINGLE budget")

			// The explicit anti-per-attempt bound: a per-attempt deadline would allow
			// (RetryMax+1) budgets, so elapsed must stay strictly below that product. The
			// no-retry row cannot express the difference - the product is one budget - so
			// it is skipped rather than asserted vacuously.
			if c.retryMax >= 1 {
				perAttemptBudget := time.Duration(c.retryMax+1) * timeoutBudget
				require.Less(t, elapsed, perAttemptBudget,
					"elapsed must not reach (RetryMax+1) budgets: the deadline is per call, not per attempt")
			}
		})
	}
}

// TestTimeoutContextCancellationIdentity pins the identity of the OTHER timeout category:
// a deadline the caller drives through the request context rather than one the client
// enforces. It asserts all four axes in the negative wherever the deadline test asserts
// them in the positive, so neither category can be substituted for the other without
// failing at least one assertion across the two tests.
//
// The client timeout is set two orders of magnitude beyond the cancellation instant, so the
// client deadline cannot be the cause. The retry layer checks the request context before
// classifying the failure and returns that context's error verbatim rather than retrying a
// cancelled request, which bypasses the fmt.Errorf("giving up after ...") wrapper entirely -
// hence the bare, pointer-identical context.Canceled instead of the deadline category's
// three-deep chain. RetryMax is 2 so that "no retry wrapper appeared" is a real finding: a
// retry budget existed and was deliberately not spent.
func TestTimeoutContextCancellationIdentity(t *testing.T) {
	ht, rt := newTimeoutHTTPX(t, timeoutNoDeadline, 2)

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel on the way out as well as on the timer, so a failure before the call cannot
	// leak the context or the blocked handler.
	defer cancel()

	req, err := ht.NewRequestWithContext(ctx, http.MethodGet, timeoutTarget)
	require.NoError(t, err)

	// The clock is read BEFORE the timer is armed: arming first would give the
	// cancellation a head start over the measurement and could land elapsed just under
	// timeoutCancelAfter, breaking the lower bound for a reason unrelated to the client.
	// Stopping the timer afterwards keeps no runtime timer past the test's completion.
	start := time.Now()
	cancelTimer := time.AfterFunc(timeoutCancelAfter, cancel)
	defer cancelTimer.Stop()

	resp, err := ht.Do(req, UnsafeOptions{})
	elapsed := time.Since(start)

	require.Error(t, err, "a cancelled request must fail the call")
	require.Nil(t, resp, "Do returns no response at all once the request is cancelled (httpx.go:261-263)")

	// AXIS 1 - concrete type. context.Canceled is an errors.New value, so it arrives
	// unwrapped, in contrast to the deadline category's *fmt.wrapError.
	require.Equal(t, "*errors.errorString", fmt.Sprintf("%T", err),
		"a cancellation must reach the caller unwrapped, unlike the deadline category's *fmt.wrapError")

	// The strongest identity available: not an error that matches the sentinel but the
	// sentinel value itself. require.Same compares pointers, so a distinct error with the
	// same message fails here where require.Equal would not.
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

	// AXIS 3 - Timeout() behaviour: errors.As FAILS outright, because context.Canceled
	// implements no Timeout method and nothing wraps it in a value that does. That is a
	// stronger statement than "Timeout() returned false".
	var cancellationErr timeoutError
	require.False(t, errors.As(err, &cancellationErr),
		"a cancellation must expose no Timeout() contract at all, so callers cannot misread it as a timeout")

	// net/http's *url.Error wrapper is likewise absent - the structural counterpart of the
	// axis above.
	var urlErr *url.Error
	require.False(t, errors.As(err, &urlErr),
		"a cancellation short-circuits before net/http wraps the failure in a *url.Error")

	// AXIS 4 - the retry exhaustion wrapper is ABSENT, asserted as an explicit absence on
	// the message rather than as a nil check, with RetryMax non-zero so it means something.
	require.NotContains(t, err.Error(), "giving up after",
		"context cancellation must not be wrapped by the retry-exhaustion message: the retry layer returns the context error verbatim instead")

	// Protocol-visible: the cancellation reached the wire once and was not retried.
	require.Equal(t, 1, rt.callCount(),
		"a cancelled request must not be retried onto the transport despite RetryMax being 2")
	hops := rt.requests()
	require.Len(t, hops, 1)
	require.Equal(t, http.MethodGet, hops[0].Method)
	require.Equal(t, timeoutTarget, hops[0].URL)

	// Elapsed tracks the CANCELLATION instant, not the client deadline, bounded on both
	// sides by inequalities.
	require.Less(t, timeoutCancelAfter, elapsed,
		"the call must last until the cancellation actually fires")
	require.Less(t, elapsed, timeoutEnvelopeFactor*timeoutCancelAfter,
		"elapsed must track the cancellation instant and stay far below the client deadline, which is the proof that the client deadline is not what ended this call")
}

// TestTimeoutContextVariantParity asserts that the client's two request constructors
// honour the deadline identically.
//
// NewRequest is pure delegation to NewRequestWithContext with context.Background(), so the
// two must be indistinguishable on the wire and in the error they produce, yet a defect
// could plausibly affect one and not the other. Both rows therefore assert the SAME
// expected values, and a projection of each row's observable outcome is compared across
// rows afterwards; divergence in either direction fails that comparison.
func TestTimeoutContextVariantParity(t *testing.T) {
	// timeoutOutcome is the DETERMINISTIC projection of one variant's observable result.
	// The rendered message is excluded because its optional client-timeout suffix varies
	// run to run, so comparing whole messages would flake for a reason unrelated to
	// constructor parity; the deterministic core is pinned per row inside the loop.
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
		// newRequest exercises one constructor. A single closure shape lets both rows run
		// byte-identical assertions, so a behavioural difference between the constructors
		// cannot hide behind two hand-written test bodies.
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

	// Collected inside the sub-tests and compared afterwards; t.Run without t.Parallel
	// runs synchronously, so the appends are ordered and race-free.
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

			// Identical identity assertions for both variants: deadline sentinel matches,
			// cancellation sentinel does not, Timeout() reachable and true.
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

			// The deterministic core of the rendered message as exact text: attempt count,
			// operation, target and cause. Only the optional trailing marker varies.
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

	// The parity assertion proper: both variants use the same URL, method and budget, so
	// any divergence means one constructor takes a different path through the client.
	require.Len(t, outcomes, len(cases),
		"both constructor variants must have produced an outcome to compare")
	require.Equal(t, outcomes[0], outcomes[1],
		"the context-free and context-bearing constructors must produce identical observable outcomes")
}
