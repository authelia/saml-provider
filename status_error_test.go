package saml

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// packageStatusErrors are the errors of this package.
var packageStatusErrors = map[string]*StatusError{
	"ErrServerError":                  ErrServerError,
	"ErrNotImplemented":               ErrNotImplemented,
	"ErrMalformedRequest":             ErrMalformedRequest,
	"ErrInvalidRequest":               ErrInvalidRequest,
	"ErrUnknownServiceProvider":       ErrUnknownServiceProvider,
	"ErrInvalidSignature":             ErrInvalidSignature,
	"ErrSignatureRequired":            ErrSignatureRequired,
	"ErrNoResponseEndpoint":           ErrNoResponseEndpoint,
	"ErrRequestDenied":                ErrRequestDenied,
	"ErrRequestNotCurrent":            ErrRequestNotCurrent,
	"ErrDestinationMismatch":          ErrDestinationMismatch,
	"ErrReplayed":                     ErrReplayed,
	"ErrRequestUnsupported":           ErrRequestUnsupported,
	"ErrVersionMismatch":              ErrVersionMismatch,
	"ErrRequestVersionTooHigh":        ErrRequestVersionTooHigh,
	"ErrRequestVersionTooLow":         ErrRequestVersionTooLow,
	"ErrUnsupportedBinding":           ErrUnsupportedBinding,
	"ErrInvalidNameIDPolicy":          ErrInvalidNameIDPolicy,
	"ErrUnknownPrincipal":             ErrUnknownPrincipal,
	"ErrInvalidAttribute":             ErrInvalidAttribute,
	"ErrTooManyResponses":             ErrTooManyResponses,
	"ErrAuthnFailed":                  ErrAuthnFailed,
	"ErrNoPassive":                    ErrNoPassive,
	"ErrNoAuthnContext":               ErrNoAuthnContext,
	"ErrNoAvailableIDP":               ErrNoAvailableIDP,
	"ErrNoSupportedIDP":               ErrNoSupportedIDP,
	"ErrProxyCountExceeded":           ErrProxyCountExceeded,
	"ErrRequiredAttributeUnavailable": ErrRequiredAttributeUnavailable,
	"ErrLogoutNotFound":               ErrLogoutNotFound,
	"ErrLogoutResponseUncorrelated":   ErrLogoutResponseUncorrelated,
	"ErrInvalidResponse":              ErrInvalidResponse,
	"ErrReceivedStatus":               ErrReceivedStatus,
}

func testStatusDetail(text string) *etree.Element {
	el := etree.NewElement("ex:Reason")
	el.CreateAttr("xmlns:ex", "https://example.com/ns/status")
	el.SetText(text)

	return el
}

// SAMLCore §3.2.2.2 allows three top-level codes for a failure, and every error must be told apart by its name.
func TestPackageStatusErrorsAreValid(t *testing.T) {
	names := map[string]string{}

	for name, e := range packageStatusErrors {
		t.Run(name, func(t *testing.T) {
			assert.NilError(t, e.Validate())
			assert.Check(t, e.StatusMessageField != "")
			assert.Check(t, is.Equal(e.DebugField, ""))
			assert.Check(t, e.Cause() == nil)
			assert.Check(t, is.Len(e.StatusDetailField, 0))
			assert.Check(t, is.Equal(strings.ToLower(e.ErrorField), e.ErrorField))

			if other, ok := names[e.ErrorField]; ok {
				t.Errorf("%s has the name of %s", name, other)
			}

			names[e.ErrorField] = name
		})
	}
}

// The package level errors are shared by every request, so no With method may change the error it is called on.
func TestStatusErrorBuildersCopy(t *testing.T) {
	builders := map[string]func(e *StatusError) *StatusError{
		"WithWrap":          func(e *StatusError) *StatusError { return e.WithWrap(errors.New("cause")) },
		"WithDebug":         func(e *StatusError) *StatusError { return e.WithDebug("debug") },
		"WithDebugf":        func(e *StatusError) *StatusError { return e.WithDebugf("debug %d", 1) },
		"WithDebugError":    func(e *StatusError) *StatusError { return e.WithDebugError(errors.New("cause")) },
		"WithStatusMessage": func(e *StatusError) *StatusError { return e.WithStatusMessage("another message") },
		"WithStatusDetail":  func(e *StatusError) *StatusError { return e.WithStatusDetail(testStatusDetail("detail")) },
		"WithSecondLevel":   func(e *StatusError) *StatusError { return e.WithSecondLevel("https://example.com/status/other") },
		"WithHTTPStatus":    func(e *StatusError) *StatusError { return e.WithHTTPStatus(http.StatusTeapot) },
	}

	for name, e := range packageStatusErrors {
		before := *e

		for builderName, build := range builders {
			built := build(e)

			assert.Check(t, built != e, "%s.%s returned the error itself", name, builderName)
			assert.Check(t, reflect.DeepEqual(before, *e), "%s.%s changed the error", name, builderName)
			assert.Check(t, !reflect.DeepEqual(before, *built), "%s.%s changed nothing", name, builderName)
			assert.Check(t, errors.Is(built, e), "%s.%s no longer matches the error", name, builderName)
		}
	}

	// A chain keeps what each step added, and a later step doesn't change the result of an earlier one.
	first := ErrRequestDenied.WithDebug("first")
	second := first.WithDebug("second").WithStatusDetail(testStatusDetail("one"))
	third := second.WithStatusDetail(testStatusDetail("two"))

	assert.Check(t, is.Equal(first.Debug(), "first"))
	assert.Check(t, is.Equal(second.Debug(), "second"))
	assert.Check(t, is.Len(first.StatusDetailField, 0))
	assert.Check(t, is.Len(second.StatusDetailField, 1))
	assert.Check(t, is.Len(third.StatusDetailField, 2))

	assert.Check(t, ErrRequestDenied.WithDebugError(nil) == ErrRequestDenied)
}

func TestStatusErrorIsAndAs(t *testing.T) {
	cause := errors.New("the cause")
	err := fmt.Errorf("validate: %w", ErrRequestNotCurrent.WithDebug("request expired").WithWrap(cause))

	// A copy matches the error it was made from, through wrapping, and its cause is found too.
	assert.Check(t, errors.Is(err, ErrRequestNotCurrent))
	assert.Check(t, errors.Is(err, cause))

	// Requester with RequestDenied is the status of many errors, which are told apart by name.
	assert.Check(t, !errors.Is(err, ErrRequestDenied))
	assert.Check(t, !errors.Is(err, ErrReplayed))
	assert.Check(t, !errors.Is(err, os.ErrNotExist))
	assert.Check(t, !errors.Is(ErrRequestNotCurrent, (*StatusError)(nil)))

	// A change of the status codes doesn't make it another error.
	assert.Check(t, errors.Is(ErrRequestDenied.WithSecondLevel(""), ErrRequestDenied))

	var statusErr *StatusError

	assert.Assert(t, errors.As(err, &statusErr))
	assert.Check(t, is.Equal(statusErr.Debug(), "request expired"))
	assert.Check(t, is.Equal(statusErr.Cause(), cause))

	// A StatusError that wraps another matches both.
	outer := ErrServerError.WithWrap(ErrInvalidSignature.WithDebug("bad"))
	assert.Check(t, errors.Is(outer, ErrServerError))
	assert.Check(t, errors.Is(outer, ErrInvalidSignature))
}

func TestToStatusError(t *testing.T) {
	assert.Check(t, ToStatusError(nil) == nil)

	// An unknown error is a failure of the identity provider, with the error as its cause and its debug message.
	plain := errors.New("connection refused")
	e := ToStatusError(plain)
	assert.Check(t, errors.Is(e, ErrServerError))
	assert.Check(t, errors.Is(e, plain))
	assert.Check(t, is.Equal(e.TopLevelField, StatusResponder))
	assert.Check(t, is.Equal(e.SecondLevelField, ""))
	assert.Check(t, is.Equal(e.HTTPStatus(), http.StatusInternalServerError))
	assert.Check(t, is.Equal(e.Debug(), "connection refused"))
	assert.Check(t, is.Equal(e.Cause(), plain))
	assert.Check(t, is.Equal(ErrServerError.Debug(), ""))

	// A StatusError is returned as it is.
	denied := ErrRequestDenied.WithDebug("why")
	assert.Check(t, ToStatusError(denied) == denied)
	assert.Check(t, ToStatusError(ErrRequestDenied) == ErrRequestDenied)

	// One that is wrapped keeps what the wrapping says, as its debug message, unless it has one.
	wrapped := ToStatusError(fmt.Errorf("%w: cannot issue the format %q", ErrInvalidNameIDPolicy, "x"))
	assert.Check(t, errors.Is(wrapped, ErrInvalidNameIDPolicy))
	assert.Check(t, is.Contains(wrapped.Debug(), `cannot issue the format "x"`))
	assert.Check(t, is.Equal(ErrInvalidNameIDPolicy.Debug(), ""))

	assert.Check(t, is.Equal(ToStatusError(fmt.Errorf("outer: %w", denied)).Debug(), "why"))
}

func TestNewStatusError(t *testing.T) {
	const custom = "https://example.com/status/account-locked"

	e, err := NewStatusError("account_locked", StatusResponder, custom, "the account is locked", http.StatusForbidden)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(e.Error(), "account_locked: the account is locked"))
	assert.Check(t, is.Equal(e.SecondLevelField, custom))

	for name, tc := range map[string]struct {
		name, top, second string
		status            int
		err               string
	}{
		"no name":                  {"", StatusResponder, "", 500, "no name"},
		"success":                  {"x", StatusSuccess, "", 500, "top-level status"},
		"second level as top":      {"x", StatusRequestDenied, "", 500, "top-level status"},
		"no top level":             {"x", "", "", 500, "top-level status"},
		"second level not a URI":   {"x", StatusRequester, "denied", 400, "absolute URI"},
		"second level with spaces": {"x", StatusRequester, "urn:x:a b", 400, "absolute URI"},
		"not an HTTP error":        {"x", StatusRequester, "", 200, "HTTP status"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewStatusError(tc.name, tc.top, tc.second, "", tc.status)
			assert.Check(t, is.ErrorContains(err, tc.err))
		})
	}

	// An HTTP status that is not one of an error is never written.
	assert.Check(t, is.Equal((&StatusError{HTTPStatusField: 200}).HTTPStatus(), http.StatusInternalServerError))
	assert.Check(t, is.Equal((&StatusError{}).HTTPStatus(), http.StatusInternalServerError))
}

func statusDetailChildren(status Status) []*etree.Element {
	if status.StatusDetail == nil {
		return nil
	}

	return status.StatusDetail.Children
}

func TestErrorStatusEncoding(t *testing.T) {
	const hostile = "https://evil.example.com/<script>\x00\x1b[31m\n"

	err := ErrUnknownPrincipal.WithDebugf("no principal for %s", hostile)

	t.Run("debug is not exposed by default", func(t *testing.T) {
		idp := &IdentityProvider{}

		status := idp.ErrorStatus(err)
		top, second := statusCodes(status)
		assert.Check(t, is.Equal(top, StatusRequester))
		assert.Check(t, is.Equal(second, StatusUnknownPrincipal))
		assert.Check(t, is.Equal(status.StatusMessage.Value, "the principal is unknown"))
		assert.Check(t, status.StatusDetail == nil)
	})

	t.Run("exposed debug is a namespaced StatusDetail child", func(t *testing.T) {
		idp := &IdentityProvider{ExposeDebug: true}

		status := idp.ErrorStatus(err)

		// The StatusMessage stays the constant text.
		assert.Check(t, is.Equal(status.StatusMessage.Value, "the principal is unknown"))

		children := statusDetailChildren(status)
		assert.Assert(t, is.Len(children, 1))
		assert.Check(t, is.Equal(children[0].Tag, "Debug"))
		assert.Check(t, is.Equal(children[0].NamespaceURI(), StatusDetailDebugNamespace))
		assert.Check(t, is.Contains(children[0].Text(), "no principal for https://evil.example.com/<script>"))

		// What an XML document can't hold is replaced, and markup is escaped when the status is written.
		assert.Check(t, !strings.ContainsAny(children[0].Text(), "\x00\x1b"))

		doc := etree.NewDocument()
		doc.SetRoot(status.Element())

		written, writeErr := doc.WriteToString()
		assert.NilError(t, writeErr)
		assert.Check(t, !strings.Contains(written, "<script>"))
		assert.NilError(t, etree.NewDocument().ReadFromString(written))

		// An error with no debug message has no Debug element.
		assert.Check(t, idp.ErrorStatus(ErrUnknownPrincipal).StatusDetail == nil)
	})

	t.Run("a requester that is not established gets the status codes alone", func(t *testing.T) {
		idp := &IdentityProvider{ExposeDebug: true}

		status := idp.status(nil, err.WithStatusDetail(testStatusDetail("detail")), requestState{})
		top, second := statusCodes(status)
		assert.Check(t, is.Equal(top, StatusRequester))
		assert.Check(t, is.Equal(second, StatusUnknownPrincipal))
		assert.Check(t, status.StatusMessage == nil)
		assert.Check(t, status.StatusDetail == nil)
	})

	t.Run("an unknown error is Responder and says nothing", func(t *testing.T) {
		status := (&IdentityProvider{}).ErrorStatus(errors.New("dial tcp 10.0.0.1: connection refused"))
		top, second := statusCodes(status)
		assert.Check(t, is.Equal(top, StatusResponder))
		assert.Check(t, is.Equal(second, ""))
		assert.Check(t, is.Equal(status.StatusMessage.Value, ErrServerError.StatusMessageField))
		assert.Check(t, status.StatusDetail == nil)
	})

	t.Run("codes that are not valid are not sent", func(t *testing.T) {
		idp := &IdentityProvider{}

		top, second := statusCodes(idp.ErrorStatus(&StatusError{ErrorField: "x", TopLevelField: StatusSuccess, SecondLevelField: StatusPartialLogout}))
		assert.Check(t, is.Equal(top, StatusResponder))
		assert.Check(t, is.Equal(second, ""))

		top, second = statusCodes(idp.ErrorStatus(ErrRequestDenied.WithSecondLevel("not a uri\n")))
		assert.Check(t, is.Equal(top, StatusRequester))
		assert.Check(t, is.Equal(second, ""))

		top, second = statusCodes(idp.ErrorStatus(ErrRequestDenied.WithSecondLevel("https://example.com/status/custom")))
		assert.Check(t, is.Equal(top, StatusRequester))
		assert.Check(t, is.Equal(second, "https://example.com/status/custom"))
	})
}

func TestStatusErrorStatusDetail(t *testing.T) {
	observer := &RecordingObserver{}
	idp := &IdentityProvider{Observer: observer}

	detail := testStatusDetail("locked until tomorrow")
	err := ErrAuthnFailed.WithStatusDetail(detail, nil)

	// The element is copied when it is added, and again when the status is made.
	detail.SetText("changed afterwards")

	status := idp.ErrorStatus(err)
	children := statusDetailChildren(status)
	assert.Assert(t, is.Len(children, 1))
	assert.Check(t, is.Equal(children[0].Text(), "locked until tomorrow"))
	assert.Check(t, is.Equal(children[0].NamespaceURI(), "https://example.com/ns/status"))

	children[0].SetText("changed in the status")
	assert.Check(t, is.Equal(statusDetailChildren(idp.ErrorStatus(err))[0].Text(), "locked until tomorrow"))
	assert.Check(t, is.Len(observer.Events(), 0))

	// The debug message comes after the detail of the application.
	idp.ExposeDebug = true

	children = statusDetailChildren(idp.ErrorStatus(err.WithDebug("why")))
	assert.Assert(t, is.Len(children, 2))
	assert.Check(t, is.Equal(children[0].Tag, "Reason"))
	assert.Check(t, is.Equal(children[1].Tag, "Debug"))

	idp.ExposeDebug = false

	// A child that is in no namespace, or whose namespace is declared outside it, is left out and reported.
	unqualified := etree.NewElement("Reason")

	borrowed := etree.NewElement("ex:Reason")

	parent := etree.NewElement("Parent")
	parent.CreateAttr("xmlns:ex", "https://example.com/ns/status")
	parent.AddChild(borrowed)

	inner := testStatusDetail("")
	inner.CreateElement("other:Inner")

	for name, child := range map[string]*etree.Element{"unqualified": unqualified, "declared outside": borrowed, "descendant": inner} {
		t.Run(name, func(t *testing.T) {
			observer.Reset()

			bad := ErrAuthnFailed.WithStatusDetail(testStatusDetail("kept"), child)
			assert.Check(t, is.ErrorContains(bad.Validate(), "StatusDetail"))

			children := statusDetailChildren(idp.ErrorStatus(bad))
			assert.Assert(t, is.Len(children, 1))
			assert.Check(t, is.Equal(children[0].Text(), "kept"))

			events := observer.Events()
			assert.Assert(t, is.Len(events, 1))
			assert.Check(t, is.Equal(events[0].Kind, EventStatusDetail))
			assert.Check(t, is.Equal(events[0].Outcome, OutcomeWarning))
		})
	}
}

// The debug message and the cause are text of the other party. The line that is logged must stay one line, and
// must not carry an escape sequence to a terminal.
func TestStatusErrorFormat(t *testing.T) {
	const hostile = "evil\n2026-01-01 level=info msg=\"admin logged in\"\r\x1b[2J\x00\u202e"

	err := ErrInvalidSignature.WithDebugf("issuer %s", hostile).WithWrap(fmt.Errorf("parse %s", hostile))

	assert.Check(t, is.Equal(err.Error(), "invalid_signature: the signature of the message could not be verified"))
	assert.Check(t, is.Equal(fmt.Sprintf("%v", err), err.Error()))
	assert.Check(t, is.Equal(fmt.Sprintf("%s", err), err.Error()))
	assert.Check(t, is.Equal(fmt.Sprintf("%q", err), `"invalid_signature: the signature of the message could not be verified"`))

	full := fmt.Sprintf("%+v", err)

	assert.Check(t, strings.HasPrefix(full, "invalid_signature: the signature of the message could not be verified status=Requester/RequestDenied http_status=400 debug=\"issuer evil\\n"), full)
	assert.Check(t, is.Contains(full, ` cause="parse evil\n`))
	assert.Check(t, is.Contains(full, `\x1b[2J`))
	assert.Check(t, is.Contains(full, `\u202e`))

	for _, r := range full {
		assert.Check(t, r >= 0x20 && r != 0x7f && r != 0x202e, "the formatted error has the character %U", r)
	}

	// The quotes of the debug message are escaped, so it can't end its own value and begin another.
	assert.Check(t, is.Contains(full, `msg=\"admin logged in\"`))

	// A wrapped error is formatted through the wrapping only as its text, which has no debug message.
	assert.Check(t, !strings.Contains(fmt.Sprintf("%+v", fmt.Errorf("outer: %w", err)), "evil"))

	t.Run("cause", func(t *testing.T) {
		// A cause that only repeats the debug message is not printed twice.
		same := ErrServerError.WithDebugError(errors.New("boom"))
		assert.Check(t, is.Equal(fmt.Sprintf("%+v", same), `server_error: the request could not be processed status=Responder http_status=500 debug="boom"`))

		// A StatusError in the chain of the cause is printed in full, with its own debug message.
		nested := ErrServerError.WithDebug("cannot answer").WithWrap(fmt.Errorf("wrapped: %w", ErrRequestNotCurrent.WithDebug("expired")))
		assert.Check(t, is.Equal(fmt.Sprintf("%+v", nested),
			`server_error: the request could not be processed status=Responder http_status=500 debug="cannot answer" `+
				`cause={request_not_current: the request has expired or is not yet valid status=Requester/RequestDenied http_status=400 debug="expired"}`))
	})

	t.Run("codes", func(t *testing.T) {
		assert.Check(t, is.Contains(fmt.Sprintf("%+v", ErrVersionMismatch), " status=VersionMismatch "))
		assert.Check(t, is.Contains(fmt.Sprintf("%+v", ErrRequestDenied.WithSecondLevel("https://example.com/status/x")), " status=Requester/https://example.com/status/x "))

		// The codes of a status that was received are text of the other party as well.
		received := StatusErrorFromStatus(Status{StatusCode: StatusCode{Value: "evil\ncode", StatusCode: &StatusCode{Value: "a b"}}})
		assert.Check(t, is.Contains(fmt.Sprintf("%+v", received), ` status="evil\ncode"/"a b" `))
	})

	t.Run("without a name or a message", func(t *testing.T) {
		assert.Check(t, is.Equal((&StatusError{ErrorField: "x"}).Error(), "x"))
		assert.Check(t, is.Equal((&StatusError{StatusMessageField: "m"}).Error(), "m"))
	})
}

func slogGroup(t *testing.T, value slog.Value) map[string]slog.Value {
	t.Helper()

	assert.Assert(t, is.Equal(value.Kind(), slog.KindGroup))

	group := map[string]slog.Value{}
	for _, attr := range value.Group() {
		group[attr.Key] = attr.Value.Resolve()
	}

	return group
}

func TestStatusErrorLogValue(t *testing.T) {
	const hostile = "evil\nline\x1b[2J"

	err := ErrInvalidSignature.WithDebug(hostile).WithWrap(errors.New("the cause"))

	group := slogGroup(t, err.LogValue())
	assert.Check(t, is.Equal(group["error"].String(), "invalid_signature"))
	assert.Check(t, is.Equal(group["top_level"].String(), StatusRequester))
	assert.Check(t, is.Equal(group["second_level"].String(), StatusRequestDenied))
	assert.Check(t, is.Equal(group["status_message"].String(), ErrInvalidSignature.StatusMessageField))
	assert.Check(t, is.Equal(group["http_status"].Int64(), int64(400)))
	assert.Check(t, is.Equal(group["debug"].String(), hostile))
	assert.Check(t, is.Equal(group["cause"].String(), "the cause"))
	assert.Check(t, is.Len(group, 7))

	// What has no value is left out.
	group = slogGroup(t, ErrServerError.LogValue())
	assert.Check(t, is.Len(group, 4))

	// The same as a map, for a logger that is not slog.
	assert.Check(t, is.DeepEqual(err.Fields(), map[string]any{
		"error":          "invalid_signature",
		"top_level":      StatusRequester,
		"second_level":   StatusRequestDenied,
		"status_message": ErrInvalidSignature.StatusMessageField,
		"http_status":    int64(400),
		"debug":          hostile,
		"cause":          "the cause",
	}))

	// A handler escapes the values, so the record stays one line.
	for name, handler := range map[string]func(w io.Writer) slog.Handler{
		"text": func(w io.Writer) slog.Handler { return slog.NewTextHandler(w, nil) },
		"json": func(w io.Writer) slog.Handler { return slog.NewJSONHandler(w, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			var logged bytes.Buffer

			slog.New(handler(&logged)).Error("failed", "err", err)

			assert.Check(t, is.Equal(strings.Count(logged.String(), "\n"), 1), logged.String())
			assert.Check(t, !strings.Contains(logged.String(), "\x1b"))
			assert.Check(t, is.Contains(logged.String(), "invalid_signature"))
		})
	}
}

func TestEventFormat(t *testing.T) {
	event := Event{
		Kind:            EventSSO,
		Outcome:         OutcomeFailure,
		Err:             ErrUnknownServiceProvider.WithDebug("no such\nservice provider"),
		ServiceProvider: "https://evil.example.com/\nforged line",
		RequestID:       "id-1",
	}

	line := event.String()
	assert.Check(t, is.Equal(line, `sso failure service_provider="https://evil.example.com/\nforged line" verified=false request_id=id-1 `+
		`error=unknown_service_provider: the service provider is unknown status=Requester/RequestDenied http_status=400 debug="no such\nservice provider"`))
	assert.Check(t, is.Equal(fmt.Sprintf("%v", event), line))
	assert.Check(t, is.Equal(fmt.Sprintf("%+v", event), line))

	group := slogGroup(t, event.LogValue())
	assert.Check(t, is.Equal(group["kind"].String(), "sso"))
	assert.Check(t, is.Equal(group["outcome"].String(), "failure"))
	assert.Check(t, is.Equal(group["service_provider"].String(), event.ServiceProvider))
	assert.Check(t, is.Equal(group["verified"].Bool(), false))
	assert.Check(t, is.Equal(group["request_id"].String(), "id-1"))
	assert.Check(t, is.Equal(slogGroup(t, group["error"])["error"].String(), "unknown_service_provider"))

	fields := event.Fields()
	assert.Check(t, is.Equal(fields["kind"], "sso"))
	assert.Check(t, is.Equal(fields["outcome"], "failure"))
	assert.Check(t, is.Equal(fields["service_provider"], event.ServiceProvider))
	assert.Check(t, is.Equal(fields["verified"], false))
	assert.Check(t, is.Equal(fields["request_id"], "id-1"))
	assert.Check(t, is.Equal(fields["error"].(map[string]any)["error"], "unknown_service_provider"))
	assert.Check(t, is.DeepEqual(Event{Kind: EventLogout, Outcome: OutcomeSuccess}.Fields(), map[string]any{"kind": "logout", "outcome": "success"}))

	success := Event{Kind: EventLogout, Outcome: OutcomeSuccess}
	assert.Check(t, is.Equal(success.String(), "logout success"))
	assert.Check(t, is.Len(slogGroup(t, success.LogValue()), 2))
}

// Without an Observer the events are logged with the default logger, at a level that tells a failure of the
// other party from one of the identity provider.
func TestDefaultObserverLogs(t *testing.T) {
	logged := captureDefaultLog(t)

	for _, tc := range []struct {
		event Event
		level string
	}{
		{requestState{}.event(EventSSO, nil), "level=INFO"},
		{requestState{}.warning(EventStore, errors.New("boom")), "level=WARN"},
		{requestState{}.event(EventSSO, ErrRequestDenied.WithDebug("evil\nline")), "level=WARN"},
		{requestState{}.event(EventSSO, errors.New("boom")), "level=ERROR"},
	} {
		logged.Reset()

		observe(context.Background(), nil, tc.event)

		assert.Check(t, is.Contains(logged.String(), tc.level))
		assert.Check(t, is.Contains(logged.String(), "saml.kind="+string(tc.event.Kind)))
		assert.Check(t, is.Equal(strings.Count(logged.String(), "\n"), 1), logged.String())
	}
}

func TestObserverFuncAndRecordingObserver(t *testing.T) {
	type key struct{}

	recorder := &RecordingObserver{}

	var seen any

	observer := ObserverFunc(func(ctx context.Context, event Event) {
		seen = ctx.Value(key{})

		recorder.Observe(ctx, event)
	})

	clock := TimeNow()

	// The context of the request reaches the observer, so that an application can relate the event to it.
	observe(context.WithValue(context.Background(), key{}, "request-1"), observer, requestState{requestID: "id-1"}.event(EventSSO, nil))
	assert.Check(t, is.Equal(seen, "request-1"))

	observe(nil, observer, requestState{}.event(EventLogout, errors.New("boom"))) //nolint:staticcheck // A nil context is replaced.
	assert.Check(t, is.Equal(seen, nil))

	events := recorder.Events()
	assert.Assert(t, is.Len(events, 2))
	assert.Check(t, is.Equal(events[0].Kind, EventSSO))
	assert.Check(t, is.Equal(events[0].RequestID, "id-1"))
	assert.Check(t, !events[0].Time.Before(clock))
	assert.Check(t, is.Equal(events[1].Outcome, OutcomeFailure))
	assert.Check(t, errors.Is(events[1].Err, ErrServerError))

	recorder.Reset()
	assert.Check(t, is.Len(recorder.Events(), 0))
}

// Everything in a status that is received is chosen by the party that sent it.
func TestStatusErrorFromStatus(t *testing.T) {
	const received = `<samlp:Status xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">` +
		`<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:NoPassive"/></samlp:StatusCode>` +
		`<samlp:StatusMessage>please&#10;log this</samlp:StatusMessage>` +
		`<samlp:StatusDetail><x:Cause xmlns:x="https://idp.example.com/ns" x:code="7">detail <b xmlns="">text</b></x:Cause><Plain/></samlp:StatusDetail>` +
		`</samlp:Status>`

	var status Status

	assert.NilError(t, xml.Unmarshal([]byte(received), &status))
	assert.Assert(t, status.StatusDetail != nil)
	assert.Assert(t, is.Len(status.StatusDetail.Children, 2))
	assert.Check(t, is.Equal(status.StatusDetail.Children[0].Tag, "Cause"))
	assert.Check(t, is.Equal(status.StatusDetail.Children[0].NamespaceURI(), "https://idp.example.com/ns"))
	assert.Check(t, is.Equal(status.StatusDetail.Children[1].NamespaceURI(), ""))

	err := StatusErrorFromStatus(status)

	assert.Check(t, errors.Is(err, ErrReceivedStatus))
	assert.Check(t, is.Equal(err.TopLevelField, StatusResponder))
	assert.Check(t, is.Equal(err.SecondLevelField, StatusNoPassive))
	assert.Check(t, is.Equal(err.HTTPStatus(), http.StatusBadGateway))

	// The text of the other party is only in the debug message.
	assert.Check(t, is.Equal(err.StatusMessageField, ErrReceivedStatus.StatusMessageField))
	assert.Check(t, is.Len(err.StatusDetailField, 0))
	assert.Check(t, is.Contains(err.Debug(), "status Responder/NoPassive"))
	assert.Check(t, is.Contains(err.Debug(), "StatusMessage: please\nlog this"))
	assert.Check(t, is.Contains(err.Debug(), "StatusDetail: "))
	assert.Check(t, is.Contains(err.Debug(), `code="7"`))
	assert.Check(t, is.Contains(err.Debug(), "detail "))
	assert.Check(t, !strings.Contains(err.Error(), "please"))
	assert.Check(t, !strings.Contains(fmt.Sprintf("%+v", err), "\n"))

	// So it is not sent on when the error is itself reported, unless the debug message is exposed.
	sent := (&IdentityProvider{}).ErrorStatus(err)
	assert.Check(t, is.Equal(sent.StatusMessage.Value, ErrReceivedStatus.StatusMessageField))
	assert.Check(t, sent.StatusDetail == nil)

	// The package level error is not changed, and what is kept of a long message is bounded.
	assert.Check(t, is.Equal(ErrReceivedStatus.SecondLevelField, ""))
	assert.Check(t, is.Equal(ErrReceivedStatus.Debug(), ""))

	long := StatusErrorFromStatus(Status{
		StatusCode:    StatusCode{Value: StatusRequester},
		StatusMessage: &StatusMessage{Value: strings.Repeat("a", 10*maxReceivedDebugLength)},
	})
	assert.Check(t, len(long.Debug()) < 2*maxReceivedDebugLength)
	assert.Check(t, is.Equal(long.SecondLevelField, ""))
}

func TestVersionError(t *testing.T) {
	assert.NilError(t, versionError("2.0"))

	for version, expected := range map[string]*StatusError{
		"3.0":  ErrRequestVersionTooHigh,
		"1.1":  ErrRequestVersionTooLow,
		"2.1":  ErrVersionMismatch,
		"2":    ErrVersionMismatch,
		"x.0":  ErrVersionMismatch,
		"2.x":  ErrVersionMismatch,
		"":     ErrVersionMismatch,
		"\n.0": ErrVersionMismatch,
	} {
		err := versionError(version)

		assert.Check(t, errors.Is(err, expected), "%q: %v", version, err)
		assert.Check(t, is.Equal(ToStatusError(err).TopLevelField, StatusVersionMismatch))
		assert.Check(t, is.Contains(ToStatusError(err).Debug(), version))
		assert.Check(t, !strings.Contains(err.Error(), "\n"))
	}
}
