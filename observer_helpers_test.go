package saml

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

// logObserver returns an Observer that writes each event that is not a success to w on a line of its own, with
// the debug message and the cause of its error as they are, for tests that look for the reason of a failure, or
// for there being none. Events of concurrent requests are written one at a time, as w need not be safe for
// concurrent use.
func logObserver(w io.Writer) Observer {
	var mu sync.Mutex

	return ObserverFunc(func(_ context.Context, event Event) {
		if event.Outcome == OutcomeSuccess {
			return
		}

		line := []string{string(event.Kind), string(event.Outcome), event.ServiceProvider}

		if event.Err != nil {
			line = append(line, event.Err.Error(), event.Err.Debug())

			if cause := event.Err.Cause(); cause != nil {
				line = append(line, fmt.Sprintf("%+v", cause))
			}
		}

		mu.Lock()
		defer mu.Unlock()

		_, _ = fmt.Fprintln(w, strings.Join(line, " "))
	})
}

// statusCodes returns the top-level and the second-level status code of status.
func statusCodes(status Status) (top, second string) {
	if status.StatusCode.StatusCode != nil {
		second = status.StatusCode.StatusCode.Value
	}

	return status.StatusCode.Value, second
}

// errorCodes returns the status codes of the StatusError of err.
func errorCodes(err error) (top, second string) {
	e := ToStatusError(err)

	return e.TopLevelField, e.SecondLevelField
}

// fixedStatusMessages are the StatusMessage texts of the errors of this package.
var fixedStatusMessages = func() map[string]bool {
	messages := map[string]bool{}

	for _, e := range []*StatusError{
		ErrServerError, ErrNotImplemented, ErrMalformedRequest, ErrInvalidRequest, ErrUnknownServiceProvider,
		ErrInvalidSignature, ErrSignatureRequired, ErrNoResponseEndpoint, ErrRequestDenied, ErrRequestNotCurrent,
		ErrDestinationMismatch, ErrReplayed, ErrRequestUnsupported, ErrVersionMismatch, ErrRequestVersionTooHigh,
		ErrRequestVersionTooLow, ErrUnsupportedBinding, ErrInvalidNameIDPolicy, ErrUnknownPrincipal,
		ErrInvalidAttribute, ErrTooManyResponses, ErrAuthnFailed, ErrNoPassive, ErrNoAuthnContext, ErrNoAvailableIDP,
		ErrNoSupportedIDP, ErrProxyCountExceeded, ErrRequiredAttributeUnavailable, ErrLogoutNotFound,
		ErrLogoutResponseUncorrelated, ErrInvalidResponse, ErrReceivedStatus,
	} {
		messages[e.StatusMessageField] = true
	}

	return messages
}()

// statusSaysNothingOfTheRequest reports whether status holds no text but that of this package: a StatusMessage
// that is the constant text of one of its errors, if any, and no StatusDetail. Every test that reads the status
// of a response checks it, so nothing that a test sends can come back in a response.
func statusSaysNothingOfTheRequest(status Status) bool {
	if status.StatusDetail != nil {
		return false
	}

	return status.StatusMessage == nil || fixedStatusMessages[status.StatusMessage.Value]
}

// errorText returns everything that err says: its text, and the debug message and the cause of its StatusError,
// as they are, for tests that look for the reason of a failure.
func errorText(err error) string {
	if err == nil {
		return ""
	}

	text := err.Error()

	var e *StatusError

	if errors.As(err, &e) {
		text += " " + e.Debug()

		if e.Cause() != nil {
			text += " " + e.Cause().Error()
		}
	}

	return text
}

// errorDebug returns the debug message of the StatusError of err.
func errorDebug(err error) string {
	return ToStatusError(err).Debug()
}
