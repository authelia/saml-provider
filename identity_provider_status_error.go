package saml

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrInvalidNameIDPolicy is returned when the NameIDPolicy of a request cannot be satisfied.
var ErrInvalidNameIDPolicy = errors.New("the NameIDPolicy cannot be satisfied")

// statusError is an error that is reported to the requester as a SAML status. It must only be sent
// once the endpoint for the response has been resolved from metadata. The Err is for logs and is
// never sent to the requester.
type statusError struct {
	TopLevel    string
	SecondLevel string
	Err         error
}

// Error implements error.
func (e *statusError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("request status %s %s", e.TopLevel, e.SecondLevel)
	}

	return e.Err.Error()
}

// Unwrap returns the wrapped error.
func (e *statusError) Unwrap() error {
	return e.Err
}

// RequestStatus returns the Status to answer a request with for err, and whether err carries one, for an
// application that serves requests with its own handler rather than ServeSSO or ServeSLO.
//
//   - For an error of IdpAuthnRequest.Validate or IdpLogoutRequest.Validate, false means that the request
//     must not be answered with a SAML response at all, but with an HTTP error such as 400, because it
//     failed before the endpoint to answer it at was established from metadata.
//   - For a later error, such as of an AssertionMaker, false means the request is answered with a
//     Responder status. An error that wraps ErrInvalidNameIDPolicy is Requester with InvalidNameIDPolicy.
//
// The Status has no StatusMessage, as the error is not meant for the service provider.
func RequestStatus(err error) (Status, bool) {
	top, second, ok := requestStatus(err)
	if !ok {
		return Status{}, false
	}

	status := Status{StatusCode: StatusCode{Value: top}}
	if second != "" {
		status.StatusCode.StatusCode = &StatusCode{Value: second}
	}

	return status, true
}

// requestStatus returns the status codes of the first statusError in the chain of err, or those of
// ErrInvalidNameIDPolicy.
func requestStatus(err error) (top, second string, ok bool) {
	var statusErr *statusError

	switch {
	case errors.As(err, &statusErr):
		return statusErr.TopLevel, statusErr.SecondLevel, true
	case errors.Is(err, ErrInvalidNameIDPolicy):
		return StatusRequester, StatusInvalidNameIDPolicy, true
	default:
		return "", "", false
	}
}

// versionStatus returns nil if version is 2.0, and otherwise the error for a request with that
// version. SAMLCore §3.2.2.3 defines RequestVersionTooHigh and RequestVersionTooLow for a major
// version other than 2. Any other version has no second level status.
func versionStatus(version string) *statusError {
	if version == "2.0" {
		return nil
	}

	statusErr := &statusError{
		TopLevel: StatusVersionMismatch,
		Err:      fmt.Errorf("expected SAML request version 2.0 got %v", version),
	}

	majorString, minorString, found := strings.Cut(version, ".")
	if !found {
		return statusErr
	}

	major, err := strconv.Atoi(majorString)
	if err != nil {
		return statusErr
	}

	if _, err = strconv.Atoi(minorString); err != nil {
		return statusErr
	}

	switch {
	case major > 2:
		statusErr.SecondLevel = StatusRequestVersionTooHigh
	case major < 2:
		statusErr.SecondLevel = StatusRequestVersionTooLow
	}

	return statusErr
}
