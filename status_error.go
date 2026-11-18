package saml

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/beevik/etree"
)

// StatusError is the error of this package for a SAML exchange that failed. It carries the two ways in which
// the failure can be reported, which are the status of a SAML response (SAMLCore §3.2.2) and the status of an
// HTTP response, and what is reported of it to the Observer.
//
// Which of the two is used is not a property of the error: it depends on how far the request got. A request
// that fails before the party that sent it is established, and the endpoint for the response is chosen from
// its metadata, is answered with HTTPStatusField and never with a SAML response. One that fails later is
// answered with a signed SAML response which has the status codes of the error, the StatusMessageField, and
// the StatusDetailField. The handlers of IdentityProvider decide that, as IdpAuthnRequest.Respondable
// describes.
//
// DebugField is the only field that may hold text which came from the other party: an entity ID, an ID, a
// URL, the text of a parser error. It is for logs, and is only sent to the other party when
// IdentityProvider.ExposeDebug is set. Every other field must be set to text that the application chose.
//
// The package level errors, such as ErrRequestDenied, are never changed: every With method returns a copy.
// [errors.Is] matches by ErrorField, so a copy with a debug message or a cause is still that error.
type StatusError struct {
	// ErrorField is the stable name of the error in snake case, such as request_denied. It is what
	// [errors.Is] compares and what the logs name the error by. It is never sent to the other party.
	ErrorField string

	// TopLevelField is the top-level status code, which SAMLCore §3.2.2.2 requires to be StatusRequester,
	// StatusResponder or StatusVersionMismatch for a failure.
	TopLevelField string

	// SecondLevelField is the optional second-level status code. It is one of the codes of SAMLCore §3.2.2.2,
	// such as StatusRequestDenied, or an absolute URI that the application defines.
	SecondLevelField string

	// StatusMessageField is the text of the StatusMessage, which SAMLCore §3.2.2.3 describes as a message that
	// may be returned to an operator. It must be constant text, and never include anything of the request.
	StatusMessageField string

	// StatusDetailField holds the children of the StatusDetail (SAMLCore §3.2.2.4). See WithStatusDetail.
	StatusDetailField []*etree.Element

	// DebugField says what went wrong for this request. It is untrusted text. See StatusError.
	DebugField string

	// HTTPStatusField is the status of the HTTP response for a failure that is not answered with a SAML
	// response.
	HTTPStatusField int

	cause error
}

// The errors of this package. Each is a template: add what is known of the failure with WithDebugf, WithWrap
// and the other With methods, which return a copy.
var (
	// ErrServerError is a failure of the identity provider itself, such as of a store or of a signing key. It
	// is also what ToStatusError makes of an error that is not a StatusError.
	ErrServerError = &StatusError{
		ErrorField:         "server_error",
		TopLevelField:      StatusResponder,
		StatusMessageField: "the request could not be processed",
		HTTPStatusField:    http.StatusInternalServerError,
	}

	// ErrNotImplemented is a request for something that this identity provider is not set up to do, such as a
	// query when the SessionProvider is not a QuerySessionProvider.
	ErrNotImplemented = &StatusError{
		ErrorField:         "not_implemented",
		TopLevelField:      StatusResponder,
		SecondLevelField:   StatusRequestUnsupported,
		StatusMessageField: "the request is not supported by the identity provider",
		HTTPStatusField:    http.StatusNotImplemented,
	}

	// ErrMalformedRequest is a message that could not be read: it is too large, is not encoded as its binding
	// requires, is not the XML of the message that is expected, or has no usable ID or Issuer.
	ErrMalformedRequest = &StatusError{
		ErrorField:         "malformed_request",
		TopLevelField:      StatusRequester,
		SecondLevelField:   StatusRequestDenied,
		StatusMessageField: "the message could not be read",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrInvalidRequest is a request that was read, and verified where that is required, but lacks something
	// that its protocol requires, such as the Subject of a query.
	ErrInvalidRequest = &StatusError{
		ErrorField:         "invalid_request",
		TopLevelField:      StatusRequester,
		StatusMessageField: "the request is not valid",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrUnknownServiceProvider is a message whose Issuer is not a service provider that the
	// ServiceProviderProvider has current metadata for.
	ErrUnknownServiceProvider = &StatusError{
		ErrorField:         "unknown_service_provider",
		TopLevelField:      StatusRequester,
		SecondLevelField:   StatusRequestDenied,
		StatusMessageField: "the service provider is unknown",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrInvalidSignature is a message whose signature could not be verified with the keys in the metadata of
	// its issuer, or is not made as the bindings and the signature policy require.
	ErrInvalidSignature = &StatusError{
		ErrorField:         "invalid_signature",
		TopLevelField:      StatusRequester,
		SecondLevelField:   StatusRequestDenied,
		StatusMessageField: "the signature of the message could not be verified",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrSignatureRequired is a message that is not signed and must be.
	ErrSignatureRequired = &StatusError{
		ErrorField:         "signature_required",
		TopLevelField:      StatusRequester,
		SecondLevelField:   StatusRequestDenied,
		StatusMessageField: "the message must be signed",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrNoResponseEndpoint is a request that can't be answered, because the metadata of the service provider
	// has no endpoint that the response can be sent to: none that the request names, none with a supported
	// binding, or none that is secure.
	ErrNoResponseEndpoint = &StatusError{
		ErrorField:         "no_response_endpoint",
		TopLevelField:      StatusRequester,
		SecondLevelField:   StatusRequestDenied,
		StatusMessageField: "the service provider has no endpoint that the response can be sent to",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrRequestDenied is a request that the identity provider refuses, for a reason that has no error of its
	// own.
	ErrRequestDenied = &StatusError{
		ErrorField:         "request_denied",
		TopLevelField:      StatusRequester,
		SecondLevelField:   StatusRequestDenied,
		StatusMessageField: "the request was denied",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrRequestNotCurrent is a request that is older than it may be, or that was issued in the future, with
	// MaxClockSkew allowed for.
	ErrRequestNotCurrent = &StatusError{
		ErrorField:         "request_not_current",
		TopLevelField:      StatusRequester,
		SecondLevelField:   StatusRequestDenied,
		StatusMessageField: "the request has expired or is not yet valid",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrDestinationMismatch is a request whose Destination is not the endpoint that it was received at.
	ErrDestinationMismatch = &StatusError{
		ErrorField:         "destination_mismatch",
		TopLevelField:      StatusRequester,
		SecondLevelField:   StatusRequestDenied,
		StatusMessageField: "the request was sent to another destination than it names",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrReplayed is returned by ReplayStore.Consume when the key has already been consumed and has not yet
	// expired, and is the error of a request that is refused for that reason (SAMLSec §6.1.2).
	ErrReplayed = &StatusError{
		ErrorField:         "replayed",
		TopLevelField:      StatusRequester,
		SecondLevelField:   StatusRequestDenied,
		StatusMessageField: "the message has already been used",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrRequestUnsupported is a request that asks for something which this package does not support, such as
	// a principal identified with a BaseID, or which is not the message that the endpoint serves.
	ErrRequestUnsupported = &StatusError{
		ErrorField:         "request_unsupported",
		TopLevelField:      StatusRequester,
		SecondLevelField:   StatusRequestUnsupported,
		StatusMessageField: "the request is not supported",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrVersionMismatch is a request whose version is not 2.0, and is not a later or an earlier major version
	// either, which are ErrRequestVersionTooHigh and ErrRequestVersionTooLow.
	ErrVersionMismatch = &StatusError{
		ErrorField:         "version_mismatch",
		TopLevelField:      StatusVersionMismatch,
		StatusMessageField: "the version of the request is not supported",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrRequestVersionTooHigh is a request of a later major version than 2.
	ErrRequestVersionTooHigh = &StatusError{
		ErrorField:         "request_version_too_high",
		TopLevelField:      StatusVersionMismatch,
		SecondLevelField:   StatusRequestVersionTooHigh,
		StatusMessageField: "the version of the request is too high",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrRequestVersionTooLow is a request of an earlier major version than 2.
	ErrRequestVersionTooLow = &StatusError{
		ErrorField:         "request_version_too_low",
		TopLevelField:      StatusVersionMismatch,
		SecondLevelField:   StatusRequestVersionTooLow,
		StatusMessageField: "the version of the request is too low",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrUnsupportedBinding is an AuthnRequest whose ProtocolBinding is not one that the identity provider can
	// send the response with.
	ErrUnsupportedBinding = &StatusError{
		ErrorField:         "unsupported_binding",
		TopLevelField:      StatusResponder,
		SecondLevelField:   StatusUnsupportedBinding,
		StatusMessageField: "the response cannot be sent with the requested binding",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrInvalidNameIDPolicy is returned when the NameIDPolicy of a request cannot be satisfied.
	ErrInvalidNameIDPolicy = &StatusError{
		ErrorField:         "invalid_name_id_policy",
		TopLevelField:      StatusRequester,
		SecondLevelField:   StatusInvalidNameIDPolicy,
		StatusMessageField: "the NameIDPolicy cannot be satisfied",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrUnknownPrincipal is returned by a NameIDManagementProvider or a NameIDMappingProvider which doesn't
	// recognize the principal that a request names, and is the error of every request whose principal is not
	// one that the requester shares with the identity provider.
	ErrUnknownPrincipal = &StatusError{
		ErrorField:         "unknown_principal",
		TopLevelField:      StatusRequester,
		SecondLevelField:   StatusUnknownPrincipal,
		StatusMessageField: "the principal is unknown",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrInvalidAttribute is an AttributeQuery which lists an attribute with no Name, or the same one twice.
	ErrInvalidAttribute = &StatusError{
		ErrorField:         "invalid_attribute",
		TopLevelField:      StatusRequester,
		SecondLevelField:   StatusInvalidAttrNameOrValue,
		StatusMessageField: "the request names an attribute that is not valid",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrTooManyResponses is a request for more than the identity provider returns in one response.
	ErrTooManyResponses = &StatusError{
		ErrorField:         "too_many_responses",
		TopLevelField:      StatusResponder,
		SecondLevelField:   StatusTooManyResponses,
		StatusMessageField: "the request asks for more than one response can hold",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrAuthnFailed is a request for which the principal could not be authenticated as it asks: with
	// ForceAuthn when the SessionProvider can't, or as the Subject that it names.
	ErrAuthnFailed = &StatusError{
		ErrorField:         "authn_failed",
		TopLevelField:      StatusResponder,
		SecondLevelField:   StatusAuthnFailed,
		StatusMessageField: "the principal could not be authenticated",
		HTTPStatusField:    http.StatusForbidden,
	}

	// ErrNoPassive is a request with IsPassive for a principal that can't be authenticated passively.
	ErrNoPassive = &StatusError{
		ErrorField:         "no_passive",
		TopLevelField:      StatusResponder,
		SecondLevelField:   StatusNoPassive,
		StatusMessageField: "the principal cannot be authenticated passively",
		HTTPStatusField:    http.StatusForbidden,
	}

	// ErrNoAuthnContext is a request whose RequestedAuthnContext the authentication of the session does not
	// satisfy.
	ErrNoAuthnContext = &StatusError{
		ErrorField:         "no_authn_context",
		TopLevelField:      StatusResponder,
		SecondLevelField:   StatusNoAuthnContext,
		StatusMessageField: "the requested authentication context cannot be satisfied",
		HTTPStatusField:    http.StatusForbidden,
	}

	// ErrNoAvailableIDP is for an identity provider that proxies, when none of the identity providers that the
	// Scoping of the request lists is available.
	ErrNoAvailableIDP = &StatusError{
		ErrorField:         "no_available_idp",
		TopLevelField:      StatusResponder,
		SecondLevelField:   StatusNoAvailableIDP,
		StatusMessageField: "none of the identity providers that the request lists is available",
		HTTPStatusField:    http.StatusForbidden,
	}

	// ErrNoSupportedIDP is for an identity provider that proxies, when it supports none of the identity
	// providers that the Scoping of the request lists.
	ErrNoSupportedIDP = &StatusError{
		ErrorField:         "no_supported_idp",
		TopLevelField:      StatusResponder,
		SecondLevelField:   StatusNoSupportedIDP,
		StatusMessageField: "none of the identity providers that the request lists is supported",
		HTTPStatusField:    http.StatusForbidden,
	}

	// ErrProxyCountExceeded is for an identity provider that proxies, when the ProxyCount of the request does
	// not allow it to.
	ErrProxyCountExceeded = &StatusError{
		ErrorField:         "proxy_count_exceeded",
		TopLevelField:      StatusResponder,
		SecondLevelField:   StatusProxyCountExceeded,
		StatusMessageField: "the request does not allow the authentication to be proxied",
		HTTPStatusField:    http.StatusForbidden,
	}

	// ErrRequiredAttributeUnavailable is returned by DefaultAssertionMaker when the service provider requires an
	// attribute, or a subject identifier, that can't be released to it.
	ErrRequiredAttributeUnavailable = &StatusError{
		ErrorField:         "required_attribute_unavailable",
		TopLevelField:      StatusResponder,
		StatusMessageField: "an attribute that the service provider requires cannot be released",
		HTTPStatusField:    http.StatusForbidden,
	}

	// ErrLogoutNotFound is a LogoutResponse for a logout that is unknown, has expired, or has no request
	// outstanding.
	ErrLogoutNotFound = &StatusError{
		ErrorField:         "logout_not_found",
		TopLevelField:      StatusRequester,
		SecondLevelField:   StatusRequestDenied,
		StatusMessageField: "the logout that the response is for is not in progress",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrLogoutResponseUncorrelated is returned by IdpLogoutResponse.Validate for a response that is not the
	// answer to the outstanding request of the logout: one with another InResponseTo, or from another issuer.
	ErrLogoutResponseUncorrelated = &StatusError{
		ErrorField:         "logout_response_uncorrelated",
		TopLevelField:      StatusRequester,
		SecondLevelField:   StatusRequestDenied,
		StatusMessageField: "the response is not to the outstanding logout request",
		HTTPStatusField:    http.StatusBadRequest,
	}

	// ErrInvalidResponse is a response of another party that could not be accepted, such as the LogoutResponse
	// of a session participant whose signature is not valid.
	ErrInvalidResponse = &StatusError{
		ErrorField:         "invalid_response",
		TopLevelField:      StatusResponder,
		StatusMessageField: "the response of the other party is not valid",
		HTTPStatusField:    http.StatusBadGateway,
	}

	// ErrReceivedStatus is the error that StatusErrorFromStatus returns for the status of another party.
	ErrReceivedStatus = &StatusError{
		ErrorField:         "received_status",
		TopLevelField:      StatusResponder,
		StatusMessageField: "the other party answered with a status that is not success",
		HTTPStatusField:    http.StatusBadGateway,
	}
)

// NewStatusError returns a StatusError with the given name, status codes, StatusMessage and HTTP status, or an
// error if they are not valid, as Validate describes. The secondLevel and the statusMessage may be empty.
func NewStatusError(name, topLevel, secondLevel, statusMessage string, httpStatus int) (*StatusError, error) {
	e := &StatusError{
		ErrorField:         name,
		TopLevelField:      topLevel,
		SecondLevelField:   secondLevel,
		StatusMessageField: statusMessage,
		HTTPStatusField:    httpStatus,
	}

	if err := e.Validate(); err != nil {
		return nil, err
	}

	return e, nil
}

// ToStatusError returns the StatusError in the chain of err. If there is none, it returns a copy of
// ErrServerError, which is Responder with an HTTP status of 500, with err as its cause and the text of err as
// its debug message. It returns nil for nil.
//
// If the StatusError was wrapped in an error that adds to its text and has no debug message of its own, the
// text of err becomes the debug message, so that what the wrapping says of the failure is not lost.
func ToStatusError(err error) *StatusError {
	if err == nil {
		return nil
	}

	var e *StatusError

	if !errors.As(err, &e) {
		return ErrServerError.WithWrap(err).WithDebug(err.Error())
	}

	//nolint:errorlint // Whether err is the StatusError itself, and not an error which wraps it, is the question.
	if outer, ok := err.(*StatusError); (!ok || outer != e) && e.DebugField == "" {
		return e.WithDebug(err.Error())
	}

	return e
}

// StatusErrorFromStatus returns the error for a status that another party answered with, which is for one that
// is not a success. It matches ErrReceivedStatus, and its TopLevelField and SecondLevelField are the status
// codes of the other party.
//
// Everything in a status that is received is chosen by the party that sent it. The StatusMessage and the
// StatusDetail are therefore not copied to StatusMessageField and StatusDetailField, which hold text of the
// application: they are in the debug message, with the status codes. The codes themselves are not checked, and
// may be any text.
func StatusErrorFromStatus(status Status) *StatusError {
	e := *ErrReceivedStatus
	e.TopLevelField = status.StatusCode.Value
	e.SecondLevelField = ""

	if status.StatusCode.StatusCode != nil {
		e.SecondLevelField = status.StatusCode.StatusCode.Value
	}

	debug := []string{"status " + e.statusCodes()}

	if status.StatusMessage != nil && status.StatusMessage.Value != "" {
		debug = append(debug, "StatusMessage: "+truncateDebug(status.StatusMessage.Value))
	}

	if status.StatusDetail != nil && len(status.StatusDetail.Children) != 0 {
		doc := etree.NewDocument()
		doc.SetRoot(status.StatusDetail.Element().Copy())

		if detail, err := doc.WriteToString(); err == nil {
			debug = append(debug, "StatusDetail: "+truncateDebug(detail))
		}
	}

	e.DebugField = strings.Join(debug, "; ")

	return &e
}

// maxReceivedDebugLength is how much of the StatusMessage, and of the StatusDetail, of another party is kept.
const maxReceivedDebugLength = 1024

func truncateDebug(s string) string {
	if len(s) > maxReceivedDebugLength {
		return strings.ToValidUTF8(s[:maxReceivedDebugLength], "") + "..."
	}

	return s
}

// Error implements error. It is the name of the error and its StatusMessage, and never includes the debug
// message.
func (e *StatusError) Error() string {
	switch {
	case e.StatusMessageField == "":
		return e.ErrorField
	case e.ErrorField == "":
		return e.StatusMessageField
	default:
		return e.ErrorField + ": " + e.StatusMessageField
	}
}

// Unwrap returns the cause of the error, for [errors.Is] and [errors.As].
func (e *StatusError) Unwrap() error {
	return e.cause
}

// Cause returns the error that WithWrap recorded, or nil.
func (e *StatusError) Cause() error {
	return e.cause
}

// Is reports whether target is a StatusError with the same ErrorField, so that a copy of a package level error
// which a With method returned still matches it.
func (e *StatusError) Is(target error) bool {
	//nolint:errorlint // errors.Is has already unwrapped the chain down to this error.
	t, ok := target.(*StatusError)

	return ok && t != nil && e.ErrorField == t.ErrorField
}

// Debug returns the debug message. It is untrusted text, as StatusError describes.
func (e *StatusError) Debug() string {
	return e.DebugField
}

// HTTPStatus returns the status of the HTTP response for a failure that is not answered with a SAML response,
// which is 500 if HTTPStatusField is not the status of an error.
func (e *StatusError) HTTPStatus() int {
	if e.HTTPStatusField < 400 || e.HTTPStatusField > 599 {
		return http.StatusInternalServerError
	}

	return e.HTTPStatusField
}

// WithWrap returns a copy of the error with cause as its cause, which [errors.Is] and [errors.As] then find.
func (e *StatusError) WithWrap(cause error) *StatusError {
	c := *e
	c.cause = cause

	return &c
}

// WithDebug returns a copy of the error with the debug message. It is the place for anything that came from
// the other party.
func (e *StatusError) WithDebug(debug string) *StatusError {
	c := *e
	c.DebugField = debug

	return &c
}

// WithDebugf returns a copy of the error with the formatted debug message.
func (e *StatusError) WithDebugf(format string, args ...any) *StatusError {
	return e.WithDebug(fmt.Sprintf(format, args...))
}

// WithDebugError returns a copy of the error with the text of err as its debug message and err as its cause.
// It returns the error unchanged if err is nil.
func (e *StatusError) WithDebugError(err error) *StatusError {
	if err == nil {
		return e
	}

	c := *e
	c.cause, c.DebugField = err, err.Error()

	return &c
}

// WithStatusMessage returns a copy of the error with the text of its StatusMessage. The message is sent to the
// other party in a response that the identity provider signs, so it must be constant text: there is no variant
// that formats, and anything of the request belongs in WithDebugf.
func (e *StatusError) WithStatusMessage(message string) *StatusError {
	c := *e
	c.StatusMessageField = message

	return &c
}

// WithStatusDetail returns a copy of the error with copies of the elements added to the children of its
// StatusDetail. The elements are not shared: changing one afterwards changes nothing.
//
// A child must be in a namespace, which it and its descendants declare themselves, as it is placed in a
// document which declares other prefixes and is then signed. One that is not is left out when the status is
// encoded, which is reported to the Observer, and Validate returns an error for it. Like the StatusMessage, a
// child must not hold anything of the request.
func (e *StatusError) WithStatusDetail(children ...*etree.Element) *StatusError {
	c := *e
	c.StatusDetailField = make([]*etree.Element, 0, len(e.StatusDetailField)+len(children))

	for _, child := range e.StatusDetailField {
		if child != nil {
			c.StatusDetailField = append(c.StatusDetailField, child.Copy())
		}
	}

	for _, child := range children {
		if child != nil {
			c.StatusDetailField = append(c.StatusDetailField, child.Copy())
		}
	}

	return &c
}

// WithSecondLevel returns a copy of the error with the second-level status code, which is one of the codes of
// SAMLCore §3.2.2.2 or an absolute URI of the application. Empty removes it.
func (e *StatusError) WithSecondLevel(secondLevel string) *StatusError {
	c := *e
	c.SecondLevelField = secondLevel

	return &c
}

// WithHTTPStatus returns a copy of the error with the status of the HTTP response for when the failure is not
// answered with a SAML response.
func (e *StatusError) WithHTTPStatus(status int) *StatusError {
	c := *e
	c.HTTPStatusField = status

	return &c
}

// Validate returns an error unless the error can be encoded as it is: the ErrorField is set, the TopLevelField
// is StatusRequester, StatusResponder or StatusVersionMismatch (SAMLCore §3.2.2.2), the SecondLevelField is
// empty or an absolute URI, the HTTPStatusField is the status of an error, and every child of the StatusDetail
// is in a namespace that it declares itself. An error that is not valid is still encoded, as
// IdentityProvider.ErrorStatus describes.
func (e *StatusError) Validate() error {
	if e.ErrorField == "" {
		return errors.New("the status error has no name")
	}

	if !isErrorTopLevelStatus(e.TopLevelField) {
		return fmt.Errorf("invalid top-level status %q for an error", e.TopLevelField)
	}

	if e.SecondLevelField != "" && !isStatusCodeURI(e.SecondLevelField) {
		return fmt.Errorf("the second-level status %q is not an absolute URI", e.SecondLevelField)
	}

	if e.HTTPStatusField < 400 || e.HTTPStatusField > 599 {
		return fmt.Errorf("the HTTP status %d is not the status of an error", e.HTTPStatusField)
	}

	for _, child := range e.StatusDetailField {
		if err := checkStatusDetailChild(child); err != nil {
			return err
		}
	}

	return nil
}

// isErrorTopLevelStatus reports whether value is a top-level status code that an error may have.
func isErrorTopLevelStatus(value string) bool {
	return value == StatusRequester || value == StatusResponder || value == StatusVersionMismatch
}

// isStatusCodeURI reports whether value is an absolute URI with nothing in it that an anyURI can't hold.
func isStatusCodeURI(value string) bool {
	if strings.ContainsFunc(value, func(r rune) bool { return unicode.IsSpace(r) || !unicode.IsPrint(r) }) {
		return false
	}

	u, err := url.Parse(value)

	return err == nil && u.IsAbs()
}

// checkStatusDetailChild returns an error unless el and every element in it that has a prefix is in a
// namespace which is declared on el or within it, and el is in a namespace at all, and every attribute of
// them with a prefix other than xmlns and xml has one that is declared on el or within it.
func checkStatusDetailChild(el *etree.Element) error {
	if el == nil {
		return errors.New("the StatusDetail has a nil child")
	}

	// A copy has no parent, so a namespace that it resolves is one that it declares.
	detached := el.Copy()

	if detached.NamespaceURI() == "" {
		return fmt.Errorf("the StatusDetail child %s is not in a namespace that it declares", el.FullTag())
	}

	for _, descendant := range detached.FindElements(".//*") {
		if descendant.Space != "" && descendant.NamespaceURI() == "" {
			return fmt.Errorf("the element %s in the StatusDetail child %s has a prefix that is not declared within it",
				descendant.FullTag(), el.FullTag())
		}
	}

	for _, e := range append([]*etree.Element{detached}, detached.FindElements(".//*")...) {
		for _, attr := range e.Attr {
			if attr.Space == "" || attr.Space == "xmlns" || attr.Space == "xml" {
				continue
			}

			if declaredNamespace(e, attr.Space) == "" {
				return fmt.Errorf("the attribute %s in the StatusDetail child %s has a prefix that is not declared within it",
					attr.FullKey(), el.FullTag())
			}
		}
	}

	return nil
}

// declaredNamespace returns the namespace that prefix is declared for on el or an ancestor of it, or "". It is
// not Attr.NamespaceURI, which resolves the prefix from the element that an attribute was copied from.
func declaredNamespace(el *etree.Element, prefix string) string {
	for e := el; e != nil; e = e.Parent() {
		for _, attr := range e.Attr {
			if attr.Space == "xmlns" && attr.Key == prefix {
				return attr.Value
			}
		}
	}

	return ""
}

// StatusDetailDebugNamespace is the namespace of the Debug element, which holds the debug message of an error
// in the StatusDetail of a response when IdentityProvider.ExposeDebug is set.
const StatusDetailDebugNamespace = "urn:authelia:saml:2.0:status-detail"

// newDebugStatusDetail returns the Debug element for the debug message.
func newDebugStatusDetail(debug string) *etree.Element {
	el := etree.NewElement("Debug")
	el.CreateAttr("xmlns", StatusDetailDebugNamespace)
	el.SetText(xmlText(debug))

	return el
}

// xmlText returns s with every character that an XML 1.0 document can't hold replaced by U+FFFD.
func xmlText(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t', r == '\n', r == '\r':
			return r
		case r < 0x20, r == 0xFFFE, r == 0xFFFF:
			return unicode.ReplacementChar
		default:
			return r
		}
	}, strings.ToValidUTF8(s, string(unicode.ReplacementChar)))
}

// status returns the Status for the error. The codes are always those of the error, or Responder alone if its
// top-level code is not one that an error may have, and a second-level code that is not an absolute URI is left
// out. The StatusMessage, the StatusDetail and, if exposeDebug, the debug message are only included if full.
// It also returns an error for each child of the StatusDetail that was left out.
func (e *StatusError) status(full, exposeDebug bool) (Status, []error) {
	status := Status{StatusCode: StatusCode{Value: e.TopLevelField}}

	if !isErrorTopLevelStatus(e.TopLevelField) {
		status.StatusCode.Value = StatusResponder
	} else if isStatusCodeURI(e.SecondLevelField) {
		status.StatusCode.StatusCode = &StatusCode{Value: e.SecondLevelField}
	}

	if !full {
		return status, nil
	}

	if e.StatusMessageField != "" {
		status.StatusMessage = &StatusMessage{Value: e.StatusMessageField}
	}

	var (
		children []*etree.Element
		refused  []error
	)

	for _, child := range e.StatusDetailField {
		if err := checkStatusDetailChild(child); err != nil {
			refused = append(refused, err)

			continue
		}

		children = append(children, child.Copy())
	}

	if exposeDebug && e.DebugField != "" {
		children = append(children, newDebugStatusDetail(e.DebugField))
	}

	if len(children) != 0 {
		status.StatusDetail = &StatusDetail{Children: children}
	}

	return status, refused
}

// statusCodePrefix is the prefix of the status codes of SAMLCore, which the formatted error leaves out.
const statusCodePrefix = "urn:oasis:names:tc:SAML:2.0:status:"

// statusCodes returns the status codes of the error as they are printed: top level and second level, without
// the prefix of the codes of SAMLCore, and quoted if they hold anything but the characters of a URI, as the
// codes of a status that was received may.
func (e *StatusError) statusCodes() string {
	codes := logToken(strings.TrimPrefix(e.TopLevelField, statusCodePrefix))

	if e.SecondLevelField != "" {
		codes += "/" + logToken(strings.TrimPrefix(e.SecondLevelField, statusCodePrefix))
	}

	return codes
}

// logToken returns s as it is if it only has characters that are plain in a log line, and quoted otherwise.
func logToken(s string) string {
	plain := func(r rune) bool {
		return r < 0x80 && (unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(":/._-#?&%+~@", r))
	}

	if s == "" || strings.ContainsFunc(s, func(r rune) bool { return !plain(r) }) {
		return strconv.Quote(s)
	}

	return s
}

// Format implements [fmt.Formatter]. The verbs %v and %s print what Error returns: the name of the error and
// its StatusMessage. %+v prints one line with everything that is known of the failure: the status codes, the
// HTTP status, the debug message and the cause. The debug message and the cause are untrusted text, so they are
// quoted as [strconv.Quote] does, which escapes control characters, line breaks and escape sequences of a
// terminal, and they can't forge another log line. %q prints Error quoted.
func (e *StatusError) Format(f fmt.State, verb rune) {
	switch {
	case verb == 'q':
		_, _ = fmt.Fprint(f, strconv.Quote(e.Error()))
	case verb == 'v' && f.Flag('+'):
		_, _ = fmt.Fprint(f, e.detailed())
	default:
		_, _ = fmt.Fprint(f, e.Error())
	}
}

// detailed returns the %+v form of the error.
func (e *StatusError) detailed() string {
	var b strings.Builder

	b.WriteString(e.Error())
	b.WriteString(" status=" + e.statusCodes())
	b.WriteString(" http_status=" + strconv.Itoa(e.HTTPStatus()))

	if e.DebugField != "" {
		b.WriteString(" debug=" + strconv.Quote(e.DebugField))
	}

	if cause := e.causeText(); cause != "" {
		b.WriteString(" cause=" + cause)
	}

	return b.String()
}

// causeText returns the cause as it is printed: the StatusError in its chain in full, in braces, or else its
// text, quoted. It is empty if there is no cause or if the cause only repeats the debug message.
func (e *StatusError) causeText() string {
	if e.cause == nil {
		return ""
	}

	var inner *StatusError

	if errors.As(e.cause, &inner) {
		return "{" + inner.detailed() + "}"
	}

	if text := e.cause.Error(); text != e.DebugField {
		return strconv.Quote(text)
	}

	return ""
}

// LogValue implements [slog.LogValuer]. The value is a group with the keys error, top_level, second_level,
// status_message, http_status, debug and cause, of which those that have no value are left out. The values
// are not escaped, as a [slog.Handler] does that.
func (e *StatusError) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.String("error", e.ErrorField),
		slog.String("top_level", e.TopLevelField),
	}

	if e.SecondLevelField != "" {
		attrs = append(attrs, slog.String("second_level", e.SecondLevelField))
	}

	if e.StatusMessageField != "" {
		attrs = append(attrs, slog.String("status_message", e.StatusMessageField))
	}

	attrs = append(attrs, slog.Int("http_status", e.HTTPStatus()))

	if e.DebugField != "" {
		attrs = append(attrs, slog.String("debug", e.DebugField))
	}

	if e.cause != nil {
		attrs = append(attrs, slog.String("cause", e.cause.Error()))
	}

	return slog.GroupValue(attrs...)
}

// Fields returns what LogValue does as a map, with the same keys, for a logger that takes the fields of a record
// as one, such as logrus. The debug message and the cause are untrusted text, and are not escaped: the formatter
// of the logger must do that, as those of logrus do.
func (e *StatusError) Fields() map[string]any {
	fields := map[string]any{}

	for _, attr := range e.LogValue().Group() {
		fields[attr.Key] = attr.Value.Any()
	}

	return fields
}

// versionError returns nil if version is 2.0, and otherwise the error for a request with that version.
// SAMLCore §3.2.2.2 defines RequestVersionTooHigh and RequestVersionTooLow for a major version other than
// 2. Any other version has no second level status.
func versionError(version string) error {
	if version == "2.0" {
		return nil
	}

	debug := fmt.Sprintf("expected SAML request version 2.0 got %v", version)

	majorString, minorString, found := strings.Cut(version, ".")
	if !found {
		return ErrVersionMismatch.WithDebug(debug)
	}

	major, err := strconv.Atoi(majorString)
	if err != nil {
		return ErrVersionMismatch.WithDebug(debug)
	}

	if _, err = strconv.Atoi(minorString); err != nil {
		return ErrVersionMismatch.WithDebug(debug)
	}

	switch {
	case major > 2:
		return ErrRequestVersionTooHigh.WithDebug(debug)
	case major < 2:
		return ErrRequestVersionTooLow.WithDebug(debug)
	default:
		return ErrVersionMismatch.WithDebug(debug)
	}
}

// statusErrorOr returns the StatusError in the chain of err, as ToStatusError does, or if there is none a copy
// of fallback with err as its cause and its text as the debug message.
func statusErrorOr(err error, fallback *StatusError) *StatusError {
	var e *StatusError

	if errors.As(err, &e) {
		return ToStatusError(err)
	}

	return fallback.WithDebugError(err)
}
