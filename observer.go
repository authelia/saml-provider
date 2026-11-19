package saml

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Observer is told of everything that this package does for a request and would otherwise have logged. It is
// the audit trail of an identity provider, as it receives one Event for each operation that completes, whether
// it succeeds or fails, and it receives the warnings: what went wrong without failing the operation.
//
// Observe is called on the goroutine that serves the request, before the handler returns, so it must not
// block for long. It may be called concurrently.
type Observer interface {
	// Observe receives the event. The ctx is that of the HTTP request which the event belongs to, so that it
	// can be related to what the application knows of the request. It is the background context for an event
	// that belongs to no request, such as a refresh of metadata.
	Observe(ctx context.Context, event Event)
}

// ObserverFunc is a function that is an Observer.
type ObserverFunc func(ctx context.Context, event Event)

// Observe implements Observer.
func (f ObserverFunc) Observe(ctx context.Context, event Event) {
	f(ctx, event)
}

// EventKind is what an Event is about: an operation of a profile, or something that went wrong within one.
type EventKind string

// The operations. An identity provider reports one event of these kinds for each request that it has finished
// with: OutcomeSuccess when it was answered as asked, OutcomeFailure with the error otherwise, and
// OutcomeWarning when it was answered with less than was asked, as a partial logout is. A request that is
// handed to the SessionProvider, such as to show a login form, is not finished and reports nothing.
const (
	// EventSSO is an AuthnRequest at ServeSSO.
	EventSSO EventKind = "sso"

	// EventIDPInitiatedSSO is a response without a request, from ServeIDPInitiated.
	EventIDPInitiatedSSO EventKind = "idp_initiated_sso"

	// EventECP is an AuthnRequest at ServeECP.
	EventECP EventKind = "ecp"

	// EventLogout is a LogoutRequest of a service provider, at ServeSLO or ServeSOAPLogout, and a logout that
	// the identity provider started with StartLogout, once it has ended.
	EventLogout EventKind = "logout"

	// EventLogoutPropagation is the logout of one session participant during a logout: its LogoutResponse at
	// ServeSLO, or the exchange with it over SOAP. The ServiceProvider is the participant.
	EventLogoutPropagation EventKind = "logout_propagation"

	// EventArtifactResolve is an ArtifactResolve at ServeArtifactResolution. An artifact that is not resolved is
	// answered with success and no message, and is reported as OutcomeWarning with the reason.
	EventArtifactResolve EventKind = "artifact_resolve"

	// EventAttributeQuery is an AttributeQuery at ServeAttributeQuery.
	EventAttributeQuery EventKind = "attribute_query"

	// EventAuthnQuery is an AuthnQuery at ServeAuthnQuery.
	EventAuthnQuery EventKind = "authn_query"

	// EventAssertionIDRequest is an AssertionIDRequest at ServeAssertionIDRequest.
	EventAssertionIDRequest EventKind = "assertion_id_request"

	// EventAssertionURI is a request for an assertion by its ID at ServeAssertionURI, on the SAML URI binding.
	EventAssertionURI EventKind = "assertion_uri"

	// EventNameIDManagement is a ManageNameIDRequest at ServeManageNameID or ServeSOAPManageNameID.
	EventNameIDManagement EventKind = "name_id_management"

	// EventNameIDMapping is a NameIDMappingRequest at ServeNameIDMapping.
	EventNameIDMapping EventKind = "name_id_mapping"

	// EventMetadata is a request for the metadata of the identity provider at ServeMetadata, which is only
	// reported when it fails.
	EventMetadata EventKind = "metadata"

	// EventMetadataRefresh is a refresh of a source of a ServiceProviderMetadataResolver, which is only reported
	// when it fails.
	EventMetadataRefresh EventKind = "metadata_refresh"
)

// The things that go wrong within an operation without failing it. They are reported with OutcomeWarning.
const (
	// EventAlgorithmFallback is a signature or an encryption for which no algorithm was negotiated with the
	// service provider, so that a default was used.
	EventAlgorithmFallback EventKind = "algorithm_fallback"

	// EventSessionTermination is a session that the SessionProvider could not end during a logout.
	EventSessionTermination EventKind = "session_termination"

	// EventAttributeRelease is an attribute, or a subject identifier, that was left out of an assertion.
	EventAttributeRelease EventKind = "attribute_release"

	// EventPrincipalUnidentified is a request whose principal could not be identified, such as one with an
	// EncryptedID that can't be decrypted, which is answered like one that names nobody.
	EventPrincipalUnidentified EventKind = "principal_unidentified"

	// EventStore is a failure to save or delete something that the operation could do without: a stored
	// artifact or assertion, the state of a logout, or what a provider knows of a NameID.
	EventStore EventKind = "store"

	// EventMetadataExpired is a service provider whose metadata the ServiceProviderProvider returned although
	// it has expired, which is then unknown.
	EventMetadataExpired EventKind = "metadata_expired"

	// EventStatusDetail is a child of the StatusDetail of an error that was left out of the response, as
	// StatusError.WithStatusDetail describes.
	EventStatusDetail EventKind = "status_detail"
)

// Outcome is how what an Event reports ended.
type Outcome string

const (
	// OutcomeSuccess is an operation that did what was asked.
	OutcomeSuccess Outcome = "success"

	// OutcomeWarning is an operation that did less than was asked, or something that went wrong without
	// failing an operation.
	OutcomeWarning Outcome = "warning"

	// OutcomeFailure is an operation that failed.
	OutcomeFailure Outcome = "failure"
)

// Event is what an Observer is told.
type Event struct {
	// Kind is what the event is about.
	Kind EventKind

	// Outcome is how it ended.
	Outcome Outcome

	// Err is the reason for an OutcomeFailure or an OutcomeWarning, and nil for an OutcomeSuccess.
	Err *StatusError

	// ServiceProvider is the entity ID of the service provider that the event concerns, if any is known. Unless
	// Verified, it is the Issuer of a message that was not authenticated, which is untrusted text.
	ServiceProvider string

	// Verified is whether the message that the event is about was authenticated as one of ServiceProvider: its
	// signature was verified with a key in the metadata of that service provider. It is also true when the
	// identity provider itself chose the service provider, as for ServeIDPInitiated and for a session
	// participant of a logout. It is false for an AuthnRequest that is not signed, even once the service
	// provider is found and the response goes to an endpoint of its metadata, as anybody can send one.
	Verified bool

	// RequestID is the ID of the message that the event is about, when it is one that may be used as an
	// InResponseTo, and is otherwise empty. For a logout that the identity provider started, it is the ID of
	// the logout.
	RequestID string

	// Time is when the event happened.
	Time time.Time
}

// String returns the event on one line, as %+v prints it.
func (e Event) String() string {
	s := string(e.Kind) + " " + string(e.Outcome)

	if e.ServiceProvider != "" {
		s += " service_provider=" + logToken(e.ServiceProvider) + " verified=" + strconv.FormatBool(e.Verified)
	}

	if e.RequestID != "" {
		s += " request_id=" + logToken(e.RequestID)
	}

	if e.Err != nil {
		s += " error=" + fmt.Sprintf("%+v", e.Err)
	}

	return s
}

// LogValue implements [slog.LogValuer]. The value is a group with the keys kind, outcome, service_provider,
// verified, request_id and error, of which service_provider, verified, request_id and error are left out when
// they have no value. The error is the group that StatusError.LogValue returns.
func (e Event) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.String("kind", string(e.Kind)),
		slog.String("outcome", string(e.Outcome)),
	}

	if e.ServiceProvider != "" {
		attrs = append(attrs, slog.String("service_provider", e.ServiceProvider), slog.Bool("verified", e.Verified))
	}

	if e.RequestID != "" {
		attrs = append(attrs, slog.String("request_id", e.RequestID))
	}

	if e.Err != nil {
		attrs = append(attrs, slog.Any("error", e.Err))
	}

	return slog.GroupValue(attrs...)
}

// Fields returns what LogValue does as a map, with the same keys, for a logger that takes the fields of a record
// as one, such as logrus. The error is the map that StatusError.Fields returns. The service provider and what the
// error holds of the request are untrusted text, and are not escaped: the formatter of the logger must do that.
func (e Event) Fields() map[string]any {
	fields := map[string]any{
		"kind":    string(e.Kind),
		"outcome": string(e.Outcome),
	}

	if e.ServiceProvider != "" {
		fields["service_provider"], fields["verified"] = e.ServiceProvider, e.Verified
	}

	if e.RequestID != "" {
		fields["request_id"] = e.RequestID
	}

	if e.Err != nil {
		fields["error"] = e.Err.Fields()
	}

	return fields
}

// slogObserver is the Observer that is used when none is set. It logs each event with [slog.Default]: a
// success at the level of information, a warning as a warning, and a failure as a warning if it is the fault
// of the other party and as an error if it is the fault of this one.
type slogObserver struct{}

// Observe implements Observer.
func (slogObserver) Observe(ctx context.Context, event Event) {
	level := slog.LevelInfo

	switch {
	case event.Outcome == OutcomeFailure && event.Err != nil && event.Err.HTTPStatus() >= http.StatusInternalServerError:
		level = slog.LevelError
	case event.Outcome != OutcomeSuccess:
		level = slog.LevelWarn
	}

	slog.Default().LogAttrs(ctx, level, "saml "+string(event.Kind)+" "+string(event.Outcome), slog.Any("saml", event))
}

// observe gives event to observer, or to the default one if it is nil, with the time if it has none.
func observe(ctx context.Context, observer Observer, event Event) {
	if observer == nil {
		observer = slogObserver{}
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if event.Time.IsZero() {
		event.Time = TimeNow()
	}

	observer.Observe(ctx, event)
}

// RecordingObserver is an Observer that keeps the events it is given, for tests. The zero value is ready to
// use, and it is safe for concurrent use.
type RecordingObserver struct {
	mu     sync.Mutex
	events []Event
}

// Observe implements Observer.
func (o *RecordingObserver) Observe(_ context.Context, event Event) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.events = append(o.events, event)
}

// Events returns a copy of the events that were observed, in order.
func (o *RecordingObserver) Events() []Event {
	o.mu.Lock()
	defer o.mu.Unlock()

	return append([]Event(nil), o.events...)
}

// Reset forgets the events that were observed.
func (o *RecordingObserver) Reset() {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.events = nil
}

// requestState is what is established of a request when it is answered or fails. It decides how a failure is
// reported, and says who an Event is about.
type requestState struct {
	// serviceProvider is the entity ID of the requester: that of its metadata once it is established, and until
	// then the Issuer of the message.
	serviceProvider string

	// verified is whether the requester is established, as Event.Verified describes.
	verified bool

	// requestID is the ID of the request if it can be used as an InResponseTo, and otherwise empty.
	requestID string

	// respondable is whether a failure may be reported with everything the error has to say: on the front
	// channel and for the Enhanced Client or Proxy profile, that the endpoint for the response was chosen from
	// the metadata of the service provider, without which no SAML response is sent at all; on the SOAP
	// binding, where the response goes back on the connection of the request, that the requester was
	// authenticated, without which the response has the status codes of the error and nothing else.
	respondable bool
}

// event returns the event of the kind for a request in this state: a success if err is nil, and otherwise a
// failure with err.
func (s requestState) event(kind EventKind, err error) Event {
	event := Event{
		Kind:            kind,
		Outcome:         OutcomeSuccess,
		ServiceProvider: s.serviceProvider,
		Verified:        s.verified,
		RequestID:       s.requestID,
	}

	if err != nil {
		event.Outcome, event.Err = OutcomeFailure, ToStatusError(err)
	}

	return event
}

// warning returns the event of the kind for something that went wrong for a request in this state without
// failing it.
func (s requestState) warning(kind EventKind, err error) Event {
	event := s.event(kind, err)
	event.Outcome = OutcomeWarning

	return event
}

// observe gives event to the Observer of the identity provider.
func (idp *IdentityProvider) observe(r *http.Request, event Event) {
	observe(requestContext(r), idp.Observer, event)
}

// ErrorStatus returns the Status that reports err to a party that is established, for an application that
// answers a request with its own handler: the status codes, the StatusMessage and the StatusDetail of the
// StatusError that ToStatusError finds in err or makes of it, and its debug message if ExposeDebug is set. It
// must not be used for a request whose requester is not established, as IdpAuthnRequest.Respondable describes.
//
// An error that Validate would refuse is still encoded: a top-level code that an error may not have becomes
// Responder, a second-level code that is not an absolute URI is left out, and so is a child of the
// StatusDetail that is not in a namespace of its own, which the Observer is told of.
func (idp *IdentityProvider) ErrorStatus(err error) Status {
	return idp.status(nil, err, requestState{respondable: true})
}

// status is the one place where an error becomes the Status of a response, for every profile. A request that
// is not respondable only gets the status codes, as requestState describes.
func (idp *IdentityProvider) status(r *http.Request, err error, state requestState) Status {
	status, refused := ToStatusError(err).status(state.respondable, idp.ExposeDebug)

	for _, reason := range refused {
		idp.observe(r, state.warning(EventStatusDetail, ErrServerError.WithDebugError(reason)))
	}

	return status
}

// writeHTTPError answers a request that failed and can't be answered with a SAML response, with the
// HTTPErrorHandler or else with the HTTP status of the error and its text.
func (idp *IdentityProvider) writeHTTPError(w http.ResponseWriter, r *http.Request, err error) {
	e := ToStatusError(err)

	if idp.HTTPErrorHandler != nil {
		idp.HTTPErrorHandler(w, r, e)

		return
	}

	http.Error(w, http.StatusText(e.HTTPStatus()), e.HTTPStatus())
}
