package saml

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

// SessionParticipant is a service provider that received an assertion for a session (SAMLProfiles §4.4.2).
type SessionParticipant struct {
	ServiceProviderEntityID string
	NameID                  NameID
	SessionIndex            string
	IssueInstant            time.Time

	// NameIDEncrypted is whether the NameID was asserted as an EncryptedID. A LogoutRequest to the service
	// provider then identifies the principal with an EncryptedID too, so that the identifier which was kept
	// from intermediaries at login isn't shown to them at logout.
	NameIDEncrypted bool
}

// ErrSessionParticipantsClosed may be returned by SessionParticipantProvider.AddSessionParticipant for a session whose
// participants were closed by CloseSessionParticipants.
var ErrSessionParticipantsClosed = errors.New("the session is being logged out and takes no more participants")

// SessionParticipantProvider is an optional interface of a SessionProvider. With it the identity provider records
// every service provider that receives an assertion, so that a logout can reach them (SAMLProfiles §4.4.2). An
// IdpAuthnRequest built outside ServeSSO or ServeIDPInitiated must set Session, or MakeResponse returns an error, as
// the participant can't be recorded without it.
type SessionParticipantProvider interface {
	// AddSessionParticipant records participant for session. It is called each time a response with an assertion is
	// sent, before it is sent, and an error stops it being sent. Checking that the session's participants aren't
	// closed and recording the participant must be one atomic operation with respect to CloseSessionParticipants for
	// the session, such as a conditional insert, or under the same lock. Once CloseSessionParticipants has been called
	// for the session, or once the session has been ended, it must return an error, such as
	// ErrSessionParticipantsClosed. The same participant may be added more than once.
	AddSessionParticipant(r *http.Request, session *Session, participant SessionParticipant) error

	// CloseSessionParticipants is called when a logout of session begins. It returns the participants of the session
	// and stops AddSessionParticipant from recording any more, as one atomic operation with respect to
	// AddSessionParticipant for the session, so that a participant is either returned or refused. A session whose
	// participants are closed must no longer be returned by the SessionProvider, even if ending it fails, so that the
	// user authenticates again to a new session rather than being refused every assertion.
	CloseSessionParticipants(r *http.Request, session *Session) ([]SessionParticipant, error)

	// SessionParticipants returns the participants of session without closing them. It is used to find the NameID
	// that was asserted to a service provider, when an assertion is made and when a LogoutRequest is matched.
	SessionParticipants(r *http.Request, session *Session) ([]SessionParticipant, error)
}

// sessionParticipant returns the participant that the assertion of the request makes of its service provider, or
// nil if the SessionProvider of the identity provider isn't a SessionParticipantProvider.
func (req *IdpAuthnRequest) sessionParticipant() (*SessionParticipant, error) {
	if _, ok := req.IDP.SessionProvider.(SessionParticipantProvider); !ok {
		return nil, nil
	}

	if req.Session == nil {
		return nil, errors.New("cannot record the service provider of a session without a session")
	}

	if req.ServiceProviderMetadata == nil || req.Assertion == nil || req.Assertion.Subject == nil ||
		req.Assertion.Subject.NameID == nil || len(req.Assertion.AuthnStatements) == 0 {
		return nil, errors.New("cannot record the service provider of a session without a complete assertion")
	}

	return &SessionParticipant{
		ServiceProviderEntityID: req.ServiceProviderMetadata.EntityID,
		NameID:                  *req.Assertion.Subject.NameID,
		SessionIndex:            req.Assertion.AuthnStatements[0].SessionIndex,
		IssueInstant:            req.Now,
		NameIDEncrypted:         req.nameIDEncrypted,
	}, nil
}

// PublishResponse calls publish, which must send ResponseEl to the browser. If ResponseEl carries an assertion made
// by MakeResponse and the SessionProvider of the identity provider is a SessionParticipantProvider, the service
// provider is first recorded as a participant of the session, on every call. If the participant can't be recorded,
// such as because a logout of the session has begun, publish isn't called and an error is returned, so no assertion
// is sent once the participants of its session are closed.
//
// WriteResponse calls it. A caller which sends the response itself, such as one which renders the form PostBinding
// returns, must send it from publish, or a logout may miss the service provider.
func (req *IdpAuthnRequest) PublishResponse(publish func() error) error {
	if provider, ok := req.IDP.SessionProvider.(SessionParticipantProvider); ok && req.responseParticipant != nil {
		if err := provider.AddSessionParticipant(req.HTTPRequest, req.Session, *req.responseParticipant); err != nil {
			return fmt.Errorf("cannot record the service provider of a session: %w", err)
		}
	}

	return publish()
}
