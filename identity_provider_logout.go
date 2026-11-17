package saml

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"

	"authelia.com/provider/saml/internal/dsig"
)

// ErrPartialLogout is returned by LogoutSessionProvider.TerminateSession when the session at the
// identity provider has ended, but other session participants are known to remain logged in. The
// service provider receives a Success status with a PartialLogout second-level status.
var ErrPartialLogout = errors.New("other session participants were not logged out")

// LogoutSessionProvider is an optional interface of a SessionProvider, which is required to serve a
// LogoutRequest. Without it those requests receive a Responder status.
type LogoutSessionProvider interface {
	// GetLogoutSessions returns every session that req names, using req.MatchesSession(r, session). Without session
	// indexes in the request that is every session of the principal with that NameID (SAMLCore §3.7.3.2).
	// It must not rely on the session cookie alone, which a browser doesn't send with a cross-site POST, and r
	// may be a request from the service provider's server, as on the SOAP binding, with no browser cookies at
	// all. It returns an empty slice and no error when no session matches. The request has been verified to
	// come from the service provider in req.ServiceProviderMetadata.
	//
	// An error sends a Responder status, and is not sent to the service provider.
	GetLogoutSessions(r *http.Request, req *IdpLogoutRequest) ([]*Session, error)

	// TerminateSession ends the session at the identity provider. It may set headers on w, such as to
	// remove a cookie, but must not write the status or body, which are the LogoutResponse. On the SOAP
	// binding r may be a request from the service provider's server, with no browser cookies, and headers
	// set on w are discarded, so the session must be ended where it is stored. An error other than
	// ErrPartialLogout sends a Responder status, and is not sent to the service provider.
	TerminateSession(w http.ResponseWriter, r *http.Request, session *Session) error
}

// IdpLogoutRequest is used by IdentityProvider to handle a single logout request from a service
// provider.
type IdpLogoutRequest struct {
	IDP                     *IdentityProvider
	HTTPRequest             *http.Request
	RelayState              string
	RequestBuffer           []byte
	Request                 LogoutRequest
	ServiceProviderMetadata *EntityDescriptor
	SLOEndpoint             *Endpoint
	Now                     time.Time

	// RedirectQuery is the raw query string of a request on the HTTP-Redirect binding which is signed
	// in the query.
	RedirectQuery string

	// NameIDEncrypted is whether the request identified the principal with an EncryptedID (SAMLCore §3.7.1),
	// which Validate decrypted into Request.NameID.
	NameIDEncrypted bool

	// Unidentified is whether the request has an EncryptedID that Validate couldn't decrypt. Such a request is
	// valid and names no session: Request.NameID is then a random identifier that was never asserted, and
	// MatchesSession never matches. It is answered exactly as a request for a principal with no session is,
	// because an answer which tells the requester that decryption failed would let it use the identity provider
	// to learn about a ciphertext that it didn't make (errata E93). GetLogoutSessions is still called, so that
	// the time taken doesn't tell either, and whatever it returns is ignored.
	Unidentified bool

	// binding is the binding that the request was received on. On SOAP the response goes back on the same
	// connection, so SLOEndpoint is not assigned and the response has no Destination.
	binding string

	// verifiedEl is the element of the request that its signature covers, which the EncryptedID is taken from.
	verifiedEl *etree.Element
}

// MatchesSession returns an error unless the request is for the session. The NameID of the request must be
// the complete identifier the identity provider asserted for the session (SAMLCore §3.7.3.2, §8.3): the
// same value, Format, NameQualifier and SPNameQualifier, and the same SPProvidedID, which is none unless
// one was asserted and recorded in a SessionParticipant, or the service provider has since registered it with
// a ManageNameIDRequest: the alias that NameIDManagementProvider.SPProvidedID returns is then part of the
// identifier (SAMLCore §3.6.3, §8.3.7), so a request which carries it matches the sessions that were
// established before it was registered. An omitted or unspecified
// Format, or an omitted qualifier, doesn't match. This is compared with what DefaultAssertionMaker
// asserts, so an identity provider with a custom AssertionMaker that asserts another identifier needs
// IdentityProvider.LogoutNameIDValueOnly, which compares only the value, or its own check. If the request
// lists session indexes, the index of the session must be one of them. A NameID that the request
// held as an EncryptedID is compared in the same way, and a request which is Unidentified matches no session.
//
// Session.NameID is only compared when Session.NameIDFormat is set, because a session without a format
// has no NameID of its own that the identity provider asserts. The NameID asserted to a service provider
// can also differ from that of the session, such as a transient identifier or one that carries an
// affiliation. So if the SessionProvider is a SessionParticipantProvider, the request also matches when it
// carries the NameID that was asserted to the requesting service provider for the session, as recorded in
// its SessionParticipant: exactly, or only its value with LogoutNameIDValueOnly. An error loading the
// participants is returned.
func (req *IdpLogoutRequest) MatchesSession(r *http.Request, session *Session) error {
	if session == nil {
		return errors.New("there is no session")
	}

	if req.Unidentified {
		return errors.New("the EncryptedID of the request could not be decrypted")
	}

	nameID := req.Request.NameID
	if nameID == nil {
		return errors.New("the request has no NameID")
	}

	if err := req.matchesSessionNameID(r, session, nameID); err != nil {
		return err
	}

	if len(req.Request.SessionIndexes) != 0 && !slices.ContainsFunc(req.Request.SessionIndexes, func(i SessionIndex) bool { return i.Value == session.Index }) {
		return errors.New("the session index is not one the request lists")
	}

	return nil
}

// matchesSessionNameID returns an error unless nameID is that of the session or that asserted to the requesting
// service provider for it.
func (req *IdpLogoutRequest) matchesSessionNameID(r *http.Request, session *Session, nameID *NameID) error {
	err := errors.New("the session has no NameIDFormat, so only a NameID asserted to a session participant matches")
	if session.NameIDFormat != "" {
		err = req.matchesSessionNameIDValue(r, session, nameID)
	}

	if err == nil || req.ServiceProviderMetadata == nil {
		return err
	}

	provider, ok := req.IDP.SessionProvider.(SessionParticipantProvider)
	if !ok {
		return err
	}

	participants, perr := provider.SessionParticipants(r, session)
	if perr != nil {
		return fmt.Errorf("cannot load the participants of the session: %w", perr)
	}

	matches, perr := req.matchesParticipantNameID(r, participants, nameID)
	if perr != nil {
		return perr
	}

	if matches {
		return nil
	}

	return err
}

// matchesParticipantNameID reports whether nameID is the identifier that one of participants records for the
// requesting service provider: exactly, or only its value with LogoutNameIDValueOnly. The SPProvidedID may also
// be the one that the service provider has registered since the participant was recorded.
func (req *IdpLogoutRequest) matchesParticipantNameID(r *http.Request, participants []SessionParticipant, nameID *NameID) (bool, error) {
	for _, p := range participants {
		if p.ServiceProviderEntityID != req.ServiceProviderMetadata.EntityID || p.NameID.Value != nameID.Value {
			continue
		}

		if req.IDP.LogoutNameIDValueOnly {
			return true, nil
		}

		if p.NameID.Format != nameID.Format || p.NameID.NameQualifier != nameID.NameQualifier || p.NameID.SPNameQualifier != nameID.SPNameQualifier {
			continue
		}

		if p.NameID.SPProvidedID == nameID.SPProvidedID {
			return true, nil
		}

		// The participant was recorded with the identifier as it was asserted, and the service provider may
		// have registered another SPProvidedID since.
		if registered, err := req.registeredSPProvidedID(r, nameID); err != nil || registered {
			return registered, err
		}
	}

	return false, nil
}

// registeredSPProvidedID reports whether the SPProvidedID of nameID, which is the identifier of the request, is
// the alias that the requesting service provider most recently registered for the principal with a
// ManageNameIDRequest (SAMLCore §3.6.3). An identifier without one is not asked about.
func (req *IdpLogoutRequest) registeredSPProvidedID(r *http.Request, nameID *NameID) (bool, error) {
	if nameID.SPProvidedID == "" || req.ServiceProviderMetadata == nil {
		return false, nil
	}

	alias, err := req.IDP.spProvidedID(r, req.ServiceProviderMetadata.EntityID, nameID)
	if err != nil {
		return false, fmt.Errorf("cannot find the SPProvidedID of the NameID: %w", err)
	}

	return alias != "" && alias == nameID.SPProvidedID, nil
}

// matchesSessionNameIDValue compares nameID with the NameID of the session, whose NameIDFormat is set.
func (req *IdpLogoutRequest) matchesSessionNameIDValue(r *http.Request, session *Session, nameID *NameID) error {
	if nameID.Value != session.NameID {
		return errors.New("the NameID value is not that of the session")
	}

	if !req.IDP.LogoutNameIDValueOnly {
		if req.ServiceProviderMetadata == nil {
			return errors.New("the request has no service provider metadata")
		}

		// An omitted Format is unspecified (SAMLCore §2.2.2), which is not the format that was asserted, and the
		// qualifiers may only be omitted where they can be derived from the message, which they can't be in a
		// request the service provider sends to the identity provider (SAMLCore §8.3.7).
		if nameID.Format != session.NameIDFormat {
			return fmt.Errorf("the NameID format is %q and the session has %q", nameID.Format, session.NameIDFormat)
		}

		// A NameID of the entity format is asserted without qualifiers (SAMLCore §8.3.6).
		nameQualifier, spNameQualifier := req.IDP.Metadata().EntityID, req.ServiceProviderMetadata.EntityID
		if !nameIDFormatHasQualifiers(nameID.Format) {
			nameQualifier, spNameQualifier = "", ""
		}

		if nameID.NameQualifier != nameQualifier {
			return fmt.Errorf("the NameID NameQualifier %q is not that of the identity provider", nameID.NameQualifier)
		}

		if nameID.SPNameQualifier != spNameQualifier {
			return fmt.Errorf("the NameID SPNameQualifier %q is not that of the service provider", nameID.SPNameQualifier)
		}

		if nameID.SPProvidedID != "" {
			registered, err := req.registeredSPProvidedID(r, nameID)
			if err != nil {
				return err
			}

			if !registered {
				return errors.New("the NameID has a SPProvidedID, which is not one the service provider registered")
			}
		}
	}

	return nil
}

// ServeSLO handles a SAML LogoutRequest from a service provider, on the HTTP-Redirect or HTTP-POST
// binding, and responds with a signed LogoutResponse. The request must be signed, as SAMLProfiles
// §4.4.4.1 requires it to be authenticated. The session at the identity provider is ended by the
// SessionProvider, which must implement LogoutSessionProvider.
//
// If the SessionProvider also implements SessionParticipantProvider and LogoutStateProvider, the
// other session participants are sent a LogoutRequest in turn through the browser before the
// requester is answered (SAMLProfiles §4.4.3.2), and ServeSLO also handles their LogoutResponse. A
// LogoutResponse for a logout that can't be found or has expired gets a StatusBadRequest response.
//
// A request that is invalid, can't be verified, or comes from a service provider with no
// SingleLogoutService for a supported binding gets a StatusBadRequest response. A verified request
// from a service provider with such an endpoint that is expired, for another destination or of
// another version is answered there with an error status, and its session is not ended. Nor is it when
// the request is a replay of one that was already verified, on any binding, which is answered with
// Requester and RequestDenied, or when the ReplayStore fails, which is answered with Responder.
func (idp *IdentityProvider) ServeSLO(w http.ResponseWriter, r *http.Request) {
	isResponse, err := isLogoutResponse(r)
	if err != nil {
		idp.logger().Printf("failed to parse logout message: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

		return
	}

	if isResponse {
		idp.serveLogoutResponse(w, r)

		return
	}

	req, err := NewIdpLogoutRequest(idp, r)
	if err != nil {
		idp.logger().Printf("failed to parse logout request: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

		return
	}

	if err := req.Validate(); err != nil {
		idp.logger().Printf("failed to validate logout request: %s", err)

		if status, ok := RequestStatus(err); ok {
			idp.writeLogoutResponse(w, req, status)

			return
		}

		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

		return
	}

	status := Status{StatusCode: StatusCode{Value: StatusSuccess}}

	if provider, ok := idp.SessionProvider.(LogoutSessionProvider); !ok {
		idp.logger().Printf("cannot terminate session: the session provider does not implement LogoutSessionProvider")

		status.StatusCode.Value = StatusResponder
	} else if sessions, err := req.logoutSessions(r, provider); err != nil {
		idp.logger().Printf("cannot find sessions to terminate: %s", err)

		status.StatusCode.Value = StatusResponder
	} else if _, _, _, err := idp.logoutProviders(); err != nil || len(sessions) == 0 {
		// Without the interfaces of a propagated logout, or without a session to propagate, the sessions
		// are ended and the requester is answered at once.
		status = idp.terminateSessions(w, r, provider, sessions)
	} else if err := idp.beginLogout(w, r, sessions, req.ServiceProviderMetadata.EntityID, "", req.logoutOrigin()); err != nil {
		idp.logger().Printf("cannot begin logout: %s", err)

		// The sessions are still ended, but the other participants were not told, so a Success is partial.
		status = withPartialLogout(idp.terminateSessions(w, r, provider, sessions))
	} else {
		return
	}

	idp.writeLogoutResponse(w, req, status)
}

// logoutSessions returns the sessions that the request names, from provider. A request whose EncryptedID couldn't
// be decrypted names none: the provider is asked all the same, with the random NameID of the request, so that such
// a request takes as long as one which names nobody, and its answer is ignored.
func (req *IdpLogoutRequest) logoutSessions(r *http.Request, provider LogoutSessionProvider) ([]*Session, error) {
	sessions, err := provider.GetLogoutSessions(r, req)
	if req.Unidentified {
		return nil, nil
	}

	return sessions, err
}

// identifyPrincipal assigns Request.NameID from the EncryptedID of the request, if it has one in place of the
// NameID (SAMLCore §3.7.1). It must only run once the signature is verified, as the EncryptedID is taken from the
// content that the signature covers and decrypted with the key of the identity provider: SAMLCore §6.2 has the
// requester encrypt and then sign, and errata E93 has the receiver require integrity protection before it
// processes encrypted data. The EncryptedID must be encrypted with algorithms that the identity provider allows.
//
// It returns an error for a request with no identifier, or with both. A request whose EncryptedID can't be
// decrypted is not an error: it is marked Unidentified and given a random NameID, and the reason is only logged.
func (req *IdpLogoutRequest) identifyPrincipal() error {
	var (
		encryptedIDEl *etree.Element
		err           error
	)

	if req.verifiedEl != nil {
		if encryptedIDEl, err = findChild(req.verifiedEl, samlAssertionNamespace, "EncryptedID"); err != nil {
			return err
		}
	}

	if encryptedIDEl == nil {
		// BaseID is not supported, so these are the only ways to identify the principal.
		if req.Request.NameID == nil || req.Request.NameID.Value == "" {
			return errors.New("request has no NameID")
		}

		return nil
	}

	if req.Request.NameID != nil {
		return errors.New("request has both a NameID and an EncryptedID")
	}

	req.NameIDEncrypted = true

	decrypter, err := req.IDP.elementDecrypter()
	if err == nil {
		req.Request.NameID, err = decrypter.decryptNameID(encryptedIDEl)
	}

	if err != nil {
		req.IDP.logger().Printf("cannot decrypt the EncryptedID of the logout request from %s: %s", req.Request.Issuer.Value, err)

		// The stand-in is 256 bits from RandReader, so it is not the identifier of anyone.
		req.Unidentified = true
		req.Request.NameID = &NameID{
			Format: string(TransientNameIDFormat),
			Value:  base64.RawURLEncoding.EncodeToString(randomBytes(32)),
		}
	}

	return nil
}

// withPartialLogout returns status with a PartialLogout second-level status if it is a plain Success.
func withPartialLogout(status Status) Status {
	if status.StatusCode.Value == StatusSuccess && status.StatusCode.StatusCode == nil {
		status.StatusCode.StatusCode = &StatusCode{Value: StatusPartialLogout}
	}

	return status
}

// writeLogoutResponse answers req with status, or with a StatusInternalServerError if that fails.
func (idp *IdentityProvider) writeLogoutResponse(w http.ResponseWriter, req *IdpLogoutRequest, status Status) {
	if err := req.WriteResponse(w, status); err != nil {
		idp.logger().Printf("failed to write logout response: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// logoutOrigin returns the LogoutOrigin which a propagated logout answers the request with. It is only for a
// request on the front channel: one on the SOAP binding has no SLOEndpoint, and is answered on its own connection.
func (req *IdpLogoutRequest) logoutOrigin() *LogoutOrigin {
	return &LogoutOrigin{
		ServiceProviderEntityID: req.ServiceProviderMetadata.EntityID,
		RequestID:               req.Request.ID,
		SLOEndpoint:             *req.SLOEndpoint,
		RelayState:              req.RelayState,
	}
}

// isLogoutResponse reports whether the message to the single logout service is a SAMLResponse, in the query of a
// GET or the form of a POST. The form is parsed with the limit that NewIdpLogoutRequest applies, and stays parsed
// for it or NewIdpLogoutResponse.
func isLogoutResponse(r *http.Request) (bool, error) {
	switch r.Method {
	case http.MethodGet:
		return r.URL.Query().Has("SAMLResponse"), nil
	case http.MethodPost:
		if r.Body != nil {
			r.Body = http.MaxBytesReader(nil, r.Body, maxAuthnRequestBodySize)
		}

		if err := r.ParseForm(); err != nil {
			return false, err
		}

		return r.PostForm.Has("SAMLResponse"), nil
	default:
		return false, nil
	}
}

// serveLogoutResponse handles a LogoutResponse from a participant of a logout, records its outcome and continues the
// logout. A response to the outstanding request that can't be verified marks the participant failed, as it may still
// be logged in. A response that can't be read, or is not to the outstanding request, is refused and changes nothing.
//
// The ID of a response is not recorded in the ReplayStore. A response only counts as the answer to the outstanding
// request, whose ID is unique and is no longer outstanding once the state is saved, which the LogoutStateProvider
// does atomically, so a replayed response is uncorrelated wherever it arrives. A response over SOAP is read from the
// connection that the identity provider opened, and can't be presented again (SAMLBind §3.2.4).
func (idp *IdentityProvider) serveLogoutResponse(w http.ResponseWriter, r *http.Request) {
	provider, ok := idp.SessionProvider.(LogoutStateProvider)
	if !ok {
		idp.logger().Printf("cannot handle logout response: the session provider does not implement LogoutStateProvider")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

		return
	}

	resp, err := NewIdpLogoutResponse(idp, r)
	if err != nil {
		idp.logger().Printf("failed to parse logout response: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

		return
	}

	state, err := provider.LoadLogoutState(r, resp.RelayState)

	switch {
	case errors.Is(err, os.ErrNotExist):
		idp.logger().Printf("cannot handle logout response: the logout is unknown")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

		return
	case err != nil:
		idp.logger().Printf("cannot load logout state: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	case !resp.Now.Before(state.ExpireTime):
		idp.logger().Printf("cannot handle logout response: the logout expired at %s", state.ExpireTime)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

		return
	case state.Current < 0 || state.Current >= len(state.Participants):
		idp.logger().Printf("cannot handle logout response: the logout has no outstanding request")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

		return
	}

	if err = resp.Validate(state); errors.Is(err, ErrLogoutResponseUncorrelated) {
		// A stale or replayed response, such as one from an earlier participant, says nothing of the current one,
		// which is left outstanding.
		idp.logger().Printf("cannot handle logout response: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

		return
	} else if err != nil {
		idp.logger().Printf("failed to validate logout response: %s", err)

		participant := &state.Participants[state.Current]
		participant.Outcome, participant.Reason = LogoutOutcomeFailed, err.Error()
	} else {
		resp.outcome(state)
	}

	state.PendingRequestID = ""

	if err = idp.continueLogout(w, r, provider, state); err != nil {
		idp.writeContinueLogoutError(w, err)
	}
}

// terminateSessions ends each of the sessions, and returns the status of the LogoutResponse. A failure
// of one session doesn't stop the others from being ended.
func (idp *IdentityProvider) terminateSessions(w http.ResponseWriter, r *http.Request, provider LogoutSessionProvider, sessions []*Session) Status {
	var failed, partial bool

	for _, session := range sessions {
		err := provider.TerminateSession(w, r, session)

		switch {
		case err == nil:
		case errors.Is(err, ErrPartialLogout):
			partial = true
		default:
			idp.logger().Printf("cannot terminate session: %s", err)

			failed = true
		}
	}

	switch {
	case failed:
		return Status{StatusCode: StatusCode{Value: StatusResponder}}
	case partial:
		return Status{StatusCode: StatusCode{Value: StatusSuccess, StatusCode: &StatusCode{Value: StatusPartialLogout}}}
	default:
		return Status{StatusCode: StatusCode{Value: StatusSuccess}}
	}
}

// NewIdpLogoutRequest returns a new IdpLogoutRequest for the given HTTP request to the single logout
// service.
func NewIdpLogoutRequest(idp *IdentityProvider, r *http.Request) (*IdpLogoutRequest, error) {
	req := &IdpLogoutRequest{
		IDP:         idp,
		HTTPRequest: r,
		Now:         TimeNow(),
	}

	var err error

	switch r.Method {
	case http.MethodGet:
		req.binding = HTTPRedirectBinding

		req.RequestBuffer, req.RelayState, req.RedirectQuery, err = readRedirectRequest(r.URL.RawQuery)
		if err != nil {
			return nil, err
		}
	case http.MethodPost:
		req.binding = HTTPPostBinding

		if r.Body != nil {
			r.Body = http.MaxBytesReader(nil, r.Body, maxAuthnRequestBodySize)
		}

		if err := r.ParseForm(); err != nil {
			return nil, err
		}

		if req.RequestBuffer, err = base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLRequest")); err != nil {
			return nil, err
		}

		req.RelayState = r.PostForm.Get("RelayState")
	default:
		return nil, fmt.Errorf("method not allowed")
	}

	return req, nil
}

// Validate checks that the logout request is valid and signed by its service provider, and assigns
// the Request, ServiceProviderMetadata and SLOEndpoint properties. An EncryptedID is decrypted into
// Request.NameID, and the request is marked Unidentified if it can't be. On the SOAP binding the request must
// carry an enveloped signature, and SLOEndpoint is not assigned, as the response goes back on the
// connection of the request.
//
// The last check consumes the ID of the request in the ReplayStore of the identity provider (SAMLSec
// §6.1.2), so Validate returns nil once for a request, here or at any instance that shares the store:
// calling it again, or for a copy of the request, returns an error that wraps ErrReplayed and carries a
// Requester status with RequestDenied. A failure of the store is an error with a Responder status. Nothing
// is recorded for a request that fails any other check, so only a registered service provider can add to
// the store.
func (req *IdpLogoutRequest) Validate() error {
	// This code runs before any authentication, and the cost of the XML parsing below is
	// proportional to the size of the request.
	if err := checkAuthnRequestSize(req.RequestBuffer); err != nil {
		return err
	}

	if err := xrv.Validate(bytes.NewReader(req.RequestBuffer)); err != nil {
		return err
	}
	//nolint:gosec // G709: the size is limited and the XML validated above, as for an AuthnRequest, into a fixed type.
	if err := xml.Unmarshal(req.RequestBuffer, &req.Request); err != nil {
		return err
	}

	if err := req.checkTrust(); err != nil {
		return err
	}

	if req.binding == SOAPBinding {
		return req.validateSOAP()
	}

	serviceProviderID := req.Request.Issuer.Value

	serviceProvider, err := req.IDP.serviceProvider(req.HTTPRequest, serviceProviderID)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot handle request from unknown service provider %s", serviceProviderID)
	} else if err != nil {
		return fmt.Errorf("cannot find service provider %s: %v", serviceProviderID, err)
	}

	req.ServiceProviderMetadata = serviceProvider

	if err := req.verifySignature(); err != nil {
		return err
	}

	if err := req.identifyPrincipal(); err != nil {
		return err
	}

	if err := req.getSLOEndpoint(); err != nil {
		return err
	}

	if err := req.checkRequestStage(); err != nil {
		return err
	}

	return req.checkReplay()
}

// validateSOAP is the rest of Validate on the SOAP binding, after checkTrust: the enveloped signature is verified
// against the service provider of the Issuer, and the content that it covers is checked.
func (req *IdpLogoutRequest) validateSOAP() error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(req.RequestBuffer); err != nil {
		return err
	}

	if doc.Root() == nil {
		return errors.New("request has no root element")
	}

	metadata, verified, err := req.IDP.verifySOAPRequester(req.HTTPRequest, doc.Root(), req.Request.Issuer.Value)
	if err != nil {
		return err
	}

	req.ServiceProviderMetadata = metadata

	if err = req.useVerifiedRequest(verified); err != nil {
		return err
	}

	req.verifiedEl = verified

	if err = req.identifyPrincipal(); err != nil {
		return err
	}

	if err := req.checkRequestStage(); err != nil {
		return err
	}

	return req.checkReplay()
}

// checkTrust makes the checks on the identity of the request that are needed before the service
// provider can be looked up. Nothing in the request is acted on before these pass, and no response is
// sent for a request that fails them.
func (req *IdpLogoutRequest) checkTrust() error {
	if !isValidAuthnRequestID(req.Request.ID) {
		// The value is not included because this error is logged without authentication.
		return fmt.Errorf("invalid request ID")
	}

	if req.Request.Issuer == nil || req.Request.Issuer.Value == "" {
		return fmt.Errorf("request has no issuer")
	}

	return nil
}

// checkRequestStage makes the checks on the content of the request that are reported to the service
// provider as a SAML status. It must only run once the SLO endpoint has been resolved from metadata, or
// on the SOAP binding the requester verified, and on the content that the signature covers. The error
// is a *statusError.
func (req *IdpLogoutRequest) checkRequestStage() error {
	if statusErr := versionStatus(req.Request.Version); statusErr != nil {
		return statusErr
	}

	if req.Request.IssueInstant.Add(MaxIssueDelay).Before(req.Now) {
		return &statusError{StatusRequester, StatusRequestDenied,
			fmt.Errorf("request expired at %s", req.Request.IssueInstant.Add(MaxIssueDelay))}
	}

	if req.Request.IssueInstant.After(req.Now.Add(MaxClockSkew)) {
		return &statusError{StatusRequester, StatusRequestDenied,
			fmt.Errorf("request issued in the future at %s", req.Request.IssueInstant)}
	}

	if req.Request.NotOnOrAfter != nil && !req.Now.Before(*req.Request.NotOnOrAfter) {
		return &statusError{StatusRequester, StatusRequestDenied,
			fmt.Errorf("request expired at %s", *req.Request.NotOnOrAfter)}
	}

	// The request must be signed, so SAMLBind §3.4.5.2 and §3.5.5.2 require the destination, and
	// verifySignature requires that it is present. SAMLBind §3.2 has no such requirement on SOAP, but a
	// Destination that is present must be this endpoint.
	destination := req.IDP.LogoutURL.String()

	if req.binding == SOAPBinding {
		if req.Request.Destination == "" {
			return nil
		}

		destination = req.IDP.SOAPLogoutURL.String()
	}

	if req.Request.Destination != destination {
		return &statusError{StatusRequester, StatusRequestDenied,
			fmt.Errorf("expected destination to be %q, not %q", destination, req.Request.Destination)}
	}

	return nil
}

// verifySignature verifies the signature of the request, which is required. A signature embedded in
// the message replaces Request with the content that it covers, for the reason given at
// IdpAuthnRequest.useVerifiedRequest.
func (req *IdpLogoutRequest) verifySignature() error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(req.RequestBuffer); err != nil {
		return err
	}

	if doc.Root() == nil {
		return errors.New("request has no root element")
	}

	signatureEl, err := findChild(doc.Root(), "http://www.w3.org/2000/09/xmldsig#", "Signature")
	if err != nil {
		return err
	}

	if req.RedirectQuery == "" && signatureEl == nil {
		return errors.New("request is not signed")
	}

	certificates, err := serviceProviderSigningCertificates(req.ServiceProviderMetadata)
	if err != nil {
		return err
	}

	if len(certificates) == 0 {
		return errors.New("request is signed but the service provider has no signing certificate")
	}

	if req.RedirectQuery != "" {
		if err := verifyRedirectSignature(req.RedirectQuery, "SAMLRequest", certificates); err != nil {
			return fmt.Errorf("invalid request signature: %w", err)
		}

		// The signature in the query covers the whole message.
		req.verifiedEl = doc.Root()
	}

	if signatureEl != nil {
		verified, err := verifyEnvelopedSignature(doc.Root(), certificates)
		if err != nil {
			return fmt.Errorf("invalid request signature: %w", err)
		}

		if err := req.useVerifiedRequest(verified); err != nil {
			return err
		}

		req.verifiedEl = verified
	}

	// SAMLBind §3.4.5.2 and §3.5.5.2 require this of a signed message. The value is checked against
	// the logout URL later, by checkRequestStage.
	if req.Request.Destination == "" {
		return errors.New("signed request has no destination")
	}

	return nil
}

// useVerifiedRequest replaces Request with the content that the signature covers, and repeats the
// trust checks that were made on the original, as IdpAuthnRequest.useVerifiedRequest does.
func (req *IdpLogoutRequest) useVerifiedRequest(verified *etree.Element) error {
	serviceProviderID := req.Request.Issuer.Value

	req.Request = LogoutRequest{}
	if err := unmarshalElement(verified, &req.Request); err != nil {
		return err
	}

	if err := req.checkTrust(); err != nil {
		return err
	}

	if req.Request.Issuer.Value != serviceProviderID {
		return errors.New("signed request has a different issuer")
	}

	return nil
}

// getSLOEndpoint finds the endpoint to deliver the response to. It prefers the binding of the request,
// and otherwise HTTP-Redirect and then HTTP-POST, which are the only bindings supported.
//
// An endpoint whose response location is insecure, as described by
// IdentityProvider.AllowInsecureServiceProviderEndpoints, is skipped. If no other endpoint remains it
// returns an error which wraps ErrInsecureEndpoint, so the request is refused before the session is
// ended or a response is made.
func (req *IdpLogoutRequest) getSLOEndpoint() error {
	var insecure error

	for _, binding := range []string{req.binding, HTTPRedirectBinding, HTTPPostBinding} {
		for _, descriptor := range req.ServiceProviderMetadata.SPSSODescriptors {
			for _, endpoint := range descriptor.SingleLogoutServices {
				if endpoint.Binding != binding {
					continue
				}

				if err := req.IDP.CheckServiceProviderEndpoint(endpointResponseLocation(endpoint)); err != nil {
					insecure = err
					continue
				}

				req.SLOEndpoint = &endpoint

				return nil
			}
		}
	}

	if insecure != nil {
		return fmt.Errorf("service provider %s has no secure SingleLogoutService: %w", req.ServiceProviderMetadata.EntityID, insecure)
	}

	return fmt.Errorf("service provider %s has no SingleLogoutService with a supported binding", req.ServiceProviderMetadata.EntityID)
}

// responseLocation returns the location of SLOEndpoint which receives responses.
func (req *IdpLogoutRequest) responseLocation() string {
	return endpointResponseLocation(*req.SLOEndpoint)
}

// endpointResponseLocation returns the location of endpoint which receives responses, SAMLMeta §2.2.2.
func endpointResponseLocation(endpoint Endpoint) string {
	if endpoint.ResponseLocation != "" {
		return endpoint.ResponseLocation
	}

	return endpoint.Location
}

// MakeResponse returns the unsigned LogoutResponse to the request with the given status. It has no
// Destination when there is no SLOEndpoint, as on the SOAP binding, and no InResponseTo when the ID of
// the request is not valid.
func (req *IdpLogoutRequest) MakeResponse(status Status) *LogoutResponse {
	response := &LogoutResponse{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		Version:      "2.0",
		IssueInstant: req.Now,
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  req.IDP.MetadataURL.String(),
		},
		Status: status,
	}

	if isValidAuthnRequestID(req.Request.ID) {
		response.InResponseTo = req.Request.ID
	}

	if req.SLOEndpoint != nil {
		response.Destination = req.responseLocation()
	}

	return response
}

// WriteResponse writes a signed LogoutResponse with the given status to the SLOEndpoint, which
// Validate assigns. On the HTTP-Redirect binding the signature is in the query, as SAMLBind §3.4.4.1
// requires, and on the HTTP-POST binding it is enveloped. A request on the SOAP binding is answered on
// w in a SOAP envelope, with an enveloped signature.
func (req *IdpLogoutRequest) WriteResponse(w http.ResponseWriter, status Status) error {
	response := req.MakeResponse(status)

	signingContext, err := req.IDP.signingContext()
	if err != nil {
		return err
	}

	if req.binding == SOAPBinding {
		el, err := signLogoutResponseEnveloped(signingContext, response)
		if err != nil {
			return err
		}

		return writeSOAPResponse(w, nil, el)
	}

	setNoCacheHeaders(w)

	switch req.SLOEndpoint.Binding {
	case HTTPRedirectBinding:
		u, err := redirectURLWithContext(response.Destination, "SAMLResponse", response.Element(), req.RelayState, signingContext)
		if err != nil {
			return err
		}

		http.Redirect(w, req.HTTPRequest, u.String(), http.StatusFound) //nolint:gosec // G710: the location is from the service provider metadata, not the request.

		return nil
	case HTTPPostBinding:
		el, err := signLogoutResponseEnveloped(signingContext, response)
		if err != nil {
			return err
		}

		doc := etree.NewDocument()
		doc.SetRoot(el)

		buf, err := doc.WriteToBytes()
		if err != nil {
			return err
		}

		tmpl := req.IDP.ResponseFormTemplate
		if tmpl == nil {
			tmpl = defaultResponseFormTemplate
		}

		form := IdpAuthnRequestForm{
			URL:          response.Destination,
			SAMLResponse: base64.StdEncoding.EncodeToString(buf),
			RelayState:   req.RelayState,
		}

		var body bytes.Buffer
		if err := tmpl.Execute(&body, form); err != nil {
			return err
		}

		_, err = w.Write(body.Bytes())

		return err
	default:
		return fmt.Errorf("unsupported binding %s", req.SLOEndpoint.Binding)
	}
}

// signLogoutResponseEnveloped signs response with an enveloped signature and returns its element, for a binding
// which carries the signature in the message, as signLogoutRequestEnveloped does for a request.
func signLogoutResponseEnveloped(signingContext *dsig.SigningContext, response *LogoutResponse) (*etree.Element, error) {
	signedEl, err := signingContext.SignEnveloped(response.Element())
	if err != nil {
		return nil, err
	}

	// SAMLCore requires the signature to follow the Issuer, rather than come last.
	response.Signature = signedEl.ChildElements()[len(signedEl.ChildElements())-1]

	return response.Element(), nil
}
