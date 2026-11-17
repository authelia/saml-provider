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
)

// ErrPartialLogout is returned by LogoutSessionProvider.TerminateSession when the session at the
// identity provider has ended, but other session participants are known to remain logged in. The
// service provider receives a Success status with a PartialLogout second-level status.
var ErrPartialLogout = errors.New("other session participants were not logged out")

// LogoutSessionProvider is an optional interface of a SessionProvider, which is required to serve a
// LogoutRequest. Without it those requests receive a Responder status.
type LogoutSessionProvider interface {
	// GetLogoutSessions returns every session that req names, using req.MatchesSession. Without session
	// indexes in the request that is every session of the principal with that NameID (SAMLCore §3.7.3.2).
	// It must not rely on the session cookie alone, which a browser doesn't send with a cross-site POST.
	// It returns an empty slice and no error when no session matches. The request has been verified to
	// come from the service provider in req.ServiceProviderMetadata.
	//
	// An error sends a Responder status, and is not sent to the service provider.
	GetLogoutSessions(r *http.Request, req *IdpLogoutRequest) ([]*Session, error)

	// TerminateSession ends the session at the identity provider. It may set headers on w, such as to
	// remove a cookie, but must not write the status or body, which are the LogoutResponse. An error
	// other than ErrPartialLogout sends a Responder status, and is not sent to the service provider.
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

	// binding is the binding that the request was received on.
	binding string
}

// MatchesSession returns an error unless the request is for the session. The NameID of the request must be
// the complete identifier the identity provider asserted for the session (SAMLCore §3.7.3.2, §8.3): the
// same value, Format, NameQualifier and SPNameQualifier, and no SPProvidedID. An omitted or unspecified
// Format, or an omitted qualifier, doesn't match. This is compared with what DefaultAssertionMaker
// asserts, so an identity provider with a custom AssertionMaker that asserts another identifier needs
// IdentityProvider.LogoutNameIDValueOnly, which compares only the value, or its own check. If the request
// lists session indexes, the index of the session must be one of them.
func (req *IdpLogoutRequest) MatchesSession(session *Session) error {
	if session == nil {
		return errors.New("there is no session")
	}

	nameID := req.Request.NameID
	if nameID == nil {
		return errors.New("the request has no NameID")
	}

	if nameID.Value != session.NameID {
		return errors.New("the NameID value is not that of the session")
	}

	if !req.IDP.LogoutNameIDValueOnly {
		if req.ServiceProviderMetadata == nil {
			return errors.New("the request has no service provider metadata")
		}

		format := session.NameIDFormat
		if format == "" {
			format = string(TransientNameIDFormat)
		}

		// An omitted Format is unspecified (SAMLCore §2.2.2), which is not the format that was asserted, and the
		// qualifiers may only be omitted where they can be derived from the message, which they can't be in a
		// request the service provider sends to the identity provider (SAMLCore §8.3.7).
		if nameID.Format != format {
			return fmt.Errorf("the NameID format is %q and the session has %q", nameID.Format, format)
		}

		if nameID.NameQualifier != req.IDP.Metadata().EntityID {
			return fmt.Errorf("the NameID NameQualifier %q is not that of the identity provider", nameID.NameQualifier)
		}

		if nameID.SPNameQualifier != req.ServiceProviderMetadata.EntityID {
			return fmt.Errorf("the NameID SPNameQualifier %q is not that of the service provider", nameID.SPNameQualifier)
		}

		if nameID.SPProvidedID != "" {
			return errors.New("the NameID has a SPProvidedID, which the identity provider does not assert")
		}
	}

	if len(req.Request.SessionIndexes) != 0 && !slices.ContainsFunc(req.Request.SessionIndexes, func(i SessionIndex) bool { return i.Value == session.Index }) {
		return errors.New("the session index is not one the request lists")
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
// SingleLogoutService for a supported binding gets a StatusBadRequest response.
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
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

		return
	}

	status := Status{StatusCode: StatusCode{Value: StatusSuccess}}

	if provider, ok := idp.SessionProvider.(LogoutSessionProvider); !ok {
		idp.logger().Printf("cannot terminate session: the session provider does not implement LogoutSessionProvider")

		status.StatusCode.Value = StatusResponder
	} else if sessions, err := provider.GetLogoutSessions(r, req); err != nil {
		idp.logger().Printf("cannot find sessions to terminate: %s", err)

		status.StatusCode.Value = StatusResponder
	} else if _, _, _, err := idp.logoutProviders(); err != nil || len(sessions) == 0 {
		// Without the interfaces of a propagated logout, or without a session to propagate, the sessions
		// are ended and the requester is answered at once.
		status = idp.terminateSessions(w, r, provider, sessions)
	} else if err := idp.beginLogout(w, r, sessions, req.ServiceProviderMetadata.EntityID, "", req.logoutOrigin()); err != nil {
		idp.logger().Printf("cannot begin logout: %s", err)

		// The sessions are still ended, but the other participants were not told, so a Success is partial.
		status = idp.terminateSessions(w, r, provider, sessions)
		if status.StatusCode.Value == StatusSuccess && status.StatusCode.StatusCode == nil {
			status.StatusCode.StatusCode = &StatusCode{Value: StatusPartialLogout}
		}
	} else {
		return
	}

	if err := req.WriteResponse(w, status); err != nil {
		idp.logger().Printf("failed to write logout response: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// logoutOrigin returns the LogoutOrigin which a propagated logout answers the request with.
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
// the Request, ServiceProviderMetadata and SLOEndpoint properties.
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

	if err := req.checkRequest(); err != nil {
		return err
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

	// BaseID and EncryptedID are not supported, so this is the only way to identify the principal.
	if req.Request.NameID == nil || req.Request.NameID.Value == "" {
		return errors.New("request has no NameID")
	}

	return req.getSLOEndpoint()
}

// checkRequest makes the checks that depend only on the content of Request and the identity provider.
func (req *IdpLogoutRequest) checkRequest() error {
	// The request must be signed, so SAMLBind §3.4.5.2 and §3.5.5.2 require the destination.
	if req.Request.Destination != req.IDP.LogoutURL.String() {
		return fmt.Errorf("expected destination to be %q, not %q", req.IDP.LogoutURL.String(), req.Request.Destination)
	}

	if req.Request.IssueInstant.Add(MaxIssueDelay).Before(req.Now) {
		return fmt.Errorf("request expired at %s", req.Request.IssueInstant.Add(MaxIssueDelay))
	}

	if req.Request.IssueInstant.After(req.Now.Add(MaxClockSkew)) {
		return fmt.Errorf("request issued in the future at %s", req.Request.IssueInstant)
	}

	if req.Request.NotOnOrAfter != nil && !req.Now.Before(*req.Request.NotOnOrAfter) {
		return fmt.Errorf("request expired at %s", *req.Request.NotOnOrAfter)
	}

	if req.Request.Version != "2.0" {
		return fmt.Errorf("expected SAML request version 2.0 got %v", req.Request.Version)
	}

	if !isValidAuthnRequestID(req.Request.ID) {
		// The value is not included because this error is logged without authentication.
		return fmt.Errorf("invalid request ID")
	}

	if req.Request.Issuer == nil || req.Request.Issuer.Value == "" {
		return fmt.Errorf("request has no issuer")
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
	}

	if signatureEl != nil {
		verified, err := verifyEnvelopedSignature(doc.Root(), certificates)
		if err != nil {
			return fmt.Errorf("invalid request signature: %w", err)
		}

		serviceProviderID := req.Request.Issuer.Value

		req.Request = LogoutRequest{}
		if err := unmarshalElement(verified, &req.Request); err != nil {
			return err
		}

		if err := req.checkRequest(); err != nil {
			return err
		}

		if req.Request.Issuer.Value != serviceProviderID {
			return errors.New("signed request has a different issuer")
		}
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

// MakeResponse returns the unsigned LogoutResponse to the request with the given status.
func (req *IdpLogoutRequest) MakeResponse(status Status) *LogoutResponse {
	return &LogoutResponse{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		InResponseTo: req.Request.ID,
		Version:      "2.0",
		IssueInstant: req.Now,
		Destination:  req.responseLocation(),
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  req.IDP.MetadataURL.String(),
		},
		Status: status,
	}
}

// WriteResponse writes a signed LogoutResponse with the given status to the SLOEndpoint, which
// Validate assigns. On the HTTP-Redirect binding the signature is in the query, as SAMLBind §3.4.4.1
// requires, and on the HTTP-POST binding it is enveloped.
func (req *IdpLogoutRequest) WriteResponse(w http.ResponseWriter, status Status) error {
	response := req.MakeResponse(status)

	signingContext, err := req.IDP.signingContext()
	if err != nil {
		return err
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
		signedEl, err := signingContext.SignEnveloped(response.Element())
		if err != nil {
			return err
		}
		// SAMLCore requires the signature to follow the Issuer, rather than come last.
		response.Signature = signedEl.ChildElements()[len(signedEl.ChildElements())-1]
		doc := etree.NewDocument()
		doc.SetRoot(response.Element())

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
