package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/beevik/etree"

	"authelia.com/provider/saml/internal/xmlrv"
)

// IdpLogoutResponse is a LogoutResponse that a service provider sent back during a logout.
type IdpLogoutResponse struct {
	IDP            *IdentityProvider
	HTTPRequest    *http.Request
	RelayState     string
	ResponseBuffer []byte
	Response       LogoutResponse
	Now            time.Time

	// RedirectQuery is the raw query string of a response on the HTTP-Redirect binding which is signed
	// in the query.
	RedirectQuery string

	// binding is the binding the response arrived on. On SOAP it is the answer on the connection the identity
	// provider opened to the service provider, so it has no Destination to check.
	binding string

	// overTLS is set when a SOAP response came back over TLS, which authenticates the service provider, so that it
	// need not be signed.
	overTLS bool
}

// newSOAPLogoutResponse returns the LogoutResponse in buf, which a service provider answered over SOAP to a
// LogoutRequest sent during r.
// overTLS reports whether it came back over TLS.
func newSOAPLogoutResponse(idp *IdentityProvider, r *http.Request, buf []byte, overTLS bool) *IdpLogoutResponse {
	return &IdpLogoutResponse{
		overTLS:        overTLS,
		IDP:            idp,
		HTTPRequest:    r,
		ResponseBuffer: buf,
		Now:            TimeNow(),
		binding:        SOAPBinding,
	}
}

// NewIdpLogoutResponse reads SAMLResponse and RelayState from a GET query or POST form.
func NewIdpLogoutResponse(idp *IdentityProvider, r *http.Request) (*IdpLogoutResponse, error) {
	resp := &IdpLogoutResponse{
		IDP:         idp,
		HTTPRequest: r,
		Now:         TimeNow(),
	}

	var err error

	switch r.Method {
	case http.MethodGet:
		resp.ResponseBuffer, resp.RelayState, resp.RedirectQuery, err = readRedirectMessage(r.URL.RawQuery, "SAMLResponse")
		if err != nil {
			return nil, err
		}
	case http.MethodPost:
		if r.Body != nil {
			r.Body = http.MaxBytesReader(nil, r.Body, maxAuthnRequestBodySize)
		}

		if err := r.ParseForm(); err != nil {
			return nil, err
		}

		if resp.ResponseBuffer, err = base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLResponse")); err != nil {
			return nil, err
		}

		resp.RelayState = r.PostForm.Get("RelayState")
	default:
		return nil, fmt.Errorf("method not allowed")
	}

	return resp, nil
}

// Validate checks the response against the outstanding request of state and returns nil only if it is a valid,
// signed answer from that participant. A response on the SOAP binding may be unsigned when it comes back over TLS
// on the connection to the service provider (see verifySignature). Its status is not checked here. On the front channel an
// error that wraps ErrLogoutResponseUncorrelated is not attributable to the current participant.
func (resp *IdpLogoutResponse) Validate(state *LogoutState) error {
	if state.Current < 0 || state.Current >= len(state.Participants) {
		return fmt.Errorf("%w: there is no outstanding logout request", ErrLogoutResponseUncorrelated)
	}

	// This code runs before any authentication, and the cost of the XML parsing below is
	// proportional to the size of the response.
	if err := checkAuthnRequestSize(resp.ResponseBuffer); err != nil {
		return fmt.Errorf("%w: %w", ErrLogoutResponseUncorrelated, err)
	}

	if err := xmlrv.Validate(resp.ResponseBuffer); err != nil {
		return fmt.Errorf("%w: %w", ErrLogoutResponseUncorrelated, err)
	}

	//nolint:gosec // G709: the size is limited and the XML validated above, as for a LogoutRequest, into a fixed type.
	if err := xml.Unmarshal(resp.ResponseBuffer, &resp.Response); err != nil {
		return fmt.Errorf("%w: %w", ErrLogoutResponseUncorrelated, err)
	}

	entityID := state.Participants[state.Current].ServiceProviderEntityID

	if err := resp.checkResponse(state, entityID); err != nil {
		return err
	}

	metadata, err := resp.IDP.serviceProvider(resp.HTTPRequest, entityID)
	if err != nil {
		return fmt.Errorf("cannot find service provider %s: %w", entityID, err)
	}

	return resp.verifySignature(state, entityID, metadata)
}

// checkResponse makes the checks that depend only on the content of Response, the state and the identity provider.
// The response is correlated with the outstanding request first, so that no other check can fail a participant on
// account of a response that is not its own.
func (resp *IdpLogoutResponse) checkResponse(state *LogoutState, entityID string) error {
	// An empty ID is never outstanding, and must not match a response that omits InResponseTo.
	if state.PendingRequestID == "" || resp.Response.InResponseTo != state.PendingRequestID {
		return ErrLogoutResponseUncorrelated
	}

	if resp.Response.Issuer == nil || resp.Response.Issuer.Value != entityID {
		return fmt.Errorf("%w: response is not from the service provider that was sent the logout request", ErrLogoutResponseUncorrelated)
	}

	if resp.Response.Version != "2.0" {
		return fmt.Errorf("expected SAML response version 2.0 got %v", resp.Response.Version)
	}

	if resp.binding != SOAPBinding && resp.Response.Destination != "" && resp.Response.Destination != resp.IDP.LogoutURL.String() {
		return fmt.Errorf("expected destination to be %q, not %q", resp.IDP.LogoutURL.String(), resp.Response.Destination)
	}

	return checkIssueInstant("response", resp.Response.IssueInstant, resp.Now, MaxIssueDelay)
}

// verifySignature verifies the signature of the response, which is required except on SOAP when the response comes
// back over TLS on the connection to the service provider, which authenticates it (SAMLBind §3.2.4). Over plain http,
// allowed by AllowInsecureServiceProviderEndpoints, nothing else authenticates it, so it must be signed. A signature embedded in the message replaces Response with
// the content that it covers, for the reason given at IdpAuthnRequest.useVerifiedRequest.
func (resp *IdpLogoutResponse) verifySignature(state *LogoutState, entityID string, metadata *EntityDescriptor) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(resp.ResponseBuffer); err != nil {
		return err
	}

	if doc.Root() == nil {
		return errors.New("response has no root element")
	}

	signatureEl, err := findChild(doc.Root(), "http://www.w3.org/2000/09/xmldsig#", "Signature")
	if err != nil {
		return err
	}

	if resp.RedirectQuery == "" && signatureEl == nil {
		return resp.checkUnsigned()
	}

	certificates, err := serviceProviderSigningCertificates(metadata)
	if err != nil {
		return err
	}

	if len(certificates) == 0 {
		return errors.New("response is signed but the service provider has no signing certificate")
	}

	policy, err := resp.IDP.signaturePolicy()
	if err != nil {
		return err
	}

	if resp.RedirectQuery != "" {
		if err := verifyRedirectSignature(resp.RedirectQuery, "SAMLResponse", certificates, policy); err != nil {
			return fmt.Errorf("invalid response signature: %w", err)
		}
	}

	if signatureEl != nil {
		verified, err := verifyEnvelopedSignature(doc.Root(), certificates, policy)
		if err != nil {
			return fmt.Errorf("invalid response signature: %w", err)
		}

		resp.Response = LogoutResponse{}
		if err := unmarshalElement(verified, &resp.Response); err != nil {
			return err
		}

		if err := resp.checkResponse(state, entityID); err != nil {
			return err
		}
	}

	return nil
}

// outcome records the result of resp on the current participant of state: Success for a Success top-level status,
// otherwise Failed with the status code as Reason. A Success with a PartialLogout second-level status is Failed with
// StatusPartialLogout as Reason, as the participant reports that it left something logged in (SAMLCore §3.7.3.2).
func (resp *IdpLogoutResponse) outcome(state *LogoutState) {
	participant := &state.Participants[state.Current]
	code := resp.Response.Status.StatusCode

	switch {
	case code.Value != StatusSuccess:
		participant.Outcome, participant.Reason = LogoutOutcomeFailed, code.Value
	case code.StatusCode != nil && code.StatusCode.Value == StatusPartialLogout:
		participant.Outcome, participant.Reason = LogoutOutcomeFailed, StatusPartialLogout
	default:
		participant.Outcome, participant.Reason = LogoutOutcomeSuccess, ""
	}
}

// statusError returns nil if the status of the response is a plain success, and otherwise the error for the status
// that the participant answered with, as StatusErrorFromStatus makes it, which includes a partial logout.
func (resp *IdpLogoutResponse) statusError() *StatusError {
	code := resp.Response.Status.StatusCode

	if code.Value == StatusSuccess && (code.StatusCode == nil || code.StatusCode.Value != StatusPartialLogout) {
		return nil
	}

	return StatusErrorFromStatus(resp.Response.Status)
}

// checkUnsigned returns nil if the response may be unsigned, which is only on SOAP over TLS.
func (resp *IdpLogoutResponse) checkUnsigned() error {
	if resp.binding == SOAPBinding && resp.overTLS {
		return nil
	}

	return errors.New("response is not signed")
}
