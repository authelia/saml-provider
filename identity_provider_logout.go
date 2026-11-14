package saml

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"os"
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
	// TerminateSession ends the session at the identity provider of the principal that
	// req.Request.NameID identifies, and of the sessions that req.Request.SessionIndexes lists, if
	// there are any. The request has been verified to come from the service provider in
	// req.ServiceProviderMetadata. Other service providers are not told of the logout.
	//
	// It may set headers on w, such as to remove a cookie, but must not write the status or body,
	// which are the LogoutResponse. An error other than ErrPartialLogout sends a Responder status, and
	// is not sent to the service provider.
	TerminateSession(w http.ResponseWriter, r *http.Request, req *IdpLogoutRequest) error
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

// ServeSLO handles a SAML LogoutRequest from a service provider, on the HTTP-Redirect or HTTP-POST
// binding, and responds with a signed LogoutResponse. The request must be signed, as SAMLProfiles
// §4.4.4.1 requires it to be authenticated. The session at the identity provider is ended by the
// SessionProvider, which must implement LogoutSessionProvider. Other session participants are not
// told of the logout.
//
// A request that is invalid, can't be verified, or comes from a service provider with no
// SingleLogoutService for a supported binding gets a StatusBadRequest response.
func (idp *IdentityProvider) ServeSLO(w http.ResponseWriter, r *http.Request) {
	req, err := NewIdpLogoutRequest(idp, r)
	if err != nil {
		idp.Logger.Printf("failed to parse logout request: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		idp.Logger.Printf("failed to validate logout request: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	status := Status{StatusCode: StatusCode{Value: StatusSuccess}}
	if provider, ok := idp.SessionProvider.(LogoutSessionProvider); !ok {
		idp.Logger.Printf("cannot terminate session: the session provider does not implement LogoutSessionProvider")
		status.StatusCode.Value = StatusResponder
	} else if err := provider.TerminateSession(w, r, req); errors.Is(err, ErrPartialLogout) {
		status.StatusCode.StatusCode = &StatusCode{Value: StatusPartialLogout}
	} else if err != nil {
		idp.Logger.Printf("cannot terminate session: %s", err)
		status.StatusCode.Value = StatusResponder
	}

	if err := req.WriteResponse(w, status); err != nil {
		idp.Logger.Printf("failed to write logout response: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
	serviceProvider, err := req.IDP.ServiceProviderProvider.GetServiceProvider(req.HTTPRequest, serviceProviderID)
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
func (req *IdpLogoutRequest) getSLOEndpoint() error {
	for _, binding := range []string{req.binding, HTTPRedirectBinding, HTTPPostBinding} {
		for _, descriptor := range req.ServiceProviderMetadata.SPSSODescriptors {
			for _, endpoint := range descriptor.SingleLogoutServices {
				if endpoint.Binding == binding {
					req.SLOEndpoint = &endpoint
					return nil
				}
			}
		}
	}
	return fmt.Errorf("service provider %s has no SingleLogoutService with a supported binding", req.ServiceProviderMetadata.EntityID)
}

// responseLocation returns the location of SLOEndpoint which receives responses.
func (req *IdpLogoutRequest) responseLocation() string {
	if req.SLOEndpoint.ResponseLocation != "" {
		return req.SLOEndpoint.ResponseLocation
	}
	return req.SLOEndpoint.Location
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
			Value:  req.IDP.entityID(),
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
