package saml

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"

	"github.com/beevik/etree"
)

const (
	// ecpNS is the namespace of the header blocks of the Enhanced Client or Proxy profile (SAMLProf §4.2.4).
	ecpNS = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"

	// channelBindingNS is the namespace of the channel bindings extension, which ECP v2.0 uses.
	channelBindingNS = "urn:oasis:names:tc:SAML:protocol:ext:channel-binding"

	soapFaultStringAuthnRequest = "the request is not an acceptable authentication request"
)

// ecpUnderstoodHeaders are the header blocks that ServeECP accepts with mustUnderstand set. A cb:ChannelBindings
// block is understood only so that it is answered with the Response that ECP v2.0 §2.3.6.2 requires, in place of a
// MustUnderstand fault.
var ecpUnderstoodHeaders = []xml.Name{{Space: channelBindingNS, Local: "ChannelBindings"}}

// ServeECP handles a SAML AuthnRequest of the Enhanced Client or Proxy profile, at ECPURL. The client, which is
// not a browser, received the request from a service provider and relays it here in a SOAP envelope; it is answered
// on the same connection with a signed Response in a SOAP envelope, which the client delivers to the
// AssertionConsumerService of the service provider on the PAOS binding (SAMLProf §4.2, ECP v2.0 §2.3.4 to §2.3.6).
// The identity provider itself only uses the SOAP binding.
//
// The principal is authenticated by the SessionProvider, which must implement ECPSessionProvider, typically with
// HTTP Basic credentials. A request with IsPassive set gets a NoPassive status, as that always takes credentials.
// The assertion is the one that ServeSSO would make, with bearer confirmation at the PAOS endpoint (SAMLProf
// §4.1.4.2), and the service provider is recorded as a participant of the session in the same way. It is saved in
// the AssertionStore, if there is one. As for ServeSSO, the request is used up once the principal is authenticated:
// its ID is recorded in the ReplayStore, and the same request sent again, with whatever credentials, gets Requester
// with RequestDenied (SAMLSec §6.1.2). A request that the client sends again after a 401 is not a replay.
//
// The envelope of every Response has an ecp:Response header block which names the endpoint the Response is for,
// which the client compares with the one the service provider gave it (SAMLProf §4.2.4.4). That endpoint is always
// an AssertionConsumerService with the PAOS binding in the metadata of the service provider: the one that the
// request names by URL or index, or the default one. A request is signed if WantAuthnRequestsSigned or the
// metadata of the service provider requires it, as for ServeSSO, and when its signature was verified the envelope
// also has an ecp:RequestAuthenticated header block (ECP v2.0 §2.3.6.1). A signed request needs no Destination.
//
// A request that is not a POST gets StatusMethodNotAllowed. One that is not a SOAP 1.1 envelope holding an
// AuthnRequest, or that fails before the endpoint is established, such as one from an unknown service provider, with
// a missing or invalid signature, or naming an endpoint that the metadata doesn't list, gets a Client fault, as a
// Response can't be addressed (ECP v2.0 §2.3.6). A header block that must be understood gets a MustUnderstand
// fault; the client must have removed those of the service provider (SAMLProf §4.2.3.4). Any later failure is a
// Response with an error status, as for ServeSSO. A request with channel bindings, which are not verified, gets
// Requester with RequestUnsupported (ECP v2.0 §2.3.6.2), and holder-of-key confirmation is not supported. A Response
// that can't be signed gets a Server fault.
func (idp *IdentityProvider) ServeECP(w http.ResponseWriter, r *http.Request) {
	soap, ok := idp.receiveSOAPRequest(w, r, ecpUnderstoodHeaders...)
	if !ok {
		return
	}

	req := &IdpAuthnRequest{
		IDP:           idp,
		HTTPRequest:   r,
		RequestBuffer: soap.Body,
		Now:           TimeNow(),
		binding:       SOAPBinding,
	}

	if err := req.validateECP(soap); err != nil {
		idp.logger().Printf("failed to validate ECP request: %s", err)

		if top, second, ok := requestStatus(err); ok {
			req.writeErrorStatus(w, top, second)

			return
		}

		writeSOAPFault(w, &soapFault{Code: "Client", String: soapFaultStringAuthnRequest})

		return
	}

	provider, ok := idp.SessionProvider.(ECPSessionProvider)
	if !ok {
		idp.logger().Printf("cannot serve ECP request: the session provider does not implement ECPSessionProvider")

		req.writeErrorStatus(w, StatusResponder, StatusRequestUnsupported)

		return
	}

	// The principal is authenticated with credentials, which a passive request rules out. This comes before
	// ForceAuthn, as for the browser (SAMLCore §3.4.1).
	if req.Request.IsPassive != nil && *req.Request.IsPassive {
		req.writeErrorStatus(w, StatusResponder, StatusNoPassive)

		return
	}

	session := provider.GetECPSession(w, r, req)
	if session == nil {
		return
	}

	req.respond(w, session)
}

// validateECP is Validate for the message of a SOAP request, with the checks that only apply to the Enhanced Client
// or Proxy profile. As for Validate, an error that carries no status means that the request must not be answered
// with a Response.
func (req *IdpAuthnRequest) validateECP(soap *soapRequest) error {
	if soap.Message.Tag != "AuthnRequest" || soap.Message.NamespaceURI() != samlProtocolNS {
		return errors.New("the message is not an AuthnRequest")
	}

	if err := req.Validate(); err != nil {
		return err
	}

	// ECP v2.0 §2.3.6.2: the channel bindings of the client and the service provider must be compared, and the
	// assertion must state the result. That isn't done here, so the request is refused whichever of them sent
	// some. The raw message is searched, as the extensions aren't parsed; one that a signature doesn't cover
	// would already have failed Validate.
	if hasChannelBindings(soap.Headers) {
		return &statusError{StatusRequester, StatusRequestUnsupported,
			errors.New("the client sent channel bindings, which are not supported")}
	}

	for _, extensions := range soap.Message.ChildElements() {
		if extensions.Tag == "Extensions" && extensions.NamespaceURI() == samlProtocolNS && hasChannelBindings(extensions.ChildElements()) {
			return &statusError{StatusRequester, StatusRequestUnsupported,
				errors.New("the request has channel bindings, which are not supported")}
		}
	}

	return nil
}

// hasChannelBindings reports whether any of the elements is a cb:ChannelBindings.
func hasChannelBindings(elements []*etree.Element) bool {
	for _, el := range elements {
		if el.Tag == "ChannelBindings" && el.NamespaceURI() == channelBindingNS {
			return true
		}
	}

	return false
}

// ecpHeaders returns the header blocks of the envelope of a Response (ECP v2.0 §2.3.6). They are addressed to the
// client, which is the next actor, and use the soapenv prefix that newSOAPEnvelope declares.
func (req *IdpAuthnRequest) ecpHeaders() []*etree.Element {
	// SAMLProf §4.2.4.4: the client refuses to deliver the Response unless this is the endpoint that the service
	// provider gave it.
	response := etree.NewElement("ecp:Response")
	response.CreateAttr("xmlns:ecp", ecpNS)
	response.CreateAttr("soapenv:mustUnderstand", "1")
	response.CreateAttr("soapenv:actor", soapActorNext)
	response.CreateAttr("AssertionConsumerServiceURL", req.ACSEndpoint.Location)

	headers := []*etree.Element{response}

	// ECP v2.0 §2.3.6.1.
	if req.requestAuthenticated {
		authenticated := etree.NewElement("ecp:RequestAuthenticated")
		authenticated.CreateAttr("xmlns:ecp", ecpNS)
		authenticated.CreateAttr("soapenv:actor", soapActorNext)

		headers = append(headers, authenticated)
	}

	return headers
}

// writeECPResponse is WriteResponse for a request of the Enhanced Client or Proxy profile: it writes ResponseEl,
// which MakeResponse makes if it is not set, in a SOAP envelope with the header blocks of the profile. The endpoint
// in them is checked like the one of PostBinding.
func (req *IdpAuthnRequest) writeECPResponse(w http.ResponseWriter) error {
	if req.ACSEndpoint == nil {
		return fmt.Errorf("%w: no validated assertion consumer service", ErrResponseNotBuilt)
	}

	if err := req.IDP.CheckServiceProviderEndpoint(req.ACSEndpoint.Location); err != nil {
		req.ResponseEl, req.responseParticipant = nil, nil

		return fmt.Errorf("%w: %w", ErrResponseNotBuilt, err)
	}

	if req.ACSEndpoint.Binding != PAOSBinding {
		return fmt.Errorf("%w: unsupported binding %s", ErrResponseNotBuilt, req.ACSEndpoint.Binding)
	}

	if req.ResponseEl == nil {
		if err := req.MakeResponse(); err != nil {
			return fmt.Errorf("%w: %w", ErrResponseNotBuilt, err)
		}
	}

	buf, err := newSOAPResponse(req.ecpHeaders(), req.ResponseEl).WriteToBytes()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrResponseNotBuilt, err)
	}

	published := false

	err = req.PublishResponse(func() error {
		published = true

		return writeSOAPBytes(w, http.StatusOK, buf)
	})

	// The participant couldn't be recorded, so nothing was written.
	if err != nil && !published {
		return fmt.Errorf("%w: %w", ErrResponseNotBuilt, err)
	}

	return err
}
