package saml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
)

// NameIDChange is a change to the identifier of a principal that the identity provider tells a service provider
// of with IdentityProvider.SendManageNameIDRequest (SAMLCore §3.6).
type NameIDChange struct {
	// NameID is the identifier as the service provider knows it before the change, complete with its Format,
	// its qualifiers and the SPProvidedID that the service provider last set, if any (SAMLCore §3.6.3). It
	// must not be of the transient format (errata E12).
	NameID NameID

	// NewID is the value that the identity provider will use in place of NameID.Value from now on. Exactly one
	// of NewID and Terminate must be set.
	NewID string

	// Terminate tells the service provider that the identity provider will no longer issue assertions to it
	// with the identifier.
	Terminate bool

	// Encrypt sends the identifier as an EncryptedID, and the NewID as a NewEncryptedID, encrypted to the
	// encryption key in the metadata of the service provider. If they can't be encrypted nothing is sent.
	Encrypt bool
}

// ManageNameIDStatusError is the error of IdentityProvider.SendManageNameIDRequest when the service provider
// answered with a status other than Success, such as UnknownPrincipal.
type ManageNameIDStatusError struct {
	// Status is the status of the ManageNameIDResponse.
	Status Status
}

// Error implements error.
func (e *ManageNameIDStatusError) Error() string {
	if second := e.Status.StatusCode.StatusCode; second != nil {
		return fmt.Sprintf("the service provider answered with the status %s %s", e.Status.StatusCode.Value, second.Value)
	}

	return fmt.Sprintf("the service provider answered with the status %s", e.Status.StatusCode.Value)
}

// SendManageNameIDRequest tells the service provider that the identity provider has changed the identifier of
// a principal, or will no longer use it, with a signed ManageNameIDRequest on the SOAP binding (SAMLCore §3.6,
// SAMLProfiles §4.5.3.1), and returns nil once the service provider has answered with Success. It is for the
// application to call when it changes or retires an identifier that it issues; nothing in the identity provider
// calls it. A status other than Success is a *ManageNameIDStatusError.
//
// The request is sent with HTTPClient to the ManageNameIDService of the service provider which is on the SOAP
// binding and passes CheckServiceProviderBackChannelEndpoint, and is only cancelled with r. The response is
// verified if it is signed, and may be unsigned only when it comes back over TLS on the connection the identity
// provider opened, as for a LogoutRequest over SOAP. A service provider that is only reached on a front-channel
// binding can't be told.
//
// A LogoutRequest must not be sent after a Terminate (errata E8): to also end the sessions of the principal at
// the service provider, log it out first, such as with StartLogout. The application must itself stop issuing
// the identifier, or issue the new one, as its NameIDProvider decides what an assertion holds.
func (idp *IdentityProvider) SendManageNameIDRequest(r *http.Request, serviceProviderEntityID string, change NameIDChange) error {
	switch {
	case change.NameID.Value == "":
		return errors.New("the name identifier has no value")
	case change.NameID.Format == string(TransientNameIDFormat):
		// Errata E12: the protocol MUST NOT be used with the transient format.
		return errors.New("a transient name identifier cannot be managed")
	case change.Terminate == (change.NewID != ""):
		return errors.New("exactly one of a new identifier and Terminate is required")
	}

	metadata, err := idp.serviceProvider(r, serviceProviderEntityID)
	if err != nil {
		return fmt.Errorf("cannot find service provider %s: %w", serviceProviderEntityID, err)
	}

	endpoint, err := idp.manageNameIDRequestEndpoint(metadata)
	if err != nil {
		return err
	}

	request := &ManageNameIDRequest{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		Version:      "2.0",
		IssueInstant: TimeNow(),
		Destination:  endpoint.Location,
		// SAMLProfiles §4.5.4.1: the Issuer MUST be the requesting entity.
		Issuer:    &Issuer{Format: string(EntityNameIDFormat), Value: idp.entityID()},
		NameID:    &change.NameID,
		NewID:     change.NewID,
		Terminate: change.Terminate,
	}

	// SAMLCore §6.2: the identifiers are encrypted first, and the signature is then calculated over the message
	// which contains the encrypted elements.
	if change.Encrypt {
		if err = idp.encryptManageNameIDRequest(request, metadata); err != nil {
			return fmt.Errorf("cannot encrypt the name identifier management request: %w", err)
		}
	}

	// Before the request is sent, so that the service provider doesn't act on one whose response can't be read.
	policy, err := idp.signaturePolicy()
	if err != nil {
		return err
	}

	signingContext, err := idp.signingContextFor(r, metadata)
	if err != nil {
		return fmt.Errorf("cannot sign the name identifier management request: %w", err)
	}

	el, err := signMessageEnveloped(signingContext, request)
	if err != nil {
		return fmt.Errorf("cannot sign the name identifier management request: %w", err)
	}

	message, overTLS, err := idp.postSOAPMessage(r, endpoint.Location, el, "name identifier management")
	if err != nil {
		return err
	}

	response, err := validateManageNameIDResponse(message, overTLS, request.ID, metadata, policy, TimeNow())
	if err != nil {
		return fmt.Errorf("invalid name identifier management response: %w", err)
	}

	if code := response.Status.StatusCode; code.Value != StatusSuccess {
		return &ManageNameIDStatusError{Status: response.Status}
	}

	return nil
}

// manageNameIDRequestEndpoint returns the ManageNameIDService on the SOAP binding to send a ManageNameIDRequest
// to: the first whose Location passes CheckServiceProviderBackChannelEndpoint.
func (idp *IdentityProvider) manageNameIDRequestEndpoint(metadata *EntityDescriptor) (*Endpoint, error) {
	var lastErr error

	for i := range metadata.SPSSODescriptors {
		endpoints := metadata.SPSSODescriptors[i].ManageNameIDServices

		for j := range endpoints {
			if endpoints[j].Binding != SOAPBinding {
				continue
			}

			if err := idp.CheckServiceProviderBackChannelEndpoint(endpoints[j].Location); err != nil {
				lastErr = err

				continue
			}

			return &endpoints[j], nil
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, errors.New("the service provider has no name identifier management service on the SOAP binding")
}

// encryptManageNameIDRequest replaces the NameID of request with an EncryptedID, and its NewID with a
// NewEncryptedID, encrypted to the encryption key of the service provider (SAMLProfiles §4.5.5).
func (idp *IdentityProvider) encryptManageNameIDRequest(request *ManageNameIDRequest, metadata *EntityDescriptor) error {
	encrypter, err := idp.serviceProviderElementEncrypter(metadata)
	if err != nil {
		return err
	}

	if request.EncryptedID, err = encrypter.encryptNameID(request.NameID); err != nil {
		return err
	}

	request.NameID = nil

	if request.Terminate {
		return nil
	}

	if request.NewEncryptedID, err = encrypter.encryptNewID(request.NewID); err != nil {
		return err
	}

	request.NewID = ""

	return nil
}

// encryptNewID returns the NewEncryptedID element of SAMLCore §3.6.1 for newID. It must take the place of the
// NewID before the request that contains it is signed (SAMLCore §6.2).
func (e *elementEncrypter) encryptNewID(newID string) (*etree.Element, error) {
	plaintext := etree.NewElement("samlp:NewID")
	plaintext.CreateAttr("xmlns:samlp", samlProtocolNS)
	plaintext.SetText(newID)

	el, err := e.encrypt("NewEncryptedID", plaintext)
	if err != nil {
		return nil, err
	}

	// encrypt names its element in the assertion namespace, and this one is of the protocol namespace.
	el.Space = "samlp"
	el.RemoveAttr("xmlns:saml")
	el.CreateAttr("xmlns:samlp", samlProtocolNS)

	return el, nil
}

// validateManageNameIDResponse returns the ManageNameIDResponse in buf if it is a valid answer of the service
// provider to the request with the ID requestID. Its status is not checked. A signature is verified when it is
// present, and is required unless the response came back over TLS on the connection to the service provider,
// which authenticates it (SAMLProfiles §4.5.3.2, SAMLBind §3.2.4).
func validateManageNameIDResponse(buf []byte, overTLS bool, requestID string, metadata *EntityDescriptor, policy *signaturePolicy, now time.Time) (*ManageNameIDResponse, error) {
	if err := checkAuthnRequestSize(buf); err != nil {
		return nil, err
	}

	if err := xrv.Validate(bytes.NewReader(buf)); err != nil {
		return nil, err
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(buf); err != nil {
		return nil, err
	}

	if doc.Root() == nil {
		return nil, errors.New("response has no root element")
	}

	response := &ManageNameIDResponse{}

	// The size is limited and the XML validated above, as for a LogoutRequest, into a fixed type.
	if err := xml.Unmarshal(buf, response); err != nil {
		return nil, err
	}

	response, err := verifyManageNameIDResponseSignature(doc.Root(), response, overTLS, metadata, policy)
	if err != nil {
		return nil, err
	}

	// An empty ID is never outstanding, and must not match a response that omits InResponseTo.
	if requestID == "" || response.InResponseTo != requestID {
		return nil, errors.New("response is not to the request that was sent")
	}

	// SAMLProfiles §4.5.4.2: the Issuer MUST be the responding entity.
	if response.Issuer == nil || response.Issuer.Value != metadata.EntityID {
		return nil, errors.New("response is not from the service provider that was sent the request")
	}

	if response.Version != "2.0" {
		return nil, fmt.Errorf("expected SAML response version 2.0 got %v", response.Version)
	}

	if response.IssueInstant.Add(MaxIssueDelay).Before(now) {
		return nil, fmt.Errorf("response expired at %s", response.IssueInstant.Add(MaxIssueDelay))
	}

	if response.IssueInstant.After(now.Add(MaxClockSkew)) {
		return nil, fmt.Errorf("response issued in the future at %s", response.IssueInstant)
	}

	return response, nil
}

// verifyManageNameIDResponseSignature returns response, which was unmarshalled from root, if root is not signed
// and came back over TLS, or the response that the signature of root covers if it is signed by the service
// provider with the algorithms of the policy.
func verifyManageNameIDResponseSignature(root *etree.Element, response *ManageNameIDResponse, overTLS bool, metadata *EntityDescriptor, policy *signaturePolicy) (*ManageNameIDResponse, error) {
	signatureEl, err := findChild(root, "http://www.w3.org/2000/09/xmldsig#", "Signature")
	if err != nil {
		return nil, err
	}

	if signatureEl == nil {
		if !overTLS {
			return nil, errors.New("response is not signed")
		}

		return response, nil
	}

	certificates, err := serviceProviderSigningCertificates(metadata)
	if err != nil {
		return nil, err
	}

	if len(certificates) == 0 {
		return nil, errors.New("response is signed but the service provider has no signing certificate")
	}

	verified, err := verifyEnvelopedSignature(root, certificates, policy)
	if err != nil {
		return nil, fmt.Errorf("invalid response signature: %w", err)
	}

	// Only the content that the signature covers is used.
	response = &ManageNameIDResponse{}
	if err = unmarshalElement(verified, response); err != nil {
		return nil, err
	}

	return response, nil
}
