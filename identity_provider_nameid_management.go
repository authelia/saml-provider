package saml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
)

// maxSPProvidedIDLength is the longest NewID, in characters, that a service provider may register as its
// SPProvidedID. SAMLCore doesn't limit it; this is the limit that §8.3.7 puts on a persistent identifier, which
// it is carried beside in every NameID from then on.
const maxSPProvidedIDLength = 256

// NameIDManagementProvider is an optional interface of a NameIDProvider, which is required to serve a
// ManageNameIDRequest from a service provider (SAMLCore §3.6, SAMLProfiles §4.5). The NameIDProvider issues
// the identifiers, so it is what keeps the state of them that this protocol changes. Without it those requests
// receive a Responder status with RequestUnsupported, and the metadata lists no ManageNameIDService.
//
// SetSPProvidedID and TerminateNameID are given a request that has been verified to come from the service provider in
// req.ServiceProviderMetadata, which may have been made by the server of the service provider, as on the SOAP
// binding, with no browser cookies. The principal is req.Request.NameID, which was decrypted if the request held
// an EncryptedID. Its SPNameQualifier, when present, names that service provider or an affiliation it is a
// member of, and when omitted means that service provider. Both must return an error that wraps
// ErrUnknownPrincipal unless the identifier is one that the identity provider issued for that service provider
// or affiliation and still uses, and must never create a record for an identifier that it doesn't recognize.
// Any other error sends a Responder status. No error is sent to the service provider.
//
// Neither is called for a request that names nobody, which has req.Unidentified set, such as one with an
// EncryptedID that couldn't be decrypted: these methods change what is stored, so they are only ever given an
// identifier that the service provider sent and may use. Such a request is answered as one for an unknown
// principal is, without asking the provider.
type NameIDManagementProvider interface {
	// SetSPProvidedID records spProvidedID as the alias that the service provider has for the principal. From
	// then on the SPProvidedID of every NameID which carries that identifier to the service provider must be
	// this value (SAMLCore §3.6.3 as changed by errata E55, §8.3.7). In an assertion that is for
	// NameIDProvider.NameID to do. It replaces an earlier alias.
	//
	// The NameID that is recorded with a SessionParticipant doesn't need to be changed: the identity provider
	// asks SPProvidedID for the alias when it matches a LogoutRequest of the service provider with a session,
	// and when it sends the service provider a LogoutRequest, so the sessions that exist follow the change.
	SetSPProvidedID(r *http.Request, req *IdpManageNameIDRequest, spProvidedID string) error

	// SPProvidedID returns the alias that SetSPProvidedID last recorded for the principal that nameID names at
	// the service provider with the entity ID, or "" if there is none, such as after TerminateNameID. nameID is
	// the identifier that the identity provider issued, whatever its SPProvidedID attribute holds. An
	// identifier that isn't recognized is not an error here, or may be reported with ErrUnknownPrincipal:
	// both mean no alias.
	//
	// It only reads, and is called while a single logout is handled: for the identifier of a LogoutRequest
	// that the service provider signed and which carries an SPProvidedID that was not recorded when the session
	// was established, and for the identifier of each service provider that a logout is propagated to. r is
	// then the request of that logout, which may come from another service provider or from the browser.
	// Another error fails the match with the session, which sends a Responder status, and leaves a propagated
	// LogoutRequest with the identifier that was recorded.
	SPProvidedID(r *http.Request, serviceProviderEntityID string, nameID *NameID) (string, error)

	// TerminateNameID ends the use of the identifier between the identity provider and the service provider:
	// the service provider no longer accepts assertions with it (SAMLCore §3.6.3). State that is kept for the
	// identifier, such as the identifier itself, its SPProvidedID and the consent to it, should be deleted or
	// marked obsolete, and a later request of the service provider about the principal handled as if there
	// had been none (errata E12). The sessions of the principal should not be ended (errata E8), and they are
	// not changed by the identity provider: the service provider can still end one with a LogoutRequest that
	// carries the identifier it was established with, and a logout is still propagated to it with that
	// identifier. SPProvidedID must return "" from then on, as the alias went with the identifier.
	TerminateNameID(r *http.Request, req *IdpManageNameIDRequest) error
}

// spProvidedID returns the alias that the service provider with the entity ID most recently registered for the
// principal that nameID names, with a ManageNameIDRequest, or "" if it registered none or the NameIDProvider is
// not a NameIDManagementProvider. SAMLCore §8.3.7 requires the SPProvidedID of an identifier to be that alias, and
// §3.6.3, as changed by errata E55, requires the identity provider to use it when it communicates with the service
// provider using the identifier, so it is looked up whenever an identifier is compared or sent, rather than copied
// to every record of the identifier.
func (idp *IdentityProvider) spProvidedID(r *http.Request, serviceProviderEntityID string, nameID *NameID) (string, error) {
	provider, ok := idp.nameIDProvider().(NameIDManagementProvider)
	if !ok {
		return "", nil
	}

	issued := *nameID
	issued.SPProvidedID = ""

	alias, err := provider.SPProvidedID(r, serviceProviderEntityID, &issued)
	if errors.Is(err, ErrUnknownPrincipal) {
		return "", nil
	}

	return alias, err
}

// IdpManageNameIDRequest is used by IdentityProvider to handle a single ManageNameIDRequest from a service
// provider.
type IdpManageNameIDRequest struct {
	IDP           *IdentityProvider
	HTTPRequest   *http.Request
	RelayState    string
	RequestBuffer []byte

	// Request is the request. After Validate its NameID is the identifier of the principal, decrypted if the
	// request held an EncryptedID, and its NewID is the new identifier, decrypted if it held a NewEncryptedID.
	Request ManageNameIDRequest

	ServiceProviderMetadata *EntityDescriptor

	// ResponseEndpoint is the ManageNameIDService of the service provider which the response is sent to on
	// the front channel. It is nil on the SOAP binding, where the response goes back on the connection of
	// the request.
	ResponseEndpoint *Endpoint

	Now time.Time

	// RedirectQuery is the raw query string of a request on the HTTP-Redirect binding which is signed in the
	// query.
	RedirectQuery string

	// NameIDEncrypted is whether the request identified the principal with an EncryptedID.
	NameIDEncrypted bool

	// NewIDEncrypted is whether the request held its new identifier in a NewEncryptedID.
	NewIDEncrypted bool

	// Unidentified is whether the identifier of the request can't be one that the identity provider shares
	// with the service provider: an EncryptedID that couldn't be decrypted, or an identifier of another
	// service provider, of another identity provider, or of the transient format, which errata E12 has this
	// protocol never used with. Request.NameID is then a random identifier that was never issued, and the
	// request is answered as one for an unknown principal is, without the NameIDManagementProvider being
	// asked.
	Unidentified bool

	// binding is the binding that the request was received on.
	binding string

	// verifiedEl is the element of the request that its signature covers, which the encrypted elements are
	// taken from.
	verifiedEl *etree.Element
}

// NewIdpManageNameIDRequest returns a new IdpManageNameIDRequest for the given HTTP request to the name
// identifier management service, on the HTTP-Redirect or HTTP-POST binding.
func NewIdpManageNameIDRequest(idp *IdentityProvider, r *http.Request) (*IdpManageNameIDRequest, error) {
	req := &IdpManageNameIDRequest{IDP: idp, HTTPRequest: r, Now: TimeNow()}

	var err error

	if req.RequestBuffer, req.RelayState, req.RedirectQuery, req.binding, err = readFrontChannelRequest(r); err != nil {
		return nil, err
	}

	return req, nil
}

func (req *IdpManageNameIDRequest) header() protocolRequestHeader {
	return protocolRequestHeader{
		ID:           req.Request.ID,
		Version:      req.Request.Version,
		IssueInstant: req.Request.IssueInstant,
		Destination:  req.Request.Destination,
		Issuer:       req.Request.Issuer,
	}
}

// Validate checks that the request is valid and signed by its service provider, and assigns the Request,
// ServiceProviderMetadata and ResponseEndpoint properties. The signature is required on every binding:
// SAMLProfiles §4.5.3.1 requires it on HTTP-Redirect and HTTP-POST, and on SOAP it is the only way that the
// requester can authenticate itself (§4.5.4.1).
//
// An error which carries a status, as RequestStatus reports, is answered with it. On the front channel any
// other error means that the request must not be answered with a SAML response at all, because it failed before
// the requester was verified and the endpoint to answer it at was established from metadata. On the SOAP
// binding, where the answer goes back to the caller, such an error is answered with Requester and RequestDenied.
//
// The EncryptedID and NewEncryptedID are decrypted once the signature is verified. A NewEncryptedID that can't
// be decrypted is an error; an EncryptedID that can't be marks the request Unidentified.
//
// The last check consumes the ID of the request in the ReplayStore of the identity provider (SAMLSec §6.1.2), as
// IdpLogoutRequest.Validate does, so Validate returns nil once for a request: a request that is presented again,
// such as an older one whose NewID would undo a later change, gets an error that wraps ErrReplayed and carries a
// Requester status with RequestDenied, and a failure of the store one with a Responder status. Nothing is recorded
// for a request that fails any other check.
func (req *IdpManageNameIDRequest) Validate() error {
	// This code runs before any authentication, and the cost of the XML parsing below is proportional to the
	// size of the request.
	if err := checkAuthnRequestSize(req.RequestBuffer); err != nil {
		return err
	}

	if err := xrv.Validate(bytes.NewReader(req.RequestBuffer)); err != nil {
		return err
	}

	root, err := parseRequestRoot(req.RequestBuffer, "ManageNameIDRequest")
	if err != nil {
		return err
	}

	//nolint:gosec // G709: the size is limited and the XML validated above, as for a LogoutRequest, into a fixed type.
	if err = xml.Unmarshal(req.RequestBuffer, &req.Request); err != nil {
		return err
	}

	if err = req.header().checkTrust(); err != nil {
		return err
	}

	endpoint, err := req.verifyRequester(root)
	if err != nil {
		return err
	}

	if err = req.header().checkRequestStage(req.Now, endpoint); err != nil {
		return err
	}

	if err = req.readNewID(); err != nil {
		return err
	}

	subject, err := req.IDP.identifySubject(req.HTTPRequest, req.verifiedEl, req.Request.NameID, req.ServiceProviderMetadata, false)
	if err != nil {
		return err
	}

	req.Request.NameID, req.NameIDEncrypted, req.Unidentified = subject.NameID, subject.Encrypted, subject.Unidentified

	return req.header().checkReplay(req.IDP, req.HTTPRequest, replayKindManageNameIDRequest)
}

// verifyRequester verifies the signature of the request, whose root element is given, against the service
// provider of its Issuer, and assigns ServiceProviderMetadata, Request from the content that the signature
// covers, and on the front channel ResponseEndpoint. It returns the URL of the endpoint of the identity provider
// that the request was received at.
func (req *IdpManageNameIDRequest) verifyRequester(root *etree.Element) (string, error) {
	var err error

	if req.binding == SOAPBinding {
		if req.ServiceProviderMetadata, req.verifiedEl, err = req.IDP.verifySOAPRequester(req.HTTPRequest, root, req.Request.Issuer.Value); err != nil {
			return "", err
		}

		return req.IDP.SOAPManageNameIDURL.String(), req.useVerifiedRequest()
	}

	if req.ServiceProviderMetadata, req.verifiedEl, err = req.IDP.verifyFrontChannelRequester(req.HTTPRequest, root, req.RedirectQuery, req.Request.Issuer.Value); err != nil {
		return "", err
	}

	if err = req.useVerifiedRequest(); err != nil {
		return "", err
	}

	// SAMLBind §3.4.5.2 and §3.5.5.2 require this of a signed message. The value is checked by the caller.
	if req.Request.Destination == "" {
		return "", errors.New("signed request has no destination")
	}

	if req.ResponseEndpoint, err = req.IDP.manageNameIDResponseEndpoint(req.ServiceProviderMetadata, req.binding); err != nil {
		return "", err
	}

	return req.IDP.ManageNameIDURL.String(), nil
}

// useVerifiedRequest replaces Request with the content that the signature covers, and repeats the trust checks
// that were made on the original, as IdpAuthnRequest.useVerifiedRequest does.
func (req *IdpManageNameIDRequest) useVerifiedRequest() error {
	serviceProviderID := req.Request.Issuer.Value

	req.Request = ManageNameIDRequest{}
	if err := unmarshalElement(req.verifiedEl, &req.Request); err != nil {
		return err
	}

	if err := req.header().checkTrust(); err != nil {
		return err
	}

	if req.Request.Issuer.Value != serviceProviderID {
		return errors.New("signed request has a different issuer")
	}

	return nil
}

// readNewID checks that the verified request has exactly one of a NewID, a NewEncryptedID and a Terminate
// (SAMLCore §3.6.1), and assigns Request.NewID from a NewEncryptedID. Every error is Requester with
// RequestDenied.
//
// A NewEncryptedID must be encrypted with a block cipher in GCM mode. The answer to this request can't hide
// whether the NewEncryptedID was decrypted, as the answer to an undecryptable EncryptedID does, because a
// request that succeeds says that it was. With a cipher in CBC mode, which doesn't protect its own integrity,
// that would let a service provider use the identity provider to decrypt a ciphertext that it didn't make,
// by sending altered copies of it (errata E93). With GCM an altered ciphertext always fails, as does one
// that holds anything but a NewID, and every failure is answered alike.
func (req *IdpManageNameIDRequest) readNewID() error {
	denied := func(err error) error {
		return &statusError{StatusRequester, StatusRequestDenied, err}
	}

	var count [3]int

	for i, tag := range []string{"NewID", "NewEncryptedID", "Terminate"} {
		els, err := findChildren(req.verifiedEl, samlProtocolNS, tag)
		if err != nil {
			return denied(err)
		}

		count[i] = len(els)
	}

	if count[0]+count[1]+count[2] != 1 {
		return denied(errors.New("request does not have exactly one of a NewID, a NewEncryptedID and a Terminate"))
	}

	if count[2] == 1 {
		req.Request.NewID = ""

		return nil
	}

	if count[1] == 1 {
		req.NewIDEncrypted = true

		newID, err := req.decryptNewID()
		if err != nil {
			return denied(fmt.Errorf("cannot use the NewEncryptedID: %w", err))
		}

		req.Request.NewID = newID
	}

	if req.Request.NewID == "" || utf8.RuneCountInString(req.Request.NewID) > maxSPProvidedIDLength {
		return denied(fmt.Errorf("the NewID is empty or longer than %d characters", maxSPProvidedIDLength))
	}

	return nil
}

// decryptNewID returns the content of the NewID that the NewEncryptedID of the verified request holds
// (SAMLCore §3.6.1).
func (req *IdpManageNameIDRequest) decryptNewID() (string, error) {
	encryptedEl, err := findOneChild(req.verifiedEl, samlProtocolNS, "NewEncryptedID")
	if err != nil {
		return "", err
	}

	if !isAuthenticatedEncryption(encryptedEl) {
		return "", errors.New("it is not encrypted with a block cipher in GCM mode")
	}

	decrypter, err := req.IDP.elementDecrypter()
	if err != nil {
		return "", err
	}

	el, err := decrypter.decrypt(encryptedEl)
	if err != nil {
		return "", err
	}

	if el.Tag != "NewID" || el.NamespaceURI() != samlProtocolNS || len(el.ChildElements()) != 0 {
		return "", errors.New("it does not hold a NewID")
	}

	return el.Text(), nil
}

// MakeResponse returns the unsigned ManageNameIDResponse to the request with the given status. It has no
// Destination when there is no ResponseEndpoint, as on the SOAP binding, and no InResponseTo when the ID of
// the request is not valid.
func (req *IdpManageNameIDRequest) MakeResponse(status Status) *ManageNameIDResponse {
	response := &ManageNameIDResponse{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		Version:      "2.0",
		IssueInstant: req.Now,
		// SAMLProfiles §4.5.4.2: the Issuer MUST be the responding entity.
		Issuer: &Issuer{Format: string(EntityNameIDFormat), Value: req.IDP.MetadataURL.String()},
		Status: status,
	}

	if isValidAuthnRequestID(req.Request.ID) {
		response.InResponseTo = req.Request.ID
	}

	if req.ResponseEndpoint != nil {
		response.Destination = endpointResponseLocation(*req.ResponseEndpoint)
	}

	return response
}

// WriteResponse writes a signed ManageNameIDResponse with the given status: to the ResponseEndpoint, which
// Validate assigns, through the browser, or on the SOAP binding to w in a SOAP envelope. The response is always
// signed, which is how the identity provider authenticates itself (SAMLProfiles §4.5.3.2).
func (req *IdpManageNameIDRequest) WriteResponse(w http.ResponseWriter, status Status) error {
	response := req.MakeResponse(status)

	if req.binding == SOAPBinding {
		return req.IDP.writeSOAPMessage(w, response)
	}

	if req.ResponseEndpoint == nil {
		return errors.New("the request has no response endpoint")
	}

	return req.IDP.writeFrontChannelResponse(w, req.HTTPRequest, req.ResponseEndpoint.Binding, response.Destination, req.RelayState, response)
}

// ServeManageNameID handles a SAML ManageNameIDRequest from a service provider on the HTTP-Redirect or
// HTTP-POST binding, at ManageNameIDURL, and answers through the browser with a signed ManageNameIDResponse at
// a ManageNameIDService of its metadata (SAMLProfiles §4.5). The request must be signed. What it asks is done
// by the NameIDProvider, which must implement NameIDManagementProvider: to record its NewID or NewEncryptedID
// as the SPProvidedID of the principal, or with Terminate to end the use of the identifier. The sessions of the
// principal are not ended (errata E8). Once an SPProvidedID is recorded, a LogoutRequest of the service provider
// that carries it finds the sessions that were established before, and a LogoutRequest to the service provider
// carries it, as IdpLogoutRequest.MatchesSession and NameIDManagementProvider describe.
//
// A request that is invalid, can't be verified, or comes from a service provider with no ManageNameIDService
// for a supported binding gets a StatusBadRequest response. A verified request from a service provider with
// such an endpoint is answered there:
//
//   - Requester with RequestDenied if it is expired, for another destination, or doesn't have exactly one
//     identifier and one of NewID, NewEncryptedID and Terminate, or its NewEncryptedID can't be used;
//   - VersionMismatch if it is of another version;
//   - Responder with RequestUnsupported if the NameIDProvider is not a NameIDManagementProvider;
//   - Requester with UnknownPrincipal if the provider doesn't recognize the identifier, or, without the
//     provider being asked, if it is one of the transient format (errata E12) or of another service provider,
//     or an EncryptedID that can't be decrypted, which must not be told apart from an unknown principal;
//   - Responder if the provider fails; and otherwise Success.
//
// The identity provider doesn't send a ManageNameIDRequest on the front channel, so a ManageNameIDResponse
// here is refused like any other invalid request.
func (idp *IdentityProvider) ServeManageNameID(w http.ResponseWriter, r *http.Request) {
	req, err := NewIdpManageNameIDRequest(idp, r)
	if err != nil {
		idp.logger().Printf("failed to parse name identifier management request: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

		return
	}

	var status Status

	if err = req.Validate(); err != nil {
		idp.logger().Printf("failed to validate name identifier management request: %s", err)

		var ok bool

		if status, ok = RequestStatus(err); !ok {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

			return
		}
	} else {
		status = idp.manageNameIDStatus(r, req)
	}

	if err = req.WriteResponse(w, status); err != nil {
		idp.logger().Printf("failed to write name identifier management response: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// ServeSOAPManageNameID handles a SAML ManageNameIDRequest from a service provider on the SOAP binding, at
// SOAPManageNameIDURL, and answers on the same connection with a signed ManageNameIDResponse in a SOAP envelope
// (SAMLProfiles §4.5, SAMLBind §3.2). The request must carry an enveloped signature by its issuer, which is how
// the requester authenticates itself (SAMLProfiles §4.5.3.1). It is otherwise handled as ServeManageNameID
// describes.
//
// Every SAML message gets a ManageNameIDResponse: one that is not a ManageNameIDRequest gets Requester with
// RequestUnsupported, and one that can't be verified Requester with RequestDenied. A request that is not a POST
// gets StatusMethodNotAllowed, one that is not a SOAP 1.1 envelope gets a Client fault, and a failure to sign or
// write the response gets a Server fault.
func (idp *IdentityProvider) ServeSOAPManageNameID(w http.ResponseWriter, r *http.Request) {
	soap, ok := idp.receiveSOAPRequest(w, r)
	if !ok {
		return
	}

	req := &IdpManageNameIDRequest{IDP: idp, HTTPRequest: r, RequestBuffer: soap.Body, Now: TimeNow(), binding: SOAPBinding}

	var status Status

	if soap.Message.Tag != "ManageNameIDRequest" || soap.Message.NamespaceURI() != samlProtocolNS {
		idp.logger().Printf("failed to handle SOAP name identifier management request: the message is not a ManageNameIDRequest")

		// MakeResponse answers it only if the ID is valid.
		req.Request.ID = soap.Message.SelectAttrValue("ID", "")
		status = requesterStatus(StatusRequestUnsupported)
	} else if err := req.Validate(); err != nil {
		idp.logger().Printf("failed to validate SOAP name identifier management request: %s", err)

		status = errorStatus(err)
	} else {
		status = idp.manageNameIDStatus(r, req)
	}

	if err := req.WriteResponse(w, status); err != nil {
		idp.logger().Printf("failed to write SOAP name identifier management response: %s", err)
		writeSOAPFault(w, &soapFault{Code: "Server", String: soapFaultStringProcessing})
	}
}

// manageNameIDStatus has the NameIDProvider do what the verified req asks, and returns the status of its
// ManageNameIDResponse.
func (idp *IdentityProvider) manageNameIDStatus(r *http.Request, req *IdpManageNameIDRequest) Status {
	provider, ok := idp.nameIDProvider().(NameIDManagementProvider)
	if !ok {
		idp.logger().Printf("cannot manage name identifier: the name identifier provider does not implement NameIDManagementProvider")

		return Status{StatusCode: StatusCode{Value: StatusResponder, StatusCode: &StatusCode{Value: StatusRequestUnsupported}}}
	}

	// A request that names nobody is refused without asking the provider, whose methods change what is stored
	// and must never be given the stand-in for an identifier that couldn't be decrypted or isn't one of the
	// requester's. SAMLCore §3.6.3: an identifier that isn't recognized MUST be answered with an error status,
	// and this is the status of every such identifier, so the answer doesn't tell them apart (errata E93).
	if req.Unidentified {
		return requesterStatus(StatusUnknownPrincipal)
	}

	var err error

	if req.Request.Terminate {
		err = provider.TerminateNameID(r, req)
	} else {
		err = provider.SetSPProvidedID(r, req, req.Request.NewID)
	}

	switch {
	case errors.Is(err, ErrUnknownPrincipal):
		// SAMLCore §3.6.3: an identifier that isn't recognized MUST be answered with an error status.
		return requesterStatus(StatusUnknownPrincipal)
	case err != nil:
		idp.logger().Printf("cannot manage name identifier: %s", err)

		return Status{StatusCode: StatusCode{Value: StatusResponder}}
	default:
		return Status{StatusCode: StatusCode{Value: StatusSuccess}}
	}
}
