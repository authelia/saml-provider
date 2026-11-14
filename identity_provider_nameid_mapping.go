package saml

import (
	"bytes"
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

// NameIDMappingProvider is an optional interface of a NameIDProvider, which is required to serve a
// NameIDMappingRequest (SAMLCore §3.8, SAMLProfiles §7). The NameIDProvider issues the identifiers, so it is
// what can tell which principal one of them names, and what that principal is called elsewhere. Without it
// those requests receive a Responder status with RequestUnsupported, and the metadata lists no
// NameIDMappingService.
type NameIDMappingProvider interface {
	// MapNameID returns the identifier, for the service provider in req.TargetMetadata, of the principal that
	// req.Request.NameID names for the requester in req.ServiceProviderMetadata. The request has been verified
	// to come from that requester, whose server made it, with no browser cookies, and the
	// NameIDMappingPolicy has allowed it to obtain identifiers of the target.
	//
	// The identifier of the request was decrypted if it was an EncryptedID. Its SPNameQualifier, when present,
	// names the requester or an affiliation it is a member of, and when omitted means the requester. It may be
	// of the transient format. MapNameID must return an error that wraps ErrUnknownPrincipal, or a nil NameID,
	// unless it is an identifier that the identity provider issued for that requester or affiliation and
	// still uses.
	//
	// The NameID returned must be of the format req.Format, or of a format that the provider chooses when
	// that is empty. Its empty Format, NameQualifier and SPNameQualifier are filled in, as for an assertion,
	// and its SPProvidedID must be what the target last set, if anything (SAMLCore §8.3.7). An identifier
	// that doesn't exist yet may only be created when req.AllowCreate is set (SAMLCore §3.4.1.1). An error
	// that wraps ErrInvalidNameIDPolicy says that no such identifier can be supplied, and sends Requester
	// with InvalidNameIDPolicy; any other error sends Responder. No error is sent to the requester.
	//
	// When req.Unidentified is set, the request named nobody, such as with an EncryptedID that couldn't be
	// decrypted, and req.Request.NameID is a random identifier that was never issued. MapNameID is still
	// called, so that such a request takes as long as one for an unknown principal, and what it returns is
	// ignored.
	MapNameID(r *http.Request, req *IdpNameIDMappingRequest) (*NameID, error)
}

// NameIDMappingPolicy is an interface used by IdentityProvider to decide which requester may obtain the
// identifiers that a principal has at which service provider, with a NameIDMappingRequest. It is the
// IdentityProvider.NameIDMappingPolicy field; without one every request is refused.
type NameIDMappingPolicy interface {
	// AllowNameIDMapping reports whether requester, which has been verified to have made the request, may
	// obtain the identifier of a principal for target. They are the same entity when the requester asks for
	// its own identifier in another format. It is asked before the principal is identified, and the answer
	// to a refused request doesn't tell whether the principal or the target exists.
	AllowNameIDMapping(r *http.Request, requester, target *EntityDescriptor) bool
}

// DefaultNameIDMappingPolicy is a NameIDMappingPolicy which allows what Targets lists. With nothing listed it
// refuses every request.
type DefaultNameIDMappingPolicy struct {
	// Targets maps the entity ID of a requester to the entity IDs of the service providers whose identifiers
	// it may obtain. A requester may only obtain its own identifiers in another format if it lists itself.
	Targets map[string][]string
}

// AllowNameIDMapping implements NameIDMappingPolicy.
func (p DefaultNameIDMappingPolicy) AllowNameIDMapping(_ *http.Request, requester, target *EntityDescriptor) bool {
	return slices.Contains(p.Targets[requester.EntityID], target.EntityID)
}

// IdpNameIDMappingRequest is used by IdentityProvider to handle a single NameIDMappingRequest.
type IdpNameIDMappingRequest struct {
	IDP           *IdentityProvider
	HTTPRequest   *http.Request
	RequestBuffer []byte

	// Request is the request. Once the principal is identified its NameID is the identifier of the principal,
	// decrypted if the request held an EncryptedID.
	Request NameIDMappingRequest

	// ServiceProviderMetadata is the metadata of the requester.
	ServiceProviderMetadata *EntityDescriptor

	// TargetMetadata is the metadata of the service provider whose identifier is requested: the one that the
	// SPNameQualifier of the NameIDPolicy names, or the requester when it names none (SAMLCore §3.4.1.1).
	// The mapped identifier is encrypted to it.
	TargetMetadata *EntityDescriptor

	// Format is the format of the identifier that is requested, or empty when the NameIDPolicy leaves it
	// open: when it has no Format, or the unspecified one, or the encrypted one, which only asks for an
	// EncryptedID and so for what every response holds.
	Format string

	// AllowCreate is whether the NameIDPolicy allows an identifier to be created for the request.
	AllowCreate bool

	Now time.Time

	// NameIDEncrypted is whether the request identified the principal with an EncryptedID.
	NameIDEncrypted bool

	// Unidentified is whether the identifier of the request can't be one that the identity provider shares
	// with the requester: an EncryptedID that couldn't be decrypted, or an identifier of another service
	// provider or of another identity provider. Request.NameID is then a random identifier that was never
	// issued, and the request is answered as one for an unknown principal is. See NameIDMappingProvider.
	Unidentified bool

	// verifiedEl is the element of the request that its signature covers, which the EncryptedID is taken
	// from.
	verifiedEl *etree.Element
}

func (req *IdpNameIDMappingRequest) header() protocolRequestHeader {
	return protocolRequestHeader{
		ID:           req.Request.ID,
		Version:      req.Request.Version,
		IssueInstant: req.Request.IssueInstant,
		Destination:  req.Request.Destination,
		Issuer:       req.Request.Issuer,
	}
}

// Validate checks that the request is valid and carries an enveloped signature by its issuer, which is how the
// requester authenticates itself on the SOAP binding (SAMLProfiles §7.3.1), and assigns the Request and
// ServiceProviderMetadata properties. An error which carries a status, as RequestStatus reports, is answered
// with it, and any other with Requester and RequestDenied. It doesn't decide whether the mapping is allowed, or
// identify the principal.
//
// The last check consumes the ID of the request in the ReplayStore of the identity provider (SAMLSec §6.1.2), so
// Validate returns nil once for a request, and a replay gets an error that wraps ErrReplayed and carries a
// Requester status with RequestDenied.
func (req *IdpNameIDMappingRequest) Validate() error {
	// This code runs before any authentication, and the cost of the XML parsing below is proportional to the
	// size of the request.
	if err := checkAuthnRequestSize(req.RequestBuffer); err != nil {
		return err
	}

	if err := xrv.Validate(bytes.NewReader(req.RequestBuffer)); err != nil {
		return err
	}

	root, err := parseRequestRoot(req.RequestBuffer, "NameIDMappingRequest")
	if err != nil {
		return err
	}

	// The size is limited and the XML validated above, as for a LogoutRequest, into a fixed type.
	if err = xml.Unmarshal(req.RequestBuffer, &req.Request); err != nil {
		return err
	}

	if err = req.header().checkTrust(); err != nil {
		return err
	}

	if err = req.verifyRequester(root); err != nil {
		return err
	}

	if err = req.header().checkRequestStage(req.Now, req.IDP.NameIDMappingURL.String()); err != nil {
		return err
	}

	if err = req.readNameIDPolicy(); err != nil {
		return err
	}

	return req.header().checkReplay(req.IDP, req.HTTPRequest, replayKindNameIDMappingRequest)
}

// verifyRequester verifies the enveloped signature of the request, whose root element is given, against the
// service provider of its Issuer, and assigns ServiceProviderMetadata, and Request from the content that the
// signature covers, with the trust checks repeated on it.
func (req *IdpNameIDMappingRequest) verifyRequester(root *etree.Element) error {
	serviceProviderID := req.Request.Issuer.Value

	var err error

	if req.ServiceProviderMetadata, req.verifiedEl, err = req.IDP.verifySOAPRequester(req.HTTPRequest, root, serviceProviderID); err != nil {
		return err
	}

	req.Request = NameIDMappingRequest{}
	if err = unmarshalElement(req.verifiedEl, &req.Request); err != nil {
		return err
	}

	if err = req.header().checkTrust(); err != nil {
		return err
	}

	if req.Request.Issuer.Value != serviceProviderID {
		return errors.New("signed request has a different issuer")
	}

	return nil
}

// readNameIDPolicy assigns Format and AllowCreate from the NameIDPolicy of the verified request, which SAMLCore
// §3.8.1 requires.
func (req *IdpNameIDMappingRequest) readNameIDPolicy() error {
	policies, err := findChildren(req.verifiedEl, samlProtocolNS, "NameIDPolicy")
	if err != nil || len(policies) != 1 || req.Request.NameIDPolicy == nil {
		return &statusError{StatusRequester, StatusRequestDenied, errors.New("request does not have exactly one NameIDPolicy")}
	}

	policy := req.Request.NameIDPolicy

	if policy.Format != nil && !isUnspecifiedNameIDFormat(*policy.Format) && *policy.Format != encryptedNameIDFormat {
		req.Format = *policy.Format
	}

	req.AllowCreate = policy.AllowCreate != nil && *policy.AllowCreate

	return nil
}

// MakeResponse returns the unsigned NameIDMappingResponse to the request with the given status and no
// identifier. It has no InResponseTo when the ID of the request is not valid.
func (req *IdpNameIDMappingRequest) MakeResponse(status Status) *NameIDMappingResponse {
	response := &NameIDMappingResponse{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		Version:      "2.0",
		IssueInstant: req.Now,
		// SAMLProfiles §7.4.2: the Issuer MUST be the responding identity provider.
		Issuer: &Issuer{Format: string(EntityNameIDFormat), Value: req.IDP.entityID()},
		Status: status,
	}

	if isValidAuthnRequestID(req.Request.ID) {
		response.InResponseTo = req.Request.ID
	}

	return response
}

// ServeNameIDMapping handles a SAML NameIDMappingRequest on the SOAP binding, at NameIDMappingURL, and answers
// on the same connection with a signed NameIDMappingResponse in a SOAP envelope (SAMLCore §3.8, SAMLProfiles
// §7). The request must carry an enveloped signature by its issuer, which must be a service provider that the
// ServiceProviderProvider knows.
//
// The requester asks for the identifier that the principal it names has in the namespace of the service
// provider that the SPNameQualifier of its NameIDPolicy names, the target, or its own identifier in another
// format when it names none. The NameIDMappingPolicy decides whether it may; without one nothing is allowed. The
// identifier is found by the NameIDProvider, which must implement NameIDMappingProvider.
//
// The mapped identifier is always returned as an EncryptedID that is encrypted to the encryption key of the
// target, never in plaintext and never to the requester (SAMLCore §3.8, SAMLProfiles §7.4.2, §7.5). So a
// requester which is not the target can pass the identifier on to the target, and can't read it or correlate
// the principal with it. A target with no key that the EncryptionCertificateEnforcer accepts can't be mapped
// to.
//
// Every SAML message gets a NameIDMappingResponse, which the schema requires to hold an identifier, so one with
// an error status holds an empty NameID:
//
//   - Requester with RequestUnsupported for a message that is not a NameIDMappingRequest, or a principal that
//     is identified with a BaseID;
//   - Requester with RequestDenied for a request that can't be verified, is expired, is for another
//     destination, or doesn't have exactly one identifier and one NameIDPolicy, and VersionMismatch for one of
//     another version;
//   - Responder with RequestUnsupported if the NameIDProvider is not a NameIDMappingProvider;
//   - Requester with InvalidNameIDPolicy if the target is unknown, can't be encrypted to or is not allowed by
//     the policy, which are not told apart, or if the provider can't supply the identifier (SAMLCore §3.8.3);
//   - Requester with UnknownPrincipal if the provider doesn't recognize the principal, if its identifier is
//     that of another service provider, or if it is an EncryptedID that can't be decrypted, which must not be
//     told apart from an unknown principal;
//   - Responder if the provider fails; and otherwise Success.
//
// A request that is not a POST gets StatusMethodNotAllowed, one that is not a SOAP 1.1 envelope gets a Client
// fault, and a failure to sign or write the response gets a Server fault.
func (idp *IdentityProvider) ServeNameIDMapping(w http.ResponseWriter, r *http.Request) {
	soap, ok := idp.receiveSOAPRequest(w, r)
	if !ok {
		return
	}

	req := &IdpNameIDMappingRequest{IDP: idp, HTTPRequest: r, RequestBuffer: soap.Body, Now: TimeNow()}

	var response *NameIDMappingResponse

	if soap.Message.Tag != "NameIDMappingRequest" || soap.Message.NamespaceURI() != samlProtocolNS {
		idp.logger().Printf("failed to handle name identifier mapping request: the message is not a NameIDMappingRequest")

		// MakeResponse answers it only if the ID is valid.
		req.Request.ID = soap.Message.SelectAttrValue("ID", "")
		response = req.MakeResponse(requesterStatus(StatusRequestUnsupported))
	} else if err := req.Validate(); err != nil {
		idp.logger().Printf("failed to validate name identifier mapping request: %s", err)

		response = req.MakeResponse(errorStatus(err))
	} else {
		response = idp.mapNameID(r, req)
	}

	if err := idp.writeSOAPMessage(w, response); err != nil {
		idp.logger().Printf("failed to write name identifier mapping response: %s", err)
		writeSOAPFault(w, &soapFault{Code: "Server", String: soapFaultStringProcessing})
	}
}

// mapNameID returns the unsigned response to the verified req. The target and the policy are decided before the
// principal is identified, so that a requester which may not map to a target learns nothing of any principal,
// and so does the key that the answer is encrypted to, so that nothing is looked up that couldn't be sent.
func (idp *IdentityProvider) mapNameID(r *http.Request, req *IdpNameIDMappingRequest) *NameIDMappingResponse {
	provider, ok := idp.nameIDProvider().(NameIDMappingProvider)
	if !ok {
		idp.logger().Printf("cannot map name identifier: the name identifier provider does not implement NameIDMappingProvider")

		return req.MakeResponse(Status{StatusCode: StatusCode{Value: StatusResponder, StatusCode: &StatusCode{Value: StatusRequestUnsupported}}})
	}

	encrypter, err := idp.nameIDMappingTarget(r, req)
	if err != nil {
		idp.logger().Printf("cannot map name identifier for %s: %s", req.ServiceProviderMetadata.EntityID, err)

		status, ok := RequestStatus(err)
		if !ok {
			status = Status{StatusCode: StatusCode{Value: StatusResponder}}
		}

		return req.MakeResponse(status)
	}

	subject, err := idp.identifySubject(r, req.verifiedEl, req.Request.NameID, req.ServiceProviderMetadata, true)
	if err != nil {
		idp.logger().Printf("failed to validate name identifier mapping request: %s", err)

		return req.MakeResponse(errorStatus(err))
	}

	req.Request.NameID, req.NameIDEncrypted, req.Unidentified = subject.NameID, subject.Encrypted, subject.Unidentified

	// An identifier that was sent in plaintext and isn't one of the requester's is refused without asking the
	// provider, as the requester knows what it sent. One that was encrypted is still looked up, so that the
	// time taken doesn't tell what became of the ciphertext.
	if req.Unidentified && !req.NameIDEncrypted {
		return req.MakeResponse(requesterStatus(StatusUnknownPrincipal))
	}

	nameID, err := provider.MapNameID(r, req)

	switch {
	case req.Unidentified, errors.Is(err, ErrUnknownPrincipal), err == nil && nameID == nil:
		return req.MakeResponse(requesterStatus(StatusUnknownPrincipal))
	case errors.Is(err, ErrInvalidNameIDPolicy):
		idp.logger().Printf("cannot map name identifier for %s: %s", req.ServiceProviderMetadata.EntityID, err)

		return req.MakeResponse(requesterStatus(StatusInvalidNameIDPolicy))
	case err != nil:
		idp.logger().Printf("cannot map name identifier for %s: %s", req.ServiceProviderMetadata.EntityID, err)

		return req.MakeResponse(Status{StatusCode: StatusCode{Value: StatusResponder}})
	}

	mapped, err := req.completeMappedNameID(nameID)
	if err != nil {
		idp.logger().Printf("cannot map name identifier for %s: %s", req.ServiceProviderMetadata.EntityID, err)

		return req.MakeResponse(Status{StatusCode: StatusCode{Value: StatusResponder}})
	}

	response := req.MakeResponse(Status{StatusCode: StatusCode{Value: StatusSuccess}})

	// SAMLCore §6.2: the identifier is encrypted first, and the response which contains the EncryptedID is
	// then signed. If it can't be encrypted, it is not sent.
	if response.EncryptedID, err = encrypter.encryptNameID(mapped); err != nil {
		idp.logger().Printf("cannot encrypt the mapped name identifier for %s: %s", req.TargetMetadata.EntityID, err)

		return req.MakeResponse(Status{StatusCode: StatusCode{Value: StatusResponder}})
	}

	return response
}

// nameIDMappingTarget assigns TargetMetadata, has the NameIDMappingPolicy decide whether the requester may map to
// it, and returns the encrypter of the mapped identifier to it. An unknown target, one that the policy doesn't
// allow and one that can't be encrypted to are the same error to the requester, Requester with
// InvalidNameIDPolicy, which SAMLCore §3.8.3 defines for an identity provider that is unable or unwilling to
// supply an identifier in the requested namespace. An affiliation can't be a target, as it has no single key.
func (idp *IdentityProvider) nameIDMappingTarget(r *http.Request, req *IdpNameIDMappingRequest) (*elementEncrypter, error) {
	refused := func(err error) error {
		return &statusError{StatusRequester, StatusInvalidNameIDPolicy, err}
	}

	req.TargetMetadata = req.ServiceProviderMetadata

	if q := req.Request.NameIDPolicy.SPNameQualifier; q != nil && *q != "" && *q != req.ServiceProviderMetadata.EntityID {
		target, err := idp.serviceProvider(r, *q)
		if errors.Is(err, os.ErrNotExist) {
			return nil, refused(errors.New("the target service provider is unknown"))
		} else if err != nil {
			return nil, fmt.Errorf("cannot find the target service provider: %w", err)
		}

		req.TargetMetadata = target
	}

	policy := idp.NameIDMappingPolicy
	if policy == nil {
		policy = DefaultNameIDMappingPolicy{}
	}

	if !policy.AllowNameIDMapping(r, req.ServiceProviderMetadata, req.TargetMetadata) {
		return nil, refused(fmt.Errorf("the policy does not allow a mapping to %s", req.TargetMetadata.EntityID))
	}

	encrypter, err := idp.serviceProviderElementEncrypter(req.TargetMetadata)
	if err != nil {
		return nil, refused(fmt.Errorf("cannot encrypt to %s: %w", req.TargetMetadata.EntityID, err))
	}

	return encrypter, nil
}

// completeMappedNameID returns a copy of the NameID that the provider mapped to, with an empty Format,
// SPNameQualifier or NameQualifier filled with the requested format, the entity ID of the target or that of the
// identity provider, as IdpAuthnRequest.completeNameID does for an assertion. It returns an error for an
// identifier that is not what was requested and allowed: one with no value, of another format than the request
// names, or in the namespace of another service provider than the target.
func (req *IdpNameIDMappingRequest) completeMappedNameID(nameID *NameID) (*NameID, error) {
	mapped := *nameID

	if mapped.Value == "" {
		return nil, errors.New("the provider returned a NameID with no value")
	}

	if mapped.Format == "" {
		mapped.Format = req.Format
	}

	if mapped.Format == encryptedNameIDFormat || (req.Format != "" && mapped.Format != req.Format) {
		return nil, fmt.Errorf("the provider returned a NameID of the format %q, which is not the one requested", mapped.Format)
	}

	// SAMLCore §8.3.6: a NameID of the entity format has no qualifiers.
	if !nameIDFormatHasQualifiers(mapped.Format) {
		mapped.NameQualifier, mapped.SPNameQualifier, mapped.SPProvidedID = "", "", ""

		return &mapped, nil
	}

	if mapped.SPNameQualifier == "" {
		mapped.SPNameQualifier = req.TargetMetadata.EntityID
	}

	if mapped.SPNameQualifier != req.TargetMetadata.EntityID {
		return nil, errors.New("the provider returned a NameID in the namespace of another service provider than the target")
	}

	if mapped.NameQualifier == "" {
		mapped.NameQualifier = req.IDP.entityID()
	}

	return &mapped, nil
}
