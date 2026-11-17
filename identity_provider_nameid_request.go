package saml

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/beevik/etree"

	"authelia.com/provider/saml/internal/dsig"
)

// ErrUnknownPrincipal is returned by a NameIDManagementProvider or a NameIDMappingProvider which doesn't
// recognize the identifier of a request. The requester receives a Requester status with an UnknownPrincipal
// second-level status (SAMLCore §3.6.3, §3.8.3).
var ErrUnknownPrincipal = errors.New("the principal is unknown")

// signableMessage is a protocol message that is signed with an enveloped signature.
type signableMessage interface {
	Element() *etree.Element
	setSignature(signature *etree.Element)
}

// signMessageEnveloped signs message with an enveloped signature and returns its element, for a binding which
// carries the signature in the message.
func signMessageEnveloped(signingContext *dsig.SigningContext, message signableMessage) (*etree.Element, error) {
	signedEl, err := signingContext.SignEnveloped(message.Element())
	if err != nil {
		return nil, err
	}

	// SAMLCore requires the signature to follow the Issuer, rather than come last.
	message.setSignature(signedEl.ChildElements()[len(signedEl.ChildElements())-1])

	return message.Element(), nil
}

// protocolRequestHeader is the content of the RequestAbstractType of SAMLCore §3.2.1 that every request is
// checked for.
type protocolRequestHeader struct {
	ID           string
	Version      string
	IssueInstant time.Time
	Destination  string
	Issuer       *Issuer
}

// checkTrust makes the checks on the identity of a request that are needed before its issuer can be looked up.
// Nothing in the request is acted on before these pass.
func (h protocolRequestHeader) checkTrust() error {
	if !isValidAuthnRequestID(h.ID) {
		// The value is not included because this error is logged without authentication.
		return errors.New("invalid request ID")
	}

	if h.Issuer == nil || h.Issuer.Value == "" {
		return errors.New("request has no issuer")
	}

	// SAMLProfiles §4.5.4.1: the Format MUST be omitted or be that of an entity.
	if h.Issuer.Format != "" && h.Issuer.Format != string(EntityNameIDFormat) {
		return errors.New("request has an issuer which is not of the entity format")
	}

	return nil
}

// checkRequestStage makes the checks on the content of a request that are reported to the requester as a SAML
// status: its version, its age, and its Destination, which must be the endpoint when it is present. The request
// must have been verified, and the error is a *statusError.
func (h protocolRequestHeader) checkRequestStage(now time.Time, endpoint string) error {
	if statusErr := versionStatus(h.Version); statusErr != nil {
		return statusErr
	}

	if h.IssueInstant.Add(MaxIssueDelay).Before(now) {
		return &statusError{StatusRequester, StatusRequestDenied,
			fmt.Errorf("request expired at %s", h.IssueInstant.Add(MaxIssueDelay))}
	}

	if h.IssueInstant.After(now.Add(MaxClockSkew)) {
		return &statusError{StatusRequester, StatusRequestDenied,
			fmt.Errorf("request issued in the future at %s", h.IssueInstant)}
	}

	// SAMLBind §3.4.5.2 and §3.5.5.2 require the Destination of a signed message on the front channel, which
	// the caller has checked is present. SAMLBind §3.2 has no such requirement on SOAP, but a Destination that
	// is present must be this endpoint (SAMLCore §3.2.1).
	if h.Destination != "" && h.Destination != endpoint {
		return &statusError{StatusRequester, StatusRequestDenied,
			fmt.Errorf("expected destination to be %q, not %q", endpoint, h.Destination)}
	}

	return nil
}

// readFrontChannelRequest returns the SAMLRequest of r, on the HTTP-Redirect binding for a GET and the HTTP-POST
// binding for a POST, with its RelayState, and the query string if it carries a signature.
func readFrontChannelRequest(r *http.Request) (buf []byte, relayState, redirectQuery, binding string, err error) {
	switch r.Method {
	case http.MethodGet:
		buf, relayState, redirectQuery, err = readRedirectRequest(r.URL.RawQuery)

		return buf, relayState, redirectQuery, HTTPRedirectBinding, err
	case http.MethodPost:
		if r.Body != nil {
			r.Body = http.MaxBytesReader(nil, r.Body, maxAuthnRequestBodySize)
		}

		if err = r.ParseForm(); err != nil {
			return nil, "", "", "", err
		}

		if buf, err = base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLRequest")); err != nil {
			return nil, "", "", "", err
		}

		return buf, r.PostForm.Get("RelayState"), "", HTTPPostBinding, nil
	default:
		return nil, "", "", "", errors.New("method not allowed")
	}
}

// verifyFrontChannelRequester looks up the service provider issuer and verifies the signature of the message
// root, which is required: in the query on the HTTP-Redirect binding, enveloped on HTTP-POST. It returns the
// metadata and the element that the signature covers. The errors are not statuses, as nothing can be answered
// to a requester that isn't verified, and they don't include the issuer, which is not verified.
func (idp *IdentityProvider) verifyFrontChannelRequester(r *http.Request, root *etree.Element, redirectQuery, issuer string) (*EntityDescriptor, *etree.Element, error) {
	metadata, err := idp.serviceProvider(r, issuer)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, errors.New("cannot handle request from unknown service provider")
	} else if err != nil {
		return nil, nil, fmt.Errorf("cannot find service provider: %w", err)
	}

	signatureEl, err := findChild(root, "http://www.w3.org/2000/09/xmldsig#", "Signature")
	if err != nil {
		return nil, nil, err
	}

	if redirectQuery == "" && signatureEl == nil {
		return nil, nil, errors.New("request is not signed")
	}

	certificates, err := serviceProviderSigningCertificates(metadata)
	if err != nil {
		return nil, nil, err
	}

	if len(certificates) == 0 {
		return nil, nil, errors.New("request is signed but the service provider has no signing certificate")
	}

	var verified *etree.Element

	if redirectQuery != "" {
		if err = verifyRedirectSignature(redirectQuery, "SAMLRequest", certificates); err != nil {
			return nil, nil, fmt.Errorf("invalid request signature: %w", err)
		}

		// The signature in the query covers the whole message.
		verified = root
	}

	if signatureEl != nil {
		if verified, err = verifyEnvelopedSignature(root, certificates); err != nil {
			return nil, nil, fmt.Errorf("invalid request signature: %w", err)
		}
	}

	return metadata, verified, nil
}

// parseRequestRoot returns the root element of the request in buf, which must be the protocol element named
// tag.
func parseRequestRoot(buf []byte, tag string) (*etree.Element, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(buf); err != nil {
		return nil, err
	}

	root := doc.Root()
	if root == nil {
		return nil, errors.New("request has no root element")
	}

	if root.Tag != tag || root.NamespaceURI() != samlProtocolNS {
		return nil, fmt.Errorf("request is not a %s", tag)
	}

	return root, nil
}

// manageNameIDResponseEndpoint returns the ManageNameIDService of the service provider to deliver a response to
// on the front channel (SAMLProfiles §4.5.3.2). It prefers the binding of the request, and otherwise
// HTTP-Redirect and then HTTP-POST, which are the only bindings supported. An endpoint whose response location
// is insecure, as described by AllowInsecureServiceProviderEndpoints, is skipped.
func (idp *IdentityProvider) manageNameIDResponseEndpoint(metadata *EntityDescriptor, binding string) (*Endpoint, error) {
	var insecure error

	for _, binding := range []string{binding, HTTPRedirectBinding, HTTPPostBinding} {
		for i := range metadata.SPSSODescriptors {
			endpoints := metadata.SPSSODescriptors[i].ManageNameIDServices

			for j := range endpoints {
				if endpoints[j].Binding != binding {
					continue
				}

				if err := idp.CheckServiceProviderEndpoint(endpointResponseLocation(endpoints[j])); err != nil {
					insecure = err

					continue
				}

				return &endpoints[j], nil
			}
		}
	}

	if insecure != nil {
		return nil, fmt.Errorf("service provider %s has no secure ManageNameIDService: %w", metadata.EntityID, insecure)
	}

	return nil, fmt.Errorf("service provider %s has no ManageNameIDService with a supported binding", metadata.EntityID)
}

// writeFrontChannelResponse sends the signed message to destination through the browser, as a SAMLResponse on
// binding. On the HTTP-Redirect binding the signature is in the query, as SAMLBind §3.4.4.1 requires, and on
// the HTTP-POST binding it is enveloped. The destination must be an endpoint from metadata which passed
// CheckServiceProviderEndpoint.
func (idp *IdentityProvider) writeFrontChannelResponse(w http.ResponseWriter, r *http.Request, binding, destination, relayState string, message signableMessage) error {
	signingContext, err := idp.signingContext()
	if err != nil {
		return err
	}

	switch binding {
	case HTTPRedirectBinding:
		u, err := redirectURLWithContext(destination, "SAMLResponse", message.Element(), relayState, signingContext)
		if err != nil {
			return err
		}

		setNoCacheHeaders(w)
		http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // G710: the location is from the service provider metadata, not the request.

		return nil
	case HTTPPostBinding:
		el, err := signMessageEnveloped(signingContext, message)
		if err != nil {
			return err
		}

		doc := etree.NewDocument()
		doc.SetRoot(el)

		buf, err := doc.WriteToBytes()
		if err != nil {
			return err
		}

		tmpl := idp.ResponseFormTemplate
		if tmpl == nil {
			tmpl = defaultResponseFormTemplate
		}

		form := IdpAuthnRequestForm{
			URL:          destination,
			SAMLResponse: base64.StdEncoding.EncodeToString(buf),
			RelayState:   relayState,
		}

		var body bytes.Buffer
		if err = tmpl.Execute(&body, form); err != nil {
			return err
		}

		setNoCacheHeaders(w)

		_, err = w.Write(body.Bytes())

		return err
	default:
		return fmt.Errorf("unsupported binding %s", binding)
	}
}

// writeSOAPMessage answers a SOAP request on w with the signed message in a SOAP envelope.
func (idp *IdentityProvider) writeSOAPMessage(w http.ResponseWriter, message signableMessage) error {
	signingContext, err := idp.signingContext()
	if err != nil {
		return err
	}

	el, err := signMessageEnveloped(signingContext, message)
	if err != nil {
		return err
	}

	return writeSOAPResponse(w, nil, el)
}

// requestSubject is the principal that a request about a name identifier names.
type requestSubject struct {
	// NameID is the identifier, decrypted if the request held an EncryptedID. It is a random identifier that
	// was never issued when the subject is Unidentified.
	NameID *NameID

	// Encrypted is whether the request held an EncryptedID.
	Encrypted bool

	// Unidentified is whether the identifier can't be one that the identity provider shares with the
	// requester: an EncryptedID that couldn't be decrypted, or an identifier of another service provider, of
	// another identity provider, or of a format that the protocol isn't used with.
	Unidentified bool
}

// identifySubject returns the principal that the verified request element names with a NameID or an EncryptedID
// (SAMLCore §3.6.1, §3.8.1). It must only run once the signature is verified, as the EncryptedID is taken from the
// content that the signature covers and decrypted with the key of the identity provider: SAMLCore §6.2 has the
// requester encrypt and then sign, and errata E93 has the receiver require integrity protection before it
// processes encrypted data. nameID is the NameID unmarshalled from that element.
//
// A request with no identifier or more than one, or with a NameID that has no value, is an error with a
// Requester status and RequestDenied, and one with a BaseID, which is not supported, is RequestUnsupported.
// Every other reason for which the identifier is not one that the requester shares with the identity provider
// is not an error: the subject is Unidentified, with a random NameID, and the reason is only logged. All of them
// are then answered alike, as an unknown principal, because an answer which tells the requester that an
// EncryptedID was decrypted, or what it held, would let it use the identity provider to learn about a ciphertext
// that it didn't make (errata E93), as IdpLogoutRequest.Unidentified describes.
func (idp *IdentityProvider) identifySubject(r *http.Request, verified *etree.Element, nameID *NameID, metadata *EntityDescriptor, allowTransient bool) (requestSubject, error) {
	var count [3]int

	for i, tag := range []string{"NameID", "EncryptedID", "BaseID"} {
		els, err := findChildren(verified, samlAssertionNamespace, tag)
		if err != nil {
			return requestSubject{}, &statusError{StatusRequester, StatusRequestDenied, err}
		}

		count[i] = len(els)
	}

	switch {
	case count[2] != 0:
		return requestSubject{}, &statusError{StatusRequester, StatusRequestUnsupported,
			errors.New("request identifies the principal with a BaseID, which is not supported")}
	case count[0]+count[1] != 1:
		return requestSubject{}, &statusError{StatusRequester, StatusRequestDenied,
			errors.New("request does not have exactly one of a NameID and an EncryptedID")}
	}

	subject := requestSubject{NameID: nameID, Encrypted: count[1] == 1}

	var reason error

	if subject.Encrypted {
		encryptedIDEl, err := findOneChild(verified, samlAssertionNamespace, "EncryptedID")
		if err != nil {
			return requestSubject{}, &statusError{StatusRequester, StatusRequestDenied, err}
		}

		decrypter, err := idp.elementDecrypter()
		if err == nil {
			subject.NameID, err = decrypter.decryptNameID(encryptedIDEl)
		}

		if err != nil {
			reason = fmt.Errorf("cannot decrypt the EncryptedID: %w", err)
		}
	} else if nameID == nil || nameID.Value == "" {
		return requestSubject{}, &statusError{StatusRequester, StatusRequestDenied, errors.New("request has a NameID with no value")}
	}

	if reason == nil {
		reason = idp.checkSubjectNameID(r, subject.NameID, metadata, allowTransient)
	}

	if reason != nil {
		idp.logger().Printf("the principal of the request from %s is not identified: %s", metadata.EntityID, reason)

		// The stand-in is 256 bits from RandReader, so it is not the identifier of anyone.
		subject.Unidentified = true
		subject.NameID = &NameID{
			Format: string(TransientNameIDFormat),
			Value:  base64.RawURLEncoding.EncodeToString(randomBytes(32)),
		}
	}

	return subject, nil
}

// checkSubjectNameID returns an error unless nameID can be an identifier that the identity provider shares with
// the service provider whose metadata is given.
//
//   - Its Format must not be transient unless allowTransient: errata E12 has the Name Identifier Management
//     protocol never used with a transient identifier (SAMLCore §3.6).
//   - Its SPNameQualifier, if present, must name the service provider or an affiliation that it is a member of
//     (SAMLCore §3.6.3, §8.3.7).
//   - The NameQualifier of a persistent identifier, if present, must name the identity provider, which created
//     it (SAMLCore §3.6.3, §8.3.7).
//
// An omitted qualifier is accepted: SAMLCore §3.6.3 allows it, though it is not recommended.
func (idp *IdentityProvider) checkSubjectNameID(r *http.Request, nameID *NameID, metadata *EntityDescriptor, allowTransient bool) error {
	if !allowTransient && nameID.Format == string(TransientNameIDFormat) {
		return errors.New("the NameID is of the transient format")
	}

	if nameID.Format == string(EncryptedNameIDFormat) {
		return errors.New("the NameID is of the encrypted format, which is not a format of an identifier")
	}

	if q := nameID.SPNameQualifier; q != "" && q != metadata.EntityID {
		if err := idp.checkAffiliation(r, metadata.EntityID, q); err != nil {
			return fmt.Errorf("the NameID has the SPNameQualifier of another service provider: %w", err)
		}
	}

	if q := nameID.NameQualifier; q != "" && nameID.Format == string(PersistentNameIDFormat) && q != idp.entityID() {
		return errors.New("the NameID has the NameQualifier of another identity provider")
	}

	return nil
}

// isAuthenticatedEncryption reports whether the EncryptedData of encryptedEl is encrypted with a block cipher in
// GCM mode, which protects the integrity of what it encrypts, unlike one in CBC mode (errata E93).
func isAuthenticatedEncryption(encryptedEl *etree.Element) bool {
	methodEl := encryptedEl.FindElement("./EncryptedData/EncryptionMethod")

	return methodEl != nil && strings.HasSuffix(methodEl.SelectAttrValue("Algorithm", ""), "-gcm")
}

// requesterStatus is the Status of a request that is refused for what it asks, with a second-level status.
func requesterStatus(second string) Status {
	return Status{StatusCode: StatusCode{Value: StatusRequester, StatusCode: &StatusCode{Value: second}}}
}

// errorStatus returns the Status to answer a request with for an error of Validate on the SOAP binding, where
// every verified or unverified SAML message is answered: the status that the error carries, or else Requester
// with RequestDenied.
func errorStatus(err error) Status {
	if status, ok := RequestStatus(err); ok {
		return status
	}

	return requesterStatus(StatusRequestDenied)
}

// checkReplay consumes the ID of the request in the ReplayStore of idp, for the kind of the message. It must be
// the last check of the request, once it is verified, so that only a registered service provider can add to the
// store. The ID is recorded until the request would be refused for its age, which is MaxIssueDelay after its
// IssueInstant, and MaxClockSkew longer. The error is a *statusError, as IdentityProvider.checkReplay describes.
func (h protocolRequestHeader) checkReplay(idp *IdentityProvider, r *http.Request, kind string) error {
	return idp.checkReplay(requestContext(r), kind, h.Issuer.Value, h.ID, h.IssueInstant.Add(MaxIssueDelay))
}
