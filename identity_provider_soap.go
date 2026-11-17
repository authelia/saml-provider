package saml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
)

const (
	soapEnvelopeNS     = "http://schemas.xmlsoap.org/soap/envelope/"
	soapActorNext      = "http://schemas.xmlsoap.org/soap/actor/next"
	soapMaxMessageSize = 64 << 10
	soapActionSAML     = "http://www.oasis-open.org/committees/security"
)

const (
	soapFaultStringEnvelope       = "the request is not a SOAP 1.1 envelope"
	soapFaultStringMustUnderstand = "a header block that must be understood is not"
	soapFaultStringProcessing     = "the request could not be processed"
)

var (
	errSOAPNotXML         = errors.New("the request is not well-formed XML")
	errSOAPNotEnvelope    = errors.New("the root element is not a SOAP 1.1 Envelope")
	errSOAPNoBody         = errors.New("the envelope has no Body")
	errSOAPBodyChildren   = errors.New("the Body does not have exactly one child element")
	errSOAPContentType    = errors.New("the content type is not text/xml")
	errSOAPReadFailed     = errors.New("the request body could not be read")
	errSOAPMustUnderstand = errors.New("a header block that must be understood is not")
	errSOAPSerialize      = errors.New("the message could not be serialized")
)

// soapFault is a SOAP 1.1 Fault.
type soapFault struct {
	// Code is the local name of the fault code: Client, Server or MustUnderstand. It is written as soapenv:<Code>.
	Code string

	// String is the faultstring. It is a fixed constant, never the text of a Go error.
	String string
}

// soapRequest is a parsed SOAP 1.1 request.
type soapRequest struct {
	Envelope *etree.Document
	Headers  []*etree.Element // Children of Header.
	Body     []byte           // The single SAML message, serialized standalone with its in-scope namespaces.
	Message  *etree.Element   // Root of Body re-parsed.
}

// parseSOAPEnvelope validates buf with xrv, parses it, checks the Envelope and Body, and returns the envelope
// document, the header blocks, and the one Body child detached with its in-scope namespaces.
func parseSOAPEnvelope(buf []byte) (*etree.Document, []*etree.Element, *etree.Element, error) {
	if err := xrv.Validate(bytes.NewReader(buf)); err != nil {
		return nil, nil, nil, errSOAPNotXML
	}

	doc := etree.NewDocument()

	if err := doc.ReadFromBytes(buf); err != nil {
		return nil, nil, nil, errSOAPNotXML
	}

	root := doc.Root()

	if root == nil || root.Tag != "Envelope" || root.NamespaceURI() != soapEnvelopeNS {
		return nil, nil, nil, errSOAPNotEnvelope
	}

	var (
		header, body *etree.Element
	)

	for _, child := range root.ChildElements() {
		if child.NamespaceURI() != soapEnvelopeNS {
			continue
		}

		switch child.Tag {
		case "Header":
			if header == nil {
				header = child
			}
		case "Body":
			if body == nil {
				body = child
			}
		}
	}

	if body == nil {
		return nil, nil, nil, errSOAPNoBody
	}

	children := body.ChildElements()

	if len(children) != 1 {
		return nil, nil, nil, errSOAPBodyChildren
	}

	var headers []*etree.Element

	if header != nil {
		headers = header.ChildElements()
	}

	return doc, headers, detachSOAPBodyChild(children[0]), nil
}

// detachSOAPBodyChild copies el and declares on the copy every namespace in scope for el that the copy does not
// already declare, the nearest declaration winning.
func detachSOAPBodyChild(el *etree.Element) *etree.Element {
	c := el.Copy()

	declared := make(map[string]bool)

	for _, attr := range c.Attr {
		if name, ok := soapNamespaceDeclaration(attr); ok {
			declared[name] = true
		}
	}

	for p := el.Parent(); p != nil; p = p.Parent() {
		for _, attr := range p.Attr {
			name, ok := soapNamespaceDeclaration(attr)
			if !ok || declared[name] {
				continue
			}

			declared[name] = true

			c.Attr = append(c.Attr, etree.Attr{Space: attr.Space, Key: attr.Key, Value: attr.Value})
		}
	}

	return c
}

// soapNamespaceDeclaration returns the declared prefix (empty for the default namespace) and true if attr is an
// xmlns or xmlns:p declaration.
func soapNamespaceDeclaration(attr etree.Attr) (string, bool) {
	switch {
	case attr.Space == "" && attr.Key == "xmlns":
		return "", true
	case attr.Space == "xmlns":
		return attr.Key, true
	default:
		return "", false
	}
}

// readSOAPRequest reads a POSTed SOAP request. The method is checked by the caller.
func readSOAPRequest(r *http.Request, understood ...xml.Name) (*soapRequest, *soapFault) {
	req, err := readSOAPRequestError(r, understood)
	if err == nil {
		return req, nil
	}

	if errors.Is(err, errSOAPMustUnderstand) {
		return nil, &soapFault{Code: "MustUnderstand", String: soapFaultStringMustUnderstand}
	}

	return nil, &soapFault{Code: "Client", String: soapFaultStringEnvelope}
}

func readSOAPRequestError(r *http.Request, understood []xml.Name) (*soapRequest, error) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "text/xml" {
		return nil, errSOAPContentType
	}

	buf, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, soapMaxMessageSize))
	if err != nil {
		return nil, errSOAPReadFailed
	}

	envelope, headers, message, err := parseSOAPEnvelope(buf)
	if err != nil {
		return nil, err
	}

	for _, header := range headers {
		if soapHeaderMustBeUnderstood(header, understood) {
			return nil, errSOAPMustUnderstand
		}
	}

	out := etree.NewDocument()
	out.SetRoot(message)

	body, err := out.WriteToBytes()
	if err != nil {
		return nil, errSOAPSerialize
	}

	parsed := etree.NewDocument()

	if err = parsed.ReadFromBytes(body); err != nil || parsed.Root() == nil {
		return nil, errSOAPNotXML
	}

	return &soapRequest{Envelope: envelope, Headers: headers, Body: body, Message: parsed.Root()}, nil
}

// soapHeaderMustBeUnderstood returns true if the header block is addressed to this node, is marked
// mustUnderstand, and is not one of the understood names.
func soapHeaderMustBeUnderstood(header *etree.Element, understood []xml.Name) bool {
	if !soapHeaderAttrIsTrue(header, "mustUnderstand") {
		return false
	}

	if actor := soapHeaderAttr(header, "actor"); actor != "" && actor != soapActorNext {
		return false
	}

	name := xml.Name{Space: header.NamespaceURI(), Local: header.Tag}

	for _, u := range understood {
		if u == name {
			return false
		}
	}

	return true
}

func soapHeaderAttr(header *etree.Element, local string) string {
	for _, attr := range header.Attr {
		if attr.Key == local && attr.Space != "" && attr.Space != "xmlns" && attr.NamespaceURI() == soapEnvelopeNS {
			return attr.Value
		}
	}

	return ""
}

func soapHeaderAttrIsTrue(header *etree.Element, local string) bool {
	v := soapHeaderAttr(header, local)

	return v == "1" || v == "true"
}

// receiveSOAPRequest answers a non-POST with 405 and a bad envelope with a fault, logging the reason, and
// returns false in both cases.
func (idp *IdentityProvider) receiveSOAPRequest(w http.ResponseWriter, r *http.Request, understood ...xml.Name) (*soapRequest, bool) {
	if r.Method != http.MethodPost {
		idp.logger().Printf("failed to read SOAP request: %s", "the method is not POST")

		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)

		return nil, false
	}

	req, fault := readSOAPRequest(r, understood...)
	if fault != nil {
		idp.logger().Printf("failed to read SOAP request: %s", fault.String)

		writeSOAPFault(w, fault)

		return nil, false
	}

	return req, true
}

func newSOAPEnvelope() (*etree.Document, *etree.Element) {
	doc := etree.NewDocument()

	envelope := doc.CreateElement("soapenv:Envelope")
	envelope.CreateAttr("xmlns:soapenv", soapEnvelopeNS)

	return doc, envelope
}

func writeSOAPDocument(w http.ResponseWriter, status int, doc *etree.Document) error {
	buf, err := doc.WriteToBytes()
	if err != nil {
		return fmt.Errorf("failed to serialize SOAP envelope: %w", err)
	}

	return writeSOAPBytes(w, status, buf)
}

// writeSOAPBytes writes a serialized SOAP envelope.
func writeSOAPBytes(w http.ResponseWriter, status int, buf []byte) error {
	setNoCacheHeaders(w)
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(status)

	_, err := w.Write(buf)

	return err
}

// newSOAPResponse returns a SOAP envelope carrying the header blocks, if any, and the message.
func newSOAPResponse(headers []*etree.Element, message *etree.Element) *etree.Document {
	doc, envelope := newSOAPEnvelope()

	if len(headers) != 0 {
		header := envelope.CreateElement("soapenv:Header")

		for _, h := range headers {
			header.AddChild(h.Copy())
		}
	}

	envelope.CreateElement("soapenv:Body").AddChild(message.Copy())

	return doc
}

// writeSOAPResponse writes a 200 SOAP envelope carrying the header blocks, if any, and the message.
func writeSOAPResponse(w http.ResponseWriter, headers []*etree.Element, message *etree.Element) error {
	return writeSOAPDocument(w, http.StatusOK, newSOAPResponse(headers, message))
}

// writeSOAPFault writes a 500 SOAP envelope carrying the fault.
func writeSOAPFault(w http.ResponseWriter, fault *soapFault) {
	doc, envelope := newSOAPEnvelope()

	el := envelope.CreateElement("soapenv:Body").CreateElement("soapenv:Fault")
	el.CreateElement("faultcode").SetText("soapenv:" + fault.Code)
	el.CreateElement("faultstring").SetText(fault.String)

	if err := writeSOAPDocument(w, http.StatusInternalServerError, doc); err != nil {
		http.Error(w, soapFaultStringProcessing, http.StatusInternalServerError)
	}
}

// verifySOAPRequester looks up the service provider issuer and verifies message's enveloped signature against
// its signing keys. It returns the metadata and the element the signature covers. Every error is a *statusError:
// unknown issuer, no signature or a bad one is Requester/RequestDenied; any other lookup failure is Responder.
//
// A message on the SOAP binding must be signed, as SAMLProfiles §4.4.4.1 requires a LogoutRequest to be
// authenticated and the binding offers nothing else. The errors don't include the issuer, which is not verified.
func (idp *IdentityProvider) verifySOAPRequester(r *http.Request, message *etree.Element, issuer string) (*EntityDescriptor, *etree.Element, error) {
	metadata, err := idp.serviceProvider(r, issuer)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, &statusError{StatusRequester, StatusRequestDenied, errors.New("the service provider is unknown")}
	} else if err != nil {
		return nil, nil, &statusError{StatusResponder, "", fmt.Errorf("cannot find the service provider: %w", err)}
	}

	signatureEl, err := findChild(message, "http://www.w3.org/2000/09/xmldsig#", "Signature")
	if err != nil {
		return nil, nil, &statusError{StatusRequester, StatusRequestDenied, err}
	}

	if signatureEl == nil {
		return nil, nil, &statusError{StatusRequester, StatusRequestDenied, errors.New("the message is not signed")}
	}

	certificates, err := serviceProviderSigningCertificates(metadata)
	if err != nil {
		return nil, nil, &statusError{StatusResponder, "", err}
	}

	if len(certificates) == 0 {
		return nil, nil, &statusError{StatusRequester, StatusRequestDenied,
			errors.New("the message is signed but the service provider has no signing certificate")}
	}

	verified, err := verifyEnvelopedSignature(message, certificates)
	if err != nil {
		return nil, nil, &statusError{StatusRequester, StatusRequestDenied, fmt.Errorf("invalid message signature: %w", err)}
	}

	return metadata, verified, nil
}
