package saml

import (
	"encoding/xml"
	"time"

	"github.com/beevik/etree"
)

// ManageNameIDRequest represents the SAML object of the same name, a request to change the identifier of a
// principal or to end its use (SAMLCore §3.6.1). Element is the way to serialize it, as the encrypted elements
// are not fields that [xml.Marshal] can write.
type ManageNameIDRequest struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol ManageNameIDRequest"`

	ID           string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Destination  string    `xml:",attr"`
	Consent      string    `xml:",attr"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element

	// Extensions are the protocol extensions of the message (SAMLCore §3.2.1, §3.2.2), or nil if there are none.
	Extensions *ProtocolExtensions `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`

	// NameID is the identifier of the principal, as the two providers know it before the request.
	NameID *NameID

	// EncryptedID is the EncryptedID element which identifies the principal in place of the NameID. Element
	// writes it and not the NameID when it is set. It isn't unmarshalled: the receiver decrypts it from the
	// element whose signature it verified.
	EncryptedID *etree.Element `xml:"-"`

	// NewID is the new identifier: the SPProvidedID when the requester is a service provider, and the value of
	// the NameID when it is the identity provider. It is written when the request has neither a
	// NewEncryptedID nor Terminate.
	NewID string `xml:"-"`

	// NewEncryptedID is the NewEncryptedID element which holds the new identifier in place of NewID. Element
	// writes it and not the NewID when it is set, and it isn't unmarshalled, like EncryptedID.
	NewEncryptedID *etree.Element `xml:"-"`

	// Terminate is whether the request ends the use of the identifier, with a Terminate element in place of
	// a new identifier.
	Terminate bool `xml:"-"`
}

// Element returns an etree.Element representing the object in XML form.
func (r *ManageNameIDRequest) Element() *etree.Element {
	el := etree.NewElement("samlp:ManageNameIDRequest")
	el.CreateAttr("xmlns:saml", samlAssertionNamespace)
	el.CreateAttr("xmlns:samlp", samlProtocolNS)
	el.CreateAttr("ID", r.ID)
	el.CreateAttr("Version", r.Version)
	el.CreateAttr("IssueInstant", RelaxedTime(r.IssueInstant).String())

	if r.Destination != "" {
		el.CreateAttr("Destination", r.Destination)
	}

	if r.Consent != "" {
		el.CreateAttr("Consent", r.Consent)
	}

	if r.Issuer != nil {
		el.AddChild(r.Issuer.Element())
	}

	if r.Signature != nil {
		el.AddChild(r.Signature)
	}

	if r.Extensions != nil {
		el.AddChild(r.Extensions.Element())
	}

	// The schema has one identifier, and a NameID must never be written beside its own ciphertext.
	switch {
	case r.EncryptedID != nil:
		el.AddChild(r.EncryptedID.Copy())
	case r.NameID != nil:
		el.AddChild(r.NameID.Element())
	}

	// The schema has one of these three, and a NewID must never be written beside its own ciphertext.
	switch {
	case r.NewEncryptedID != nil:
		el.AddChild(r.NewEncryptedID.Copy())
	case r.Terminate:
		el.CreateElement("samlp:Terminate")
	default:
		el.CreateElement("samlp:NewID").SetText(r.NewID)
	}

	return el
}

// UnmarshalXML implements [xml.Unmarshaler]. The EncryptedID and NewEncryptedID are not unmarshalled.
func (r *ManageNameIDRequest) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias ManageNameIDRequest

	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		NewID        *string     `xml:"urn:oasis:names:tc:SAML:2.0:protocol NewID"`
		Terminate    *struct{}   `xml:"urn:oasis:names:tc:SAML:2.0:protocol Terminate"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}

	r.IssueInstant = time.Time(aux.IssueInstant)
	r.Terminate = aux.Terminate != nil

	if aux.NewID != nil {
		r.NewID = *aux.NewID
	}

	return nil
}

func (r *ManageNameIDRequest) setSignature(signature *etree.Element) {
	r.Signature = signature
}

// ManageNameIDResponse represents the SAML object of the same name, the answer to a ManageNameIDRequest
// (SAMLCore §3.6.2).
type ManageNameIDResponse struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol ManageNameIDResponse"`
	ID           string    `xml:",attr"`
	InResponseTo string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Destination  string    `xml:",attr"`
	Consent      string    `xml:",attr"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element

	// Extensions are the protocol extensions of the message (SAMLCore §3.2.1, §3.2.2), or nil if there are none.
	Extensions *ProtocolExtensions `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
	Status     Status              `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
}

// Element returns an etree.Element representing the object in XML form.
func (r *ManageNameIDResponse) Element() *etree.Element {
	el := etree.NewElement("samlp:ManageNameIDResponse")
	statusResponseElement(el, r.ID, r.InResponseTo, r.Version, r.IssueInstant, r.Destination, r.Consent, r.Issuer, r.Signature, r.Extensions)
	el.AddChild(r.Status.Element())

	return el
}

// UnmarshalXML implements [xml.Unmarshaler].
func (r *ManageNameIDResponse) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias ManageNameIDResponse

	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}

	r.IssueInstant = time.Time(aux.IssueInstant)

	return nil
}

func (r *ManageNameIDResponse) setSignature(signature *etree.Element) {
	r.Signature = signature
}

// NameIDMappingRequest represents the SAML object of the same name, a request for the identifier of a principal
// in another format or in the namespace of another service provider (SAMLCore §3.8.1). Element is the way to
// serialize it, as the EncryptedID is not a field that [xml.Marshal] can write.
type NameIDMappingRequest struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDMappingRequest"`

	ID           string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Destination  string    `xml:",attr"`
	Consent      string    `xml:",attr"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element

	// Extensions are the protocol extensions of the message (SAMLCore §3.2.1, §3.2.2), or nil if there are none.
	Extensions *ProtocolExtensions `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`

	// NameID is the identifier of the principal, as the requester and the identity provider know it.
	NameID *NameID

	// EncryptedID is the EncryptedID element which identifies the principal in place of the NameID. Element
	// writes it and not the NameID when it is set. It isn't unmarshalled: the receiver decrypts it from the
	// element whose signature it verified.
	EncryptedID *etree.Element `xml:"-"`

	// NameIDPolicy states the format of the identifier to return and, as its SPNameQualifier, the service
	// provider whose identifier it is to be.
	NameIDPolicy *NameIDPolicy `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
}

// Element returns an etree.Element representing the object in XML form.
func (r *NameIDMappingRequest) Element() *etree.Element {
	el := etree.NewElement("samlp:NameIDMappingRequest")
	el.CreateAttr("xmlns:saml", samlAssertionNamespace)
	el.CreateAttr("xmlns:samlp", samlProtocolNS)
	el.CreateAttr("ID", r.ID)
	el.CreateAttr("Version", r.Version)
	el.CreateAttr("IssueInstant", RelaxedTime(r.IssueInstant).String())

	if r.Destination != "" {
		el.CreateAttr("Destination", r.Destination)
	}

	if r.Consent != "" {
		el.CreateAttr("Consent", r.Consent)
	}

	if r.Issuer != nil {
		el.AddChild(r.Issuer.Element())
	}

	if r.Signature != nil {
		el.AddChild(r.Signature)
	}

	if r.Extensions != nil {
		el.AddChild(r.Extensions.Element())
	}

	// The schema has one identifier, and a NameID must never be written beside its own ciphertext.
	switch {
	case r.EncryptedID != nil:
		el.AddChild(r.EncryptedID.Copy())
	case r.NameID != nil:
		el.AddChild(r.NameID.Element())
	}

	if r.NameIDPolicy != nil {
		el.AddChild(r.NameIDPolicy.Element())
	}

	return el
}

// UnmarshalXML implements [xml.Unmarshaler]. The EncryptedID is not unmarshalled.
func (r *NameIDMappingRequest) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias NameIDMappingRequest

	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}

	r.IssueInstant = time.Time(aux.IssueInstant)

	return nil
}

func (r *NameIDMappingRequest) setSignature(signature *etree.Element) {
	r.Signature = signature
}

// NameIDMappingResponse represents the SAML object of the same name, the answer to a NameIDMappingRequest
// (SAMLCore §3.8.2).
type NameIDMappingResponse struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDMappingResponse"`
	ID           string    `xml:",attr"`
	InResponseTo string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Destination  string    `xml:",attr"`
	Consent      string    `xml:",attr"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element

	// Extensions are the protocol extensions of the message (SAMLCore §3.2.1, §3.2.2), or nil if there are none.
	Extensions *ProtocolExtensions `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
	Status     Status              `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`

	// NameID is the mapped identifier in plaintext.
	NameID *NameID

	// EncryptedID is the EncryptedID element which holds the mapped identifier. Element writes it and not the
	// NameID when it is set, and it isn't unmarshalled: the entity it was encrypted to decrypts it, such as
	// with ServiceProvider.DecryptNameID.
	EncryptedID *etree.Element `xml:"-"`
}

// Element returns an etree.Element representing the object in XML form. The schema of SAMLCore §3.8.2 requires
// an identifier whatever the status is, so a response with neither a NameID nor an EncryptedID, which is one
// with an error status, is written with an empty NameID.
func (r *NameIDMappingResponse) Element() *etree.Element {
	el := etree.NewElement("samlp:NameIDMappingResponse")
	statusResponseElement(el, r.ID, r.InResponseTo, r.Version, r.IssueInstant, r.Destination, r.Consent, r.Issuer, r.Signature, r.Extensions)
	el.AddChild(r.Status.Element())

	// A NameID must never be written beside its own ciphertext.
	switch {
	case r.EncryptedID != nil:
		el.AddChild(r.EncryptedID.Copy())
	case r.NameID != nil:
		el.AddChild(r.NameID.Element())
	default:
		el.AddChild((&NameID{}).Element())
	}

	return el
}

// UnmarshalXML implements [xml.Unmarshaler]. The EncryptedID is not unmarshalled.
func (r *NameIDMappingResponse) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias NameIDMappingResponse

	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}

	r.IssueInstant = time.Time(aux.IssueInstant)

	return nil
}

func (r *NameIDMappingResponse) setSignature(signature *etree.Element) {
	r.Signature = signature
}

// statusResponseElement writes the attributes, Issuer and Signature of a StatusResponseType (SAMLCore §3.2.2)
// to el.
func statusResponseElement(el *etree.Element, id, inResponseTo, version string, issueInstant time.Time, destination, consent string, issuer *Issuer, signature *etree.Element, extensions *ProtocolExtensions) {
	el.CreateAttr("xmlns:saml", samlAssertionNamespace)
	el.CreateAttr("xmlns:samlp", samlProtocolNS)
	el.CreateAttr("ID", id)

	if inResponseTo != "" {
		el.CreateAttr("InResponseTo", inResponseTo)
	}

	el.CreateAttr("Version", version)
	el.CreateAttr("IssueInstant", RelaxedTime(issueInstant).String())

	if destination != "" {
		el.CreateAttr("Destination", destination)
	}

	if consent != "" {
		el.CreateAttr("Consent", consent)
	}

	if issuer != nil {
		el.AddChild(issuer.Element())
	}

	if signature != nil {
		el.AddChild(signature)
	}

	if extensions != nil {
		el.AddChild(extensions.Element())
	}
}
