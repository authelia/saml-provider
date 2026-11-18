package saml

import (
	"encoding/xml"
	"time"

	"github.com/beevik/etree"
)

// AttributeQuery represents the SAML object of the same name, a request from a service provider for
// the attributes of a subject.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §3.3.2.3.
type AttributeQuery struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AttributeQuery"`

	ID           string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Destination  string    `xml:",attr"`
	Consent      string    `xml:",attr"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element

	// Extensions are the protocol extensions of the message (SAMLCore §3.2.1, §3.2.2), or nil if there are none.
	Extensions *ProtocolExtensions `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`

	Subject *Subject

	// Attributes lists the attributes to return, and none means every attribute that policy allows. An
	// attribute with values asks for those values only.
	Attributes []Attribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

// Element returns an etree.Element representing the object in XML form.
func (r *AttributeQuery) Element() *etree.Element {
	el := newQueryElement("samlp:AttributeQuery", r.ID, r.Version, r.IssueInstant, r.Destination, r.Consent, r.Issuer, r.Signature, r.Extensions)

	if r.Subject != nil {
		el.AddChild(r.Subject.Element())
	}

	for i := range r.Attributes {
		el.AddChild(r.Attributes[i].Element())
	}

	return el
}

// MarshalXML implements [xml.Marshaler].
func (r *AttributeQuery) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias AttributeQuery

	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		*Alias
	}{
		IssueInstant: RelaxedTime(r.IssueInstant),
		Alias:        (*Alias)(r),
	}

	return e.Encode(aux)
}

// UnmarshalXML implements [xml.Unmarshaler].
func (r *AttributeQuery) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias AttributeQuery

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

// AuthnQuery represents the SAML object of the same name, a request from a service provider for
// statements about the authentication of a subject that has already happened.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §3.3.2.2.
type AuthnQuery struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnQuery"`

	ID           string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Destination  string    `xml:",attr"`
	Consent      string    `xml:",attr"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element

	// Extensions are the protocol extensions of the message (SAMLCore §3.2.1, §3.2.2), or nil if there are none.
	Extensions *ProtocolExtensions `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`

	Subject *Subject

	// SessionIndex limits the answer to the session with that index.
	SessionIndex string `xml:",attr"`

	// RequestedAuthnContext limits the answer to the authentications that satisfy it.
	RequestedAuthnContext *RequestedAuthnContext
}

// Element returns an etree.Element representing the object in XML form.
func (r *AuthnQuery) Element() *etree.Element {
	el := newQueryElement("samlp:AuthnQuery", r.ID, r.Version, r.IssueInstant, r.Destination, r.Consent, r.Issuer, r.Signature, r.Extensions)

	if r.SessionIndex != "" {
		el.CreateAttr("SessionIndex", r.SessionIndex)
	}

	if r.Subject != nil {
		el.AddChild(r.Subject.Element())
	}

	if r.RequestedAuthnContext != nil {
		el.AddChild(r.RequestedAuthnContext.Element())
	}

	return el
}

// MarshalXML implements [xml.Marshaler].
func (r *AuthnQuery) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias AuthnQuery

	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		*Alias
	}{
		IssueInstant: RelaxedTime(r.IssueInstant),
		Alias:        (*Alias)(r),
	}

	return e.Encode(aux)
}

// UnmarshalXML implements [xml.Unmarshaler].
func (r *AuthnQuery) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias AuthnQuery

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

// AssertionIDRequest represents the SAML object of the same name, a request from a service provider
// for assertions that it knows the identifiers of.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §3.3.1.
type AssertionIDRequest struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AssertionIDRequest"`

	ID           string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Destination  string    `xml:",attr"`
	Consent      string    `xml:",attr"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element

	// Extensions are the protocol extensions of the message (SAMLCore §3.2.1, §3.2.2), or nil if there are none.
	Extensions *ProtocolExtensions `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`

	AssertionIDRefs []AssertionIDRef `xml:"urn:oasis:names:tc:SAML:2.0:assertion AssertionIDRef"`
}

// Element returns an etree.Element representing the object in XML form.
func (r *AssertionIDRequest) Element() *etree.Element {
	el := newQueryElement("samlp:AssertionIDRequest", r.ID, r.Version, r.IssueInstant, r.Destination, r.Consent, r.Issuer, r.Signature, r.Extensions)

	for i := range r.AssertionIDRefs {
		el.AddChild(r.AssertionIDRefs[i].Element())
	}

	return el
}

// MarshalXML implements [xml.Marshaler].
func (r *AssertionIDRequest) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias AssertionIDRequest

	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		*Alias
	}{
		IssueInstant: RelaxedTime(r.IssueInstant),
		Alias:        (*Alias)(r),
	}

	return e.Encode(aux)
}

// UnmarshalXML implements [xml.Unmarshaler].
func (r *AssertionIDRequest) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias AssertionIDRequest

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

// AssertionIDRef represents the SAML element AssertionIDRef, a reference to an assertion by its ID.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.3.1.
type AssertionIDRef struct {
	Value string `xml:",chardata"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *AssertionIDRef) Element() *etree.Element {
	el := etree.NewElement("saml:AssertionIDRef")
	el.SetText(a.Value)

	return el
}

// newQueryElement returns the element of a request of the assertion query and request protocol with the
// content of RequestAbstractType (SAMLCore §3.2.1), which every such request begins with.
func newQueryElement(tag, id, version string, issueInstant time.Time, destination, consent string, issuer *Issuer, signature *etree.Element, extensions *ProtocolExtensions) *etree.Element {
	el := etree.NewElement(tag)
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	el.CreateAttr("ID", id)
	el.CreateAttr("Version", version)
	el.CreateAttr("IssueInstant", issueInstant.Format(timeFormat))

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

	return el
}
