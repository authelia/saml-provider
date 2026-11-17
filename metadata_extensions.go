package saml

import (
	"encoding/xml"
	"strconv"
	"strings"
	"time"
)

// The namespaces of the metadata extensions that are modelled, and the prefixes they are marshalled with, which are
// those their specifications use.
const (
	mduiNamespace   = "urn:oasis:names:tc:SAML:metadata:ui"
	mdattrNamespace = "urn:oasis:names:tc:SAML:metadata:attribute"
	mdrpiNamespace  = "urn:oasis:names:tc:SAML:metadata:rpi"
	shibmdNamespace = "urn:mace:shibboleth:metadata:1.0"
	samlNamespace   = "urn:oasis:names:tc:SAML:2.0:assertion"
	xsNamespace     = "http://www.w3.org/2001/XMLSchema"
	xsiNamespace    = "http://www.w3.org/2001/XMLSchema-instance"
	xmlNamespace    = "http://www.w3.org/XML/1998/namespace"
	refedsNamespace = "http://refeds.org/metadata"
	algNamespace    = "urn:oasis:names:tc:SAML:metadata:algsupport"
)

// REFEDSSecurityContactType is the ContactPerson.REFEDSContactType of the security contact that the REFEDS Security
// Contact Metadata Extension defines, and Sirtfi requires. Its ContactType is other.
const REFEDSSecurityContactType = "http://refeds.org/metadata/contactType/security"

// Extensions represents the SAML element Extensions, which holds what other specifications add to metadata. The
// extensions that are modelled have a field each, and every other element is kept in Other, so that metadata which
// is parsed and marshalled again loses none of them.
//
// It is marshalled with the conventional prefix of each extension, declared on the extension itself, with those
// that are modelled first, in the order of the fields, and then Other. It is not marshalled at all when it is empty,
// as the schema requires it to have a child.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.2.1.
type Extensions struct {
	// RegistrationInfo says who registered the entity, on an EntityDescriptor or an EntitiesDescriptor.
	RegistrationInfo *RegistrationInfo `xml:"urn:oasis:names:tc:SAML:metadata:rpi RegistrationInfo"`

	// PublicationInfo says who published the metadata, on the root element of a metadata document.
	PublicationInfo *PublicationInfo `xml:"urn:oasis:names:tc:SAML:metadata:rpi PublicationInfo"`

	// EntityAttributes are the attributes of the entity, on an EntityDescriptor or an EntitiesDescriptor.
	EntityAttributes *EntityAttributes `xml:"urn:oasis:names:tc:SAML:metadata:attribute EntityAttributes"`

	// UIInfo describes the entity to a user, on a role descriptor.
	UIInfo *UIInfo `xml:"urn:oasis:names:tc:SAML:metadata:ui UIInfo"`

	// DiscoHints helps a discovery service to suggest an identity provider, on an IDPSSODescriptor.
	DiscoHints *DiscoHints `xml:"urn:oasis:names:tc:SAML:metadata:ui DiscoHints"`

	// Scopes are the scopes that an identity provider may assert, on its EntityDescriptor or a role descriptor.
	Scopes []Scope `xml:"urn:mace:shibboleth:metadata:1.0 Scope"`

	// DigestMethods are the digest algorithms that the entity can verify in an XML signature, in its order of
	// preference, on an EntityDescriptor or a role descriptor. EntityDescriptor.DigestMethods returns those that
	// apply to a role.
	DigestMethods []DigestMethod `xml:"urn:oasis:names:tc:SAML:metadata:algsupport DigestMethod"`

	// SigningMethods are the signature algorithms that the entity can verify, in its order of preference, on an
	// EntityDescriptor or a role descriptor. EntityDescriptor.SigningMethods returns those that apply to a role.
	SigningMethods []SigningMethod `xml:"urn:oasis:names:tc:SAML:metadata:algsupport SigningMethod"`

	// Other holds every other element.
	Other []ExtensionElement `xml:",any"`
}

// UIInfo represents the mdui:UIInfo element, which describes the entity in a role to a user, for a login page, a
// discovery service or a consent page. Each of DisplayNames, Descriptions, Keywords, InformationURLs and
// PrivacyStatementURLs has at most one member for a language.
//
// See the Metadata Extensions for Login and Discovery User Interface §2.1.
type UIInfo struct {
	DisplayNames         []LocalizedName `xml:"urn:oasis:names:tc:SAML:metadata:ui DisplayName"`
	Descriptions         []LocalizedName `xml:"urn:oasis:names:tc:SAML:metadata:ui Description"`
	Keywords             []Keywords      `xml:"urn:oasis:names:tc:SAML:metadata:ui Keywords"`
	Logos                []Logo          `xml:"urn:oasis:names:tc:SAML:metadata:ui Logo"`
	InformationURLs      []LocalizedURI  `xml:"urn:oasis:names:tc:SAML:metadata:ui InformationURL"`
	PrivacyStatementURLs []LocalizedURI  `xml:"urn:oasis:names:tc:SAML:metadata:ui PrivacyStatementURL"`
}

// Keywords represents the mdui:Keywords element, the search keywords of an entity in a language.
//
// See the Metadata Extensions for Login and Discovery User Interface §2.1.4.
type Keywords struct {
	Lang string

	// Values are the keywords. A space within one is written as a plus, so a keyword can't contain a plus.
	Values []string
}

// UnmarshalXML implements [xml.Unmarshaler].
func (m *Keywords) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var aux LocalizedName
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}

	m.Lang = aux.Lang
	m.Values = strings.Fields(aux.Value)

	for i, value := range m.Values {
		m.Values[i] = strings.ReplaceAll(value, "+", " ")
	}

	return nil
}

// Logo represents the mdui:Logo element, an image that stands for the entity.
//
// See the Metadata Extensions for Login and Discovery User Interface §2.1.5.
type Logo struct {
	// URL is where the image is, or the image itself as a data URI.
	URL string

	// Height and Width are the size of the image in pixels. They are 0 if metadata that was parsed gives none
	// that is a number.
	Height int
	Width  int

	// Lang is the language of the image, or empty if it is for every language.
	Lang string
}

// UnmarshalXML implements [xml.Unmarshaler]. A height or width that isn't a number is read as 0 instead of
// refusing the metadata, which may be an aggregate of thousands of other entities.
func (m *Logo) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var aux struct {
		URL    string `xml:",chardata"`
		Height string `xml:"height,attr"`
		Width  string `xml:"width,attr"`
		Lang   string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
	}

	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}

	m.URL = strings.TrimSpace(aux.URL)
	m.Height, _ = strconv.Atoi(strings.TrimSpace(aux.Height))
	m.Width, _ = strconv.Atoi(strings.TrimSpace(aux.Width))
	m.Lang = aux.Lang

	return nil
}

// DiscoHints represents the mdui:DiscoHints element, which helps a discovery service to suggest an identity
// provider to a user.
//
// See the Metadata Extensions for Login and Discovery User Interface §2.2.
type DiscoHints struct {
	// IPHints are networks in CIDR notation that the users of the identity provider are likely to come from.
	IPHints []string `xml:"urn:oasis:names:tc:SAML:metadata:ui IPHint"`

	// DomainHints are DNS domains that are associated with the identity provider.
	DomainHints []string `xml:"urn:oasis:names:tc:SAML:metadata:ui DomainHint"`

	// GeolocationHints are geo URIs (RFC 5870) of where the identity provider is.
	GeolocationHints []string `xml:"urn:oasis:names:tc:SAML:metadata:ui GeolocationHint"`
}

// EntityAttributes represents the mdattr:EntityAttributes element, which holds attributes of the entity, such as
// the entity categories it belongs to. Only its Attribute elements are modelled: an Assertion in it, which is
// signed by whoever vouches for its attributes, is not read and is not kept.
//
// See the SAML V2.0 Metadata Extension for Entity Attributes §2.1.
type EntityAttributes struct {
	Attributes []Attribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

// Scope represents the shibmd:Scope element, a scope that an identity provider may assert in a scoped attribute,
// such as the subject-id and pairwise-id attributes, whose value is uniqueID@scope. A service provider refuses a
// scope that the metadata of the identity provider doesn't list.
//
// See the SAML V2.0 Subject Identifier Attributes Profile §3.5.2.
type Scope struct {
	Value string

	// Regexp says that Value is a regular expression that a scope must match, and not the scope itself. SAML2Int
	// doesn't allow it (SDP-IDP14).
	Regexp bool
}

// UnmarshalXML implements [xml.Unmarshaler].
func (m *Scope) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var aux struct {
		Value  string `xml:",chardata"`
		Regexp string `xml:"regexp,attr"`
	}

	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}

	m.Value = strings.TrimSpace(aux.Value)

	regexp := strings.TrimSpace(aux.Regexp)
	m.Regexp = regexp == "true" || regexp == "1"

	return nil
}

// RegistrationInfo represents the mdrpi:RegistrationInfo element, which says who registered the entity, when, and
// under which policy.
//
// See the SAML V2.0 Metadata Extensions for Registration and Publication Information §2.1.
type RegistrationInfo struct {
	// RegistrationAuthority is the identifier of the registrar, which is required.
	RegistrationAuthority string

	// RegistrationInstant is when the entity was registered, or zero if it isn't said.
	RegistrationInstant time.Time

	// RegistrationPolicies are the URLs of the policy of the registrar, one for each language.
	RegistrationPolicies []LocalizedURI
}

// UnmarshalXML implements [xml.Unmarshaler]. An instant that isn't a time is read as zero.
func (m *RegistrationInfo) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var aux struct {
		RegistrationAuthority string         `xml:"registrationAuthority,attr"`
		RegistrationInstant   string         `xml:"registrationInstant,attr"`
		RegistrationPolicies  []LocalizedURI `xml:"urn:oasis:names:tc:SAML:metadata:rpi RegistrationPolicy"`
	}

	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}

	m.RegistrationAuthority = aux.RegistrationAuthority
	m.RegistrationInstant = parseExtensionInstant(aux.RegistrationInstant)
	m.RegistrationPolicies = aux.RegistrationPolicies

	return nil
}

// PublicationInfo represents the mdrpi:PublicationInfo element, which says who published the metadata, when, and
// under which terms of use.
//
// See the SAML V2.0 Metadata Extensions for Registration and Publication Information §2.2.
type PublicationInfo struct {
	// Publisher is the identifier of the publisher, which is required.
	Publisher string

	// CreationInstant is when the metadata was published, or zero if it isn't said.
	CreationInstant time.Time

	// PublicationID identifies this publication, or is empty.
	PublicationID string

	// UsagePolicies are the URLs of the terms of use of the metadata, one for each language.
	UsagePolicies []LocalizedURI
}

// UnmarshalXML implements [xml.Unmarshaler]. An instant that isn't a time is read as zero.
func (m *PublicationInfo) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var aux struct {
		Publisher       string         `xml:"publisher,attr"`
		CreationInstant string         `xml:"creationInstant,attr"`
		PublicationID   string         `xml:"publicationId,attr"`
		UsagePolicies   []LocalizedURI `xml:"urn:oasis:names:tc:SAML:metadata:rpi UsagePolicy"`
	}

	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}

	m.Publisher = aux.Publisher
	m.CreationInstant = parseExtensionInstant(aux.CreationInstant)
	m.PublicationID = aux.PublicationID
	m.UsagePolicies = aux.UsagePolicies

	return nil
}

// parseExtensionInstant returns the time that value states, or zero if it states none.
func parseExtensionInstant(value string) time.Time {
	var instant RelaxedTime
	if err := instant.UnmarshalText([]byte(strings.TrimSpace(value))); err != nil {
		return time.Time{}
	}

	return time.Time(instant)
}

// ExtensionElement is an element of Extensions that isn't modelled, with everything in it. Its name and those of
// its attributes hold the namespace they are in and not the prefix, and namespace declarations are not kept, so it
// means the same wherever it is marshalled. Two things are not preserved: the order of text and elements when an
// element has both, and the meaning of a prefix within a value, such as a QName, which no common metadata
// extension has.
type ExtensionElement struct {
	XMLName xml.Name

	// Attrs are the attributes, but for namespace declarations.
	Attrs []xml.Attr `xml:",any,attr"`

	// Content is the text, without the white space around it.
	Content string `xml:",chardata"`

	Children []ExtensionElement `xml:",any"`
}

// UnmarshalXML implements [xml.Unmarshaler].
func (m *ExtensionElement) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type alias ExtensionElement

	if err := d.DecodeElement((*alias)(m), &start); err != nil {
		return err
	}

	var attrs []xml.Attr

	for _, attr := range m.Attrs {
		if attr.Name.Space == "xmlns" || (attr.Name.Space == "" && attr.Name.Local == "xmlns") {
			continue
		}

		attrs = append(attrs, attr)
	}

	m.Attrs = attrs
	m.Content = strings.TrimSpace(m.Content)

	return nil
}

// MarshalXML implements [xml.Marshaler]. The element declares its namespace as the default one, and the encoder
// declares a prefix for each attribute that is in a namespace.
func (m ExtensionElement) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	start := xml.StartElement{Name: m.XMLName, Attr: append([]xml.Attr(nil), m.Attrs...)}

	// An element in no namespace must say so, as its parent has a default namespace.
	if m.XMLName.Space == "" {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "xmlns"}})
	}

	if err := e.EncodeToken(start); err != nil {
		return err
	}

	if m.Content != "" {
		if err := e.EncodeToken(xml.CharData(m.Content)); err != nil {
			return err
		}
	}

	for _, child := range m.Children {
		if err := child.MarshalXML(e, xml.StartElement{}); err != nil {
			return err
		}
	}

	return e.EncodeToken(start.End())
}

// isEmpty reports whether there is nothing to marshal.
func (m *Extensions) isEmpty() bool {
	return m == nil || (m.RegistrationInfo == nil && m.PublicationInfo == nil && m.EntityAttributes.isEmpty() &&
		m.UIInfo.isEmpty() && m.DiscoHints.isEmpty() && len(m.Scopes) == 0 && len(m.DigestMethods) == 0 &&
		len(m.SigningMethods) == 0 && len(m.Other) == 0)
}

func (m *EntityAttributes) isEmpty() bool {
	return m == nil || len(m.Attributes) == 0
}

func (m *UIInfo) isEmpty() bool {
	return m == nil || (len(m.DisplayNames) == 0 && len(m.Descriptions) == 0 && len(m.Keywords) == 0 &&
		len(m.Logos) == 0 && len(m.InformationURLs) == 0 && len(m.PrivacyStatementURLs) == 0)
}

func (m *DiscoHints) isEmpty() bool {
	return m == nil || (len(m.IPHints) == 0 && len(m.DomainHints) == 0 && len(m.GeolocationHints) == 0)
}

// MarshalXML implements [xml.Marshaler].
func (m Extensions) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if m.isEmpty() {
		return nil
	}

	w := &extensionWriter{encoder: e}

	// The element is in the namespace of its parent, which is the default one.
	start.Name.Space = ""
	start.Attr = nil
	w.token(start)

	m.RegistrationInfo.write(w)
	m.PublicationInfo.write(w)
	m.EntityAttributes.write(w)
	m.UIInfo.write(w)
	m.DiscoHints.write(w)

	for _, scope := range m.Scopes {
		w.leaf("shibmd:Scope", scope.Value, extAttr("xmlns:shibmd", shibmdNamespace), extAttr("regexp", strconv.FormatBool(scope.Regexp)))
	}

	for _, method := range m.DigestMethods {
		w.leaf("alg:DigestMethod", "", extAttr("xmlns:alg", algNamespace), extAttr("Algorithm", method.Algorithm))
	}

	for _, method := range m.SigningMethods {
		method.write(w)
	}

	for _, other := range m.Other {
		if w.err == nil {
			w.err = other.MarshalXML(e, xml.StartElement{})
		}
	}

	w.token(start.End())

	return w.err
}

func (m *RegistrationInfo) write(w *extensionWriter) {
	if m == nil {
		return
	}

	attrs := []xml.Attr{extAttr("xmlns:mdrpi", mdrpiNamespace), extAttr("registrationAuthority", m.RegistrationAuthority)}
	if !m.RegistrationInstant.IsZero() {
		attrs = append(attrs, extAttr("registrationInstant", RelaxedTime(m.RegistrationInstant).String()))
	}

	w.open("mdrpi:RegistrationInfo", attrs...)
	writeLocalized(w, "mdrpi:RegistrationPolicy", m.RegistrationPolicies)
	w.close("mdrpi:RegistrationInfo")
}

func (m *PublicationInfo) write(w *extensionWriter) {
	if m == nil {
		return
	}

	attrs := []xml.Attr{extAttr("xmlns:mdrpi", mdrpiNamespace), extAttr("publisher", m.Publisher)}
	if !m.CreationInstant.IsZero() {
		attrs = append(attrs, extAttr("creationInstant", RelaxedTime(m.CreationInstant).String()))
	}

	if m.PublicationID != "" {
		attrs = append(attrs, extAttr("publicationId", m.PublicationID))
	}

	w.open("mdrpi:PublicationInfo", attrs...)
	writeLocalized(w, "mdrpi:UsagePolicy", m.UsagePolicies)
	w.close("mdrpi:PublicationInfo")
}

func (m *EntityAttributes) write(w *extensionWriter) {
	if m.isEmpty() {
		return
	}

	w.open("mdattr:EntityAttributes", extAttr("xmlns:mdattr", mdattrNamespace), extAttr("xmlns:saml", samlNamespace))

	for _, attribute := range m.Attributes {
		attrs := []xml.Attr{extAttr("Name", attribute.Name)}
		if attribute.NameFormat != "" {
			attrs = append(attrs, extAttr("NameFormat", attribute.NameFormat))
		}

		if attribute.FriendlyName != "" {
			attrs = append(attrs, extAttr("FriendlyName", attribute.FriendlyName))
		}

		w.open("saml:Attribute", attrs...)

		for _, value := range attribute.Values {
			w.leaf("saml:AttributeValue", value.Value, attributeValueTypeAttrs(value.Type)...)
		}

		w.close("saml:Attribute")
	}

	w.close("mdattr:EntityAttributes")
}

// attributeValueTypeAttrs returns the attributes that state the xsi:type of an attribute value, for a type of XML
// Schema with the prefix xs or xsd, such as xs:string. The prefix is declared with the type, as the type is a QName
// and means nothing without it. Any other type is left out, because the namespace of its prefix is not known.
func attributeValueTypeAttrs(valueType string) []xml.Attr {
	prefix, local, ok := strings.Cut(valueType, ":")
	if !ok || local == "" || (prefix != "xs" && prefix != "xsd") {
		return nil
	}

	return []xml.Attr{extAttr("xmlns:"+prefix, xsNamespace), extAttr("xmlns:xsi", xsiNamespace), extAttr("xsi:type", valueType)}
}

func (m *UIInfo) write(w *extensionWriter) {
	if m.isEmpty() {
		return
	}

	w.open("mdui:UIInfo", extAttr("xmlns:mdui", mduiNamespace))
	writeLocalized(w, "mdui:DisplayName", m.DisplayNames)
	writeLocalized(w, "mdui:Description", m.Descriptions)

	for _, keywords := range m.Keywords {
		values := make([]string, 0, len(keywords.Values))
		for _, value := range keywords.Values {
			values = append(values, strings.ReplaceAll(value, " ", "+"))
		}

		w.leaf("mdui:Keywords", strings.Join(values, " "), extAttr("xml:lang", keywords.Lang))
	}

	for _, logo := range m.Logos {
		attrs := []xml.Attr{extAttr("height", strconv.Itoa(logo.Height)), extAttr("width", strconv.Itoa(logo.Width))}
		if logo.Lang != "" {
			attrs = append(attrs, extAttr("xml:lang", logo.Lang))
		}

		w.leaf("mdui:Logo", logo.URL, attrs...)
	}

	writeLocalized(w, "mdui:InformationURL", m.InformationURLs)
	writeLocalized(w, "mdui:PrivacyStatementURL", m.PrivacyStatementURLs)
	w.close("mdui:UIInfo")
}

func (m *DiscoHints) write(w *extensionWriter) {
	if m.isEmpty() {
		return
	}

	w.open("mdui:DiscoHints", extAttr("xmlns:mdui", mduiNamespace))

	for _, hint := range m.IPHints {
		w.leaf("mdui:IPHint", hint)
	}

	for _, hint := range m.DomainHints {
		w.leaf("mdui:DomainHint", hint)
	}

	for _, hint := range m.GeolocationHints {
		w.leaf("mdui:GeolocationHint", hint)
	}

	w.close("mdui:DiscoHints")
}

// writeLocalized writes an element called name for each of values, with its language.
func writeLocalized[T LocalizedName | LocalizedURI](w *extensionWriter, name string, values []T) {
	for _, value := range values {
		localized := LocalizedName(value)
		w.leaf(name, localized.Value, extAttr("xml:lang", localized.Lang))
	}
}

// extAttr returns an attribute whose name is written as it is, which may have a prefix.
func extAttr(name, value string) xml.Attr {
	return xml.Attr{Name: xml.Name{Local: name}, Value: value}
}

// extensionWriter writes elements whose names have a prefix to an encoder, and keeps the first error. The encoder
// writes a name in no namespace as it is, so a name with a prefix is given to it whole, and the prefix is declared
// with an attribute.
type extensionWriter struct {
	encoder *xml.Encoder
	err     error
}

func (w *extensionWriter) token(token xml.Token) {
	if w.err == nil {
		w.err = w.encoder.EncodeToken(token)
	}
}

func (w *extensionWriter) open(name string, attrs ...xml.Attr) {
	w.token(xml.StartElement{Name: xml.Name{Local: name}, Attr: attrs})
}

func (w *extensionWriter) close(name string) {
	w.token(xml.EndElement{Name: xml.Name{Local: name}})
}

func (w *extensionWriter) leaf(name, content string, attrs ...xml.Attr) {
	w.open(name, attrs...)

	if content != "" {
		w.token(xml.CharData(content))
	}

	w.close(name)
}
