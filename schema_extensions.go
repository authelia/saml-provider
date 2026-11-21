package saml

import (
	"encoding/xml"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/beevik/etree"
)

// attributeExtNamespace is the namespace of the XML attributes of the SAML V2.0 Attribute Extensions, and
// attributeExtPrefix the prefix they are marshalled with, which is the one their specification uses.
const (
	attributeExtNamespace = "urn:oasis:names:tc:SAML:attribute:ext"
	attributeExtPrefix    = "ext"
)

// ProtocolExtensions represents the samlp:Extensions element of a request or a response, which holds extensions
// to the protocol that the parties have agreed on (SAMLCore §3.2.1, §3.2.2). The extensions are not modelled, and
// each is kept whole in Elements, so that one which isn't understood can be passed on or ignored. A party need not
// act on any of them.
//
// Every element must be in a namespace other than those of SAML assertions and protocols, and there must be at
// least one, for what the identity provider sends. What it receives is not checked, as its schema is processed
// laxly. The text of an element received is kept as it is, white space and all, but ExtensionElement describes
// what else is not preserved.
type ProtocolExtensions struct {
	// Elements are the extensions, in the order they appear in.
	Elements []ExtensionElement `xml:",any"`
}

// Find returns the first of the Elements with that namespace and local name, or nil if there is none or m is
// nil.
func (m *ProtocolExtensions) Find(space, local string) *ExtensionElement {
	if m == nil {
		return nil
	}

	for i := range m.Elements {
		if m.Elements[i].XMLName.Space == space && m.Elements[i].XMLName.Local == local {
			return &m.Elements[i]
		}
	}

	return nil
}

// Element returns the element of the extensions, or nil if m is nil, so that a message without extensions has
// no Extensions element.
func (m *ProtocolExtensions) Element() *etree.Element {
	if m == nil {
		return nil
	}

	el := etree.NewElement("samlp:Extensions")

	for _, extension := range m.Elements {
		el.AddChild(extension.Element())
	}

	return el
}

// check returns an error if m can't be sent: SAMLCore §3.2.1 requires each element to be in a namespace that SAML
// doesn't define, and the schema requires there to be one.
func (m *ProtocolExtensions) check() error {
	if m == nil {
		return nil
	}

	if len(m.Elements) == 0 {
		return errors.New("protocol extensions must have at least one element")
	}

	for _, extension := range m.Elements {
		switch extension.XMLName.Space {
		case "":
			return fmt.Errorf("protocol extension %q is in no namespace", extension.XMLName.Local)
		case samlNamespace, samlProtocolNS:
			return fmt.Errorf("protocol extension %q is in the SAML namespace %q", extension.XMLName.Local, extension.XMLName.Space)
		}

		if err := extension.checkNames(); err != nil {
			return fmt.Errorf("protocol extension %q: %w", extension.XMLName.Local, err)
		}
	}

	return nil
}

// checkNames returns an error if the local name of m, of one of its attributes or of an element in it is not one
// that Element can write, which is an NCName, or if an attribute in no namespace is named xmlns, which Element
// declares itself.
func (m ExtensionElement) checkNames() error {
	if !isNCName(m.XMLName.Local) {
		return fmt.Errorf("the element name %q is not a valid XML name", m.XMLName.Local)
	}

	for _, attr := range m.Attrs {
		if !isNCName(attr.Name.Local) {
			return fmt.Errorf("the attribute name %q of the element %q is not a valid XML name", attr.Name.Local, m.XMLName.Local)
		}

		if attr.Name.Space == "" && attr.Name.Local == "xmlns" {
			return fmt.Errorf("the element %q has a namespace declaration as an attribute", m.XMLName.Local)
		}
	}

	for _, child := range m.Children {
		if err := child.checkNames(); err != nil {
			return err
		}
	}

	return nil
}

// isNCName reports whether s is a name without a colon, as the NCName production of Namespaces in XML 1.0 defines
// it.
func isNCName(s string) bool {
	// Ranging over invalid UTF-8 yields U+FFFD, which is a NameStartChar, so the bytes are checked first.
	if s == "" || !utf8.ValidString(s) {
		return false
	}

	for i, r := range s {
		if !isNameStartChar(r) && (i == 0 || !isNameChar(r)) {
			return false
		}
	}

	return true
}

// nameStartChars are the NameStartChar of XML 1.0 §2.3, but for the colon.
var nameStartChars = &unicode.RangeTable{
	R16: []unicode.Range16{
		{Lo: 'A', Hi: 'Z', Stride: 1},
		{Lo: '_', Hi: '_', Stride: 1},
		{Lo: 'a', Hi: 'z', Stride: 1},
		{Lo: 0xC0, Hi: 0xD6, Stride: 1},
		{Lo: 0xD8, Hi: 0xF6, Stride: 1},
		{Lo: 0xF8, Hi: 0x2FF, Stride: 1},
		{Lo: 0x370, Hi: 0x37D, Stride: 1},
		{Lo: 0x37F, Hi: 0x1FFF, Stride: 1},
		{Lo: 0x200C, Hi: 0x200D, Stride: 1},
		{Lo: 0x2070, Hi: 0x218F, Stride: 1},
		{Lo: 0x2C00, Hi: 0x2FEF, Stride: 1},
		{Lo: 0x3001, Hi: 0xD7FF, Stride: 1},
		{Lo: 0xF900, Hi: 0xFDCF, Stride: 1},
		{Lo: 0xFDF0, Hi: 0xFFFD, Stride: 1},
	},
	R32: []unicode.Range32{
		{Lo: 0x10000, Hi: 0xEFFFF, Stride: 1},
	},
}

// isNameStartChar reports whether r is a NameStartChar of XML 1.0 §2.3, but for the colon.
func isNameStartChar(r rune) bool {
	return unicode.Is(nameStartChars, r)
}

// isNameChar reports whether r is a NameChar of XML 1.0 §2.3 that is not a NameStartChar.
func isNameChar(r rune) bool {
	return r == '-' || r == '.' || ('0' <= r && r <= '9') || r == 0xB7 ||
		(0x300 <= r && r <= 0x36F) || (0x203F <= r && r <= 0x2040)
}

// UnmarshalXML implements [xml.Unmarshaler]. Unlike an element of metadata Extensions, the text of each extension
// is kept as it is, white space and all, as it is the text of a message which the application may pass on.
func (m *ProtocolExtensions) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var aux struct {
		Elements []protocolExtensionElement `xml:",any"`
	}

	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}

	m.Elements = nil
	for _, element := range aux.Elements {
		m.Elements = append(m.Elements, element.extensionElement())
	}

	return nil
}

// protocolExtensionElement is how an ExtensionElement of ProtocolExtensions is decoded: as ExtensionElement is, but
// with its text untrimmed.
type protocolExtensionElement struct {
	XMLName  xml.Name
	Attrs    []xml.Attr                 `xml:",any,attr"`
	Content  string                     `xml:",chardata"`
	Children []protocolExtensionElement `xml:",any"`
}

// extensionElement returns m as an ExtensionElement, without its namespace declarations.
func (m protocolExtensionElement) extensionElement() ExtensionElement {
	out := ExtensionElement{XMLName: m.XMLName, Attrs: withoutNamespaceDeclarations(m.Attrs), Content: m.Content}

	for _, child := range m.Children {
		out.Children = append(out.Children, child.extensionElement())
	}

	return out
}

// clone returns a copy of m that shares nothing with it.
func (m *ProtocolExtensions) clone() *ProtocolExtensions {
	if m == nil {
		return nil
	}

	out := &ProtocolExtensions{Elements: make([]ExtensionElement, len(m.Elements))}
	for i, extension := range m.Elements {
		out.Elements[i] = extension.clone()
	}

	return out
}

// clone returns a copy of m that shares nothing with it.
func (m ExtensionElement) clone() ExtensionElement {
	out := m
	out.Attrs = slices.Clone(m.Attrs)

	if m.Children != nil {
		out.Children = make([]ExtensionElement, len(m.Children))
		for i, child := range m.Children {
			out.Children[i] = child.clone()
		}
	}

	return out
}

// Element returns the element in XML form. It declares its namespace as the default one, as MarshalXML does, and a
// prefix for each attribute that is in a namespace.
func (m ExtensionElement) Element() *etree.Element {
	el := etree.NewElement(m.XMLName.Local)

	// An element in no namespace must say so, as its parent may have a default namespace.
	el.CreateAttr("xmlns", m.XMLName.Space)

	setNamespacedAttrs(el, m.Attrs)

	if m.Content != "" {
		el.SetText(m.Content)
	}

	for _, child := range m.Children {
		el.AddChild(child.Element())
	}

	return el
}

// setNamespacedAttrs sets attrs on el, which hold the namespace of each attribute and not its prefix. An attribute
// in the XML namespace has the prefix xml, which is never declared, and one in another namespace has a prefix that
// is declared on el. The prefix of X500AttributeNamespace is x500, and that of any other namespace is ns1, ns2 and
// so on in order of appearance.
func setNamespacedAttrs(el *etree.Element, attrs []xml.Attr) {
	prefixes := map[string]string{}
	generated := 0

	for _, attr := range attrs {
		switch attr.Name.Space {
		case "":
			el.CreateAttr(attr.Name.Local, attr.Value)
		case xmlNamespace:
			el.CreateAttr("xml:"+attr.Name.Local, attr.Value)
		default:
			prefix, ok := prefixes[attr.Name.Space]
			if !ok {
				if attr.Name.Space == X500AttributeNamespace {
					prefix = "x500"
				} else {
					generated++
					prefix = "ns" + strconv.Itoa(generated)
				}

				prefixes[attr.Name.Space] = prefix

				el.CreateAttr("xmlns:"+prefix, attr.Name.Space)
			}

			el.CreateAttr(prefix+":"+attr.Name.Local, attr.Value)
		}
	}
}

// attributeExtensionAttrs returns the XML attributes of the Attribute Extensions that a has, OriginalIssuer and
// LastModified, with the prefix ext, which they declare when declare is true.
func (a *Attribute) attributeExtensionAttrs(declare bool) []xml.Attr {
	if a.OriginalIssuer == "" && a.LastModified.IsZero() {
		return nil
	}

	var attrs []xml.Attr

	if declare {
		attrs = append(attrs, extAttr("xmlns:"+attributeExtPrefix, attributeExtNamespace))
	}

	if a.OriginalIssuer != "" {
		attrs = append(attrs, extAttr(attributeExtPrefix+":OriginalIssuer", a.OriginalIssuer))
	}

	if !a.LastModified.IsZero() {
		attrs = append(attrs, extAttr(attributeExtPrefix+":LastModified", RelaxedTime(a.LastModified).String()))
	}

	return attrs
}

// MarshalXML implements [xml.Marshaler]. It marshals the attributes of the Attribute Extensions with the prefix
// ext, and every other XML attribute in Attrs with a prefix that the encoder declares.
func (a Attribute) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return a.marshalXML(e, start, nil)
}

// marshalXML marshals a as the element start, with extra as further XML attributes of it.
func (a Attribute) marshalXML(e *xml.Encoder, start xml.StartElement, extra []xml.Attr) error {
	start.Attr = append(start.Attr,
		extAttr("FriendlyName", a.FriendlyName),
		extAttr("Name", a.Name),
		extAttr("NameFormat", a.NameFormat))
	start.Attr = append(start.Attr, a.attributeExtensionAttrs(true)...)
	start.Attr = append(start.Attr, a.Attrs...)
	start.Attr = append(start.Attr, extra...)

	aux := struct {
		Values []AttributeValue `xml:"AttributeValue"`
	}{
		Values: a.Values,
	}

	return e.EncodeElement(aux, start)
}

// UnmarshalXML implements [xml.Unmarshaler]. A LastModified that isn't a time is kept in Attrs, as it is in an
// extension which is not critical, and an aggregate of metadata is not refused for it.
func (a *Attribute) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type alias Attribute

	aux := struct {
		*alias
		OriginalIssuer string `xml:"urn:oasis:names:tc:SAML:attribute:ext OriginalIssuer,attr"`
		LastModified   string `xml:"urn:oasis:names:tc:SAML:attribute:ext LastModified,attr"`
	}{
		alias: (*alias)(a),
	}

	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}

	a.OriginalIssuer = aux.OriginalIssuer
	a.Attrs = withoutNamespaceDeclarations(a.Attrs)

	if lastModified := strings.TrimSpace(aux.LastModified); lastModified != "" {
		var t RelaxedTime
		if err := t.UnmarshalText([]byte(lastModified)); err == nil {
			a.LastModified = time.Time(t)
		} else {
			a.Attrs = append(a.Attrs, xml.Attr{
				Name:  xml.Name{Space: attributeExtNamespace, Local: "LastModified"},
				Value: aux.LastModified,
			})
		}
	}

	return nil
}

// MarshalXML implements [xml.Marshaler]. It is needed as Attribute, which is embedded, has its own.
func (m RequestedAttribute) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	var extra []xml.Attr
	if m.IsRequired != nil {
		extra = append(extra, extAttr("isRequired", strconv.FormatBool(*m.IsRequired)))
	}

	return m.marshalXML(e, start, extra)
}

// UnmarshalXML implements [xml.Unmarshaler]. It is needed as Attribute, which is embedded, has its own.
func (m *RequestedAttribute) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	m.IsRequired = nil

	attrs := make([]xml.Attr, 0, len(start.Attr))

	for _, attr := range start.Attr {
		if attr.Name.Space != "" || attr.Name.Local != "isRequired" {
			attrs = append(attrs, attr)

			continue
		}

		isRequired, err := strconv.ParseBool(strings.TrimSpace(attr.Value))
		if err != nil {
			return fmt.Errorf("invalid isRequired %q: %w", attr.Value, err)
		}

		m.IsRequired = &isRequired
	}

	start.Attr = attrs

	return m.Attribute.UnmarshalXML(d, start)
}
