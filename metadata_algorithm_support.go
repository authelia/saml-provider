package saml

import (
	"encoding/xml"
	"strconv"
	"strings"
)

// SigningMethod represents the alg:SigningMethod element, which says that an entity can verify a signature made
// with an algorithm, and with which sizes of key. An entity lists them in its order of preference.
//
// See the SAML V2.0 Metadata Profile for Algorithm Support §2.4.
type SigningMethod struct {
	// Algorithm is the identifier of the signature algorithm in XML Signature, such as
	// http://www.w3.org/2001/04/xmldsig-more#rsa-sha256.
	Algorithm string

	// MinKeySize is the smallest key, in bits, that the entity supports with the algorithm, or 0 if it states
	// none, which implies no minimum.
	MinKeySize int

	// MaxKeySize is the largest key, in bits, that the entity supports with the algorithm, or 0 if it states
	// none, which implies no maximum.
	MaxKeySize int

	// Parameters holds what the element contains, which is whatever else the algorithm defines that a signer
	// needs, such as the RSAPSSParams of RSASSA-PSS (RFC 6931 §2.3.9).
	Parameters []ExtensionElement
}

// UnmarshalXML implements [xml.Unmarshaler]. A size that isn't a positive integer is read as 0 instead of
// refusing the metadata, which may be an aggregate of thousands of other entities.
func (m *SigningMethod) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var aux struct {
		Algorithm  string             `xml:"Algorithm,attr"`
		MinKeySize string             `xml:"MinKeySize,attr"`
		MaxKeySize string             `xml:"MaxKeySize,attr"`
		Parameters []ExtensionElement `xml:",any"`
	}

	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}

	m.Algorithm = aux.Algorithm
	m.MinKeySize = parseKeySize(aux.MinKeySize)
	m.MaxKeySize = parseKeySize(aux.MaxKeySize)
	m.Parameters = aux.Parameters

	return nil
}

// parseKeySize returns the positive integer that value states, or 0 if it states none.
func parseKeySize(value string) int {
	size, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || size < 0 {
		return 0
	}

	return size
}

func (m SigningMethod) write(w *extensionWriter) {
	attrs := []xml.Attr{extAttr("xmlns:alg", algNamespace), extAttr("Algorithm", m.Algorithm)}

	if m.MinKeySize > 0 {
		attrs = append(attrs, extAttr("MinKeySize", strconv.Itoa(m.MinKeySize)))
	}

	if m.MaxKeySize > 0 {
		attrs = append(attrs, extAttr("MaxKeySize", strconv.Itoa(m.MaxKeySize)))
	}

	w.open("alg:SigningMethod", attrs...)

	for _, parameter := range m.Parameters {
		if w.err == nil {
			w.err = parameter.MarshalXML(w.encoder, xml.StartElement{})
		}
	}

	w.close("alg:SigningMethod")
}

// allows reports whether a key of that many bits is within the sizes that the entity supports with the
// algorithm.
func (m SigningMethod) allows(bits int) bool {
	return (m.MinKeySize <= 0 || bits >= m.MinKeySize) && (m.MaxKeySize <= 0 || bits <= m.MaxKeySize)
}

// SigningMethods returns the signature algorithms that the entity says it can verify in that role, in its order
// of preference: the alg:SigningMethod elements of the role if it has any, and otherwise those of the entity. The
// Metadata Profile for Algorithm Support §2.5 gives what a role lists precedence over what its entity lists, and
// doesn't combine the two. A nil role gives those of the entity. The role is one of the entity, such as
// &m.SPSSODescriptors[0].RoleDescriptor.
//
// None means that the entity says nothing, and not that it supports nothing (§2.5). The digest algorithms are
// decided on their own, by DigestMethods, so a role that only lists signature algorithms has the digests of its
// entity.
func (m *EntityDescriptor) SigningMethods(role *RoleDescriptor) []SigningMethod {
	if role != nil && role.Extensions != nil && len(role.Extensions.SigningMethods) != 0 {
		return role.Extensions.SigningMethods
	}

	if m.Extensions == nil {
		return nil
	}

	return m.Extensions.SigningMethods
}

// DigestMethods returns the digest algorithms that the entity says it can verify in a signature in that role, in
// its order of preference: the alg:DigestMethod elements of the role if it has any, and otherwise those of the
// entity. See SigningMethods.
func (m *EntityDescriptor) DigestMethods(role *RoleDescriptor) []DigestMethod {
	if role != nil && role.Extensions != nil && len(role.Extensions.DigestMethods) != 0 {
		return role.Extensions.DigestMethods
	}

	if m.Extensions == nil {
		return nil
	}

	return m.Extensions.DigestMethods
}
