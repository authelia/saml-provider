package saml

import (
	"encoding/base64"
	"encoding/xml"
	"strings"
)

// The attribute name formats of SAMLCore §8.2: unspecified (§8.2.1), uri (§8.2.2) and basic (§8.2.3).
const (
	AttributeNameFormatUnspecified = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
	AttributeNameFormatURI         = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	AttributeNameFormatBasic       = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
)

// X500AttributeNamespace is the namespace of the XML attributes of the SAML V2.0 X.500/LDAP Attribute Profile, which
// is the one of its x500:Encoding attribute (X.500 profile §2.4).
const X500AttributeNamespace = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500"

// X500EncodingLDAP is the value of x500:Encoding which states that the values of an attribute are encoded as LDAP
// does (X.500 profile §2.4).
const X500EncodingLDAP = "LDAP"

// NewX500Attribute returns an attribute of the X.500/LDAP Attribute Profile for the directory attribute type with the
// object identifier oid, which may carry a leading urn:oid:. The name has the form urn:oid:oid and the NameFormat is
// AttributeNameFormatURI (X.500 profile §2.3), x500:Encoding is LDAP (§2.4) and each value has the type xs:string
// (§2.5).
//
// It is for directory attributes whose LDAP syntax is a UTF-8 string; use NewX500BinaryAttribute for the others.
// friendlyName should be a descriptor of the attribute type, such as givenName (§2.3). The result is meant for
// Session.CustomAttributes. Without values it describes the attribute, for a RequestedAttribute or a query.
func NewX500Attribute(oid, friendlyName string, values ...string) Attribute {
	attribute := newX500Attribute(oid, friendlyName)

	for _, value := range values {
		attribute.Values = append(attribute.Values, AttributeValue{Type: "xs:string", Value: value})
	}

	return attribute
}

// NewX500BinaryAttribute is NewX500Attribute for the directory attributes whose LDAP syntax is not a UTF-8 string,
// which the profile has base64 encoded with the type xs:base64Binary (X.500 profile §2.5). Each of values is the
// LDAP value of the attribute, without an ASN.1 OCTET STRING wrapper.
func NewX500BinaryAttribute(oid, friendlyName string, values ...[]byte) Attribute {
	attribute := newX500Attribute(oid, friendlyName)

	for _, value := range values {
		attribute.Values = append(attribute.Values, AttributeValue{Type: "xs:base64Binary", Value: base64.StdEncoding.EncodeToString(value)})
	}

	return attribute
}

// trimOIDPrefix removes a leading urn:oid:, in any case since URN schemes and namespace identifiers are not case
// sensitive (RFC 8141 §3.1).
func trimOIDPrefix(oid string) string {
	if len(oid) >= len("urn:oid:") && strings.EqualFold(oid[:len("urn:oid:")], "urn:oid:") {
		return oid[len("urn:oid:"):]
	}

	return oid
}

func newX500Attribute(oid, friendlyName string) Attribute {
	return Attribute{
		FriendlyName: friendlyName,
		Name:         "urn:oid:" + trimOIDPrefix(oid),
		NameFormat:   AttributeNameFormatURI,
		Attrs:        []xml.Attr{{Name: xml.Name{Space: X500AttributeNamespace, Local: "Encoding"}, Value: X500EncodingLDAP}},
	}
}
