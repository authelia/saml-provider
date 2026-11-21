package saml

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func x500EncodingAttr() xml.Attr {
	return xml.Attr{Name: xml.Name{Space: X500AttributeNamespace, Local: "Encoding"}, Value: "LDAP"}
}

func givenNameAttribute() Attribute {
	return Attribute{
		FriendlyName: "givenName",
		Name:         "urn:oid:2.5.4.42",
		NameFormat:   AttributeNameFormatURI,
		Attrs:        []xml.Attr{x500EncodingAttr()},
		Values:       []AttributeValue{{Type: "xs:string", Value: "Steven"}},
	}
}

func TestNewX500Attribute(t *testing.T) {
	assert.Equal(t, NewX500Attribute("2.5.4.42", "givenName", "Steven"), givenNameAttribute())
	assert.Equal(t, NewX500Attribute("urn:oid:2.5.4.42", "givenName", "Steven"), givenNameAttribute())
	assert.Equal(t, NewX500Attribute("URN:OID:2.5.4.42", "givenName", "Steven"), givenNameAttribute())

	two := NewX500Attribute("2.5.4.3", "cn", "a", "b")
	assert.Equal(t, two.Values, []AttributeValue{{Type: "xs:string", Value: "a"}, {Type: "xs:string", Value: "b"}})

	none := NewX500Attribute("2.5.4.3", "")
	assert.Len(t, none.Values, 0)
	assert.Equal(t, none.FriendlyName, "")

	a, b := NewX500Attribute("2.5.4.42", "givenName"), NewX500Attribute("2.5.4.42", "givenName")
	a.Attrs[0].Value = "changed"
	assert.Equal(t, b.Attrs[0].Value, "LDAP")
}

func TestX500AttributeElement(t *testing.T) {
	attribute := NewX500Attribute("2.5.4.42", "givenName", "Steven")

	doc := etree.NewDocument()
	doc.SetRoot(attribute.Element())

	out, err := doc.WriteToString()
	require.NoError(t, err)
	assert.Equal(t, out, `<saml:Attribute FriendlyName="givenName" Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" xmlns:x500="urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500" x500:Encoding="LDAP">`+
		`<saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">Steven</saml:AttributeValue></saml:Attribute>`)

	var back Attribute

	require.NoError(t, xml.Unmarshal([]byte(`<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="givenName" Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" xmlns:x500="urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500" x500:Encoding="LDAP">`+
		`<saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">Steven</saml:AttributeValue></saml:Attribute>`), &back))
	assert.Equal(t, back, attribute)

	mixed := NewX500Attribute("2.5.4.42", "givenName")
	mixed.Attrs = append(mixed.Attrs, xml.Attr{Name: xml.Name{Space: "urn:example:other", Local: "Flag"}, Value: "1"})

	doc = etree.NewDocument()
	doc.SetRoot(mixed.Element())

	out, err = doc.WriteToString()
	require.NoError(t, err)
	assert.Contains(t, out, `xmlns:x500="urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500" x500:Encoding="LDAP" xmlns:ns1="urn:example:other" ns1:Flag="1"`)
	assert.Equal(t, 1, strings.Count(out, "xmlns:x500="))
	assert.Equal(t, 1, strings.Count(out, "xmlns:ns1="))
}

func TestNewX500BinaryAttribute(t *testing.T) {
	attribute := NewX500BinaryAttribute("2.5.4.36", "userCertificate", []byte{0x30, 0x03, 0x02, 0x01, 0x05})

	assert.Equal(t, attribute.Name, "urn:oid:2.5.4.36")
	assert.Equal(t, attribute.Attrs, []xml.Attr{x500EncodingAttr()})
	assert.Equal(t, attribute.Values, []AttributeValue{{Type: "xs:base64Binary", Value: "MAMCAQU="}})
}

func TestAttributeNameFormatConstants(t *testing.T) {
	assert.Equal(t, AttributeNameFormatUnspecified, "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified")
	assert.Equal(t, AttributeNameFormatURI, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
	assert.Equal(t, AttributeNameFormatBasic, "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
}
