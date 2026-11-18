package saml

import (
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	extensionsTestNamespace = "urn:example:extension"
	x500Namespace           = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500"
)

// extensionsTestValue returns protocol extensions with an element that has an attribute in a namespace, an
// attribute in none, text and a child.
func extensionsTestValue() *ProtocolExtensions {
	return &ProtocolExtensions{Elements: []ExtensionElement{
		{
			XMLName: xml.Name{Space: extensionsTestNamespace, Local: "Hint"},
			Attrs: []xml.Attr{
				{Name: xml.Name{Local: "kind"}, Value: "a"},
				{Name: xml.Name{Space: x500Namespace, Local: "Encoding"}, Value: "LDAP"},
			},
			Children: []ExtensionElement{{XMLName: xml.Name{Space: extensionsTestNamespace, Local: "Value"}, Content: "42"}},
		},
		{XMLName: xml.Name{Space: "urn:example:other", Local: "Flag"}},
	}}
}

// extensionsRoundTrip marshals msg with Element, checks that the Extensions follow the Issuer, unmarshals it again
// and returns its Extensions.
func extensionsRoundTrip[T any, PT interface {
	*T
	Element() *etree.Element
}](t *testing.T, msg PT, extensions func(PT) *ProtocolExtensions,
) *ProtocolExtensions {
	t.Helper()

	el := msg.Element()

	tags := make([]string, 0, len(el.ChildElements()))
	for _, child := range el.ChildElements() {
		tags = append(tags, child.Tag)
	}

	require.True(t, len(tags) >= 2, "children: %v", tags)
	assert.Equal(t, tags[:2], []string{"Issuer", "Extensions"})

	doc := etree.NewDocument()
	doc.SetRoot(el)

	buf, err := doc.WriteToBytes()
	require.NoError(t, err)

	parsed := PT(new(T))
	require.NoError(t, xml.Unmarshal(buf, parsed), string(buf))

	return extensions(parsed)
}

func TestProtocolExtensionsRoundTripOnEveryMessage(t *testing.T) {
	issuer := func() *Issuer { return &Issuer{Value: "https://sp.example.com"} }
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	want := extensionsTestValue()

	for name, got := range map[string]func(t *testing.T) *ProtocolExtensions{
		"AuthnRequest": func(t *testing.T) *ProtocolExtensions {
			return extensionsRoundTrip(t, &AuthnRequest{ID: "id-1", Version: "2.0", IssueInstant: now, Issuer: issuer(), Extensions: want,
				Subject: &Subject{NameID: &NameID{Value: "alice"}}},
				func(m *AuthnRequest) *ProtocolExtensions { return m.Extensions })
		},
		"LogoutRequest": func(t *testing.T) *ProtocolExtensions {
			return extensionsRoundTrip(t, &LogoutRequest{ID: "id-1", Version: "2.0", IssueInstant: now, Issuer: issuer(), Extensions: want,
				NameID: &NameID{Value: "alice"}},
				func(m *LogoutRequest) *ProtocolExtensions { return m.Extensions })
		},
		"LogoutResponse": func(t *testing.T) *ProtocolExtensions {
			return extensionsRoundTrip(t, &LogoutResponse{ID: "id-1", Version: "2.0", IssueInstant: now, Issuer: issuer(), Extensions: want,
				Status: Status{StatusCode: StatusCode{Value: StatusSuccess}}},
				func(m *LogoutResponse) *ProtocolExtensions { return m.Extensions })
		},
		"Response": func(t *testing.T) *ProtocolExtensions {
			return extensionsRoundTrip(t, &Response{ID: "id-1", Version: "2.0", IssueInstant: now, Issuer: issuer(), Extensions: want,
				Status: Status{StatusCode: StatusCode{Value: StatusSuccess}}},
				func(m *Response) *ProtocolExtensions { return m.Extensions })
		},
		"ArtifactResolve": func(t *testing.T) *ProtocolExtensions {
			return extensionsRoundTrip(t, &ArtifactResolve{ID: "id-1", Version: "2.0", IssueInstant: now, Issuer: issuer(), Extensions: want,
				Artifact: "AAQAAA"},
				func(m *ArtifactResolve) *ProtocolExtensions { return m.Extensions })
		},
		"ArtifactResponse": func(t *testing.T) *ProtocolExtensions {
			return extensionsRoundTrip(t, &ArtifactResponse{ID: "id-1", Version: "2.0", IssueInstant: now, Issuer: issuer(), Extensions: want,
				Status: Status{StatusCode: StatusCode{Value: StatusSuccess}}},
				func(m *ArtifactResponse) *ProtocolExtensions { return m.Extensions })
		},
		"AttributeQuery": func(t *testing.T) *ProtocolExtensions {
			return extensionsRoundTrip(t, &AttributeQuery{ID: "id-1", Version: "2.0", IssueInstant: now, Issuer: issuer(), Extensions: want,
				Subject: &Subject{NameID: &NameID{Value: "alice"}}},
				func(m *AttributeQuery) *ProtocolExtensions { return m.Extensions })
		},
		"AuthnQuery": func(t *testing.T) *ProtocolExtensions {
			return extensionsRoundTrip(t, &AuthnQuery{ID: "id-1", Version: "2.0", IssueInstant: now, Issuer: issuer(), Extensions: want,
				Subject: &Subject{NameID: &NameID{Value: "alice"}}},
				func(m *AuthnQuery) *ProtocolExtensions { return m.Extensions })
		},
		"AssertionIDRequest": func(t *testing.T) *ProtocolExtensions {
			return extensionsRoundTrip(t, &AssertionIDRequest{ID: "id-1", Version: "2.0", IssueInstant: now, Issuer: issuer(), Extensions: want,
				AssertionIDRefs: []AssertionIDRef{{Value: "id-2"}}},
				func(m *AssertionIDRequest) *ProtocolExtensions { return m.Extensions })
		},
		"ManageNameIDRequest": func(t *testing.T) *ProtocolExtensions {
			return extensionsRoundTrip(t, &ManageNameIDRequest{ID: "id-1", Version: "2.0", IssueInstant: now, Issuer: issuer(), Extensions: want,
				NameID: &NameID{Value: "alice"}, Terminate: true},
				func(m *ManageNameIDRequest) *ProtocolExtensions { return m.Extensions })
		},
		"ManageNameIDResponse": func(t *testing.T) *ProtocolExtensions {
			return extensionsRoundTrip(t, &ManageNameIDResponse{ID: "id-1", Version: "2.0", IssueInstant: now, Issuer: issuer(), Extensions: want,
				Status: Status{StatusCode: StatusCode{Value: StatusSuccess}}},
				func(m *ManageNameIDResponse) *ProtocolExtensions { return m.Extensions })
		},
		"NameIDMappingRequest": func(t *testing.T) *ProtocolExtensions {
			return extensionsRoundTrip(t, &NameIDMappingRequest{ID: "id-1", Version: "2.0", IssueInstant: now, Issuer: issuer(), Extensions: want,
				NameID: &NameID{Value: "alice"}, NameIDPolicy: &NameIDPolicy{}},
				func(m *NameIDMappingRequest) *ProtocolExtensions { return m.Extensions })
		},
		"NameIDMappingResponse": func(t *testing.T) *ProtocolExtensions {
			return extensionsRoundTrip(t, &NameIDMappingResponse{ID: "id-1", Version: "2.0", IssueInstant: now, Issuer: issuer(), Extensions: want,
				Status: Status{StatusCode: StatusCode{Value: StatusSuccess}}, NameID: &NameID{Value: "alice"}},
				func(m *NameIDMappingResponse) *ProtocolExtensions { return m.Extensions })
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, got(t), want)
		})
	}
}

func TestProtocolExtensionsAbsentByDefault(t *testing.T) {
	el := (&Response{ID: "id-1", Version: "2.0", Status: Status{StatusCode: StatusCode{Value: StatusSuccess}}}).Element()
	assert.Nil(t, el.FindElement("./Extensions"))

	var req AuthnRequest
	require.NoError(t, xml.Unmarshal([]byte(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id-1" Version="2.0"/>`), &req))
	assert.Nil(t, req.Extensions)
	assert.True(t, req.Extensions.Find(extensionsTestNamespace, "Hint") == nil)
}

func TestProtocolExtensionsParsedFromRequest(t *testing.T) {
	const raw = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:x="urn:example:extension"
		xmlns:x500="urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500" ID="id-1" Version="2.0">
		<saml:Issuer>https://sp.example.com</saml:Issuer>
		<samlp:Extensions>
			<x:Hint kind="a" x500:Encoding="LDAP"><x:Value> 42 </x:Value></x:Hint>
			<Flag xmlns="urn:example:other"/>
		</samlp:Extensions>
	</samlp:AuthnRequest>`

	var req AuthnRequest
	require.NoError(t, xml.Unmarshal([]byte(raw), &req))

	// The text of a protocol extension is kept as it is, where that of a metadata extension is trimmed.
	want := extensionsTestValue()
	want.Elements[0].Children[0].Content = " 42 "
	assert.Equal(t, req.Extensions, want)

	hint := req.Extensions.Find(extensionsTestNamespace, "Hint")
	require.NotNil(t, hint)
	assert.Equal(t, hint.Children[0].Content, " 42 ")
	assert.True(t, req.Extensions.Find(extensionsTestNamespace, "Flag") == nil)
}

func TestProtocolExtensionsElementDeclaresNamespaces(t *testing.T) {
	doc := etree.NewDocument()
	doc.SetRoot(extensionsTestValue().Element())

	out, err := doc.WriteToString()
	require.NoError(t, err)
	assert.Equal(t, out, `<samlp:Extensions>`+
		`<Hint xmlns="urn:example:extension" kind="a" xmlns:ns1="urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500" ns1:Encoding="LDAP">`+
		`<Value xmlns="urn:example:extension">42</Value></Hint>`+
		`<Flag xmlns="urn:example:other"/>`+
		`</samlp:Extensions>`)
}

func TestProtocolExtensionsCheck(t *testing.T) {
	var none *ProtocolExtensions
	assert.NoError(t, none.check())
	assert.NoError(t, extensionsTestValue().check())

	for name, tc := range map[string]struct {
		extensions *ProtocolExtensions
		err        string
	}{
		"empty":               {&ProtocolExtensions{}, "at least one element"},
		"no namespace":        {&ProtocolExtensions{Elements: []ExtensionElement{{XMLName: xml.Name{Local: "Hint"}}}}, "in no namespace"},
		"assertion namespace": {&ProtocolExtensions{Elements: []ExtensionElement{{XMLName: xml.Name{Space: samlAssertionNS, Local: "Hint"}}}}, "SAML namespace"},
		"protocol namespace":  {&ProtocolExtensions{Elements: []ExtensionElement{{XMLName: xml.Name{Space: samlProtocolNS, Local: "Hint"}}}}, "SAML namespace"},
		"empty name":          {&ProtocolExtensions{Elements: []ExtensionElement{{XMLName: xml.Name{Space: extensionsTestNamespace}}}}, "not a valid XML name"},
		"invalid name":        {&ProtocolExtensions{Elements: []ExtensionElement{{XMLName: xml.Name{Space: extensionsTestNamespace, Local: "1Hint"}}}}, "not a valid XML name"},
		"invalid UTF-8 name":  {&ProtocolExtensions{Elements: []ExtensionElement{{XMLName: xml.Name{Space: extensionsTestNamespace, Local: "\xff"}}}}, "not a valid XML name"},
		"invalid UTF-8 child name": {&ProtocolExtensions{Elements: []ExtensionElement{{
			XMLName:  xml.Name{Space: extensionsTestNamespace, Local: "Hint"},
			Children: []ExtensionElement{{XMLName: xml.Name{Space: extensionsTestNamespace, Local: "Va\xfflue"}}},
		}}}, "not a valid XML name"},
		"invalid UTF-8 attribute name": {&ProtocolExtensions{Elements: []ExtensionElement{{
			XMLName: xml.Name{Space: extensionsTestNamespace, Local: "Hint"},
			Attrs:   []xml.Attr{{Name: xml.Name{Local: "\xff"}, Value: "c"}},
		}}}, "not a valid XML name"},
		"prefixed name": {&ProtocolExtensions{Elements: []ExtensionElement{{XMLName: xml.Name{Space: extensionsTestNamespace, Local: "x:Hint"}}}}, "not a valid XML name"},
		"invalid child name": {&ProtocolExtensions{Elements: []ExtensionElement{{
			XMLName:  xml.Name{Space: extensionsTestNamespace, Local: "Hint"},
			Children: []ExtensionElement{{XMLName: xml.Name{Space: extensionsTestNamespace, Local: "Va lue"}}},
		}}}, `"Va lue" is not a valid XML name`},
		"invalid attribute name": {&ProtocolExtensions{Elements: []ExtensionElement{{
			XMLName: xml.Name{Space: extensionsTestNamespace, Local: "Hint"},
			Attrs:   []xml.Attr{{Name: xml.Name{Local: "a=b"}, Value: "c"}},
		}}}, "not a valid XML name"},
		"namespace declaration": {&ProtocolExtensions{Elements: []ExtensionElement{{
			XMLName: xml.Name{Space: extensionsTestNamespace, Local: "Hint"},
			Attrs:   []xml.Attr{{Name: xml.Name{Local: "xmlns"}, Value: "urn:example:other"}},
		}}}, "namespace declaration"},
	} {
		t.Run(name, func(t *testing.T) {
			assert.ErrorContains(t, tc.extensions.check(), tc.err)
		})
	}
}

func TestProtocolExtensionsCheckAcceptsValidNames(t *testing.T) {
	extensions := &ProtocolExtensions{Elements: []ExtensionElement{{
		XMLName:  xml.Name{Space: extensionsTestNamespace, Local: "_Hint-1.é"},
		Attrs:    []xml.Attr{{Name: xml.Name{Space: xmlNamespace, Local: "lang"}, Value: "en"}},
		Children: []ExtensionElement{{XMLName: xml.Name{Space: extensionsTestNamespace, Local: "Value"}}},
	}}}

	assert.NoError(t, extensions.check())
}

func TestProtocolExtensionsCloneSharesNothing(t *testing.T) {
	original := extensionsTestValue()
	clone := original.clone()
	assert.Equal(t, clone, original)

	clone.Elements[0].Attrs[0].Value = "changed"
	clone.Elements[0].Children[0].Content = "changed"

	assert.Equal(t, original, extensionsTestValue())
}

const attributeExtRaw = `<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
	xmlns:ext="urn:oasis:names:tc:SAML:attribute:ext" xmlns:x500="urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500"
	NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" Name="urn:oid:2.5.4.42" FriendlyName="givenName"
	ext:OriginalIssuer="https://idp.example.com/saml" ext:LastModified="2008-10-31T12:46:02Z" x500:Encoding="LDAP">
	<saml:AttributeValue>Scott</saml:AttributeValue>
</saml:Attribute>`

// attributeExtValue is the Attribute of attributeExtRaw.
func attributeExtValue() Attribute {
	return Attribute{
		FriendlyName:   "givenName",
		Name:           "urn:oid:2.5.4.42",
		NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
		OriginalIssuer: "https://idp.example.com/saml",
		LastModified:   time.Date(2008, 10, 31, 12, 46, 2, 0, time.UTC),
		Attrs:          []xml.Attr{{Name: xml.Name{Space: x500Namespace, Local: "Encoding"}, Value: "LDAP"}},
		Values:         []AttributeValue{{Value: "Scott"}},
	}
}

func TestAttributeExtensionsParsed(t *testing.T) {
	var attribute Attribute
	require.NoError(t, xml.Unmarshal([]byte(attributeExtRaw), &attribute))
	assert.Equal(t, attribute, attributeExtValue())
}

func TestAttributeExtensionsInvalidLastModifiedIsKept(t *testing.T) {
	raw := strings.Replace(attributeExtRaw, "2008-10-31T12:46:02Z", "yesterday", 1)

	var attribute Attribute
	require.NoError(t, xml.Unmarshal([]byte(raw), &attribute))
	assert.True(t, attribute.LastModified.IsZero())
	assert.Equal(t, attribute.Attrs, []xml.Attr{
		{Name: xml.Name{Space: x500Namespace, Local: "Encoding"}, Value: "LDAP"},
		{Name: xml.Name{Space: attributeExtNamespace, Local: "LastModified"}, Value: "yesterday"},
	})
}

func TestAttributeExtensionsElement(t *testing.T) {
	attribute := attributeExtValue()

	doc := etree.NewDocument()
	doc.SetRoot(attribute.Element())

	buf, err := doc.WriteToBytes()
	require.NoError(t, err)

	el := doc.Root()
	assert.Equal(t, el.SelectAttrValue("xmlns:ext", ""), attributeExtNamespace)
	assert.Equal(t, el.SelectAttrValue("ext:OriginalIssuer", ""), "https://idp.example.com/saml")
	assert.Equal(t, el.SelectAttrValue("ext:LastModified", ""), "2008-10-31T12:46:02Z")

	var parsed Attribute
	require.NoError(t, xml.Unmarshal(buf, &parsed), string(buf))
	assert.Equal(t, parsed, attribute)
}

func TestAttributeWithoutExtensionsElementIsUnchanged(t *testing.T) {
	attribute := Attribute{Name: "urn:oid:2.5.4.42", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"}

	doc := etree.NewDocument()
	doc.SetRoot(attribute.Element())

	out, err := doc.WriteToString()
	require.NoError(t, err)
	assert.Equal(t, out, `<saml:Attribute Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>`)
}

func TestAttributeExtensionsMarshalXML(t *testing.T) {
	attribute := attributeExtValue()

	buf, err := xml.Marshal(attribute)
	require.NoError(t, err)
	assert.Contains(t, string(buf), `xmlns:ext="urn:oasis:names:tc:SAML:attribute:ext"`)
	assert.Contains(t, string(buf), `ext:OriginalIssuer="https://idp.example.com/saml"`)

	var parsed Attribute
	require.NoError(t, xml.Unmarshal(buf, &parsed), string(buf))
	assert.Equal(t, parsed, attribute)
}

func TestRequestedAttributeKeepsIsRequiredAndExtensions(t *testing.T) {
	required := true
	requested := RequestedAttribute{Attribute: attributeExtValue(), IsRequired: &required}

	buf, err := xml.Marshal(requested)
	require.NoError(t, err)
	assert.Contains(t, string(buf), `isRequired="true"`)

	var parsed RequestedAttribute
	require.NoError(t, xml.Unmarshal(buf, &parsed), string(buf))
	assert.Equal(t, parsed, requested)

	var optional RequestedAttribute
	require.NoError(t, xml.Unmarshal([]byte(`<RequestedAttribute Name="a"/>`), &optional))
	assert.Nil(t, optional.IsRequired)

	assert.ErrorContains(t, xml.Unmarshal([]byte(`<RequestedAttribute Name="a" isRequired="maybe"/>`), &optional), "isRequired")
}

func TestEntityAttributesMarshalAttributeExtensions(t *testing.T) {
	extensions := Extensions{EntityAttributes: &EntityAttributes{Attributes: []Attribute{attributeExtValue()}}}

	buf, err := xml.Marshal(struct {
		XMLName    xml.Name    `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
		Extensions *Extensions `xml:"urn:oasis:names:tc:SAML:2.0:metadata Extensions"`
	}{Extensions: &extensions})
	require.NoError(t, err)
	assert.Contains(t, string(buf), `ext:OriginalIssuer="https://idp.example.com/saml"`)
	assert.Contains(t, string(buf), `ext:LastModified="2008-10-31T12:46:02Z"`)

	var parsed struct {
		Extensions Extensions `xml:"urn:oasis:names:tc:SAML:2.0:metadata Extensions"`
	}
	require.NoError(t, xml.Unmarshal(buf, &parsed), string(buf))
	require.True(t, parsed.Extensions.EntityAttributes != nil, string(buf))
	assert.Equal(t, parsed.Extensions.EntityAttributes.Attributes[0], attributeExtValue())
}
