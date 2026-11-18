package saml

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
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

	assert.Assert(t, len(tags) >= 2, "children: %v", tags)
	assert.Check(t, is.DeepEqual(tags[:2], []string{"Issuer", "Extensions"}))

	doc := etree.NewDocument()
	doc.SetRoot(el)

	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)

	parsed := PT(new(T))
	assert.NilError(t, xml.Unmarshal(buf, parsed), string(buf))

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
			assert.Check(t, is.DeepEqual(got(t), want))
		})
	}
}

func TestProtocolExtensionsAbsentByDefault(t *testing.T) {
	el := (&Response{ID: "id-1", Version: "2.0", Status: Status{StatusCode: StatusCode{Value: StatusSuccess}}}).Element()
	assert.Check(t, el.FindElement("./Extensions") == nil)

	var req AuthnRequest
	assert.NilError(t, xml.Unmarshal([]byte(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id-1" Version="2.0"/>`), &req))
	assert.Check(t, req.Extensions == nil)
	assert.Check(t, req.Extensions.Find(extensionsTestNamespace, "Hint") == nil)
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
	assert.NilError(t, xml.Unmarshal([]byte(raw), &req))

	// The text of a protocol extension is kept as it is, where that of a metadata extension is trimmed.
	want := extensionsTestValue()
	want.Elements[0].Children[0].Content = " 42 "
	assert.Check(t, is.DeepEqual(req.Extensions, want))

	hint := req.Extensions.Find(extensionsTestNamespace, "Hint")
	assert.Assert(t, hint != nil)
	assert.Check(t, is.Equal(hint.Children[0].Content, " 42 "))
	assert.Check(t, req.Extensions.Find(extensionsTestNamespace, "Flag") == nil)
}

func TestProtocolExtensionsElementDeclaresNamespaces(t *testing.T) {
	doc := etree.NewDocument()
	doc.SetRoot(extensionsTestValue().Element())

	out, err := doc.WriteToString()
	assert.NilError(t, err)
	assert.Check(t, is.Equal(out, `<samlp:Extensions>`+
		`<Hint xmlns="urn:example:extension" kind="a" xmlns:ns1="urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500" ns1:Encoding="LDAP">`+
		`<Value xmlns="urn:example:extension">42</Value></Hint>`+
		`<Flag xmlns="urn:example:other"/>`+
		`</samlp:Extensions>`))
}

func TestProtocolExtensionsCheck(t *testing.T) {
	var none *ProtocolExtensions
	assert.Check(t, none.check())
	assert.Check(t, extensionsTestValue().check())

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
			assert.Check(t, is.ErrorContains(tc.extensions.check(), tc.err))
		})
	}
}

func TestProtocolExtensionsCheckAcceptsValidNames(t *testing.T) {
	extensions := &ProtocolExtensions{Elements: []ExtensionElement{{
		XMLName:  xml.Name{Space: extensionsTestNamespace, Local: "_Hint-1.é"},
		Attrs:    []xml.Attr{{Name: xml.Name{Space: xmlNamespace, Local: "lang"}, Value: "en"}},
		Children: []ExtensionElement{{XMLName: xml.Name{Space: extensionsTestNamespace, Local: "Value"}}},
	}}}

	assert.Check(t, extensions.check())
}

func TestProtocolExtensionsCloneSharesNothing(t *testing.T) {
	original := extensionsTestValue()
	clone := original.clone()
	assert.Check(t, is.DeepEqual(clone, original))

	clone.Elements[0].Attrs[0].Value = "changed"
	clone.Elements[0].Children[0].Content = "changed"

	assert.Check(t, is.DeepEqual(original, extensionsTestValue()))
}
