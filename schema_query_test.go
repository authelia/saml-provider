package saml

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func queryElementBytes(t *testing.T, el *etree.Element) []byte {
	t.Helper()

	doc := etree.NewDocument()
	doc.SetRoot(el)

	buf, err := doc.WriteToBytes()
	require.NoError(t, err)

	return buf
}

func TestAttributeQueryRoundTrip(t *testing.T) {
	query := &AttributeQuery{
		ID:           "id-1",
		Version:      "2.0",
		IssueInstant: time.Date(2015, 12, 1, 1, 57, 9, 0, time.UTC),
		Destination:  "https://idp.example.com/saml/attributes",
		Consent:      "urn:oasis:names:tc:SAML:2.0:consent:obtained",
		Issuer:       &Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: "https://sp.example.com"},
		Subject: &Subject{NameID: &NameID{
			Format:          string(PersistentNameIDFormat),
			NameQualifier:   "https://idp.example.com",
			SPNameQualifier: "https://sp.example.com",
			Value:           "abc",
		}},
		Attributes: []Attribute{
			{Name: "urn:oid:2.5.4.42", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", FriendlyName: "givenName"},
			{Name: "role", Values: []AttributeValue{{Type: "xs:string", Value: "admin"}, {Type: "xs:string", Value: "auditor"}}},
		},
	}

	buf := queryElementBytes(t, query.Element())
	assert.Equal(t, string(buf), `<samlp:AttributeQuery xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`+
		` ID="id-1" Version="2.0" IssueInstant="2015-12-01T01:57:09Z" Destination="https://idp.example.com/saml/attributes"`+
		` Consent="urn:oasis:names:tc:SAML:2.0:consent:obtained">`+
		`<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://sp.example.com</saml:Issuer>`+
		`<saml:Subject><saml:NameID NameQualifier="https://idp.example.com" SPNameQualifier="https://sp.example.com"`+
		` Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">abc</saml:NameID></saml:Subject>`+
		`<saml:Attribute FriendlyName="givenName" Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>`+
		`<saml:Attribute Name="role">`+
		`<saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">admin</saml:AttributeValue>`+
		`<saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">auditor</saml:AttributeValue>`+
		`</saml:Attribute></samlp:AttributeQuery>`)

	parsed := &AttributeQuery{}
	require.NoError(t, xml.Unmarshal(buf, parsed))
	assert.Equal(t, parsed.ID, query.ID)
	assert.Equal(t, parsed.Version, query.Version)
	assert.True(t, parsed.IssueInstant.Equal(query.IssueInstant))
	assert.Equal(t, parsed.Destination, query.Destination)
	assert.Equal(t, parsed.Consent, query.Consent)
	require.NotNil(t, parsed.Issuer)
	assert.Equal(t, parsed.Issuer.Value, "https://sp.example.com")
	require.True(t, parsed.Subject != nil && parsed.Subject.NameID != nil)
	assert.Equal(t, *parsed.Subject.NameID, *query.Subject.NameID)
	assert.Equal(t, parsed.Attributes, query.Attributes)

	// The types marshal with encoding/xml too, and parse back.
	marshalled, err := xml.Marshal(query)
	require.NoError(t, err)

	again := &AttributeQuery{}
	require.NoError(t, xml.Unmarshal(marshalled, again))
	assert.Equal(t, again.ID, query.ID)
	assert.True(t, again.IssueInstant.Equal(query.IssueInstant))
	assert.Equal(t, again.Attributes, query.Attributes)
}

func TestAttributeQueryWithoutAttributes(t *testing.T) {
	// The example of SAMLProfiles §8.2.6, shortened, with the prefixes of another implementation.
	const input = `<p:AttributeQuery xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion"` +
		` ID="aaf23196-1773-2113-474a-fe114412ab72" Version="2.0" IssueInstant="2006-07-17T20:31:40Z">` +
		`<a:Issuer>https://sp.example.com</a:Issuer>` +
		`<a:Subject><a:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName">CN=trscavo@uiuc.edu,OU=User,O=NCSA-TEST,C=US</a:NameID></a:Subject>` +
		`</p:AttributeQuery>`

	parsed := &AttributeQuery{}
	require.NoError(t, xml.Unmarshal([]byte(input), parsed))
	assert.Equal(t, parsed.ID, "aaf23196-1773-2113-474a-fe114412ab72")
	assert.Equal(t, parsed.Destination, "")
	assert.Len(t, parsed.Attributes, 0)
	require.True(t, parsed.Subject != nil && parsed.Subject.NameID != nil)
	assert.Equal(t, parsed.Subject.NameID.Value, "CN=trscavo@uiuc.edu,OU=User,O=NCSA-TEST,C=US")

	// An element of another namespace is not an AttributeQuery.
	assert.True(t, xml.Unmarshal([]byte(`<AttributeQuery xmlns="urn:example:other" ID="x"/>`), &AttributeQuery{}) != nil)
}

func TestAuthnQueryRoundTrip(t *testing.T) {
	query := &AuthnQuery{
		ID:           "id-2",
		Version:      "2.0",
		IssueInstant: time.Date(2015, 12, 1, 1, 57, 9, 0, time.UTC),
		Issuer:       &Issuer{Value: "https://sp.example.com"},
		Subject:      &Subject{NameID: &NameID{Value: "abc"}},
		SessionIndex: "index-1",
		RequestedAuthnContext: &RequestedAuthnContext{
			Comparison:            AuthnContextComparisonMinimum,
			AuthnContextClassRefs: []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:Password"},
		},
	}

	buf := queryElementBytes(t, query.Element())
	assert.Equal(t, string(buf), `<samlp:AuthnQuery xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`+
		` ID="id-2" Version="2.0" IssueInstant="2015-12-01T01:57:09Z" SessionIndex="index-1">`+
		`<saml:Issuer>https://sp.example.com</saml:Issuer>`+
		`<saml:Subject><saml:NameID>abc</saml:NameID></saml:Subject>`+
		`<samlp:RequestedAuthnContext Comparison="minimum"><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>`+
		`</samlp:AuthnQuery>`)

	parsed := &AuthnQuery{}
	require.NoError(t, xml.Unmarshal(buf, parsed))
	assert.Equal(t, parsed.ID, query.ID)
	assert.True(t, parsed.IssueInstant.Equal(query.IssueInstant))
	assert.Equal(t, parsed.SessionIndex, "index-1")
	require.True(t, parsed.Subject != nil && parsed.Subject.NameID != nil)
	assert.Equal(t, parsed.Subject.NameID.Value, "abc")
	require.NotNil(t, parsed.RequestedAuthnContext)
	assert.Equal(t, parsed.RequestedAuthnContext.Comparison, AuthnContextComparisonMinimum)
	assert.Equal(t, parsed.RequestedAuthnContext.AuthnContextClassRefs, query.RequestedAuthnContext.AuthnContextClassRefs)

	bare := &AuthnQuery{}
	require.NoError(t, xml.Unmarshal(queryElementBytes(t, (&AuthnQuery{ID: "id-3", Version: "2.0"}).Element()), bare))
	assert.Equal(t, bare.SessionIndex, "")
	assert.Nil(t, bare.RequestedAuthnContext)
	assert.Nil(t, bare.Subject)
	assert.Nil(t, bare.Issuer)

	marshalled, err := xml.Marshal(query)
	require.NoError(t, err)

	again := &AuthnQuery{}
	require.NoError(t, xml.Unmarshal(marshalled, again))
	assert.Equal(t, again.SessionIndex, "index-1")
	assert.True(t, again.IssueInstant.Equal(query.IssueInstant))
}

func TestAssertionIDRequestRoundTrip(t *testing.T) {
	request := &AssertionIDRequest{
		ID:              "id-4",
		Version:         "2.0",
		IssueInstant:    time.Date(2015, 12, 1, 1, 57, 9, 0, time.UTC),
		Destination:     "https://idp.example.com/saml/assertion-id",
		Issuer:          &Issuer{Value: "https://sp.example.com"},
		AssertionIDRefs: []AssertionIDRef{{Value: "id-a"}, {Value: "id-b"}},
	}

	buf := queryElementBytes(t, request.Element())
	assert.Equal(t, string(buf), `<samlp:AssertionIDRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`+
		` ID="id-4" Version="2.0" IssueInstant="2015-12-01T01:57:09Z" Destination="https://idp.example.com/saml/assertion-id">`+
		`<saml:Issuer>https://sp.example.com</saml:Issuer>`+
		`<saml:AssertionIDRef>id-a</saml:AssertionIDRef><saml:AssertionIDRef>id-b</saml:AssertionIDRef>`+
		`</samlp:AssertionIDRequest>`)

	parsed := &AssertionIDRequest{}
	require.NoError(t, xml.Unmarshal(buf, parsed))
	assert.Equal(t, parsed.ID, request.ID)
	assert.True(t, parsed.IssueInstant.Equal(request.IssueInstant))
	assert.Equal(t, parsed.Destination, request.Destination)
	assert.Equal(t, parsed.AssertionIDRefs, request.AssertionIDRefs)

	marshalled, err := xml.Marshal(request)
	require.NoError(t, err)

	again := &AssertionIDRequest{}
	require.NoError(t, xml.Unmarshal(marshalled, again))
	assert.Equal(t, again.AssertionIDRefs, request.AssertionIDRefs)
	assert.True(t, again.IssueInstant.Equal(request.IssueInstant))
}

// The signature of a request goes after the Issuer, where SAMLCore §3.2.1 has it.
func TestQueryElementsPlaceSignatureAfterIssuer(t *testing.T) {
	signature := func() *etree.Element { return etree.NewElement("ds:Signature") }
	issuer := &Issuer{Value: "https://sp.example.com"}
	subject := &Subject{NameID: &NameID{Value: "abc"}}

	for name, el := range map[string]*etree.Element{
		"AttributeQuery":     (&AttributeQuery{Issuer: issuer, Signature: signature(), Subject: subject}).Element(),
		"AuthnQuery":         (&AuthnQuery{Issuer: issuer, Signature: signature(), Subject: subject}).Element(),
		"AssertionIDRequest": (&AssertionIDRequest{Issuer: issuer, Signature: signature(), AssertionIDRefs: []AssertionIDRef{{Value: "id-a"}}}).Element(),
	} {
		t.Run(name, func(t *testing.T) {
			children := el.ChildElements()
			require.Len(t, children, 3)
			assert.Equal(t, children[0].Tag, "Issuer")
			assert.Equal(t, children[1].Tag, "Signature")
		})
	}
}
