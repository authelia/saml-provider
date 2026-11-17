package saml

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func queryElementBytes(t *testing.T, el *etree.Element) []byte {
	t.Helper()

	doc := etree.NewDocument()
	doc.SetRoot(el)

	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)

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
	assert.Check(t, is.Equal(string(buf), `<samlp:AttributeQuery xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`+
		` ID="id-1" Version="2.0" IssueInstant="2015-12-01T01:57:09Z" Destination="https://idp.example.com/saml/attributes"`+
		` Consent="urn:oasis:names:tc:SAML:2.0:consent:obtained">`+
		`<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://sp.example.com</saml:Issuer>`+
		`<saml:Subject><saml:NameID NameQualifier="https://idp.example.com" SPNameQualifier="https://sp.example.com"`+
		` Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">abc</saml:NameID></saml:Subject>`+
		`<saml:Attribute FriendlyName="givenName" Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>`+
		`<saml:Attribute Name="role">`+
		`<saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">admin</saml:AttributeValue>`+
		`<saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">auditor</saml:AttributeValue>`+
		`</saml:Attribute></samlp:AttributeQuery>`))

	parsed := &AttributeQuery{}
	assert.NilError(t, xml.Unmarshal(buf, parsed))
	assert.Check(t, is.Equal(parsed.ID, query.ID))
	assert.Check(t, is.Equal(parsed.Version, query.Version))
	assert.Check(t, parsed.IssueInstant.Equal(query.IssueInstant))
	assert.Check(t, is.Equal(parsed.Destination, query.Destination))
	assert.Check(t, is.Equal(parsed.Consent, query.Consent))
	assert.Assert(t, parsed.Issuer != nil)
	assert.Check(t, is.Equal(parsed.Issuer.Value, "https://sp.example.com"))
	assert.Assert(t, parsed.Subject != nil && parsed.Subject.NameID != nil)
	assert.Check(t, is.DeepEqual(*parsed.Subject.NameID, *query.Subject.NameID))
	assert.Check(t, is.DeepEqual(parsed.Attributes, query.Attributes))

	// The types marshal with encoding/xml too, and parse back.
	marshalled, err := xml.Marshal(query)
	assert.NilError(t, err)

	again := &AttributeQuery{}
	assert.NilError(t, xml.Unmarshal(marshalled, again))
	assert.Check(t, is.Equal(again.ID, query.ID))
	assert.Check(t, again.IssueInstant.Equal(query.IssueInstant))
	assert.Check(t, is.DeepEqual(again.Attributes, query.Attributes))
}

func TestAttributeQueryWithoutAttributes(t *testing.T) {
	// The example of SAMLProfiles §8.2.6, shortened, with the prefixes of another implementation.
	const input = `<p:AttributeQuery xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion"` +
		` ID="aaf23196-1773-2113-474a-fe114412ab72" Version="2.0" IssueInstant="2006-07-17T20:31:40Z">` +
		`<a:Issuer>https://sp.example.com</a:Issuer>` +
		`<a:Subject><a:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName">CN=trscavo@uiuc.edu,OU=User,O=NCSA-TEST,C=US</a:NameID></a:Subject>` +
		`</p:AttributeQuery>`

	parsed := &AttributeQuery{}
	assert.NilError(t, xml.Unmarshal([]byte(input), parsed))
	assert.Check(t, is.Equal(parsed.ID, "aaf23196-1773-2113-474a-fe114412ab72"))
	assert.Check(t, is.Equal(parsed.Destination, ""))
	assert.Check(t, is.Len(parsed.Attributes, 0))
	assert.Assert(t, parsed.Subject != nil && parsed.Subject.NameID != nil)
	assert.Check(t, is.Equal(parsed.Subject.NameID.Value, "CN=trscavo@uiuc.edu,OU=User,O=NCSA-TEST,C=US"))

	// An element of another namespace is not an AttributeQuery.
	assert.Check(t, xml.Unmarshal([]byte(`<AttributeQuery xmlns="urn:example:other" ID="x"/>`), &AttributeQuery{}) != nil)
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
	assert.Check(t, is.Equal(string(buf), `<samlp:AuthnQuery xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`+
		` ID="id-2" Version="2.0" IssueInstant="2015-12-01T01:57:09Z" SessionIndex="index-1">`+
		`<saml:Issuer>https://sp.example.com</saml:Issuer>`+
		`<saml:Subject><saml:NameID>abc</saml:NameID></saml:Subject>`+
		`<samlp:RequestedAuthnContext Comparison="minimum"><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>`+
		`</samlp:AuthnQuery>`))

	parsed := &AuthnQuery{}
	assert.NilError(t, xml.Unmarshal(buf, parsed))
	assert.Check(t, is.Equal(parsed.ID, query.ID))
	assert.Check(t, parsed.IssueInstant.Equal(query.IssueInstant))
	assert.Check(t, is.Equal(parsed.SessionIndex, "index-1"))
	assert.Assert(t, parsed.Subject != nil && parsed.Subject.NameID != nil)
	assert.Check(t, is.Equal(parsed.Subject.NameID.Value, "abc"))
	assert.Assert(t, parsed.RequestedAuthnContext != nil)
	assert.Check(t, is.Equal(parsed.RequestedAuthnContext.Comparison, AuthnContextComparisonMinimum))
	assert.Check(t, is.DeepEqual(parsed.RequestedAuthnContext.AuthnContextClassRefs, query.RequestedAuthnContext.AuthnContextClassRefs))

	bare := &AuthnQuery{}
	assert.NilError(t, xml.Unmarshal(queryElementBytes(t, (&AuthnQuery{ID: "id-3", Version: "2.0"}).Element()), bare))
	assert.Check(t, is.Equal(bare.SessionIndex, ""))
	assert.Check(t, bare.RequestedAuthnContext == nil)
	assert.Check(t, bare.Subject == nil)
	assert.Check(t, bare.Issuer == nil)

	marshalled, err := xml.Marshal(query)
	assert.NilError(t, err)

	again := &AuthnQuery{}
	assert.NilError(t, xml.Unmarshal(marshalled, again))
	assert.Check(t, is.Equal(again.SessionIndex, "index-1"))
	assert.Check(t, again.IssueInstant.Equal(query.IssueInstant))
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
	assert.Check(t, is.Equal(string(buf), `<samlp:AssertionIDRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`+
		` ID="id-4" Version="2.0" IssueInstant="2015-12-01T01:57:09Z" Destination="https://idp.example.com/saml/assertion-id">`+
		`<saml:Issuer>https://sp.example.com</saml:Issuer>`+
		`<saml:AssertionIDRef>id-a</saml:AssertionIDRef><saml:AssertionIDRef>id-b</saml:AssertionIDRef>`+
		`</samlp:AssertionIDRequest>`))

	parsed := &AssertionIDRequest{}
	assert.NilError(t, xml.Unmarshal(buf, parsed))
	assert.Check(t, is.Equal(parsed.ID, request.ID))
	assert.Check(t, parsed.IssueInstant.Equal(request.IssueInstant))
	assert.Check(t, is.Equal(parsed.Destination, request.Destination))
	assert.Check(t, is.DeepEqual(parsed.AssertionIDRefs, request.AssertionIDRefs))

	marshalled, err := xml.Marshal(request)
	assert.NilError(t, err)

	again := &AssertionIDRequest{}
	assert.NilError(t, xml.Unmarshal(marshalled, again))
	assert.Check(t, is.DeepEqual(again.AssertionIDRefs, request.AssertionIDRefs))
	assert.Check(t, again.IssueInstant.Equal(request.IssueInstant))
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
			assert.Assert(t, is.Len(children, 3))
			assert.Check(t, is.Equal(children[0].Tag, "Issuer"))
			assert.Check(t, is.Equal(children[1].Tag, "Signature"))
		})
	}
}
