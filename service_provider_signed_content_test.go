package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml/internal/dsig"
)

// addAttributes adds attributes to the end of the first tag that starts with prefix.
func addAttributes(t *testing.T, body, prefix, attributes string) string {
	t.Helper()
	start := strings.Index(body, prefix)
	assert.Assert(t, start >= 0, "no %s in %s", prefix, body)
	end := start + strings.Index(body[start:], ">")
	if body[end-1] == '/' {
		end--
	}
	return body[:end] + " " + attributes + body[end:]
}

// signedResponseForSP returns a response in plaintext which the test service provider accepts for
// the request id-request, until its validity runs out.
func signedResponseForSP(t *testing.T) (*IdentityProviderTest, string) {
	t.Helper()
	test := NewIdentityProviderTest(t, applyKey)
	test.SP.IDPMetadata = test.IDP.Metadata()

	previousClock := Clock
	t.Cleanup(func() { Clock = previousClock })
	Clock = dsig.NewFakeClockAt(test.Certificate.NotBefore)

	metadata := test.SP.Metadata()
	descriptor := &metadata.SPSSODescriptors[0]
	descriptor.KeyDescriptors = nil
	req := &IdpAuthnRequest{
		IDP:                     &test.IDP,
		HTTPRequest:             httptest.NewRequest("GET", "/", nil),
		Now:                     TimeNow(),
		ServiceProviderMetadata: metadata,
		SPSSODescriptor:         descriptor,
		ACSEndpoint:             &descriptor.AssertionConsumerServices[0],
	}
	req.Request.ID = "id-request"
	req.Request.Issuer = &Issuer{Value: test.SP.MetadataURL.String()}
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "session", NameID: "alice"}))
	assert.NilError(t, req.MakeResponse())

	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)
	body, err := doc.WriteToString()
	assert.NilError(t, err)

	_, err = test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
	assert.NilError(t, err)
	return test, body
}

func TestParseResponseRejectsExpiredResponseWithUnusedDeclarations(t *testing.T) {
	test, body := signedResponseForSP(t)
	issued := TimeNow()
	later := issued.Add(10 * time.Hour)
	TimeNow = func() time.Time { return later }

	_, err := test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
	assert.Assert(t, err != nil, "the response must have expired for this test to mean anything")

	now := later.UTC().Format(time.RFC3339)
	far := later.Add(100 * time.Hour).UTC().Format(time.RFC3339)
	body = addAttributes(t, body, "<samlp:Response ", `xmlns:IssueInstant="`+now+`"`)
	body = addAttributes(t, body, "<saml:Assertion ", `xmlns:IssueInstant="`+now+`"`)
	body = addAttributes(t, body, "<saml:Conditions ", `xmlns:NotOnOrAfter="`+far+`"`)
	body = addAttributes(t, body, "<saml:SubjectConfirmationData ", `xmlns:NotOnOrAfter="`+far+`"`)

	_, err = test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
	assert.Check(t, err != nil)
}

func TestParseResponseRejectsOtherRequestWithUnusedDeclarations(t *testing.T) {
	test, body := signedResponseForSP(t)
	body = addAttributes(t, body, "<samlp:Response ", `xmlns:InResponseTo="id-other"`)
	body = addAttributes(t, body, "<saml:SubjectConfirmationData ", `xmlns:InResponseTo="id-other"`)

	_, err := test.SP.ParseXMLResponse([]byte(body), []string{"id-other"}, test.SP.AcsURL)
	assert.Check(t, err != nil)
}

func TestParseResponseRejectsOtherRecipientWithUnusedDeclarations(t *testing.T) {
	test, body := signedResponseForSP(t)
	other := mustParseURL("https://other.example.com/acs")
	test.SP.AcsURL = other
	body = addAttributes(t, body, "<samlp:Response ", `xmlns:Destination="`+other.String()+`"`)
	body = addAttributes(t, body, "<saml:SubjectConfirmationData ", `xmlns:Recipient="`+other.String()+`"`)

	_, err := test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, other)
	assert.Check(t, err != nil)
}

func TestParseResponseAcceptsUnusedDeclarationsThatChangeNothing(t *testing.T) {
	test, body := signedResponseForSP(t)
	body = addAttributes(t, body, "<samlp:Response ", `xmlns:unused="urn:example:unused"`)

	_, err := test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
	assert.Check(t, err)
}

func TestValidateLogoutResponseRejectsDestinationInUnusedDeclaration(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	TimeNow = time.Now
	previousClock := Clock
	t.Cleanup(func() { Clock = previousClock })
	Clock = dsig.NewFakeClockAt(test.Certificate.NotBefore)

	test.SP.IDPMetadata = test.IDP.Metadata()
	test.SP.SloURL = mustParseURL("https://sp.example.com/saml2/slo")
	test.SP.SignatureMethod = dsig.RSASHA256SignatureMethod
	test.SP.MetadataURL = test.IDP.MetadataURL

	sign := func(destination string) string {
		response, err := test.SP.MakeLogoutResponse(destination, "id-request")
		assert.NilError(t, err)
		doc := etree.NewDocument()
		doc.SetRoot(response.Element())
		body, err := doc.WriteToString()
		assert.NilError(t, err)
		return body
	}
	encode := func(body string) string { return base64.StdEncoding.EncodeToString([]byte(body)) }

	assert.NilError(t, test.SP.ValidateLogoutResponseForm(encode(sign(test.SP.SloURL.String()))))

	body := addAttributes(t, sign("https://other.example.com/slo"), "<samlp:LogoutResponse ", `xmlns:Destination="`+test.SP.SloURL.String()+`"`)
	assert.Check(t, is.ErrorContains(test.SP.ValidateLogoutResponseForm(encode(body)), "Destination"))
}

func TestRemoveUnusedNamespaceDeclarations(t *testing.T) {
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(`<a:root xmlns:a="urn:a" xmlns:b="urn:b" xmlns:c="urn:c" xmlns:d="urn:d" xmlns:e="urn:e" c:attr="1">`+
		`<b:child xmlns:unused="urn:u"/><x xmlns:e="urn:e"><e:y/></x></a:root>`))
	original, err := doc.WriteToString()
	assert.NilError(t, err)

	stripped := removeUnusedNamespaceDeclarations(doc.Root())

	result := etree.NewDocument()
	result.SetRoot(stripped)
	got, err := result.WriteToString()
	assert.NilError(t, err)
	assert.Check(t, is.Equal(got, `<a:root xmlns:a="urn:a" xmlns:b="urn:b" xmlns:c="urn:c" c:attr="1">`+
		`<b:child/><x xmlns:e="urn:e"><e:y/></x></a:root>`))

	after, err := doc.WriteToString()
	assert.NilError(t, err)
	assert.Check(t, is.Equal(after, original), "the signed document must not change")
}

// Serializing a subtree declares the prefixes of the whole document on it, which include those of
// elements outside of what a signature on the subtree covers.
func TestUnmarshalElementIgnoresDeclarationsFromOutsideTheSubtree(t *testing.T) {
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(`<a:root xmlns:a="urn:a">`+
		`<Value:outside xmlns:Value="forged"/><a:signed Value="original"/></a:root>`))

	var signed struct {
		Value string `xml:",attr"`
	}
	assert.NilError(t, unmarshalElement(doc.Root().ChildElements()[1], &signed))
	assert.Check(t, is.Equal(signed.Value, "original"))
}

// With no signature on the response, only the assertion's own signature protects its values.
func TestParseResponseChecksAssertionOnlySignature(t *testing.T) {
	test, body := signedResponseForSP(t)
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(body))
	root := doc.Root()
	root.RemoveChild(root.SelectElement("Signature"))
	issued := TimeNow()
	later := issued.Add(10 * time.Hour)
	now := later.UTC().Format(time.RFC3339)
	far := later.Add(100 * time.Hour).UTC().Format(time.RFC3339)
	root.CreateAttr("IssueInstant", now)
	unsigned, err := doc.WriteToString()
	assert.NilError(t, err)

	_, err = test.SP.ParseXMLResponse([]byte(unsigned), []string{"id-request"}, test.SP.AcsURL)
	assert.NilError(t, err)

	TimeNow = func() time.Time { return later }
	_, err = test.SP.ParseXMLResponse([]byte(unsigned), []string{"id-request"}, test.SP.AcsURL)
	assert.Assert(t, err != nil, "the assertion must have expired for this test to mean anything")

	altered := addAttributes(t, unsigned, "<saml:Assertion ", `xmlns:IssueInstant="`+now+`"`)
	altered = addAttributes(t, altered, "<saml:Conditions ", `xmlns:NotOnOrAfter="`+far+`"`)
	altered = addAttributes(t, altered, "<saml:SubjectConfirmationData ", `xmlns:NotOnOrAfter="`+far+`"`)
	_, err = test.SP.ParseXMLResponse([]byte(altered), []string{"id-request"}, test.SP.AcsURL)
	assert.Check(t, err != nil)
}

func TestParseResponseKeepsAttributeValueTypes(t *testing.T) {
	var value struct {
		Value AttributeValue
	}
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(`<root xmlns:xs="http://www.w3.org/2001/XMLSchema"><Value xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">alice</Value></root>`))
	assert.NilError(t, unmarshalElement(doc.Root(), &value))
	assert.Check(t, is.Equal(value.Value.Type, "xs:string"))
	assert.Check(t, is.Equal(value.Value.Value, "alice"))
}

func TestValidateLogoutResponseRedirectRejectsDestinationInUnusedDeclaration(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	TimeNow = time.Now
	previousClock := Clock
	t.Cleanup(func() { Clock = previousClock })
	Clock = dsig.NewFakeClockAt(test.Certificate.NotBefore)

	test.SP.IDPMetadata = test.IDP.Metadata()
	test.SP.SloURL = mustParseURL("https://sp.example.com/saml2/slo")
	test.SP.SignatureMethod = dsig.RSASHA256SignatureMethod
	test.SP.MetadataURL = test.IDP.MetadataURL

	response, err := test.SP.MakeLogoutResponse("https://other.example.com/slo", "id-request")
	assert.NilError(t, err)
	doc := etree.NewDocument()
	doc.SetRoot(response.Element())
	body, err := doc.WriteToString()
	assert.NilError(t, err)
	body = addAttributes(t, body, "<samlp:LogoutResponse ", `xmlns:Destination="`+test.SP.SloURL.String()+`"`)

	var compressed bytes.Buffer
	w, err := flate.NewWriter(&compressed, flate.BestCompression)
	assert.NilError(t, err)
	_, err = w.Write([]byte(body))
	assert.NilError(t, err)
	assert.NilError(t, w.Close())

	err = test.SP.ValidateLogoutResponseRedirect(&url.URL{RawQuery: "SAMLResponse=" + url.QueryEscape(base64.StdEncoding.EncodeToString(compressed.Bytes()))})
	assert.Check(t, is.ErrorContains(err, "Destination"))
}

// useInSignature makes content inside the signature use a prefix. An enveloped signature doesn't
// cover itself, so this doesn't make a declaration of that prefix part of what was signed.
func useInSignature(t *testing.T, body, prefix string) string {
	t.Helper()
	const end = "</ds:Signature>"
	assert.Assert(t, strings.Contains(body, end))
	return strings.Replace(body, end, "<"+prefix+":x/>"+end, 1)
}

func TestParseResponseRejectsDeclarationUsedOnlyInSignature(t *testing.T) {
	test, body := signedResponseForSP(t)
	later := TimeNow().Add(10 * time.Hour)
	TimeNow = func() time.Time { return later }

	body = useInSignature(t, body, "IssueInstant")
	body = addAttributes(t, body, "<samlp:Response ", `xmlns:IssueInstant="`+later.UTC().Format(time.RFC3339)+`"`)

	_, err := test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
	var invalid *InvalidResponseError
	assert.Assert(t, errors.As(err, &invalid), "got %v", err)
	assert.Check(t, is.ErrorContains(invalid.PrivateErr, "response IssueInstant expired"))
}

// logoutResponseWithDeclarationUsedInSignature returns a signed response for another destination,
// with a declaration of the expected one.
func logoutResponseWithDeclarationUsedInSignature(t *testing.T) (*IdentityProviderTest, string) {
	t.Helper()
	test := NewIdentityProviderTest(t, applyKey)
	TimeNow = time.Now
	previousClock := Clock
	t.Cleanup(func() { Clock = previousClock })
	Clock = dsig.NewFakeClockAt(test.Certificate.NotBefore)

	test.SP.IDPMetadata = test.IDP.Metadata()
	test.SP.SloURL = mustParseURL("https://sp.example.com/saml2/slo")
	test.SP.SignatureMethod = dsig.RSASHA256SignatureMethod
	test.SP.MetadataURL = test.IDP.MetadataURL

	response, err := test.SP.MakeLogoutResponse("https://other.example.com/slo", "id-request")
	assert.NilError(t, err)
	doc := etree.NewDocument()
	doc.SetRoot(response.Element())
	body, err := doc.WriteToString()
	assert.NilError(t, err)

	body = useInSignature(t, body, "Destination")
	return test, addAttributes(t, body, "<samlp:LogoutResponse ", `xmlns:Destination="`+test.SP.SloURL.String()+`"`)
}

func TestValidateLogoutResponseFormRejectsDeclarationUsedOnlyInSignature(t *testing.T) {
	test, body := logoutResponseWithDeclarationUsedInSignature(t)

	err := test.SP.ValidateLogoutResponseForm(base64.StdEncoding.EncodeToString([]byte(body)))
	assert.Check(t, is.ErrorContains(err, "Destination"))
}

func TestValidateLogoutResponseRedirectRejectsDeclarationUsedOnlyInSignature(t *testing.T) {
	test, body := logoutResponseWithDeclarationUsedInSignature(t)

	var compressed bytes.Buffer
	w, err := flate.NewWriter(&compressed, flate.BestCompression)
	assert.NilError(t, err)
	_, err = w.Write([]byte(body))
	assert.NilError(t, err)
	assert.NilError(t, w.Close())

	err = test.SP.ValidateLogoutResponseRedirect(&url.URL{RawQuery: "SAMLResponse=" + url.QueryEscape(base64.StdEncoding.EncodeToString(compressed.Bytes()))})
	assert.Check(t, is.ErrorContains(err, "Destination"))
}

func TestRemoveUnusedNamespaceDeclarationsIgnoresSignatureContent(t *testing.T) {
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(`<a:root xmlns:a="urn:a" xmlns:signed="urn:s" xmlns:onlysig="urn:o" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`+
		`<ds:Signature><onlysig:x/><signed:x/></ds:Signature><signed:y/></a:root>`))

	result := etree.NewDocument()
	result.SetRoot(removeUnusedNamespaceDeclarations(doc.Root()))
	got, err := result.WriteToString()
	assert.NilError(t, err)
	assert.Check(t, is.Equal(got, `<a:root xmlns:a="urn:a" xmlns:signed="urn:s">`+
		`<ds:Signature><onlysig:x/><signed:x/></ds:Signature><signed:y/></a:root>`))
}
