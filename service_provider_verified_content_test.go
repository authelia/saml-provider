package saml

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml/internal/dsig"
)

const signatureDeclaration = `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`

// rebindSignaturePrefix alters a signed element without changing what its signature covers. The
// namespace of the first signature moves to the signed element, which starts with rootPrefix, along
// with attributes. The signature's content uses the prefix used, and declares prefix again deep inside.
func rebindSignaturePrefix(t *testing.T, body, rootPrefix, attributes, used, prefix string) string {
	t.Helper()
	start := strings.Index(body, rootPrefix)
	assert.Assert(t, start >= 0)
	head, rest := body[:start], body[start:]
	assert.Assert(t, strings.Contains(rest, signatureDeclaration))

	open := "<" + prefix + ":Signature>"
	shut := "</" + prefix + ":Signature>"
	rest = strings.Replace(rest, signatureDeclaration, open, 1)
	end := strings.Index(rest, "</ds:Signature>")
	assert.Assert(t, end >= 0)

	deep := "<" + prefix + `:deep xmlns:` + prefix + `="urn:other"/>`
	for range 12 {
		deep = "<n>" + deep + "</n>"
	}
	rest = rest[:end] + "<" + used + ":x/>" + deep + shut + rest[end+len("</ds:Signature>"):]

	declarations := `xmlns:ds="` + dsig.Namespace + `"`
	if prefix != "ds" {
		declarations += ` xmlns:` + prefix + `="` + dsig.Namespace + `"`
	}
	return addAttributes(t, head+rest, rootPrefix, declarations+" "+attributes)
}

func signedLogoutResponseForOtherDestination(t *testing.T) (*IdentityProviderTest, string) {
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
	return test, body
}

func TestValidateLogoutResponseUsesSignedAttributesWhenSignaturePrefixIsRebound(t *testing.T) {
	for _, prefix := range []string{"ds", "zz"} {
		t.Run(prefix, func(t *testing.T) {
			test, body := signedLogoutResponseForOtherDestination(t)
			altered := rebindSignaturePrefix(t, body, "<samlp:LogoutResponse ",
				`xmlns:Destination="`+test.SP.SloURL.String()+`"`, "Destination", prefix)

			err := test.SP.ValidateLogoutResponseForm(base64.StdEncoding.EncodeToString([]byte(altered)))
			assert.Check(t, is.ErrorContains(err, "Destination"))
		})
	}
}

func TestParseResponseUsesSignedAttributesWhenSignaturePrefixIsRebound(t *testing.T) {
	for _, prefix := range []string{"ds", "zz"} {
		t.Run(prefix, func(t *testing.T) {
			test, body := signedResponseForSP(t)
			later := TimeNow().Add(10 * time.Hour)
			TimeNow = func() time.Time { return later }
			altered := rebindSignaturePrefix(t, body, "<samlp:Response ",
				`xmlns:IssueInstant="`+later.UTC().Format(time.RFC3339)+`"`, "IssueInstant", prefix)

			_, err := test.SP.ParseXMLResponse([]byte(altered), []string{"id-request"}, test.SP.AcsURL)
			var invalid *InvalidResponseError
			assert.Assert(t, errors.As(err, &invalid), "got %v", err)
			assert.Check(t, is.ErrorContains(invalid.PrivateErr, "response IssueInstant expired"))
		})
	}
}

// Only the assertion is signed here, so only its signature protects its attributes.
func TestParseAssertionUsesSignedAttributesWhenSignaturePrefixIsRebound(t *testing.T) {
	test, body := signedResponseForSP(t)
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(body))
	doc.Root().RemoveChild(doc.Root().SelectElement("Signature"))
	issued := TimeNow()
	later := issued.Add(MaxIssueDelay + time.Second)
	now := later.UTC().Format(time.RFC3339)
	doc.Root().CreateAttr("IssueInstant", now)
	unsigned, err := doc.WriteToString()
	assert.NilError(t, err)

	altered := rebindSignaturePrefix(t, unsigned, "<saml:Assertion ", `xmlns:IssueInstant="`+now+`"`, "IssueInstant", "ds")

	TimeNow = func() time.Time { return later }
	_, err = test.SP.ParseXMLResponse([]byte(altered), []string{"id-request"}, test.SP.AcsURL)
	var invalid *InvalidResponseError
	assert.Assert(t, errors.As(err, &invalid), "got %v", err)
	assert.Check(t, is.ErrorContains(invalid.PrivateErr, "expired on"))
}

// recordingVerifier verifies in the same way as the default, as an implementation outside of this
// module would, and provides no verified element.
type recordingVerifier struct{}

func (recordingVerifier) VerifySignature(validationContext *ValidationContext, el *etree.Element) error {
	_, err := validationContext.Validate(el)
	return err
}

func TestSignatureVerifierPathIgnoresReboundSignaturePrefix(t *testing.T) {
	for _, prefix := range []string{"ds", "zz"} {
		t.Run(prefix, func(t *testing.T) {
			test, body := signedLogoutResponseForOtherDestination(t)
			test.SP.SignatureVerifier = recordingVerifier{}
			altered := rebindSignaturePrefix(t, body, "<samlp:LogoutResponse ",
				`xmlns:Destination="`+test.SP.SloURL.String()+`"`, "Destination", prefix)

			err := test.SP.ValidateLogoutResponseForm(base64.StdEncoding.EncodeToString([]byte(altered)))
			assert.Check(t, is.ErrorContains(err, "Destination"))
		})
	}
}

// A prefix from outside of the subtree must not change what is declared on it.
func TestElementToBytesDoesNotRebindDeclarationOnSubtree(t *testing.T) {
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(`<a:root xmlns:a="urn:a"><b:signed xmlns:b="urn:b"><c:x xmlns:c="urn:c"/></b:signed><b:out xmlns:b="urn:other"/></a:root>`))

	buf, err := elementToBytes(doc.Root().ChildElements()[0])
	assert.NilError(t, err)
	assert.Check(t, is.Contains(string(buf), `xmlns:b="urn:b"`))
	assert.Check(t, !strings.Contains(string(buf), "urn:other"))
}

func TestParseArtifactResponseUsesSignedAttributes(t *testing.T) {
	test, body := signedResponseForSP(t)
	issued := TimeNow()

	inner := etree.NewDocument()
	assert.NilError(t, inner.ReadFromString(body))
	artifact := etree.NewElement("samlp:ArtifactResponse")
	artifact.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	artifact.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	artifact.CreateAttr("ID", "id-artifact-response")
	artifact.CreateAttr("InResponseTo", "id-artifact")
	artifact.CreateAttr("Version", "2.0")
	artifact.CreateAttr("IssueInstant", issued.UTC().Format(time.RFC3339))
	status := artifact.CreateElement("samlp:Status")
	status.CreateElement("samlp:StatusCode").CreateAttr("Value", StatusSuccess)
	artifact.AddChild(inner.Root())

	req := &IdpAuthnRequest{IDP: &test.IDP}
	signingContext, err := req.signingContext()
	assert.NilError(t, err)
	signed, err := signingContext.SignEnveloped(artifact)
	assert.NilError(t, err)

	doc := etree.NewDocument()
	doc.SetRoot(signed)
	signedBody, err := doc.WriteToString()
	assert.NilError(t, err)

	parse := func(xml string) error {
		parsed := etree.NewDocument()
		assert.NilError(t, parsed.ReadFromString(xml))
		_, err := test.SP.parseArtifactResponse(parsed.Root(), []string{"id-request"}, "id-artifact", TimeNow(), test.SP.AcsURL)
		return err
	}
	assert.NilError(t, parse(signedBody))

	later := issued.Add(10 * time.Hour)
	TimeNow = func() time.Time { return later }
	altered := addAttributes(t, signedBody, "<samlp:ArtifactResponse ", `xmlns:IssueInstant="`+later.UTC().Format(time.RFC3339)+`"`)

	err = parse(altered)
	var invalid *InvalidResponseError
	assert.Assert(t, errors.As(err, &invalid), "got %v", err)
	assert.Check(t, is.ErrorContains(invalid.PrivateErr, "response IssueInstant expired"))
}

func TestVerifySignatureReturnsOnlyWhatTheSignatureCovers(t *testing.T) {
	test, body := signedLogoutResponseForOtherDestination(t)
	altered := addAttributes(t, body, "<samlp:LogoutResponse ", `xmlns:Destination="https://sp.example.com/saml2/slo"`)
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(altered))

	verified, err := test.SP.verifySignature(doc.Root())
	assert.NilError(t, err)
	assert.Check(t, verified.SelectAttr("xmlns:Destination") == nil)
	assert.Check(t, is.Equal(verified.SelectAttrValue("Destination", ""), "https://other.example.com/slo"))
}

// An inner declaration of a prefix applies only below it, even when it's the shallowest use.
func TestElementToBytesUsesBindingsInScopeAtTheElement(t *testing.T) {
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(`<a:root xmlns:a="urn:a" xmlns:b="urn:outer">`+
		`<a:el><a:inner xmlns:b="urn:inner"><b:x/></a:inner><a:n><a:m><b:y/></a:m></a:n></a:el></a:root>`))

	buf, err := elementToBytes(doc.Root().ChildElements()[0])
	assert.NilError(t, err)

	parsed := etree.NewDocument()
	assert.NilError(t, parsed.ReadFromBytes(buf))
	assert.Check(t, is.Equal(parsed.Root().SelectAttrValue("xmlns:b", ""), "urn:outer"))
	assert.Check(t, is.Equal(parsed.Root().FindElement(".//y").NamespaceURI(), "urn:outer"))
	assert.Check(t, is.Equal(parsed.Root().FindElement(".//x").NamespaceURI(), "urn:inner"))
}

func TestElementToBytesLeavesInnerDeclarationsWithDescendants(t *testing.T) {
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(`<a:root xmlns:a="urn:a"><a:el><c:x xmlns:c="urn:c"/></a:el></a:root>`))

	buf, err := elementToBytes(doc.Root().ChildElements()[0])
	assert.NilError(t, err)

	parsed := etree.NewDocument()
	assert.NilError(t, parsed.ReadFromBytes(buf))
	assert.Check(t, parsed.Root().SelectAttr("xmlns:c") == nil)
	assert.Check(t, is.Equal(parsed.Root().FindElement(".//x").NamespaceURI(), "urn:c"))
}

func TestElementToBytesCopiesDefaultNamespaceInScope(t *testing.T) {
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(`<a:root xmlns:a="urn:a" xmlns="urn:default"><el/></a:root>`))

	buf, err := elementToBytes(doc.Root().ChildElements()[0])
	assert.NilError(t, err)

	parsed := etree.NewDocument()
	assert.NilError(t, parsed.ReadFromBytes(buf))
	assert.Check(t, is.Equal(parsed.Root().NamespaceURI(), "urn:default"))
}

func TestElementToBytesReturnsErrorForInvalidNamespaceContext(t *testing.T) {
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(`<a:root xmlns:a="urn:a" xmlns:xmlns="urn:reserved"><a:el/></a:root>`))

	_, err := elementToBytes(doc.Root().ChildElements()[0])
	assert.Check(t, err != nil)
}
