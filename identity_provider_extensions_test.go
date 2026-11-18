package saml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestIdentityProviderReadsRequestExtensions(t *testing.T) {
	test := issuanceTestIDP(t)

	var got *ProtocolExtensions

	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(_ http.ResponseWriter, _ *http.Request, req *IdpAuthnRequest) *Session {
			got = req.Request.Extensions

			return &Session{ID: "f00f00", UserName: "alice", NameID: "alice"}
		},
	}

	// The extensions are signed with the request, which is verified before they are read.
	body := signedPostBody(t, &test.SP, func(request *AuthnRequest) { request.Extensions = extensionsTestValue() })

	w := serveSSO(test, replayPostRequest(body, nil))
	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())
	assert.Check(t, is.DeepEqual(got, extensionsTestValue()))
}

func TestIssuanceResponseExtensions(t *testing.T) {
	test := issuanceTestIDP(t)
	issuanceFor(test, ServiceProviderIssuance{ResponseExtensions: extensionsTestValue()})

	responseEl, responseXML, requestID := issuanceSSO(t, test)

	tags := make([]string, 0, len(responseEl.ChildElements()))
	for _, child := range responseEl.ChildElements() {
		tags = append(tags, child.Tag)
	}

	assert.Assert(t, len(tags) >= 3, "children: %v", tags)
	assert.Check(t, is.DeepEqual(tags[:3], []string{"Issuer", "Signature", "Extensions"}))

	// The extensions are covered by the signature of the response, which the service provider accepts.
	issuanceAccept(t, &test.SP, responseXML, []string{requestID})

	var response Response
	assert.NilError(t, xml.Unmarshal(responseXML, &response))
	assert.Check(t, is.DeepEqual(response.Extensions, extensionsTestValue()))

	assertExtensionsTamperBreaksSignature(t, &test.SP, responseEl)
}

// assertExtensionsTamperBreaksSignature checks that the signature of a copy of responseEl, whose extensions have
// one value changed, no longer verifies.
func assertExtensionsTamperBreaksSignature(t *testing.T, sp *ServiceProvider, responseEl *etree.Element) {
	t.Helper()

	assert.NilError(t, sp.validateSignature(responseEl.Copy()))

	tampered := responseEl.Copy()
	hint := tampered.FindElement("./Extensions/Hint")
	assert.Assert(t, hint != nil)
	assert.Assert(t, hint.SelectAttrValue("kind", "") == "a")
	hint.CreateAttr("kind", "b")

	assert.Check(t, sp.validateSignature(tampered) != nil)
}

func TestIssuanceResponseExtensionsSignResponseWhenAssertionOnly(t *testing.T) {
	test := issuanceTestIDP(t)
	issuanceFor(test, ServiceProviderIssuance{Sign: SignAssertion, ResponseExtensions: extensionsTestValue()})

	responseEl, responseXML, requestID := issuanceSSO(t, test)

	// The extensions are outside the assertion, so the Response is signed to cover them.
	response, assertion, _ := issuanceSignatures(t, &test.SP, responseEl)
	assert.Check(t, response != nil)
	assert.Check(t, assertion != nil)

	issuanceAccept(t, &test.SP, responseXML, []string{requestID})
	assertExtensionsTamperBreaksSignature(t, &test.SP, responseEl)
}

func TestIssuanceResponseExtensionsCheckedOnlyForSSO(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	issuanceFor(test, ServiceProviderIssuance{ResponseExtensions: &ProtocolExtensions{}})

	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	assert.NilError(t, err)

	_, err = req.Issuance(nil)
	assert.Check(t, is.ErrorContains(err, "ResponseExtensions"))

	// An assertion that answers a query is issued with no endpoint, and carries no extensions.
	req.ACSEndpoint = nil
	_, err = req.Issuance(nil)
	assert.Check(t, err)

	_, err = test.IDP.signingContextFor(req.HTTPRequest, req.ServiceProviderMetadata)
	assert.Check(t, err)
}

func TestIssuanceResponseExtensionsOnErrorResponse(t *testing.T) {
	test := issuanceTestIDP(t)
	issuanceFor(test, ServiceProviderIssuance{ResponseExtensions: extensionsTestValue()})

	test.IDP.AssertionMaker = assertionMakerFunc(func(*IdpAuthnRequest, *Session) error { return errors.New("boom") })

	body := signedPostBody(t, &test.SP, nil)
	w := serveSSO(test, replayPostRequest(body, nil))
	assertRequestStatus(t, w, authnRequestID(t, body), StatusResponder, "")

	doc, _ := postedResponse(t, w.Body.String())
	assert.Check(t, doc.Root().FindElement("./Extensions/Hint") != nil)
	assert.NilError(t, test.SP.validateSignature(doc.Root()))

	assertExtensionsTamperBreaksSignature(t, &test.SP, doc.Root())
}

func TestIssuanceRefusesInvalidResponseExtensions(t *testing.T) {
	for name, extensions := range map[string]*ProtocolExtensions{
		"empty":        {},
		"no namespace": {Elements: []ExtensionElement{{XMLName: xml.Name{Local: "Hint"}}}},
		"saml":         {Elements: []ExtensionElement{{XMLName: xml.Name{Space: samlProtocolNS, Local: "Hint"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			test := issuanceTestIDP(t)
			issuanceFor(test, ServiceProviderIssuance{ResponseExtensions: extensions})

			logs := &bytes.Buffer{}
			test.IDP.Observer = logObserver(logs)

			w := serveSSO(test, replayPostRequest(signedPostBody(t, &test.SP, nil), nil))
			assert.Check(t, is.Equal(w.Code, http.StatusInternalServerError))
			assert.Check(t, !strings.Contains(w.Body.String(), "SAMLResponse"))
			assert.Check(t, is.Contains(logs.String(), "ResponseExtensions"))
		})
	}
}

func TestIssuanceReleasesAttributeExtensions(t *testing.T) {
	test := issuanceTestIDP(t)
	test.IDP.AttributeReleasePolicy = releaseEveryAttribute
	issuanceMetadata(test, issuanceUnencrypted)

	lastModified := time.Date(2008, 10, 31, 12, 46, 2, 0, time.UTC)

	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
			return &Session{ID: "f00f00", UserName: "alice", NameID: "alice", CustomAttributes: []Attribute{attributeExtValue()}}
		},
	}

	_, responseXML, requestID := issuanceSSO(t, test)

	assertion := issuanceAccept(t, &test.SP, responseXML, []string{requestID})

	var found *Attribute

	for _, statement := range assertion.AttributeStatements {
		for i := range statement.Attributes {
			if statement.Attributes[i].Name == "urn:oid:2.5.4.42" {
				found = &statement.Attributes[i]
			}
		}
	}

	assert.Assert(t, found != nil, "the attribute was not released")
	assert.Check(t, is.Equal(found.OriginalIssuer, "https://idp.example.com/saml"))
	assert.Check(t, found.LastModified.Equal(lastModified))
	assert.Check(t, is.DeepEqual(found.Attrs, attributeExtValue().Attrs))
}
