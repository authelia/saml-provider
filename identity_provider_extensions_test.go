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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.Equal(t, w.Code, http.StatusOK, "body: %s", w.Body.String())
	assert.Equal(t, got, extensionsTestValue())
}

func TestIssuanceResponseExtensions(t *testing.T) {
	test := issuanceTestIDP(t)
	issuanceFor(test, ServiceProviderIssuance{ResponseExtensions: extensionsTestValue()})

	responseEl, responseXML, requestID := issuanceSSO(t, test)

	tags := make([]string, 0, len(responseEl.ChildElements()))
	for _, child := range responseEl.ChildElements() {
		tags = append(tags, child.Tag)
	}

	require.True(t, len(tags) >= 3, "children: %v", tags)
	assert.Equal(t, tags[:3], []string{"Issuer", "Signature", "Extensions"})

	// The extensions are covered by the signature of the response, which the service provider accepts.
	issuanceAccept(t, &test.SP, responseXML, []string{requestID})

	var response Response
	require.NoError(t, xml.Unmarshal(responseXML, &response))
	assert.Equal(t, response.Extensions, extensionsTestValue())

	assertExtensionsTamperBreaksSignature(t, &test.SP, responseEl)
}

// assertExtensionsTamperBreaksSignature checks that the signature of a copy of responseEl, whose extensions have
// one value changed, no longer verifies.
func assertExtensionsTamperBreaksSignature(t *testing.T, sp *ServiceProvider, responseEl *etree.Element) {
	t.Helper()

	require.NoError(t, sp.validateSignature(responseEl.Copy()))

	tampered := responseEl.Copy()
	hint := tampered.FindElement("./Extensions/Hint")
	require.NotNil(t, hint)
	require.True(t, hint.SelectAttrValue("kind", "") == "a")
	hint.CreateAttr("kind", "b")

	assert.NotNil(t, sp.validateSignature(tampered))
}

func TestIssuanceResponseExtensionsSignResponseWhenAssertionOnly(t *testing.T) {
	test := issuanceTestIDP(t)
	issuanceFor(test, ServiceProviderIssuance{Sign: SignAssertion, ResponseExtensions: extensionsTestValue()})

	responseEl, responseXML, requestID := issuanceSSO(t, test)

	// The extensions are outside the assertion, so the Response is signed to cover them.
	response, assertion, _ := issuanceSignatures(t, &test.SP, responseEl)
	assert.NotNil(t, response)
	assert.NotNil(t, assertion)

	issuanceAccept(t, &test.SP, responseXML, []string{requestID})
	assertExtensionsTamperBreaksSignature(t, &test.SP, responseEl)
}

func TestIssuanceResponseExtensionsCheckedOnlyForSSO(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	issuanceFor(test, ServiceProviderIssuance{ResponseExtensions: &ProtocolExtensions{}})

	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	require.NoError(t, err)

	_, err = req.Issuance(nil)
	assert.ErrorContains(t, err, "ResponseExtensions")

	// An assertion that answers a query is issued with no endpoint, and carries no extensions.
	req.ACSEndpoint = nil
	_, err = req.Issuance(nil)
	assert.NoError(t, err)

	_, err = test.IDP.signingContextFor(req.HTTPRequest, req.ServiceProviderMetadata)
	assert.NoError(t, err)
}

func TestIssuanceResponseExtensionsOnErrorResponse(t *testing.T) {
	test := issuanceTestIDP(t)
	issuanceFor(test, ServiceProviderIssuance{ResponseExtensions: extensionsTestValue()})

	test.IDP.AssertionMaker = assertionMakerFunc(func(*IdpAuthnRequest, *Session) error { return errors.New("boom") })

	body := signedPostBody(t, &test.SP, nil)
	w := serveSSO(test, replayPostRequest(body, nil))
	assertRequestStatus(t, w, authnRequestID(t, body), StatusResponder, "")

	doc, _ := postedResponse(t, w.Body.String())
	assert.NotNil(t, doc.Root().FindElement("./Extensions/Hint"))
	require.NoError(t, test.SP.validateSignature(doc.Root()))

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
			assert.Equal(t, w.Code, http.StatusInternalServerError)
			assert.False(t, strings.Contains(w.Body.String(), "SAMLResponse"))
			assert.Contains(t, logs.String(), "ResponseExtensions")
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

	require.True(t, found != nil, "the attribute was not released")
	assert.Equal(t, found.OriginalIssuer, "https://idp.example.com/saml")
	assert.True(t, found.LastModified.Equal(lastModified))
	assert.Equal(t, found.Attrs, attributeExtValue().Attrs)
}
