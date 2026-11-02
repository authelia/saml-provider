package saml

import (
	"encoding/base64"
	"encoding/xml"
	"html"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// errorResponseRequest returns a validated request, which has selected an ACS endpoint.
func errorResponseRequest(t *testing.T) (*IdentityProviderTest, *IdpAuthnRequest) {
	t.Helper()
	test := NewIdentityProviderTest(t, applyKey)
	req, err := hardeningValidate(test, hardeningRequest(`ID="id-request"`, TimeNow(), hardeningIssuer))
	assert.NilError(t, err)
	req.RelayState = "relay-<state>"
	return test, req
}

// postedResponse extracts and parses the SAMLResponse from the HTML form that was written.
func postedResponse(t *testing.T, body string) (*etree.Document, Response) {
	t.Helper()
	const marker = `name="SAMLResponse" value="`
	start := strings.Index(body, marker)
	assert.Assert(t, start >= 0, "no SAMLResponse in %q", body)
	encoded, _, _ := strings.Cut(body[start+len(marker):], `"`)
	buf, err := base64.StdEncoding.DecodeString(html.UnescapeString(encoded))
	assert.NilError(t, err)

	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(buf))

	var response Response
	assert.NilError(t, xml.Unmarshal(buf, &response))
	return doc, response
}

func TestWriteErrorResponseWritesSignedStatus(t *testing.T) {
	test, req := errorResponseRequest(t)

	w := httptest.NewRecorder()
	assert.NilError(t, req.WriteErrorResponse(w, StatusResponder, StatusNoPassive, "cannot <authenticate> passively"))

	assert.Check(t, is.Contains(w.Body.String(), `action="https://sp.example.com/saml2/acs"`))
	assert.Check(t, is.Contains(w.Body.String(), `name="RelayState" value="relay-&lt;state&gt;"`))

	doc, response := postedResponse(t, w.Body.String())
	assert.Check(t, is.Equal(response.InResponseTo, "id-request"))
	assert.Check(t, is.Equal(response.Destination, "https://sp.example.com/saml2/acs"))
	assert.Check(t, is.Equal(response.Issuer.Value, test.IDP.MetadataURL.String()))
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusResponder))
	assert.Assert(t, response.Status.StatusCode.StatusCode != nil)
	assert.Check(t, is.Equal(response.Status.StatusCode.StatusCode.Value, StatusNoPassive))
	assert.Assert(t, response.Status.StatusMessage != nil)
	assert.Check(t, is.Equal(response.Status.StatusMessage.Value, "cannot <authenticate> passively"))

	test.SP.IDPMetadata = test.IDP.Metadata()
	// The certificate of the test identity provider has expired by the time that the tests use.
	previousClock := Clock
	t.Cleanup(func() { Clock = previousClock })
	Clock = dsig.NewFakeClockAt(test.Certificate.NotBefore)
	assert.Check(t, test.SP.validateSignature(doc.Root()))

	// The signature must cover the status, which is what the service provider acts on.
	doc.Root().FindElement("./Status/StatusCode").CreateAttr("Value", StatusSuccess)
	assert.Check(t, test.SP.validateSignature(doc.Root()) != nil)
}

func TestWriteErrorResponseOmitsOptionalStatusParts(t *testing.T) {
	_, req := errorResponseRequest(t)

	w := httptest.NewRecorder()
	assert.NilError(t, req.WriteErrorResponse(w, StatusRequester, "", ""))

	_, response := postedResponse(t, w.Body.String())
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusRequester))
	assert.Check(t, response.Status.StatusCode.StatusCode == nil)
	assert.Check(t, response.Status.StatusMessage == nil)
}

// An assertion made before the failure was found must not reach the service provider.
func TestWriteErrorResponseDropsExistingAssertion(t *testing.T) {
	_, req := errorResponseRequest(t)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "session", NameID: "alice"}))
	assert.NilError(t, req.MakeResponse())

	w := httptest.NewRecorder()
	assert.NilError(t, req.WriteErrorResponse(w, StatusResponder, StatusRequestDenied, ""))

	doc, response := postedResponse(t, w.Body.String())
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusResponder))
	assert.Check(t, response.Assertion == nil)
	assert.Check(t, response.EncryptedAssertion == nil)
	assert.Check(t, doc.Root().FindElement("./Assertion") == nil)
	assert.Check(t, doc.Root().FindElement("./EncryptedAssertion") == nil)
}

// Sending a response to an endpoint that was not validated would let an unauthenticated client
// choose where a signed message goes.
func TestWriteErrorResponseRequiresValidatedACS(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req := &IdpAuthnRequest{IDP: &test.IDP, Now: TimeNow()}
	req.Request.AssertionConsumerServiceURL = "https://attacker.example.com/acs"

	w := httptest.NewRecorder()
	err := req.WriteErrorResponse(w, StatusRequester, "", "")

	assert.Check(t, is.ErrorContains(err, "assertion consumer service"))
	assert.Check(t, is.Equal(w.Body.Len(), 0))
}

func TestWriteErrorResponseRejectsInvalidTopLevelStatus(t *testing.T) {
	for _, status := range []string{"", StatusSuccess, StatusNoPassive} {
		t.Run(status, func(t *testing.T) {
			_, req := errorResponseRequest(t)

			w := httptest.NewRecorder()
			err := req.WriteErrorResponse(w, status, "", "")

			assert.Check(t, is.ErrorContains(err, "top-level status"))
			assert.Check(t, is.Equal(w.Body.Len(), 0))
		})
	}
}
