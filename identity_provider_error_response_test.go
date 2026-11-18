package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"html"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/dsig"
)

// errorResponseRequest returns a validated request, which has selected an ACS endpoint.
func errorResponseRequest(t *testing.T) (*IdentityProviderTest, *IdpAuthnRequest) {
	t.Helper()
	test := NewIdentityProviderTest(t, applyKey)
	req, err := hardeningValidate(test, hardeningRequest(`ID="id-request"`, TimeNow(), hardeningIssuer))
	require.NoError(t, err)

	req.RelayState = "relay-<state>"

	return test, req
}

// postedResponse extracts and parses the SAMLResponse from the HTML form that was written.
func postedResponse(t *testing.T, body string) (*etree.Document, Response) {
	t.Helper()

	const marker = `name="SAMLResponse" value="`

	start := strings.Index(body, marker)
	require.True(t, start >= 0, "no SAMLResponse in %q", body)
	encoded, _, _ := strings.Cut(body[start+len(marker):], `"`)
	buf, err := base64.StdEncoding.DecodeString(html.UnescapeString(encoded))
	require.NoError(t, err)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(buf))

	var response Response
	require.NoError(t, xml.Unmarshal(buf, &response))

	return doc, response
}

func TestWriteErrorResponseWritesSignedStatus(t *testing.T) {
	test, req := errorResponseRequest(t)

	w := httptest.NewRecorder()
	require.NoError(t, req.WriteErrorResponse(w, ErrNoPassive.WithStatusMessage("cannot <authenticate> passively")))

	assert.Contains(t, w.Body.String(), `action="https://sp.example.com/saml2/acs"`)
	assert.Contains(t, w.Body.String(), `name="RelayState" value="relay-&lt;state&gt;"`)

	doc, response := postedResponse(t, w.Body.String())
	assert.Equal(t, response.InResponseTo, "id-request")
	assert.Equal(t, response.Destination, "https://sp.example.com/saml2/acs")
	assert.Equal(t, response.Issuer.Value, test.IDP.MetadataURL.String())
	assert.Equal(t, response.Status.StatusCode.Value, StatusResponder)
	require.NotNil(t, response.Status.StatusCode.StatusCode)
	assert.Equal(t, response.Status.StatusCode.StatusCode.Value, StatusNoPassive)
	require.NotNil(t, response.Status.StatusMessage)
	assert.Equal(t, response.Status.StatusMessage.Value, "cannot <authenticate> passively")

	test.SP.IDPMetadata = test.IDP.Metadata()
	// The certificate of the test identity provider has expired by the time that the tests use.
	previousClock := Clock

	t.Cleanup(func() { Clock = previousClock })

	Clock = dsig.NewFakeClockAt(test.Certificate.NotBefore)
	assert.NoError(t, test.SP.validateSignature(doc.Root()))

	// The signature must cover the status, which is what the service provider acts on.
	doc.Root().FindElement("./Status/StatusCode").CreateAttr("Value", StatusSuccess)
	assert.NotNil(t, test.SP.validateSignature(doc.Root()))
}

func TestWriteErrorResponseOmitsOptionalStatusParts(t *testing.T) {
	_, req := errorResponseRequest(t)

	w := httptest.NewRecorder()
	require.NoError(t, req.WriteErrorResponse(w, ErrInvalidRequest.WithStatusMessage("").WithDebug("never sent")))

	doc, response := postedResponse(t, w.Body.String())
	assert.Equal(t, response.Status.StatusCode.Value, StatusRequester)
	assert.Nil(t, response.Status.StatusCode.StatusCode)
	assert.Nil(t, response.Status.StatusMessage)
	assert.Nil(t, doc.Root().FindElement("./Status/StatusDetail"))
}

// An error that is not a StatusError is a failure of the identity provider, and nothing of its text is sent.
func TestWriteErrorResponseOfPlainError(t *testing.T) {
	_, req := errorResponseRequest(t)

	w := httptest.NewRecorder()
	require.NoError(t, req.WriteErrorResponse(w, errors.New("the database at 10.0.0.1 is down")))

	doc, response := postedResponse(t, w.Body.String())
	assert.Equal(t, response.Status.StatusCode.Value, StatusResponder)
	assert.Nil(t, response.Status.StatusCode.StatusCode)
	assert.Equal(t, response.Status.StatusMessage.Value, ErrServerError.StatusMessageField)

	decoded, err := doc.WriteToString()
	require.NoError(t, err)
	assert.False(t, strings.Contains(decoded, "10.0.0.1"))

	assert.ErrorContains(t, req.WriteErrorResponse(httptest.NewRecorder(), nil), "without an error")
}

// An assertion made before the failure was found must not reach the service provider.
func TestWriteErrorResponseDropsExistingAssertion(t *testing.T) {
	_, req := errorResponseRequest(t)
	require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "session", NameID: "alice"}))
	require.NoError(t, req.MakeResponse())

	w := httptest.NewRecorder()
	require.NoError(t, req.WriteErrorResponse(w, ErrServerError.WithSecondLevel(StatusRequestDenied)))

	doc, response := postedResponse(t, w.Body.String())
	assert.Equal(t, response.Status.StatusCode.Value, StatusResponder)
	assert.Nil(t, response.Assertion)
	assert.Nil(t, response.EncryptedAssertion)
	assert.Nil(t, doc.Root().FindElement("./Assertion"))
	assert.Nil(t, doc.Root().FindElement("./EncryptedAssertion"))
}

// Sending a response to an endpoint that was not validated would let an unauthenticated client
// choose where a signed message goes.
func TestWriteErrorResponseRequiresValidatedACS(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req := &IdpAuthnRequest{IDP: &test.IDP, Now: TimeNow()}
	req.Request.AssertionConsumerServiceURL = "https://attacker.example.com/acs"

	w := httptest.NewRecorder()
	err := req.WriteErrorResponse(w, ErrInvalidRequest)

	assert.ErrorContains(t, err, "assertion consumer service")
	assert.Equal(t, w.Body.Len(), 0)
	assert.False(t, req.Respondable())
}

// SAMLCore §3.2.2.2 allows three top-level codes for a failure. An error with another one, which Validate
// refuses, is never sent as it is: it would be Success, or not a status at all.
func TestWriteErrorResponseNeverSendsInvalidTopLevelStatus(t *testing.T) {
	for _, status := range []string{"", StatusSuccess, StatusNoPassive} {
		t.Run(status, func(t *testing.T) {
			_, req := errorResponseRequest(t)

			failure := &StatusError{ErrorField: "custom", TopLevelField: status, SecondLevelField: StatusNoPassive, HTTPStatusField: 400}
			assert.ErrorContains(t, failure.Validate(), "top-level status")

			w := httptest.NewRecorder()
			require.NoError(t, req.WriteErrorResponse(w, failure))

			_, response := postedResponse(t, w.Body.String())
			assert.Equal(t, response.Status.StatusCode.Value, StatusResponder)
			assert.Nil(t, response.Status.StatusCode.StatusCode)
		})
	}
}
