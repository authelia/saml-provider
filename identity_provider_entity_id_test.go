package saml

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

const entityIDTestValue = "urn:example:idp"

// entityIDRequest returns a validated request to an identity provider whose entity ID is entityID.
func entityIDRequest(t *testing.T, entityID string) (*IdentityProviderTest, *IdpAuthnRequest) {
	t.Helper()
	test, req := errorResponseRequest(t)
	test.IDP.EntityID = entityID
	return test, req
}

func TestIDPEntityIDDefaultsToMetadataURL(t *testing.T) {
	test, req := entityIDRequest(t, "")

	assert.Check(t, is.Equal(test.IDP.Metadata().EntityID, "https://idp.example.com/saml/metadata"))

	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "session", NameID: "alice"}))
	assert.Check(t, is.Equal(req.Assertion.Issuer.Value, "https://idp.example.com/saml/metadata"))
	assert.Check(t, is.Equal(req.Assertion.Subject.NameID.NameQualifier, "https://idp.example.com/saml/metadata"))
}

func TestIDPEntityIDInMetadata(t *testing.T) {
	test, _ := entityIDRequest(t, entityIDTestValue)

	assert.Check(t, is.Equal(test.IDP.Metadata().EntityID, entityIDTestValue))

	// The metadata is still served at the MetadataURL.
	w := httptest.NewRecorder()
	test.IDP.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, test.IDP.MetadataURL.String(), nil))
	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())
	var metadata EntityDescriptor
	assert.NilError(t, xml.Unmarshal(w.Body.Bytes(), &metadata))
	assert.Check(t, is.Equal(metadata.EntityID, entityIDTestValue))
}

func TestIDPEntityIDInAssertion(t *testing.T) {
	_, req := entityIDRequest(t, entityIDTestValue)

	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "session", NameID: "alice"}))
	assert.Check(t, is.Equal(req.Assertion.Issuer.Value, entityIDTestValue))
	assert.Check(t, is.Equal(req.Assertion.Subject.NameID.NameQualifier, entityIDTestValue))

	assert.NilError(t, req.MakeResponse())
	issuer := req.ResponseEl.FindElement("./Issuer")
	assert.Assert(t, issuer != nil)
	assert.Check(t, is.Equal(issuer.Text(), entityIDTestValue))
}

func TestIDPEntityIDInErrorResponse(t *testing.T) {
	_, req := entityIDRequest(t, entityIDTestValue)

	w := httptest.NewRecorder()
	assert.NilError(t, req.WriteErrorResponse(w, StatusResponder, StatusNoPassive, ""))

	_, response := postedResponse(t, w.Body.String())
	assert.Assert(t, response.Issuer != nil)
	assert.Check(t, is.Equal(response.Issuer.Value, entityIDTestValue))
}

func TestIDPEntityIDInLogoutResponse(t *testing.T) {
	test, _ := logoutTestIDP(t)
	test.IDP.EntityID = entityIDTestValue
	test.SP.IDPMetadata = test.IDP.Metadata()

	r, id := postLogoutRequest(t, &test.SP, nil)
	encoded, _, response := postedLogoutResponse(t, serveSLO(test, r))
	assert.Assert(t, response.Issuer != nil)
	assert.Check(t, is.Equal(response.Issuer.Value, entityIDTestValue))
	// The service provider compares the Issuer with the entity ID in the metadata.
	assert.Check(t, test.SP.ValidateLogoutResponseForm(encoded, []string{id}))
}

// SAMLCore §8.3.6 requires an entity identifier to be a URI of no more than 1024 characters, and
// SAMLCore §1.3.2 requires the URI to be absolute.
func TestIDPRefusesInvalidEntityID(t *testing.T) {
	for name, entityID := range map[string]string{
		"relative":   "idp",
		"whitespace": "urn:example: idp",
		"too long":   "urn:example:" + strings.Repeat("a", 1024-len("urn:example:")+1),
	} {
		t.Run(name, func(t *testing.T) {
			test, req := entityIDRequest(t, entityID)

			w := httptest.NewRecorder()
			test.IDP.ServeMetadata(w, httptest.NewRequest(http.MethodGet, test.IDP.MetadataURL.String(), nil))
			assert.Check(t, is.Equal(w.Code, http.StatusInternalServerError))
			assert.Check(t, !strings.Contains(w.Body.String(), "EntityDescriptor"))

			assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "session", NameID: "alice"}))
			assert.Check(t, is.ErrorContains(req.MakeAssertionEl(), "entity ID"))

			w = httptest.NewRecorder()
			assert.Check(t, is.ErrorContains(req.WriteErrorResponse(w, StatusResponder, "", ""), "entity ID"))
			assert.Check(t, is.Equal(w.Body.Len(), 0))
		})
	}
}

func TestIDPAcceptsLongestEntityID(t *testing.T) {
	entityID := "urn:example:" + strings.Repeat("a", 1024-len("urn:example:"))
	_, req := entityIDRequest(t, entityID)

	w := httptest.NewRecorder()
	assert.NilError(t, req.WriteErrorResponse(w, StatusResponder, "", ""))
	_, response := postedResponse(t, w.Body.String())
	assert.Check(t, is.Equal(response.Issuer.Value, entityID))
}

func TestIDPRefusesInvalidEntityIDInLogoutResponse(t *testing.T) {
	test, _ := logoutTestIDP(t)
	r, _ := postLogoutRequest(t, &test.SP, nil)
	test.IDP.EntityID = "idp"

	w := serveSLO(test, r)
	assert.Check(t, is.Equal(w.Code, http.StatusInternalServerError))
	assert.Check(t, !strings.Contains(w.Body.String(), "SAMLResponse"))
}
