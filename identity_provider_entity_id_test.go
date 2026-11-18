package saml

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	assert.Equal(t, test.IDP.Metadata().EntityID, "https://idp.example.com/saml/metadata")

	require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "session", NameID: "alice"}))
	assert.Equal(t, req.Assertion.Issuer.Value, "https://idp.example.com/saml/metadata")
	assert.Equal(t, req.Assertion.Subject.NameID.NameQualifier, "https://idp.example.com/saml/metadata")
}

func TestIDPEntityIDInMetadata(t *testing.T) {
	test, _ := entityIDRequest(t, entityIDTestValue)

	assert.Equal(t, test.IDP.Metadata().EntityID, entityIDTestValue)

	// The metadata is still served at the MetadataURL.
	w := httptest.NewRecorder()
	test.IDP.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, test.IDP.MetadataURL.String(), nil))
	require.Equal(t, w.Code, http.StatusOK, "body: %s", w.Body.String())

	var metadata EntityDescriptor
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &metadata))
	assert.Equal(t, metadata.EntityID, entityIDTestValue)
}

func TestIDPEntityIDInAssertion(t *testing.T) {
	_, req := entityIDRequest(t, entityIDTestValue)

	require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "session", NameID: "alice"}))
	assert.Equal(t, req.Assertion.Issuer.Value, entityIDTestValue)
	assert.Equal(t, req.Assertion.Subject.NameID.NameQualifier, entityIDTestValue)

	require.NoError(t, req.MakeResponse())
	issuer := req.ResponseEl.FindElement("./Issuer")
	require.NotNil(t, issuer)
	assert.Equal(t, issuer.Text(), entityIDTestValue)
}

func TestIDPEntityIDInErrorResponse(t *testing.T) {
	_, req := entityIDRequest(t, entityIDTestValue)

	w := httptest.NewRecorder()
	require.NoError(t, req.WriteErrorResponse(w, ErrNoPassive))

	_, response := postedResponse(t, w.Body.String())
	require.NotNil(t, response.Issuer)
	assert.Equal(t, response.Issuer.Value, entityIDTestValue)
}

func TestIDPEntityIDInLogoutResponse(t *testing.T) {
	test, _ := logoutTestIDP(t)
	test.IDP.EntityID = entityIDTestValue
	test.SP.IDPMetadata = test.IDP.Metadata()

	r, id := postLogoutRequest(t, &test.SP, nil)
	encoded, _, response := postedLogoutResponse(t, serveSLO(test, r))
	require.NotNil(t, response.Issuer)
	assert.Equal(t, response.Issuer.Value, entityIDTestValue)
	// The service provider compares the Issuer with the entity ID in the metadata.
	assert.NoError(t, test.SP.ValidateLogoutResponseForm(encoded, []string{id}))
}

func TestIDPEntityIDInLogoutRequest(t *testing.T) {
	test, _ := logoutTestIDP(t)
	test.IDP.EntityID = entityIDTestValue

	state := &LogoutState{ExpireTime: TimeNow().Add(time.Minute)}
	participant := &LogoutParticipant{NameID: NameID{Value: "alice"}}

	request, err := test.IDP.makeLogoutRequest(httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/slo", nil), state, participant, nil, &Endpoint{Location: "https://sp.example.com/saml2/slo"})
	require.NoError(t, err)
	require.NotNil(t, request.Issuer)
	assert.Equal(t, request.Issuer.Value, entityIDTestValue)
}

// SAMLBind §3.6.4 makes the SourceID of an artifact the SHA-1 of the entity ID, which a service provider computes
// from the entityID of the metadata.
func TestIDPEntityIDInArtifactSourceID(t *testing.T) {
	test, _ := logoutTestIDP(t)
	test.IDP.EntityID = entityIDTestValue

	message := etree.NewElement("samlp:Response")

	artifact, _, err := test.IDP.issueArtifact(t.Context(), test.SP.EntityID, message)
	require.NoError(t, err)
	assert.Equal(t, artifact.SourceID, ArtifactSourceID(test.IDP.Metadata().EntityID))
	assert.Equal(t, artifact.SourceID, ArtifactSourceID(entityIDTestValue))
}

// SAML2Int SDP-G04 requires an entity identifier to be an absolute URI of no more than 256 characters, which is
// within the 1024 characters of SAMLCore §8.3.6.
func TestIDPRefusesInvalidEntityID(t *testing.T) {
	for name, entityID := range map[string]string{
		"relative":   "idp",
		"whitespace": "urn:example: idp",
		"too long":   "urn:example:" + strings.Repeat("a", 256-len("urn:example:")+1),
	} {
		t.Run(name, func(t *testing.T) {
			test, req := entityIDRequest(t, entityID)

			w := httptest.NewRecorder()
			test.IDP.ServeMetadata(w, httptest.NewRequest(http.MethodGet, test.IDP.MetadataURL.String(), nil))
			assert.Equal(t, w.Code, http.StatusInternalServerError)
			assert.False(t, strings.Contains(w.Body.String(), "EntityDescriptor"))

			require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "session", NameID: "alice"}))
			assert.ErrorContains(t, req.MakeAssertionEl(), "entity ID")

			w = httptest.NewRecorder()
			assert.ErrorContains(t, req.WriteErrorResponse(w, ErrServerError), "entity ID")
			assert.Equal(t, w.Body.Len(), 0)
		})
	}
}

func TestIDPAcceptsLongestEntityID(t *testing.T) {
	entityID := "urn:example:" + strings.Repeat("a", 256-len("urn:example:"))
	_, req := entityIDRequest(t, entityID)

	w := httptest.NewRecorder()
	require.NoError(t, req.WriteErrorResponse(w, ErrServerError))
	_, response := postedResponse(t, w.Body.String())
	assert.Equal(t, response.Issuer.Value, entityID)
}

func TestIDPRefusesInvalidEntityIDInLogoutResponse(t *testing.T) {
	test, _ := logoutTestIDP(t)
	r, _ := postLogoutRequest(t, &test.SP, nil)
	test.IDP.EntityID = "idp"

	w := serveSLO(test, r)
	assert.Equal(t, w.Code, http.StatusInternalServerError)
	assert.False(t, strings.Contains(w.Body.String(), "SAMLResponse"))
}
