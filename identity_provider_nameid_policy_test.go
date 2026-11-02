package saml

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"encoding/base64"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

const unspecifiedNameIDFormat20 = "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"

type nameIDPolicyEnforcerFunc func(*IdpAuthnRequest, *Session) error

func (f nameIDPolicyEnforcerFunc) EnforceNameIDPolicy(req *IdpAuthnRequest, session *Session) error {
	return f(req, session)
}

// serveSSOWithPolicy posts a request with the given policy, and returns the response sent to the
// service provider.
func serveSSOWithPolicy(t *testing.T, test *IdentityProviderTest, session *Session, policy *NameIDPolicy) Response {
	t.Helper()
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session { return session },
	}

	request, err := test.SP.MakeAuthenticationRequest("https://idp.example.com/saml/sso", HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	request.NameIDPolicy = policy
	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	body, err := doc.WriteToBytes()
	assert.NilError(t, err)

	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}}
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/saml/sso", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, r)
	assert.Check(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())

	_, response := postedResponse(t, w.Body.String())
	return response
}

func assertInvalidNameIDPolicy(t *testing.T, response Response) {
	t.Helper()
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusRequester))
	assert.Assert(t, response.Status.StatusCode.StatusCode != nil)
	assert.Check(t, is.Equal(response.Status.StatusCode.StatusCode.Value, StatusInvalidNameIDPolicy))
	assert.Check(t, response.Assertion == nil)
	assert.Check(t, response.EncryptedAssertion == nil)
}

func TestServeSSOAcceptsSatisfiableNameIDPolicy(t *testing.T) {
	transient := string(TransientNameIDFormat)
	email := string(EmailAddressNameIDFormat)
	unspecified11 := string(UnspecifiedNameIDFormat)
	unspecified20 := unspecifiedNameIDFormat20
	requester := "https://sp.example.com/saml2/metadata"
	yes := true

	for name, tc := range map[string]struct {
		sessionFormat string
		policy        *NameIDPolicy
	}{
		"no policy":       {"", nil},
		"empty policy":    {"", &NameIDPolicy{}},
		"same format":     {"", &NameIDPolicy{Format: &transient}},
		"session format":  {email, &NameIDPolicy{Format: &email}},
		"unspecified 1.1": {email, &NameIDPolicy{Format: &unspecified11}},
		"unspecified 2.0": {email, &NameIDPolicy{Format: &unspecified20}},
		"own qualifier":   {"", &NameIDPolicy{SPNameQualifier: &requester}},
		"allow create":    {"", &NameIDPolicy{AllowCreate: &yes}},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			response := serveSSOWithPolicy(t, test, &Session{ID: "s", NameID: "alice", NameIDFormat: tc.sessionFormat}, tc.policy)
			assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
		})
	}
}

func TestServeSSORejectsUnsatisfiableNameIDPolicy(t *testing.T) {
	email := string(EmailAddressNameIDFormat)
	persistent := string(PersistentNameIDFormat)
	encrypted := encryptedNameIDFormat
	other := "https://other.example.com/affiliation"

	for name, policy := range map[string]*NameIDPolicy{
		"other format":    {Format: &email},
		"persistent":      {Format: &persistent},
		"encrypted":       {Format: &encrypted},
		"other qualifier": {SPNameQualifier: &other},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			assertInvalidNameIDPolicy(t, serveSSOWithPolicy(t, test, &Session{ID: "s", NameID: "alice"}, policy))
		})
	}
}

func TestServeSSOUsesConfiguredNameIDPolicyEnforcer(t *testing.T) {
	email := string(EmailAddressNameIDFormat)

	t.Run("accepts what the default would not", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.NameIDPolicyEnforcer = nameIDPolicyEnforcerFunc(func(*IdpAuthnRequest, *Session) error { return nil })
		response := serveSSOWithPolicy(t, test, &Session{ID: "s", NameID: "alice"}, &NameIDPolicy{Format: &email})
		assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	})

	t.Run("refuses per service provider", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		var seen string
		test.IDP.NameIDPolicyEnforcer = nameIDPolicyEnforcerFunc(func(req *IdpAuthnRequest, _ *Session) error {
			seen = req.ServiceProviderMetadata.EntityID
			return errors.New("not established for this service provider")
		})
		assertInvalidNameIDPolicy(t, serveSSOWithPolicy(t, test, &Session{ID: "s", NameID: "alice"}, &NameIDPolicy{}))
		assert.Check(t, is.Equal(seen, "https://sp.example.com/saml2/metadata"))
	})
}

// The reason may describe the principal, and the service provider isn't entitled to it.
func TestServeSSODoesNotSendNameIDPolicyErrorText(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.NameIDPolicyEnforcer = nameIDPolicyEnforcerFunc(func(*IdpAuthnRequest, *Session) error {
		return errors.New("alice has no identifier")
	})
	response := serveSSOWithPolicy(t, test, &Session{ID: "s", NameID: "alice"}, &NameIDPolicy{})
	assert.Check(t, response.Status.StatusMessage == nil)
}

// An IdP-initiated response isn't answering a request, so there is no policy to enforce.
func TestServeIDPInitiatedSkipsNameIDPolicyEnforcer(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.NameIDPolicyEnforcer = nameIDPolicyEnforcerFunc(func(*IdpAuthnRequest, *Session) error {
		t.Error("the enforcer must not run")
		return nil
	})
	w := httptest.NewRecorder()
	test.IDP.ServeIDPInitiated(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/sso", nil), test.SP.MetadataURL.String(), "")
	assert.Check(t, is.Equal(w.Code, http.StatusOK))
}

// Matching formats aren't enough, because the assertion still holds the NameID in plaintext.
func TestServeSSORefusesEncryptedFormatFromSession(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	encrypted := encryptedNameIDFormat
	response := serveSSOWithPolicy(t, test, &Session{ID: "s", NameID: "alice", NameIDFormat: encrypted}, &NameIDPolicy{Format: &encrypted})
	assertInvalidNameIDPolicy(t, response)
}
