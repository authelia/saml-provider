package saml

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// constraintSessionProvider records how it was called. It only implements SessionProvider, and the
// wrappers below add each of the optional interfaces.
type constraintSessionProvider struct {
	session *Session
	calls   []string
}

func (p *constraintSessionProvider) GetSession(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
	p.calls = append(p.calls, "GetSession")
	return p.session
}

type passiveProvider struct{ *constraintSessionProvider }

func (p passiveProvider) GetPassiveSession(*http.Request, *IdpAuthnRequest) *Session {
	p.calls = append(p.calls, "GetPassiveSession")
	return p.session
}

type forceProvider struct{ *constraintSessionProvider }

func (p forceProvider) GetForcedSession(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
	p.calls = append(p.calls, "GetForcedSession")
	return p.session
}

type fullProvider struct {
	passiveProvider
	forceProvider
}

func (p fullProvider) GetSession(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
	return p.passiveProvider.GetSession(w, r, req)
}

func serveConstrainedSSO(t *testing.T, test *IdentityProviderTest, provider SessionProvider, force, passive *bool) *httptest.ResponseRecorder {
	t.Helper()
	test.IDP.SessionProvider = provider

	request, err := test.SP.MakeAuthenticationRequest("https://idp.example.com/saml/sso", HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	request.ForceAuthn = force
	request.IsPassive = passive
	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	body, err := doc.WriteToBytes()
	assert.NilError(t, err)

	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}}
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/saml/sso", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, r)
	return w
}

func assertErrorStatus(t *testing.T, w *httptest.ResponseRecorder, secondLevel string) {
	t.Helper()
	assert.Check(t, is.Equal(w.Code, http.StatusOK))
	_, response := postedResponse(t, w.Body.String())
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusResponder))
	assert.Assert(t, response.Status.StatusCode.StatusCode != nil)
	assert.Check(t, is.Equal(response.Status.StatusCode.StatusCode.Value, secondLevel))
	assert.Check(t, response.Assertion == nil)
	assert.Check(t, response.EncryptedAssertion == nil)
}

func assertSuccessStatus(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	_, response := postedResponse(t, w.Body.String())
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
}

func TestServeSSOWithoutConstraintsUsesGetSession(t *testing.T) {
	no := false
	for name, tc := range map[string]struct{ force, passive *bool }{
		"absent": {nil, nil},
		"false":  {&no, &no},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			base := &constraintSessionProvider{session: &Session{ID: "s", NameID: "alice"}}
			w := serveConstrainedSSO(t, test, fullProvider{passiveProvider{base}, forceProvider{base}}, tc.force, tc.passive)
			assertSuccessStatus(t, w)
			assert.Check(t, is.DeepEqual(base.calls, []string{"GetSession"}))
		})
	}
}

func TestServeSSOIsPassiveUsesExistingSession(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	yes := true
	base := &constraintSessionProvider{session: &Session{ID: "s", NameID: "alice"}}
	w := serveConstrainedSSO(t, test, passiveProvider{base}, nil, &yes)
	assertSuccessStatus(t, w)
	assert.Check(t, is.DeepEqual(base.calls, []string{"GetPassiveSession"}))
}

func TestServeSSOIsPassiveWithoutSessionReturnsNoPassive(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	yes := true
	base := &constraintSessionProvider{}
	w := serveConstrainedSSO(t, test, passiveProvider{base}, nil, &yes)
	assertErrorStatus(t, w, StatusNoPassive)
}

// GetSession may show a login form, which a passive request forbids.
func TestServeSSOIsPassiveWithoutInterfaceReturnsNoPassive(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	yes := true
	base := &constraintSessionProvider{session: &Session{ID: "s", NameID: "alice"}}
	w := serveConstrainedSSO(t, test, base, nil, &yes)
	assertErrorStatus(t, w, StatusNoPassive)
	assert.Check(t, is.Len(base.calls, 0))
}

func TestServeSSOForceAuthnUsesForcedSession(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	yes := true
	base := &constraintSessionProvider{session: &Session{ID: "s", NameID: "alice"}}
	w := serveConstrainedSSO(t, test, forceProvider{base}, &yes, nil)
	assertSuccessStatus(t, w)
	assert.Check(t, is.DeepEqual(base.calls, []string{"GetForcedSession"}))
}

// As with GetSession, a nil session means that the provider has written the response.
func TestServeSSOForceAuthnLeavesResponseToProvider(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	yes := true
	base := &constraintSessionProvider{}
	w := serveConstrainedSSO(t, test, forceProvider{base}, &yes, nil)
	assert.Check(t, is.Equal(w.Body.Len(), 0))
}

// GetSession may rely on the existing session, which the request forbids.
func TestServeSSOForceAuthnWithoutInterfaceReturnsAuthnFailed(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	yes := true
	base := &constraintSessionProvider{session: &Session{ID: "s", NameID: "alice"}}
	w := serveConstrainedSSO(t, test, base, &yes, nil)
	assertErrorStatus(t, w, StatusAuthnFailed)
	assert.Check(t, is.Len(base.calls, 0))
}

// SAMLCore §3.4.1: with both set, IsPassive decides, and only a provider that can authenticate
// without interaction can succeed.
func TestServeSSOForceAuthnAndIsPassiveUsesPassiveSession(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	yes := true
	base := &constraintSessionProvider{}
	w := serveConstrainedSSO(t, test, fullProvider{passiveProvider{base}, forceProvider{base}}, &yes, &yes)
	assertErrorStatus(t, w, StatusNoPassive)
	assert.Check(t, is.DeepEqual(base.calls, []string{"GetPassiveSession"}))
}

// An IdP-initiated login isn't answering a request, so nothing constrains it.
func TestServeIDPInitiatedUsesGetSession(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	base := &constraintSessionProvider{session: &Session{ID: "s", NameID: "alice"}}
	test.IDP.SessionProvider = fullProvider{passiveProvider{base}, forceProvider{base}}
	w := httptest.NewRecorder()
	test.IDP.ServeIDPInitiated(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/sso", nil), test.SP.MetadataURL.String(), "")
	assert.Check(t, is.Equal(w.Code, http.StatusOK))
	assert.Check(t, is.DeepEqual(base.calls, []string{"GetSession"}))
}
