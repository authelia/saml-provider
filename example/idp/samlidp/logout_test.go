package samlidp

import (
	"encoding/base64"
	"errors"
	stdhtml "html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml"
)

// rsaSHA256SignatureMethod is the XML Signature algorithm for RSA with SHA-256.
const rsaSHA256SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

// logoutTest returns a server with a user, and a service provider which accepts logout, with a clock
// at which the certificate of the service provider is valid.
func logoutTest(t *testing.T) *ServerTest {
	t.Helper()
	test := NewServerTest(t)
	hardeningAddUser(t, test)
	test.SP.SloURL = mustParseURL("https://sp.example.com/saml2/slo")
	test.SP.LogoutBindings = []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding}
	// The signing key is only listed when requests are signed, which would also require the
	// AuthnRequests of the login helpers to be signed.
	signer := signingServiceProvider(test)
	metadata := signer.Metadata()
	unsigned := false
	metadata.SPSSODescriptors[0].AuthnRequestsSigned = &unsigned
	test.Server.serviceProviders["https://sp.example.com/saml2/metadata"] = metadata

	previousClock := saml.Clock
	t.Cleanup(func() { saml.Clock = previousClock })
	saml.Clock = saml.NewFakeClockAt(test.SPCertificate.NotBefore)
	return test
}

// logoutRedirect sends a signed HTTP-Redirect logout request for nameID, and returns the response.
func logoutRedirect(t *testing.T, test *ServerTest, nameID string, cookie *http.Cookie, mutate func(*saml.LogoutRequest)) (*httptest.ResponseRecorder, string) {
	t.Helper()
	signer := signingServiceProvider(test)
	request, err := signer.MakeLogoutRequest(signer.GetSLOBindingLocation(saml.HTTPRedirectBinding), nameID)
	require.NoError(t, err)
	if mutate != nil {
		mutate(request)
	}
	u, err := request.Redirect("frob", &signer)
	require.NoError(t, err)
	return serveWithCookie(test, u.String(), cookie), request.ID
}

// issuedNameID returns the value of the NameID that was asserted to the service provider for the session
// of cookie, which is a random transient identifier because the session has no NameIDFormat.
func issuedNameID(t *testing.T, test *ServerTest, cookie *http.Cookie) string {
	t.Helper()

	session := saml.Session{}
	require.NoError(t, test.Store.Get("/sessions/"+cookie.Value, &session))

	participants, err := test.Server.SessionParticipants(nil, &session)
	require.NoError(t, err)
	require.Len(t, participants, 1)

	return participants[0].NameID.Value
}

func sessionStored(t *testing.T, test *ServerTest, cookie *http.Cookie) bool {
	t.Helper()
	err := test.Store.Get("/sessions/"+cookie.Value, &saml.Session{})
	if err == ErrNotFound {
		return false
	}

	require.NoError(t, err)
	return true
}

func logoutStatus(t *testing.T, test *ServerTest, w *httptest.ResponseRecorder, id string) string {
	t.Helper()
	require.Equal(t, w.Code, http.StatusFound, "body: %s", w.Body.String())
	location, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	if err := test.SP.ValidateLogoutResponseRedirect(location, []string{id}); err != nil {
		return err.Error()
	}
	return saml.StatusSuccess
}

func TestLogoutAdvertisedInMetadata(t *testing.T) {
	test := logoutTest(t)
	assert.Equal(t, test.SP.GetSLOBindingLocation(saml.HTTPRedirectBinding), "https://idp.example.com/logout")
	assert.Equal(t, test.SP.GetSLOBindingLocation(saml.HTTPPostBinding), "https://idp.example.com/logout")
}

func TestLogoutEndsSession(t *testing.T) {
	test := logoutTest(t)
	cookie := loggedInCookie(t, test)
	require.True(t, sessionStored(t, test, cookie))

	w, id := logoutRedirect(t, test, issuedNameID(t, test, cookie), cookie, nil)
	assert.Equal(t, logoutStatus(t, test, w, id), saml.StatusSuccess)
	assert.False(t, sessionStored(t, test, cookie))

	var cleared *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "session" {
			cleared = c
		}
	}

	require.NotNil(t, cleared)
	assert.True(t, cleared.MaxAge < 0)
	assert.True(t, cleared.Secure)
	assert.True(t, cleared.HttpOnly)
	assert.Equal(t, cleared.Path, "/")

	// The next request needs the user to log in again.
	w = serveWithCookie(test, constrainedRequestURL(t, test, false, false), cookie)
	assert.True(t, strings.Contains(w.Body.String(), `name="password"`), w.Body.String())
}

func TestLogoutWithMatchingSessionIndex(t *testing.T) {
	test := logoutTest(t)
	cookie := loggedInCookie(t, test)
	session := saml.Session{}
	require.NoError(t, test.Store.Get("/sessions/"+cookie.Value, &session))

	w, id := logoutRedirect(t, test, issuedNameID(t, test, cookie), cookie, func(r *saml.LogoutRequest) {
		r.SessionIndexes = []saml.SessionIndex{{Value: "other"}, {Value: session.Index}}
	})
	assert.Equal(t, logoutStatus(t, test, w, id), saml.StatusSuccess)
	assert.False(t, sessionStored(t, test, cookie))
}

// A service provider can only end a session that it names, so a request for another principal or
// another session leaves the session of this browser in place.
func TestLogoutKeepsOtherSessions(t *testing.T) {
	for name, tc := range map[string]struct {
		// nameID is the value of the NameID, or the one asserted to the service provider if empty.
		nameID string
		mutate func(*saml.LogoutRequest)
	}{
		"other principal":      {nameID: "bob@example.com"},
		"email of the session": {nameID: "alice@example.com"},
		"other session index": {mutate: func(r *saml.LogoutRequest) {
			r.SessionIndexes = []saml.SessionIndex{{Value: "other"}}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			test := logoutTest(t)
			cookie := loggedInCookie(t, test)

			nameID := tc.nameID
			if nameID == "" {
				nameID = issuedNameID(t, test, cookie)
			}

			w, id := logoutRedirect(t, test, nameID, cookie, tc.mutate)
			assert.ErrorContains(t, errorString(logoutStatus(t, test, w, id)), "status code")
			assert.True(t, sessionStored(t, test, cookie))
			for _, c := range w.Result().Cookies() {
				assert.True(t, c.Name != "session", "the cookie must not be cleared")
			}
		})
	}
}

// A NameID qualified for another service provider isn't the one that the identity provider asserted to
// this service provider, so the request can't end the session.
func TestLogoutRefusesNameIDOfAnotherServiceProvider(t *testing.T) {
	test := logoutTest(t)
	cookie := loggedInCookie(t, test)

	w, id := logoutRedirect(t, test, issuedNameID(t, test, cookie), cookie, func(r *saml.LogoutRequest) {
		r.NameID.SPNameQualifier = "https://other.example.com/saml2/metadata"
	})
	assert.ErrorContains(t, errorString(logoutStatus(t, test, w, id)), "status code")
	assert.True(t, sessionStored(t, test, cookie))
}

// With LogoutNameIDValueOnly only the value of the NameID is compared.
func TestLogoutValueOnlyOption(t *testing.T) {
	test := logoutTest(t)
	test.Server.IDP.LogoutNameIDValueOnly = true
	cookie := loggedInCookie(t, test)

	w, id := logoutRedirect(t, test, issuedNameID(t, test, cookie), cookie, func(r *saml.LogoutRequest) {
		r.NameID.SPNameQualifier = "https://other.example.com/saml2/metadata"
	})
	assert.Equal(t, logoutStatus(t, test, w, id), saml.StatusSuccess)
	assert.False(t, sessionStored(t, test, cookie))
}

// Without a session there is nothing to end in this browser.
func TestLogoutWithoutSession(t *testing.T) {
	test := logoutTest(t)
	w, id := logoutRedirect(t, test, "alice@example.com", nil, nil)
	assert.Equal(t, logoutStatus(t, test, w, id), saml.StatusSuccess)
}

// The session cookie is SameSite=Lax, so a browser doesn't send it with the cross-site POST of the
// HTTP-POST binding. Reporting success would leave the session in place while telling the service
// provider that it had ended.
func TestLogoutPostWithoutCookieIsNotSuccess(t *testing.T) {
	test := logoutTest(t)
	cookie := loggedInCookie(t, test)

	signer := signingServiceProvider(test)
	html, err := signer.MakePostLogoutRequest("alice@example.com", "frob")
	require.NoError(t, err)
	const marker = `name="SAMLRequest" value="`
	start := strings.Index(string(html), marker)
	require.True(t, start >= 0)
	encoded, _, _ := strings.Cut(string(html)[start+len(marker):], `"`)
	encoded = stdhtml.UnescapeString(encoded)
	_, err = base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)

	form := url.Values{"SAMLRequest": {encoded}, "RelayState": {"frob"}}
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/logout", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	test.Server.ServeHTTP(w, r)
	require.Equal(t, w.Code, http.StatusOK, "body: %s", w.Body.String())
	assert.True(t, strings.Contains(w.Body.String(), `name="SAMLResponse"`))

	start = strings.Index(w.Body.String(), `name="SAMLResponse" value="`)
	value, _, _ := strings.Cut(w.Body.String()[start+len(`name="SAMLResponse" value="`):], `"`)
	value = stdhtml.UnescapeString(value)
	buf, err := base64.StdEncoding.DecodeString(value)
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(buf), saml.StatusResponder), string(buf))
	assert.True(t, sessionStored(t, test, cookie))
}

type errorString string

func (e errorString) Error() string { return string(e) }

// signingServiceProvider returns the service provider of the test, signing its requests. Its
// metadata, as registered, doesn't require signed AuthnRequests, so the login helpers still work.
func signingServiceProvider(test *ServerTest) saml.ServiceProvider {
	signer := test.SP
	signer.SignatureMethod = rsaSHA256SignatureMethod
	return signer
}

func TestServerStartLogoutVisitsServiceProvider(t *testing.T) {
	test := logoutTest(t)
	cookie := loggedInCookie(t, test)

	w := postWithCookie(test, "/logout/start", cookie, nil)
	require.Equal(t, w.Code, http.StatusFound, "body: %s", w.Body.String())

	location, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, location.Scheme+"://"+location.Host+location.Path, "https://sp.example.com/saml2/slo")
	assert.True(t, location.Query().Get("SAMLRequest") != "")
	assert.True(t, location.Query().Get("RelayState") != "")
	assert.True(t, location.Query().Get("Signature") != "")
	assert.Equal(t, location.Query().Get("SigAlg"), rsaSHA256SignatureMethod)

	// The session of the IdP ends before the service provider is visited.
	assert.False(t, sessionStored(t, test, cookie))
}

func TestServerStartLogoutWithoutSessionDoesNothing(t *testing.T) {
	test := logoutTest(t)

	w := postWithCookie(test, "/logout/start", nil, nil)
	assert.Equal(t, w.Code, http.StatusFound)
	assert.Equal(t, w.Header().Get("Location"), "/")
}

func TestServerStartLogoutRefusesCrossSite(t *testing.T) {
	test := logoutTest(t)
	cookie := loggedInCookie(t, test)

	w := postWithCookie(test, "/logout/start", cookie, map[string]string{"Sec-Fetch-Site": "cross-site"})
	assert.Equal(t, w.Code, http.StatusForbidden)
	assert.True(t, sessionStored(t, test, cookie))
}

func TestLogoutGetWithoutSAMLMessageDoesNotLogOut(t *testing.T) {
	test := logoutTest(t)
	cookie := loggedInCookie(t, test)

	w := serveWithCookie(test, "https://idp.example.com/logout", cookie)
	assert.True(t, w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "sp.example.com"))
	assert.True(t, sessionStored(t, test, cookie))
}

// postWithCookie sends a POST with the cookie and headers.
func postWithCookie(test *ServerTest, target string, cookie *http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", target, nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}

	for k, v := range headers {
		r.Header.Set(k, v)
	}

	w := httptest.NewRecorder()
	test.Server.ServeHTTP(w, r)

	return w
}

func TestServerClosedSessionTakesNoParticipants(t *testing.T) {
	test := logoutTest(t)
	cookie := loggedInCookie(t, test)

	session := &saml.Session{ID: cookie.Value}
	participant := saml.SessionParticipant{ServiceProviderEntityID: "https://sp-two.example.com"}

	before, err := test.Server.CloseSessionParticipants(nil, session)
	require.NoError(t, err)

	err = test.Server.AddSessionParticipant(nil, session, participant)
	assert.True(t, errors.Is(err, saml.ErrSessionParticipantsClosed))

	after, err := test.Server.CloseSessionParticipants(nil, session)
	require.NoError(t, err)
	assert.Equal(t, after, before)

	// A session that has ended takes no participants either, though the mark of closing went with it.
	require.NoError(t, test.Server.TerminateSession(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/logout/start", nil), session))
	assert.True(t, test.Server.AddSessionParticipant(nil, session, participant) != nil)
}

// A session whose participants are closed, such as because it failed to end, isn't used again, so that the user
// logs in to a new session rather than being refused every assertion.
func TestServerClosedSessionIsNotUsed(t *testing.T) {
	test := logoutTest(t)
	cookie := loggedInCookie(t, test)

	r := httptest.NewRequest(http.MethodGet, "/sso", nil)
	r.AddCookie(cookie)

	session, err := test.Server.existingSession(r)
	require.NoError(t, err)
	require.NotNil(t, session)

	_, err = test.Server.CloseSessionParticipants(nil, session)
	require.NoError(t, err)

	session, err = test.Server.existingSession(r)
	require.NoError(t, err)
	assert.Nil(t, session)
}

func TestServerSaveLogoutStateIsConditional(t *testing.T) {
	test := logoutTest(t)

	state := &saml.LogoutState{ID: "state", Revision: 1}
	require.NoError(t, test.Server.SaveLogoutState(nil, state))

	stale := *state
	state.Revision = 2
	require.NoError(t, test.Server.SaveLogoutState(nil, state))

	stale.Revision = 2
	assert.True(t, errors.Is(test.Server.SaveLogoutState(nil, &stale), saml.ErrLogoutStateConflict))

	// A deleted state can't be saved again by a request that loaded it earlier.
	require.NoError(t, test.Server.DeleteLogoutState(nil, state.ID))
	state.Revision = 3
	assert.True(t, errors.Is(test.Server.SaveLogoutState(nil, state), saml.ErrLogoutStateConflict))
}
