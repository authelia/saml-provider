package samlidp

import (
	"encoding/base64"
	stdhtml "html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml"
	"authelia.com/provider/saml/internal/dsig"
)

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
	saml.Clock = dsig.NewFakeClockAt(test.SPCertificate.NotBefore)
	return test
}

// logoutRedirect sends a signed HTTP-Redirect logout request for nameID, and returns the response.
func logoutRedirect(t *testing.T, test *ServerTest, nameID string, cookie *http.Cookie, mutate func(*saml.LogoutRequest)) (*httptest.ResponseRecorder, string) {
	t.Helper()
	signer := signingServiceProvider(test)
	request, err := signer.MakeLogoutRequest(signer.GetSLOBindingLocation(saml.HTTPRedirectBinding), nameID)
	assert.NilError(t, err)
	if mutate != nil {
		mutate(request)
	}
	u, err := request.Redirect("frob", &signer)
	assert.NilError(t, err)
	return serveWithCookie(test, u.String(), cookie), request.ID
}

func sessionStored(t *testing.T, test *ServerTest, cookie *http.Cookie) bool {
	t.Helper()
	err := test.Store.Get("/sessions/"+cookie.Value, &saml.Session{})
	if err == ErrNotFound {
		return false
	}
	assert.NilError(t, err)
	return true
}

func logoutStatus(t *testing.T, test *ServerTest, w *httptest.ResponseRecorder, id string) string {
	t.Helper()
	assert.Assert(t, is.Equal(w.Code, http.StatusFound), "body: %s", w.Body.String())
	location, err := url.Parse(w.Header().Get("Location"))
	assert.NilError(t, err)
	if err := test.SP.ValidateLogoutResponseRedirect(location, []string{id}); err != nil {
		return err.Error()
	}
	return saml.StatusSuccess
}

func TestLogoutAdvertisedInMetadata(t *testing.T) {
	test := logoutTest(t)
	assert.Check(t, is.Equal(test.SP.GetSLOBindingLocation(saml.HTTPRedirectBinding), "https://idp.example.com/logout"))
	assert.Check(t, is.Equal(test.SP.GetSLOBindingLocation(saml.HTTPPostBinding), "https://idp.example.com/logout"))
}

func TestLogoutEndsSession(t *testing.T) {
	test := logoutTest(t)
	cookie := loggedInCookie(t, test)
	assert.Assert(t, sessionStored(t, test, cookie))

	w, id := logoutRedirect(t, test, "alice@example.com", cookie, nil)
	assert.Check(t, is.Equal(logoutStatus(t, test, w, id), saml.StatusSuccess))
	assert.Check(t, !sessionStored(t, test, cookie))

	var cleared *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "session" {
			cleared = c
		}
	}
	assert.Assert(t, cleared != nil)
	assert.Check(t, cleared.MaxAge < 0)
	assert.Check(t, cleared.Secure)
	assert.Check(t, cleared.HttpOnly)
	assert.Check(t, is.Equal(cleared.Path, "/"))

	// The next request needs the user to log in again.
	w = serveWithCookie(test, constrainedRequestURL(t, test, false, false), cookie)
	assert.Check(t, strings.Contains(w.Body.String(), `name="password"`), w.Body.String())
}

func TestLogoutWithMatchingSessionIndex(t *testing.T) {
	test := logoutTest(t)
	cookie := loggedInCookie(t, test)
	session := saml.Session{}
	assert.NilError(t, test.Store.Get("/sessions/"+cookie.Value, &session))

	w, id := logoutRedirect(t, test, "alice@example.com", cookie, func(r *saml.LogoutRequest) {
		r.SessionIndexes = []saml.SessionIndex{{Value: "other"}, {Value: session.Index}}
	})
	assert.Check(t, is.Equal(logoutStatus(t, test, w, id), saml.StatusSuccess))
	assert.Check(t, !sessionStored(t, test, cookie))
}

// A service provider can only end a session that it names, so a request for another principal or
// another session leaves the session of this browser in place.
func TestLogoutKeepsOtherSessions(t *testing.T) {
	for name, tc := range map[string]struct {
		nameID string
		mutate func(*saml.LogoutRequest)
	}{
		"other principal": {nameID: "bob@example.com"},
		"other session index": {nameID: "alice@example.com", mutate: func(r *saml.LogoutRequest) {
			r.SessionIndexes = []saml.SessionIndex{{Value: "other"}}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			test := logoutTest(t)
			cookie := loggedInCookie(t, test)
			w, id := logoutRedirect(t, test, tc.nameID, cookie, tc.mutate)
			assert.Check(t, is.ErrorContains(errorString(logoutStatus(t, test, w, id)), "status code"))
			assert.Check(t, sessionStored(t, test, cookie))
			for _, c := range w.Result().Cookies() {
				assert.Check(t, c.Name != "session", "the cookie must not be cleared")
			}
		})
	}
}

// Without a session there is nothing to end in this browser.
func TestLogoutWithoutSession(t *testing.T) {
	test := logoutTest(t)
	w, id := logoutRedirect(t, test, "alice@example.com", nil, nil)
	assert.Check(t, is.Equal(logoutStatus(t, test, w, id), saml.StatusSuccess))
}

// The session cookie is SameSite=Lax, so a browser doesn't send it with the cross-site POST of the
// HTTP-POST binding. Reporting success would leave the session in place while telling the service
// provider that it had ended.
func TestLogoutPostWithoutCookieIsNotSuccess(t *testing.T) {
	test := logoutTest(t)
	cookie := loggedInCookie(t, test)

	signer := signingServiceProvider(test)
	html, err := signer.MakePostLogoutRequest("alice@example.com", "frob")
	assert.NilError(t, err)
	const marker = `name="SAMLRequest" value="`
	start := strings.Index(string(html), marker)
	assert.Assert(t, start >= 0)
	encoded, _, _ := strings.Cut(string(html)[start+len(marker):], `"`)
	encoded = stdhtml.UnescapeString(encoded)
	_, err = base64.StdEncoding.DecodeString(encoded)
	assert.NilError(t, err)

	form := url.Values{"SAMLRequest": {encoded}, "RelayState": {"frob"}}
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/logout", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	test.Server.ServeHTTP(w, r)
	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())
	assert.Check(t, strings.Contains(w.Body.String(), `name="SAMLResponse"`))

	start = strings.Index(w.Body.String(), `name="SAMLResponse" value="`)
	value, _, _ := strings.Cut(w.Body.String()[start+len(`name="SAMLResponse" value="`):], `"`)
	value = stdhtml.UnescapeString(value)
	buf, err := base64.StdEncoding.DecodeString(value)
	assert.NilError(t, err)
	assert.Check(t, strings.Contains(string(buf), saml.StatusResponder), string(buf))
	assert.Check(t, sessionStored(t, test, cookie))
}

type errorString string

func (e errorString) Error() string { return string(e) }

// signingServiceProvider returns the service provider of the test, signing its requests. Its
// metadata, as registered, doesn't require signed AuthnRequests, so the login helpers still work.
func signingServiceProvider(test *ServerTest) saml.ServiceProvider {
	signer := test.SP
	signer.SignatureMethod = dsig.RSASHA256SignatureMethod
	return signer
}
