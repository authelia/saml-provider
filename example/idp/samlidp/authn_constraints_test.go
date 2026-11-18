package samlidp

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml"
)

// constrainedRequestURL returns the URL of a request with the given constraints.
func constrainedRequestURL(t *testing.T, test *ServerTest, force, passive bool) string {
	t.Helper()
	binding := test.SP.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	request, err := test.SP.MakeAuthenticationRequest(binding, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	require.NoError(t, err)
	if force {
		request.ForceAuthn = &force
	}
	if passive {
		request.IsPassive = &passive
	}
	u, err := request.Redirect("frob", &test.SP)
	require.NoError(t, err)
	return u.String()
}

// loggedInCookie logs in and returns the session cookie.
func loggedInCookie(t *testing.T, test *ServerTest) *http.Cookie {
	t.Helper()
	w := hardeningSubmitLogin(t, test, hardeningStartSSO(t, test), "hunter2")
	hardeningAssertSAMLResponse(t, w, "frob")
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "session" {
			return cookie
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func serveWithCookie(test *ServerTest, target string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", target, nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	test.Server.ServeHTTP(w, r)
	return w
}

// samlResponseXML returns the decoded response, which fails the test if a login form was shown.
func samlResponseXML(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	assert.Equal(t, http.StatusOK, w.Code)
	buf, err := base64.StdEncoding.DecodeString(hardeningHidden(t, w.Body.String(), "SAMLResponse"))
	require.NoError(t, err)
	return string(buf)
}

func TestIsPassiveWithoutSessionReturnsNoPassive(t *testing.T) {
	test := NewServerTest(t)
	hardeningAddUser(t, test)

	response := samlResponseXML(t, serveWithCookie(test, constrainedRequestURL(t, test, false, true), nil))
	assert.Contains(t, response, saml.StatusNoPassive)
}

func TestIsPassiveWithSessionReturnsAssertion(t *testing.T) {
	test := NewServerTest(t)
	hardeningAddUser(t, test)
	cookie := loggedInCookie(t, test)

	response := samlResponseXML(t, serveWithCookie(test, constrainedRequestURL(t, test, false, true), cookie))
	assert.Contains(t, response, saml.StatusSuccess)
}

func TestIsPassiveWithUnknownSessionReturnsNoPassive(t *testing.T) {
	test := NewServerTest(t)
	hardeningAddUser(t, test)

	cookie := &http.Cookie{Name: "session", Value: "unknown"} //nolint:gosec // This is only sent to the test server.
	response := samlResponseXML(t, serveWithCookie(test, constrainedRequestURL(t, test, false, true), cookie))
	assert.Contains(t, response, saml.StatusNoPassive)
}

func TestForceAuthnShowsLoginFormDespiteSession(t *testing.T) {
	test := NewServerTest(t)
	hardeningAddUser(t, test)
	cookie := loggedInCookie(t, test)

	w := serveWithCookie(test, constrainedRequestURL(t, test, true, false), cookie)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `name="password"`)
	assert.False(t, strings.Contains(w.Body.String(), "SAMLResponse"))
}

func TestForceAuthnRequiresPasswordOnResubmission(t *testing.T) {
	test := NewServerTest(t)
	hardeningAddUser(t, test)
	cookie := loggedInCookie(t, test)
	form := serveWithCookie(test, constrainedRequestURL(t, test, true, false), cookie).Body.String()

	// The re-presented request carries ForceAuthn too, so the cookie can't stand in for the password.
	values := url.Values{"SAMLRequest": {hardeningHidden(t, form, "SAMLRequest")}, "RelayState": {"frob"}}
	r := httptest.NewRequest("POST", hardeningFormAction(t, form), strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	test.Server.ServeHTTP(w, r)
	assert.False(t, strings.Contains(w.Body.String(), "SAMLResponse"))

	hardeningAssertSAMLResponse(t, hardeningSubmitLogin(t, test, form, "hunter2"), "frob")
}

func TestForceAuthnRejectsWrongPassword(t *testing.T) {
	test := NewServerTest(t)
	hardeningAddUser(t, test)
	cookie := loggedInCookie(t, test)
	form := serveWithCookie(test, constrainedRequestURL(t, test, true, false), cookie).Body.String()

	w := hardeningSubmitLogin(t, test, form, "wrong")
	assert.False(t, strings.Contains(w.Body.String(), "SAMLResponse"))
}

// With both set, this provider has no way to authenticate without interaction.
func TestForceAuthnAndIsPassiveReturnsNoPassiveDespiteSession(t *testing.T) {
	test := NewServerTest(t)
	hardeningAddUser(t, test)
	cookie := loggedInCookie(t, test)

	response := samlResponseXML(t, serveWithCookie(test, constrainedRequestURL(t, test, true, true), cookie))
	assert.Contains(t, response, saml.StatusNoPassive)
}
