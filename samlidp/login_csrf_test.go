package samlidp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// postLogin posts the credentials of alice, with the hidden fields of form if it isn't empty, to
// target with the given request headers.
func postLogin(t *testing.T, test *ServerTest, target, form string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	values := url.Values{"user": {"alice"}, "password": {"hunter2"}}
	if form != "" {
		values.Set("SAMLRequest", hardeningHidden(t, form, "SAMLRequest"))
		values.Set("RelayState", hardeningHidden(t, form, "RelayState"))
	}
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	w := httptest.NewRecorder()
	test.Server.ServeHTTP(w, r)
	return w
}

// loginTargets returns the URL and the login form of each route which accepts credentials.
func loginTargets(t *testing.T, test *ServerTest) map[string][2]string {
	t.Helper()
	assert.NilError(t, test.Store.Put("/shortcuts/app", Shortcut{ServiceProviderID: "https://sp.example.com/saml2/metadata"}))
	shortcut := serveAdminRoute(test.Server, http.MethodGet, "/login/app").Body.String()
	return map[string][2]string{
		"sso":      {"https://idp.example.com/sso", hardeningStartSSO(t, test)},
		"login":    {"https://idp.example.com/login", ""},
		"shortcut": {"https://idp.example.com/login/app", shortcut},
	}
}

func storedSessions(t *testing.T, test *ServerTest) []string {
	t.Helper()
	sessions, err := test.Store.List("/sessions/")
	assert.NilError(t, err)
	return sessions
}

// Another site must not be able to log the browser in with credentials of its choosing, which would
// have the user act at service providers as the attacker.
func TestLoginRefusesCrossOriginCredentials(t *testing.T) {
	for name, headers := range map[string]map[string]string{
		"cross site":   {"Sec-Fetch-Site": "cross-site"},
		"same site":    {"Sec-Fetch-Site": "same-site"},
		"other origin": {"Origin": "https://attacker.example.com"},
		"other scheme": {"Origin": "http://idp.example.com"},
		"other port":   {"Origin": "https://idp.example.com:8443"},
		"opaque":       {"Origin": "null"},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewServerTest(t)
			hardeningAddUser(t, test)
			for route, target := range loginTargets(t, test) {
				w := postLogin(t, test, target[0], target[1], headers)
				assert.Check(t, is.Equal(w.Code, http.StatusForbidden), route)
				assert.Check(t, is.Len(w.Result().Cookies(), 0), route)
			}
			assert.Check(t, is.Len(storedSessions(t, test), 0))
		})
	}
}

func TestLoginAcceptsSameOriginCredentials(t *testing.T) {
	for name, headers := range map[string]map[string]string{
		"same origin":     {"Sec-Fetch-Site": "same-origin"},
		"matching origin": {"Origin": "https://idp.example.com"},
		"no headers":      {},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewServerTest(t)
			hardeningAddUser(t, test)
			for route, target := range loginTargets(t, test) {
				w := postLogin(t, test, target[0], target[1], headers)
				assert.Check(t, is.Equal(w.Code, http.StatusOK), route)
				assert.Check(t, is.Len(w.Result().Cookies(), 1), route)
			}
		})
	}
}

// A service provider posts its AuthnRequest from its own site, which carries no credentials and must
// still reach the login form.
func TestCrossSiteAuthnRequestStillShowsLoginForm(t *testing.T) {
	test := NewServerTest(t)
	form := hardeningStartSSO(t, test)
	values := url.Values{"SAMLRequest": {hardeningHidden(t, form, "SAMLRequest")}, "RelayState": {"frob"}}
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/sso", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.Header.Set("Origin", "https://sp.example.com")
	w := httptest.NewRecorder()
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(w.Code, http.StatusOK))
	assert.Check(t, strings.Contains(w.Body.String(), `name="password"`), w.Body.String())
}

// Without Sec-Fetch-Site, the Origin is compared with the configured URL, not the Host header or any
// forwarded header, which a proxy or the client chooses.
func TestLoginComparesOriginWithConfiguredURL(t *testing.T) {
	for name, tc := range map[string]struct {
		host, origin string
		code         int
	}{
		"proxied host":     {"127.0.0.1:8080", "https://idp.example.com", http.StatusOK},
		"origin from host": {"127.0.0.1:8080", "https://127.0.0.1:8080", http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewServerTest(t)
			hardeningAddUser(t, test)
			values := url.Values{"user": {"alice"}, "password": {"hunter2"}}
			r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/login", strings.NewReader(values.Encode()))
			r.Host = tc.host
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("X-Forwarded-Host", "127.0.0.1:8080")
			r.Header.Set("X-Forwarded-Proto", "https")
			w := httptest.NewRecorder()
			test.Server.ServeHTTP(w, r)
			assert.Check(t, is.Equal(w.Code, tc.code))
		})
	}
}
