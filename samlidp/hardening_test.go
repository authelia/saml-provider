package samlidp

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml"
	"authelia.com/provider/saml/internal/dsig"
)

var adminRoutes = []struct{ method, path string }{
	{"GET", "/services/"},
	{"GET", "/services/x"},
	{"PUT", "/services/x"},
	{"POST", "/services/x"},
	{"DELETE", "/services/x"},
	{"GET", "/users/"},
	{"GET", "/users/x"},
	{"PUT", "/users/x"},
	{"DELETE", "/users/x"},
	{"GET", "/sessions/"},
	{"GET", "/sessions/x"},
	{"DELETE", "/sessions/x"},
	{"GET", "/shortcuts/"},
	{"GET", "/shortcuts/x"},
	{"PUT", "/shortcuts/x"},
	{"DELETE", "/shortcuts/x"},
}

func serveAdminRoute(s *Server, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(method, "https://idp.example.com"+path, strings.NewReader("{}")))
	return w
}

func TestAdminRoutesDeniedWithoutAuthorizer(t *testing.T) {
	test := NewServerTest(t)
	test.Server.AdminAuthorizer = nil
	assert.NilError(t, test.Store.Put("/users/x", User{Name: "x"}))

	for _, route := range adminRoutes {
		w := serveAdminRoute(test.Server, route.method, route.path)
		assert.Check(t, is.Equal(http.StatusForbidden, w.Code), "%s %s", route.method, route.path)
	}

	user := User{}
	assert.Check(t, test.Store.Get("/users/x", &user), "denied DELETE must not remove the user")
}

func TestAdminRoutesDeniedWhenAuthorizerRefuses(t *testing.T) {
	test := NewServerTest(t)
	var seen []string
	test.Server.AdminAuthorizer = func(r *http.Request) bool {
		seen = append(seen, r.Method+" "+r.URL.Path)
		return false
	}

	for _, route := range adminRoutes {
		w := serveAdminRoute(test.Server, route.method, route.path)
		assert.Check(t, is.Equal(http.StatusForbidden, w.Code), "%s %s", route.method, route.path)
	}
	assert.Check(t, is.Equal(len(adminRoutes), len(seen)))
}

func TestAdminRoutesAllowedWhenAuthorized(t *testing.T) {
	test := NewServerTest(t)
	w := serveAdminRoute(test.Server, "GET", "/users/")
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
}

func TestPublicRoutesDoNotRequireAuthorizer(t *testing.T) {
	test := NewServerTest(t)
	test.Server.AdminAuthorizer = nil
	for _, path := range []string{"/metadata", "/login"} {
		w := serveAdminRoute(test.Server, "GET", path)
		assert.Check(t, is.Equal(http.StatusOK, w.Code), path)
	}
}

func TestMemoryStoreListIsSafeForConcurrentUse(t *testing.T) {
	store := &MemoryStore{}
	assert.NilError(t, store.Put("/a/seed", "v"))

	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := range 2000 {
				assert.Check(t, store.Put(fmt.Sprintf("/a/%d-%d", i, j), "v"))
			}
		}()
		go func() {
			defer wg.Done()
			for range 200 {
				_, err := store.List("/a/")
				assert.Check(t, err)
			}
		}()
	}
	wg.Wait()
}

// queueWriterStore queues a writer on the server's config lock while a session is looked up, which
// is the window between HandleIDPInitiated taking the lock and GetServiceProvider taking it again.
type queueWriterStore struct {
	Store
	mu *sync.RWMutex
}

func (s *queueWriterStore) Get(key string, value interface{}) error {
	if strings.HasPrefix(key, "/sessions/") {
		go func() {
			s.mu.Lock()
			defer s.mu.Unlock()
		}()
		time.Sleep(50 * time.Millisecond)
	}
	return s.Store.Get(key, value)
}

func TestIDPInitiatedDoesNotDeadlockWithConfigWriter(t *testing.T) {
	test := NewServerTest(t)
	assert.NilError(t, test.Store.Put("/shortcuts/app", Shortcut{ServiceProviderID: "https://sp.example.com/saml2/metadata"}))
	assert.NilError(t, test.Store.Put("/sessions/s", saml.Session{ID: "s", NameID: "alice", ExpireTime: saml.TimeNow().Add(time.Hour)}))
	test.Server.Store = &queueWriterStore{Store: &test.Store, mu: &test.Server.idpConfigMu}

	done := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "https://idp.example.com/login/app", nil)
		r.Header.Set("Cookie", "session=s")
		test.Server.ServeHTTP(w, r)
		done <- w.Code
	}()

	select {
	case code := <-done:
		assert.Check(t, is.Equal(http.StatusOK, code))
	case <-time.After(5 * time.Second):
		t.Fatal("IDP-initiated login deadlocked against a writer")
	}
}

func hardeningAddUser(t *testing.T, test *ServerTest) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	assert.NilError(t, err)
	assert.NilError(t, test.Store.Put("/users/alice", User{Name: "alice", Email: "alice@example.com", HashedPassword: hash}))
}

func TestSessionCookieAttributes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		idpScheme string
		target    string
		tls       bool
		secure    bool
	}{
		{name: "configured https behind a proxy", idpScheme: "https", target: "/login", secure: true},
		{name: "direct TLS with http configured", idpScheme: "http", target: "/login", tls: true, secure: true},
		{name: "plain http", idpScheme: "http", target: "/login"},
		{name: "absolute https url does not count", idpScheme: "http", target: "https://idp.example.com/login"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := NewServerTest(t)
			hardeningAddUser(t, test)
			test.Server.IDP.SSOURL.Scheme = tc.idpScheme

			r := httptest.NewRequest("POST", tc.target, strings.NewReader("user=alice&password=hunter2"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			} else {
				r.TLS = nil
			}
			w := httptest.NewRecorder()
			test.Server.ServeHTTP(w, r)

			cookies := w.Result().Cookies()
			assert.Assert(t, is.Len(cookies, 1))
			assert.Check(t, is.Equal(tc.secure, cookies[0].Secure))
			assert.Check(t, cookies[0].HttpOnly)
			assert.Check(t, is.Equal(http.SameSiteLaxMode, cookies[0].SameSite))
		})
	}
}

var hardeningFormRE = regexp.MustCompile(`action="([^"]*)"`)

func hardeningHidden(t *testing.T, body, name string) string {
	t.Helper()
	m := regexp.MustCompile(`name="` + name + `" value="([^"]*)"`).FindStringSubmatch(body)
	assert.Assert(t, m != nil, "no %s in %s", name, body)
	return html.UnescapeString(m[1])
}

func hardeningFormAction(t *testing.T, body string) string {
	t.Helper()
	m := hardeningFormRE.FindStringSubmatch(body)
	assert.Assert(t, m != nil, "no form in %s", body)
	return html.UnescapeString(m[1])
}

// hardeningSubmitLogin posts credentials and the hidden fields of a login form to its action.
func hardeningSubmitLogin(t *testing.T, test *ServerTest, form, password string) *httptest.ResponseRecorder {
	t.Helper()
	values := url.Values{
		"user":        {"alice"},
		"password":    {password},
		"SAMLRequest": {hardeningHidden(t, form, "SAMLRequest")},
		"RelayState":  {hardeningHidden(t, form, "RelayState")},
	}
	r := httptest.NewRequest("POST", hardeningFormAction(t, form), strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	test.Server.ServeHTTP(w, r)
	return w
}

func hardeningAssertSAMLResponse(t *testing.T, w *httptest.ResponseRecorder, relayState string) {
	t.Helper()
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	body := w.Body.String()
	assert.Check(t, is.Equal("https://sp.example.com/saml2/acs", hardeningFormAction(t, body)))
	assert.Check(t, is.Equal(relayState, hardeningHidden(t, body, "RelayState")))
	response, err := base64.StdEncoding.DecodeString(hardeningHidden(t, body, "SAMLResponse"))
	assert.NilError(t, err)
	assert.Check(t, strings.Contains(string(response), "EncryptedAssertion"), string(response))
}

func hardeningStartSSO(t *testing.T, test *ServerTest) string {
	t.Helper()
	u, err := test.SP.MakeRedirectAuthenticationRequest("frob")
	assert.NilError(t, err)
	w := httptest.NewRecorder()
	test.Server.ServeHTTP(w, httptest.NewRequest("GET", u.String(), nil))
	assert.Assert(t, is.Equal(http.StatusOK, w.Code))
	return w.Body.String()
}

func TestFirstLoginReturnsToServiceProvider(t *testing.T) {
	test := NewServerTest(t)
	hardeningAddUser(t, test)

	form := hardeningStartSSO(t, test)
	assert.Check(t, is.Equal("https://idp.example.com/sso", hardeningFormAction(t, form)))

	hardeningAssertSAMLResponse(t, hardeningSubmitLogin(t, test, form, "hunter2"), "frob")
}

func TestFailedLoginKeepsTheRequestInProgress(t *testing.T) {
	test := NewServerTest(t)
	hardeningAddUser(t, test)

	w := hardeningSubmitLogin(t, test, hardeningStartSSO(t, test), "wrong")
	assert.Check(t, strings.Contains(w.Body.String(), "Invalid username or password"), w.Body.String())

	hardeningAssertSAMLResponse(t, hardeningSubmitLogin(t, test, w.Body.String(), "hunter2"), "frob")
}

func TestStandaloneLoginFormPostsToLogin(t *testing.T) {
	test := NewServerTest(t)
	w := serveAdminRoute(test.Server, "GET", "/login")
	assert.Check(t, is.Equal("https://idp.example.com/login", hardeningFormAction(t, w.Body.String())))
}

func TestFirstLoginThroughShortcut(t *testing.T) {
	test := NewServerTest(t)
	hardeningAddUser(t, test)
	assert.NilError(t, test.Store.Put("/shortcuts/app", Shortcut{
		ServiceProviderID:     "https://sp.example.com/saml2/metadata",
		URISuffixAsRelayState: true,
	}))

	w := serveAdminRoute(test.Server, "GET", "/login/app/whoami")
	assert.Check(t, is.Equal("https://idp.example.com/login/app/whoami", hardeningFormAction(t, w.Body.String())))

	hardeningAssertSAMLResponse(t, hardeningSubmitLogin(t, test, w.Body.String(), "hunter2"), "/whoami")
}

func TestLoginFormCanBeSubmittedAfterRequestDelay(t *testing.T) {
	start := saml.TimeNow
	for _, tc := range []struct {
		name  string
		delay time.Duration
		code  int
	}{
		{name: "past the issue delay", delay: saml.MaxIssueDelay + time.Second, code: http.StatusOK},
		{name: "at the limit", delay: maxLoginDuration, code: http.StatusOK},
		{name: "past the limit", delay: maxLoginDuration + time.Second, code: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := NewServerTest(t)
			defer func() { saml.TimeNow = start }()
			hardeningAddUser(t, test)
			form := hardeningStartSSO(t, test)

			issued := saml.TimeNow()
			saml.TimeNow = func() time.Time { return issued.Add(tc.delay) }

			w := hardeningSubmitLogin(t, test, form, "hunter2")
			assert.Check(t, is.Equal(tc.code, w.Code))
			if tc.code == http.StatusOK {
				hardeningAssertSAMLResponse(t, w, "frob")
			}
		})
	}
}

func TestShortcutLoginFormStaysOnTheShortcutPath(t *testing.T) {
	for _, tc := range []struct {
		name, suffix, action string
		relayState           string
	}{
		{name: "plain", suffix: "/whoami", action: "/login/app/whoami", relayState: "/whoami"},
		{name: "no suffix", suffix: "", action: "/login/app", relayState: ""},
		{name: "escaped traversal", suffix: "/..%2F..%2F..%2Fblog%2Fcollect", action: "/login/app/..%2F..%2F..%2Fblog%2Fcollect", relayState: "/../../../blog/collect"},
		{name: "escaped slash", suffix: "/a%2Fb", action: "/login/app/a%2Fb", relayState: "/a/b"},
		{name: "escaped percent", suffix: "/a%25b", action: "/login/app/a%25b", relayState: "/a%b"},
		{name: "double escaped space", suffix: "/a%2520b", action: "/login/app/a%2520b", relayState: "/a%20b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := NewServerTest(t)
			hardeningAddUser(t, test)
			assert.NilError(t, test.Store.Put("/shortcuts/app", Shortcut{
				ServiceProviderID:     "https://sp.example.com/saml2/metadata",
				URISuffixAsRelayState: true,
			}))

			w := serveAdminRoute(test.Server, "GET", "/login/app"+tc.suffix)
			assert.Check(t, is.Equal("https://idp.example.com"+tc.action, hardeningFormAction(t, w.Body.String())))

			hardeningAssertSAMLResponse(t, hardeningSubmitLogin(t, test, w.Body.String(), "hunter2"), tc.relayState)
		})
	}
}

func TestShortcutLoginFormRejectsDotSegments(t *testing.T) {
	for _, suffix := range []string{"%2e%2e", "%2e", ".%2e"} {
		t.Run(suffix, func(t *testing.T) {
			test := NewServerTest(t)
			assert.NilError(t, test.Store.Put("/shortcuts/app", Shortcut{
				ServiceProviderID:     "https://sp.example.com/saml2/metadata",
				URISuffixAsRelayState: true,
			}))

			w := serveAdminRoute(test.Server, "GET", "/login/app/"+suffix)
			assert.Check(t, is.Equal(http.StatusBadRequest, w.Code), w.Body.String())
		})
	}
}

func TestShortcutGetIgnoresMalformedQuery(t *testing.T) {
	test := NewServerTest(t)
	assert.NilError(t, test.Store.Put("/shortcuts/app", Shortcut{ServiceProviderID: "https://sp.example.com/saml2/metadata"}))

	w := serveAdminRoute(test.Server, "GET", "/login/app?a=%zz")
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
}

func TestSignedRedirectResumesAfterLogin(t *testing.T) {
	test := NewServerTest(t)
	hardeningAddUser(t, test)
	test.SP.SignatureMethod = dsig.RSASHA256SignatureMethod
	test.Server.serviceProviders["https://sp.example.com/saml2/metadata"] = test.SP.Metadata()

	previousClock := saml.Clock
	t.Cleanup(func() { saml.Clock = previousClock })
	saml.Clock = dsig.NewFakeClockAt(test.SPCertificate.NotBefore)

	form := hardeningStartSSO(t, test)

	values := url.Values{
		"user":              {"alice"},
		"password":          {"hunter2"},
		"SAMLRedirectQuery": {hardeningHidden(t, form, "SAMLRedirectQuery")},
	}
	r := httptest.NewRequest("POST", hardeningFormAction(t, form), strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	test.Server.ServeHTTP(w, r)
	hardeningAssertSAMLResponse(t, w, "frob")

	// Without the signed query the request is refused, so the field can't simply be dropped.
	failed := hardeningSubmitLogin(t, test, form, "hunter2")
	assert.Check(t, is.Equal(http.StatusBadRequest, failed.Code))
}
