package samlidp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml"
)

// addBobSession stores the user bob and a session of his, which changes to alice must leave alone.
func addBobSession(t *testing.T, test *ServerTest) *http.Cookie {
	t.Helper()
	assert.NilError(t, test.Store.Put("/users/bob", User{Name: "bob", Email: "bob@example.com"}))
	assert.NilError(t, test.Store.Put("/sessions/bob-session", saml.Session{
		ID:         "bob-session",
		UserName:   "bob",
		NameID:     "bob@example.com",
		CreateTime: saml.TimeNow(),
		ExpireTime: saml.TimeNow().Add(time.Hour),
	}))
	return &http.Cookie{Name: "session", Value: "bob-session", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
}

func adminRequest(test *ServerTest, method, path, body string) int {
	w := httptest.NewRecorder()
	test.Server.ServeHTTP(w, httptest.NewRequest(method, "https://idp.example.com"+path, strings.NewReader(body)))
	return w.Code
}

// assertLoggedOut checks that the cookie no longer logs in: the request receives the login form.
func assertLoggedOut(t *testing.T, test *ServerTest, cookie *http.Cookie) {
	t.Helper()
	w := serveWithCookie(test, constrainedRequestURL(t, test, false, false), cookie)
	assert.Check(t, strings.Contains(w.Body.String(), `name="password"`), w.Body.String())
}

// A change to a user, such as a new password, ends the sessions of that user, which would otherwise
// keep asserting the old details until they expire.
func TestUserChangesEndTheirSessions(t *testing.T) {
	for name, change := range map[string]struct{ method, body string }{
		"delete":          {method: http.MethodDelete},
		"password change": {method: http.MethodPut, body: `{"password":"correct horse","email":"alice@example.com"}`},
		"email change":    {method: http.MethodPut, body: `{"email":"alice@example.org"}`},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewServerTest(t)
			hardeningAddUser(t, test)
			bob := addBobSession(t, test)
			cookie := loggedInCookie(t, test)

			assert.Assert(t, is.Equal(adminRequest(test, change.method, "/users/alice", change.body), http.StatusNoContent))
			assert.Check(t, !sessionStored(t, test, cookie))
			assertLoggedOut(t, test, cookie)
			assert.Check(t, sessionStored(t, test, bob))
		})
	}
}

// A session is not used once its user is gone, even if it was stored after the user was deleted,
// such as by a login which was in progress at the time.
func TestSessionOfMissingUserIsNotUsed(t *testing.T) {
	test := NewServerTest(t)
	hardeningAddUser(t, test)
	cookie := loggedInCookie(t, test)

	assert.NilError(t, test.Store.Delete("/users/alice"))
	assertLoggedOut(t, test, cookie)
}

// The sessions of a user can't be ended if they can't be listed, so the change reports a failure
// rather than leaving them in place silently.
func TestUserChangeFailsWhenSessionsCannotBeEnded(t *testing.T) {
	test := NewServerTest(t)
	hardeningAddUser(t, test)
	test.Server.Store = &failingListStore{Store: &test.Store}
	assert.Check(t, is.Equal(adminRequest(test, http.MethodDelete, "/users/alice", ""), http.StatusInternalServerError))
}

type failingListStore struct {
	Store
}

func (failingListStore) List(string) ([]string, error) {
	return nil, errors.New("store unavailable")
}

// A login which read the user before an update can store its session after the update has ended the
// user's sessions. That session is from an earlier revision of the user, so it isn't used.
func TestSessionFromEarlierUserRevisionIsNotUsed(t *testing.T) {
	test := NewServerTest(t)
	hardeningAddUser(t, test)
	assert.Assert(t, is.Equal(adminRequest(test, http.MethodPut, "/users/alice", `{"password":"hunter2","email":"alice@example.com"}`), http.StatusNoContent))
	cookie := loggedInCookie(t, test)
	var stale map[string]any
	assert.NilError(t, test.Store.Get("/sessions/"+cookie.Value, &stale))

	assert.Assert(t, is.Equal(adminRequest(test, http.MethodPut, "/users/alice", `{"email":"alice@example.org"}`), http.StatusNoContent))
	assert.NilError(t, test.Store.Put("/sessions/"+cookie.Value, stale))
	assertLoggedOut(t, test, cookie)
}

// The revision is set by the server, so a request can't choose one that matches an old session.
func TestUserRevisionIsNotTakenFromTheRequest(t *testing.T) {
	test := NewServerTest(t)
	assert.Assert(t, is.Equal(adminRequest(test, http.MethodPut, "/users/carol", `{"revision":"chosen"}`), http.StatusNoContent))
	user := User{}
	assert.NilError(t, test.Store.Get("/users/carol", &user))
	assert.Check(t, user.Revision != "" && user.Revision != "chosen", user.Revision)
}
