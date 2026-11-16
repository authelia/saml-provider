package samlidp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func putUser(test *ServerTest, name, body string) int {
	w := httptest.NewRecorder()
	test.Server.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "https://idp.example.com/users/"+name, strings.NewReader(body)))
	return w.Code
}

// The email of a user is their NameID, so two users with one email would be one principal at every
// service provider.
func TestPutUserRefusesAnotherUsersEmail(t *testing.T) {
	test := NewServerTest(t)
	assert.Assert(t, is.Equal(putUser(test, "alice", `{"email":"alice@example.com"}`), http.StatusNoContent))

	assert.Check(t, is.Equal(putUser(test, "mallory", `{"email":"alice@example.com"}`), http.StatusConflict))
	assert.Check(t, is.Equal(putUser(test, "mallory", `{"email":"Alice@Example.com"}`), http.StatusConflict))
	assert.Check(t, is.Equal(putUser(test, "alice", `{"email":"alice@example.com","given_name":"Alice"}`), http.StatusNoContent))
	assert.Check(t, is.Equal(putUser(test, "bob", `{"email":"bob@example.com"}`), http.StatusNoContent))
	assert.Check(t, is.Equal(putUser(test, "carol", `{}`), http.StatusNoContent))
	assert.Check(t, is.Equal(putUser(test, "dave", `{}`), http.StatusNoContent))

	// Once alice has another email, hers is free.
	assert.Check(t, is.Equal(putUser(test, "alice", `{"email":"alice@example.org"}`), http.StatusNoContent))
	assert.Check(t, is.Equal(putUser(test, "mallory", `{"email":"alice@example.com"}`), http.StatusNoContent))
}

func TestNewRejectsDuplicateUserEmails(t *testing.T) {
	test := NewServerTest(t)
	assert.NilError(t, test.Store.Put("/users/alice", User{Name: "alice", Email: "alice@example.com"}))
	assert.NilError(t, test.Store.Put("/users/mallory", User{Name: "mallory", Email: "ALICE@example.com"}))

	_, err := New(Options{Certificate: test.Certificate, Key: test.Key, Store: &test.Store, URL: test.Server.IDP.MetadataURL})
	assert.Check(t, is.ErrorContains(err, `users "alice" and "mallory" have the same email`))
}

// A user without an email has no NameID, so they can log in but receive no assertion.
func TestUserWithoutEmailReceivesNoAssertion(t *testing.T) {
	test := NewServerTest(t)
	hardeningAddUser(t, test)
	user := User{}
	assert.NilError(t, test.Store.Get("/users/alice", &user))
	user.Email = ""
	assert.NilError(t, test.Store.Put("/users/alice", user))

	w := hardeningSubmitLogin(t, test, hardeningStartSSO(t, test), "hunter2")
	assert.Check(t, !strings.Contains(w.Body.String(), "SAMLResponse"), w.Body.String())
	assert.Check(t, is.Equal(w.Code, http.StatusInternalServerError))
}

// Users without an email have no NameID, so they don't share one.
func TestNewAcceptsUsersWithoutEmail(t *testing.T) {
	test := NewServerTest(t)
	assert.NilError(t, test.Store.Put("/users/carol", User{Name: "carol"}))
	assert.NilError(t, test.Store.Put("/users/dave", User{Name: "dave"}))
	assert.NilError(t, test.Store.Put("/users/erin", User{Name: "erin", Email: "erin@example.com"}))

	_, err := New(Options{Certificate: test.Certificate, Key: test.Key, Store: &test.Store, URL: test.Server.IDP.MetadataURL})
	assert.Check(t, err)
}
