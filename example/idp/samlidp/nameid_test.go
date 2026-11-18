package samlidp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml"
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
	require.Equal(t, putUser(test, "alice", `{"email":"alice@example.com"}`), http.StatusNoContent)

	assert.Equal(t, putUser(test, "mallory", `{"email":"alice@example.com"}`), http.StatusConflict)
	assert.Equal(t, putUser(test, "mallory", `{"email":"Alice@Example.com"}`), http.StatusConflict)
	assert.Equal(t, putUser(test, "alice", `{"email":"alice@example.com","given_name":"Alice"}`), http.StatusNoContent)
	assert.Equal(t, putUser(test, "bob", `{"email":"bob@example.com"}`), http.StatusNoContent)
	assert.Equal(t, putUser(test, "carol", `{}`), http.StatusNoContent)
	assert.Equal(t, putUser(test, "dave", `{}`), http.StatusNoContent)

	// Once alice has another email, hers is free.
	assert.Equal(t, putUser(test, "alice", `{"email":"alice@example.org"}`), http.StatusNoContent)
	assert.Equal(t, putUser(test, "mallory", `{"email":"alice@example.com"}`), http.StatusNoContent)
}

func TestNewRejectsDuplicateUserEmails(t *testing.T) {
	test := NewServerTest(t)
	require.NoError(t, test.Store.Put("/users/alice", User{Name: "alice", Email: "alice@example.com"}))
	require.NoError(t, test.Store.Put("/users/mallory", User{Name: "mallory", Email: "ALICE@example.com"}))

	_, err := New(Options{Certificate: test.Certificate, Key: test.Key, Store: &test.Store, URL: test.Server.IDP.MetadataURL})
	assert.ErrorContains(t, err, `users "alice" and "mallory" have the same email`)
}

// A user without an email has no NameID of their own, so they're asserted a random transient NameID, which
// no other user shares.
func TestUserWithoutEmailReceivesTransientNameID(t *testing.T) {
	test := NewServerTest(t)
	hardeningAddUser(t, test)
	user := User{}
	require.NoError(t, test.Store.Get("/users/alice", &user))
	user.Email = ""
	require.NoError(t, test.Store.Put("/users/alice", user))

	w := hardeningSubmitLogin(t, test, hardeningStartSSO(t, test), "hunter2")
	response := samlResponseXML(t, w)
	assert.Contains(t, response, saml.StatusSuccess)
	assert.True(t, strings.Contains(response, "Assertion"), response)
}

// Users without an email have no NameID, so they don't share one.
func TestNewAcceptsUsersWithoutEmail(t *testing.T) {
	test := NewServerTest(t)
	require.NoError(t, test.Store.Put("/users/carol", User{Name: "carol"}))
	require.NoError(t, test.Store.Put("/users/dave", User{Name: "dave"}))
	require.NoError(t, test.Store.Put("/users/erin", User{Name: "erin", Email: "erin@example.com"}))

	_, err := New(Options{Certificate: test.Certificate, Key: test.Key, Store: &test.Store, URL: test.Server.IDP.MetadataURL})
	assert.NoError(t, err)
}

// A persistent NameID is issued by the NameIDProvider of the options, and advertised in the metadata.
func TestNameIDProviderOption(t *testing.T) {
	test := NewServerTest(t)

	server, err := New(Options{
		Certificate:    test.Certificate,
		Key:            test.Key,
		Store:          &test.Store,
		URL:            test.Server.IDP.MetadataURL,
		NameIDProvider: saml.PersistentNameIDProvider{Secret: []byte("0123456789abcdef0123456789abcdef")},
	})
	require.NoError(t, err)

	formats := server.IDP.Metadata().IDPSSODescriptors[0].NameIDFormats
	assert.Equal(t, formats, []saml.NameIDFormat{saml.PersistentNameIDFormat, saml.TransientNameIDFormat})
}
