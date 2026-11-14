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

// insecureServiceMetadata returns metadata whose HTTP-POST ACS endpoints have the given locations.
func insecureServiceMetadata(entityID string, locations ...string) string {
	var acs strings.Builder
	for i, location := range locations {
		acs.WriteString(`<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` +
			location + `" index="` + string(rune('1'+i)) + `"/>`)
	}
	return `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + entityID + `">` +
		`<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + acs.String() +
		`</SPSSODescriptor></EntityDescriptor>`
}

func putService(test *ServerTest, id, metadata string) int {
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("PUT", "https://idp.example.com/services/"+id, strings.NewReader(metadata))
	test.Server.ServeHTTP(w, r)
	return w.Code
}

// A service which could never receive an assertion is refused when it is registered.
func TestPutServiceRefusesInsecureACS(t *testing.T) {
	test := NewServerTest(t)

	assert.Check(t, is.Equal(putService(test, "a", insecureServiceMetadata("https://a.example.com/metadata", "http://a.example.com/acs")), http.StatusBadRequest))
	_, ok := test.Server.serviceProviders["https://a.example.com/metadata"]
	assert.Check(t, !ok)

	// One secure endpoint is enough, as it is the one which is used.
	assert.Check(t, is.Equal(putService(test, "b", insecureServiceMetadata("https://b.example.com/metadata", "http://b.example.com/acs", "https://b.example.com/acs")), http.StatusNoContent))
	assert.Check(t, is.Equal(putService(test, "c", insecureServiceMetadata("https://c.example.com/metadata", "http://localhost:8000/acs")), http.StatusNoContent))
}

func TestOptionsAllowInsecureServiceProviderEndpoints(t *testing.T) {
	server, err := New(Options{
		URL:                                   url.URL{Scheme: "https", Host: "idp.example.com"},
		Store:                                 &MemoryStore{},
		AllowInsecureServiceProviderEndpoints: true,
	})
	assert.NilError(t, err)
	assert.Check(t, server.IDP.AllowInsecureServiceProviderEndpoints)
	server.AdminAuthorizer = func(*http.Request) bool { return true }

	test := &ServerTest{Server: server}
	assert.Check(t, is.Equal(putService(test, "a", insecureServiceMetadata("https://a.example.com/metadata", "http://a.example.com/acs")), http.StatusNoContent))
}
