package samlidp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	assert.Equal(t, putService(test, "a", insecureServiceMetadata("https://a.example.com/metadata", "http://a.example.com/acs")), http.StatusBadRequest)
	_, ok := test.Server.serviceProviders["https://a.example.com/metadata"]
	assert.False(t, ok)

	// One secure endpoint is enough, as it is the one which is used.
	assert.Equal(t, putService(test, "b", insecureServiceMetadata("https://b.example.com/metadata", "http://b.example.com/acs", "https://b.example.com/acs")), http.StatusNoContent)
	assert.Equal(t, putService(test, "c", insecureServiceMetadata("https://c.example.com/metadata", "http://localhost:8000/acs")), http.StatusNoContent)
}

func TestOptionsAllowInsecureServiceProviderEndpoints(t *testing.T) {
	server, err := New(Options{
		URL:                                   url.URL{Scheme: "https", Host: "idp.example.com"},
		Store:                                 &MemoryStore{},
		AllowInsecureServiceProviderEndpoints: true,
	})
	require.NoError(t, err)
	assert.True(t, server.IDP.AllowInsecureServiceProviderEndpoints)
	server.AdminAuthorizer = func(*http.Request) bool { return true }

	test := &ServerTest{Server: server}
	assert.Equal(t, putService(test, "a", insecureServiceMetadata("https://a.example.com/metadata", "http://a.example.com/acs")), http.StatusNoContent)
}

// Only the descriptors that have not expired are served, so a secure endpoint in an expired one
// doesn't count. The stored metadata is still the metadata that was put.
func TestPutServiceChecksACSOfCurrentDescriptors(t *testing.T) {
	test := NewServerTest(t)

	descriptor := func(validUntil, location string) string {
		return `<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"` + validUntil + `>` +
			`<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + location + `" index="1"/>` +
			`</SPSSODescriptor>`
	}
	metadata := func(entityID string, descriptors ...string) string {
		return `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + entityID + `">` +
			strings.Join(descriptors, "") + `</EntityDescriptor>`
	}
	expired := ` validUntil="2000-01-01T00:00:00Z"`

	assert.Equal(t, putService(test, "a", metadata("https://a.example.com/metadata",
		descriptor(expired, "https://a.example.com/acs"),
		descriptor("", "http://a.example.com/acs"))), http.StatusBadRequest)
	_, ok := test.Server.serviceProviders["https://a.example.com/metadata"]
	assert.False(t, ok)

	assert.Equal(t, putService(test, "b", metadata("https://b.example.com/metadata",
		descriptor(expired, "http://b.example.com/acs"),
		descriptor("", "https://b.example.com/acs"))), http.StatusNoContent)
	stored := Service{}
	require.NoError(t, test.Store.Get("/services/b", &stored))
	assert.Len(t, stored.Metadata.SPSSODescriptors, 2)
}
