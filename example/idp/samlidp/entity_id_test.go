package samlidp

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml"
)

func TestNewSetsEntityID(t *testing.T) {
	test := NewServerTest(t)
	server, err := New(Options{
		Certificate: test.Certificate,
		Key:         test.Key,
		Store:       &test.Store,
		URL:         url.URL{Scheme: "https", Host: "idp.example.com"},
		EntityID:    "urn:example:idp",
	})
	assert.NilError(t, err)
	assert.Check(t, is.Equal(server.IDP.EntityID, "urn:example:idp"))

	w := httptest.NewRecorder()
	server.ServeHTTP(w, httptest.NewRequest(http.MethodGet, server.IDP.MetadataURL.String(), nil))
	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())
	var metadata saml.EntityDescriptor
	assert.NilError(t, xml.Unmarshal(w.Body.Bytes(), &metadata))
	assert.Check(t, is.Equal(metadata.EntityID, "urn:example:idp"))
}
