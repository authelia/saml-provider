package samlidp

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	require.NoError(t, err)
	assert.Equal(t, server.IDP.EntityID, "urn:example:idp")

	w := httptest.NewRecorder()
	server.ServeHTTP(w, httptest.NewRequest(http.MethodGet, server.IDP.MetadataURL.String(), nil))
	require.Equal(t, w.Code, http.StatusOK, "body: %s", w.Body.String())
	var metadata saml.EntityDescriptor
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &metadata))
	assert.Equal(t, metadata.EntityID, "urn:example:idp")
}
