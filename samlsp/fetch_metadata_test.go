package samlsp

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFetchMetadata(t *testing.T) {
	test := NewMiddlewareTest(t)

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/metadata", r.URL.String())

		_, err := w.Write(test.IDPMetadata)
		assert.NoError(t, err)
	}))

	u, _ := url.Parse(testServer.URL + "/metadata")
	md, err := FetchMetadata(context.Background(), testServer.Client(), *u)
	assert.NoError(t, err)
	assert.Equal(t, "https://idp.testshib.org/idp/shibboleth", md.EntityID)
}

func TestFetchMetadataRejectsInvalid(t *testing.T) {
	test := NewMiddlewareTest(t)
	test.IDPMetadata = bytes.ReplaceAll(test.IDPMetadata,
		[]byte("<EntityDescriptor "), []byte("<EntityDescriptor ::foo=\"bar\">]]"))

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/metadata", r.URL.String())

		_, err := w.Write(test.IDPMetadata)
		assert.NoError(t, err)
	}))

	u, _ := url.Parse(testServer.URL + "/metadata")
	md, err := FetchMetadata(context.Background(), testServer.Client(), *u)
	assert.NotNil(t, err)
	assert.Nil(t, md)
}
