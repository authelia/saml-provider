package saml

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// The identity provider never decrypts anything, so its metadata must not invite a service provider
// to encrypt to it, whatever the type of its key.
func TestIDPMetadataPublishesOnlySigningKeyForRSACertificate(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	descriptors := test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors
	assert.Check(t, is.DeepEqual([]string{"signing"}, keyDescriptorUses(descriptors)))
	for _, descriptor := range descriptors {
		assert.Check(t, is.Len(descriptor.EncryptionMethods, 0))
	}
}

func TestIDPMetadataOmitsSingleLogoutWithoutLogoutURL(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	assert.Check(t, is.Len(test.IDP.Metadata().IDPSSODescriptors[0].SingleLogoutServices, 0))

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/saml/slo", nil)
	test.IDP.Handler().ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusNotFound, w.Code))
}
