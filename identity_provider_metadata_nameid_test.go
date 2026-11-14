package saml

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

const persistentNameIDFormat = NameIDFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")

func TestIDPMetadataNameIDFormatsDefaultToTransient(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)

	got := test.IDP.Metadata().IDPSSODescriptors[0].NameIDFormats
	assert.Check(t, is.DeepEqual(got, []NameIDFormat{TransientNameIDFormat}))

	test.IDP.NameIDFormats = []NameIDFormat{}
	got = test.IDP.Metadata().IDPSSODescriptors[0].NameIDFormats
	assert.Check(t, is.DeepEqual(got, []NameIDFormat{TransientNameIDFormat}))
}

// The formats are advertised in the order given, which some service providers use to choose the
// format they request.
func TestIDPMetadataAdvertisesNameIDFormats(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.NameIDFormats = []NameIDFormat{EmailAddressNameIDFormat, persistentNameIDFormat, TransientNameIDFormat}

	w := httptest.NewRecorder()
	test.IDP.ServeMetadata(w, httptest.NewRequest(http.MethodGet, test.IDP.MetadataURL.String(), nil))
	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())
	var metadata EntityDescriptor
	assert.NilError(t, xml.Unmarshal(w.Body.Bytes(), &metadata))
	assert.Assert(t, is.Len(metadata.IDPSSODescriptors, 1))
	assert.Check(t, is.DeepEqual(metadata.IDPSSODescriptors[0].NameIDFormats,
		[]NameIDFormat{EmailAddressNameIDFormat, persistentNameIDFormat, TransientNameIDFormat}))
}

// The metadata must not share the slice of the identity provider, or changing one would change
// the other.
func TestIDPMetadataCopiesNameIDFormats(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.NameIDFormats = []NameIDFormat{EmailAddressNameIDFormat}

	test.IDP.Metadata().IDPSSODescriptors[0].NameIDFormats[0] = persistentNameIDFormat
	assert.Check(t, is.DeepEqual(test.IDP.NameIDFormats, []NameIDFormat{EmailAddressNameIDFormat}))
}

// The NameIDPolicy is checked against the format that is asserted, whatever the metadata
// advertises: a format the session issues satisfies it, and one that is advertised but not issued
// doesn't.
func TestServeSSONameIDPolicyIgnoresAdvertisedFormats(t *testing.T) {
	email := string(EmailAddressNameIDFormat)
	persistent := string(persistentNameIDFormat)

	t.Run("issued but not advertised", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.NameIDFormats = []NameIDFormat{persistentNameIDFormat}
		test.SP.IDPMetadata = test.IDP.Metadata()
		session := &Session{ID: "session", NameID: "alice@example.com", NameIDFormat: email}

		response := serveSSOWithPolicy(t, test, session, &NameIDPolicy{Format: &email})
		assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	})

	t.Run("advertised but not issued", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.NameIDFormats = []NameIDFormat{persistentNameIDFormat, EmailAddressNameIDFormat}
		test.SP.IDPMetadata = test.IDP.Metadata()
		session := &Session{ID: "session", NameID: "alice@example.com", NameIDFormat: email}

		assertInvalidNameIDPolicy(t, serveSSOWithPolicy(t, test, session, &NameIDPolicy{Format: &persistent}))
	})
}
