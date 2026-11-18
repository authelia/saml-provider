package saml

import (
	"crypto/rsa"
	"encoding/base64"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The service provider variants carry what generate.py's transforms put in pysaml2's metadata, and nothing of what
// they take out of it.
func TestInteropSPVariants(t *testing.T) {
	encryption := func(t *testing.T, name string) KeyDescriptor {
		t.Helper()

		descriptor := interopSPMetadata(t, name).SPSSODescriptors[0]

		for _, kd := range descriptor.KeyDescriptors {
			if kd.Use == "encryption" {
				return kd
			}
		}

		t.Fatalf("%s has no encryption key", name)

		return KeyDescriptor{}
	}

	methods := func(kd KeyDescriptor) []EncryptionMethod { return kd.EncryptionMethods }

	t.Run("sp-rsa-negotiate", func(t *testing.T) {
		assert.Equal(t, []EncryptionMethod{
			{Algorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm"},
			{
				Algorithm:    "http://www.w3.org/2009/xmlenc11#rsa-oaep",
				DigestMethod: &DigestMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256"},
				MGF:          &MGF{Algorithm: "http://www.w3.org/2009/xmlenc11#mgf1sha256"},
			},
		}, methods(encryption(t, "sp-rsa-negotiate")))

		extensions := interopSPMetadata(t, "sp-rsa-negotiate").Extensions
		require.NotNil(t, extensions)
		assert.Equal(t, []SigningMethod{{Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"}}, extensions.SigningMethods)
		assert.Equal(t, []DigestMethod{{Algorithm: "http://www.w3.org/2001/04/xmldsig-more#sha384"}}, extensions.DigestMethods)
	})

	t.Run("sp-rsa-cbc", func(t *testing.T) {
		assert.Equal(t, []EncryptionMethod{
			{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},
			{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
		}, methods(encryption(t, "sp-rsa-cbc")))
	})

	t.Run("sp-rsa-keyvalue", func(t *testing.T) {
		kd := encryption(t, "sp-rsa-keyvalue")
		assert.Empty(t, kd.KeyInfo.X509Data.X509Certificates, "the certificate is still in the metadata")
		require.Len(t, kd.KeyInfo.KeyValues, 1)
		require.NotNil(t, kd.KeyInfo.KeyValues[0].RSAKeyValue)

		got, err := kd.KeyInfo.KeyValues[0].RSAKeyValue.PublicKey()
		require.NoError(t, err)

		_, cert := interopKey(t, "sp-rsa")
		assert.True(t, cert.PublicKey.(*rsa.PublicKey).Equal(got))
	})

	t.Run("sp-ecdh", func(t *testing.T) {
		_, signing := interopKey(t, "sp-rsa")
		_, enc := interopKey(t, "sp-ec")

		byUse := map[string][]KeyDescriptor{}
		for _, kd := range interopSPMetadata(t, "sp-ecdh").SPSSODescriptors[0].KeyDescriptors {
			byUse[kd.Use] = append(byUse[kd.Use], kd)
		}

		require.Len(t, byUse, 2, "uses other than signing and encryption: %v", slices.Collect(maps.Keys(byUse)))

		for use, want := range map[string][]byte{"signing": signing.Raw, "encryption": enc.Raw} {
			require.Len(t, byUse[use], 1, "%s keys", use)
			require.Len(t, byUse[use][0].KeyInfo.X509Data.X509Certificates, 1, "%s certificates", use)
			assert.Equal(t, want, mustDecodeBase64(t, byUse[use][0].KeyInfo.X509Data.X509Certificates[0].Data), use)
		}
	})

	t.Run("sp-rsa-mail", func(t *testing.T) {
		services := interopSPMetadata(t, "sp-rsa-mail").SPSSODescriptors[0].AttributeConsumingServices
		require.Len(t, services, 1)

		names := make([]string, 0, len(services[0].RequestedAttributes))
		for _, attribute := range services[0].RequestedAttributes {
			names = append(names, attribute.Name)
		}

		assert.Contains(t, names, "urn:oid:0.9.2342.19200300.100.1.3")
	})
}

func mustDecodeBase64(t *testing.T, s string) []byte {
	t.Helper()

	data, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	require.NoError(t, err)

	return data
}
