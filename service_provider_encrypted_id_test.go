package saml

import (
	"bytes"
	"compress/flate"
	"crypto/elliptic"
	"encoding/base64"
	"html"
	"io"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSPRequestsEncryptedNameID(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.SP.AuthnNameIDFormat = PersistentNameIDFormat

	request, err := test.SP.MakeAuthenticationRequest("https://idp.example.com/saml/sso", HTTPRedirectBinding, HTTPPostBinding)
	require.NoError(t, err)
	assert.Equal(t, string(PersistentNameIDFormat), *request.NameIDPolicy.Format)

	test.SP.EncryptNameID = true

	request, err = test.SP.MakeAuthenticationRequest("https://idp.example.com/saml/sso", HTTPRedirectBinding, HTTPPostBinding)
	require.NoError(t, err)
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted", *request.NameIDPolicy.Format)

	// Errata E6: the request can't say which kind of identifier to encrypt, and the metadata may.
	assert.Equal(t, []NameIDFormat{PersistentNameIDFormat}, test.SP.Metadata().SPSSODescriptors[0].NameIDFormats)
}

// The identity provider chooses the identifier it encrypts from the formats of the metadata of the service provider.
func TestIDPEncryptsFormatOfSPMetadataForSPOfThisLibrary(t *testing.T) {
	test, req := encryptedPartsRequest(t)
	test.IDP.NameIDProvider = DefaultNameIDProvider{Formats: []string{string(TransientNameIDFormat), string(EmailAddressNameIDFormat)}}
	test.SP.AuthnNameIDFormat = EmailAddressNameIDFormat
	test.SP.EncryptNameID = true

	metadata := test.SP.Metadata()
	req.ServiceProviderMetadata, req.SPSSODescriptor = metadata, &metadata.SPSSODescriptors[0]
	req.ACSEndpoint = &metadata.SPSSODescriptors[0].AssertionConsumerServices[0]

	request, err := test.SP.MakeAuthenticationRequest("https://idp.example.com/saml/sso", HTTPRedirectBinding, HTTPPostBinding)
	require.NoError(t, err)

	req.Request.NameIDPolicy = request.NameIDPolicy

	assertion, err := test.SP.ParseXMLResponse([]byte(respond(t, req)), []string{"id-request"}, test.SP.AcsURL)
	require.NoError(t, err)
	assert.Equal(t, string(EmailAddressNameIDFormat), assertion.Subject.NameID.Format)
	assert.Equal(t, "alice@example.com", assertion.Subject.NameID.Value)
	assert.True(t, req.nameIDEncrypted)
}

func TestSPMakesLogoutRequestWithEncryptedID(t *testing.T) {
	test, _ := logoutTestIDP(t)
	test.SP.EncryptNameID = true
	test.SP.AuthnNameIDFormat = PersistentNameIDFormat

	decrypter, err := test.IDP.elementDecrypter()
	require.NoError(t, err)

	check := func(t *testing.T, el *etree.Element) {
		t.Helper()

		assert.Nil(t, el.FindElement("./NameID"))
		assert.False(t, strings.Contains(elementToString(el), "alice"))

		encryptedID, err := findOneChild(el, samlAssertionNamespace, "EncryptedID")
		require.NoError(t, err)

		// The identity provider of this library lists AES-128-GCM first (SAMLProfiles §4.4.5).
		assert.Equal(t, aes128GCM, encryptedID.FindElement("./EncryptedData/EncryptionMethod").SelectAttrValue("Algorithm", ""))
		assert.Equal(t, test.IDP.Metadata().EntityID, encryptedID.FindElement("./EncryptedData/KeyInfo/EncryptedKey").SelectAttrValue("Recipient", ""))

		nameID, err := decrypter.decryptNameID(encryptedID)
		require.NoError(t, err)
		assert.Equal(t, NameID{
			Format:          string(PersistentNameIDFormat),
			NameQualifier:   test.IDP.Metadata().EntityID,
			SPNameQualifier: test.SP.MetadataURL.String(),
			Value:           "alice",
		}, *nameID)
	}

	t.Run("signed", func(t *testing.T) {
		request, err := test.SP.MakeLogoutRequest(logoutTestSLOURL, "alice")
		require.NoError(t, err)
		assert.Nil(t, request.NameID)

		// SAMLCore §6.2: the signature is calculated over the message which contains the EncryptedID.
		certificates, err := serviceProviderSigningCertificates(test.SP.Metadata())
		require.NoError(t, err)

		verified, err := verifyEnvelopedSignature(reparse(t, request.Element()), certificates, anySignaturePolicy)
		require.NoError(t, err)
		check(t, verified)
	})

	t.Run("post", func(t *testing.T) {
		form, err := test.SP.MakePostLogoutRequest("alice", "relay")
		require.NoError(t, err)

		const marker = `name="SAMLRequest" value="`

		_, rest, found := strings.Cut(string(form), marker)
		require.True(t, found)

		encoded, _, _ := strings.Cut(rest, `"`)
		buf, err := base64.StdEncoding.DecodeString(html.UnescapeString(encoded))
		require.NoError(t, err)

		doc := etree.NewDocument()
		require.NoError(t, doc.ReadFromBytes(buf))
		check(t, doc.Root())
	})

	t.Run("redirect", func(t *testing.T) {
		u, err := test.SP.MakeRedirectLogoutRequest("alice", "relay")
		require.NoError(t, err)

		compressed, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
		require.NoError(t, err)

		buf, err := io.ReadAll(flate.NewReader(bytes.NewReader(compressed)))
		require.NoError(t, err)

		doc := etree.NewDocument()
		require.NoError(t, doc.ReadFromBytes(buf))
		check(t, doc.Root())
	})
}

func TestSPDoesNotSendNameIDItCannotEncrypt(t *testing.T) {
	keyDescriptor := func(use string, certificate []byte, methods ...EncryptionMethod) KeyDescriptor {
		descriptor := KeyDescriptor{Use: use, EncryptionMethods: methods}
		descriptor.KeyInfo.X509Data.X509Certificates = []X509Certificate{{Data: base64.StdEncoding.EncodeToString(certificate)}}

		return descriptor
	}

	_, rsaCertificate := negotiationKey()
	_, ecdsaCertificate := newECDSATestKey(t, elliptic.P224())

	for name, tc := range map[string]struct {
		metadata *EntityDescriptor
		err      string
		content  string
	}{
		"no metadata": {nil, "cannot encrypt to the identity provider without its metadata", ""},
		"signing key only": {
			&EntityDescriptor{EntityID: "https://idp.example.com", IDPSSODescriptors: []IDPSSODescriptor{{SSODescriptor: SSODescriptor{RoleDescriptor: RoleDescriptor{
				KeyDescriptors: []KeyDescriptor{keyDescriptor("signing", rsaCertificate.Raw)},
			}}}}},
			`the identity provider "https://idp.example.com" has no encryption key in its metadata that can be encrypted to`, "",
		},
		// ECDH-ES is only supported on P-256, P-384 and P-521, so a key on another curve is never encrypted to.
		"ecdsa key on another curve": {
			&EntityDescriptor{EntityID: "https://idp.example.com", IDPSSODescriptors: []IDPSSODescriptor{{SSODescriptor: SSODescriptor{RoleDescriptor: RoleDescriptor{
				KeyDescriptors: []KeyDescriptor{keyDescriptor("encryption", ecdsaCertificate.Raw), keyDescriptor("", ecdsaCertificate.Raw)},
			}}}}},
			"has no encryption key in its metadata that can be encrypted to", "",
		},
		"only algorithms that are not supported": {
			&EntityDescriptor{EntityID: "https://idp.example.com", IDPSSODescriptors: []IDPSSODescriptor{{SSODescriptor: SSODescriptor{RoleDescriptor: RoleDescriptor{
				KeyDescriptors: []KeyDescriptor{keyDescriptor("encryption", rsaCertificate.Raw, method(tripleDES))},
			}}}}},
			"the encryption key lists no content encryption algorithm", "",
		},
		"key with no use": {
			&EntityDescriptor{EntityID: "https://idp.example.com", IDPSSODescriptors: []IDPSSODescriptor{{SSODescriptor: SSODescriptor{RoleDescriptor: RoleDescriptor{
				KeyDescriptors: []KeyDescriptor{keyDescriptor("signing", rsaCertificate.Raw), keyDescriptor("", rsaCertificate.Raw)},
			}}}}},
			"", aes128GCM,
		},
		"encryption key is preferred to one with no use": {
			&EntityDescriptor{EntityID: "https://idp.example.com", IDPSSODescriptors: []IDPSSODescriptor{{SSODescriptor: SSODescriptor{RoleDescriptor: RoleDescriptor{
				KeyDescriptors: []KeyDescriptor{keyDescriptor("", rsaCertificate.Raw), keyDescriptor("encryption", rsaCertificate.Raw, method(aes256GCM))},
			}}}}},
			"", aes256GCM,
		},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			test.SP.EncryptNameID = true
			test.SP.IDPMetadata = tc.metadata

			if tc.metadata == nil {
				_, err := test.SP.idpElementEncrypter()
				assert.ErrorContains(t, err, tc.err)

				return
			}

			request, err := test.SP.MakeLogoutRequest("https://idp.example.com/slo", "alice")
			if tc.err != "" {
				assert.Nil(t, request)
				assert.ErrorContains(t, err, tc.err)

				return
			}

			require.NoError(t, err)
			assert.Nil(t, request.NameID)
			assert.Equal(t, tc.content, request.EncryptedID.FindElement("./EncryptedData/EncryptionMethod").SelectAttrValue("Algorithm", ""))

			nameID, err := testElementDecrypter().decryptNameID(reparse(t, request.EncryptedID))
			require.NoError(t, err)
			assert.Equal(t, "alice", nameID.Value)
		})
	}
}

func TestSPDecryptNameID(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)

	_, err := test.SP.DecryptNameID(nil)
	assert.ErrorContains(t, err, "there is no EncryptedID")

	encrypter := &elementEncrypter{certificate: test.SPCertificate, encrypter: testElementEncrypter(t, method(aes128GCM)).encrypter}

	encryptedID, err := encrypter.encryptNameID(&testEncryptedNameID)
	require.NoError(t, err)

	nameID, err := test.SP.DecryptNameID(reparse(t, encryptedID))
	require.NoError(t, err)
	assert.Equal(t, testEncryptedNameID, *nameID)
}
