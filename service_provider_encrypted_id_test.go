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
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestSPRequestsEncryptedNameID(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.SP.AuthnNameIDFormat = PersistentNameIDFormat

	request, err := test.SP.MakeAuthenticationRequest("https://idp.example.com/saml/sso", HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(string(PersistentNameIDFormat), *request.NameIDPolicy.Format))

	test.SP.EncryptNameID = true

	request, err = test.SP.MakeAuthenticationRequest("https://idp.example.com/saml/sso", HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted", *request.NameIDPolicy.Format))

	// Errata E6: the request can't say which kind of identifier to encrypt, and the metadata may.
	assert.Check(t, is.DeepEqual([]NameIDFormat{PersistentNameIDFormat}, test.SP.Metadata().SPSSODescriptors[0].NameIDFormats))
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
	assert.NilError(t, err)

	req.Request.NameIDPolicy = request.NameIDPolicy

	assertion, err := test.SP.ParseXMLResponse([]byte(respond(t, req)), []string{"id-request"}, test.SP.AcsURL)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(string(EmailAddressNameIDFormat), assertion.Subject.NameID.Format))
	assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
	assert.Check(t, req.nameIDEncrypted)
}

func TestSPMakesLogoutRequestWithEncryptedID(t *testing.T) {
	test, _ := logoutTestIDP(t)
	test.SP.EncryptNameID = true
	test.SP.AuthnNameIDFormat = PersistentNameIDFormat

	decrypter, err := test.IDP.elementDecrypter()
	assert.NilError(t, err)

	check := func(t *testing.T, el *etree.Element) {
		t.Helper()

		assert.Check(t, el.FindElement("./NameID") == nil)
		assert.Check(t, !strings.Contains(elementToString(el), "alice"))

		encryptedID, err := findOneChild(el, samlAssertionNamespace, "EncryptedID")
		assert.NilError(t, err)

		// The identity provider of this library lists AES-128-GCM first (SAMLProfiles §4.4.5).
		assert.Check(t, is.Equal(aes128GCM, encryptedID.FindElement("./EncryptedData/EncryptionMethod").SelectAttrValue("Algorithm", "")))
		assert.Check(t, is.Equal(test.IDP.Metadata().EntityID, encryptedID.FindElement("./EncryptedData/KeyInfo/EncryptedKey").SelectAttrValue("Recipient", "")))

		nameID, err := decrypter.decryptNameID(encryptedID)
		assert.NilError(t, err)
		assert.Check(t, is.DeepEqual(NameID{
			Format:          string(PersistentNameIDFormat),
			NameQualifier:   test.IDP.Metadata().EntityID,
			SPNameQualifier: test.SP.MetadataURL.String(),
			Value:           "alice",
		}, *nameID))
	}

	t.Run("signed", func(t *testing.T) {
		request, err := test.SP.MakeLogoutRequest(logoutTestSLOURL, "alice")
		assert.NilError(t, err)
		assert.Check(t, request.NameID == nil)

		// SAMLCore §6.2: the signature is calculated over the message which contains the EncryptedID.
		certificates, err := serviceProviderSigningCertificates(test.SP.Metadata())
		assert.NilError(t, err)

		verified, err := verifyEnvelopedSignature(reparse(t, request.Element()), certificates, anySignaturePolicy)
		assert.NilError(t, err)
		check(t, verified)
	})

	t.Run("post", func(t *testing.T) {
		form, err := test.SP.MakePostLogoutRequest("alice", "relay")
		assert.NilError(t, err)

		const marker = `name="SAMLRequest" value="`

		_, rest, found := strings.Cut(string(form), marker)
		assert.Assert(t, found)

		encoded, _, _ := strings.Cut(rest, `"`)
		buf, err := base64.StdEncoding.DecodeString(html.UnescapeString(encoded))
		assert.NilError(t, err)

		doc := etree.NewDocument()
		assert.NilError(t, doc.ReadFromBytes(buf))
		check(t, doc.Root())
	})

	t.Run("redirect", func(t *testing.T) {
		u, err := test.SP.MakeRedirectLogoutRequest("alice", "relay")
		assert.NilError(t, err)

		compressed, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
		assert.NilError(t, err)

		buf, err := io.ReadAll(flate.NewReader(bytes.NewReader(compressed)))
		assert.NilError(t, err)

		doc := etree.NewDocument()
		assert.NilError(t, doc.ReadFromBytes(buf))
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
	_, ecdsaCertificate := newECDSATestKey(t, elliptic.P256())

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
			`the identity provider "https://idp.example.com" has no RSA encryption key in its metadata`, "",
		},
		// Only RSA key transport is supported, so an ECDSA key is never encrypted to.
		"ecdsa key": {
			&EntityDescriptor{EntityID: "https://idp.example.com", IDPSSODescriptors: []IDPSSODescriptor{{SSODescriptor: SSODescriptor{RoleDescriptor: RoleDescriptor{
				KeyDescriptors: []KeyDescriptor{keyDescriptor("encryption", ecdsaCertificate.Raw), keyDescriptor("", ecdsaCertificate.Raw)},
			}}}}},
			"has no RSA encryption key in its metadata", "",
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
			"", aes128CBC,
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
				assert.Check(t, is.ErrorContains(err, tc.err))

				return
			}

			request, err := test.SP.MakeLogoutRequest("https://idp.example.com/slo", "alice")
			if tc.err != "" {
				assert.Check(t, request == nil)
				assert.Check(t, is.ErrorContains(err, tc.err))

				return
			}

			assert.NilError(t, err)
			assert.Check(t, request.NameID == nil)
			assert.Check(t, is.Equal(tc.content, request.EncryptedID.FindElement("./EncryptedData/EncryptionMethod").SelectAttrValue("Algorithm", "")))

			nameID, err := testElementDecrypter().decryptNameID(reparse(t, request.EncryptedID))
			assert.NilError(t, err)
			assert.Check(t, is.Equal("alice", nameID.Value))
		})
	}
}

func TestSPDecryptNameID(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)

	_, err := test.SP.DecryptNameID(nil)
	assert.Check(t, is.ErrorContains(err, "there is no EncryptedID"))

	encrypter := &elementEncrypter{certificate: test.SPCertificate, encrypter: testElementEncrypter(t, method(aes128GCM)).encrypter}

	encryptedID, err := encrypter.encryptNameID(&testEncryptedNameID)
	assert.NilError(t, err)

	nameID, err := test.SP.DecryptNameID(reparse(t, encryptedID))
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(testEncryptedNameID, *nameID))
}
