package saml

import (
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encryptQuerySubject replaces the NameID of the Subject of message with an EncryptedID of nameID, made by
// encrypter.
func encryptQuerySubject(t *testing.T, encrypter *elementEncrypter, message *etree.Element, nameID *NameID) {
	t.Helper()

	encryptedID, err := encrypter.encryptNameID(nameID)
	require.NoError(t, err)

	subject := message.FindElement("./Subject")
	require.NotNil(t, subject)

	if el := subject.FindElement("./NameID"); el != nil {
		subject.RemoveChild(el)
	}

	subject.InsertChildAt(0, encryptedID)
}

// withoutEncryptionKey removes the encryption keys of the service provider from its metadata, after edit.
func withoutEncryptionKey(edit func(*EntityDescriptor)) func(*EntityDescriptor) {
	return func(metadata *EntityDescriptor) {
		if edit != nil {
			edit(metadata)
		}

		descriptor := &metadata.SPSSODescriptors[0]

		signing := descriptor.KeyDescriptors[:0]
		for _, keyDescriptor := range descriptor.KeyDescriptors {
			if keyDescriptor.Use == "signing" {
				signing = append(signing, keyDescriptor)
			}
		}

		descriptor.KeyDescriptors = signing
	}
}

func TestServeQueryEncryptedID(t *testing.T) {
	for _, service := range queryServices[:2] {
		t.Run(service.name, func(t *testing.T) {
			f := newQueryFixture(t)
			f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))

			nameID := f.subject().NameID
			message := service.message(f)
			encryptQuerySubject(t, idpEncrypter(t, f.test), message, nameID)
			assert.False(t, strings.Contains(elementToString(message), queryTestPersistentNameID))

			response := f.query(t, service, message)
			assertQueryStatus(t, response, StatusSuccess, "")
			require.Len(t, response.Assertions, 1)
			assert.Equal(t, response.Encrypted, 1)

			// The provider is asked about the identifier that was encrypted.
			assert.Equal(t, f.provider.nameIDs, []NameID{*nameID})

			// The assertion names the principal as the query did, with an EncryptedID, which is encrypted to the
			// service provider (SAMLCore §3.3.4).
			subjectEl := response.AssertionEls[0].FindElement("./Subject")
			require.NotNil(t, subjectEl)
			assert.Nil(t, subjectEl.FindElement("./NameID"))

			encryptedID := subjectEl.FindElement("./EncryptedID")
			require.NotNil(t, encryptedID)

			decrypted, err := f.test.SP.DecryptNameID(encryptedID)
			require.NoError(t, err)
			assert.Equal(t, *decrypted, *nameID)
		})
	}
}

// An EncryptedID that names nobody the service provider shares an identifier with is answered as a principal that
// is not found, whatever is wrong with it, so that the answer says nothing of what it held (errata E93).
func TestServeQueryUnidentifiedEncryptedID(t *testing.T) {
	cases := []struct {
		name    string
		encrypt func(*queryFixture, *testing.T, *etree.Element)
		reason  string
	}{
		{
			name: "encrypted to another key",
			encrypt: func(f *queryFixture, t *testing.T, message *etree.Element) {
				encryptQuerySubject(t, otherKeyEncrypter(t, f.test), message, f.subject().NameID)
			},
			reason: "cannot decrypt the EncryptedID",
		},
		{
			name: "SPNameQualifier of another service provider",
			encrypt: func(f *queryFixture, t *testing.T, message *etree.Element) {
				nameID := f.subject().NameID
				nameID.SPNameQualifier = queryTestOtherProviderID

				encryptQuerySubject(t, idpEncrypter(t, f.test), message, nameID)
			},
			reason: "SPNameQualifier of another service provider",
		},
		{
			name: "NameQualifier of another identity provider",
			encrypt: func(f *queryFixture, t *testing.T, message *etree.Element) {
				nameID := f.subject().NameID
				nameID.NameQualifier = queryTestOtherProviderID

				encryptQuerySubject(t, idpEncrypter(t, f.test), message, nameID)
			},
			reason: "NameQualifier of another identity provider",
		},
		{
			name: "encrypted format",
			encrypt: func(f *queryFixture, t *testing.T, message *etree.Element) {
				nameID := f.subject().NameID
				nameID.Format = string(EncryptedNameIDFormat)

				encryptQuerySubject(t, idpEncrypter(t, f.test), message, nameID)
			},
			reason: "encrypted format",
		},
	}

	for _, service := range queryServices[:2] {
		for _, tc := range cases {
			t.Run(service.name+"/"+tc.name, func(t *testing.T) {
				f := newQueryFixture(t)
				f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))

				message := service.message(f)
				tc.encrypt(f, t, message)

				response := f.query(t, service, message)
				assertQueryStatus(t, response, StatusSuccess, "")
				assert.Len(t, response.Assertions, 0)
				assert.Len(t, f.provider.nameIDs, 0, "the session provider must not be asked")

				log := f.log.String()
				assert.Contains(t, log, string(EventPrincipalUnidentified))
				assert.Contains(t, log, tc.reason)
			})
		}
	}
}

// An EncryptedID can't be answered to a service provider with no encryption key without sending the identifier in
// plaintext, so it is refused before it is decrypted.
func TestServeQueryEncryptedIDWithoutEncryptionKey(t *testing.T) {
	for _, service := range queryServices[:2] {
		t.Run(service.name, func(t *testing.T) {
			f := newQueryFixture(t)
			f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))
			f.metadata = withoutEncryptionKey(f.metadata)

			message := service.message(f)
			encryptQuerySubject(t, idpEncrypter(t, f.test), message, f.subject().NameID)

			response := f.query(t, service, message)
			assertQueryStatus(t, response, StatusRequester, StatusRequestUnsupported)
			assert.Len(t, f.provider.nameIDs, 0)
			assert.False(t, strings.Contains(f.log.String(), string(EventPrincipalUnidentified)))
		})
	}
}
