package saml

import (
	"encoding/base64"
	"encoding/xml"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"

	"authelia.com/provider/saml/xmlenc"
)

// An EncryptedAssertion is decrypted before its signature can be checked, so anyone who has started a
// login can present these by encrypting to the public certificate of the service provider.
func TestSPRejectsForgedCBCCiphertextWithoutPanic(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cipher xmlenc.BlockCipher
		size   int
	}{
		{"aes-128 partial block", xmlenc.AES128CBC, 17},
		{"aes-256 partial block", xmlenc.AES256CBC, 33},
		{"3des partial block", xmlenc.TripleDES, 12},
		{"3des shorter than an aes block", xmlenc.TripleDES, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := NewServiceProviderTest(t)
			sp := ServiceProvider{
				Key:         test.Key,
				Certificate: test.Certificate,
				MetadataURL: mustParseURL("https://sp.example.com/saml2/metadata"),
				AcsURL:      mustParseURL("https://sp.example.com/saml2/acs"),
				IDPMetadata: &EntityDescriptor{},
			}
			assert.NilError(t, xml.Unmarshal(test.IDPMetadata, sp.IDPMetadata))

			encrypter := xmlenc.OAEP()
			encrypter.BlockCipher = tc.cipher
			encrypter.DigestMethod = &xmlenc.SHA1
			encryptedData, err := encrypter.Encrypt(test.Certificate, []byte("<a/>"), nil)
			assert.NilError(t, err)
			encryptedData.FindElement("./CipherData/CipherValue").SetText(base64.StdEncoding.EncodeToString(make([]byte, tc.size)))

			doc := etree.NewDocument()
			response := doc.CreateElement("samlp:Response")
			response.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
			response.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
			response.CreateAttr("ID", "id-forged")
			response.CreateAttr("InResponseTo", "id-1")
			response.CreateAttr("Version", "2.0")
			response.CreateAttr("IssueInstant", TimeNow().UTC().Format(time.RFC3339))
			response.CreateAttr("Destination", sp.AcsURL.String())
			response.CreateElement("saml:Issuer").SetText(sp.IDPMetadata.EntityID)
			response.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", StatusSuccess)
			response.CreateElement("saml:EncryptedAssertion").AddChild(encryptedData)
			serialized, err := doc.WriteToBytes()
			assert.NilError(t, err)

			_, err = sp.ParseXMLResponse(serialized, []string{"id-1"}, sp.AcsURL)
			assert.Assert(t, err != nil)
		})
	}
}
