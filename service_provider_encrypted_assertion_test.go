package saml

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml/xmlenc"
)

// An EncryptedAssertion is decrypted before its signature can be checked, so anyone who has started a
// login, which gives them a request ID, can present a short ciphertext by encrypting to the public
// certificate of the service provider.
func TestSPRejectsForgedShortGCMCiphertextWithoutPanic(t *testing.T) {
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
	encrypter.BlockCipher = xmlenc.AES128GCM
	encrypter.DigestMethod = &xmlenc.SHA1
	encryptedData, err := encrypter.Encrypt(test.Certificate, []byte("<a/>"), nil)
	assert.NilError(t, err)
	encryptedData.FindElement("./CipherData/CipherValue").SetText("AAAA")

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
	status := response.CreateElement("samlp:Status").CreateElement("samlp:StatusCode")
	status.CreateAttr("Value", StatusSuccess)
	response.CreateElement("saml:EncryptedAssertion").AddChild(encryptedData)
	serialized, err := doc.WriteToBytes()
	assert.NilError(t, err)

	_, err = sp.ParseXMLResponse(serialized, []string{"id-1"}, sp.AcsURL)
	assert.Assert(t, err != nil)
	assert.Check(t, is.ErrorContains(err.(*InvalidResponseError).PrivateErr, "ciphertext too short"))
}
