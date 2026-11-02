package saml

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml/xmlenc"
)

const (
	aes128CBC  = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	aes192CBC  = "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
	aes256CBC  = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
	aes128GCM  = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	aes256GCM  = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	tripleDES  = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
	rsaOAEP    = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	sessionFor = "alice"
)

// encryptedAssertionFor returns the encrypted assertion an IdP makes for the given service provider key descriptors.
func encryptedAssertionFor(t *testing.T, test *IdentityProviderTest, descriptors []KeyDescriptor) *etree.Element {
	t.Helper()
	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	assert.NilError(t, err)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: sessionFor}))
	req.SPSSODescriptor.KeyDescriptors = descriptors
	assert.NilError(t, req.MakeAssertionEl())

	doc := etree.NewDocument()
	doc.SetRoot(req.AssertionEl)
	serialized, err := doc.WriteToBytes()
	assert.NilError(t, err)
	parsed := etree.NewDocument()
	assert.NilError(t, parsed.ReadFromBytes(serialized))
	return parsed.Root()
}

func TestIDPChoosesContentEncryptionFromMetadata(t *testing.T) {
	for _, tc := range []struct {
		name    string
		methods []string
		want    string
	}{
		{"nothing advertised", nil, aes128CBC},
		{"only key transport advertised", []string{rsaOAEP}, aes128CBC},
		{"gcm advertised", []string{aes128GCM, rsaOAEP}, aes128GCM},
		{"gcm preferred", []string{aes128GCM, aes128CBC}, aes128GCM},
		{"cbc preferred over gcm", []string{aes128CBC, aes128GCM}, aes128CBC},
		{"larger cbc preferred", []string{aes256CBC, aes128CBC}, aes256CBC},
		{"aes-192 cbc", []string{aes192CBC}, aes192CBC},
		{"unsupported skipped", []string{aes256GCM, aes128GCM}, aes128GCM},
		{"3des is not chosen", []string{tripleDES, aes128CBC}, aes128CBC},
		{"nothing supported", []string{aes256GCM}, aes128CBC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			descriptor := KeyDescriptor{Use: "encryption"}
			descriptor.KeyInfo.X509Data.X509Certificates = []X509Certificate{{Data: base64Certificate(test)}}
			for _, method := range tc.methods {
				descriptor.EncryptionMethods = append(descriptor.EncryptionMethods, EncryptionMethod{Algorithm: method})
			}

			el := encryptedAssertionFor(t, test, []KeyDescriptor{descriptor})
			encryptedData := el.FindElement("./EncryptedData")
			assert.Assert(t, encryptedData != nil)
			assert.Check(t, is.Equal(tc.want, encryptedData.FindElement("./EncryptionMethod").SelectAttrValue("Algorithm", "")))

			plaintext, err := xmlenc.Decrypt(test.SPKey, encryptedData)
			assert.NilError(t, err)
			assert.Check(t, strings.Contains(string(plaintext), sessionFor))
		})
	}
}

func TestIDPUsesEncryptionMethodsOfKeyItEncryptsTo(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	certificate := []X509Certificate{{Data: base64Certificate(test)}}
	other := KeyDescriptor{Use: "signing", EncryptionMethods: []EncryptionMethod{{Algorithm: aes256CBC}}}
	other.KeyInfo.X509Data.X509Certificates = certificate
	encryption := KeyDescriptor{Use: "encryption", EncryptionMethods: []EncryptionMethod{{Algorithm: aes128GCM}}}
	encryption.KeyInfo.X509Data.X509Certificates = certificate
	unspecified := KeyDescriptor{EncryptionMethods: []EncryptionMethod{{Algorithm: aes256CBC}}}
	unspecified.KeyInfo.X509Data.X509Certificates = certificate

	el := encryptedAssertionFor(t, test, []KeyDescriptor{other, unspecified, encryption})
	assert.Check(t, is.Equal(aes128GCM, el.FindElement("./EncryptedData/EncryptionMethod").SelectAttrValue("Algorithm", "")))
}

func TestSPOfThisLibraryReceivesAndDecryptsGCM(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	sp := ServiceProvider{
		Key:         test.SPKey,
		Certificate: test.SPCertificate,
		MetadataURL: mustParseURL("https://sp.example.com/saml2/metadata"),
		AcsURL:      mustParseURL("https://sp.example.com/saml2/acs"),
	}
	metadata := sp.Metadata()

	el := encryptedAssertionFor(t, test, metadata.SPSSODescriptors[0].KeyDescriptors)
	assert.Check(t, is.Equal(aes128GCM, el.FindElement("./EncryptedData/EncryptionMethod").SelectAttrValue("Algorithm", "")))

	assertion, err := sp.decryptElement(el)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(sessionFor, assertion.FindElement("./Subject/NameID").Text()))
}

func base64Certificate(test *IdentityProviderTest) string {
	return base64.StdEncoding.EncodeToString(test.SPCertificate.Raw)
}
