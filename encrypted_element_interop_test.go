package saml

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// xmlsec1Keys returns the path of xmlsec1 and of the negotiation key and its certificate in PEM, or skips the test
// if xmlsec1 isn't installed.
func xmlsec1Keys(t *testing.T) (xmlsec1, keyPath, certPath string) {
	t.Helper()

	xmlsec1, err := exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("xmlsec1 is not installed")
	}

	key, cert := negotiationKey()
	dir := t.TempDir()

	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	keyPath, certPath = filepath.Join(dir, "key.pem"), filepath.Join(dir, "cert.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600))

	return xmlsec1, keyPath, certPath
}

var interopEncryptionMethods = map[string][]EncryptionMethod{
	"aes-128-gcm with oaep mgf1p":         {method(aes128GCM), method(rsaOAEP)},
	"aes-256-gcm with oaep mgf1p sha-256": {method(aes256GCM), oaepMethod(rsaOAEP, digestSHA256, "")},
	"aes-128-cbc with oaep mgf1p":         {method(aes128CBC), method(rsaOAEP)},
	"aes-256-cbc with oaep 1.1 sha-256":   {method(aes256CBC), oaepMethod(rsaOAEP11, digestSHA256, mgf1SHA256)},
	"aes-192-gcm with oaep 1.1 sha-512":   {method(aes192GCM), oaepMethod(rsaOAEP11, digestSHA512, mgf1SHA512)},
}

// What this library encrypts, xmlsec1 decrypts.
func TestXMLSec1DecryptsEncryptedElements(t *testing.T) {
	xmlsec1, keyPath, _ := xmlsec1Keys(t)

	attribute := Attribute{
		Name:       "urn:oid:0.9.2342.19200300.100.1.3",
		NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
		Values:     []AttributeValue{{Type: "xs:string", Value: "alice@example.com"}},
	}

	for name, methods := range interopEncryptionMethods {
		t.Run(name, func(t *testing.T) {
			encrypter := testElementEncrypter(t, methods...)

			encryptedID, err := encrypter.encryptNameID(&testEncryptedNameID)
			require.NoError(t, err)

			encryptedAttribute, err := encrypter.encryptAttribute(&attribute)
			require.NoError(t, err)

			for want, el := range map[string]*etree.Element{">p-1234</saml:NameID>": encryptedID, ">alice@example.com</saml:AttributeValue>": encryptedAttribute} {
				doc := etree.NewDocument()
				doc.SetRoot(el)

				path := filepath.Join(t.TempDir(), "encrypted.xml")
				require.NoError(t, doc.WriteToFile(path))

				out, err := exec.Command(xmlsec1, "--decrypt", "--lax-key-search", "--privkey-pem", keyPath, path).CombinedOutput()
				require.NoError(t, err, "xmlsec1: %s", out)

				// xmlsec1 puts the element in the place of its EncryptedData (SAMLCore §6.1).
				assert.Contains(t, string(out), want)
				assert.False(t, strings.Contains(string(out), "EncryptedData"))
			}
		})
	}
}

// What xmlsec1 encrypts, this library decrypts, with the algorithms an identity provider accepts by default.
func TestDecryptsElementsEncryptedByXMLSec1(t *testing.T) {
	xmlsec1, _, certPath := xmlsec1Keys(t)

	policy, err := (&IdentityProvider{}).encryptionPolicy()
	require.NoError(t, err)

	sessionKeys := map[string]string{aes128GCM: "aes-128", aes192GCM: "aes-192", aes256GCM: "aes-256", aes128CBC: "aes-128", aes256CBC: "aes-256"}

	for name, methods := range interopEncryptionMethods {
		t.Run(name, func(t *testing.T) {
			keyTransport := `<xenc:EncryptionMethod Algorithm="` + methods[1].Algorithm + `">`
			if methods[1].DigestMethod != nil {
				keyTransport += `<ds:DigestMethod Algorithm="` + methods[1].DigestMethod.Algorithm + `"/>`
			}

			if methods[1].MGF != nil {
				keyTransport += `<xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" Algorithm="` + methods[1].MGF.Algorithm + `"/>`
			}

			keyTransport += `</xenc:EncryptionMethod>`

			template := `<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">` +
				`<xenc:EncryptionMethod Algorithm="` + methods[0].Algorithm + `"/>` +
				`<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey>` + keyTransport +
				`<ds:KeyInfo><ds:KeyName>sp</ds:KeyName></ds:KeyInfo><xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>` +
				`<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>`

			dir := t.TempDir()
			templatePath, dataPath := filepath.Join(dir, "template.xml"), filepath.Join(dir, "nameid.xml")
			require.NoError(t, os.WriteFile(templatePath, []byte(template), 0o600))
			require.NoError(t, os.WriteFile(dataPath, []byte(`<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" `+
				`Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" SPNameQualifier="https://sp.example.com/saml2/metadata">p-1234</saml:NameID>`), 0o600))

			out, err := exec.Command(xmlsec1, "--encrypt", "--pubkey-cert-pem:sp", certPath, "--session-key", sessionKeys[methods[0].Algorithm],
				"--xml-data", dataPath, templatePath).CombinedOutput()
			require.NoError(t, err, "xmlsec1: %s", out)

			encrypted := etree.NewDocument()
			require.NoError(t, encrypted.ReadFromBytes(out))

			encryptedID := etree.NewElement("saml:EncryptedID")
			encryptedID.CreateAttr("xmlns:saml", samlAssertionNamespace)
			encryptedID.AddChild(encrypted.Root())

			decrypter := testElementDecrypter()
			decrypter.policy = policy

			nameID, err := decrypter.decryptNameID(reparse(t, encryptedID))
			require.NoError(t, err)
			assert.Equal(t, NameID{
				Format:          string(PersistentNameIDFormat),
				SPNameQualifier: "https://sp.example.com/saml2/metadata",
				Value:           "p-1234",
			}, *nameID)
		})
	}
}
