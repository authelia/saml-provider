package xmlenc

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// xmlsec1ECDHOptions are the options of xmlsec1 for ECDH-ES, which it only reads from key data that is enabled, and
// which nests an AgreementMethod one level below the EncryptedKey that it is in.
var xmlsec1ECDHOptions = []string{"--enabled-key-data", "agreement-method,enc-key,key-value,key-name,ec,x509", "--max-encrypted-key-level", "3"}

// xmlsec1Path returns the path of xmlsec1, or skips the test if it isn't installed.
func xmlsec1Path(t *testing.T) string {
	t.Helper()

	xmlsec1, err := exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("xmlsec1 is not installed")
	}

	return xmlsec1
}

// writePEM writes a PEM block of der to a file named name in dir, and returns its path.
func writePEM(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()

	path := filepath.Join(dir, name)
	assert.NilError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600))

	return path
}

// What ECDHES encrypts, xmlsec1 decrypts, on every curve and with every key wrap.
func TestXMLSec1DecryptsECDHES(t *testing.T) {
	xmlsec1 := xmlsec1Path(t)

	RandReader = rand.Reader

	for name, curve := range map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()} {
		for _, wrap := range []AESKeyWrap{AES128KW, AES192KW, AES256KW} {
			for _, cipher := range []BlockCipher{AES128GCM, AES256CBC} {
				t.Run(name+" "+wrap.Algorithm()+" "+cipher.Algorithm(), func(t *testing.T) {
					key, cert := ecTestCertificate(t, curve)

					der, err := x509.MarshalPKCS8PrivateKey(key)
					assert.NilError(t, err)

					dir := t.TempDir()
					keyPath := writePEM(t, dir, "key.pem", "PRIVATE KEY", der)
					certPath := writePEM(t, dir, "cert.pem", "CERTIFICATE", cert.Raw)

					el, err := ECDHES{BlockCipher: cipher, KeyWrap: wrap}.Encrypt(cert, []byte(`<secret xmlns="urn:example">alice</secret>`), nil)
					assert.NilError(t, err)

					el.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")

					root := etree.NewElement("root")
					root.AddChild(el)

					doc := etree.NewDocument()
					doc.SetRoot(root)

					path := filepath.Join(dir, "encrypted.xml")
					assert.NilError(t, doc.WriteToFile(path))

					args := append([]string{"--decrypt"}, xmlsec1ECDHOptions...)
					args = append(args, "--lax-key-search", "--privkey-pem", keyPath+","+certPath, path)

					out, err := exec.Command(xmlsec1, args...).CombinedOutput()
					assert.NilError(t, err, "xmlsec1: %s", out)
					assert.Check(t, is.Contains(string(out), `>alice</secret>`))
					assert.Check(t, !strings.Contains(string(out), "EncryptedData"))
				})
			}
		}
	}
}

// xmlsec1ECDHTemplate is what xmlsec1 fills in to encrypt with ECDH-ES, with parameters of ConcatKDF that aren't
// empty, so that both read them the same way. The originator and the recipient are keys that xmlsec1 has loaded
// under those names, and it writes the ECKeyValue of the originator.
const xmlsec1ECDHTemplate = `<root><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
	xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" Type="http://www.w3.org/2001/04/xmlenc#Element">
<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
<ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes128"/>
<ds:KeyInfo><xenc:AgreementMethod Algorithm="http://www.w3.org/2009/xmlenc11#ECDH-ES">
<xenc11:KeyDerivationMethod Algorithm="http://www.w3.org/2009/xmlenc11#ConcatKDF">
<xenc11:ConcatKDFParams AlgorithmID="00ABCD" PartyUInfo="0001" PartyVInfo="00">
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></xenc11:ConcatKDFParams></xenc11:KeyDerivationMethod>
<xenc:OriginatorKeyInfo><ds:KeyName>originator</ds:KeyName><ds:KeyValue/></xenc:OriginatorKeyInfo>
<xenc:RecipientKeyInfo><ds:KeyName>recipient</ds:KeyName></xenc:RecipientKeyInfo>
</xenc:AgreementMethod></ds:KeyInfo><xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>
<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData></root>`

// What xmlsec1 encrypts with ECDH-ES, Decrypt decrypts with the private key of the recipient.
func TestDecryptsECDHESOfXMLSec1(t *testing.T) {
	xmlsec1 := xmlsec1Path(t)

	recipient, _ := ecTestCertificate(t, elliptic.P256())
	originator, _ := ecTestCertificate(t, elliptic.P256())

	originatorDER, err := x509.MarshalPKCS8PrivateKey(originator)
	assert.NilError(t, err)

	recipientDER, err := x509.MarshalPKIXPublicKey(&recipient.PublicKey)
	assert.NilError(t, err)

	dir := t.TempDir()
	originatorPath := writePEM(t, dir, "originator.pem", "PRIVATE KEY", originatorDER)
	recipientPath := writePEM(t, dir, "recipient.pem", "PUBLIC KEY", recipientDER)

	templatePath, dataPath, outPath := filepath.Join(dir, "template.xml"), filepath.Join(dir, "data.xml"), filepath.Join(dir, "out.xml")
	assert.NilError(t, os.WriteFile(templatePath, []byte(xmlsec1ECDHTemplate), 0o600))
	assert.NilError(t, os.WriteFile(dataPath, []byte(`<secret xmlns="urn:example">bob</secret>`), 0o600))

	args := append([]string{"--encrypt"}, xmlsec1ECDHOptions...)
	args = append(args, "--session-key", "aes-128", "--privkey-pem:originator", originatorPath,
		"--pubkey-pem:recipient", recipientPath, "--xml-data", dataPath, "--output", outPath, templatePath)

	out, err := exec.Command(xmlsec1, args...).CombinedOutput()
	assert.NilError(t, err, "xmlsec1: %s", out)

	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromFile(outPath))

	encryptedData := doc.FindElement("//EncryptedData")
	assert.Assert(t, encryptedData != nil)

	plaintext, err := Decrypt(recipient, encryptedData)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(string(plaintext), `<secret xmlns="urn:example">bob</secret>`))

	// The ConcatKDF parameters are part of the key: one that is changed derives another.
	encryptedData.FindElement(".//ConcatKDFParams").CreateAttr("PartyUInfo", "00")

	_, err = Decrypt(recipient, encryptedData)
	assert.Check(t, is.ErrorContains(err, "integrity"))
}
