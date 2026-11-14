package xmlenc

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"
)

// encryptedKeyCiphertext returns the RSA ciphertext of the EncryptedKey of an EncryptedData element.
func encryptedKeyCiphertext(t *testing.T, el *etree.Element) []byte {
	t.Helper()
	value := el.FindElement("./KeyInfo/EncryptedKey/CipherData/CipherValue")
	assert.Assert(t, value != nil)
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value.Text()))
	assert.NilError(t, err)
	return ciphertext
}

func TestGCMKeySizes(t *testing.T) {
	for _, tc := range []struct {
		cipher    BlockCipher
		keySize   int
		algorithm string
	}{
		{AES128GCM, 16, "http://www.w3.org/2009/xmlenc11#aes128-gcm"},
		{AES192GCM, 24, "http://www.w3.org/2009/xmlenc11#aes192-gcm"},
		{AES256GCM, 32, "http://www.w3.org/2009/xmlenc11#aes256-gcm"},
	} {
		t.Run(tc.algorithm, func(t *testing.T) {
			assert.Check(t, is.Equal(tc.keySize, tc.cipher.KeySize()))
			assert.Check(t, is.Equal(tc.algorithm, tc.cipher.Algorithm()))

			key, cert := newDigestTestKey(t)
			encrypter := OAEP()
			encrypter.BlockCipher = tc.cipher
			el, err := encrypter.Encrypt(cert, []byte("plaintext"), nil)
			assert.NilError(t, err)
			assert.Check(t, is.Equal(tc.algorithm, el.FindElement("./EncryptionMethod").SelectAttrValue("Algorithm", "")))

			// The default registry decrypts every GCM key size.
			plaintext, err := Decrypt(key, el)
			assert.NilError(t, err)
			assert.Check(t, is.Equal("plaintext", string(plaintext)))
		})
	}
}

func TestOAEPMGF1PAlwaysMasksWithSHA1(t *testing.T) {
	key, cert := newDigestTestKey(t)
	for _, tc := range []struct {
		digest DigestMethod
		hash   crypto.Hash
	}{
		{SHA1, crypto.SHA1},
		{SHA256, crypto.SHA256},
		{SHA512, crypto.SHA512},
	} {
		t.Run(tc.digest.Algorithm(), func(t *testing.T) {
			encrypter := OAEP()
			encrypter.BlockCipher = AES128CBC
			encrypter.DigestMethod = tc.digest
			encrypter.MGFHash = crypto.SHA512 // ignored, as RSA-OAEP-MGF1P fixes MGF1 with SHA-1
			el, err := encrypter.Encrypt(cert, []byte("plaintext"), nil)
			assert.NilError(t, err)
			assert.Check(t, el.FindElement("./KeyInfo/EncryptedKey/EncryptionMethod/MGF") == nil)

			// XML Encryption §5.4.2 fixes the mask generation function of RSA-OAEP-MGF1P to MGF1 with SHA-1,
			// whatever the digest.
			_, err = key.Decrypt(nil, encryptedKeyCiphertext(t, el), &rsa.OAEPOptions{Hash: tc.hash, MGFHash: crypto.SHA1})
			assert.NilError(t, err)

			plaintext, err := Decrypt(key, el)
			assert.NilError(t, err)
			assert.Check(t, is.Equal("plaintext", string(plaintext)))
		})
	}
}

func TestOAEP11RoundTrip(t *testing.T) {
	key, cert := newDigestTestKey(t)
	for _, digest := range []struct {
		method DigestMethod
		hash   crypto.Hash
	}{
		{nil, crypto.SHA1},
		{SHA1, crypto.SHA1},
		{SHA256, crypto.SHA256},
		{SHA512, crypto.SHA512},
	} {
		for _, mgf := range []struct {
			hash      crypto.Hash
			want      crypto.Hash
			algorithm string
		}{
			{0, crypto.SHA1, "http://www.w3.org/2009/xmlenc11#mgf1sha1"},
			{crypto.SHA1, crypto.SHA1, "http://www.w3.org/2009/xmlenc11#mgf1sha1"},
			{crypto.SHA224, crypto.SHA224, "http://www.w3.org/2009/xmlenc11#mgf1sha224"},
			{crypto.SHA256, crypto.SHA256, "http://www.w3.org/2009/xmlenc11#mgf1sha256"},
			{crypto.SHA384, crypto.SHA384, "http://www.w3.org/2009/xmlenc11#mgf1sha384"},
			{crypto.SHA512, crypto.SHA512, "http://www.w3.org/2009/xmlenc11#mgf1sha512"},
		} {
			t.Run(digest.hash.String()+"/"+mgf.algorithm, func(t *testing.T) {
				encrypter := OAEP_SHA256()
				encrypter.BlockCipher = AES256GCM
				encrypter.DigestMethod = digest.method
				encrypter.MGFHash = mgf.hash
				el, err := encrypter.Encrypt(cert, []byte("plaintext"), nil)
				assert.NilError(t, err)

				method := el.FindElement("./KeyInfo/EncryptedKey/EncryptionMethod")
				assert.Check(t, is.Equal("http://www.w3.org/2009/xmlenc11#rsa-oaep", method.SelectAttrValue("Algorithm", "")))
				mgfEl := method.FindElement("./MGF")
				assert.Assert(t, mgfEl != nil)
				assert.Check(t, is.Equal("http://www.w3.org/2009/xmlenc11#", mgfEl.NamespaceURI()))
				assert.Check(t, is.Equal(mgf.algorithm, mgfEl.SelectAttrValue("Algorithm", "")))

				_, err = key.Decrypt(nil, encryptedKeyCiphertext(t, el), &rsa.OAEPOptions{Hash: digest.hash, MGFHash: mgf.want})
				assert.NilError(t, err)

				// Serialise and parse so that namespaces are resolved as a receiver would see them.
				doc := etree.NewDocument()
				doc.SetRoot(el)
				buf, err := doc.WriteToBytes()
				assert.NilError(t, err)
				parsed := etree.NewDocument()
				assert.NilError(t, parsed.ReadFromBytes(buf))

				plaintext, err := Decrypt(key, parsed.Root())
				assert.NilError(t, err)
				assert.Check(t, is.Equal("plaintext", string(plaintext)))
			})
		}
	}
}

func TestOAEPConstructorsMaskAsTheyDeclare(t *testing.T) {
	assert.Check(t, is.Equal(crypto.SHA256, OAEP_SHA256().MGFHash))
	assert.Check(t, is.Equal(crypto.SHA512, OAEP_SHA512().MGFHash))
}

func TestOAEP11DecryptRejectsAnUnknownMaskGenerationFunction(t *testing.T) {
	key, cert := newDigestTestKey(t)
	encrypter := OAEP_SHA256()
	encrypter.BlockCipher = AES128CBC
	el, err := encrypter.Encrypt(cert, []byte("plaintext"), nil)
	assert.NilError(t, err)
	el.FindElement("./KeyInfo/EncryptedKey/EncryptionMethod/MGF").SelectAttr("Algorithm").Value = "http://www.w3.org/2009/xmlenc11#mgf1md5"

	_, err = Decrypt(key, el)
	assert.Check(t, is.ErrorContains(err, "algorithm is not implemented: http://www.w3.org/2009/xmlenc11#mgf1md5"))
}

func TestOAEPEncryptRejectsAMaskHashWithNoIdentifier(t *testing.T) {
	_, cert := newDigestTestKey(t)
	encrypter := OAEP_SHA256()
	encrypter.MGFHash = crypto.MD5
	_, err := encrypter.Encrypt(cert, []byte("plaintext"), nil)
	assert.Check(t, is.ErrorContains(err, "MGF1"))
}

func TestOAEPDecryptsXMLSec1Ciphertexts(t *testing.T) {
	block, _ := pem.Decode(golden.Get(t, "xmlsec1-rsa2048.key"))
	assert.Assert(t, block != nil)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	assert.NilError(t, err)

	// These were made by xmlsec1 1.3.13 (OpenSSL), an independent implementation of XML Encryption.
	for _, name := range []string{
		"xmlsec1-mgf1p-sha256-aes256gcm.xml",
		"xmlsec1-oaep11-sha256-mgf1sha512-aes192gcm.xml",
		"xmlsec1-oaep11-defaults-aes128cbc.xml",
	} {
		t.Run(name, func(t *testing.T) {
			doc := etree.NewDocument()
			assert.NilError(t, doc.ReadFromBytes(golden.Get(t, name)))
			el := doc.FindElement("//EncryptedData")
			assert.Assert(t, el != nil)

			plaintext, err := Decrypt(key, el)
			assert.NilError(t, err)
			assert.Check(t, is.Equal("<secret>hello</secret>", string(plaintext)))
		})
	}
}
