package xmlenc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// A bare RSA key is encrypted to like one in a certificate, and the EncryptedKey identifies it by its KeyValue
// (XML Signature §4.4.2.2), as there is no certificate to identify it by.
func TestRSAEncryptToBarePublicKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)

	for name, encrypter := range map[string]RSA{"RSA-OAEP-MGF1P": OAEP(), "RSA-OAEP": OAEP_SHA256()} {
		t.Run(name, func(t *testing.T) {
			el, err := encrypter.Encrypt(&key.PublicKey, []byte("<plaintext/>"), nil)
			assert.NilError(t, err)

			// It is parsed again, as the receiver finds it.
			doc := etree.NewDocument()
			doc.SetRoot(el)

			buf, err := doc.WriteToBytes()
			assert.NilError(t, err)

			doc = etree.NewDocument()
			assert.NilError(t, doc.ReadFromBytes(buf))

			keyInfo := doc.Root().FindElement("./KeyInfo/EncryptedKey/KeyInfo")
			assert.Assert(t, keyInfo != nil)
			assert.Check(t, keyInfo.FindElement("./X509Data") == nil)
			assert.Check(t, is.Len(keyInfo.ChildElements(), 1))

			rsaKeyValue := keyInfo.FindElement("./KeyValue/RSAKeyValue")
			assert.Assert(t, rsaKeyValue != nil)
			assert.Check(t, is.Equal(rsaKeyValue.NamespaceURI(), "http://www.w3.org/2000/09/xmldsig#"))

			modulus, err := base64.StdEncoding.DecodeString(rsaKeyValue.FindElement("./Modulus").Text())
			assert.NilError(t, err)
			assert.Check(t, is.Equal(new(big.Int).SetBytes(modulus).Cmp(key.N), 0))

			// ds:CryptoBinary has no leading zero octet.
			assert.Check(t, modulus[0] != 0)
			assert.Check(t, is.Equal(rsaKeyValue.FindElement("./Exponent").Text(), "AQAB"))

			plaintext, err := Decrypt(key, doc.Root())
			assert.NilError(t, err)
			assert.Check(t, is.Equal(string(plaintext), "<plaintext/>"))
		})
	}
}

func TestRSAEncryptRejectsOtherKeys(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NilError(t, err)

	for name, key := range map[string]any{
		"nil":                        nil,
		"nil certificate":            (*x509.Certificate)(nil),
		"nil RSA key":                (*rsa.PublicKey)(nil),
		"RSA key with no modulus":    &rsa.PublicKey{E: 65537},
		"EC key":                     &ecKey.PublicKey,
		"certificate with no key":    &x509.Certificate{},
		"certificate with EC key":    &x509.Certificate{PublicKey: &ecKey.PublicKey},
		"RSA key that is no pointer": rsa.PublicKey{N: big.NewInt(3233), E: 17},
	} {
		t.Run(name, func(t *testing.T) {
			el, err := OAEP().Encrypt(key, []byte("<plaintext/>"), nil)

			var incorrect ErrIncorrectKeyType

			assert.Check(t, errors.As(err, &incorrect), "err=%v", err)
			assert.Check(t, el == nil)
		})
	}
}
