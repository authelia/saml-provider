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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A bare RSA key is encrypted to like one in a certificate, and the EncryptedKey identifies it by its KeyValue
// (XML Signature §4.4.2.2), as there is no certificate to identify it by.
func TestRSAEncryptToBarePublicKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for name, encrypter := range map[string]RSA{"RSA-OAEP-MGF1P": OAEP(), "RSA-OAEP": OAEP_SHA256()} {
		t.Run(name, func(t *testing.T) {
			el, err := encrypter.Encrypt(&key.PublicKey, []byte("<plaintext/>"), nil)
			require.NoError(t, err)

			// It is parsed again, as the receiver finds it.
			doc := etree.NewDocument()
			doc.SetRoot(el)

			buf, err := doc.WriteToBytes()
			require.NoError(t, err)

			doc = etree.NewDocument()
			require.NoError(t, doc.ReadFromBytes(buf))

			keyInfo := doc.Root().FindElement("./KeyInfo/EncryptedKey/KeyInfo")
			require.NotNil(t, keyInfo)
			assert.Nil(t, keyInfo.FindElement("./X509Data"))
			assert.Len(t, keyInfo.ChildElements(), 1)

			rsaKeyValue := keyInfo.FindElement("./KeyValue/RSAKeyValue")
			require.NotNil(t, rsaKeyValue)
			assert.Equal(t, rsaKeyValue.NamespaceURI(), "http://www.w3.org/2000/09/xmldsig#")

			modulus, err := base64.StdEncoding.DecodeString(rsaKeyValue.FindElement("./Modulus").Text())
			require.NoError(t, err)
			assert.Equal(t, new(big.Int).SetBytes(modulus).Cmp(key.N), 0)

			// ds:CryptoBinary has no leading zero octet.
			assert.True(t, modulus[0] != 0)
			assert.Equal(t, rsaKeyValue.FindElement("./Exponent").Text(), "AQAB")

			plaintext, err := Decrypt(key, doc.Root())
			require.NoError(t, err)
			assert.Equal(t, string(plaintext), "<plaintext/>")
		})
	}
}

func TestRSAEncryptRejectsOtherKeys(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

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

			assert.True(t, errors.As(err, &incorrect), "err=%v", err)
			assert.Nil(t, el)
		})
	}
}
