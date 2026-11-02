package xmlenc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDigestMethodsUseStandardAlgorithmIdentifiers(t *testing.T) {
	assert.Equal(t, "http://www.w3.org/2000/09/xmldsig#sha1", SHA1.Algorithm())
	assert.Equal(t, "http://www.w3.org/2001/04/xmlenc#sha256", SHA256.Algorithm())
	assert.Equal(t, "http://www.w3.org/2001/04/xmlenc#sha512", SHA512.Algorithm())
	assert.Equal(t, "http://www.w3.org/2001/04/xmlenc#ripemd160", RIPEMD160.Algorithm())
}

func TestDecryptDigestIdentifiers(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	for _, tc := range []struct {
		name       string
		digest     DigestMethod
		identifier string
		err        string
	}{
		{"standard sha256", SHA256, "http://www.w3.org/2001/04/xmlenc#sha256", ""},
		{"standard sha512", SHA512, "http://www.w3.org/2001/04/xmlenc#sha512", ""},
		{"standard ripemd160", RIPEMD160, "http://www.w3.org/2001/04/xmlenc#ripemd160", ""},
		{"nonstandard sha256", SHA256, "http://www.w3.org/2000/09/xmldsig#sha256", "algorithm is not implemented"},
		{"nonstandard sha512", SHA512, "http://www.w3.org/2000/09/xmldsig#sha512", "algorithm is not implemented"},
		{"nonstandard ripemd160", RIPEMD160, "http://www.w3.org/2000/09/xmldsig#ripemd160", "algorithm is not implemented"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encrypter := OAEP()
			encrypter.BlockCipher = AES128GCM
			encrypter.DigestMethod = tc.digest
			el, err := encrypter.Encrypt(cert, []byte("plaintext"), nil)
			require.NoError(t, err)

			digestEl := el.FindElement("./KeyInfo/EncryptedKey/EncryptionMethod/DigestMethod")
			require.NotNil(t, digestEl)
			digestEl.SelectAttr("Algorithm").Value = tc.identifier

			plaintext, err := Decrypt(key, el)
			if tc.err != "" {
				assert.ErrorContains(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "plaintext", string(plaintext))
		})
	}
}
