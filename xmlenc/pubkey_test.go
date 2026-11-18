package xmlenc

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/golden"
)

func TestPKCS1v15DecryptRequiresOptIn(t *testing.T) {
	testCases := []struct {
		name     string
		register bool
		err      string
	}{
		{
			name:     "default",
			register: false,
			err:      "algorithm is not implemented: http://www.w3.org/2001/04/xmlenc#rsa-1_5",
		},
		{
			name:     "registered",
			register: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.register {
				RegisterDecrypter(PKCS1v15())
				t.Cleanup(func() {
					delete(decrypters, PKCS1v15().Algorithm())
				})
			}

			certBlock, _ := pem.Decode(golden.Get(t, "cert.cert"))
			certificate, err := x509.ParseCertificate(certBlock.Bytes)
			require.NoError(t, err)

			keyBlock, _ := pem.Decode(golden.Get(t, "cert.key"))
			key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
			require.NoError(t, err)

			plaintext := golden.Get(t, "plaintext.xml")
			el, err := PKCS1v15().Encrypt(certificate, plaintext, nil)
			require.NoError(t, err)

			doc := etree.NewDocument()
			doc.SetRoot(el)

			actual, err := Decrypt(key, doc.Root())
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, plaintext, actual)
		})
	}
}
