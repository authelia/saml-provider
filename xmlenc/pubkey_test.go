package xmlenc

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"
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
			assert.NilError(t, err)

			keyBlock, _ := pem.Decode(golden.Get(t, "cert.key"))
			key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
			assert.NilError(t, err)

			plaintext := golden.Get(t, "plaintext.xml")
			el, err := PKCS1v15().Encrypt(certificate, plaintext, nil)
			assert.NilError(t, err)

			doc := etree.NewDocument()
			doc.SetRoot(el)

			actual, err := Decrypt(key, doc.Root())
			if tc.err != "" {
				assert.Check(t, is.Error(err, tc.err))
				return
			}

			assert.NilError(t, err)
			assert.Check(t, is.DeepEqual(plaintext, actual))
		})
	}
}
