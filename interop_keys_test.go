package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// interopKey returns the committed key pair of the interop fixtures by its name, such as sp-rsa or idp-ec.
func interopKey(tb testing.TB, name string) (crypto.Signer, *x509.Certificate) {
	tb.Helper()

	read := func(ext string) *pem.Block {
		data, err := os.ReadFile(filepath.Join("testdata", "interop", "keys", name+ext))
		require.NoError(tb, err)

		block, _ := pem.Decode(data)
		require.NotNil(tb, block, "%s%s is not PEM", name, ext)

		return block
	}

	key, err := x509.ParsePKCS8PrivateKey(read(".key").Bytes)
	require.NoError(tb, err)

	cert, err := x509.ParseCertificate(read(".crt").Bytes)
	require.NoError(tb, err)

	signer, ok := key.(crypto.Signer)
	require.True(tb, ok, "%s is not a signer", name)

	return signer, cert
}

func TestInteropKeys(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)

	for _, name := range []string{"idp-rsa", "idp-ec", "sp-rsa", "sp-ec"} {
		t.Run(name, func(t *testing.T) {
			key, cert := interopKey(t, name)

			assert.True(t, cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(key.Public()))
			assert.Equal(t, notBefore, cert.NotBefore.UTC())
			assert.Equal(t, notAfter, cert.NotAfter.UTC())

			switch name[len(name)-3:] {
			case "rsa":
				rsaKey, ok := key.(*rsa.PrivateKey)
				require.True(t, ok)
				assert.Equal(t, 2048, rsaKey.N.BitLen())
			default:
				ecKey, ok := key.(*ecdsa.PrivateKey)
				require.True(t, ok)
				assert.Equal(t, elliptic.P256(), ecKey.Curve)
			}
		})
	}
}
