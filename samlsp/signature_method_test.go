package samlsp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/dsig"
)

func TestDefaultServiceProviderSigningMethodWithRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	u, err := url.Parse("https://sp.example.com/")
	require.NoError(t, err)

	for name, signer := range map[string]crypto.Signer{"key": key, "opaque signer": opaqueSigner{key}} {
		t.Run(name, func(t *testing.T) {
			sp := DefaultServiceProvider(Options{URL: *u, Key: signer, SignRequest: true})
			assert.Equal(t, dsig.RSASHA256SignatureMethod, sp.SignatureMethod)

			sp = DefaultServiceProvider(Options{URL: *u, Key: signer})
			assert.Equal(t, "", sp.SignatureMethod)
		})
	}
}
