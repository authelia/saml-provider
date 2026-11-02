package samlsp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/url"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml/internal/dsig"
)

func TestDefaultServiceProviderSigningMethodWithRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	u, err := url.Parse("https://sp.example.com/")
	assert.NilError(t, err)

	for name, signer := range map[string]crypto.Signer{"key": key, "opaque signer": opaqueSigner{key}} {
		t.Run(name, func(t *testing.T) {
			sp := DefaultServiceProvider(Options{URL: *u, Key: signer, SignRequest: true})
			assert.Check(t, is.Equal(dsig.RSASHA256SignatureMethod, sp.SignatureMethod))

			sp = DefaultServiceProvider(Options{URL: *u, Key: signer})
			assert.Check(t, is.Equal("", sp.SignatureMethod))
		})
	}
}
