package samlsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/url"
	"testing"

	"authelia.com/provider/jose"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml/internal/dsig"
)

type opaqueSigner struct {
	crypto.Signer
}

var ecdsaTestCurves = []struct {
	name      string
	curve     elliptic.Curve
	algorithm jose.SignatureAlgorithm
	method    string
}{
	{"P-256", elliptic.P256(), jose.ES256, dsig.ECDSASHA256SignatureMethod},
	{"P-384", elliptic.P384(), jose.ES384, dsig.ECDSASHA384SignatureMethod},
	{"P-521", elliptic.P521(), jose.ES512, dsig.ECDSASHA512SignatureMethod},
}

func ecdsaTestSigners(t *testing.T, curve elliptic.Curve) map[string]crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	assert.NilError(t, err)
	return map[string]crypto.Signer{"key": key, "opaque signer": opaqueSigner{key}}
}

func TestDefaultCodecsRoundTripWithECDSA(t *testing.T) {
	for _, tc := range ecdsaTestCurves {
		for name, signer := range ecdsaTestSigners(t, tc.curve) {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				u, err := url.Parse("https://sp.example.com/")
				assert.NilError(t, err)
				opts := Options{URL: *u, Key: signer}

				sessions := DefaultSessionCodec(opts)
				assert.Check(t, is.Equal(tc.algorithm, sessions.SigningMethod))
				session, err := sessions.Decode(encodeTestSession(t, sessions))
				assert.NilError(t, err)
				assert.Check(t, is.Equal("alice", session.(JWTSessionClaims).Subject))

				requests := DefaultTrackedRequestCodec(opts)
				assert.Check(t, is.Equal(tc.algorithm, requests.SigningMethod))
				token, err := requests.Encode(TrackedRequest{Index: "idx", SAMLRequestID: "id-1", URI: "/"})
				assert.NilError(t, err)
				tracked, err := requests.Decode(token)
				assert.NilError(t, err)
				assert.Check(t, is.Equal("id-1", tracked.SAMLRequestID))
			})
		}
	}
}

func TestDefaultServiceProviderSigningMethodWithECDSA(t *testing.T) {
	for _, tc := range ecdsaTestCurves {
		for name, signer := range ecdsaTestSigners(t, tc.curve) {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				u, err := url.Parse("https://sp.example.com/")
				assert.NilError(t, err)
				sp := DefaultServiceProvider(Options{URL: *u, Key: signer, SignRequest: true})
				assert.Check(t, is.Equal(tc.method, sp.SignatureMethod))
			})
		}
	}
}
