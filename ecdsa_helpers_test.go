package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"gotest.tools/assert"

	"authelia.com/provider/saml/internal/dsig"
)

// opaqueSigner hides the concrete key type, as a key held in an HSM or KMS would.
type opaqueSigner struct {
	crypto.Signer
}

var ecdsaTestCurves = []struct {
	name    string
	curve   elliptic.Curve
	method  string
	newHash crypto.Hash
}{
	{"P-256", elliptic.P256(), dsig.ECDSASHA256SignatureMethod, crypto.SHA256},
	{"P-384", elliptic.P384(), dsig.ECDSASHA384SignatureMethod, crypto.SHA384},
	{"P-521", elliptic.P521(), dsig.ECDSASHA512SignatureMethod, crypto.SHA512},
}

func newECDSATestKey(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	assert.NilError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	assert.NilError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)
	return key, cert
}

func keyDescriptorUses(descriptors []KeyDescriptor) []string {
	uses := make([]string, 0, len(descriptors))
	for _, descriptor := range descriptors {
		uses = append(uses, descriptor.Use)
	}
	return uses
}
