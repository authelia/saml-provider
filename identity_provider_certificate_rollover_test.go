package saml

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml/internal/dsig"
)

// newRolloverTestRSAKey returns an RSA key and a self-signed certificate for it which is valid now.
func newRolloverTestRSAKey(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	return key, newRolloverTestCertificate(t, key)
}

// newRolloverTestCertificate returns a self-signed certificate for key which is valid now.
func newRolloverTestCertificate(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	assert.NilError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)
	return cert
}

// signingCertificates returns the certificates of the signing KeyDescriptors in metadata, in order.
func signingCertificates(t *testing.T, descriptors []KeyDescriptor) []string {
	t.Helper()
	var certs []string
	for _, descriptor := range descriptors {
		if descriptor.Use != "signing" {
			continue
		}
		assert.Check(t, is.Len(descriptor.KeyInfo.X509Data.X509Certificates, 1), "each key must be in its own KeyDescriptor")
		for _, cert := range descriptor.KeyInfo.X509Data.X509Certificates {
			certs = append(certs, cert.Data)
		}
	}
	return certs
}

func encodeCertificate(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}

func TestIDPMetadataPublishesRolloverCertificates(t *testing.T) {
	_, current := newRolloverTestRSAKey(t)
	_, next := newRolloverTestRSAKey(t)
	_, ecdsaNext := newECDSATestKey(t, elliptic.P256())

	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.Certificate = current
	test.IDP.RolloverCertificates = []*x509.Certificate{next, ecdsaNext}

	descriptors := test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors
	assert.Check(t, is.Equal("signing", descriptors[0].Use), "the signing certificate stays first")
	assert.Check(t, is.DeepEqual(
		[]string{encodeCertificate(current), encodeCertificate(next), encodeCertificate(ecdsaNext)},
		signingCertificates(t, descriptors)))
}

func TestIDPMetadataRolloverCertificatesAreNotAdvertisedForEncryption(t *testing.T) {
	_, current := newRolloverTestRSAKey(t)
	_, next := newRolloverTestRSAKey(t)

	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.Certificate = current
	test.IDP.RolloverCertificates = []*x509.Certificate{next}

	for _, descriptor := range test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors {
		if descriptor.Use == "signing" {
			continue
		}
		for _, cert := range descriptor.KeyInfo.X509Data.X509Certificates {
			assert.Check(t, cert.Data != encodeCertificate(next), "a rollover certificate is only published for signing")
		}
	}
}

func TestIDPMetadataRolloverCertificatesAreDeduplicated(t *testing.T) {
	_, current := newRolloverTestRSAKey(t)
	_, next := newRolloverTestRSAKey(t)

	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.Certificate = current
	test.IDP.RolloverCertificates = []*x509.Certificate{nil, current, next, next}

	assert.Check(t, is.DeepEqual(
		[]string{encodeCertificate(current), encodeCertificate(next)},
		signingCertificates(t, test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors)))
}

func TestIDPMetadataWithoutRolloverCertificatesPublishesOneSigningKey(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	assert.Check(t, is.DeepEqual(
		[]string{encodeCertificate(test.Certificate)},
		signingCertificates(t, test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors)))
}

// rolloverSignedResponse returns a Response signed by an identity provider with key and cert, after
// a round trip through serialization.
func rolloverSignedResponse(t *testing.T, key crypto.Signer, cert *x509.Certificate) *etree.Element {
	t.Helper()
	test := NewIdentityProviderTest(t)
	test.IDP.Key = nil
	test.IDP.Signer = key
	test.IDP.Certificate = cert

	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	assert.NilError(t, err)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice"}))
	assert.NilError(t, req.MakeResponse())

	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)
	serialized, err := doc.WriteToBytes()
	assert.NilError(t, err)
	parsed := etree.NewDocument()
	assert.NilError(t, parsed.ReadFromBytes(serialized))
	return parsed.Root()
}

func TestSPVerifiesResponseSignedWithAnyPublishedCertificate(t *testing.T) {
	oldKey, oldCert := newRolloverTestRSAKey(t)
	newKey, newCert := newECDSATestKey(t, elliptic.P256())
	otherKey, otherCert := newRolloverTestRSAKey(t)

	// The identity provider still signs with the old key, and publishes the new one ahead of the switch.
	test := NewIdentityProviderTest(t)
	test.IDP.Key = nil
	test.IDP.Signer = oldKey
	test.IDP.Certificate = oldCert
	test.IDP.RolloverCertificates = []*x509.Certificate{newCert}
	metadata := test.IDP.Metadata()

	signedByOld := rolloverSignedResponse(t, oldKey, oldCert)
	signedByNew := rolloverSignedResponse(t, newKey, newCert)
	signedByOther := rolloverSignedResponse(t, otherKey, otherCert)

	previous := Clock
	Clock = dsig.NewFakeClockAt(time.Now())
	defer func() { Clock = previous }()

	sp := ServiceProvider{IDPMetadata: metadata}
	assert.Check(t, sp.validateSignature(signedByOld))
	assert.Check(t, sp.validateSignature(signedByNew))
	assert.Check(t, sp.validateSignature(signedByOther) != nil, "a certificate the metadata doesn't publish must not verify")
}
