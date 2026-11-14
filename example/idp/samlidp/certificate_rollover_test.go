package samlidp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/url"
	"testing"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"

	"authelia.com/provider/saml/logger"
)

func TestServerPublishesRolloverCertificates(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NilError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	assert.NilError(t, err)
	next, err := x509.ParseCertificate(der)
	assert.NilError(t, err)

	current := mustParseCertificate(golden.Get(t, "idp_cert.pem"))
	server, err := New(Options{
		Certificate:          current,
		RolloverCertificates: []*x509.Certificate{next},
		Key:                  mustParsePrivateKey(golden.Get(t, "idp_key.pem")),
		Logger:               logger.DefaultLogger,
		Store:                &MemoryStore{},
		URL:                  url.URL{Scheme: "https", Host: "idp.example.com"},
	})
	assert.NilError(t, err)

	var signing []string
	for _, descriptor := range server.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors {
		if descriptor.Use == "signing" {
			signing = append(signing, descriptor.KeyInfo.X509Data.X509Certificates[0].Data)
		}
	}
	assert.Check(t, is.DeepEqual([]string{
		base64.StdEncoding.EncodeToString(current.Raw),
		base64.StdEncoding.EncodeToString(next.Raw),
	}, signing))
}
