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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/golden"
)

func TestServerPublishesRolloverCertificates(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	next, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	current := mustParseCertificate(golden.Get(t, "idp_cert.pem"))
	server, err := New(Options{
		Certificate:          current,
		RolloverCertificates: []*x509.Certificate{next},
		Key:                  mustParsePrivateKey(golden.Get(t, "idp_key.pem")),
		Store:                &MemoryStore{},
		URL:                  url.URL{Scheme: "https", Host: "idp.example.com"},
	})
	require.NoError(t, err)

	var signing []string
	for _, descriptor := range server.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors {
		if descriptor.Use == "signing" {
			signing = append(signing, descriptor.KeyInfo.X509Data.X509Certificates[0].Data)
		}
	}

	assert.Equal(t, []string{
		base64.StdEncoding.EncodeToString(current.Raw),
		base64.StdEncoding.EncodeToString(next.Raw),
	}, signing)
}
