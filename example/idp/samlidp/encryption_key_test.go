package samlidp

import (
	"crypto/rand"
	"crypto/rsa"
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

	"authelia.com/provider/saml"
	"authelia.com/provider/saml/logger"
)

func newEncryptionKeyPair(t *testing.T) saml.DecryptionKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)

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

	return saml.DecryptionKey{Certificate: cert, Key: key}
}

func TestServerPublishesEncryptionKey(t *testing.T) {
	current, previous := newEncryptionKeyPair(t), newEncryptionKeyPair(t)

	options := Options{
		Certificate: mustParseCertificate(golden.Get(t, "idp_cert.pem")),
		Key:         mustParsePrivateKey(golden.Get(t, "idp_key.pem")),
		Logger:      logger.DefaultLogger,
		Store:       &MemoryStore{},
		URL:         url.URL{Scheme: "https", Host: "idp.example.com"},

		EncryptionCertificate: current.Certificate,
		EncryptionKey:         current.Key,
		DecryptionKeys:        []saml.DecryptionKey{previous},
	}

	server, err := New(options)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(server.IDP.DecryptionKeys, []saml.DecryptionKey{previous}))

	var encryption []string

	for _, descriptor := range server.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors {
		if descriptor.Use == "encryption" {
			encryption = append(encryption, descriptor.KeyInfo.X509Data.X509Certificates[0].Data)
		}
	}

	assert.Check(t, is.DeepEqual([]string{base64.StdEncoding.EncodeToString(current.Certificate.Raw)}, encryption))

	// Keys that are not valid are refused when the server is made.
	options.EncryptionKey = previous.Key
	_, err = New(options)
	assert.Check(t, is.Error(err, "IdentityProvider.EncryptionKey: the private key is not that of the certificate"))
}
