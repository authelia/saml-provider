package samlidp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml"
	"authelia.com/provider/saml/internal/dsig"
	"authelia.com/provider/saml/internal/golden"
)

// signedServiceMetadata returns sp_metadata.xml with an ID and an enveloped signature by a new key, and the
// certificate of that key.
func signedServiceMetadata(t *testing.T) ([]byte, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "federation.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(golden.Get(t, "sp_metadata.xml")))
	doc.Root().CreateAttr("ID", "sp-metadata")

	signingContext, err := dsig.NewSigningContext(key, [][]byte{cert.Raw})
	require.NoError(t, err)

	signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	signed, err := signingContext.SignEnveloped(doc.Root())
	require.NoError(t, err)

	last := len(signed.Child) - 1
	signature := signed.Child[last]
	signed.RemoveChildAt(last)
	signed.InsertChildAt(0, signature)
	doc.SetRoot(signed)

	data, err := doc.WriteToBytes()
	require.NoError(t, err)

	return data, cert
}

func TestPutServiceVerifiesMetadata(t *testing.T) {
	signed, cert := signedServiceMetadata(t)

	put := func(test *ServerTest, data []byte) int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPut, "https://idp.example.com/services/sp", bytes.NewReader(data))
		test.Server.ServeHTTP(w, r)

		return w.Code
	}

	t.Run("signed by a trusted certificate", func(t *testing.T) {
		test := NewServerTest(t)
		test.Server.ServiceProviderMetadataVerifier = &saml.MetadataVerifier{Certificates: []*x509.Certificate{cert}}

		assert.Equal(t, http.StatusNoContent, put(test, signed))
		assert.NotNil(t, test.Server.serviceProviders["https://example.com/saml2/metadata"])
	})

	t.Run("unsigned", func(t *testing.T) {
		test := NewServerTest(t)
		test.Server.ServiceProviderMetadataVerifier = &saml.MetadataVerifier{Certificates: []*x509.Certificate{cert}}

		assert.Equal(t, http.StatusBadRequest, put(test, golden.Get(t, "sp_metadata.xml")))
		assert.Nil(t, test.Server.serviceProviders["https://example.com/saml2/metadata"])
	})

	t.Run("tampered", func(t *testing.T) {
		test := NewServerTest(t)
		test.Server.ServiceProviderMetadataVerifier = &saml.MetadataVerifier{Certificates: []*x509.Certificate{cert}}

		tampered := []byte(strings.Replace(string(signed), "https://example.com/saml2/acs", "https://evil.example.com/acs", 1))
		assert.False(t, bytes.Equal(signed, tampered))
		assert.Equal(t, http.StatusBadRequest, put(test, tampered))
		assert.Nil(t, test.Server.serviceProviders["https://example.com/saml2/metadata"])
	})

	t.Run("without a verifier the signature isn't needed", func(t *testing.T) {
		test := NewServerTest(t)

		assert.Equal(t, http.StatusNoContent, put(test, golden.Get(t, "sp_metadata.xml")))
	})
}
