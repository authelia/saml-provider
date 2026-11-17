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
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"

	"authelia.com/provider/saml"
	"authelia.com/provider/saml/internal/dsig"
)

// signedServiceMetadata returns sp_metadata.xml with an ID and an enveloped signature by a new key, and the
// certificate of that key.
func signedServiceMetadata(t *testing.T) ([]byte, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "federation.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	assert.NilError(t, err)

	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)

	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(golden.Get(t, "sp_metadata.xml")))
	doc.Root().CreateAttr("ID", "sp-metadata")

	signingContext, err := dsig.NewSigningContext(key, [][]byte{cert.Raw})
	assert.NilError(t, err)

	signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	signed, err := signingContext.SignEnveloped(doc.Root())
	assert.NilError(t, err)

	last := len(signed.Child) - 1
	signature := signed.Child[last]
	signed.RemoveChildAt(last)
	signed.InsertChildAt(0, signature)
	doc.SetRoot(signed)

	data, err := doc.WriteToBytes()
	assert.NilError(t, err)

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

		assert.Check(t, is.Equal(http.StatusNoContent, put(test, signed)))
		assert.Check(t, test.Server.serviceProviders["https://example.com/saml2/metadata"] != nil)
	})

	t.Run("unsigned", func(t *testing.T) {
		test := NewServerTest(t)
		test.Server.ServiceProviderMetadataVerifier = &saml.MetadataVerifier{Certificates: []*x509.Certificate{cert}}

		assert.Check(t, is.Equal(http.StatusBadRequest, put(test, golden.Get(t, "sp_metadata.xml"))))
		assert.Check(t, test.Server.serviceProviders["https://example.com/saml2/metadata"] == nil)
	})

	t.Run("tampered", func(t *testing.T) {
		test := NewServerTest(t)
		test.Server.ServiceProviderMetadataVerifier = &saml.MetadataVerifier{Certificates: []*x509.Certificate{cert}}

		tampered := []byte(strings.Replace(string(signed), "https://example.com/saml2/acs", "https://evil.example.com/acs", 1))
		assert.Check(t, !bytes.Equal(signed, tampered))
		assert.Check(t, is.Equal(http.StatusBadRequest, put(test, tampered)))
		assert.Check(t, test.Server.serviceProviders["https://example.com/saml2/metadata"] == nil)
	})

	t.Run("without a verifier the signature isn't needed", func(t *testing.T) {
		test := NewServerTest(t)

		assert.Check(t, is.Equal(http.StatusNoContent, put(test, golden.Get(t, "sp_metadata.xml"))))
	})
}
