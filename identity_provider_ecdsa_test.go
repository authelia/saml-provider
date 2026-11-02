package saml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

func TestSPVerifiesIDPSignatureInRawECDSAEncoding(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
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

	test := NewIdentityProviderTest(t)
	test.IDP.Key = nil
	test.IDP.Signer = key
	test.IDP.Certificate = cert
	test.IDP.SignatureMethod = dsig.ECDSASHA384SignatureMethod

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

	value, err := base64.StdEncoding.DecodeString(parsed.Root().FindElement("./Signature/SignatureValue").Text())
	assert.NilError(t, err)
	assert.Check(t, is.Len(value, 96))

	previous := Clock
	Clock = dsig.NewFakeClockAt(time.Now())
	defer func() { Clock = previous }()

	sp := ServiceProvider{IDPMetadata: test.IDP.Metadata()}
	assert.Check(t, sp.validateSignature(parsed.Root()))
}
