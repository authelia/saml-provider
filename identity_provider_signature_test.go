package saml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func interopSignatureMethod(t *testing.T, test *IdentityProviderTest) (signature, digest string) {
	t.Helper()
	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	assert.NilError(t, err)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice"}))
	assert.NilError(t, req.MakeResponse())
	signature = req.ResponseEl.FindElement(".//SignatureMethod").SelectAttrValue("Algorithm", "")
	digest = req.ResponseEl.FindElement(".//DigestMethod").SelectAttrValue("Algorithm", "")
	return signature, digest
}

func TestIDPDefaultSignatureMethod(t *testing.T) {
	const sha256Digest = "http://www.w3.org/2001/04/xmlenc#sha256"

	t.Run("rsa key", func(t *testing.T) {
		signature, digest := interopSignatureMethod(t, NewIdentityProviderTest(t, applyKey))
		assert.Check(t, is.Equal(dsig.RSASHA256SignatureMethod, signature))
		assert.Check(t, is.Equal(sha256Digest, digest))
	})

	t.Run("rsa signer", func(t *testing.T) {
		signature, _ := interopSignatureMethod(t, NewIdentityProviderTest(t, applySigner))
		assert.Check(t, is.Equal(dsig.RSASHA256SignatureMethod, signature))
	})

	t.Run("ecdsa signer must choose a method explicitly", func(t *testing.T) {
		// goxmldsig writes ECDSA signatures in DER rather than the r||s form of XML Signature, which
		// other implementations reject, so this must not be selected without asking for it.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		assert.NilError(t, err)
		test := NewIdentityProviderTest(t)
		test.IDP.Signer = key
		req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
		assert.NilError(t, err)
		assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice"}))
		assert.Check(t, is.ErrorContains(req.MakeResponse(), "incompatible"))

		test.IDP.SignatureMethod = dsig.ECDSASHA256SignatureMethod
		signature, _ := interopSignatureMethod(t, test)
		assert.Check(t, is.Equal(dsig.ECDSASHA256SignatureMethod, signature))
	})

	t.Run("explicit method is kept", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.SignatureMethod = dsig.RSASHA512SignatureMethod
		signature, _ := interopSignatureMethod(t, test)
		assert.Check(t, is.Equal(dsig.RSASHA512SignatureMethod, signature))
	})
}
