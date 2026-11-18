package saml

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/dsig"
)

func interopSignatureMethod(t *testing.T, test *IdentityProviderTest) (signature, digest string) {
	t.Helper()

	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	require.NoError(t, err)
	require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice"}))
	require.NoError(t, req.MakeResponse())
	signature = req.ResponseEl.FindElement(".//SignatureMethod").SelectAttrValue("Algorithm", "")
	digest = req.ResponseEl.FindElement(".//DigestMethod").SelectAttrValue("Algorithm", "")

	return signature, digest
}

func TestIDPDefaultSignatureMethod(t *testing.T) {
	const sha256Digest = "http://www.w3.org/2001/04/xmlenc#sha256"

	t.Run("rsa key", func(t *testing.T) {
		signature, digest := interopSignatureMethod(t, NewIdentityProviderTest(t, applyKey))
		assert.Equal(t, dsig.RSASHA256SignatureMethod, signature)
		assert.Equal(t, sha256Digest, digest)
	})

	t.Run("rsa signer", func(t *testing.T) {
		signature, _ := interopSignatureMethod(t, NewIdentityProviderTest(t, applySigner))
		assert.Equal(t, dsig.RSASHA256SignatureMethod, signature)
	})

	t.Run("explicit method is kept", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.SignatureMethod = dsig.RSASHA512SignatureMethod
		signature, _ := interopSignatureMethod(t, test)
		assert.Equal(t, dsig.RSASHA512SignatureMethod, signature)
	})
}
