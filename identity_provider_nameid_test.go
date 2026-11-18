package saml

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An empty NameID names nobody, and every session that asserted one would be the same principal at the
// service provider. A session without a NameID gets a random transient one instead, and one whose format
// requires its own NameID is refused.
func TestDefaultAssertionMakerNeverAssertsEmptyNameID(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	require.NoError(t, err)

	require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", UserName: "alice"}))
	assert.Equal(t, req.Assertion.Subject.NameID.Format, string(TransientNameIDFormat))
	assert.True(t, req.Assertion.Subject.NameID.Value != "")

	req.Assertion = nil
	err = DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", UserName: "alice", NameIDFormat: string(EmailAddressNameIDFormat)})
	assert.NotNil(t, err)
	assert.Nil(t, req.Assertion)
}
