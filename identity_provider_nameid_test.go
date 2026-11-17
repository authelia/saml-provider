package saml

import (
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// An empty NameID names nobody, and every session that asserted one would be the same principal at the
// service provider. A session without a NameID gets a random transient one instead, and one whose format
// requires its own NameID is refused.
func TestDefaultAssertionMakerNeverAssertsEmptyNameID(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	assert.NilError(t, err)

	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", UserName: "alice"}))
	assert.Check(t, is.Equal(req.Assertion.Subject.NameID.Format, string(TransientNameIDFormat)))
	assert.Check(t, req.Assertion.Subject.NameID.Value != "")

	req.Assertion = nil
	err = DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", UserName: "alice", NameIDFormat: string(EmailAddressNameIDFormat)})
	assert.Check(t, err != nil)
	assert.Check(t, req.Assertion == nil)
}
