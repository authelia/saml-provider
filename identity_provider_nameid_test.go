package saml

import (
	"testing"

	"gotest.tools/assert"
)

// An empty NameID names nobody, and every session without one would be the same principal at the
// service provider.
func TestDefaultAssertionMakerRefusesEmptyNameID(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	assert.NilError(t, err)
	assert.Check(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", UserName: "alice"}) != nil)
	assert.Check(t, req.Assertion == nil)
}
