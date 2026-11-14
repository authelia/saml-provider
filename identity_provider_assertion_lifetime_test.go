package saml

import (
	"testing"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// lifetimeAssertion validates a current request and makes an assertion for it.
func lifetimeAssertion(t *testing.T, test *IdentityProviderTest) (*IdpAuthnRequest, error) {
	t.Helper()
	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	assert.NilError(t, err)
	return req, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice"})
}

func TestIDPAssertionLifetimeDefault(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req, err := lifetimeAssertion(t, test)
	assert.NilError(t, err)

	confirmation := req.Assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData
	assert.Check(t, req.Assertion.Conditions.NotBefore.Equal(TimeNow().Add(-MaxClockSkew)))
	assert.Check(t, req.Assertion.Conditions.NotOnOrAfter.Equal(TimeNow().Add(MaxIssueDelay)))
	assert.Check(t, confirmation.NotOnOrAfter.Equal(TimeNow().Add(MaxIssueDelay)))
}

func TestIDPAssertionLifetime(t *testing.T) {
	for _, lifetime := range []time.Duration{time.Second, 30 * time.Second, 10 * time.Minute} {
		t.Run(lifetime.String(), func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			test.IDP.AssertionLifetime = lifetime
			req, err := lifetimeAssertion(t, test)
			assert.NilError(t, err)

			confirmation := req.Assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData
			assert.Check(t, req.Assertion.Conditions.NotOnOrAfter.Equal(TimeNow().Add(lifetime)),
				"Conditions NotOnOrAfter=%s", req.Assertion.Conditions.NotOnOrAfter)
			assert.Check(t, confirmation.NotOnOrAfter.Equal(TimeNow().Add(lifetime)),
				"SubjectConfirmationData NotOnOrAfter=%s", confirmation.NotOnOrAfter)
			assert.Check(t, req.Assertion.Conditions.NotBefore.Equal(TimeNow().Add(-MaxClockSkew)),
				"the lifetime must not move NotBefore")
		})
	}
}

func TestIDPAssertionLifetimeNegative(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.AssertionLifetime = -time.Second
	_, err := lifetimeAssertion(t, test)
	assert.Check(t, is.ErrorContains(err, "AssertionLifetime"))
}

func TestIDPAssertionLifetimeDoesNotChangeRequestAge(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.AssertionLifetime = 10 * time.Minute
	old := hardeningRequest(`ID="id-1"`, TimeNow().Add(-MaxIssueDelay-time.Second), hardeningIssuer)

	_, err := hardeningValidate(test, old)
	assert.Check(t, is.ErrorContains(err, "expired"), "MaxAuthnRequestAge must not default to AssertionLifetime")
}
