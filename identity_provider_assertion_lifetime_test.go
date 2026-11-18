package saml

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lifetimeAssertion validates a current request and makes an assertion for it.
func lifetimeAssertion(t *testing.T, test *IdentityProviderTest) (*IdpAuthnRequest, error) {
	t.Helper()

	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	require.NoError(t, err)

	return req, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice"})
}

func TestIDPAssertionLifetimeDefault(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req, err := lifetimeAssertion(t, test)
	require.NoError(t, err)

	confirmation := req.Assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData
	assert.True(t, req.Assertion.Conditions.NotBefore.Equal(TimeNow().Add(-MaxClockSkew)))
	assert.True(t, req.Assertion.Conditions.NotOnOrAfter.Equal(TimeNow().Add(MaxIssueDelay)))
	assert.True(t, confirmation.NotOnOrAfter.Equal(TimeNow().Add(MaxIssueDelay)))
}

func TestIDPAssertionLifetime(t *testing.T) {
	for _, lifetime := range []time.Duration{time.Second, 30 * time.Second, 10 * time.Minute} {
		t.Run(lifetime.String(), func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			test.IDP.AssertionLifetime = lifetime
			req, err := lifetimeAssertion(t, test)
			require.NoError(t, err)

			confirmation := req.Assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData
			assert.True(t, req.Assertion.Conditions.NotOnOrAfter.Equal(TimeNow().Add(lifetime)),
				"Conditions NotOnOrAfter=%s", req.Assertion.Conditions.NotOnOrAfter)
			assert.True(t, confirmation.NotOnOrAfter.Equal(TimeNow().Add(lifetime)),
				"SubjectConfirmationData NotOnOrAfter=%s", confirmation.NotOnOrAfter)
			assert.True(t, req.Assertion.Conditions.NotBefore.Equal(TimeNow().Add(-MaxClockSkew)),
				"the lifetime must not move NotBefore")
		})
	}
}

func TestIDPAssertionLifetimeNegative(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.AssertionLifetime = -time.Second
	_, err := lifetimeAssertion(t, test)
	assert.ErrorContains(t, err, "AssertionLifetime")
}

func TestIDPAssertionLifetimeDoesNotChangeRequestAge(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.AssertionLifetime = 10 * time.Minute
	old := hardeningRequest(`ID="id-1"`, TimeNow().Add(-MaxIssueDelay-MaxClockSkew), hardeningIssuer)

	_, err := hardeningValidate(test, old)
	assert.ErrorContains(t, err, "expired", "MaxAuthnRequestAge must not default to AssertionLifetime")
}
