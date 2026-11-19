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

// The validity of an assertion is written to the millisecond, so a window from MaxClockSkew before it is made to
// AssertionLifetime after that is shorter than a millisecond could be written as NotBefore equal to NotOnOrAfter,
// in which no instant is valid. Such an assertion is not issued.
func TestIDPAssertionLifetimeShorterThanItsPrecision(t *testing.T) {
	skew := MaxClockSkew

	t.Cleanup(func() { MaxClockSkew = skew })

	MaxClockSkew = 0

	test := NewIdentityProviderTest(t, applyKey)
	now := TimeNow().Add(600 * time.Microsecond)
	TimeNow = func() time.Time { return now }

	test.IDP.AssertionLifetime = 500 * time.Microsecond
	_, err := lifetimeAssertion(t, test)
	assert.ErrorContains(t, err, "millisecond")
}

// A window of a millisecond or more is issued, and is written with NotBefore before NotOnOrAfter, whether the
// millisecond comes from the lifetime or from the clock skew.
func TestIDPAssertionLifetimeOfItsPrecision(t *testing.T) {
	skew := MaxClockSkew

	t.Cleanup(func() { MaxClockSkew = skew })

	for name, tc := range map[string]struct{ skew, lifetime time.Duration }{
		"a millisecond, no skew":      {0, time.Millisecond},
		"under a millisecond, skewed": {skew, 500 * time.Microsecond},
	} {
		t.Run(name, func(t *testing.T) {
			MaxClockSkew = tc.skew

			test := NewIdentityProviderTest(t, applyKey)
			now := TimeNow().Add(600 * time.Microsecond)
			TimeNow = func() time.Time { return now }

			test.IDP.AssertionLifetime = tc.lifetime
			req, err := lifetimeAssertion(t, test)
			require.NoError(t, err)

			conditions := req.Assertion.Conditions.Element()
			assert.Less(t, conditions.SelectAttrValue("NotBefore", ""), conditions.SelectAttrValue("NotOnOrAfter", ""))
		})
	}
}
