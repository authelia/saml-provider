package saml

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sessionNotOnOrAfterAssertion validates a current request and makes an assertion for the session.
func sessionNotOnOrAfterAssertion(t *testing.T, include bool, session *Session) (*IdpAuthnRequest, error) {
	t.Helper()
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.IncludeSessionNotOnOrAfter = include
	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	require.NoError(t, err)

	return req, DefaultAssertionMaker{}.MakeAssertion(req, session)
}

func TestIDPSessionNotOnOrAfterOmittedByDefault(t *testing.T) {
	req, err := sessionNotOnOrAfterAssertion(t, false, &Session{ID: "f00d", NameID: "alice", ExpireTime: TimeNow().Add(time.Hour)})
	require.NoError(t, err)
	assert.Nil(t, req.Assertion.AuthnStatements[0].SessionNotOnOrAfter)
}

func TestIDPSessionNotOnOrAfterExpiredSessionWhenNotIncluded(t *testing.T) {
	// Without IncludeSessionNotOnOrAfter the expiry of the session is not consulted.
	_, err := sessionNotOnOrAfterAssertion(t, false, &Session{ID: "f00d", NameID: "alice", ExpireTime: TimeNow().Add(-time.Hour)})
	assert.NoError(t, err)
}

func TestIDPSessionNotOnOrAfter(t *testing.T) {
	expire := TimeNow().Add(time.Hour)
	req, err := sessionNotOnOrAfterAssertion(t, true, &Session{ID: "f00d", NameID: "alice", ExpireTime: expire})
	require.NoError(t, err)

	got := req.Assertion.AuthnStatements[0].SessionNotOnOrAfter
	require.NotNil(t, got)
	assert.True(t, got.Equal(expire), "SessionNotOnOrAfter=%s", got)
}

func TestIDPSessionNotOnOrAfterZeroExpireTime(t *testing.T) {
	req, err := sessionNotOnOrAfterAssertion(t, true, &Session{ID: "f00d", NameID: "alice"})
	require.NoError(t, err)
	assert.Nil(t, req.Assertion.AuthnStatements[0].SessionNotOnOrAfter)
}

func TestIDPSessionNotOnOrAfterExpiredSession(t *testing.T) {
	for name, offset := range map[string]time.Duration{
		"expires now":     0,
		"already expired": -time.Second,
	} {
		t.Run(name, func(t *testing.T) {
			req, err := sessionNotOnOrAfterAssertion(t, true, &Session{ID: "f00d", NameID: "alice", ExpireTime: TimeNow().Add(offset)})
			assert.ErrorContains(t, err, "session expired")
			assert.Nil(t, req.Assertion)
		})
	}
}

func TestIDPSessionNotOnOrAfterIsUTC(t *testing.T) {
	zone := time.FixedZone("UTC+10", 10*60*60)
	expire := TimeNow().Add(time.Hour).In(zone)
	req, err := sessionNotOnOrAfterAssertion(t, true, &Session{ID: "f00d", NameID: "alice", ExpireTime: expire})
	require.NoError(t, err)

	statement := req.Assertion.AuthnStatements[0]
	assert.Equal(t, statement.SessionNotOnOrAfter.Location(), time.UTC)

	// SAMLCore §2.7.2 requires the value to be encoded in UTC, whichever way it is serialized.
	const want = "2015-12-01T02:57:09Z"
	assert.Equal(t, statement.Element().SelectAttrValue("SessionNotOnOrAfter", ""), want)
	buf, err := xml.Marshal(&statement)
	require.NoError(t, err)
	assert.Contains(t, string(buf), `SessionNotOnOrAfter="`+want+`"`)
}

func TestIDPSessionNotOnOrAfterParsedBySP(t *testing.T) {
	expire := TimeNow().Add(time.Hour)
	req, err := sessionNotOnOrAfterAssertion(t, true, &Session{ID: "f00d", NameID: "alice", ExpireTime: expire})
	require.NoError(t, err)

	doc := etree.NewDocument()
	doc.SetRoot(req.Assertion.Element())
	buf, err := doc.WriteToBytes()
	require.NoError(t, err)

	var parsed Assertion
	require.NoError(t, xml.Unmarshal(buf, &parsed))
	got := parsed.AuthnStatements[0].SessionNotOnOrAfter
	require.NotNil(t, got)
	assert.True(t, got.Equal(expire), "SessionNotOnOrAfter=%s", got)
}
