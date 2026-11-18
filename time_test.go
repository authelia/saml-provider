package saml

import (
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRelaxedTimeFormat(t *testing.T) {
	rt := time.Date(1981, 02, 03, 14, 15, 16, 17, time.UTC)
	assert.Equal(t, "1981-02-03T14:15:16Z", RelaxedTime(rt).String())

	buf, err := RelaxedTime(rt).MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, "1981-02-03T14:15:16Z", string(buf))

	loc, err := time.LoadLocation("America/New_York")
	require.NoError(t, err)

	rt = time.Date(1981, 02, 03, 9, 15, 16, 17, loc)

	assert.Equal(t, "1981-02-03T14:15:16Z", RelaxedTime(rt).String())
	buf, err = RelaxedTime(rt).MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, "1981-02-03T14:15:16Z", string(buf))
}

func TestRelaxedTimeParse(t *testing.T) {
	{
		var rt RelaxedTime

		err := rt.UnmarshalText([]byte("1981-02-03T14:15:16Z"))
		assert.NoError(t, err)
		assert.Equal(t, RelaxedTime(time.Date(1981, 02, 03, 14, 15, 16, 0, time.UTC)), rt)
	}
	{
		var rt RelaxedTime

		err := rt.UnmarshalText([]byte("1981-02-03T14:15:16.178901234Z"))
		assert.NoError(t, err)
		assert.Equal(t, RelaxedTime(time.Date(1981, 02, 03, 14, 15, 16, 179000000, time.UTC)), rt)
	}
	{
		var rt RelaxedTime

		err := rt.UnmarshalText([]byte("1981-02-03T14:15:16.1717Z"))
		assert.NoError(t, err)
		assert.Equal(t, RelaxedTime(time.Date(1981, 02, 03, 14, 15, 16, 172000000, time.UTC)), rt)
	}
	{
		var rt RelaxedTime

		err := rt.UnmarshalText([]byte("1981-02-03T14:15:16Z04:00"))
		assert.EqualError(t, err, "parsing time \"1981-02-03T14:15:16Z04:00\": extra text: \"04:00\"")
	}
}

// TestElementTimesAreUTC checks that every time an Element method writes is in UTC with the Z designator and
// no offset, as SAMLCore §1.3.3 requires, whatever the location of the time it is given, and is rounded to the
// millisecond as MarshalXML writes it.
func TestElementTimesAreUTC(t *testing.T) {
	loc := time.FixedZone("AEDT", 11*60*60)
	// A fraction of a millisecond, so that a time written without rounding to the millisecond fails too.
	local := time.Date(2026, 11, 19, 8, 0, 0, 123600000, loc)
	localPtr := &local

	const want = "2026-11-18T21:00:00.124Z"

	testCases := []struct {
		name  string
		el    *etree.Element
		attrs []string
	}{
		{"LogoutRequest", (&LogoutRequest{IssueInstant: local, NotOnOrAfter: localPtr}).Element(), []string{"IssueInstant", "NotOnOrAfter"}},
		{"AuthnRequest", (&AuthnRequest{IssueInstant: local}).Element(), []string{"IssueInstant"}},
		{"ArtifactResolve", (&ArtifactResolve{IssueInstant: local}).Element(), []string{"IssueInstant"}},
		{"ArtifactResponse", (&ArtifactResponse{IssueInstant: local}).Element(), []string{"IssueInstant"}},
		{"Response", (&Response{IssueInstant: local}).Element(), []string{"IssueInstant"}},
		{"Assertion", (&Assertion{IssueInstant: local}).Element(), []string{"IssueInstant"}},
		{"SubjectConfirmationData", (&SubjectConfirmationData{NotBefore: local, NotOnOrAfter: local}).Element(), []string{"NotBefore", "NotOnOrAfter"}},
		{"Conditions", (&Conditions{NotBefore: local, NotOnOrAfter: local}).Element(), []string{"NotBefore", "NotOnOrAfter"}},
		{"AuthnStatement", (&AuthnStatement{AuthnInstant: local, SessionNotOnOrAfter: localPtr}).Element(), []string{"AuthnInstant", "SessionNotOnOrAfter"}},
		{"LogoutResponse", (&LogoutResponse{IssueInstant: local}).Element(), []string{"IssueInstant"}},
		{"AttributeQuery", (&AttributeQuery{IssueInstant: local}).Element(), []string{"IssueInstant"}},
		{"AuthnQuery", (&AuthnQuery{IssueInstant: local}).Element(), []string{"IssueInstant"}},
		{"AssertionIDRequest", (&AssertionIDRequest{IssueInstant: local}).Element(), []string{"IssueInstant"}},
		{"ManageNameIDRequest", (&ManageNameIDRequest{IssueInstant: local}).Element(), []string{"IssueInstant"}},
		{"ManageNameIDResponse", (&ManageNameIDResponse{IssueInstant: local}).Element(), []string{"IssueInstant"}},
		{"NameIDMappingRequest", (&NameIDMappingRequest{IssueInstant: local}).Element(), []string{"IssueInstant"}},
		{"NameIDMappingResponse", (&NameIDMappingResponse{IssueInstant: local}).Element(), []string{"IssueInstant"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, attr := range tc.attrs {
				assert.Equal(t, want, tc.el.SelectAttrValue(attr, ""), attr)
			}
		})
	}
}
