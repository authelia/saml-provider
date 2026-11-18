package saml

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIdpLogoutRequestMatchesSession(t *testing.T) {
	const (
		transient  = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
		persistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	)

	test := NewIdentityProviderTest(t)
	sp := test.SP.Metadata()
	idpEntityID := test.IDP.Metadata().EntityID

	// full returns the complete identifier DefaultAssertionMaker asserts for alice, with format.
	full := func(format string) *NameID {
		return &NameID{Format: format, NameQualifier: idpEntityID, SPNameQualifier: sp.EntityID, Value: "alice@example.com"}
	}
	with := func(nameID *NameID, change func(*NameID)) *NameID {
		change(nameID)
		return nameID
	}

	indexes := func(values ...string) []SessionIndex {
		out := make([]SessionIndex, 0, len(values))
		for _, v := range values {
			out = append(out, SessionIndex{Value: v})
		}

		return out
	}

	// noFormat is a session that sets no NameIDFormat, which is otherwise transient.
	const noFormat = "none"

	testCases := []struct {
		name          string
		nameID        *NameID
		indexes       []SessionIndex
		sessionFormat string
		match         bool
		// valueOnlyMatch is whether it matches with LogoutNameIDValueOnly.
		valueOnlyMatch bool
	}{
		{name: "complete identifier", nameID: full(transient), match: true, valueOnlyMatch: true},
		{name: "complete persistent identifier with persistent session", nameID: full(persistent), sessionFormat: persistent, match: true, valueOnlyMatch: true},
		{name: "persistent format with empty session format", nameID: full(persistent), sessionFormat: noFormat},
		// A session without a format never had its NameID asserted, so only a participant can match.
		{name: "transient format with empty session format", nameID: full(transient), sessionFormat: noFormat},
		{name: "value only with empty session format", nameID: &NameID{Value: "alice@example.com"}, sessionFormat: noFormat},
		{name: "transient format with persistent session", nameID: full(transient), sessionFormat: persistent, valueOnlyMatch: true},
		{name: "value only", nameID: &NameID{Value: "alice@example.com"}, valueOnlyMatch: true},
		{name: "other value", nameID: with(full(transient), func(n *NameID) { n.Value = "bob@example.com" })},
		{name: "omitted format", nameID: with(full(transient), func(n *NameID) { n.Format = "" }), valueOnlyMatch: true},
		{name: "unspecified 1.1 format", nameID: full(string(UnspecifiedNameIDFormat)), valueOnlyMatch: true},
		{name: "unspecified 2.0 format", nameID: full(unspecifiedNameIDFormat), valueOnlyMatch: true},
		{name: "omitted name qualifier", nameID: with(full(transient), func(n *NameID) { n.NameQualifier = "" }), valueOnlyMatch: true},
		{name: "other name qualifier", nameID: with(full(transient), func(n *NameID) { n.NameQualifier = "https://other.example.com" }), valueOnlyMatch: true},
		{name: "omitted sp name qualifier", nameID: with(full(transient), func(n *NameID) { n.SPNameQualifier = "" }), valueOnlyMatch: true},
		{name: "sp name qualifier of another sp", nameID: with(full(transient), func(n *NameID) { n.SPNameQualifier = "https://other-sp.example.com" }), valueOnlyMatch: true},
		{name: "sp provided id", nameID: with(full(transient), func(n *NameID) { n.SPProvidedID = "x" }), valueOnlyMatch: true},
		{name: "session index listed", nameID: full(transient), indexes: indexes("i0", "i1"), match: true, valueOnlyMatch: true},
		{name: "only other session indexes", nameID: full(transient), indexes: indexes("i0", "i2")},
		{name: "nil name id"},
		// An entity NameID is asserted without qualifiers (SAMLCore §8.3.6), so the request must omit them too.
		{name: "entity identifier without qualifiers", nameID: &NameID{Format: string(EntityNameIDFormat), Value: "alice@example.com"}, sessionFormat: string(EntityNameIDFormat), match: true, valueOnlyMatch: true},
		{name: "entity identifier with qualifiers", nameID: full(string(EntityNameIDFormat)), sessionFormat: string(EntityNameIDFormat), valueOnlyMatch: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, valueOnly := range []bool{false, true} {
				idp := test.IDP
				idp.LogoutNameIDValueOnly = valueOnly

				req := &IdpLogoutRequest{
					IDP:                     &idp,
					ServiceProviderMetadata: sp,
					Request:                 LogoutRequest{NameID: tc.nameID, SessionIndexes: tc.indexes},
				}

				format := tc.sessionFormat
				switch format {
				case "":
					format = transient
				case noFormat:
					format = ""
				}

				session := &Session{NameID: "alice@example.com", NameIDFormat: format, Index: "i1"}

				want := tc.match
				if valueOnly {
					want = tc.valueOnlyMatch
				}

				err := req.MatchesSession(nil, session)
				if want {
					require.NoError(t, err, "valueOnly=%t", valueOnly)
				} else {
					require.True(t, err != nil, "valueOnly=%t", valueOnly)
				}
			}
		})
	}
}

func TestIdpLogoutRequestMatchesSessionNilPreconditions(t *testing.T) {
	test := NewIdentityProviderTest(t)
	idp := test.IDP
	session := &Session{NameID: "alice@example.com", NameIDFormat: string(TransientNameIDFormat)}

	req := &IdpLogoutRequest{IDP: &idp, ServiceProviderMetadata: test.SP.Metadata(), Request: LogoutRequest{NameID: &NameID{Value: "alice@example.com"}}}
	require.True(t, req.MatchesSession(nil, nil) != nil)

	// An SPNameQualifier can't be checked without the metadata of the service provider.
	req = &IdpLogoutRequest{IDP: &idp, Request: LogoutRequest{NameID: &NameID{SPNameQualifier: "https://sp.example.com", Value: "alice@example.com"}}}
	require.True(t, req.MatchesSession(nil, session) != nil)

	// The complete identifier can't be compared without it either, so only the value-only match succeeds.
	req.Request.NameID.SPNameQualifier = ""
	require.True(t, req.MatchesSession(nil, session) != nil)

	idp.LogoutNameIDValueOnly = true

	require.NoError(t, req.MatchesSession(nil, session))

	// The NameID of a session without a format was never asserted, even when only the value is compared.
	require.True(t, req.MatchesSession(nil, &Session{NameID: "alice@example.com"}) != nil)
}

// fixedParticipantProvider is a SessionProvider whose session participants are fixed.
type fixedParticipantProvider struct {
	mockSessionProvider

	participants []SessionParticipant
	err          error
}

func (p *fixedParticipantProvider) AddSessionParticipant(*http.Request, *Session, SessionParticipant) error {
	return nil
}

func (p *fixedParticipantProvider) SessionParticipants(*http.Request, *Session) ([]SessionParticipant, error) {
	return p.participants, p.err
}

func (p *fixedParticipantProvider) CloseSessionParticipants(r *http.Request, session *Session) ([]SessionParticipant, error) {
	return p.SessionParticipants(r, session)
}

// spProvidedID makes the recorded participant's NameID carry the SPProvidedID id.
func spProvidedID(id string) func(*fixedParticipantProvider) {
	return func(p *fixedParticipantProvider) { p.participants[0].NameID.SPProvidedID = id }
}

func TestIdpLogoutRequestMatchesParticipantNameID(t *testing.T) {
	test := NewIdentityProviderTest(t)
	sp := test.SP.Metadata()
	idpEntityID := test.IDP.Metadata().EntityID

	asserted := NameID{Format: string(TransientNameIDFormat), NameQualifier: idpEntityID, SPNameQualifier: sp.EntityID, Value: "abc"}
	with := func(change func(*NameID)) *NameID {
		n := asserted
		change(&n)

		return &n
	}

	testCases := []struct {
		name         string
		nameID       *NameID
		participant  string
		indexes      []SessionIndex
		valueOnly    bool
		participants func(p *fixedParticipantProvider)
		match        bool
	}{
		{name: "all four fields equal", nameID: with(func(*NameID) {}), match: true},
		{name: "value differs", nameID: with(func(n *NameID) { n.Value = "abd" })},
		{name: "format differs", nameID: with(func(n *NameID) { n.Format = string(PersistentNameIDFormat) })},
		{name: "name qualifier differs", nameID: with(func(n *NameID) { n.NameQualifier = "https://other.example.com" })},
		{name: "sp name qualifier differs", nameID: with(func(n *NameID) { n.SPNameQualifier = "https://other-sp.example.com" })},
		{name: "participant of another sp", nameID: with(func(*NameID) {}), participant: "https://other-sp.example.com"},
		{name: "sp provided id", nameID: with(func(n *NameID) { n.SPProvidedID = "x" })},
		// A NameIDProvider may assert an SPProvidedID, which the request must then carry (SAMLCore §8.3.7).
		{name: "recorded sp provided id", nameID: with(func(n *NameID) { n.SPProvidedID = "x" }), participants: spProvidedID("x"), match: true},
		{name: "recorded sp provided id omitted", nameID: with(func(*NameID) {}), participants: spProvidedID("x")},
		{name: "recorded sp provided id differs", nameID: with(func(n *NameID) { n.SPProvidedID = "y" }), participants: spProvidedID("x")},
		{name: "session index not listed", nameID: with(func(*NameID) {}), indexes: []SessionIndex{{Value: "other"}}},
		{name: "session index listed", nameID: with(func(*NameID) {}), indexes: []SessionIndex{{Value: "i1"}}, match: true},
		{name: "value only matches participant value", nameID: &NameID{Value: "abc"}, valueOnly: true, match: true},
		{name: "value only matches complete participant identifier", nameID: with(func(*NameID) {}), valueOnly: true, match: true},
		{name: "value only participant with other value", nameID: &NameID{Value: "abd"}, valueOnly: true},
		{name: "value only participant of another sp", nameID: &NameID{Value: "abc"}, participant: "https://other-sp.example.com", valueOnly: true},
		{name: "value only session index not listed", nameID: &NameID{Value: "abc"}, indexes: []SessionIndex{{Value: "other"}}, valueOnly: true},
		{name: "participants error", nameID: with(func(*NameID) {}), participants: func(p *fixedParticipantProvider) { p.err = errors.New("boom") }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			participantSP := tc.participant
			if participantSP == "" {
				participantSP = sp.EntityID
			}

			provider := &fixedParticipantProvider{participants: []SessionParticipant{{ServiceProviderEntityID: participantSP, NameID: asserted}}}
			if tc.participants != nil {
				tc.participants(provider)
			}

			idp := test.IDP
			idp.SessionProvider = provider
			idp.LogoutNameIDValueOnly = tc.valueOnly

			req := &IdpLogoutRequest{IDP: &idp, ServiceProviderMetadata: sp, Request: LogoutRequest{NameID: tc.nameID, SessionIndexes: tc.indexes}}
			err := req.MatchesSession(httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/slo", nil), &Session{NameID: "alice@example.com", Index: "i1"})

			if tc.match {
				require.NoError(t, err)
			} else {
				require.NotNil(t, err)
			}
		})
	}

	t.Run("participants error is returned", func(t *testing.T) {
		boom := errors.New("boom")
		idp := test.IDP
		idp.SessionProvider = &fixedParticipantProvider{err: boom}

		req := &IdpLogoutRequest{IDP: &idp, ServiceProviderMetadata: sp, Request: LogoutRequest{NameID: &asserted}}
		require.True(t, errors.Is(req.MatchesSession(nil, &Session{NameID: "alice@example.com"}), boom))
	})

	t.Run("affiliation", func(t *testing.T) {
		const affiliation = "https://affiliation.example.com"

		idp := test.IDP
		idp.SessionProvider = &fixedParticipantProvider{participants: []SessionParticipant{{
			ServiceProviderEntityID: sp.EntityID,
			NameID:                  NameID{Format: string(PersistentNameIDFormat), NameQualifier: idpEntityID, SPNameQualifier: affiliation, Value: "abc"},
		}}}

		nameID := NameID{Format: string(PersistentNameIDFormat), NameQualifier: idpEntityID, SPNameQualifier: affiliation, Value: "abc"}
		req := &IdpLogoutRequest{IDP: &idp, ServiceProviderMetadata: sp, Request: LogoutRequest{NameID: &nameID}}
		require.NoError(t, req.MatchesSession(nil, &Session{NameID: "alice@example.com"}))
	})
}
