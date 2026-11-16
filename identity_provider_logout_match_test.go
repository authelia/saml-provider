package saml

import (
	"testing"

	"gotest.tools/assert"
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
		{name: "persistent format with empty session format", nameID: full(persistent), valueOnlyMatch: true},
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
				session := &Session{NameID: "alice@example.com", NameIDFormat: tc.sessionFormat, Index: "i1"}

				want := tc.match
				if valueOnly {
					want = tc.valueOnlyMatch
				}

				err := req.MatchesSession(session)
				if want {
					assert.NilError(t, err, "valueOnly=%t", valueOnly)
				} else {
					assert.Assert(t, err != nil, "valueOnly=%t", valueOnly)
				}
			}
		})
	}
}

func TestIdpLogoutRequestMatchesSessionNilPreconditions(t *testing.T) {
	test := NewIdentityProviderTest(t)
	idp := test.IDP
	session := &Session{NameID: "alice@example.com"}

	req := &IdpLogoutRequest{IDP: &idp, ServiceProviderMetadata: test.SP.Metadata(), Request: LogoutRequest{NameID: &NameID{Value: "alice@example.com"}}}
	assert.Assert(t, req.MatchesSession(nil) != nil)

	// An SPNameQualifier can't be checked without the metadata of the service provider.
	req = &IdpLogoutRequest{IDP: &idp, Request: LogoutRequest{NameID: &NameID{SPNameQualifier: "https://sp.example.com", Value: "alice@example.com"}}}
	assert.Assert(t, req.MatchesSession(session) != nil)

	// The complete identifier can't be compared without it either, so only the value-only match succeeds.
	req.Request.NameID.SPNameQualifier = ""
	assert.Assert(t, req.MatchesSession(session) != nil)

	idp.LogoutNameIDValueOnly = true

	assert.NilError(t, req.MatchesSession(session))
}
