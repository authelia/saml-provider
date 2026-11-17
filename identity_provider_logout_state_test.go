package saml

import (
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
)

func logoutTestParticipants(base time.Time) []SessionParticipant {
	x := NameID{Value: "x", Format: "urn:format"}
	y := NameID{Value: "y"}
	z := NameID{Value: "z"}

	return []SessionParticipant{
		{ServiceProviderEntityID: "A", NameID: x, SessionIndex: "1", IssueInstant: base},
		{ServiceProviderEntityID: "A", NameID: x, SessionIndex: "2", IssueInstant: base.Add(time.Second)},
		{ServiceProviderEntityID: "A", NameID: x, SessionIndex: "1", IssueInstant: base.Add(2 * time.Second)},
		{ServiceProviderEntityID: "B", NameID: y, SessionIndex: "1", IssueInstant: base.Add(3 * time.Second)},
		{ServiceProviderEntityID: "A", NameID: z, SessionIndex: "3", IssueInstant: base.Add(4 * time.Second)},
	}
}

func TestNewLogoutStateGroupsParticipants(t *testing.T) {
	state := newLogoutState(&IdentityProvider{}, logoutTestParticipants(time.Unix(1000, 0)), "")

	assert.Equal(t, len(state.Participants), 3)
	assert.Equal(t, state.Participants[0].ServiceProviderEntityID, "A")
	assert.Equal(t, state.Participants[0].NameID.Value, "x")
	assert.DeepEqual(t, state.Participants[0].SessionIndexes, []string{"1", "2"})
	assert.Equal(t, state.Participants[1].ServiceProviderEntityID, "B")
	assert.DeepEqual(t, state.Participants[1].SessionIndexes, []string{"1"})
	assert.Equal(t, state.Participants[2].NameID.Value, "z")
	assert.DeepEqual(t, state.Participants[2].SessionIndexes, []string{"3"})

	for _, p := range state.Participants {
		assert.Equal(t, p.Outcome, LogoutOutcomePending)
	}
}

func TestNewLogoutStateGroupKeyIgnoresSPProvidedIDAndEmptyIndexes(t *testing.T) {
	base := time.Unix(1000, 0)

	state := newLogoutState(&IdentityProvider{}, []SessionParticipant{
		{ServiceProviderEntityID: "A", NameID: NameID{Value: "x", SPProvidedID: "p"}, SessionIndex: "", IssueInstant: base},
		{ServiceProviderEntityID: "A", NameID: NameID{Value: "x", SPProvidedID: "q"}, SessionIndex: "1", IssueInstant: base.Add(time.Second)},
		{ServiceProviderEntityID: "B", NameID: NameID{Value: "y"}, SessionIndex: "2", IssueInstant: base.Add(2 * time.Second)},
		{ServiceProviderEntityID: "B", NameID: NameID{Value: "y"}, SessionIndex: "", IssueInstant: base.Add(3 * time.Second)},
		{ServiceProviderEntityID: "C", NameID: NameID{Value: "z"}, SessionIndex: "3", IssueInstant: base.Add(4 * time.Second)},
	}, "")

	assert.Equal(t, len(state.Participants), 3)

	// A group with a member that has no SessionIndex is sent a request without any, whatever the order.
	assert.Check(t, cmp.Len(state.Participants[0].SessionIndexes, 0))
	assert.Check(t, cmp.Len(state.Participants[1].SessionIndexes, 0))
	assert.DeepEqual(t, state.Participants[2].SessionIndexes, []string{"3"})

	idp := &IdentityProvider{MetadataURL: mustParseURL("https://idp.example.com/metadata")}
	endpoint := &Endpoint{Location: "https://sp.example.com/slo"}

	assert.Check(t, cmp.Len(idp.makeLogoutRequest(state, &state.Participants[0], endpoint).SessionIndexes, 0))
	assert.Check(t, cmp.Len(idp.makeLogoutRequest(state, &state.Participants[1], endpoint).SessionIndexes, 0))
	assert.DeepEqual(t, idp.makeLogoutRequest(state, &state.Participants[2], endpoint).SessionIndexes, []SessionIndex{{Value: "3"}})
}

func TestNewLogoutStateOrdersByEarliestIssueInstant(t *testing.T) {
	base := time.Unix(1000, 0)

	state := newLogoutState(&IdentityProvider{}, []SessionParticipant{
		{ServiceProviderEntityID: "B", NameID: NameID{Value: "y"}, SessionIndex: "1", IssueInstant: base.Add(2 * time.Second)},
		{ServiceProviderEntityID: "A", NameID: NameID{Value: "x"}, SessionIndex: "1", IssueInstant: base},
	}, "")

	assert.Equal(t, state.Participants[0].ServiceProviderEntityID, "A")
	assert.Equal(t, state.Participants[1].ServiceProviderEntityID, "B")
}

func TestNewLogoutStateExcludesOrigin(t *testing.T) {
	state := newLogoutState(&IdentityProvider{}, logoutTestParticipants(time.Unix(1000, 0)), "A")

	assert.Equal(t, len(state.Participants), 1)
	assert.Equal(t, state.Participants[0].ServiceProviderEntityID, "B")
}

func TestNewLogoutStateID(t *testing.T) {
	now := time.Unix(2000, 0)
	TimeNow = func() time.Time { return now }

	defer func() { TimeNow = time.Now }()

	a := newLogoutState(&IdentityProvider{}, nil, "")
	b := newLogoutState(&IdentityProvider{}, nil, "")

	assert.Equal(t, len(a.ID), 43)
	assert.Assert(t, regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(a.ID))
	assert.Assert(t, a.ID != b.ID)
	assert.Assert(t, a.ExpireTime.Equal(now.Add(5*time.Minute)))
	assert.Equal(t, a.Current, -1)

	custom := newLogoutState(&IdentityProvider{LogoutStateLifetime: time.Hour}, nil, "")
	assert.Assert(t, custom.ExpireTime.Equal(now.Add(time.Hour)))
}

func TestLogoutResultPartial(t *testing.T) {
	testCases := []struct {
		name     string
		result   LogoutResult
		expected bool
	}{
		{"AllSucceeded", LogoutResult{SessionTerminated: true, Participants: []LogoutParticipant{{Outcome: LogoutOutcomeSuccess}}}, false},
		{"Skipped", LogoutResult{SessionTerminated: true, Participants: []LogoutParticipant{{Outcome: LogoutOutcomeSuccess}, {Outcome: LogoutOutcomeSkipped}}}, true},
		{"Failed", LogoutResult{SessionTerminated: true, Participants: []LogoutParticipant{{Outcome: LogoutOutcomeFailed}}}, true},
		{"SessionNotTerminated", LogoutResult{SessionTerminated: false}, true},
		{"SessionPartialLogout", LogoutResult{SessionTerminated: true, SessionPartialLogout: true}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.result.Partial(), tc.expected)
		})
	}
}

func TestLogoutStateResult(t *testing.T) {
	state := &LogoutState{
		ID:                "state-id",
		ReturnURL:         "https://idp.example.com/done",
		SessionTerminated: true,
		PartialLogout:     true,
		Participants:      []LogoutParticipant{{ServiceProviderEntityID: "A", Outcome: LogoutOutcomeSuccess}},
	}

	result := state.result()

	assert.Equal(t, result.StateID, "state-id")
	assert.Equal(t, result.ReturnURL, "https://idp.example.com/done")
	assert.Assert(t, result.SessionTerminated)
	assert.Assert(t, result.SessionPartialLogout)
	assert.DeepEqual(t, result.Participants, state.Participants)
}

func TestLogoutStateJSONRoundTrip(t *testing.T) {
	state := newLogoutState(&IdentityProvider{}, logoutTestParticipants(time.Unix(1000, 0)), "")
	state.ReturnURL = "https://idp.example.com/done"
	state.Origin = &LogoutOrigin{ServiceProviderEntityID: "A", RequestID: "id-1", RelayState: "rs"}
	state.Participants[0].Outcome = LogoutOutcomeFailed
	state.Participants[0].Reason = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	state.ExpireTime = state.ExpireTime.UTC()

	data, err := json.Marshal(state)
	assert.NilError(t, err)

	var out LogoutState

	assert.NilError(t, json.Unmarshal(data, &out))
	assert.Check(t, cmp.DeepEqual(state, &out))
}
