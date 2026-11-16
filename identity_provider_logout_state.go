package saml

import (
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"sort"
	"time"
)

// LogoutOutcome is the result of the LogoutRequest sent to one participant of a logout.
type LogoutOutcome string

const (
	// LogoutOutcomePending means no result is known yet.
	LogoutOutcomePending LogoutOutcome = ""

	// LogoutOutcomeSuccess means the service provider reported that it ended the session.
	LogoutOutcomeSuccess LogoutOutcome = "success"

	// LogoutOutcomeFailed means the service provider reported a failure, or the request could not be completed.
	LogoutOutcomeFailed LogoutOutcome = "failed"

	// LogoutOutcomeSkipped means no LogoutRequest was sent to the service provider.
	LogoutOutcomeSkipped LogoutOutcome = "skipped"
)

// LogoutParticipant is one LogoutRequest of a logout: a service provider and the NameID it was given.
type LogoutParticipant struct {
	ServiceProviderEntityID string
	NameID                  NameID
	SessionIndexes          []string
	Outcome                 LogoutOutcome

	// Reason is a status code or error, for the application. It is never sent to a service provider.
	Reason string
}

// LogoutOrigin is the service provider whose LogoutRequest started a logout.
type LogoutOrigin struct {
	ServiceProviderEntityID string
	RequestID               string
	SLOEndpoint             Endpoint
	RelayState              string
}

// LogoutState is the state of a logout that is spread over several browser requests.
type LogoutState struct {
	ID           string
	ExpireTime   time.Time
	Participants []LogoutParticipant

	// Revision is incremented by the identity provider before each SaveLogoutState, which stores the state only if
	// it replaces the previous revision, so that two requests which loaded the same revision can't both advance it.
	Revision uint64

	// Current is the index into Participants of the outstanding request, or -1.
	Current int

	// PendingRequestID is the ID of the outstanding LogoutRequest.
	PendingRequestID string

	// SessionTerminated is set when every session of the logout was ended at the identity provider, including with
	// ErrPartialLogout.
	SessionTerminated bool

	// PartialLogout is set when TerminateSession returned ErrPartialLogout: the session at the identity provider was
	// ended, but the application knows of something else that is still logged in. It says nothing of the
	// participants, whose outcomes are in Participants.
	PartialLogout bool

	// ReturnURL is set for a logout that the identity provider initiated.
	ReturnURL string

	// Origin is set for a logout that a service provider initiated.
	Origin *LogoutOrigin
}

// ErrLogoutStateConflict is wrapped by the error of LogoutStateProvider.SaveLogoutState when the stored state is not
// the revision that state follows, as another request has advanced, finished or abandoned the logout.
var ErrLogoutStateConflict = errors.New("the logout state was changed by another request")

// LogoutStateProvider stores the LogoutState of logouts in progress. It is an optional interface of a SessionProvider.
type LogoutStateProvider interface {
	// SaveLogoutState stores state under state.ID if, and only if, the stored state has Revision state.Revision-1, or
	// no state is stored and state.Revision is 1. Otherwise it stores nothing and returns an error that wraps
	// ErrLogoutStateConflict. The comparison and the store must be atomic with respect to other calls with the same
	// ID, such as with a conditional write, as concurrent requests of one logout rely on it to make each step once.
	SaveLogoutState(r *http.Request, state *LogoutState) error

	// LoadLogoutState returns os.ErrNotExist if there is no state with the ID.
	LoadLogoutState(r *http.Request, id string) (*LogoutState, error)

	// DeleteLogoutState removes the state with the ID.
	DeleteLogoutState(r *http.Request, id string) error
}

// LogoutResult is the outcome of a logout which StartLogout began. Partial is the aggregate an application should
// use to tell the user whether the logout was complete: no single field says so on its own.
type LogoutResult struct {
	// StateID is the ID of the LogoutState of the logout, which is the RelayState of its LogoutRequests.
	StateID string

	// ReturnURL is the return URL that StartLogout was given.
	ReturnURL string

	// SessionTerminated is set when the session at the identity provider was ended.
	SessionTerminated bool

	// SessionPartialLogout is set when TerminateSession returned ErrPartialLogout. It is false when the session was
	// ended cleanly, even if a participant was left logged in, so it is not by itself a sign of success.
	SessionPartialLogout bool

	// Participants is the outcome of each LogoutRequest of the logout (SAMLProfiles §4.4.3.2).
	Participants []LogoutParticipant
}

// Partial reports whether anything was left logged in: the session, or any participant that didn't succeed. It is
// the aggregate of every other field, and is what an application should use to report the result of a logout.
func (r *LogoutResult) Partial() bool {
	if !r.SessionTerminated || r.SessionPartialLogout {
		return true
	}

	for _, participant := range r.Participants {
		if participant.Outcome != LogoutOutcomeSuccess {
			return true
		}
	}

	return false
}

// LogoutResultHandler is an optional interface of a SessionProvider. It completes the HTTP request at the end of a
// logout which StartLogout began. Without it the browser is redirected to the return URL.
type LogoutResultHandler interface {
	FinishLogout(w http.ResponseWriter, r *http.Request, result *LogoutResult)
}

func (idp *IdentityProvider) logoutStateLifetime() time.Duration {
	if idp.LogoutStateLifetime > 0 {
		return idp.LogoutStateLifetime
	}

	return 5 * time.Minute
}

type logoutGroupKey struct {
	entityID        string
	value           string
	format          string
	nameQualifier   string
	spNameQualifier string
}

// newLogoutState groups the participants into one LogoutParticipant for each service provider and NameID, ordered by
// the earliest IssueInstant of each group, leaving out the service provider with the excludeEntityID.
func newLogoutState(idp *IdentityProvider, participants []SessionParticipant, excludeEntityID string) *LogoutState {
	sorted := make([]SessionParticipant, 0, len(participants))

	for _, participant := range participants {
		if excludeEntityID != "" && participant.ServiceProviderEntityID == excludeEntityID {
			continue
		}

		sorted = append(sorted, participant)
	}

	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].IssueInstant.Before(sorted[j].IssueInstant)
	})

	state := &LogoutState{
		ID:         base64.RawURLEncoding.EncodeToString(randomBytes(32)),
		ExpireTime: TimeNow().Add(idp.logoutStateLifetime()),
		Current:    -1,
	}

	index := map[logoutGroupKey]int{}

	// A group with a member that was given no SessionIndex is sent no SessionIndexes, as a request that lists them
	// would leave that member's session alive (SAMLCore §3.7.3.2).
	unindexed := map[int]bool{}

	for _, participant := range sorted {
		key := logoutGroupKey{
			entityID:        participant.ServiceProviderEntityID,
			value:           participant.NameID.Value,
			format:          participant.NameID.Format,
			nameQualifier:   participant.NameID.NameQualifier,
			spNameQualifier: participant.NameID.SPNameQualifier,
		}

		i, ok := index[key]
		if !ok {
			i = len(state.Participants)
			index[key] = i

			state.Participants = append(state.Participants, LogoutParticipant{
				ServiceProviderEntityID: participant.ServiceProviderEntityID,
				NameID:                  participant.NameID,
			})
		}

		group := &state.Participants[i]

		if participant.SessionIndex == "" {
			unindexed[i], group.SessionIndexes = true, nil

			continue
		}

		if !unindexed[i] && !slices.Contains(group.SessionIndexes, participant.SessionIndex) {
			group.SessionIndexes = append(group.SessionIndexes, participant.SessionIndex)
		}
	}

	return state
}

func (s *LogoutState) result() *LogoutResult {
	return &LogoutResult{
		StateID:              s.ID,
		ReturnURL:            s.ReturnURL,
		SessionTerminated:    s.SessionTerminated,
		SessionPartialLogout: s.PartialLogout,
		Participants:         s.Participants,
	}
}

// status returns the status of the LogoutResponse to the service provider that started the logout: Responder if the
// session was not ended, and otherwise Success, with a PartialLogout second-level status if anything was left logged
// in (SAMLCore §3.7.3.2).
func (s *LogoutState) status() Status {
	switch {
	case !s.SessionTerminated:
		return Status{StatusCode: StatusCode{Value: StatusResponder}}
	case s.result().Partial():
		return Status{StatusCode: StatusCode{Value: StatusSuccess, StatusCode: &StatusCode{Value: StatusPartialLogout}}}
	default:
		return Status{StatusCode: StatusCode{Value: StatusSuccess}}
	}
}
