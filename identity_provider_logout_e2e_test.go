package saml

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml/xmlenc"
)

const propagationReturnURL = "https://idp.example.com/logged-out"

// propagationSessionProvider is an in-memory SessionProvider which implements every interface of a propagated
// logout. It records the order of the calls made to it, the sessions it terminates and the final LogoutResult.
type propagationSessionProvider struct {
	mockSessionProvider
	memoryLogoutStateProvider

	sessions        []*Session
	participants    map[string][]SessionParticipant
	closed          map[string]bool
	participantsErr error
	terminateErr    error

	// saveErrAfter, if not zero, makes every save after that many fail with saveErrLater.
	saveErrAfter int
	saveErrLater error
	saves        int

	calls      []string
	terminated []*Session

	// stale, if set, is returned by the next LoadLogoutState in place of the stored state, as if the request had
	// loaded it before a concurrent request saved a newer revision.
	stale *LogoutState

	// finished counts the calls of FinishLogout.
	finished int

	// writtenBeforeTerminate is set if the response had been written to when TerminateSession was called.
	writtenBeforeTerminate bool

	result *LogoutResult
}

func (p *propagationSessionProvider) GetLogoutSessions(_ *http.Request, _ *IdpLogoutRequest) ([]*Session, error) {
	return p.sessions, nil
}

func (p *propagationSessionProvider) TerminateSession(w http.ResponseWriter, _ *http.Request, session *Session) error {
	p.calls = append(p.calls, "terminate "+session.ID)
	p.terminated = append(p.terminated, session)

	if recorder, ok := w.(*httptest.ResponseRecorder); ok && (recorder.Header().Get("Location") != "" || recorder.Body.Len() != 0) {
		p.writtenBeforeTerminate = true
	}

	return p.terminateErr
}

func (p *propagationSessionProvider) AddSessionParticipant(_ *http.Request, session *Session, participant SessionParticipant) error {
	if p.closed[session.ID] {
		return ErrSessionParticipantsClosed
	}

	p.participants[session.ID] = append(p.participants[session.ID], participant)

	return nil
}

func (p *propagationSessionProvider) CloseSessionParticipants(_ *http.Request, session *Session) ([]SessionParticipant, error) {
	p.calls = append(p.calls, "participants "+session.ID)

	if p.participantsErr != nil {
		return nil, p.participantsErr
	}

	if p.closed == nil {
		p.closed = map[string]bool{}
	}

	p.closed[session.ID] = true

	return p.participants[session.ID], nil
}

func (p *propagationSessionProvider) SessionParticipants(_ *http.Request, session *Session) ([]SessionParticipant, error) {
	return p.participants[session.ID], nil
}

func (p *propagationSessionProvider) SaveLogoutState(r *http.Request, state *LogoutState) error {
	p.calls = append(p.calls, "save")
	p.saves++

	if p.saveErrAfter != 0 && p.saves > p.saveErrAfter {
		return p.saveErrLater
	}

	return p.memoryLogoutStateProvider.SaveLogoutState(r, state)
}

func (p *propagationSessionProvider) LoadLogoutState(r *http.Request, id string) (*LogoutState, error) {
	if stale := p.stale; stale != nil {
		p.stale = nil

		return stale, nil
	}

	return p.memoryLogoutStateProvider.LoadLogoutState(r, id)
}

func (p *propagationSessionProvider) FinishLogout(w http.ResponseWriter, _ *http.Request, result *LogoutResult) {
	p.result = result
	p.finished++

	w.WriteHeader(http.StatusNoContent)
}

// withoutResultHandler hides the LogoutResultHandler of a propagationSessionProvider.
type withoutResultHandler struct {
	SessionProvider
	LogoutSessionProvider
	SessionParticipantProvider
	LogoutStateProvider
}

// withoutLogoutState hides the LogoutStateProvider of a propagationSessionProvider.
type withoutLogoutState struct {
	SessionProvider
	LogoutSessionProvider
	SessionParticipantProvider
}

// propagationFixture is an identity provider with two service providers, A and B, which both took part in one
// session.
type propagationFixture struct {
	test     *IdentityProviderTest
	a, b     *ServiceProvider
	provider *propagationSessionProvider
	session  *Session
}

func newPropagationFixture(t *testing.T) *propagationFixture {
	t.Helper()

	test, _ := logoutTestIDP(t)
	test.SP.LogoutBindings = []string{HTTPRedirectBinding}

	b := test.SP
	b.MetadataURL = mustParseURL("https://sp-b.example.com/saml2/metadata")
	b.AcsURL = mustParseURL("https://sp-b.example.com/saml2/acs")
	b.SloURL = mustParseURL("https://sp-b.example.com/saml2/slo")
	b.Key, b.Certificate = propagationServiceProviderKey(t)

	f := &propagationFixture{test: test, a: &test.SP, b: &b, session: &Session{ID: "session-one", NameID: "alice", Index: "index-one"}}

	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			for _, sp := range []*ServiceProvider{f.a, f.b} {
				if serviceProviderID == sp.MetadataURL.String() {
					return sp.Metadata(), nil
				}
			}

			return nil, os.ErrNotExist
		},
	}

	f.provider = &propagationSessionProvider{sessions: []*Session{f.session}, participants: map[string][]SessionParticipant{}}
	test.IDP.SessionProvider = f.provider

	for i, sp := range []*ServiceProvider{f.a, f.b} {
		assert.NilError(t, f.provider.AddSessionParticipant(nil, f.session, SessionParticipant{
			ServiceProviderEntityID: sp.MetadataURL.String(),
			NameID: NameID{
				Format:          string(PersistentNameIDFormat),
				Value:           "alice",
				NameQualifier:   test.IDP.Metadata().EntityID,
				SPNameQualifier: sp.MetadataURL.String(),
			},
			SessionIndex: f.session.Index,
			IssueInstant: TimeNow().Add(time.Duration(i) * time.Second),
		}))
	}

	return f
}

// propagationServiceProviderKey returns a signing key and certificate for a second service provider, as the
// fixtures share one key.
func propagationServiceProviderKey(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sp-b"},
		NotBefore:    time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	assert.NilError(t, err)
	certificate, err := x509.ParseCertificate(der)
	assert.NilError(t, err)

	return key, certificate
}

func (f *propagationFixture) startLogout(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()

	w := httptest.NewRecorder()
	assert.NilError(t, f.test.IDP.StartLogout(w, httptest.NewRequest(http.MethodGet, "/logout", nil), f.session, propagationReturnURL))

	return w
}

// sentLogoutRequest returns where the identity provider sent a LogoutRequest, with its SAMLRequest and RelayState
// in the query. A request on the HTTP-POST binding is in the query as it was in the form, without SigAlg.
func sentLogoutRequest(t *testing.T, w *httptest.ResponseRecorder) *url.URL {
	t.Helper()

	if w.Code == http.StatusFound {
		location, err := url.Parse(w.Header().Get("Location"))
		assert.NilError(t, err)

		return location
	}

	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())
	body := w.Body.String()
	attribute := func(marker string) string {
		start := strings.Index(body, marker)
		assert.Assert(t, start >= 0, "no %s in %q", marker, body)
		value, _, _ := strings.Cut(body[start+len(marker):], `"`)

		return html.UnescapeString(value)
	}

	location, err := url.Parse(attribute(`action="`))
	assert.NilError(t, err)

	location.RawQuery = url.Values{
		"SAMLRequest": {attribute(`name="SAMLRequest" value="`)},
		"RelayState":  {attribute(`name="RelayState" value="`)},
	}.Encode()

	return location
}

// respondAsSP is the service provider at location: it verifies the identity provider's LogoutRequest, checks that
// it names alice's session, and returns its signed HTTP-Redirect LogoutResponse.
func respondAsSP(t *testing.T, sp *ServiceProvider, location *url.URL) *http.Request {
	t.Helper()

	return respondAsSPWithStatus(t, sp, location, StatusSuccess)
}

func respondAsSPWithStatus(t *testing.T, sp *ServiceProvider, location *url.URL, status string) *http.Request {
	t.Helper()

	return respondAsSPWithStatusCode(t, sp, location, StatusCode{Value: status})
}

// respondAsSPWithStatusCode is respondAsSP answering with the status code, which may have a second-level code.
func respondAsSPWithStatusCode(t *testing.T, sp *ServiceProvider, location *url.URL, code StatusCode) *http.Request {
	t.Helper()

	return respondAsSPForNameID(t, sp, location, code, "alice")
}

// respondAsSPForNameID is respondAsSPWithStatusCode for a LogoutRequest that names the NameID value.
func respondAsSPForNameID(t *testing.T, sp *ServiceProvider, location *url.URL, code StatusCode, value string) *http.Request {
	t.Helper()

	assert.Check(t, is.Equal(location.Scheme+"://"+location.Host+location.Path, sp.SloURL.String()))

	certificates, err := sp.getIDPSigningCerts()
	assert.NilError(t, err)

	encoded, err := base64.StdEncoding.DecodeString(location.Query().Get("SAMLRequest"))
	assert.NilError(t, err)

	var request LogoutRequest

	if location.Query().Has("SigAlg") {
		assert.NilError(t, verifyRedirectSignature(location.RawQuery, "SAMLRequest", certificates))

		buf, err := io.ReadAll(flate.NewReader(bytes.NewReader(encoded)))
		assert.NilError(t, err)
		assert.NilError(t, xml.Unmarshal(buf, &request))
	} else {
		doc := etree.NewDocument()
		assert.NilError(t, doc.ReadFromBytes(encoded))
		verified, err := verifyEnvelopedSignature(doc.Root(), certificates)
		assert.NilError(t, err)
		assert.NilError(t, unmarshalElement(verified, &request))
	}

	assert.Assert(t, request.NameID != nil)
	assert.Check(t, is.Equal(request.NameID.Value, value))
	assert.Check(t, is.Equal(request.NameID.SPNameQualifier, sp.MetadataURL.String()))
	assert.Check(t, is.DeepEqual(request.SessionIndexes, []SessionIndex{{Value: "index-one"}}))
	assert.Check(t, is.Equal(request.Destination, sp.SloURL.String()))

	relayState := location.Query().Get("RelayState")

	var u *url.URL

	if code.Value == StatusSuccess && code.StatusCode == nil {
		u, err = sp.MakeRedirectLogoutResponse(request.ID, relayState)
		assert.NilError(t, err)
	} else {
		response, err := sp.MakeLogoutResponse(sp.GetSLOBindingLocation(HTTPRedirectBinding), request.ID)
		assert.NilError(t, err)

		response.Status.StatusCode = code
		u, err = response.Redirect(relayState, sp)
		assert.NilError(t, err)
	}

	return httptest.NewRequest(http.MethodGet, u.String(), nil)
}

// participantOutcomes returns the outcome of each participant, by entity ID.
func participantOutcomes(participants []LogoutParticipant) map[string]LogoutOutcome {
	outcomes := map[string]LogoutOutcome{}
	for _, participant := range participants {
		outcomes[participant.ServiceProviderEntityID] = participant.Outcome
	}

	return outcomes
}

func TestStartLogoutVisitsEveryParticipant(t *testing.T) {
	for _, binding := range []string{HTTPRedirectBinding, HTTPPostBinding} {
		t.Run(binding, func(t *testing.T) {
			f := newPropagationFixture(t)
			f.b.LogoutBindings = []string{binding}

			w := f.startLogout(t)
			assert.Check(t, is.DeepEqual(f.provider.calls, []string{"participants session-one", "save", "terminate session-one", "save"}))
			assert.Check(t, !f.provider.writtenBeforeTerminate)
			assert.Check(t, is.DeepEqual(f.provider.terminated, []*Session{f.session}))

			// The participants were closed when the logout began, so a service provider can't be added that the
			// logout won't reach.
			err := f.provider.AddSessionParticipant(nil, f.session, SessionParticipant{ServiceProviderEntityID: "https://sp-c.example.com"})
			assert.Check(t, errors.Is(err, ErrSessionParticipantsClosed))

			w = serveSLO(f.test, respondAsSP(t, f.a, sentLogoutRequest(t, w)))
			assert.Check(t, f.provider.result == nil)

			w = serveSLO(f.test, respondAsSP(t, f.b, sentLogoutRequest(t, w)))
			assert.Check(t, is.Equal(w.Code, http.StatusNoContent))

			assert.Assert(t, f.provider.result != nil)
			assert.Check(t, f.provider.result.SessionTerminated)
			assert.Check(t, !f.provider.result.Partial())
			assert.Check(t, is.DeepEqual(participantOutcomes(f.provider.result.Participants), map[string]LogoutOutcome{
				f.a.MetadataURL.String(): LogoutOutcomeSuccess,
				f.b.MetadataURL.String(): LogoutOutcomeSuccess,
			}))
			assert.Check(t, is.Len(f.provider.states, 0))
			assert.Check(t, is.Len(f.provider.deleted, 1))
		})
	}
}

func TestStartLogoutWithoutResultHandlerRedirects(t *testing.T) {
	f := newPropagationFixture(t)
	f.test.IDP.SessionProvider = withoutResultHandler{f.provider, f.provider, f.provider, f.provider}

	w := f.startLogout(t)
	w = serveSLO(f.test, respondAsSP(t, f.a, sentLogoutRequest(t, w)))
	w = serveSLO(f.test, respondAsSP(t, f.b, sentLogoutRequest(t, w)))

	assert.Check(t, is.Equal(w.Code, http.StatusFound))
	assert.Check(t, is.Equal(w.Header().Get("Location"), propagationReturnURL))
	assert.Check(t, f.provider.result == nil)
	assert.Check(t, is.Len(f.provider.states, 0))
}

func TestStartLogoutNoParticipants(t *testing.T) {
	f := newPropagationFixture(t)
	f.provider.participants = map[string][]SessionParticipant{}
	f.test.IDP.SessionProvider = withoutResultHandler{f.provider, f.provider, f.provider, f.provider}

	w := f.startLogout(t)
	assert.Check(t, is.Equal(w.Code, http.StatusFound))
	assert.Check(t, is.Equal(w.Header().Get("Location"), propagationReturnURL))
	assert.Check(t, is.DeepEqual(f.provider.terminated, []*Session{f.session}))
	assert.Check(t, is.Len(f.provider.states, 0))
	assert.Check(t, is.Len(f.provider.deleted, 1))
}

func TestStartLogoutRequiresInterfaces(t *testing.T) {
	f := newPropagationFixture(t)
	f.test.IDP.SessionProvider = withoutLogoutState{f.provider, f.provider, f.provider}

	w := httptest.NewRecorder()
	err := f.test.IDP.StartLogout(w, httptest.NewRequest(http.MethodGet, "/logout", nil), f.session, propagationReturnURL)
	assert.Check(t, is.ErrorContains(err, "LogoutStateProvider"))
	assert.Check(t, is.Equal(w.Code, http.StatusOK))
	assert.Check(t, is.Equal(w.Body.Len(), 0))
	assert.Check(t, is.Len(w.Header(), 0))
	assert.Check(t, is.Len(f.provider.terminated, 0))
}

func TestStartLogoutRequiresReturnURLWithoutResultHandler(t *testing.T) {
	f := newPropagationFixture(t)
	f.test.IDP.SessionProvider = withoutResultHandler{f.provider, f.provider, f.provider, f.provider}

	w := httptest.NewRecorder()
	err := f.test.IDP.StartLogout(w, httptest.NewRequest(http.MethodGet, "/logout", nil), f.session, "")
	assert.Check(t, is.ErrorContains(err, "without a return URL"))
	assert.Check(t, !errors.Is(err, ErrLogoutNotPropagated))
	assert.Check(t, is.Equal(w.Code, http.StatusOK))
	assert.Check(t, is.Equal(w.Body.Len(), 0))
	assert.Check(t, is.Len(w.Header(), 0))
	assert.Check(t, is.Len(f.provider.calls, 0))
	assert.Check(t, is.Len(f.provider.terminated, 0))
}

func TestStartLogoutWithResultHandlerAllowsEmptyReturnURL(t *testing.T) {
	f := newPropagationFixture(t)

	w := httptest.NewRecorder()
	assert.NilError(t, f.test.IDP.StartLogout(w, httptest.NewRequest(http.MethodGet, "/logout", nil), f.session, ""))
	assert.Check(t, is.Equal(w.Code, http.StatusFound))
}

func TestStartLogoutWritesNothingWhenItCannotBegin(t *testing.T) {
	for name, fail := range map[string]func(*propagationSessionProvider){
		"participants": func(p *propagationSessionProvider) { p.participantsErr = errors.New("storage unavailable") },
		"save":         func(p *propagationSessionProvider) { p.saveErr = errors.New("storage unavailable") },
	} {
		t.Run(name, func(t *testing.T) {
			f := newPropagationFixture(t)
			fail(f.provider)

			w := httptest.NewRecorder()
			err := f.test.IDP.StartLogout(w, httptest.NewRequest(http.MethodGet, "/logout", nil), f.session, propagationReturnURL)
			assert.Check(t, errors.Is(err, ErrLogoutNotPropagated), "error: %v", err)
			assert.Check(t, is.ErrorContains(err, "storage unavailable"))
			assert.Check(t, is.Equal(w.Code, http.StatusOK))
			assert.Check(t, is.Equal(w.Body.Len(), 0))
			assert.Check(t, is.Equal(w.Header().Get("Location"), ""))
			assert.Check(t, is.DeepEqual(f.provider.terminated, []*Session{f.session}))
			assert.Check(t, f.provider.result == nil)
		})
	}
}

func TestStartLogoutCannotBeginAndTerminationFails(t *testing.T) {
	for name, fail := range map[string]func(*propagationSessionProvider){
		"participants": func(p *propagationSessionProvider) { p.participantsErr = errors.New("storage unavailable") },
		"save":         func(p *propagationSessionProvider) { p.saveErr = errors.New("storage unavailable") },
	} {
		t.Run(name, func(t *testing.T) {
			f := newPropagationFixture(t)
			fail(f.provider)
			f.provider.terminateErr = errors.New("session store down")

			w := httptest.NewRecorder()
			err := f.test.IDP.StartLogout(w, httptest.NewRequest(http.MethodGet, "/logout", nil), f.session, propagationReturnURL)
			assert.Assert(t, err != nil)
			assert.Check(t, !errors.Is(err, ErrLogoutNotPropagated), "error: %v", err)
			assert.Check(t, is.ErrorContains(err, "storage unavailable"))
			assert.Check(t, is.ErrorContains(err, "session store down"))
			assert.Check(t, is.Equal(w.Code, http.StatusOK))
			assert.Check(t, is.Equal(w.Body.Len(), 0))
			assert.Check(t, is.DeepEqual(f.provider.terminated, []*Session{f.session}))
		})
	}
}

func TestStartLogoutCannotBeginWithPartialTermination(t *testing.T) {
	f := newPropagationFixture(t)
	f.provider.saveErr = errors.New("storage unavailable")
	f.provider.terminateErr = ErrPartialLogout

	err := f.test.IDP.StartLogout(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/logout", nil), f.session, propagationReturnURL)
	assert.Check(t, errors.Is(err, ErrLogoutNotPropagated), "error: %v", err)
}

func TestStartLogoutSaveFailureDuringSequenceFinishes(t *testing.T) {
	f := newPropagationFixture(t)
	f.provider.saveErrAfter, f.provider.saveErrLater = 1, errors.New("storage unavailable")

	w := f.startLogout(t)
	assert.Check(t, is.Equal(w.Code, http.StatusNoContent))
	assert.Check(t, is.DeepEqual(f.provider.terminated, []*Session{f.session}))

	assert.Assert(t, f.provider.result != nil)
	assert.Check(t, f.provider.result.SessionTerminated)
	assert.Check(t, f.provider.result.Partial())
	assert.Check(t, is.Equal(f.provider.result.ReturnURL, propagationReturnURL))
	assert.Check(t, f.provider.result.StateID != "")

	for _, participant := range f.provider.result.Participants {
		assert.Check(t, is.Equal(participant.Outcome, LogoutOutcomeFailed))
		assert.Check(t, is.Contains(participant.Reason, "storage unavailable"))
	}

	assert.Check(t, is.Len(f.provider.result.Participants, 2))
}

// serveSLOFromA sends A's signed LogoutRequest, and returns the answer and the ID of the request.
func (f *propagationFixture) serveSLOFromA(t *testing.T) (*httptest.ResponseRecorder, string) {
	t.Helper()

	r, id := redirectLogoutRequest(t, f.a, nil)

	return serveSLO(f.test, r), id
}

func TestServeSLOPropagates(t *testing.T) {
	f := newPropagationFixture(t)

	w, id := f.serveSLOFromA(t)
	assert.Check(t, is.DeepEqual(f.provider.terminated, []*Session{f.session}))
	assert.Check(t, !f.provider.writtenBeforeTerminate)

	w = serveSLO(f.test, respondAsSP(t, f.b, sentLogoutRequest(t, w)))

	location, response := redirectedLogoutResponse(t, w)
	assert.Check(t, is.Equal(location.Scheme+"://"+location.Host+location.Path, f.a.SloURL.String()))
	assert.Check(t, is.Equal(location.Query().Get("RelayState"), "relay"))
	assert.Check(t, is.Equal(response.InResponseTo, id))
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	assert.Check(t, response.Status.StatusCode.StatusCode == nil)
	assert.Check(t, f.a.ValidateLogoutResponseRedirect(location, []string{id}))
	assert.Check(t, f.provider.result == nil, "the service provider is answered, not the result handler")
	assert.Check(t, is.Len(f.provider.states, 0))
}

func TestServeSLOPartialWhenParticipantFails(t *testing.T) {
	f := newPropagationFixture(t)

	w, id := f.serveSLOFromA(t)
	w = serveSLO(f.test, respondAsSPWithStatus(t, f.b, sentLogoutRequest(t, w), StatusRequester))

	location, response := redirectedLogoutResponse(t, w)
	assert.Check(t, is.Equal(response.InResponseTo, id))
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	assert.Assert(t, response.Status.StatusCode.StatusCode != nil)
	assert.Check(t, is.Equal(response.Status.StatusCode.StatusCode.Value, StatusPartialLogout))
	assert.Check(t, f.a.ValidateLogoutResponseRedirect(location, []string{id}))
}

func TestServeSLOPartialWhenParticipantPartiallyLogsOut(t *testing.T) {
	f := newPropagationFixture(t)

	w, id := f.serveSLOFromA(t)
	w = serveSLO(f.test, respondAsSPWithStatusCode(t, f.b, sentLogoutRequest(t, w), StatusCode{
		Value:      StatusSuccess,
		StatusCode: &StatusCode{Value: StatusPartialLogout},
	}))

	location, response := redirectedLogoutResponse(t, w)
	assert.Check(t, is.Equal(response.InResponseTo, id))
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	assert.Assert(t, response.Status.StatusCode.StatusCode != nil)
	assert.Check(t, is.Equal(response.Status.StatusCode.StatusCode.Value, StatusPartialLogout))
	assert.Check(t, f.a.ValidateLogoutResponseRedirect(location, []string{id}))
}

func TestStartLogoutParticipantPartialLogoutIsFailed(t *testing.T) {
	f := newPropagationFixture(t)

	w := f.startLogout(t)
	w = serveSLO(f.test, respondAsSPWithStatusCode(t, f.a, sentLogoutRequest(t, w), StatusCode{
		Value:      StatusSuccess,
		StatusCode: &StatusCode{Value: StatusPartialLogout},
	}))
	w = serveSLO(f.test, respondAsSP(t, f.b, sentLogoutRequest(t, w)))
	assert.Check(t, is.Equal(w.Code, http.StatusNoContent))

	assert.Assert(t, f.provider.result != nil)
	assert.Check(t, f.provider.result.Partial())
	assert.Check(t, is.Equal(f.provider.result.Participants[0].Outcome, LogoutOutcomeFailed))
	assert.Check(t, is.Equal(f.provider.result.Participants[0].Reason, StatusPartialLogout))
	assert.Check(t, is.Equal(f.provider.result.Participants[1].Outcome, LogoutOutcomeSuccess))
}

func TestServeSLOPartialWhenSaveFailsDuringSequence(t *testing.T) {
	f := newPropagationFixture(t)
	f.provider.saveErrAfter, f.provider.saveErrLater = 1, errors.New("storage unavailable")

	w, id := f.serveSLOFromA(t)

	location, response := redirectedLogoutResponse(t, w)
	assert.Check(t, is.Equal(location.Scheme+"://"+location.Host+location.Path, f.a.SloURL.String()))
	assert.Check(t, is.Equal(response.InResponseTo, id))
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	assert.Assert(t, response.Status.StatusCode.StatusCode != nil)
	assert.Check(t, is.Equal(response.Status.StatusCode.StatusCode.Value, StatusPartialLogout))
	assert.Check(t, f.a.ValidateLogoutResponseRedirect(location, []string{id}))
	assert.Check(t, is.DeepEqual(f.provider.terminated, []*Session{f.session}))

	// The state couldn't be claimed, so it is left to expire rather than deleted, as it may be a newer revision.
	assert.Check(t, is.Len(f.provider.deleted, 0))
}

func TestServeSLOResponderWhenTerminationFails(t *testing.T) {
	f := newPropagationFixture(t)
	f.provider.terminateErr = errors.New("storage unavailable")

	w, id := f.serveSLOFromA(t)
	w = serveSLO(f.test, respondAsSP(t, f.b, sentLogoutRequest(t, w)))

	_, response := redirectedLogoutResponse(t, w)
	assert.Check(t, is.Equal(response.InResponseTo, id))
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusResponder))
	assert.Check(t, response.Status.StatusMessage == nil)
}

func TestServeSLOWithoutPropagationInterfacesUnchanged(t *testing.T) {
	test, provider := logoutTestIDP(t)

	r, id := redirectLogoutRequest(t, &test.SP, nil)
	location, response := redirectedLogoutResponse(t, serveSLO(test, r))
	assert.Check(t, is.Equal(location.Scheme+"://"+location.Host+location.Path, test.SP.SloURL.String()))
	assert.Check(t, is.Equal(response.InResponseTo, id))
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	assert.Check(t, test.SP.ValidateLogoutResponseRedirect(location, []string{id}))
	assert.Check(t, is.Len(provider.terminated, 1))
}

func TestServeSLOResponseUnknownState(t *testing.T) {
	f := newPropagationFixture(t)

	u, err := f.a.MakeRedirectLogoutResponse("id-unknown", "unknown-state")
	assert.NilError(t, err)

	w := serveSLO(f.test, httptest.NewRequest(http.MethodGet, u.String(), nil))
	assert.Check(t, is.Equal(w.Code, http.StatusBadRequest))
	assert.Check(t, f.provider.result == nil)
	assert.Check(t, is.Len(f.provider.deleted, 0))
}

func TestServeSLOResponseExpiredState(t *testing.T) {
	f := newPropagationFixture(t)

	w := f.startLogout(t)
	location := sentLogoutRequest(t, w)
	stateID := location.Query().Get("RelayState")
	f.provider.states[stateID].ExpireTime = TimeNow().Add(-time.Second)

	w = serveSLO(f.test, respondAsSP(t, f.a, location))
	assert.Check(t, is.Equal(w.Code, http.StatusBadRequest))
	assert.Check(t, f.provider.result == nil)
	assert.Check(t, is.Len(f.provider.deleted, 0))
	assert.Check(t, is.Equal(f.provider.states[stateID].Participants[0].Outcome, LogoutOutcomePending))
}

func TestServeSLOResponseForgedMarksFailed(t *testing.T) {
	f := newPropagationFixture(t)

	w := f.startLogout(t)

	unsigned := *f.a
	unsigned.SignatureMethod = ""
	w = serveSLO(f.test, respondAsSP(t, &unsigned, sentLogoutRequest(t, w)))
	w = serveSLO(f.test, respondAsSP(t, f.b, sentLogoutRequest(t, w)))
	assert.Check(t, is.Equal(w.Code, http.StatusNoContent))

	assert.Assert(t, f.provider.result != nil)
	assert.Check(t, f.provider.result.Partial())
	assert.Check(t, is.DeepEqual(participantOutcomes(f.provider.result.Participants), map[string]LogoutOutcome{
		f.a.MetadataURL.String(): LogoutOutcomeFailed,
		f.b.MetadataURL.String(): LogoutOutcomeSuccess,
	}))
	assert.Check(t, is.Contains(f.provider.result.Participants[0].Reason, "not signed"))
}

func TestServeSLOResponseReplayedLeavesOutstandingParticipant(t *testing.T) {
	f := newPropagationFixture(t)

	w := f.startLogout(t)
	stale := respondAsSP(t, f.a, sentLogoutRequest(t, w))
	w = serveSLO(f.test, stale)
	toB := sentLogoutRequest(t, w)
	stateID := toB.Query().Get("RelayState")
	before := *f.provider.states[stateID]

	// A's response is resubmitted while the request to B is outstanding.
	w = serveSLO(f.test, httptest.NewRequest(http.MethodGet, stale.URL.String(), nil))
	assert.Check(t, is.Equal(w.Code, http.StatusBadRequest))
	assert.Check(t, f.provider.result == nil)

	after := f.provider.states[stateID]
	assert.Check(t, is.Equal(after.Current, before.Current))
	assert.Check(t, is.Equal(after.PendingRequestID, before.PendingRequestID))
	assert.Check(t, is.Equal(after.Participants[1].Outcome, LogoutOutcomePending))

	// B's own response is still accepted.
	w = serveSLO(f.test, respondAsSP(t, f.b, toB))
	assert.Check(t, is.Equal(w.Code, http.StatusNoContent))
	assert.Assert(t, f.provider.result != nil)
	assert.Check(t, !f.provider.result.Partial())
}

func TestServeSLOResponseConcurrentCopiesConflict(t *testing.T) {
	f := newPropagationFixture(t)

	w := f.startLogout(t)
	fromA := respondAsSP(t, f.a, sentLogoutRequest(t, w))
	stateID := fromA.URL.Query().Get("RelayState")

	// Two copies of A's response load the same revision; the first advances the logout to B.
	stale, err := f.provider.memoryLogoutStateProvider.LoadLogoutState(nil, stateID)
	assert.NilError(t, err)

	w = serveSLO(f.test, fromA)
	toB := sentLogoutRequest(t, w)
	advanced := *f.provider.states[stateID]

	// The second can't overwrite that progress with a request to B of its own.
	f.provider.stale = stale
	w = serveSLO(f.test, httptest.NewRequest(http.MethodGet, fromA.URL.String(), nil))
	assert.Check(t, is.Equal(w.Code, http.StatusConflict))
	assert.Check(t, is.Equal(f.provider.states[stateID].Revision, advanced.Revision))
	assert.Check(t, is.Equal(f.provider.states[stateID].PendingRequestID, advanced.PendingRequestID))

	// Two copies of B's response: the first finishes the logout, and the second can't finish it again or recreate the
	// deleted state.
	fromB := respondAsSP(t, f.b, toB)
	stale, err = f.provider.memoryLogoutStateProvider.LoadLogoutState(nil, stateID)
	assert.NilError(t, err)

	w = serveSLO(f.test, fromB)
	assert.Check(t, is.Equal(w.Code, http.StatusNoContent))
	assert.Assert(t, f.provider.result != nil)
	assert.Check(t, !f.provider.result.Partial())

	f.provider.stale = stale
	w = serveSLO(f.test, httptest.NewRequest(http.MethodGet, fromB.URL.String(), nil))
	assert.Check(t, is.Equal(w.Code, http.StatusConflict))
	assert.Check(t, is.Equal(f.provider.finished, 1))
	assert.Check(t, is.Len(f.provider.states, 0))
}

// postedInstead returns the LogoutResponse of the HTTP-Redirect request r on the HTTP-POST binding instead, with an
// enveloped signature by sp.
func postedInstead(t *testing.T, sp *ServiceProvider, r *http.Request) *http.Request {
	t.Helper()

	compressed, err := base64.StdEncoding.DecodeString(r.URL.Query().Get("SAMLResponse"))
	assert.NilError(t, err)
	buf, err := io.ReadAll(flate.NewReader(bytes.NewReader(compressed)))
	assert.NilError(t, err)

	var response LogoutResponse
	assert.NilError(t, xml.Unmarshal(buf, &response))
	assert.NilError(t, sp.SignLogoutResponse(&response))

	doc := etree.NewDocument()
	doc.SetRoot(response.Element())
	body, err := doc.WriteToBytes()
	assert.NilError(t, err)

	form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(body)}, "RelayState": {r.URL.Query().Get("RelayState")}}
	posted := httptest.NewRequest(http.MethodPost, logoutTestSLOURL, strings.NewReader(form.Encode()))
	posted.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return posted
}

func TestServeSLOResponsePost(t *testing.T) {
	f := newPropagationFixture(t)

	w := f.startLogout(t)
	w = serveSLO(f.test, postedInstead(t, f.a, respondAsSP(t, f.a, sentLogoutRequest(t, w))))
	w = serveSLO(f.test, postedInstead(t, f.b, respondAsSP(t, f.b, sentLogoutRequest(t, w))))
	assert.Check(t, is.Equal(w.Code, http.StatusNoContent))

	assert.Assert(t, f.provider.result != nil)
	assert.Check(t, !f.provider.result.Partial())
}

func TestServeSLOEndsSessionWhenPropagationCannotBegin(t *testing.T) {
	for name, fail := range map[string]func(*propagationSessionProvider){
		"participants": func(p *propagationSessionProvider) { p.participantsErr = errors.New("storage unavailable") },
		"save":         func(p *propagationSessionProvider) { p.saveErr = errors.New("storage unavailable") },
	} {
		t.Run(name, func(t *testing.T) {
			f := newPropagationFixture(t)
			fail(f.provider)

			w, id := f.serveSLOFromA(t)

			location, response := redirectedLogoutResponse(t, w)
			assert.Check(t, is.Equal(response.InResponseTo, id))
			assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
			assert.Assert(t, response.Status.StatusCode.StatusCode != nil)
			assert.Check(t, is.Equal(response.Status.StatusCode.StatusCode.Value, StatusPartialLogout))
			assert.Check(t, f.a.ValidateLogoutResponseRedirect(location, []string{id}))
			assert.Check(t, is.DeepEqual(f.provider.terminated, []*Session{f.session}))
		})
	}
}

func TestServeSLOResponderWhenPropagationCannotBeginAndTerminationFails(t *testing.T) {
	f := newPropagationFixture(t)
	f.provider.saveErr = errors.New("storage unavailable")
	f.provider.terminateErr = errors.New("storage unavailable")

	w, id := f.serveSLOFromA(t)

	_, response := redirectedLogoutResponse(t, w)
	assert.Check(t, is.Equal(response.InResponseTo, id))
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusResponder))
	assert.Check(t, response.Status.StatusCode.StatusCode == nil)
	assert.Check(t, is.DeepEqual(f.provider.terminated, []*Session{f.session}))
}

// matchingLogoutSessionProvider returns only the sessions that the request matches through MatchesSession, as a
// real LogoutSessionProvider does.
type matchingLogoutSessionProvider struct {
	*propagationSessionProvider
}

func (p matchingLogoutSessionProvider) GetLogoutSessions(r *http.Request, req *IdpLogoutRequest) ([]*Session, error) {
	var matched []*Session

	for _, session := range p.sessions {
		if err := req.MatchesSession(r, session); err != nil {
			return nil, err
		}

		matched = append(matched, session)
	}

	return matched, nil
}

// sso sends sp's AuthnRequest to the identity provider, for the session of the fixture, and returns the NameID of
// the assertion. The request has policy if it is not nil, and otherwise the default of the service provider.
func (f *propagationFixture) sso(t *testing.T, sp *ServiceProvider, policy *NameIDPolicy) NameID {
	t.Helper()

	f.provider.GetSessionFunc = func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session { return f.session }

	request, err := sp.MakeAuthenticationRequest("https://idp.example.com/saml/sso", HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)

	if policy != nil {
		request.NameIDPolicy = policy
		request.Signature = nil

		if sp.SignatureMethod != "" {
			assert.NilError(t, sp.SignAuthnRequest(request))
		}
	}

	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	body, err := doc.WriteToBytes()
	assert.NilError(t, err)

	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}}
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/saml/sso", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	f.test.IDP.ServeSSO(w, r)
	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())

	// The assertion is encrypted to the service provider.
	posted, response := postedResponse(t, w.Body.String())
	assert.Assert(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))

	plaintext, err := xmlenc.Decrypt(sp.Key, posted.FindElement("//EncryptedAssertion/EncryptedData"))
	assert.NilError(t, err)

	var assertion Assertion
	assert.NilError(t, xml.Unmarshal(plaintext, &assertion))
	assert.Assert(t, assertion.Subject != nil && assertion.Subject.NameID != nil)

	return *assertion.Subject.NameID
}

// sloWithNameID sends sp's signed LogoutRequest for nameID to the identity provider, and checks that it is
// answered with Success.
func (f *propagationFixture) sloWithNameID(t *testing.T, sp *ServiceProvider, nameID NameID) {
	t.Helper()

	r, id := redirectLogoutRequest(t, sp, func(req *LogoutRequest) {
		req.NameID = &nameID
	})

	w := serveSLO(f.test, r)

	location, logoutResponse := redirectedLogoutResponse(t, w)
	assert.Check(t, is.Equal(logoutResponse.InResponseTo, id))
	assert.Check(t, is.Equal(logoutResponse.Status.StatusCode.Value, StatusSuccess))
	assert.Check(t, sp.ValidateLogoutResponseRedirect(location, []string{id}))
	assert.Check(t, is.DeepEqual(f.provider.terminated, []*Session{f.session}))
}

func TestServeSLOMatchesTransientNameIDThroughParticipant(t *testing.T) {
	f := newPropagationFixture(t)
	f.test.IDP.SessionProvider = matchingLogoutSessionProvider{f.provider}
	f.provider.participants = map[string][]SessionParticipant{}

	// The session leaves the format open, so ServeSSO issues a random transient NameID.
	issued := f.sso(t, f.a, nil)
	assert.Assert(t, issued.Value != f.session.NameID, "the fallback is only exercised when the NameID is not that of the session")
	assert.Assert(t, is.Len(f.provider.participants[f.session.ID], 1))

	f.sloWithNameID(t, f.a, issued)
}

// A NameID qualified by an affiliation that the request named is found through the participant, and ends the
// session (SAMLCore §3.4.1.1, §3.7.3.2).
func TestServeSLOMatchesAffiliationNameIDThroughParticipant(t *testing.T) {
	f := newPropagationFixture(t)
	withAffiliation(f.test, nil)
	f.test.IDP.SessionProvider = matchingLogoutSessionProvider{f.provider}
	f.provider.participants = map[string][]SessionParticipant{}

	affiliation := testAffiliationID
	issued := f.sso(t, f.a, &NameIDPolicy{SPNameQualifier: &affiliation})
	assert.Assert(t, is.Equal(issued.SPNameQualifier, testAffiliationID))

	f.sloWithNameID(t, f.a, issued)
}

// A service provider that receives several assertions in a session receives one transient NameID, so a logout
// sends it one LogoutRequest rather than one for each assertion.
func TestStartLogoutSendsOneRequestForRepeatedTransientSSO(t *testing.T) {
	f := newPropagationFixture(t)
	f.provider.participants = map[string][]SessionParticipant{}

	first := f.sso(t, f.a, nil)
	second := f.sso(t, f.a, nil)
	assert.Check(t, is.Equal(first.Format, string(TransientNameIDFormat)))
	assert.Check(t, first.Value != f.session.NameID)
	assert.Check(t, is.DeepEqual(first, second))
	assert.Assert(t, is.Len(f.provider.participants[f.session.ID], 2))

	w := f.startLogout(t)
	w = serveSLO(f.test, respondAsSPForNameID(t, f.a, sentLogoutRequest(t, w), StatusCode{Value: StatusSuccess}, first.Value))
	assert.Check(t, is.Equal(w.Code, http.StatusNoContent), "body: %s", w.Body.String())

	assert.Assert(t, f.provider.result != nil)
	assert.Check(t, is.Len(f.provider.result.Participants, 1))
	assert.Check(t, is.DeepEqual(participantOutcomes(f.provider.result.Participants), map[string]LogoutOutcome{
		f.a.MetadataURL.String(): LogoutOutcomeSuccess,
	}))
}
