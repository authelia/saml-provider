package saml

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// participantCall is a call of AddSessionParticipant.
type participantCall struct {
	session     *Session
	participant SessionParticipant
}

// participantSessionProvider records the participants it is given. As SessionParticipantProvider requires, one lock
// covers recording a participant and closing the participants.
type participantSessionProvider struct {
	mockSessionProvider

	mu     sync.Mutex
	added  []participantCall
	closed bool
	err    error
}

func (p *participantSessionProvider) AddSessionParticipant(_ *http.Request, session *Session, participant SessionParticipant) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.err != nil {
		return p.err
	}

	if p.closed {
		return ErrSessionParticipantsClosed
	}

	p.added = append(p.added, participantCall{session: session, participant: participant})

	return nil
}

func (p *participantSessionProvider) CloseSessionParticipants(*http.Request, *Session) ([]SessionParticipant, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.closed = true

	return p.participants(), nil
}

func (p *participantSessionProvider) SessionParticipants(*http.Request, *Session) ([]SessionParticipant, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.participants(), nil
}

// participants returns the recorded participants. The caller holds mu.
func (p *participantSessionProvider) participants() []SessionParticipant {
	participants := make([]SessionParticipant, 0, len(p.added))
	for _, call := range p.added {
		participants = append(participants, call.participant)
	}

	return participants
}

// assertionCapture is an AssertionMaker which keeps the assertion that the default one made.
type assertionCapture struct {
	assertion *Assertion
}

func (a *assertionCapture) MakeAssertion(req *IdpAuthnRequest, session *Session) error {
	if err := (DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
		return err
	}

	a.assertion = req.Assertion

	return nil
}

func newParticipantTest(t *testing.T, session *Session) (*IdentityProviderTest, *participantSessionProvider, *assertionCapture) {
	t.Helper()

	test := NewIdentityProviderTest(t, applyKey)
	provider := &participantSessionProvider{
		mockSessionProvider: mockSessionProvider{
			GetSessionFunc: func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session { return session },
		},
	}
	capture := &assertionCapture{}

	test.IDP.SessionProvider = provider
	test.IDP.AssertionMaker = capture

	return test, provider, capture
}

func serveParticipantSSO(t *testing.T, test *IdentityProviderTest, policy *NameIDPolicy) *httptest.ResponseRecorder {
	t.Helper()

	request, err := test.SP.MakeAuthenticationRequest("https://idp.example.com/saml/sso", HTTPPostBinding, HTTPPostBinding)
	require.NoError(t, err)

	request.NameIDPolicy = policy
	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	body, err := doc.WriteToBytes()
	require.NoError(t, err)

	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}}
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/saml/sso", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, r)

	return w
}

func assertParticipantRecorded(t *testing.T, test *IdentityProviderTest, provider *participantSessionProvider, capture *assertionCapture, session *Session) {
	t.Helper()

	require.Len(t, provider.added, 1)
	require.NotNil(t, capture.assertion)

	call := provider.added[0]
	assert.True(t, call.session == session)
	assert.Equal(t, call.participant.ServiceProviderEntityID, test.SP.MetadataURL.String())
	assert.Equal(t, call.participant.NameID.Value, capture.assertion.Subject.NameID.Value)
	assert.True(t, call.participant.NameID.Value != "")
	assert.Equal(t, call.participant.SessionIndex, session.Index)
	assert.Equal(t, call.participant.IssueInstant, TimeNow())
}

func TestServeSSORecordsSessionParticipant(t *testing.T) {
	session := &Session{ID: "f00df00df00d", NameID: "alice", UserName: "alice", Index: "index-1"}
	test, provider, capture := newParticipantTest(t, session)

	w := serveParticipantSSO(t, test, nil)
	assert.Equal(t, w.Code, http.StatusOK)
	assertSuccessStatus(t, w)
	assertParticipantRecorded(t, test, provider, capture, session)
}

func TestServeIDPInitiatedRecordsSessionParticipant(t *testing.T) {
	session := &Session{ID: "f00df00df00d", NameID: "alice", UserName: "alice", Index: "index-2"}
	test, provider, capture := newParticipantTest(t, session)

	w := httptest.NewRecorder()
	test.IDP.ServeIDPInitiated(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/sso", nil), test.SP.MetadataURL.String(), "")
	assert.Equal(t, w.Code, http.StatusOK)
	assertSuccessStatus(t, w)
	assertParticipantRecorded(t, test, provider, capture, session)
}

func TestErrorResponseRecordsNoParticipant(t *testing.T) {
	session := &Session{ID: "f00df00df00d", NameID: "alice", UserName: "alice", Index: "index-3"}
	test, provider, _ := newParticipantTest(t, session)

	format := "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	w := serveParticipantSSO(t, test, &NameIDPolicy{Format: &format})
	assert.Equal(t, w.Code, http.StatusOK)

	_, response := postedResponse(t, w.Body.String())
	assert.Equal(t, response.Status.StatusCode.Value, StatusRequester)
	assert.Len(t, provider.added, 0)
}

func TestMakeResponseFailsWhenParticipantCannotBeRecorded(t *testing.T) {
	session := &Session{ID: "f00df00df00d", NameID: "alice", UserName: "alice", Index: "index-4"}

	t.Run("provider error", func(t *testing.T) {
		test, provider, _ := newParticipantTest(t, session)
		provider.err = errors.New("storage unavailable")

		w := serveParticipantSSO(t, test, nil)
		assert.Equal(t, w.Code, http.StatusOK)

		_, response := postedResponse(t, w.Body.String())
		assert.Equal(t, response.Status.StatusCode.Value, StatusResponder)
		assert.Nil(t, response.Assertion)
		assert.Nil(t, response.EncryptedAssertion)
	})

	t.Run("no session", func(t *testing.T) {
		test, req := errorResponseRequest(t)
		test.IDP.SessionProvider = &participantSessionProvider{}

		require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, session))
		assert.ErrorContains(t, req.MakeResponse(), "session")
		assert.Nil(t, req.ResponseEl)
	})
}

func TestMakeResponseWithoutParticipantProvider(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
			return &Session{ID: "f00df00df00d", NameID: "alice", UserName: "alice", Index: "index-5"}
		},
	}

	w := serveParticipantSSO(t, test, nil)
	assert.Equal(t, w.Code, http.StatusOK)
	assertSuccessStatus(t, w)
}

// participantRequest returns a validated request of the test service provider for session, with its assertion made.
func participantRequest(t *testing.T, session *Session) (*IdentityProviderTest, *participantSessionProvider, *IdpAuthnRequest) {
	t.Helper()

	test, provider, _ := newParticipantTest(t, session)
	_, req := errorResponseRequest(t)
	req.IDP = &test.IDP
	req.Session = session

	require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, session))

	return test, provider, req
}

// A logout which begins after the response was made, but before it was written, must not be given a participant
// whose assertion hasn't been sent, and the assertion must then not be sent.
func TestLogoutBetweenMakeResponseAndWriteResponse(t *testing.T) {
	session := &Session{ID: "f00df00df00d", NameID: "alice", UserName: "alice", Index: "index-6"}
	_, provider, req := participantRequest(t, session)

	require.NoError(t, req.MakeResponse())
	require.NotNil(t, req.ResponseEl)

	participants, err := provider.CloseSessionParticipants(nil, session)
	require.NoError(t, err)
	assert.Len(t, participants, 0)

	w := httptest.NewRecorder()
	err = req.WriteResponse(w)
	assert.True(t, errors.Is(err, ErrSessionParticipantsClosed))
	assert.Equal(t, w.Body.Len(), 0)
	assert.Len(t, provider.added, 0)
}

// A response written again is recorded again, and so isn't written again once a logout of the session has begun.
func TestWriteResponseAgainAfterLogoutSendsNothing(t *testing.T) {
	session := &Session{ID: "f00df00df00d", NameID: "alice", UserName: "alice", Index: "index-8"}
	_, provider, req := participantRequest(t, session)

	first := httptest.NewRecorder()
	require.NoError(t, req.WriteResponse(first))
	assertSuccessStatus(t, first)

	participants, err := provider.CloseSessionParticipants(nil, session)
	require.NoError(t, err)
	assert.Len(t, participants, 1)

	second := httptest.NewRecorder()
	err = req.WriteResponse(second)
	assert.True(t, errors.Is(err, ErrSessionParticipantsClosed))
	assert.Equal(t, second.Body.Len(), 0)
	assert.Len(t, provider.added, 1)
}

// A response which can't be written leaves its participant recorded, since part of it may have been sent.
func TestPublishResponseKeepsTheParticipantWhenPublishFails(t *testing.T) {
	session := &Session{ID: "f00df00df00d", NameID: "alice", UserName: "alice", Index: "index-9"}
	_, provider, req := participantRequest(t, session)

	require.NoError(t, req.MakeResponse())

	failed := errors.New("connection reset")
	assert.Equal(t, req.PublishResponse(func() error { return failed }), failed)
	assert.Len(t, provider.added, 1)
}
