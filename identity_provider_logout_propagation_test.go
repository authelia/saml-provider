package saml

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memoryLogoutStateProvider is an in-memory LogoutStateProvider.
type memoryLogoutStateProvider struct {
	states  map[string]*LogoutState
	saveErr error
	deleted []string
}

func (p *memoryLogoutStateProvider) SaveLogoutState(_ *http.Request, state *LogoutState) error {
	if p.saveErr != nil {
		return p.saveErr
	}

	if p.states == nil {
		p.states = map[string]*LogoutState{}
	}

	if stored, ok := p.states[state.ID]; (ok && stored.Revision+1 != state.Revision) || (!ok && state.Revision != 1) {
		return ErrLogoutStateConflict
	}

	saved := *state
	saved.Participants = append([]LogoutParticipant(nil), state.Participants...)
	p.states[state.ID] = &saved

	return nil
}

func (p *memoryLogoutStateProvider) LoadLogoutState(_ *http.Request, id string) (*LogoutState, error) {
	state, ok := p.states[id]
	if !ok {
		return nil, os.ErrNotExist
	}

	loaded := *state
	loaded.Participants = append([]LogoutParticipant(nil), state.Participants...)

	return &loaded, nil
}

func (p *memoryLogoutStateProvider) DeleteLogoutState(_ *http.Request, id string) error {
	p.deleted = append(p.deleted, id)
	delete(p.states, id)

	return nil
}

func propagationState(entityIDs ...string) *LogoutState {
	state := &LogoutState{ID: "state-id", ExpireTime: TimeNow().Add(time.Minute), Current: -1}

	for _, id := range entityIDs {
		state.Participants = append(state.Participants, LogoutParticipant{
			ServiceProviderEntityID: id,
			NameID:                  NameID{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", Value: "alice"},
			SessionIndexes:          []string{"index-one", "index-two"},
		})
	}

	return state
}

func TestContinueLogoutRedirect(t *testing.T) {
	test, _ := logoutTestIDP(t)
	provider := &memoryLogoutStateProvider{}
	state := propagationState(test.SP.MetadataURL.String())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/logout", nil)
	require.NoError(t, test.IDP.continueLogout(w, r, provider, state))
	require.Equal(t, w.Code, http.StatusFound)

	location, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, location.Host, "sp.example.com")
	assert.Equal(t, location.Path, "/saml2/slo")
	assert.Equal(t, location.Query().Get("RelayState"), state.ID)
	assert.True(t, location.Query().Get("SigAlg") != "")
	assert.True(t, location.Query().Get("Signature") != "")
	require.NoError(t, verifyRedirectSignature(location.RawQuery, "SAMLRequest", []*x509.Certificate{test.IDP.Certificate}, anySignaturePolicy))
	assert.Equal(t, w.Header().Get("Cache-Control"), "no-cache, no-store")

	compressed, err := base64.StdEncoding.DecodeString(location.Query().Get("SAMLRequest"))
	require.NoError(t, err)
	buf, err := io.ReadAll(flate.NewReader(bytes.NewReader(compressed)))
	require.NoError(t, err)

	var request LogoutRequest
	require.NoError(t, xml.Unmarshal(buf, &request))
	assert.Equal(t, request.NameID.Value, "alice")
	require.Len(t, request.SessionIndexes, 2)
	assert.Equal(t, request.SessionIndexes[0].Value, "index-one")
	assert.Equal(t, request.SessionIndexes[1].Value, "index-two")
	require.NotNil(t, request.NotOnOrAfter)
	assert.True(t, request.NotOnOrAfter.Equal(state.ExpireTime))
	assert.Equal(t, request.Destination, "https://sp.example.com/saml2/slo")
	assert.Equal(t, request.Issuer.Value, test.IDP.MetadataURL.String())

	saved, err := provider.LoadLogoutState(r, state.ID)
	require.NoError(t, err)
	assert.Equal(t, saved.Current, 0)
	assert.Equal(t, saved.PendingRequestID, request.ID)
}

func TestContinueLogoutPost(t *testing.T) {
	test, _ := logoutTestIDP(t)
	test.SP.LogoutBindings = []string{HTTPPostBinding}
	provider := &memoryLogoutStateProvider{}
	state := propagationState(test.SP.MetadataURL.String())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/logout", nil)
	require.NoError(t, test.IDP.continueLogout(w, r, provider, state))
	require.Equal(t, w.Code, http.StatusOK)

	body := w.Body.String()
	assert.True(t, strings.Contains(body, `action="https://sp.example.com/saml2/slo"`), body)
	assert.True(t, strings.Contains(body, `name="RelayState" value="state-id"`), body)

	marker := `name="SAMLRequest" value="`
	start := strings.Index(body, marker)
	require.True(t, start >= 0, body)
	value, _, _ := strings.Cut(body[start+len(marker):], `"`)
	decoded, err := base64.StdEncoding.DecodeString(html.UnescapeString(value))
	require.NoError(t, err)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(decoded))

	children := doc.Root().ChildElements()
	assert.Equal(t, children[0].Tag, "Issuer")
	assert.Equal(t, children[1].Tag, "Signature")

	_, err = verifyEnvelopedSignature(doc.Root(), []*x509.Certificate{test.IDP.Certificate}, anySignaturePolicy)
	require.NoError(t, err)

	saved, err := provider.LoadLogoutState(r, state.ID)
	require.NoError(t, err)
	assert.Equal(t, saved.Current, 0)
	assert.True(t, saved.PendingRequestID != "")
}

func TestContinueLogoutSkipsUnknownServiceProvider(t *testing.T) {
	test, _ := logoutTestIDP(t)
	provider := &memoryLogoutStateProvider{}
	state := propagationState("https://unknown.example.com/metadata", test.SP.MetadataURL.String())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/logout", nil)
	require.NoError(t, test.IDP.continueLogout(w, r, provider, state))
	require.Equal(t, w.Code, http.StatusFound)

	saved, err := provider.LoadLogoutState(r, state.ID)
	require.NoError(t, err)
	assert.Equal(t, saved.Participants[0].Outcome, LogoutOutcomeSkipped)
	assert.True(t, saved.Participants[0].Reason != "")
	assert.Equal(t, saved.Participants[1].Outcome, LogoutOutcomePending)
	assert.Equal(t, saved.Current, 1)
}

func TestContinueLogoutSkipsInsecureEndpoint(t *testing.T) {
	test, _ := logoutTestIDP(t)
	metadata := test.SP.Metadata()
	metadata.SPSSODescriptors[0].SingleLogoutServices = []Endpoint{{Binding: HTTPRedirectBinding, Location: "http://sp.example.com/slo"}}
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) { return metadata, nil },
	}

	provider := &memoryLogoutStateProvider{}
	state := propagationState(test.SP.MetadataURL.String())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/logout", nil)
	require.NoError(t, test.IDP.continueLogout(w, r, provider, state))

	assert.Len(t, provider.deleted, 1)
	assert.Equal(t, state.Participants[0].Outcome, LogoutOutcomeSkipped)
	assert.True(t, state.Participants[0].Reason != "")
}

func TestContinueLogoutNoPendingFinishes(t *testing.T) {
	test, _ := logoutTestIDP(t)
	provider := &memoryLogoutStateProvider{}
	state := propagationState(test.SP.MetadataURL.String())
	state.Participants[0].Outcome = LogoutOutcomeSuccess

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/logout", nil)
	require.NoError(t, test.IDP.continueLogout(w, r, provider, state))
	require.Equal(t, provider.deleted, []string{state.ID})
}

func TestContinueLogoutSaveFailureFinishes(t *testing.T) {
	test, _ := logoutTestIDP(t)
	provider := &memoryLogoutStateProvider{saveErr: errors.New("boom")}
	state := propagationState(test.SP.MetadataURL.String(), test.SP.MetadataURL.String())
	state.SessionTerminated = true
	state.ReturnURL = "https://idp.example.com/done"

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/logout", nil)
	require.NoError(t, test.IDP.continueLogout(w, r, provider, state))
	assert.Equal(t, w.Code, http.StatusFound)
	assert.Equal(t, w.Header().Get("Location"), "https://idp.example.com/done")

	// The state couldn't be claimed, so it is left to expire rather than deleted, as it may be a newer revision.
	assert.Len(t, provider.deleted, 0)

	for _, participant := range state.Participants {
		assert.Equal(t, participant.Outcome, LogoutOutcomeFailed)
		assert.Contains(t, participant.Reason, "boom")
	}

	assert.Equal(t, state.Current, -1)
	assert.Equal(t, state.PendingRequestID, "")
}

func TestContinueLogoutSigningFailureFinishes(t *testing.T) {
	test, _ := logoutTestIDP(t)
	test.IDP.Key = nil
	test.IDP.Signer = nil
	provider := &memoryLogoutStateProvider{}
	state := propagationState(test.SP.MetadataURL.String())
	state.Participants = append(state.Participants, LogoutParticipant{ServiceProviderEntityID: "done", Outcome: LogoutOutcomeSuccess})
	state.ReturnURL = "https://idp.example.com/done"

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/logout", nil)
	require.NoError(t, test.IDP.continueLogout(w, r, provider, state))
	assert.Equal(t, w.Code, http.StatusFound)
	assert.Equal(t, state.Participants[0].Outcome, LogoutOutcomeFailed)
	assert.Contains(t, state.Participants[0].Reason, "cannot make the logout request")
	assert.Equal(t, state.Participants[1].Outcome, LogoutOutcomeSuccess)
}

func TestFinishLogoutSaveFailureKeepsNewerState(t *testing.T) {
	test, _ := logoutTestIDP(t)

	// Another request has advanced the logout to a newer revision than the one this request loaded.
	newer := propagationState(test.SP.MetadataURL.String())
	newer.Revision, newer.Current, newer.PendingRequestID = 5, 0, "id-newer"
	provider := &memoryLogoutStateProvider{states: map[string]*LogoutState{newer.ID: newer}}

	stale := propagationState(test.SP.MetadataURL.String())
	stale.Revision = 4
	stale.Participants[0].Outcome = LogoutOutcomeSuccess
	stale.ReturnURL = "https://idp.example.com/done"

	// The save fails for a reason other than a conflict, so this request can't tell that the state is newer.
	provider.saveErr = errors.New("boom")

	w := httptest.NewRecorder()
	require.NoError(t, test.IDP.continueLogout(w, httptest.NewRequest(http.MethodGet, "/logout", nil), provider, stale))
	assert.Equal(t, w.Code, http.StatusFound)
	assert.Len(t, provider.deleted, 0)
	require.NotNil(t, provider.states[newer.ID])
	assert.Equal(t, provider.states[newer.ID].PendingRequestID, "id-newer")
}
