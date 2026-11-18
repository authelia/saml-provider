package saml

import (
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSOAPPropagationFixture is newSOAPLogoutFixture with the SOAP logout URL set, so that A can log out over SOAP.
// Every LogoutRequest that B is sent is recorded in the calls of the session provider as "logout B", after handler
// has decided the answer.
func newSOAPPropagationFixture(t *testing.T, handler soapLogoutSPHandler) (*propagationFixture, *soapLogoutSPRecorder) {
	t.Helper()

	var f *propagationFixture

	f, _, recorder := newSOAPLogoutFixture(t, func(w http.ResponseWriter, request *LogoutRequest, response *LogoutResponse) bool {
		f.provider.calls = append(f.provider.calls, "logout B")

		return handler == nil || handler(w, request, response)
	})

	f.test.IDP.SOAPLogoutURL = mustParseURL(soapLogoutTestURL)

	return f, recorder
}

// serveSOAPLogoutFromA sends A's signed LogoutRequest over SOAP, and returns the LogoutResponse to it, checking that
// it answers the request.
func (f *propagationFixture) serveSOAPLogoutFromA(t *testing.T) *LogoutResponse {
	t.Helper()

	r, id := soapLogoutRequest(t, f.a, nil)

	response := soapLogoutResponse(t, serveSOAPLogout(f.test, r))
	assert.Equal(t, response.InResponseTo, id)

	return response
}

func TestServeSOAPLogoutPropagatesToSOAPParticipant(t *testing.T) {
	f, recorder := newSOAPPropagationFixture(t, nil)

	response := f.serveSOAPLogoutFromA(t)
	assertLogoutStatus(t, response, StatusSuccess, "")

	received := recorder.Received()
	require.Len(t, received, 1)
	require.NotNil(t, received[0].Request)
	require.NotNil(t, received[0].Request.NameID)
	assert.Equal(t, received[0].Request.NameID.Value, "alice")
	assert.Equal(t, received[0].Request.NameID.SPNameQualifier, f.b.MetadataURL.String())
	assert.Equal(t, received[0].Request.SessionIndexes, []SessionIndex{{Value: "index-one"}})

	assert.Equal(t, f.provider.calls, []string{"participants session-one", "terminate session-one", "logout B"})
	assert.Equal(t, f.provider.terminated, []*Session{f.session})
	assert.Len(t, f.provider.states, 0)
	assert.True(t, f.provider.result == nil, "the service provider is answered, not the result handler")
}

func TestServeSOAPLogoutSkipsFrontChannelParticipant(t *testing.T) {
	f, recorder := newSOAPPropagationFixture(t, nil)
	f.b.LogoutBindings = []string{HTTPRedirectBinding}

	response := f.serveSOAPLogoutFromA(t)
	assertLogoutStatus(t, response, StatusSuccess, StatusPartialLogout)

	assert.Len(t, recorder.Received(), 0)
	assert.Equal(t, f.provider.terminated, []*Session{f.session})
}

func TestServeSOAPLogoutParticipantFails(t *testing.T) {
	f, recorder := newSOAPPropagationFixture(t, func(_ http.ResponseWriter, _ *LogoutRequest, response *LogoutResponse) bool {
		response.Status.StatusCode = StatusCode{Value: StatusResponder}

		return true
	})

	response := f.serveSOAPLogoutFromA(t)
	assertLogoutStatus(t, response, StatusSuccess, StatusPartialLogout)

	assert.Len(t, recorder.Received(), 1)
	assert.Equal(t, f.provider.terminated, []*Session{f.session})
}

func TestServeSOAPLogoutWithoutLogoutStateProvider(t *testing.T) {
	f, recorder := newSOAPPropagationFixture(t, nil)
	f.test.IDP.SessionProvider = withoutLogoutState{f.provider, f.provider, f.provider}

	response := f.serveSOAPLogoutFromA(t)
	assertLogoutStatus(t, response, StatusSuccess, "")

	assert.Len(t, recorder.Received(), 1)
	assert.Equal(t, f.provider.terminated, []*Session{f.session})
}

func TestServeSOAPLogoutParticipantsError(t *testing.T) {
	f, recorder := newSOAPPropagationFixture(t, nil)
	f.provider.participantsErr = errors.New("storage unavailable")

	response := f.serveSOAPLogoutFromA(t)
	assertLogoutStatus(t, response, StatusSuccess, StatusPartialLogout)

	assert.Len(t, recorder.Received(), 0)
	assert.Equal(t, f.provider.terminated, []*Session{f.session})
}

func TestServeSOAPLogoutTerminationFailsStillPropagates(t *testing.T) {
	f, recorder := newSOAPPropagationFixture(t, nil)
	f.provider.terminateErr = errors.New("session store down")

	response := f.serveSOAPLogoutFromA(t)
	assertLogoutStatus(t, response, StatusResponder, "")

	assert.Len(t, recorder.Received(), 1)
	assert.Equal(t, f.provider.calls, []string{"participants session-one", "terminate session-one", "logout B"})
}

func TestServeSOAPLogoutPropagatesToSOAPParticipantsInOrder(t *testing.T) {
	f, recorder := newSOAPPropagationFixture(t, nil)

	c := *f.b
	c.MetadataURL = mustParseURL("https://sp-c.example.com/saml2/metadata")
	c.AcsURL = mustParseURL("https://sp-c.example.com/saml2/acs")
	c.Key, c.Certificate = propagationServiceProviderKey(t)

	_, recorderC := soapLogoutSP(t, &c, func(http.ResponseWriter, *LogoutRequest, *LogoutResponse) bool {
		f.provider.calls = append(f.provider.calls, "logout C")

		return true
	})

	f.test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			for _, sp := range []*ServiceProvider{f.a, f.b, &c} {
				if serviceProviderID == sp.MetadataURL.String() {
					return sp.Metadata(), nil
				}
			}

			return nil, os.ErrNotExist
		},
	}

	// C joined the session before B, so it is logged out first.
	participants := f.provider.participants[f.session.ID]
	require.Len(t, participants, 2)

	participantC := participants[1]
	participantC.ServiceProviderEntityID = c.MetadataURL.String()
	participantC.NameID.SPNameQualifier = c.MetadataURL.String()
	participantC.IssueInstant = participants[1].IssueInstant.Add(-time.Second / 2)
	f.provider.participants[f.session.ID] = append(participants, participantC)

	response := f.serveSOAPLogoutFromA(t)
	assertLogoutStatus(t, response, StatusSuccess, "")

	assert.Equal(t, f.provider.calls, []string{"participants session-one", "terminate session-one", "logout C", "logout B"})
	assert.Len(t, recorder.Received(), 1)

	receivedC := recorderC.Received()
	require.Len(t, receivedC, 1)
	require.NotNil(t, receivedC[0].Request)
	assert.Equal(t, receivedC[0].Request.Destination, c.SloURL.String())
	require.NotNil(t, receivedC[0].Request.NameID)
	assert.Equal(t, receivedC[0].Request.NameID.SPNameQualifier, c.MetadataURL.String())
}
