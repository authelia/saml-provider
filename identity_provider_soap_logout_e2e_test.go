package saml

import (
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
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
	assert.Check(t, is.Equal(response.InResponseTo, id))

	return response
}

func TestServeSOAPLogoutPropagatesToSOAPParticipant(t *testing.T) {
	f, recorder := newSOAPPropagationFixture(t, nil)

	response := f.serveSOAPLogoutFromA(t)
	assertLogoutStatus(t, response, StatusSuccess, "")

	received := recorder.Received()
	assert.Assert(t, is.Len(received, 1))
	assert.Assert(t, received[0].Request != nil)
	assert.Assert(t, received[0].Request.NameID != nil)
	assert.Check(t, is.Equal(received[0].Request.NameID.Value, "alice"))
	assert.Check(t, is.Equal(received[0].Request.NameID.SPNameQualifier, f.b.MetadataURL.String()))
	assert.Check(t, is.DeepEqual(received[0].Request.SessionIndexes, []SessionIndex{{Value: "index-one"}}))

	assert.Check(t, is.DeepEqual(f.provider.calls, []string{"participants session-one", "terminate session-one", "logout B"}))
	assert.Check(t, is.DeepEqual(f.provider.terminated, []*Session{f.session}))
	assert.Check(t, is.Len(f.provider.states, 0))
	assert.Check(t, f.provider.result == nil, "the service provider is answered, not the result handler")
}

func TestServeSOAPLogoutSkipsFrontChannelParticipant(t *testing.T) {
	f, recorder := newSOAPPropagationFixture(t, nil)
	f.b.LogoutBindings = []string{HTTPRedirectBinding}

	response := f.serveSOAPLogoutFromA(t)
	assertLogoutStatus(t, response, StatusSuccess, StatusPartialLogout)

	assert.Check(t, is.Len(recorder.Received(), 0))
	assert.Check(t, is.DeepEqual(f.provider.terminated, []*Session{f.session}))
}

func TestServeSOAPLogoutParticipantFails(t *testing.T) {
	f, recorder := newSOAPPropagationFixture(t, func(_ http.ResponseWriter, _ *LogoutRequest, response *LogoutResponse) bool {
		response.Status.StatusCode = StatusCode{Value: StatusResponder}

		return true
	})

	response := f.serveSOAPLogoutFromA(t)
	assertLogoutStatus(t, response, StatusSuccess, StatusPartialLogout)

	assert.Check(t, is.Len(recorder.Received(), 1))
	assert.Check(t, is.DeepEqual(f.provider.terminated, []*Session{f.session}))
}

func TestServeSOAPLogoutWithoutLogoutStateProvider(t *testing.T) {
	f, recorder := newSOAPPropagationFixture(t, nil)
	f.test.IDP.SessionProvider = withoutLogoutState{f.provider, f.provider, f.provider}

	response := f.serveSOAPLogoutFromA(t)
	assertLogoutStatus(t, response, StatusSuccess, "")

	assert.Check(t, is.Len(recorder.Received(), 1))
	assert.Check(t, is.DeepEqual(f.provider.terminated, []*Session{f.session}))
}

func TestServeSOAPLogoutParticipantsError(t *testing.T) {
	f, recorder := newSOAPPropagationFixture(t, nil)
	f.provider.participantsErr = errors.New("storage unavailable")

	response := f.serveSOAPLogoutFromA(t)
	assertLogoutStatus(t, response, StatusSuccess, StatusPartialLogout)

	assert.Check(t, is.Len(recorder.Received(), 0))
	assert.Check(t, is.DeepEqual(f.provider.terminated, []*Session{f.session}))
}

func TestServeSOAPLogoutTerminationFailsStillPropagates(t *testing.T) {
	f, recorder := newSOAPPropagationFixture(t, nil)
	f.provider.terminateErr = errors.New("session store down")

	response := f.serveSOAPLogoutFromA(t)
	assertLogoutStatus(t, response, StatusResponder, "")

	assert.Check(t, is.Len(recorder.Received(), 1))
	assert.Check(t, is.DeepEqual(f.provider.calls, []string{"participants session-one", "terminate session-one", "logout B"}))
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
	assert.Assert(t, is.Len(participants, 2))

	participantC := participants[1]
	participantC.ServiceProviderEntityID = c.MetadataURL.String()
	participantC.NameID.SPNameQualifier = c.MetadataURL.String()
	participantC.IssueInstant = participants[1].IssueInstant.Add(-time.Second / 2)
	f.provider.participants[f.session.ID] = append(participants, participantC)

	response := f.serveSOAPLogoutFromA(t)
	assertLogoutStatus(t, response, StatusSuccess, "")

	assert.Check(t, is.DeepEqual(f.provider.calls, []string{"participants session-one", "terminate session-one", "logout C", "logout B"}))
	assert.Check(t, is.Len(recorder.Received(), 1))

	receivedC := recorderC.Received()
	assert.Assert(t, is.Len(receivedC, 1))
	assert.Assert(t, receivedC[0].Request != nil)
	assert.Check(t, is.Equal(receivedC[0].Request.Destination, c.SloURL.String()))
	assert.Assert(t, receivedC[0].Request.NameID != nil)
	assert.Check(t, is.Equal(receivedC[0].Request.NameID.SPNameQualifier, c.MetadataURL.String()))
}
