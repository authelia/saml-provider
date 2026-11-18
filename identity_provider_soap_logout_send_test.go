package saml

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// soapLogoutSPReceived is one request that a service provider started by soapLogoutSP received.
type soapLogoutSPReceived struct {
	Path        string
	SOAPAction  string
	ContentType string

	// Request is the verified LogoutRequest, or nil if the request could not be read or verified.
	Request *LogoutRequest

	// Element is the element of Request which the signature covers.
	Element *etree.Element
}

// soapLogoutSPRecorder records the requests that a service provider started by soapLogoutSP received.
type soapLogoutSPRecorder struct {
	mu       sync.Mutex
	received []soapLogoutSPReceived
}

func (r *soapLogoutSPRecorder) add(received soapLogoutSPReceived) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.received = append(r.received, received)
}

// Received returns the requests received so far, in order.
func (r *soapLogoutSPRecorder) Received() []soapLogoutSPReceived {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]soapLogoutSPReceived(nil), r.received...)
}

// soapLogoutSPHandler decides how a service provider started by soapLogoutSP answers a verified LogoutRequest. It
// may change the unsigned Success response, which is then signed if the service provider has a SignatureMethod and
// sent in a SOAP envelope, and returns true; or it writes its own answer to w and returns false.
type soapLogoutSPHandler func(w http.ResponseWriter, request *LogoutRequest, response *LogoutResponse) bool

// soapLogoutSP makes sp a service provider whose only SingleLogoutService is on the SOAP binding, at an httptest
// TLS server which is closed when the test ends; the client of the server trusts its certificate. On any request it reads the SOAP envelope, verifies the identity
// provider's signature of the LogoutRequest with the IDPMetadata of sp, and answers with a LogoutResponse to it as
// handler decides; a nil handler answers Success. A request that can't be read or verified fails the test and is
// answered with a SOAP fault. Every request is recorded, with its path and headers.
func soapLogoutSP(t *testing.T, sp *ServiceProvider, handler soapLogoutSPHandler) (*httptest.Server, *soapLogoutSPRecorder) {
	t.Helper()

	recorder := &soapLogoutSPRecorder{}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received := soapLogoutSPReceived{
			Path:        r.URL.Path,
			SOAPAction:  r.Header.Get("SOAPAction"),
			ContentType: r.Header.Get("Content-Type"),
		}

		request, element, err := soapLogoutSPReadRequest(sp, r)
		received.Request, received.Element = request, element
		recorder.add(received)

		if err != nil {
			t.Errorf("the service provider could not read the logout request: %v", err)
			writeSOAPFault(w, &soapFault{Code: "Client", String: soapFaultStringEnvelope})

			return
		}

		response, err := sp.MakeLogoutResponse("", request.ID)
		if err != nil {
			t.Errorf("the service provider could not make the logout response: %v", err)
			writeSOAPFault(w, &soapFault{Code: "Server", String: soapFaultStringProcessing})

			return
		}

		response.Signature = nil

		if handler != nil && !handler(w, request, response) {
			return
		}

		if sp.SignatureMethod != "" {
			if err = sp.SignLogoutResponse(response); err != nil {
				t.Errorf("the service provider could not sign the logout response: %v", err)
				writeSOAPFault(w, &soapFault{Code: "Server", String: soapFaultStringProcessing})

				return
			}
		}

		if err = writeSOAPResponse(w, nil, response.Element()); err != nil {
			t.Errorf("the service provider could not write the logout response: %v", err)
		}
	}))

	t.Cleanup(server.Close)

	sp.SloURL = mustParseURL(server.URL + "/saml2/slo")
	sp.LogoutBindings = []string{SOAPBinding}

	return server, recorder
}

// soapLogoutSPReadRequest reads the LogoutRequest of r as sp, verifying that the identity provider signed it.
func soapLogoutSPReadRequest(sp *ServiceProvider, r *http.Request) (*LogoutRequest, *etree.Element, error) {
	if r.Method != http.MethodPost {
		return nil, nil, errors.New("the method is not POST")
	}

	message, fault := readSOAPRequest(r)
	if fault != nil {
		return nil, nil, errors.New(fault.String)
	}

	certificates, err := sp.getIDPSigningCerts()
	if err != nil {
		return nil, nil, err
	}

	verified, err := verifyEnvelopedSignature(message.Message, certificates, anySignaturePolicy)
	if err != nil {
		return nil, nil, err
	}

	request := &LogoutRequest{}

	if err = unmarshalElement(verified, request); err != nil {
		return nil, nil, err
	}

	return request, verified, nil
}

// newSOAPLogoutFixture is newPropagationFixture with B a SOAP service provider answering as handler decides, an
// HTTPClient which trusts the certificate of its server, and a logger which discards what the identity provider logs.
func newSOAPLogoutFixture(t *testing.T, handler soapLogoutSPHandler) (*propagationFixture, *httptest.Server, *soapLogoutSPRecorder) {
	t.Helper()

	f := newPropagationFixture(t)
	f.test.IDP.Observer = logObserver(io.Discard)

	server, recorder := soapLogoutSP(t, f.b, handler)
	f.test.IDP.HTTPClient = server.Client()

	return f, server, recorder
}

// sendToB logs B, the only participant of a new logout state, out over SOAP, and returns the state.
func (f *propagationFixture) sendToB(t *testing.T) *LogoutState {
	t.Helper()

	state := newLogoutState(&f.test.IDP, f.provider.participants[f.session.ID], f.a.MetadataURL.String())
	require.Len(t, state.Participants, 1)

	endpoint, err := f.test.IDP.logoutRequestEndpoint(f.b.Metadata(), backChannelLogoutBindings...)
	require.NoError(t, err)

	f.test.IDP.sendSOAPLogoutRequest(httptest.NewRequest(http.MethodGet, "/logout", nil), state, 0, f.b.Metadata(), endpoint)

	assert.Equal(t, state.Current, -1)
	assert.Equal(t, state.PendingRequestID, "")

	return state
}

func TestSendSOAPLogoutRequestSuccess(t *testing.T) {
	f, _, recorder := newSOAPLogoutFixture(t, nil)

	state := f.sendToB(t)
	assert.Equal(t, state.Participants[0].Outcome, LogoutOutcomeSuccess)
	assert.Equal(t, state.Participants[0].Reason, "")

	received := recorder.Received()
	require.Len(t, received, 1)
	assert.Equal(t, received[0].SOAPAction, `"`+soapActionSAML+`"`)

	mediaType, _, err := mime.ParseMediaType(received[0].ContentType)
	require.NoError(t, err)
	assert.Equal(t, mediaType, "text/xml")

	request := received[0].Request
	require.NotNil(t, request)
	require.NotNil(t, request.NameID)
	assert.Equal(t, request.NameID.Value, "alice")
	assert.Equal(t, request.SessionIndexes, []SessionIndex{{Value: "index-one"}})
	assert.Equal(t, request.Destination, f.b.SloURL.String())
	require.NotNil(t, request.NotOnOrAfter)
	assert.True(t, request.NotOnOrAfter.Equal(state.ExpireTime))
	require.NotNil(t, request.Issuer)
	assert.Equal(t, request.Issuer.Value, f.test.IDP.MetadataURL.String())
}

func TestSendSOAPLogoutRequestUnsignedResponseAccepted(t *testing.T) {
	f, _, _ := newSOAPLogoutFixture(t, nil)
	f.b.SignatureMethod = ""

	state := f.sendToB(t)
	assert.Equal(t, state.Participants[0].Outcome, LogoutOutcomeSuccess)
	assert.Equal(t, state.Participants[0].Reason, "")
}

func TestSendSOAPLogoutRequestOverHTTP(t *testing.T) {
	testCases := []struct {
		name     string
		unsigned bool
		expected LogoutOutcome
	}{
		{"ShouldRefuseUnsignedResponse", true, LogoutOutcomeFailed},
		{"ShouldAcceptSignedResponse", false, LogoutOutcomeSuccess},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, server, recorder := newSOAPLogoutFixture(t, nil)
			serveLoopbackHTTP(t, f.b, server)
			f.test.IDP.AllowInsecureServiceProviderEndpoints = true

			if tc.unsigned {
				f.b.SignatureMethod = ""
			}

			state := f.sendToB(t)
			assert.Len(t, recorder.Received(), 1)
			assert.Equal(t, state.Participants[0].Outcome, tc.expected)

			if tc.expected == LogoutOutcomeFailed {
				assert.Contains(t, state.Participants[0].Reason, "response is not signed")
			}
		})
	}
}

func TestBackChannelLogoutOutlivesCancelledRequest(t *testing.T) {
	f, _, recorder := newSOAPLogoutFixture(t, nil)

	state := newLogoutState(&f.test.IDP, f.provider.participants[f.session.ID], f.a.MetadataURL.String())
	require.Len(t, state.Participants, 1)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	r := httptest.NewRequestWithContext(ctx, http.MethodPost, soapLogoutTestURL, nil)
	f.test.IDP.backChannelLogout(r, state)

	assert.Len(t, recorder.Received(), 1)
	assert.Equal(t, state.Participants[0].Outcome, LogoutOutcomeSuccess)
	assert.Equal(t, state.Participants[0].Reason, "")
}

func TestSendSOAPLogoutRequestIgnoresDestination(t *testing.T) {
	f, _, _ := newSOAPLogoutFixture(t, func(_ http.ResponseWriter, _ *LogoutRequest, response *LogoutResponse) bool {
		response.Destination = "https://elsewhere.example.com/slo"

		return true
	})

	state := f.sendToB(t)
	assert.Equal(t, state.Participants[0].Outcome, LogoutOutcomeSuccess)
	assert.Equal(t, state.Participants[0].Reason, "")
}

func TestSendSOAPLogoutRequestStatus(t *testing.T) {
	testCases := []struct {
		name   string
		code   StatusCode
		reason string
	}{
		{"ShouldFailResponder", StatusCode{Value: StatusResponder}, StatusResponder},
		{"ShouldFailPartialLogout", StatusCode{Value: StatusSuccess, StatusCode: &StatusCode{Value: StatusPartialLogout}}, StatusPartialLogout},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, _, _ := newSOAPLogoutFixture(t, func(_ http.ResponseWriter, _ *LogoutRequest, response *LogoutResponse) bool {
				response.Status.StatusCode = tc.code

				return true
			})

			state := f.sendToB(t)
			assert.Equal(t, state.Participants[0].Outcome, LogoutOutcomeFailed)
			assert.Equal(t, state.Participants[0].Reason, tc.reason)
		})
	}
}

func TestSendSOAPLogoutRequestFails(t *testing.T) {
	testCases := []struct {
		name    string
		reason  string
		handler soapLogoutSPHandler
		setup   func(t *testing.T, f *propagationFixture, server *httptest.Server)
		check   func(t *testing.T, received []soapLogoutSPReceived)
	}{
		{
			name:   "ShouldFailOnTimeout",
			reason: "Client.Timeout exceeded",
			handler: func(http.ResponseWriter, *LogoutRequest, *LogoutResponse) bool {
				time.Sleep(200 * time.Millisecond)

				return true
			},
			setup: func(_ *testing.T, f *propagationFixture, server *httptest.Server) {
				f.test.IDP.HTTPClient = &http.Client{Transport: server.Client().Transport, Timeout: 50 * time.Millisecond}
			},
		},
		{
			name:   "ShouldFailOnRedirect",
			reason: "HTTP status 302",
			handler: func(w http.ResponseWriter, _ *LogoutRequest, _ *LogoutResponse) bool {
				w.Header().Set("Location", "/other")
				w.WriteHeader(http.StatusFound)

				return false
			},
			check: func(t *testing.T, received []soapLogoutSPReceived) {
				require.Len(t, received, 1)
				assert.Equal(t, received[0].Path, "/saml2/slo")
			},
		},
		{
			name:   "ShouldFailOnNon200",
			reason: "HTTP status 500",
			handler: func(w http.ResponseWriter, _ *LogoutRequest, _ *LogoutResponse) bool {
				writeSOAPFault(w, &soapFault{Code: "Server", String: soapFaultStringProcessing})

				return false
			},
		},
		{
			name:   "ShouldFailOnOversizedResponse",
			reason: "larger than 65536 bytes",
			handler: func(w http.ResponseWriter, _ *LogoutRequest, response *LogoutResponse) bool {
				w.Header().Set("Content-Type", "text/xml")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, soapTestEnvelope("", strings.Repeat(" ", soapMaxMessageSize)+`<samlp:LogoutResponse xmlns:samlp="`+soapTestProtocolNS+`" InResponseTo="`+response.InResponseTo+`"/>`))

				return false
			},
		},
		{
			name:   "ShouldFailOnFaultWithStatus200",
			reason: "SOAP fault",
			handler: func(w http.ResponseWriter, _ *LogoutRequest, _ *LogoutResponse) bool {
				w.Header().Set("Content-Type", "text/xml")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, soapTestEnvelope("", `<soapenv:Fault><faultcode>soapenv:Server</faultcode><faultstring>failed</faultstring></soapenv:Fault>`))

				return false
			},
		},
		{
			name:   "ShouldFailOnResponseNotAnEnvelope",
			reason: "not a SOAP 1.1 Envelope",
			handler: func(w http.ResponseWriter, _ *LogoutRequest, response *LogoutResponse) bool {
				w.Header().Set("Content-Type", "text/xml")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `<samlp:LogoutResponse xmlns:samlp="`+soapTestProtocolNS+`" Version="2.0" InResponseTo="`+response.InResponseTo+`"/>`)

				return false
			},
		},
		{
			name:   "ShouldFailOnWrongInResponseTo",
			reason: "not to the outstanding logout request",
			handler: func(_ http.ResponseWriter, _ *LogoutRequest, response *LogoutResponse) bool {
				response.InResponseTo = "id-other"

				return true
			},
		},
		{
			name:   "ShouldFailOnWrongIssuer",
			reason: "not from the service provider",
			setup: func(_ *testing.T, f *propagationFixture, _ *httptest.Server) {
				f.b.EntityID = f.a.MetadataURL.String()
			},
		},
		{
			name:   "ShouldFailOnBadSignature",
			reason: "invalid response signature",
			setup: func(t *testing.T, f *propagationFixture, _ *httptest.Server) {
				f.b.Key, _ = propagationServiceProviderKey(t)
			},
		},
		{
			name:   "ShouldFailOnConnectionRefused",
			reason: "connection refused",
			setup: func(_ *testing.T, _ *propagationFixture, server *httptest.Server) {
				server.Close()
			},
			check: func(t *testing.T, received []soapLogoutSPReceived) {
				assert.Len(t, received, 0)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, server, recorder := newSOAPLogoutFixture(t, tc.handler)

			// The endpoint is chosen before setup, so that a change to B affects only how it answers.
			endpoint, err := f.test.IDP.logoutRequestEndpoint(f.b.Metadata(), backChannelLogoutBindings...)
			require.NoError(t, err)

			if tc.setup != nil {
				tc.setup(t, f, server)
			}

			state := newLogoutState(&f.test.IDP, f.provider.participants[f.session.ID], f.a.MetadataURL.String())
			require.Len(t, state.Participants, 1)

			f.test.IDP.sendSOAPLogoutRequest(httptest.NewRequest(http.MethodGet, "/logout", nil), state, 0, f.b.Metadata(), endpoint)

			assert.Equal(t, state.Participants[0].Outcome, LogoutOutcomeFailed)
			assert.Contains(t, state.Participants[0].Reason, tc.reason)
			assert.Equal(t, state.Current, -1)
			assert.Equal(t, state.PendingRequestID, "")

			if tc.check != nil {
				tc.check(t, recorder.Received())
			}
		})
	}
}

func TestHTTPClientDefault(t *testing.T) {
	client := (&IdentityProvider{}).httpClient()
	assert.Equal(t, client.Timeout, 10*time.Second)
	require.NotNil(t, client.CheckRedirect)
	assert.True(t, errors.Is(client.CheckRedirect(nil, nil), http.ErrUseLastResponse))
}

func TestHTTPClientSet(t *testing.T) {
	t.Run("ShouldNotFollowRedirectsAndDefaultTheTimeout", func(t *testing.T) {
		transport := &http.Transport{}
		set := &http.Client{Transport: transport}

		client := (&IdentityProvider{HTTPClient: set}).httpClient()
		assert.True(t, client != set)
		assert.True(t, client.Transport == transport)
		assert.Equal(t, client.Timeout, 10*time.Second)
		require.NotNil(t, client.CheckRedirect)
		assert.True(t, errors.Is(client.CheckRedirect(nil, nil), http.ErrUseLastResponse))

		assert.True(t, set.CheckRedirect == nil, "the client that was set is not changed")
		assert.Equal(t, set.Timeout, time.Duration(0))
	})

	t.Run("ShouldKeepTheTimeout", func(t *testing.T) {
		set := &http.Client{Timeout: 5 * time.Second}

		assert.Equal(t, (&IdentityProvider{HTTPClient: set}).httpClient().Timeout, 5*time.Second)
	})

	t.Run("ShouldNotFollowARedirect", func(t *testing.T) {
		var paths []string

		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			paths = append(paths, r.URL.Path)
			http.Redirect(w, r, "/other", http.StatusFound)
		}))
		t.Cleanup(server.Close)

		res, err := (&IdentityProvider{HTTPClient: server.Client()}).httpClient().Get(server.URL + "/slo")
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		assert.Equal(t, res.StatusCode, http.StatusFound)
		assert.Equal(t, paths, []string{"/slo"})
	})
}

func TestLogoutRequestEndpointBindings(t *testing.T) {
	testCases := []struct {
		name     string
		bindings []string
		prefer   []string
		expected string
	}{
		{"ShouldPreferPostToSOAPOnFrontChannel", []string{SOAPBinding, HTTPPostBinding}, frontChannelLogoutBindings, HTTPPostBinding},
		{"ShouldFallBackToSOAPOnFrontChannel", []string{SOAPBinding}, frontChannelLogoutBindings, SOAPBinding},
		{"ShouldNotPickPostOnBackChannel", []string{HTTPPostBinding}, backChannelLogoutBindings, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPropagationFixture(t)
			f.b.LogoutBindings = tc.bindings

			endpoint, err := f.test.IDP.logoutRequestEndpoint(f.b.Metadata(), tc.prefer...)

			if tc.expected == "" {
				assert.NotNil(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, endpoint.Binding, tc.expected)
			assert.Equal(t, endpoint.Location, f.b.SloURL.String())
		})
	}
}

func TestContinueLogoutSOAPParticipantInline(t *testing.T) {
	t.Run("ShouldLogOutSOAPParticipantAfterFrontChannel", func(t *testing.T) {
		f, _, recorder := newSOAPLogoutFixture(t, nil)

		w := f.startLogout(t)
		assert.Len(t, recorder.Received(), 0)

		w = serveSLO(f.test, respondAsSP(t, f.a, sentLogoutRequest(t, w)))
		assert.Equal(t, w.Code, http.StatusNoContent)
		assert.Len(t, recorder.Received(), 1)

		require.NotNil(t, f.provider.result)
		assert.Equal(t, participantOutcomes(f.provider.result.Participants), map[string]LogoutOutcome{
			f.a.MetadataURL.String(): LogoutOutcomeSuccess,
			f.b.MetadataURL.String(): LogoutOutcomeSuccess,
		})
	})

	t.Run("ShouldLogOutSOAPParticipantBeforeRedirect", func(t *testing.T) {
		f, _, recorder := newSOAPLogoutFixture(t, nil)
		f.provider.participants[f.session.ID][1].IssueInstant = TimeNow().Add(-time.Second)

		w := f.startLogout(t)
		assert.Len(t, recorder.Received(), 1)
		assert.Nil(t, f.provider.result)

		w = serveSLO(f.test, respondAsSP(t, f.a, sentLogoutRequest(t, w)))
		assert.Equal(t, w.Code, http.StatusNoContent)
		assert.Len(t, recorder.Received(), 1)

		require.NotNil(t, f.provider.result)
		assert.Equal(t, participantOutcomes(f.provider.result.Participants), map[string]LogoutOutcome{
			f.a.MetadataURL.String(): LogoutOutcomeSuccess,
			f.b.MetadataURL.String(): LogoutOutcomeSuccess,
		})
	})

	t.Run("ShouldFinishInStartLogoutWithOnlySOAPParticipants", func(t *testing.T) {
		f, _, recorder := newSOAPLogoutFixture(t, nil)
		f.provider.participants[f.session.ID] = f.provider.participants[f.session.ID][1:]

		w := f.startLogout(t)
		assert.Equal(t, w.Code, http.StatusNoContent)
		assert.Len(t, recorder.Received(), 1)

		require.NotNil(t, f.provider.result)
		assert.Equal(t, participantOutcomes(f.provider.result.Participants), map[string]LogoutOutcome{
			f.b.MetadataURL.String(): LogoutOutcomeSuccess,
		})
		assert.Len(t, f.provider.states, 0)
	})
}

func TestContinueLogoutPrefersFrontChannel(t *testing.T) {
	f, _, recorder := newSOAPLogoutFixture(t, nil)
	f.b.LogoutBindings = []string{HTTPRedirectBinding, SOAPBinding}
	f.provider.participants[f.session.ID] = f.provider.participants[f.session.ID][1:]

	w := f.startLogout(t)
	assert.Equal(t, w.Code, http.StatusFound)

	location := sentLogoutRequest(t, w)
	assert.Equal(t, location.Scheme+"://"+location.Host+location.Path, f.b.SloURL.String())
	assert.Len(t, recorder.Received(), 0)
}

// serveLoopbackHTTP serves the handler of the SOAP service provider server at a plain http loopback URL as well, and
// makes it the SingleLogoutService of sp.
func serveLoopbackHTTP(t *testing.T, sp *ServiceProvider, server *httptest.Server) {
	t.Helper()

	plain := httptest.NewServer(server.Config.Handler)
	t.Cleanup(plain.Close)

	require.True(t, strings.HasPrefix(plain.URL, "http://127.0.0.1:"))

	sp.SloURL = mustParseURL(plain.URL + "/saml2/slo")
}

func TestSOAPLogoutLoopbackHTTPEndpoint(t *testing.T) {
	testCases := []struct {
		name     string
		insecure bool
		expected LogoutOutcome
		received int
	}{
		{"ShouldSkipWithoutAllowInsecure", false, LogoutOutcomeSkipped, 0},
		{"ShouldLogOutWithAllowInsecure", true, LogoutOutcomeSuccess, 1},
	}

	for _, tc := range testCases {
		t.Run("BackChannel"+tc.name, func(t *testing.T) {
			f, server, recorder := newSOAPLogoutFixture(t, nil)
			serveLoopbackHTTP(t, f.b, server)
			f.test.IDP.AllowInsecureServiceProviderEndpoints = tc.insecure

			state := newLogoutState(&f.test.IDP, f.provider.participants[f.session.ID], f.a.MetadataURL.String())
			require.Len(t, state.Participants, 1)

			f.test.IDP.backChannelLogout(httptest.NewRequest(http.MethodPost, soapLogoutTestURL, nil), state)

			assert.Equal(t, state.Participants[0].Outcome, tc.expected)
			assert.Len(t, recorder.Received(), tc.received)

			if tc.expected == LogoutOutcomeSkipped {
				assert.Contains(t, state.Participants[0].Reason, ErrInsecureEndpoint.Error())
			}
		})

		t.Run("FrontChannel"+tc.name, func(t *testing.T) {
			f, server, recorder := newSOAPLogoutFixture(t, nil)
			serveLoopbackHTTP(t, f.b, server)
			f.test.IDP.AllowInsecureServiceProviderEndpoints = tc.insecure
			f.provider.participants[f.session.ID] = f.provider.participants[f.session.ID][1:]

			w := f.startLogout(t)
			assert.Equal(t, w.Code, http.StatusNoContent)
			assert.Len(t, recorder.Received(), tc.received)

			require.NotNil(t, f.provider.result)
			assert.Equal(t, participantOutcomes(f.provider.result.Participants), map[string]LogoutOutcome{
				f.b.MetadataURL.String(): tc.expected,
			})
		})
	}
}
