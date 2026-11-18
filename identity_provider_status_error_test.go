package saml

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/dsig"
)

// hostileMarker is text that a test sends in a request, which must never come back in a response unless the debug
// message is exposed, and then only in the Debug element.
const hostileMarker = "HOSTILE-MARKER"

// lastEvent returns the one event that the identity provider of test reported.
func lastEvent(t *testing.T, test *IdentityProviderTest) Event {
	t.Helper()

	events := test.Events.Events()
	require.Len(t, events, 1, "%v", events)

	return events[0]
}

// debugDetail returns the text of the Debug element in the StatusDetail of status, or "" if it has none.
func debugDetail(status Status) string {
	for _, child := range statusDetailChildren(status) {
		if child.Tag == "Debug" && child.NamespaceURI() == StatusDetailDebugNamespace {
			return child.Text()
		}
	}

	return ""
}

func postAuthnRequest(t *testing.T, request *AuthnRequest) *http.Request {
	t.Helper()

	doc := etree.NewDocument()
	doc.SetRoot(request.Element())

	body, err := doc.WriteToBytes()
	require.NoError(t, err)

	return replayPostRequest(body, nil)
}

// A request that fails before the endpoint for the response is chosen from metadata is answered with HTTP, and
// one that fails after it with a signed SAML response, whatever the error is.
func TestServeSSODispositionFollowsTheRequestStage(t *testing.T) {
	for _, tc := range []struct {
		name        string
		modify      func(test *IdentityProviderTest, request *AuthnRequest)
		err         *StatusError
		respondable bool
		httpStatus  int

		// silent is whether the error says nothing of the request, as there is nothing to say or as what there
		// is to say is deliberately left out.
		silent bool
	}{
		{
			name:   "malformed",
			modify: func(_ *IdentityProviderTest, request *AuthnRequest) { request.ID = "bad id " + hostileMarker },
			err:    ErrMalformedRequest, httpStatus: http.StatusBadRequest, silent: true,
		},
		{
			name: "unknown service provider",
			modify: func(_ *IdentityProviderTest, request *AuthnRequest) {
				request.Issuer.Value = "https://" + hostileMarker + ".example.com/\nforged"
			},
			err: ErrUnknownServiceProvider, httpStatus: http.StatusBadRequest,
		},
		{
			name: "service provider lookup fails",
			modify: func(test *IdentityProviderTest, _ *AuthnRequest) {
				test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
					GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) {
						return nil, errors.New("database " + hostileMarker + " is down")
					},
				}
			},
			err: ErrServerError, httpStatus: http.StatusInternalServerError,
		},
		{
			name:   "signature required",
			modify: func(test *IdentityProviderTest, _ *AuthnRequest) { test.IDP.WantAuthnRequestsSigned = true },
			err:    ErrSignatureRequired, httpStatus: http.StatusBadRequest, silent: true,
		},
		{
			name: "no endpoint",
			modify: func(_ *IdentityProviderTest, request *AuthnRequest) {
				request.AssertionConsumerServiceURL = "https://" + hostileMarker + ".example.com/acs"
			},
			err: ErrNoResponseEndpoint, httpStatus: http.StatusBadRequest, silent: true,
		},
		{
			name: "destination",
			modify: func(_ *IdentityProviderTest, request *AuthnRequest) {
				request.Destination = "https://" + hostileMarker + ".example.com/sso"
			},
			err: ErrDestinationMismatch, respondable: true,
		},
		{
			name:   "version",
			modify: func(_ *IdentityProviderTest, request *AuthnRequest) { request.Version = "3." + hostileMarker },
			err:    ErrVersionMismatch, respondable: true,
		},
		{
			name: "binding",
			modify: func(_ *IdentityProviderTest, request *AuthnRequest) {
				request.ProtocolBinding = "urn:" + hostileMarker
				request.AssertionConsumerServiceURL = ""
			},
			err: ErrUnsupportedBinding, respondable: true,
		},
	} {
		for _, exposeDebug := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/expose debug %v", tc.name, exposeDebug), func(t *testing.T) {
				test := NewIdentityProviderTest(t, applyKey)
				test.IDP.ExposeDebug = exposeDebug

				request, err := test.SP.MakeAuthenticationRequest("https://idp.example.com/saml/sso", HTTPPostBinding, HTTPPostBinding)
				require.NoError(t, err)

				tc.modify(test, request)

				w := serveSSO(test, postAuthnRequest(t, request))

				// The reason is always given to the Observer, as one event for the request.
				event := lastEvent(t, test)
				assert.Equal(t, event.Kind, EventSSO)
				assert.Equal(t, event.Outcome, OutcomeFailure)
				assert.True(t, errors.Is(event.Err, tc.err), "%+v", event.Err)
				assert.False(t, event.Verified)
				assert.Equal(t, strings.Contains(event.Err.Debug()+event.ServiceProvider, hostileMarker), !tc.silent)
				assert.False(t, strings.Contains(event.Err.Error(), hostileMarker))
				assert.False(t, strings.ContainsAny(event.String(), "\n\r"))

				if !tc.respondable {
					// Nothing of the request, and no SAML response, in the answer: there is nowhere to send one.
					assert.Equal(t, w.Code, tc.httpStatus)
					assert.Equal(t, w.Body.String(), http.StatusText(tc.httpStatus)+"\n")

					return
				}

				require.Equal(t, w.Code, http.StatusOK, w.Body.String())

				doc, response := postedResponse(t, w.Body.String())

				top, second := statusCodes(response.Status)
				assert.Equal(t, top, tc.err.TopLevelField)
				assert.Equal(t, second, tc.err.SecondLevelField)
				assert.Equal(t, response.Status.StatusMessage.Value, tc.err.StatusMessageField)
				assert.Nil(t, response.Assertion)

				written, err := doc.WriteToString()
				require.NoError(t, err)

				if !exposeDebug {
					assert.Nil(t, response.Status.StatusDetail)
					assert.False(t, strings.Contains(written, hostileMarker), written)
					assert.False(t, strings.Contains(w.Body.String(), hostileMarker))

					return
				}

				// The debug message is in the Debug element, and nowhere else.
				assert.Contains(t, debugDetail(response.Status), hostileMarker)
				assert.Equal(t, strings.Count(written, hostileMarker), strings.Count(debugDetail(response.Status), hostileMarker))

				// It is part of what the identity provider signs.
				assert.NotNil(t, doc.Root().FindElement("./Signature"))
				assertSignedByIDP(t, test, doc.Root())
			})
		}
	}
}

// assertSignedByIDP checks the enveloped signature of the identity provider of test on el.
func assertSignedByIDP(t *testing.T, test *IdentityProviderTest, el *etree.Element) {
	t.Helper()

	previousClock := Clock

	defer func() { Clock = previousClock }()

	Clock = dsig.NewFakeClockAt(test.Certificate.NotBefore)

	test.SP.IDPMetadata = test.IDP.Metadata()
	assert.NoError(t, test.SP.validateSignature(el))
}

// The HTTPErrorHandler renders the answer to a request that can't be answered with a SAML response.
func TestHTTPErrorHandler(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)

	var handled *StatusError

	test.IDP.HTTPErrorHandler = func(w http.ResponseWriter, r *http.Request, err *StatusError) {
		handled = err

		assert.NotNil(t, r)
		http.Error(w, "our own page", err.HTTPStatus())
	}

	w, _ := serveSSOModified(t, test, func(request *AuthnRequest) { request.Issuer.Value = "https://unknown.example.com" })

	assert.Equal(t, w.Code, http.StatusBadRequest)
	assert.Equal(t, w.Body.String(), "our own page\n")
	require.NotNil(t, handled)
	assert.True(t, errors.Is(handled, ErrUnknownServiceProvider))
	assert.Contains(t, handled.Debug(), "https://unknown.example.com")

	// It is not asked about a request that is answered with a SAML response.
	handled = nil

	w, id := serveSSOModified(t, test, func(request *AuthnRequest) { request.Version = "1.1" })
	assertRequestStatus(t, w, id, StatusVersionMismatch, StatusRequestVersionTooLow)
	assert.Nil(t, handled)

	// A request that could not be parsed at all, and the single logout service, use it too.
	w = serveSSO(test, httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/sso?SAMLRequest=%21", nil))
	assert.Equal(t, w.Body.String(), "our own page\n")
	assert.True(t, errors.Is(handled, ErrMalformedRequest))

	handled = nil

	w = serveSLO(test, httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/slo?SAMLRequest=%21", nil))
	assert.Equal(t, w.Code, http.StatusBadRequest)
	assert.True(t, errors.Is(handled, ErrMalformedRequest))
}

// An application reports its own failures with the errors of the package, or with its own, and what it adds to
// the status reaches the service provider in the signed response.
func TestSessionProviderWritesStatusError(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)

	locked, err := NewStatusError("account_locked", StatusResponder, "https://idp.example.com/status/account-locked",
		"the account is locked", http.StatusForbidden)
	require.NoError(t, err)

	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, _ *http.Request, req *IdpAuthnRequest) *Session {
			assert.True(t, req.Respondable())
			assert.NoError(t, req.WriteErrorResponse(w, locked.
				WithStatusDetail(testStatusDetail("until tomorrow")).
				WithDebugf("the account of %s is locked", hostileMarker)))

			return nil
		},
	}

	w, id := serveSSOModified(t, test, func(*AuthnRequest) {})
	require.Equal(t, w.Code, http.StatusOK, w.Body.String())

	doc, response := postedResponse(t, w.Body.String())
	assert.Equal(t, response.InResponseTo, id)

	top, second := statusCodes(response.Status)
	assert.Equal(t, top, StatusResponder)
	assert.Equal(t, second, "https://idp.example.com/status/account-locked")
	assert.Equal(t, response.Status.StatusMessage.Value, "the account is locked")

	children := statusDetailChildren(response.Status)
	require.Len(t, children, 1)
	assert.Equal(t, children[0].Tag, "Reason")
	assert.Equal(t, children[0].NamespaceURI(), "https://example.com/ns/status")
	assert.Equal(t, children[0].Text(), "until tomorrow")
	assert.False(t, strings.Contains(w.Body.String(), hostileMarker))

	assertSignedByIDP(t, test, doc.Root())

	// What the service provider makes of it: the codes are fields, and the rest is untrusted text.
	received := StatusErrorFromStatus(response.Status)
	assert.True(t, errors.Is(received, ErrReceivedStatus))
	assert.Equal(t, received.SecondLevelField, "https://idp.example.com/status/account-locked")
	assert.Contains(t, received.Debug(), "the account is locked")
	assert.Contains(t, received.Debug(), "until tomorrow")
	assert.Len(t, received.StatusDetailField, 0)
}

// Each operation that completes is reported once, with who it was for.
func TestServeSSOReportsOneEvent(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		useSession(test)

		w, id := serveSSOModified(t, test, func(*AuthnRequest) {})
		assertAssertionResponse(t, w, id)

		event := lastEvent(t, test)
		assert.Equal(t, event.Kind, EventSSO)
		assert.Equal(t, event.Outcome, OutcomeSuccess)
		assert.Nil(t, event.Err)
		assert.Equal(t, event.ServiceProvider, test.SP.MetadataURL.String())
		assert.Equal(t, event.RequestID, id)
		assert.False(t, event.Time.IsZero())

		// The request was not signed, so nobody is known to have sent it.
		assert.False(t, event.Verified)
	})

	t.Run("signed", func(t *testing.T) {
		test := signatureTestIDP(t)
		useSession(test)

		w := serveSSO(test, replayPostRequest(signedPostBody(t, &test.SP, nil), nil))
		assert.Equal(t, w.Code, http.StatusOK)

		event := lastEvent(t, test)
		assert.Equal(t, event.Outcome, OutcomeSuccess)
		assert.True(t, event.Verified)
	})

	t.Run("login form", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.SessionProvider = &mockSessionProvider{
			GetSessionFunc: func(w http.ResponseWriter, _ *http.Request, _ *IdpAuthnRequest) *Session {
				w.WriteHeader(http.StatusOK)

				return nil
			},
		}

		serveSSOModified(t, test, func(*AuthnRequest) {})

		// The request is not finished with, so there is nothing to report.
		assert.Len(t, test.Events.Events(), 0)
	})

	t.Run("refused by the assertion maker", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		useSession(test)

		test.IDP.AssertionMaker = assertionMakerFunc(func(*IdpAuthnRequest, *Session) error {
			return fmt.Errorf("%w: no format for %s", ErrInvalidNameIDPolicy, hostileMarker)
		})

		w, id := serveSSOModified(t, test, func(*AuthnRequest) {})
		assertRequestStatus(t, w, id, StatusRequester, StatusInvalidNameIDPolicy)
		assert.False(t, strings.Contains(w.Body.String(), hostileMarker))

		event := lastEvent(t, test)
		assert.Equal(t, event.Outcome, OutcomeFailure)
		assert.True(t, errors.Is(event.Err, ErrInvalidNameIDPolicy))
		assert.Contains(t, event.Err.Debug(), hostileMarker)
	})

	t.Run("idp initiated", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		useSession(test)

		w := httptest.NewRecorder()
		test.IDP.ServeIDPInitiated(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/services/sp", nil), test.SP.MetadataURL.String(), "")
		assert.Equal(t, w.Code, http.StatusOK)

		event := lastEvent(t, test)
		assert.Equal(t, event.Kind, EventIDPInitiatedSSO)
		assert.Equal(t, event.Outcome, OutcomeSuccess)
		assert.True(t, event.Verified)

		test.Events.Reset()

		w = httptest.NewRecorder()
		test.IDP.ServeIDPInitiated(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/services/sp", nil), "https://unknown.example.com", "")
		assert.Equal(t, w.Code, http.StatusNotFound)

		event = lastEvent(t, test)
		assert.Equal(t, event.Outcome, OutcomeFailure)
		assert.True(t, errors.Is(event.Err, ErrUnknownServiceProvider))
		assert.False(t, event.Verified)
	})
}

func TestServeSLOReportsAndEncodesErrors(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		test, _ := logoutTestIDP(t)

		r, id := redirectLogoutRequest(t, &test.SP, nil)
		w := serveSLO(test, r)
		assert.Equal(t, w.Code, http.StatusFound)

		event := lastEvent(t, test)
		assert.Equal(t, event.Kind, EventLogout)
		assert.Equal(t, event.Outcome, OutcomeSuccess)
		assert.True(t, event.Verified)
		assert.Equal(t, event.RequestID, id)
	})

	t.Run("not respondable", func(t *testing.T) {
		test, provider := logoutTestIDP(t)

		// The request is not signed, so nothing says that the service provider sent it.
		unsigned := test.SP
		unsigned.SignatureMethod = ""

		r, _ := postLogoutRequest(t, &unsigned, nil)
		w := serveSLO(test, r)

		assert.Equal(t, w.Code, http.StatusBadRequest)
		assert.Equal(t, w.Body.String(), "Bad Request\n")
		assert.Len(t, provider.terminated, 0)

		event := lastEvent(t, test)
		assert.Equal(t, event.Outcome, OutcomeFailure)
		assert.True(t, errors.Is(event.Err, ErrSignatureRequired))
		assert.False(t, event.Verified)
	})

	for _, exposeDebug := range []bool{false, true} {
		t.Run(fmt.Sprintf("respondable/expose debug %v", exposeDebug), func(t *testing.T) {
			test, provider := logoutTestIDP(t)
			test.IDP.ExposeDebug = exposeDebug

			r, id := postLogoutRequest(t, &test.SP, func(request *LogoutRequest) {
				request.Destination = "https://" + hostileMarker + ".example.com/slo"
			})

			_, _, response := postedLogoutResponse(t, serveSLO(test, r))

			assert.Equal(t, response.InResponseTo, id)
			assertLogoutStatus(t, &response, StatusRequester, StatusRequestDenied)
			assert.Equal(t, response.Status.StatusMessage.Value, ErrDestinationMismatch.StatusMessageField)
			assert.Equal(t, strings.Contains(debugDetail(response.Status), hostileMarker), exposeDebug)
			assert.Len(t, provider.terminated, 0)

			event := lastEvent(t, test)
			assert.True(t, errors.Is(event.Err, ErrDestinationMismatch))
			assert.True(t, event.Verified)
			assert.Contains(t, event.Err.Debug(), hostileMarker)
		})
	}

	// A partial logout is a result, and is reported with a warning, not as a failure.
	t.Run("partial logout", func(t *testing.T) {
		test, provider := logoutTestIDP(t)
		provider.err = ErrPartialLogout

		r, _ := redirectLogoutRequest(t, &test.SP, nil)
		_, response := redirectedLogoutResponse(t, serveSLO(test, r))
		assertLogoutStatus(t, &response, StatusSuccess, StatusPartialLogout)
		assert.Nil(t, response.Status.StatusMessage)

		event := lastEvent(t, test)
		assert.Equal(t, event.Kind, EventLogout)
		assert.Equal(t, event.Outcome, OutcomeWarning)
		assert.True(t, errors.Is(event.Err, ErrPartialLogout))
	})

	t.Run("session not ended", func(t *testing.T) {
		test, provider := logoutTestIDP(t)
		provider.err = errors.New("the session store is down")

		r, _ := redirectLogoutRequest(t, &test.SP, nil)
		_, response := redirectedLogoutResponse(t, serveSLO(test, r))
		assertLogoutStatus(t, &response, StatusResponder, "")

		events := test.Events.Events()
		require.Len(t, events, 2)
		assert.Equal(t, events[0].Kind, EventSessionTermination)
		assert.Equal(t, events[0].Outcome, OutcomeWarning)
		assert.Contains(t, events[0].Err.Debug(), "the session store is down")
		assert.Equal(t, events[1].Kind, EventLogout)
		assert.Equal(t, events[1].Outcome, OutcomeFailure)
	})
}

// On the SOAP binding every SAML message is answered with a status (SAMLBind §3.2.3.3). Until the requester is
// verified the answer has the status codes and nothing else, whatever is set.
func TestSOAPErrorsOfUnverifiedRequestersSayNothing(t *testing.T) {
	t.Run("logout", func(t *testing.T) {
		test, _ := soapLogoutTestIDP(t)
		test.IDP.Observer = test.Events
		test.IDP.ExposeDebug = true

		unsigned := test.SP
		unsigned.SignatureMethod = ""

		r, id := soapLogoutRequest(t, &unsigned, func(request *LogoutRequest) {
			request.Destination = "https://" + hostileMarker + ".example.com/slo"
		})

		w := serveSOAPLogout(test, r)
		response := soapLogoutResponse(t, w)

		assert.Equal(t, response.InResponseTo, id)
		assertLogoutStatus(t, response, StatusRequester, StatusRequestDenied)
		assert.Nil(t, response.Status.StatusMessage)
		assert.Nil(t, response.Status.StatusDetail)
		assert.False(t, strings.Contains(w.Body.String(), hostileMarker))

		event := lastEvent(t, test)
		assert.Equal(t, event.Kind, EventLogout)
		assert.True(t, errors.Is(event.Err, ErrSignatureRequired))
		assert.False(t, event.Verified)
	})

	t.Run("logout of a verified requester", func(t *testing.T) {
		test, _ := soapLogoutTestIDP(t)
		test.IDP.Observer = test.Events
		test.IDP.ExposeDebug = true

		r, _ := soapLogoutRequest(t, &test.SP, func(request *LogoutRequest) {
			request.Destination = "https://" + hostileMarker + ".example.com/slo"
		})

		response := soapLogoutResponse(t, serveSOAPLogout(test, r))

		assertLogoutStatus(t, response, StatusRequester, StatusRequestDenied)
		assert.Equal(t, response.Status.StatusMessage.Value, ErrDestinationMismatch.StatusMessageField)
		assert.Contains(t, debugDetail(response.Status), hostileMarker)
		assert.True(t, lastEvent(t, test).Verified)

		// Without ExposeDebug the same request is answered with the constant text alone.
		test.IDP.ExposeDebug = false

		r, _ = soapLogoutRequest(t, &test.SP, func(request *LogoutRequest) {
			request.Destination = "https://" + hostileMarker + ".example.com/slo"
		})

		w := serveSOAPLogout(test, r)
		response = soapLogoutResponse(t, w)

		assert.Equal(t, response.Status.StatusMessage.Value, ErrDestinationMismatch.StatusMessageField)
		assert.Nil(t, response.Status.StatusDetail)
		assert.False(t, strings.Contains(w.Body.String(), hostileMarker))
	})

	for _, service := range queryServices {
		t.Run(service.name, func(t *testing.T) {
			f := newQueryFixture(t)
			f.test.IDP.Observer = f.test.Events
			f.test.IDP.ExposeDebug = true

			message := service.message(f)
			message.CreateAttr("Destination", "https://"+hostileMarker+".example.com/query")

			// Not signed: the status codes of the error, and nothing of the request.
			w := f.serve(service, queryPost(t, service.url, message))
			response := f.answer(t, w)

			assertQueryStatus(t, response, StatusRequester, StatusRequestDenied)
			assert.Nil(t, response.Response.Status.StatusMessage)
			assert.Nil(t, response.Response.Status.StatusDetail)
			assert.False(t, strings.Contains(w.Body.String(), hostileMarker))

			event := lastEvent(t, f.test)
			assert.True(t, errors.Is(event.Err, ErrSignatureRequired))
			assert.False(t, event.Verified)

			f.test.Events.Reset()

			// Signed: the requester is established, and is told what failed.
			message = service.message(f)
			message.CreateAttr("Destination", "https://"+hostileMarker+".example.com/query")

			response = f.answer(t, f.serve(service, queryPost(t, service.url, signQueryElement(t, &f.test.SP, message))))

			top, second := statusCodes(response.Response.Status)
			assert.Equal(t, top, StatusRequester)
			assert.Equal(t, second, StatusRequestDenied)
			assert.Equal(t, response.Response.Status.StatusMessage.Value, ErrDestinationMismatch.StatusMessageField)
			assert.Contains(t, debugDetail(response.Response.Status), hostileMarker)

			event = lastEvent(t, f.test)
			assert.True(t, errors.Is(event.Err, ErrDestinationMismatch))
			assert.True(t, event.Verified)
			assert.Equal(t, string(event.Kind), map[string]string{
				attributeQueryMessage:     "attribute_query",
				authnQueryMessage:         "authn_query",
				assertionIDRequestMessage: "assertion_id_request",
			}[service.name])
		})
	}
}

// An artifact that is not resolved is answered with success (SAMLBind §3.6.6), which is a result and not an
// error, and is reported with a warning that says why.
func TestServeArtifactResolutionReportsEvents(t *testing.T) {
	test, _ := artifactTestIDP(t)
	test.IDP.Observer = test.Events
	test.IDP.ExposeDebug = true

	artifact, authnRequestID := issueTestArtifact(t, test, &test.SP)
	test.Events.Reset()

	r, id := artifactResolvePost(t, &test.SP, artifact, nil)
	assertResolvedArtifactResponse(t, serveArtifactResolution(test, r), id, authnRequestID)

	event := lastEvent(t, test)
	assert.Equal(t, event.Kind, EventArtifactResolve)
	assert.Equal(t, event.Outcome, OutcomeSuccess)
	assert.True(t, event.Verified)

	test.Events.Reset()

	// The same artifact again: success with no message, and nothing in the response that says why.
	r, id = artifactResolvePost(t, &test.SP, artifact, nil)
	response, message := artifactResponse(t, serveArtifactResolution(test, r))
	assert.Equal(t, response.InResponseTo, id)
	assert.Equal(t, response.Status.StatusCode.Value, StatusSuccess)
	assert.Nil(t, message)
	assert.Nil(t, response.Status.StatusMessage)
	assert.Nil(t, response.Status.StatusDetail)

	event = lastEvent(t, test)
	assert.Equal(t, event.Outcome, OutcomeWarning)
	assert.Contains(t, event.Err.Debug(), "artifact not resolved")

	test.Events.Reset()

	// A message of another protocol is an error, of a requester that is not established.
	other, _ := soapLogoutRequestElement(t, &test.SP, nil)
	other.CreateAttr("ID", "id-other")

	response, _ = artifactResponse(t, serveArtifactResolution(test, artifactSOAPPost(soapLogoutEnvelope(t, other))))
	assert.Equal(t, response.InResponseTo, "id-other")

	top, second := statusCodes(response.Status)
	assert.Equal(t, top, StatusRequester)
	assert.Equal(t, second, StatusRequestUnsupported)
	assert.Nil(t, response.Status.StatusMessage)
	assert.Nil(t, response.Status.StatusDetail)

	event = lastEvent(t, test)
	assert.Equal(t, event.Outcome, OutcomeFailure)
	assert.True(t, errors.Is(event.Err, ErrRequestUnsupported))
	assert.False(t, event.Verified)

	test.Events.Reset()

	// An error of SOAP itself is a fault, before there is a SAML message to answer (SAMLBind §3.2.3.3).
	w := serveArtifactResolution(test, artifactSOAPPost([]byte("<not-an-envelope/>")))
	assert.Equal(t, w.Code, http.StatusInternalServerError)
	assert.Equal(t, soapFaultCode(t, w), "soapenv:Client")

	event = lastEvent(t, test)
	assert.Equal(t, event.Kind, EventArtifactResolve)
	assert.True(t, errors.Is(event.Err, ErrMalformedRequest))
}

func TestServeSOAPManageNameIDReportsEvents(t *testing.T) {
	test, _ := manageNameIDTestIDP(t)
	test.IDP.Observer = test.Events

	serve := func(opts manageNameIDOptions, signer *ServiceProvider) *httptest.ResponseRecorder {
		el, _ := manageNameIDRequestElement(test, soapManageNameIDTestURL, opts)

		w := httptest.NewRecorder()
		test.IDP.ServeSOAPManageNameID(w, nameIDTestSOAPPost(t, soapManageNameIDTestURL, signTestElement(t, signer, el)))

		return w
	}

	w := serve(manageNameIDOptions{}, &test.SP)
	assert.Equal(t, w.Code, http.StatusOK)

	event := lastEvent(t, test)
	assert.Equal(t, event.Kind, EventNameIDManagement)
	assert.Equal(t, event.Outcome, OutcomeSuccess, "%+v", event)
	assert.True(t, event.Verified)

	test.Events.Reset()

	// Not signed: Requester with RequestDenied and nothing else, and the reason for the Observer.
	w = serve(manageNameIDOptions{}, nil)

	message := nameIDTestSOAPMessage(t, w, "ManageNameIDResponse")
	assert.Nil(t, message.FindElement("./Status/StatusMessage"))
	assert.Nil(t, message.FindElement("./Status/StatusDetail"))
	assert.Equal(t, message.FindElement("./Status/StatusCode/StatusCode").SelectAttrValue("Value", ""), StatusRequestDenied)

	event = lastEvent(t, test)
	assert.Equal(t, event.Outcome, OutcomeFailure)
	assert.True(t, errors.Is(event.Err, ErrSignatureRequired))
	assert.False(t, event.Verified)
}

// The form of the request is the only thing that a malformed request to the front channel services has, so it
// is answered with HTTP by each of them.
func TestFrontChannelServicesAnswerMalformedRequestsWithHTTP(t *testing.T) {
	test, _ := manageNameIDTestIDP(t)
	test.IDP.Observer = test.Events
	test.IDP.LogoutURL = mustParseURL(logoutTestSLOURL)

	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte("<" + hostileMarker))}}

	for name, tc := range map[string]struct {
		serve http.HandlerFunc
		kind  EventKind
	}{
		"sso":                {test.IDP.ServeSSO, EventSSO},
		"slo":                {test.IDP.ServeSLO, EventLogout},
		"name id management": {test.IDP.ServeManageNameID, EventNameIDManagement},
	} {
		t.Run(name, func(t *testing.T) {
			test.Events.Reset()

			r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/saml", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			w := httptest.NewRecorder()
			tc.serve(w, r)

			assert.Equal(t, w.Code, http.StatusBadRequest)
			assert.Equal(t, w.Body.String(), "Bad Request\n")

			event := lastEvent(t, test)
			assert.Equal(t, event.Kind, tc.kind)
			assert.True(t, errors.Is(event.Err, ErrMalformedRequest), "%+v", event.Err)
			assert.Equal(t, event.ServiceProvider, "")
			assert.Equal(t, event.RequestID, "")
		})
	}
}
