package saml

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/dsig"
)

// eventsOfKind returns the events that observer recorded of the kind.
func eventsOfKind(observer *RecordingObserver, kind EventKind) []Event {
	var events []Event

	for _, event := range observer.Events() {
		if event.Kind == kind {
			events = append(events, event)
		}
	}

	return events
}

// An algorithm that was not negotiated is reported as verified only if the request that the message answers is,
// or if there is none and the identity provider chose the service provider.
func TestAlgorithmFallbackIsVerifiedAsItsRequest(t *testing.T) {
	test := issuanceTestIDP(t)
	bits := test.IDP.Key.(*rsa.PrivateKey).N.BitLen()

	metadata := test.SP.Metadata()
	algorithmsListed([]SigningMethod{{Algorithm: dsig.RSASHA512SignatureMethod, MinKeySize: bits * 2}}, nil)(metadata)

	for _, tc := range []struct {
		name     string
		request  *IdpAuthnRequest
		verified bool
	}{
		{name: "unsigned request", request: &IdpAuthnRequest{ServiceProviderMetadata: metadata}},
		{name: "signed request", request: &IdpAuthnRequest{ServiceProviderMetadata: metadata, requestAuthenticated: true}, verified: true},
		{name: "chosen by the identity provider", request: &IdpAuthnRequest{ServiceProviderMetadata: metadata, serviceProviderChosen: true}, verified: true},
		{name: "no request", verified: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var observer RecordingObserver

			test.IDP.Observer = &observer

			_, err := test.IDP.issuance(IssuanceRequest{ServiceProviderMetadata: metadata, AuthnRequest: tc.request})
			require.NoError(t, err)

			events := eventsOfKind(&observer, EventAlgorithmFallback)
			require.Len(t, events, 1)
			assert.Equal(t, events[0].Verified, tc.verified)
			assert.Equal(t, events[0].ServiceProvider, metadata.EntityID)
		})
	}
}

// A subject-id that is left out is reported as verified only if the request is.
func TestInvalidSubjectIDWarningIsVerifiedAsItsRequest(t *testing.T) {
	wanted := service(0, nil, requested(SubjectIDAttributeName, uriAttrNameFormat))

	for _, authenticated := range []bool{false, true} {
		test := NewIdentityProviderTest(t, applyKey)

		var observer RecordingObserver

		test.IDP.Observer = &observer

		req := attributeReleaseRequest(t, test, "", wanted)
		req.requestAuthenticated = authenticated

		releasedAttributes(t, req, &Session{ID: "s", NameID: "alice", SubjectID: "alice"})

		events := eventsOfKind(&observer, EventAttributeRelease)
		require.Len(t, events, 1)
		assert.Equal(t, events[0].Outcome, OutcomeWarning)
		assert.Equal(t, events[0].Verified, authenticated)
	}
}

// A participant that answers with PartialLogout is reported with a warning, and one that answers with an error
// with a failure, while the logout as a whole is partial either way.
func TestLogoutParticipantPartialLogoutIsWarning(t *testing.T) {
	for _, tc := range []struct {
		code    StatusCode
		outcome Outcome
	}{
		{code: StatusCode{Value: StatusSuccess, StatusCode: &StatusCode{Value: StatusPartialLogout}}, outcome: OutcomeWarning},
		{code: StatusCode{Value: StatusResponder}, outcome: OutcomeFailure},
	} {
		t.Run(tc.code.Value, func(t *testing.T) {
			f := newPropagationFixture(t)

			var observer RecordingObserver

			f.test.IDP.Observer = &observer

			w := f.startLogout(t)
			w = serveSLO(f.test, respondAsSPWithStatusCode(t, f.a, sentLogoutRequest(t, w), tc.code))
			serveSLO(f.test, respondAsSP(t, f.b, sentLogoutRequest(t, w)))

			require.NotNil(t, f.provider.result)
			assert.True(t, f.provider.result.Partial())
			assert.Equal(t, f.provider.result.Participants[0].Outcome, LogoutOutcomeFailed)

			var outcomes []Outcome

			for _, event := range eventsOfKind(&observer, EventLogoutPropagation) {
				if event.ServiceProvider == f.a.MetadataURL.String() {
					outcomes = append(outcomes, event.Outcome)
					assert.True(t, event.Verified)
					assert.NotNil(t, event.Err)
				}
			}

			assert.Equal(t, outcomes, []Outcome{tc.outcome})
		})
	}
}

// A logout response that can't be written is reported with an error that is both the failure to write it and
// the failure that it was to report.
func TestLogoutResponseWriteFailureKeepsBothCauses(t *testing.T) {
	test, _ := logoutTestIDP(t)

	policyErr := errors.New("no issuance for this service provider")
	test.IDP.IssuancePolicy = issuancePolicyFunc(func(IssuanceRequest) (Issuance, error) {
		return Issuance{}, policyErr
	})

	var observer RecordingObserver

	test.IDP.Observer = &observer

	metadata := test.SP.Metadata()
	req := &IdpLogoutRequest{
		IDP:                     &test.IDP,
		HTTPRequest:             httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/slo", nil),
		ServiceProviderMetadata: metadata,
		SLOEndpoint:             &Endpoint{Binding: HTTPRedirectBinding, Location: "https://sp.example.com/saml2/slo"},
		Now:                     TimeNow(),
	}

	req.fail(httptest.NewRecorder(), ErrRequestDenied)

	events := eventsOfKind(&observer, EventLogout)
	require.Len(t, events, 1)
	assert.True(t, errors.Is(events[0].Err, ErrServerError))
	assert.True(t, errors.Is(events[0].Err, policyErr))
	assert.True(t, errors.Is(events[0].Err, ErrRequestDenied))
}

// A SessionProvider that refuses a request with WriteErrorResponse has it reported as one EventSSO with the
// error, and one that shows a login form has nothing reported.
func TestServeSSOReportsRefusalOfSessionProvider(t *testing.T) {
	for _, tc := range []struct {
		name   string
		get    func(w http.ResponseWriter, req *IdpAuthnRequest) *Session
		events int
	}{
		{
			name: "refusal",
			get: func(w http.ResponseWriter, req *IdpAuthnRequest) *Session {
				require.NoError(t, req.WriteErrorResponse(w, ErrRequestDenied.WithDebug("the user declined")))

				return nil
			},
			events: 1,
		},
		{
			name: "login form",
			get: func(w http.ResponseWriter, _ *IdpAuthnRequest) *Session {
				_, _ = w.Write([]byte("<form></form>"))

				return nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := issuanceTestIDP(t)

			var observer RecordingObserver

			test.IDP.Observer = &observer
			test.IDP.SessionProvider = &mockSessionProvider{
				GetSessionFunc: func(w http.ResponseWriter, _ *http.Request, req *IdpAuthnRequest) *Session {
					return tc.get(w, req)
				},
			}

			serveSSO(test, replayPostRequest(signedPostBody(t, &test.SP, nil), nil))

			events := eventsOfKind(&observer, EventSSO)
			require.Len(t, events, tc.events)

			if tc.events != 0 {
				assert.Equal(t, events[0].Outcome, OutcomeFailure)
				assert.True(t, errors.Is(events[0].Err, ErrRequestDenied))
				assert.True(t, events[0].Verified)
			}
		})
	}
}

// An attribute of a StatusDetail child must have a prefix that is declared within the child.
func TestCheckStatusDetailChildAttributePrefixes(t *testing.T) {
	parse := func(t *testing.T, xml string) *etree.Element {
		t.Helper()

		doc := etree.NewDocument()
		require.NoError(t, doc.ReadFromString(xml))

		return doc.Root()
	}

	for _, tc := range []struct {
		name string
		xml  string
		ok   bool
	}{
		{name: "declared on the child", xml: `<a:Detail xmlns:a="urn:a" a:kind="x"/>`, ok: true},
		{name: "declared on a descendant", xml: `<a:Detail xmlns:a="urn:a"><b:Item xmlns:b="urn:b" b:kind="x"/></a:Detail>`, ok: true},
		{name: "xml prefix", xml: `<a:Detail xmlns:a="urn:a" xml:lang="en"/>`, ok: true},
		{name: "undeclared on the child", xml: `<a:Detail xmlns:a="urn:a" c:kind="x"/>`},
		{name: "undeclared on a descendant", xml: `<a:Detail xmlns:a="urn:a"><a:Item c:kind="x"/></a:Detail>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkStatusDetailChild(parse(t, tc.xml))
			assert.Equal(t, err == nil, tc.ok, "%v", err)
		})
	}

	// A prefix that only the parent of the child declares is not one that the child declares.
	parent := parse(t, `<p:Parent xmlns:p="urn:p" xmlns:c="urn:c"><a:Detail xmlns:a="urn:a" c:kind="x"/></p:Parent>`)
	assert.NotNil(t, checkStatusDetailChild(parent.ChildElements()[0]))
}
