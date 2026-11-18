package saml

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

const logoutResponseTestRequestID = "id-pending"

// logoutResponseState returns the state of a logout with one outstanding request to the test service provider.
func logoutResponseState(test *IdentityProviderTest) *LogoutState {
	state := propagationState(test.SP.MetadataURL.String())
	state.Current = 0
	state.PendingRequestID = logoutResponseTestRequestID

	return state
}

// signedLogoutResponse returns a response from sp on the binding. It is signed by signer, which is sp unless
// the test needs another key, after mutate has changed it; a nil signer leaves it unsigned.
func signedLogoutResponse(t *testing.T, binding string, sp, signer *ServiceProvider, mutate func(*LogoutResponse)) *http.Request {
	t.Helper()

	unsigned := *sp
	unsigned.SignatureMethod = ""
	response, err := unsigned.MakeLogoutResponse(logoutTestSLOURL, logoutResponseTestRequestID)
	assert.NilError(t, err)

	if mutate != nil {
		mutate(response)
	}

	if binding == HTTPRedirectBinding {
		u, err := response.Redirect("state-id", signer)
		assert.NilError(t, err)

		return httptest.NewRequest(http.MethodGet, u.String(), nil)
	}

	if signer != nil {
		assert.NilError(t, signer.SignLogoutResponse(response))
	}

	doc := etree.NewDocument()
	doc.SetRoot(response.Element())
	body, err := doc.WriteToBytes()
	assert.NilError(t, err)

	form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(body)}, "RelayState": {"state-id"}}
	r := httptest.NewRequest(http.MethodPost, logoutTestSLOURL, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return r
}

func validateLogoutResponse(test *IdentityProviderTest, r *http.Request, state *LogoutState) (*IdpLogoutResponse, error) {
	resp, err := NewIdpLogoutResponse(&test.IDP, r)
	if err != nil {
		return nil, err
	}

	return resp, resp.Validate(state)
}

func TestLogoutResponseValid(t *testing.T) {
	for _, binding := range []string{HTTPRedirectBinding, HTTPPostBinding} {
		t.Run(binding, func(t *testing.T) {
			test, _ := logoutTestIDP(t)
			state := logoutResponseState(test)

			resp, err := validateLogoutResponse(test, signedLogoutResponse(t, binding, &test.SP, &test.SP, nil), state)
			assert.NilError(t, err)
			assert.Check(t, is.Equal(resp.RelayState, "state-id"))

			resp.outcome(state)
			assert.Check(t, is.Equal(state.Participants[0].Outcome, LogoutOutcomeSuccess))
			assert.Check(t, is.Equal(state.PendingRequestID, logoutResponseTestRequestID))
		})
	}
}

func TestLogoutResponseRejects(t *testing.T) {
	cases := []struct {
		name         string
		mutate       func(*LogoutResponse)
		state        func(*LogoutState)
		signer       func(*testing.T, *IdentityProviderTest) *ServiceProvider
		expected     string
		uncorrelated bool
	}{
		{name: "unsigned", signer: func(*testing.T, *IdentityProviderTest) *ServiceProvider { return nil }, expected: "response is not signed"},
		{name: "signed by another key", signer: func(t *testing.T, test *IdentityProviderTest) *ServiceProvider {
			other := serviceProviderWithOtherKey(t, test)

			return &other
		}, expected: "invalid response signature"},
		{name: "wrong InResponseTo", mutate: func(r *LogoutResponse) { r.InResponseTo = "id-other" }, expected: "response is not to the outstanding logout request", uncorrelated: true},
		{name: "no InResponseTo", mutate: func(r *LogoutResponse) { r.InResponseTo = "" }, state: func(s *LogoutState) { s.PendingRequestID = "" }, expected: "response is not to the outstanding logout request", uncorrelated: true},
		{name: "wrong issuer", mutate: func(r *LogoutResponse) { r.Issuer.Value = "https://other.example.com/metadata" }, expected: "response is not from the service provider that was sent the logout request", uncorrelated: true},
		{name: "no issuer", mutate: func(r *LogoutResponse) { r.Issuer = nil }, expected: "response is not from the service provider that was sent the logout request", uncorrelated: true},
		{name: "unrelated with version 1.0", mutate: func(r *LogoutResponse) { r.InResponseTo, r.Version = "id-other", "1.0" }, expected: "response is not to the outstanding logout request", uncorrelated: true},
		{name: "wrong destination", mutate: func(r *LogoutResponse) { r.Destination = "https://idp.example.com/other" }, expected: `not "https://idp.example.com/other"`},
		{name: "expired", mutate: func(r *LogoutResponse) { r.IssueInstant = r.IssueInstant.Add(-MaxIssueDelay - MaxClockSkew) }, expected: "response expired at"},
		{name: "in the future", mutate: func(r *LogoutResponse) { r.IssueInstant = r.IssueInstant.Add(MaxClockSkew + time.Minute) }, expected: "response issued in the future"},
		{name: "version 1.0", mutate: func(r *LogoutResponse) { r.Version = "1.0" }, expected: "expected SAML response version 2.0 got 1.0"},
		{name: "no outstanding request", state: func(s *LogoutState) { s.Current = -1 }, expected: "there is no outstanding logout request", uncorrelated: true},
	}

	for _, binding := range []string{HTTPRedirectBinding, HTTPPostBinding} {
		for _, tc := range cases {
			t.Run(binding+"/"+tc.name, func(t *testing.T) {
				test, _ := logoutTestIDP(t)
				state := logoutResponseState(test)

				if tc.state != nil {
					tc.state(state)
				}

				signer := &test.SP
				if tc.signer != nil {
					signer = tc.signer(t, test)
				}

				_, err := validateLogoutResponse(test, signedLogoutResponse(t, binding, &test.SP, signer, tc.mutate), state)
				assert.ErrorContains(t, err, tc.expected)
				assert.Check(t, is.Equal(errors.Is(err, ErrLogoutResponseUncorrelated), tc.uncorrelated), "error: %v", err)
			})
		}
	}

	t.Run("oversized body", func(t *testing.T) {
		test, _ := logoutTestIDP(t)
		form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 2*maxAuthnRequestBodySize)))}}
		r := httptest.NewRequest(http.MethodPost, logoutTestSLOURL, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err := validateLogoutResponse(test, r, logoutResponseState(test))
		assert.ErrorContains(t, err, "request body too large")
	})

	t.Run("unknown service provider", func(t *testing.T) {
		test, _ := logoutTestIDP(t)
		state := logoutResponseState(test)
		state.Participants[0].ServiceProviderEntityID = "https://unknown.example.com/metadata"

		_, err := validateLogoutResponse(test, signedLogoutResponse(t, HTTPPostBinding, &test.SP, &test.SP, func(r *LogoutResponse) {
			r.Issuer.Value = "https://unknown.example.com/metadata"
		}), state)
		assert.ErrorContains(t, err, "cannot find service provider https://unknown.example.com/metadata")
	})
}

func TestLogoutResponseNonSuccessStatus(t *testing.T) {
	for _, binding := range []string{HTTPRedirectBinding, HTTPPostBinding} {
		t.Run(binding, func(t *testing.T) {
			test, _ := logoutTestIDP(t)
			state := logoutResponseState(test)

			r := signedLogoutResponse(t, binding, &test.SP, &test.SP, func(r *LogoutResponse) {
				r.Status.StatusCode.Value = StatusRequester
			})

			resp, err := validateLogoutResponse(test, r, state)
			assert.NilError(t, err)

			resp.outcome(state)
			assert.Check(t, is.Equal(state.Participants[0].Outcome, LogoutOutcomeFailed))
			assert.Check(t, is.Equal(state.Participants[0].Reason, StatusRequester))
		})
	}
}

func TestLogoutResponseOutcomeWithoutStatusIsFailed(t *testing.T) {
	test, _ := logoutTestIDP(t)
	state := logoutResponseState(test)
	resp := &IdpLogoutResponse{}

	resp.outcome(state)
	assert.Check(t, is.Equal(state.Participants[0].Outcome, LogoutOutcomeFailed))
}

func TestLogoutResponseOutcome(t *testing.T) {
	testCases := []struct {
		name     string
		code     StatusCode
		outcome  LogoutOutcome
		expected string
	}{
		{"Success", StatusCode{Value: StatusSuccess}, LogoutOutcomeSuccess, ""},
		{"SuccessPartialLogout", StatusCode{Value: StatusSuccess, StatusCode: &StatusCode{Value: StatusPartialLogout}}, LogoutOutcomeFailed, StatusPartialLogout},
		{"SuccessOtherSecondLevel", StatusCode{Value: StatusSuccess, StatusCode: &StatusCode{Value: StatusRequestDenied}}, LogoutOutcomeSuccess, ""},
		{"Responder", StatusCode{Value: StatusResponder}, LogoutOutcomeFailed, StatusResponder},
		{"ResponderPartialLogout", StatusCode{Value: StatusResponder, StatusCode: &StatusCode{Value: StatusPartialLogout}}, LogoutOutcomeFailed, StatusResponder},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			test, _ := logoutTestIDP(t)
			state := logoutResponseState(test)
			resp := &IdpLogoutResponse{Response: LogoutResponse{Status: Status{StatusCode: tc.code}}}

			resp.outcome(state)
			assert.Check(t, is.Equal(state.Participants[0].Outcome, tc.outcome))
			assert.Check(t, is.Equal(state.Participants[0].Reason, tc.expected))
		})
	}
}
