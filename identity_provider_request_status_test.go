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
)

// serveSSOModified posts a request made by the test service provider after modify has changed it,
// and returns the recorder.
func serveSSOModified(t *testing.T, test *IdentityProviderTest, modify func(*AuthnRequest)) (*httptest.ResponseRecorder, string) {
	t.Helper()

	request, err := test.SP.MakeAuthenticationRequest("https://idp.example.com/saml/sso", HTTPPostBinding, HTTPPostBinding)
	require.NoError(t, err)

	modify(request)

	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	body, err := doc.WriteToBytes()
	require.NoError(t, err)

	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}}
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/saml/sso", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, r)

	return w, request.ID
}

// assertRequestStatus checks that the response is a SAML error response with the given statuses.
func assertRequestStatus(t *testing.T, w *httptest.ResponseRecorder, id, top, second string) {
	t.Helper()

	require.Equal(t, w.Code, http.StatusOK, "body: %s", w.Body.String())

	_, response := postedResponse(t, w.Body.String())

	assert.Equal(t, response.InResponseTo, id)
	assert.Equal(t, response.Status.StatusCode.Value, top)

	if second == "" {
		assert.Nil(t, response.Status.StatusCode.StatusCode)
	} else {
		require.NotNil(t, response.Status.StatusCode.StatusCode)
		assert.Equal(t, response.Status.StatusCode.StatusCode.Value, second)
	}

	assert.True(t, statusSaysNothingOfTheRequest(response.Status))
	assert.Nil(t, response.Assertion)
	assert.Nil(t, response.EncryptedAssertion)
}

func TestServeSSOVersionMismatch(t *testing.T) {
	for _, tc := range []struct {
		version string
		second  string
	}{
		{"3.0", StatusRequestVersionTooHigh},
		{"1.1", StatusRequestVersionTooLow},
		{"2.1", ""},
		{"x", ""},
	} {
		t.Run(tc.version, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			w, id := serveSSOModified(t, test, func(r *AuthnRequest) { r.Version = tc.version })
			assertRequestStatus(t, w, id, StatusVersionMismatch, tc.second)
		})
	}
}

func TestServeSSOExpiredRequestDenied(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	w, id := serveSSOModified(t, test, func(r *AuthnRequest) { r.IssueInstant = TimeNow().Add(-MaxIssueDelay - MaxClockSkew) })
	assertRequestStatus(t, w, id, StatusRequester, StatusRequestDenied)
}

func TestServeSSOFutureRequestDenied(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	w, id := serveSSOModified(t, test, func(r *AuthnRequest) { r.IssueInstant = TimeNow().Add(2 * MaxClockSkew) })
	assertRequestStatus(t, w, id, StatusRequester, StatusRequestDenied)
}

func TestServeSSOWrongDestinationDenied(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	w, id := serveSSOModified(t, test, func(r *AuthnRequest) { r.Destination = "https://idp.example.com/other" })
	assertRequestStatus(t, w, id, StatusRequester, StatusRequestDenied)
}

func TestServeSSOUnsupportedProtocolBinding(t *testing.T) {
	for name, binding := range map[string]string{
		"artifact": HTTPArtifactBinding,
		"redirect": HTTPRedirectBinding,
		"paos":     "urn:oasis:names:tc:SAML:2.0:bindings:PAOS",
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			w, id := serveSSOModified(t, test, func(r *AuthnRequest) { r.ProtocolBinding = binding })
			assertRequestStatus(t, w, id, StatusResponder, StatusUnsupportedBinding)

			// The status goes to the HTTP-POST endpoint of the metadata.
			_, response := postedResponse(t, w.Body.String())
			assert.Equal(t, response.Destination, test.SP.AcsURL.String())
		})
	}
}

func TestServeSSOVersionMismatchGoesToMetadataACS(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	w, _ := serveSSOModified(t, test, func(r *AuthnRequest) {
		r.Version = "3.0"
		r.AssertionConsumerServiceURL = "https://attacker.example.com/acs"
	})

	assert.Equal(t, w.Code, http.StatusBadRequest)
	assert.False(t, strings.Contains(w.Body.String(), "SAMLResponse"))
}

func TestServeSSOInvalidRequestIDStays400(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	w, _ := serveSSOModified(t, test, func(r *AuthnRequest) { r.ID = "bad id" })

	assert.Equal(t, w.Code, http.StatusBadRequest)
	assert.False(t, strings.Contains(w.Body.String(), "SAMLResponse"))
}

func TestServeSSOSignedRequestFailsRequestStage(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*AuthnRequest)
		top    string
		second string
	}{
		"version":     {func(r *AuthnRequest) { r.Version = "3.0" }, StatusVersionMismatch, StatusRequestVersionTooHigh},
		"destination": {func(r *AuthnRequest) { r.Destination = "https://idp.example.com/other" }, StatusRequester, StatusRequestDenied},
	} {
		t.Run(name, func(t *testing.T) {
			test := signatureTestIDP(t)

			var id string

			body := signedPostBody(t, &test.SP, func(r *AuthnRequest) {
				id = r.ID

				tc.mutate(r)
			})

			form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}}
			r := httptest.NewRequest(http.MethodPost, signatureTestSSOURL, strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			w := httptest.NewRecorder()
			test.IDP.ServeSSO(w, r)

			assertRequestStatus(t, w, id, tc.top, tc.second)
		})
	}
}

type encryptionKeyEnforcerFunc func(*IdpAuthnRequest, ServiceProviderEncryptionKey) error

func (f encryptionKeyEnforcerFunc) EnforceEncryptionKey(req *IdpAuthnRequest, key ServiceProviderEncryptionKey) error {
	return f(req, key)
}

func useSession(test *IdentityProviderTest) {
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
			return &Session{ID: "f00f00", UserName: "alice", NameID: "alice"}
		},
	}
}

func TestServeSSOResponderWhenAssertionMakerFails(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	useSession(test)

	test.IDP.AssertionMaker = assertionMakerFunc(func(*IdpAuthnRequest, *Session) error { return errors.New("boom") })

	w, id := serveSSOModified(t, test, func(*AuthnRequest) {})
	assertRequestStatus(t, w, id, StatusResponder, "")
	assert.False(t, strings.Contains(w.Body.String(), "boom"))
}

func TestServeSSOResponderWhenEncryptionFails(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	useSession(test)

	called := false

	test.IDP.EncryptionKeyEnforcer = encryptionKeyEnforcerFunc(func(*IdpAuthnRequest, ServiceProviderEncryptionKey) error {
		called = true

		return errors.New("boom")
	})

	w, id := serveSSOModified(t, test, func(*AuthnRequest) {})
	assert.True(t, called)
	assertRequestStatus(t, w, id, StatusResponder, "")
	assert.False(t, strings.Contains(w.Body.String(), "boom"))
}

func TestServeSSOInvalidNameIDPolicyFromAssertionMaker(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	useSession(test)

	test.IDP.AssertionMaker = assertionMakerFunc(func(*IdpAuthnRequest, *Session) error {
		return fmt.Errorf("x: %w", ErrInvalidNameIDPolicy)
	})

	w, id := serveSSOModified(t, test, func(*AuthnRequest) {})
	assertRequestStatus(t, w, id, StatusRequester, StatusInvalidNameIDPolicy)
}

func TestErrorStatusCodes(t *testing.T) {
	idp := &IdentityProvider{}

	for name, tc := range map[string]struct {
		err         error
		top, second string
	}{
		"request stage":         {ErrRequestNotCurrent.WithDebug("expired"), StatusRequester, StatusRequestDenied},
		"wrapped request stage": {fmt.Errorf("validate: %w", ErrVersionMismatch), StatusVersionMismatch, ""},
		"name id policy":        {fmt.Errorf("cannot issue a NameID: %w", ErrInvalidNameIDPolicy), StatusRequester, StatusInvalidNameIDPolicy},
		"other":                 {errors.New("cannot find service provider"), StatusResponder, ""},
	} {
		t.Run(name, func(t *testing.T) {
			top, second := statusCodes(idp.ErrorStatus(tc.err))
			assert.Equal(t, top, tc.top)
			assert.Equal(t, second, tc.second)
		})
	}
}

// Respondable tells a custom handler which errors of Validate may be answered with a SAML status.
func TestRespondableAfterValidate(t *testing.T) {
	validate := func(t *testing.T, modify func(*AuthnRequest)) (*IdpAuthnRequest, error) {
		t.Helper()

		test := NewIdentityProviderTest(t, applyKey)
		request, err := test.SP.MakeAuthenticationRequest("https://idp.example.com/saml/sso", HTTPPostBinding, HTTPPostBinding)
		require.NoError(t, err)
		modify(request)

		doc := etree.NewDocument()
		doc.SetRoot(request.Element())
		body, err := doc.WriteToBytes()
		require.NoError(t, err)

		req := &IdpAuthnRequest{IDP: &test.IDP, HTTPRequest: httptest.NewRequest(http.MethodPost, "https://idp.example.com/saml/sso", nil), RequestBuffer: body, Now: TimeNow()}

		return req, req.Validate()
	}

	req, err := validate(t, func(r *AuthnRequest) { r.ID = "bad id" })
	assert.True(t, errors.Is(err, ErrMalformedRequest), "%v", err)
	assert.False(t, req.Respondable(), "a request that fails before its endpoint is known must not get a SAML response")
	assert.NotNil(t, req.MakeErrorResponse(err))

	req, err = validate(t, func(r *AuthnRequest) { r.Version = "3.0" })
	assert.True(t, errors.Is(err, ErrRequestVersionTooHigh), "%v", err)
	assert.True(t, req.Respondable())
	assert.Equal(t, req.IDP.ErrorStatus(err).StatusCode.Value, StatusVersionMismatch)
	require.NoError(t, req.MakeErrorResponse(err))
}
