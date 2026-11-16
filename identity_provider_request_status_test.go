package saml

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// serveSSOModified posts a request made by the test service provider after modify has changed it,
// and returns the recorder.
func serveSSOModified(t *testing.T, test *IdentityProviderTest, modify func(*AuthnRequest)) (*httptest.ResponseRecorder, string) {
	t.Helper()

	request, err := test.SP.MakeAuthenticationRequest("https://idp.example.com/saml/sso", HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)

	modify(request)

	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	body, err := doc.WriteToBytes()
	assert.NilError(t, err)

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

	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())

	_, response := postedResponse(t, w.Body.String())

	assert.Check(t, is.Equal(response.InResponseTo, id))
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, top))

	if second == "" {
		assert.Check(t, response.Status.StatusCode.StatusCode == nil)
	} else {
		assert.Assert(t, response.Status.StatusCode.StatusCode != nil)
		assert.Check(t, is.Equal(response.Status.StatusCode.StatusCode.Value, second))
	}

	assert.Check(t, response.Status.StatusMessage == nil)
	assert.Check(t, response.Assertion == nil)
	assert.Check(t, response.EncryptedAssertion == nil)
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
	w, id := serveSSOModified(t, test, func(r *AuthnRequest) { r.IssueInstant = TimeNow().Add(-2 * MaxIssueDelay) })
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
			assert.Check(t, is.Equal(response.Destination, test.SP.AcsURL.String()))
		})
	}
}

func TestServeSSOVersionMismatchGoesToMetadataACS(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	w, _ := serveSSOModified(t, test, func(r *AuthnRequest) {
		r.Version = "3.0"
		r.AssertionConsumerServiceURL = "https://attacker.example.com/acs"
	})

	assert.Check(t, is.Equal(w.Code, http.StatusBadRequest))
	assert.Check(t, !strings.Contains(w.Body.String(), "SAMLResponse"))
}

func TestServeSSOInvalidRequestIDStays400(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	w, _ := serveSSOModified(t, test, func(r *AuthnRequest) { r.ID = "bad id" })

	assert.Check(t, is.Equal(w.Code, http.StatusBadRequest))
	assert.Check(t, !strings.Contains(w.Body.String(), "SAMLResponse"))
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

func TestStatusErrorWithoutErr(t *testing.T) {
	assert.Check(t, (&statusError{TopLevel: StatusRequester}).Error() != "")
}

type encryptionCertificateEnforcerFunc func(*IdpAuthnRequest, *x509.Certificate) error

func (f encryptionCertificateEnforcerFunc) EnforceEncryptionCertificate(req *IdpAuthnRequest, cert *x509.Certificate) error {
	return f(req, cert)
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
	assert.Check(t, !strings.Contains(w.Body.String(), "boom"))
}

func TestServeSSOResponderWhenEncryptionFails(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	useSession(test)

	called := false

	test.IDP.EncryptionCertificateEnforcer = encryptionCertificateEnforcerFunc(func(*IdpAuthnRequest, *x509.Certificate) error {
		called = true

		return errors.New("boom")
	})

	w, id := serveSSOModified(t, test, func(*AuthnRequest) {})
	assert.Check(t, called)
	assertRequestStatus(t, w, id, StatusResponder, "")
	assert.Check(t, !strings.Contains(w.Body.String(), "boom"))
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

func TestRequestStatus(t *testing.T) {
	status := func(top, second string) Status {
		s := Status{StatusCode: StatusCode{Value: top}}
		if second != "" {
			s.StatusCode.StatusCode = &StatusCode{Value: second}
		}

		return s
	}

	for name, tc := range map[string]struct {
		err    error
		status Status
		ok     bool
	}{
		"request stage":         {&statusError{StatusRequester, StatusRequestDenied, errors.New("expired")}, status(StatusRequester, StatusRequestDenied), true},
		"wrapped request stage": {fmt.Errorf("validate: %w", &statusError{TopLevel: StatusVersionMismatch}), status(StatusVersionMismatch, ""), true},
		"name id policy":        {fmt.Errorf("cannot issue a NameID: %w", ErrInvalidNameIDPolicy), status(StatusRequester, StatusInvalidNameIDPolicy), true},
		"other":                 {errors.New("cannot find service provider"), Status{}, false},
		"nil":                   {nil, Status{}, false},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := RequestStatus(tc.err)
			assert.Check(t, is.Equal(ok, tc.ok))
			assert.Check(t, is.DeepEqual(got, tc.status))
		})
	}
}

// RequestStatus tells a custom handler which errors of Validate may be answered with a SAML status.
func TestRequestStatusOfValidate(t *testing.T) {
	validate := func(t *testing.T, modify func(*AuthnRequest)) error {
		t.Helper()

		test := NewIdentityProviderTest(t, applyKey)
		request, err := test.SP.MakeAuthenticationRequest("https://idp.example.com/saml/sso", HTTPPostBinding, HTTPPostBinding)
		assert.NilError(t, err)
		modify(request)

		doc := etree.NewDocument()
		doc.SetRoot(request.Element())
		body, err := doc.WriteToBytes()
		assert.NilError(t, err)

		req := &IdpAuthnRequest{IDP: &test.IDP, HTTPRequest: httptest.NewRequest(http.MethodPost, "https://idp.example.com/saml/sso", nil), RequestBuffer: body, Now: TimeNow()}

		return req.Validate()
	}

	_, ok := RequestStatus(validate(t, func(r *AuthnRequest) { r.ID = "bad id" }))
	assert.Check(t, !ok, "a request that fails before its endpoint is known must not get a SAML response")

	status, ok := RequestStatus(validate(t, func(r *AuthnRequest) { r.Version = "3.0" }))
	assert.Check(t, ok)
	assert.Check(t, is.Equal(status.StatusCode.Value, StatusVersionMismatch))
}
