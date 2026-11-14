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

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestIsSecureEndpointLocation(t *testing.T) {
	for _, tc := range []struct {
		location string
		secure   bool
	}{
		{"https://sp.example.com/saml2/acs", true},
		{"HTTPS://sp.example.com/saml2/acs", true},
		{"https://sp.example.com:8443/saml2/acs", true},
		{"http://sp.example.com/saml2/acs", false},
		{"HTTP://sp.example.com/saml2/acs", false},

		// Loopback hosts are secure contexts for a browser, and the traffic never leaves the machine.
		{"http://localhost/saml2/acs", true},
		{"http://LocalHost:8080/saml2/acs", true},
		{"http://sp.localhost:8080/saml2/acs", true},
		{"http://127.0.0.1/saml2/acs", true},
		{"http://127.10.20.30:8000/saml2/acs", true},
		{"http://[::1]:8000/saml2/acs", true},
		{"http://[::ffff:127.0.0.1]/saml2/acs", true},
		// Both Go and the WHATWG URL parser take the host after the last '@'.
		{"http://user@sp.example.com@localhost/saml2/acs", true},

		// Names and addresses which only look like loopback.
		{"http://localhost.example.com/saml2/acs", false},
		{"http://127.0.0.1.example.com/saml2/acs", false},
		{"http://notlocalhost/saml2/acs", false},
		{"http://0.0.0.0/saml2/acs", false},
		{"http://[::]/saml2/acs", false},
		{"http://10.0.0.1/saml2/acs", false},

		// Not an absolute http or https URL with a host.
		{"", false},
		{"/saml2/acs", false},
		{"//sp.example.com/saml2/acs", false},
		{"https:///saml2/acs", false},
		{"https://:443/saml2/acs", false},
		{"https:sp.example.com/saml2/acs", false},
		{"ftp://sp.example.com/saml2/acs", false},
		{"javascript:alert(1)", false},
		{"https://sp.example.com/%zz", false},
		{"https://sp example.com/saml2/acs", false},
	} {
		t.Run(tc.location, func(t *testing.T) {
			assert.Check(t, is.Equal(isSecureEndpointLocation(tc.location), tc.secure))
		})
	}
}

func TestCheckServiceProviderEndpoint(t *testing.T) {
	idp := &IdentityProvider{}
	assert.Check(t, idp.CheckServiceProviderEndpoint("https://sp.example.com/acs"))
	assert.Check(t, idp.CheckServiceProviderEndpoint("http://localhost:8080/acs"))
	err := idp.CheckServiceProviderEndpoint("http://sp.example.com/acs")
	assert.Check(t, errors.Is(err, ErrInsecureEndpoint), "error: %v", err)

	idp.AllowInsecureServiceProviderEndpoints = true
	assert.Check(t, idp.CheckServiceProviderEndpoint("http://sp.example.com/acs"))
	assert.Check(t, idp.CheckServiceProviderEndpoint("HTTP://sp.example.com/acs"))
	// The option only allows plain HTTP, not URLs which are not HTTP at all.
	for _, location := range []string{"", "/acs", "//sp.example.com/acs", "http:///acs", "ftp://sp.example.com/acs", "http://%zz/"} {
		assert.Check(t, errors.Is(idp.CheckServiceProviderEndpoint(location), ErrInsecureEndpoint), "location %q", location)
	}
}

// insecureEndpointTestIDP returns an identity provider whose service provider has the given ACS endpoints.
func insecureEndpointTestIDP(t *testing.T, acs ...IndexedEndpoint) *IdentityProviderTest {
	t.Helper()
	test := NewIdentityProviderTest(t, applyKey)
	metadata := test.SP.Metadata()
	metadata.SPSSODescriptors[0].AssertionConsumerServices = acs
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			if serviceProviderID == test.SP.MetadataURL.String() {
				return metadata, nil
			}
			return nil, errors.New("unknown service provider")
		},
	}
	return test
}

// insecureEndpointRequest returns an AuthnRequest with the given ACS attributes.
func insecureEndpointRequest(acsAttrs string) []byte {
	return []byte(`<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ` + acsAttrs + ` ` +
		`Destination="https://idp.example.com/saml/sso" ID="id-1" ` +
		`IssueInstant="` + TimeNow().UTC().Format(time.RFC3339) + `" Version="2.0">` + hardeningIssuer + `</AuthnRequest>`)
}

var (
	insecureACS = IndexedEndpoint{Binding: HTTPPostBinding, Location: "http://sp.example.com/saml2/acs", Index: 1}
	secureACS   = IndexedEndpoint{Binding: HTTPPostBinding, Location: "https://sp.example.com/saml2/acs", Index: 2}
)

func TestIDPRefusesInsecureACS(t *testing.T) {
	test := insecureEndpointTestIDP(t, insecureACS)

	for name, attrs := range map[string]string{
		"by url":   `AssertionConsumerServiceURL="http://sp.example.com/saml2/acs"`,
		"by index": `AssertionConsumerServiceIndex="1"`,
		"default":  ``,
	} {
		t.Run(name, func(t *testing.T) {
			req, err := hardeningValidate(test, insecureEndpointRequest(attrs))
			assert.Check(t, errors.Is(err, ErrInsecureEndpoint), "error: %v", err)
			assert.Check(t, req.ACSEndpoint == nil, "an insecure endpoint must not be selected")
			// A SAML error response goes to the ACS, so none can be sent either.
			assert.Check(t, req.WriteErrorResponse(httptest.NewRecorder(), StatusResponder, "", "") != nil)
		})
	}
}

func TestIDPAllowsInsecureACSWhenEnabled(t *testing.T) {
	test := insecureEndpointTestIDP(t, insecureACS)
	test.IDP.AllowInsecureServiceProviderEndpoints = true

	for name, attrs := range map[string]string{
		"by url":   `AssertionConsumerServiceURL="http://sp.example.com/saml2/acs"`,
		"by index": `AssertionConsumerServiceIndex="1"`,
		"default":  ``,
	} {
		t.Run(name, func(t *testing.T) {
			req, err := hardeningValidate(test, insecureEndpointRequest(attrs))
			assert.NilError(t, err)
			assert.Check(t, is.Equal(req.ACSEndpoint.Location, insecureACS.Location))
		})
	}
}

func TestIDPAllowsLoopbackACS(t *testing.T) {
	loopback := IndexedEndpoint{Binding: HTTPPostBinding, Location: "http://localhost:8080/saml2/acs", Index: 1}
	test := insecureEndpointTestIDP(t, loopback)

	req, err := hardeningValidate(test, insecureEndpointRequest(`AssertionConsumerServiceURL="http://localhost:8080/saml2/acs"`))
	assert.NilError(t, err)
	assert.Check(t, is.Equal(req.ACSEndpoint.Location, loopback.Location))
}

// A service provider which lists an insecure endpoint alongside a secure one can still be used
// through the secure one.
func TestIDPMixedACSEndpoints(t *testing.T) {
	isDefault := true
	defaultInsecure := insecureACS
	defaultInsecure.IsDefault = &isDefault
	test := insecureEndpointTestIDP(t, defaultInsecure, secureACS)

	t.Run("secure url", func(t *testing.T) {
		req, err := hardeningValidate(test, insecureEndpointRequest(`AssertionConsumerServiceURL="https://sp.example.com/saml2/acs"`))
		assert.NilError(t, err)
		assert.Check(t, is.Equal(req.ACSEndpoint.Location, secureACS.Location))
	})

	t.Run("secure index", func(t *testing.T) {
		req, err := hardeningValidate(test, insecureEndpointRequest(`AssertionConsumerServiceIndex="2"`))
		assert.NilError(t, err)
		assert.Check(t, is.Equal(req.ACSEndpoint.Location, secureACS.Location))
	})

	// The default skips the insecure endpoint, although it is marked as the default.
	t.Run("default", func(t *testing.T) {
		req, err := hardeningValidate(test, insecureEndpointRequest(``))
		assert.NilError(t, err)
		assert.Check(t, is.Equal(req.ACSEndpoint.Location, secureACS.Location))
	})

	// An explicit choice of the insecure endpoint is refused, rather than replaced by another.
	t.Run("insecure url", func(t *testing.T) {
		req, err := hardeningValidate(test, insecureEndpointRequest(`AssertionConsumerServiceURL="http://sp.example.com/saml2/acs"`))
		assert.Check(t, errors.Is(err, ErrInsecureEndpoint), "error: %v", err)
		assert.Check(t, req.ACSEndpoint == nil)
	})

	t.Run("insecure index", func(t *testing.T) {
		req, err := hardeningValidate(test, insecureEndpointRequest(`AssertionConsumerServiceIndex="1"`))
		assert.Check(t, errors.Is(err, ErrInsecureEndpoint), "error: %v", err)
		assert.Check(t, req.ACSEndpoint == nil)
	})

	t.Run("enabled default", func(t *testing.T) {
		test.IDP.AllowInsecureServiceProviderEndpoints = true
		t.Cleanup(func() { test.IDP.AllowInsecureServiceProviderEndpoints = false })
		req, err := hardeningValidate(test, insecureEndpointRequest(``))
		assert.NilError(t, err)
		assert.Check(t, is.Equal(req.ACSEndpoint.Location, insecureACS.Location))
	})
}

// refusingAssertionMaker fails the test if an assertion is made.
type refusingAssertionMaker struct{ t *testing.T }

func (m refusingAssertionMaker) MakeAssertion(*IdpAuthnRequest, *Session) error {
	m.t.Error("no assertion must be made for an insecure endpoint")
	return errors.New("refused")
}

func TestIDPServeSSORefusesInsecureACS(t *testing.T) {
	test := insecureEndpointTestIDP(t, insecureACS)
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
			t.Error("request must be rejected before the session is looked up")
			return nil
		},
	}
	test.IDP.AssertionMaker = refusingAssertionMaker{t}

	request := insecureEndpointRequest(`AssertionConsumerServiceURL="http://sp.example.com/saml2/acs"`)
	body := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(request)}}.Encode()
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/saml/sso", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, r)

	assert.Check(t, is.Equal(w.Code, http.StatusBadRequest))
	assert.Check(t, !strings.Contains(w.Body.String(), "SAMLResponse"))
	assert.Check(t, !strings.Contains(w.Body.String(), "http://sp.example.com"))
}

func TestIDPServeIDPInitiatedRefusesInsecureACS(t *testing.T) {
	session := func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
		return &Session{ID: "f00df00df00d", NameID: "alice", UserName: "alice"}
	}

	t.Run("refused", func(t *testing.T) {
		test := insecureEndpointTestIDP(t, insecureACS)
		test.IDP.SessionProvider = &mockSessionProvider{GetSessionFunc: session}
		test.IDP.AssertionMaker = refusingAssertionMaker{t}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/services/sp/whoami", nil)
		test.IDP.ServeIDPInitiated(w, r, test.SP.MetadataURL.String(), "relay")
		assert.Check(t, is.Equal(w.Code, http.StatusInternalServerError))
		assert.Check(t, !strings.Contains(w.Body.String(), "SAMLResponse"))
	})

	t.Run("secure endpoint chosen", func(t *testing.T) {
		test := insecureEndpointTestIDP(t, insecureACS, secureACS)
		test.IDP.SessionProvider = &mockSessionProvider{GetSessionFunc: session}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/services/sp/whoami", nil)
		test.IDP.ServeIDPInitiated(w, r, test.SP.MetadataURL.String(), "relay")
		assert.Check(t, is.Equal(w.Code, http.StatusOK))
		assert.Check(t, is.Contains(w.Body.String(), `action="https://sp.example.com/saml2/acs"`))
	})

	t.Run("enabled", func(t *testing.T) {
		test := insecureEndpointTestIDP(t, insecureACS)
		test.IDP.AllowInsecureServiceProviderEndpoints = true
		test.IDP.SessionProvider = &mockSessionProvider{GetSessionFunc: session}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/services/sp/whoami", nil)
		test.IDP.ServeIDPInitiated(w, r, test.SP.MetadataURL.String(), "relay")
		assert.Check(t, is.Equal(w.Code, http.StatusOK))
		assert.Check(t, is.Contains(w.Body.String(), `action="http://sp.example.com/saml2/acs"`))
	})
}

// A request whose ACSEndpoint was set without being selected by the identity provider is refused
// when the response is written.
func TestIDPPostBindingRefusesInsecureACS(t *testing.T) {
	_, req := errorResponseRequest(t)
	req.ACSEndpoint = &insecureACS

	_, err := req.PostBinding()
	assert.Check(t, errors.Is(err, ErrInsecureEndpoint), "error: %v", err)
	assert.Check(t, req.ResponseEl == nil, "no response must be made for an insecure endpoint")

	w := httptest.NewRecorder()
	err = req.WriteErrorResponse(w, StatusResponder, "", "")
	assert.Check(t, errors.Is(err, ErrInsecureEndpoint), "error: %v", err)
	assert.Check(t, is.Equal(w.Body.Len(), 0))
}

// insecureLogoutTestIDP returns an identity provider whose service provider has the given SLO endpoints.
func insecureLogoutTestIDP(t *testing.T, slo ...Endpoint) (*IdentityProviderTest, *logoutSessionProvider) {
	t.Helper()
	test, provider := logoutTestIDP(t)
	metadata := test.SP.Metadata()
	metadata.SPSSODescriptors[0].SingleLogoutServices = slo
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) { return metadata, nil },
	}
	return test, provider
}

func TestServeSLORefusesInsecureEndpoint(t *testing.T) {
	t.Run("location", func(t *testing.T) {
		test, provider := insecureLogoutTestIDP(t, Endpoint{Binding: HTTPRedirectBinding, Location: "http://sp.example.com/saml2/slo"})
		r, _ := redirectLogoutRequest(t, &test.SP, nil)
		w := serveSLO(test, r)
		assert.Check(t, is.Equal(w.Code, http.StatusBadRequest))
		assert.Check(t, is.Equal(w.Header().Get("Location"), ""))
		assert.Check(t, is.Len(provider.terminated, 0))
	})

	t.Run("response location", func(t *testing.T) {
		test, provider := insecureLogoutTestIDP(t, Endpoint{
			Binding:          HTTPPostBinding,
			Location:         "https://sp.example.com/saml2/slo",
			ResponseLocation: "http://sp.example.com/saml2/slo-response",
		})
		r, _ := postLogoutRequest(t, &test.SP, nil)
		w := serveSLO(test, r)
		assert.Check(t, is.Equal(w.Code, http.StatusBadRequest))
		assert.Check(t, !strings.Contains(w.Body.String(), "SAMLResponse"))
		assert.Check(t, is.Len(provider.terminated, 0))
	})

	// The response location is all that the identity provider uses, so an insecure location for
	// requests does not matter.
	t.Run("secure response location", func(t *testing.T) {
		test, _ := insecureLogoutTestIDP(t, Endpoint{
			Binding:          HTTPRedirectBinding,
			Location:         "http://sp.example.com/saml2/slo",
			ResponseLocation: "https://sp.example.com/saml2/slo-response",
		})
		r, _ := redirectLogoutRequest(t, &test.SP, nil)
		location, _ := redirectedLogoutResponse(t, serveSLO(test, r))
		assert.Check(t, is.Equal(location.Scheme, "https"))
	})

	// An insecure endpoint for the binding of the request is skipped for a secure one.
	t.Run("secure endpoint chosen", func(t *testing.T) {
		test, _ := insecureLogoutTestIDP(t,
			Endpoint{Binding: HTTPRedirectBinding, Location: "http://sp.example.com/saml2/slo"},
			Endpoint{Binding: HTTPPostBinding, Location: "https://sp.example.com/saml2/slo"},
		)
		r, _ := redirectLogoutRequest(t, &test.SP, nil)
		_, _, response := postedLogoutResponse(t, serveSLO(test, r))
		assert.Check(t, is.Equal(response.Destination, "https://sp.example.com/saml2/slo"))
	})

	t.Run("enabled", func(t *testing.T) {
		test, provider := insecureLogoutTestIDP(t, Endpoint{Binding: HTTPRedirectBinding, Location: "http://sp.example.com/saml2/slo"})
		test.IDP.AllowInsecureServiceProviderEndpoints = true
		r, _ := redirectLogoutRequest(t, &test.SP, nil)
		location, _ := redirectedLogoutResponse(t, serveSLO(test, r))
		assert.Check(t, is.Equal(location.Scheme, "http"))
		assert.Check(t, is.Len(provider.terminated, 1))
	})

	t.Run("loopback", func(t *testing.T) {
		test, _ := insecureLogoutTestIDP(t, Endpoint{Binding: HTTPRedirectBinding, Location: "http://127.0.0.1:8080/saml2/slo"})
		r, _ := redirectLogoutRequest(t, &test.SP, nil)
		location, _ := redirectedLogoutResponse(t, serveSLO(test, r))
		assert.Check(t, is.Equal(location.Host, "127.0.0.1:8080"))
	})
}
