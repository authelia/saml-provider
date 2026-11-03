package saml

import (
	"bytes"
	"compress/flate"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml/internal/dsig"
)

const logoutTestSLOURL = "https://idp.example.com/saml/slo"

// logoutSessionProvider is a SessionProvider which records the logout requests it terminates.
type logoutSessionProvider struct {
	mockSessionProvider
	terminated []*IdpLogoutRequest
	err        error
}

func (p *logoutSessionProvider) TerminateSession(w http.ResponseWriter, _ *http.Request, req *IdpLogoutRequest) error {
	p.terminated = append(p.terminated, req)
	http.SetCookie(w, &http.Cookie{Name: "session", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	return p.err
}

// logoutTestIDP returns an identity provider with a logout URL, and a service provider which signs
// its requests and accepts logout on both bindings.
func logoutTestIDP(t *testing.T) (*IdentityProviderTest, *logoutSessionProvider) {
	t.Helper()
	test := signatureTestIDP(t)
	test.IDP.LogoutURL = mustParseURL(logoutTestSLOURL)
	test.SP.SloURL = mustParseURL("https://sp.example.com/saml2/slo")
	test.SP.LogoutBindings = []string{HTTPRedirectBinding, HTTPPostBinding}
	test.SP.IDPMetadata = test.IDP.Metadata()

	provider := &logoutSessionProvider{}
	test.IDP.SessionProvider = provider
	return test, provider
}

// serveSLO sends r to the identity provider.
func serveSLO(test *IdentityProviderTest, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	test.IDP.ServeSLO(w, r)
	return w
}

// redirectLogoutRequest returns a signed HTTP-Redirect logout request, and its ID.
func redirectLogoutRequest(t *testing.T, sp *ServiceProvider, mutate func(*LogoutRequest)) (*http.Request, string) {
	t.Helper()
	request, err := sp.MakeLogoutRequest(logoutTestSLOURL, "alice")
	assert.NilError(t, err)
	if mutate != nil {
		mutate(request)
	}
	// As LogoutRequest.Redirect does, but to the logout URL whatever the Destination is.
	unsigned := *request
	unsigned.Signature = nil
	u, err := redirectURL(logoutTestSLOURL, "SAMLRequest", unsigned.Element(), "relay", sp)
	assert.NilError(t, err)
	return httptest.NewRequest(http.MethodGet, u.String(), nil), request.ID
}

// postLogoutRequest returns an HTTP-POST logout request with an enveloped signature, after mutate
// has changed the request and before it is signed, and its ID.
func postLogoutRequest(t *testing.T, sp *ServiceProvider, mutate func(*LogoutRequest)) (*http.Request, string) {
	t.Helper()
	unsigned := *sp
	unsigned.SignatureMethod = ""
	request, err := unsigned.MakeLogoutRequest(logoutTestSLOURL, "alice")
	assert.NilError(t, err)
	if mutate != nil {
		mutate(request)
	}
	if sp.SignatureMethod != "" {
		assert.NilError(t, sp.SignLogoutRequest(request))
	}
	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	body, err := doc.WriteToBytes()
	assert.NilError(t, err)
	return postLogoutBody(body), request.ID
}

func postLogoutBody(body []byte) *http.Request {
	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}, "RelayState": {"relay"}}
	r := httptest.NewRequest(http.MethodPost, logoutTestSLOURL, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// redirectedLogoutResponse returns the LogoutResponse in the location of a redirect.
func redirectedLogoutResponse(t *testing.T, w *httptest.ResponseRecorder) (*url.URL, LogoutResponse) {
	t.Helper()
	assert.Assert(t, is.Equal(w.Code, http.StatusFound), "body: %s", w.Body.String())
	location, err := url.Parse(w.Header().Get("Location"))
	assert.NilError(t, err)
	compressed, err := base64.StdEncoding.DecodeString(location.Query().Get("SAMLResponse"))
	assert.NilError(t, err)
	buf, err := io.ReadAll(flate.NewReader(bytes.NewReader(compressed)))
	assert.NilError(t, err)
	var response LogoutResponse
	assert.NilError(t, xml.Unmarshal(buf, &response))
	return location, response
}

// postedLogoutResponse returns the encoded LogoutResponse and RelayState in a form, and the response.
func postedLogoutResponse(t *testing.T, w *httptest.ResponseRecorder) (string, string, LogoutResponse) {
	t.Helper()
	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())
	body := w.Body.String()
	field := func(name string) string {
		marker := `name="` + name + `" value="`
		start := strings.Index(body, marker)
		assert.Assert(t, start >= 0, "no %s in %q", name, body)
		value, _, _ := strings.Cut(body[start+len(marker):], `"`)
		return html.UnescapeString(value)
	}
	encoded := field("SAMLResponse")
	buf, err := base64.StdEncoding.DecodeString(encoded)
	assert.NilError(t, err)
	var response LogoutResponse
	assert.NilError(t, xml.Unmarshal(buf, &response))
	return encoded, field("RelayState"), response
}

func TestServeSLORedirect(t *testing.T) {
	test, provider := logoutTestIDP(t)
	r, id := redirectLogoutRequest(t, &test.SP, func(request *LogoutRequest) {
		request.SessionIndexes = []SessionIndex{{Value: "one"}, {Value: "two"}}
	})
	w := serveSLO(test, r)

	location, response := redirectedLogoutResponse(t, w)
	assert.Check(t, is.Equal(location.Scheme+"://"+location.Host+location.Path, test.SP.SloURL.String()))
	assert.Check(t, is.Equal(location.Query().Get("RelayState"), "relay"))
	assert.Check(t, is.Equal(response.InResponseTo, id))
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	assert.Check(t, response.Signature == nil, "the signature is in the query")
	assert.Check(t, test.SP.ValidateLogoutResponseRedirect(location, []string{id}))
	assert.Check(t, strings.Contains(w.Header().Get("Set-Cookie"), "session="))

	assert.Assert(t, is.Len(provider.terminated, 1))
	terminated := provider.terminated[0]
	assert.Check(t, is.Equal(terminated.Request.NameID.Value, "alice"))
	assert.Check(t, is.DeepEqual(terminated.Request.SessionIndexes, []SessionIndex{{Value: "one"}, {Value: "two"}}))
	assert.Check(t, is.Equal(terminated.ServiceProviderMetadata.EntityID, test.SP.MetadataURL.String()))
	assert.Check(t, is.Equal(terminated.RelayState, "relay"))
}

func TestServeSLOPost(t *testing.T) {
	test, provider := logoutTestIDP(t)
	r, id := postLogoutRequest(t, &test.SP, nil)
	w := serveSLO(test, r)

	encoded, relayState, response := postedLogoutResponse(t, w)
	assert.Check(t, is.Equal(relayState, "relay"))
	assert.Check(t, is.Equal(response.InResponseTo, id))
	assert.Check(t, is.Equal(response.Destination, test.SP.SloURL.String()))
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	assert.Check(t, response.Signature != nil)
	assert.Check(t, test.SP.ValidateLogoutResponseForm(encoded, []string{id}))

	// SAMLCore requires the signature to follow the Issuer.
	buf, err := base64.StdEncoding.DecodeString(encoded)
	assert.NilError(t, err)
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(buf))
	children := doc.Root().ChildElements()
	assert.Assert(t, len(children) >= 2)
	assert.Check(t, is.Equal(children[0].Tag, "Issuer"))
	assert.Check(t, is.Equal(children[1].Tag, "Signature"))
	assert.Check(t, strings.Contains(w.Header().Get("Cache-Control"), "no-store"))
	assert.Check(t, is.Len(provider.terminated, 1))
}

// The response uses the binding of the request when the service provider has an endpoint for it.
func TestServeSLOChoosesResponseEndpoint(t *testing.T) {
	t.Run("post only", func(t *testing.T) {
		test, _ := logoutTestIDP(t)
		test.SP.LogoutBindings = []string{HTTPPostBinding}
		r, _ := redirectLogoutRequest(t, &test.SP, nil)
		_, _, response := postedLogoutResponse(t, serveSLO(test, r))
		assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	})

	t.Run("redirect only", func(t *testing.T) {
		test, _ := logoutTestIDP(t)
		test.SP.LogoutBindings = []string{HTTPRedirectBinding}
		r, _ := postLogoutRequest(t, &test.SP, nil)
		_, response := redirectedLogoutResponse(t, serveSLO(test, r))
		assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	})

	t.Run("response location", func(t *testing.T) {
		test, _ := logoutTestIDP(t)
		metadata := test.SP.Metadata()
		metadata.SPSSODescriptors[0].SingleLogoutServices = []Endpoint{{
			Binding:          HTTPRedirectBinding,
			Location:         "https://sp.example.com/saml2/slo-request",
			ResponseLocation: "https://sp.example.com/saml2/slo-response",
		}}
		test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
			GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) { return metadata, nil },
		}
		r, _ := redirectLogoutRequest(t, &test.SP, nil)
		location, response := redirectedLogoutResponse(t, serveSLO(test, r))
		assert.Check(t, is.Equal(location.Path, "/saml2/slo-response"))
		assert.Check(t, is.Equal(response.Destination, "https://sp.example.com/saml2/slo-response"))
	})

	t.Run("no endpoint", func(t *testing.T) {
		test, provider := logoutTestIDP(t)
		test.SP.LogoutBindings = nil
		r, _ := redirectLogoutRequest(t, &test.SP, nil)
		assert.Check(t, is.Equal(serveSLO(test, r).Code, http.StatusBadRequest))
		assert.Check(t, is.Len(provider.terminated, 0))
	})
}

// SAMLProfiles §4.4.4.1 requires a LogoutRequest to be authenticated, which here means signed.
func TestServeSLORejectsUnauthenticatedRequests(t *testing.T) {
	for name, request := range map[string]func(*testing.T, *IdentityProviderTest) *http.Request{
		"unsigned redirect": func(t *testing.T, test *IdentityProviderTest) *http.Request {
			unsigned := test.SP
			unsigned.SignatureMethod = ""
			r, _ := redirectLogoutRequest(t, &unsigned, nil)
			return r
		},
		"unsigned post": func(t *testing.T, test *IdentityProviderTest) *http.Request {
			unsigned := test.SP
			unsigned.SignatureMethod = ""
			r, _ := postLogoutRequest(t, &unsigned, nil)
			return r
		},
		"redirect signed by another key": func(t *testing.T, test *IdentityProviderTest) *http.Request {
			other := serviceProviderWithOtherKey(t, test)
			r, _ := redirectLogoutRequest(t, &other, nil)
			return r
		},
		"post signed by another key": func(t *testing.T, test *IdentityProviderTest) *http.Request {
			other := serviceProviderWithOtherKey(t, test)
			r, _ := postLogoutRequest(t, &other, nil)
			return r
		},
		"altered relay state": func(t *testing.T, test *IdentityProviderTest) *http.Request {
			r, _ := redirectLogoutRequest(t, &test.SP, nil)
			r.URL.RawQuery = strings.Replace(r.URL.RawQuery, "RelayState=relay", "RelayState=other", 1)
			return r
		},
		"altered post": func(t *testing.T, test *IdentityProviderTest) *http.Request {
			r, _ := postLogoutRequest(t, &test.SP, nil)
			assert.NilError(t, r.ParseForm())
			body, err := base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLRequest"))
			assert.NilError(t, err)
			return postLogoutBody(bytes.Replace(body, []byte(">alice<"), []byte(">bob<"), 1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			test, provider := logoutTestIDP(t)
			w := serveSLO(test, request(t, test))
			assert.Check(t, is.Equal(w.Code, http.StatusBadRequest))
			assert.Check(t, is.Len(provider.terminated, 0))
			assert.Check(t, is.Equal(w.Header().Get("Set-Cookie"), ""))
		})
	}
}

func TestServeSLORejectsInvalidRequests(t *testing.T) {
	for name, mutate := range map[string]func(*LogoutRequest){
		"other destination": func(r *LogoutRequest) { r.Destination = "https://idp.example.com/saml/sso" },
		"no destination":    func(r *LogoutRequest) { r.Destination = "" },
		"expired":           func(r *LogoutRequest) { r.IssueInstant = r.IssueInstant.Add(-time.Hour) },
		"future":            func(r *LogoutRequest) { r.IssueInstant = r.IssueInstant.Add(time.Hour) },
		"not on or after": func(r *LogoutRequest) {
			now := TimeNow()
			r.NotOnOrAfter = &now
		},
		"version":        func(r *LogoutRequest) { r.Version = "1.1" },
		"invalid id":     func(r *LogoutRequest) { r.ID = "a b" },
		"no issuer":      func(r *LogoutRequest) { r.Issuer = nil },
		"unknown issuer": func(r *LogoutRequest) { r.Issuer.Value = "https://other.example.com/metadata" },
		"no name id":     func(r *LogoutRequest) { r.NameID = nil },
		"empty name id":  func(r *LogoutRequest) { r.NameID.Value = "" },
		"oversized":      func(r *LogoutRequest) { r.NameID.Value = strings.Repeat("a", maxAuthnRequestSize) },
	} {
		t.Run(name, func(t *testing.T) {
			for binding, request := range map[string]func(*testing.T, *ServiceProvider, func(*LogoutRequest)) (*http.Request, string){
				"redirect": redirectLogoutRequest,
				"post":     postLogoutRequest,
			} {
				t.Run(binding, func(t *testing.T) {
					test, provider := logoutTestIDP(t)
					r, _ := request(t, &test.SP, mutate)
					assert.Check(t, is.Equal(serveSLO(test, r).Code, http.StatusBadRequest))
					assert.Check(t, is.Len(provider.terminated, 0))
				})
			}
		})
	}

	t.Run("method", func(t *testing.T) {
		test, _ := logoutTestIDP(t)
		w := serveSLO(test, httptest.NewRequest(http.MethodPut, logoutTestSLOURL, nil))
		assert.Check(t, is.Equal(w.Code, http.StatusBadRequest))
	})
}

// As with AuthnRequests, the content that the signature covers is what is used. Exclusive
// canonicalization drops the unused declaration, so the digest is unchanged, while encoding/xml
// reads it as the IssueInstant.
func TestServeSLOUsesSignedContent(t *testing.T) {
	test, provider := logoutTestIDP(t)
	r, _ := postLogoutRequest(t, &test.SP, func(request *LogoutRequest) {
		request.IssueInstant = request.IssueInstant.Add(-time.Hour)
	})
	assert.NilError(t, r.ParseForm())
	body, err := base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLRequest"))
	assert.NilError(t, err)
	now := TimeNow().UTC().Format(timeFormat)
	// encoding/xml keeps the last of the two, so the declaration goes at the end of the start tag.
	end := bytes.IndexByte(body, '>')
	smuggled := append(append(append([]byte{}, body[:end]...), []byte(` xmlns:IssueInstant="`+now+`"`)...), body[end:]...)
	assert.Assert(t, !bytes.Equal(body, smuggled))

	w := serveSLO(test, postLogoutBody(smuggled))
	assert.Check(t, is.Equal(w.Code, http.StatusBadRequest))
	assert.Check(t, is.Len(provider.terminated, 0))
}

func TestServeSLOReportsTerminationFailure(t *testing.T) {
	t.Run("not supported", func(t *testing.T) {
		test, _ := logoutTestIDP(t)
		test.IDP.SessionProvider = &mockSessionProvider{}
		r, id := redirectLogoutRequest(t, &test.SP, nil)
		location, response := redirectedLogoutResponse(t, serveSLO(test, r))
		assert.Check(t, is.Equal(response.InResponseTo, id))
		assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusResponder))
		// The service provider can still verify a failure, although it reports it as one.
		err := test.SP.ValidateLogoutResponseRedirect(location, []string{id})
		assert.Check(t, is.ErrorContains(err, "status code"))
	})

	t.Run("error", func(t *testing.T) {
		test, provider := logoutTestIDP(t)
		provider.err = errors.New("alice has no session")
		r, _ := redirectLogoutRequest(t, &test.SP, nil)
		_, response := redirectedLogoutResponse(t, serveSLO(test, r))
		assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusResponder))
		assert.Check(t, response.Status.StatusMessage == nil)
	})

	t.Run("partial", func(t *testing.T) {
		test, provider := logoutTestIDP(t)
		provider.err = ErrPartialLogout
		r, id := redirectLogoutRequest(t, &test.SP, nil)
		location, response := redirectedLogoutResponse(t, serveSLO(test, r))
		assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
		assert.Assert(t, response.Status.StatusCode.StatusCode != nil)
		assert.Check(t, is.Equal(response.Status.StatusCode.StatusCode.Value, StatusPartialLogout))
		assert.Check(t, test.SP.ValidateLogoutResponseRedirect(location, []string{id}))
	})
}

func TestServeSLOSignsWithECDSA(t *testing.T) {
	test, _ := logoutTestIDP(t)
	key, certificate := ecdsaIdentityProviderKey(t, test)
	test.IDP.Key, test.IDP.Certificate = key, certificate
	test.SP.IDPMetadata = test.IDP.Metadata()

	for binding, request := range map[string]func(*testing.T, *ServiceProvider, func(*LogoutRequest)) (*http.Request, string){
		"redirect": redirectLogoutRequest,
		"post":     postLogoutRequest,
	} {
		t.Run(binding, func(t *testing.T) {
			test.SP.LogoutBindings = []string{HTTPRedirectBinding}
			if binding == "post" {
				test.SP.LogoutBindings = []string{HTTPPostBinding}
			}
			r, id := request(t, &test.SP, nil)
			w := serveSLO(test, r)
			if binding == "post" {
				encoded, _, _ := postedLogoutResponse(t, w)
				assert.Check(t, test.SP.ValidateLogoutResponseForm(encoded, []string{id}))
				return
			}
			location, _ := redirectedLogoutResponse(t, w)
			assert.Check(t, is.Equal(location.Query().Get("SigAlg"), dsig.ECDSASHA256SignatureMethod))
			assert.Check(t, test.SP.ValidateLogoutResponseRedirect(location, []string{id}))
		})
	}
}

func TestIdentityProviderLogoutMetadataAndHandler(t *testing.T) {
	test, provider := logoutTestIDP(t)
	services := test.IDP.Metadata().IDPSSODescriptors[0].SingleLogoutServices
	assert.Check(t, is.DeepEqual(services, []Endpoint{
		{Binding: HTTPRedirectBinding, Location: logoutTestSLOURL},
		{Binding: HTTPPostBinding, Location: logoutTestSLOURL},
	}))

	r, _ := redirectLogoutRequest(t, &test.SP, nil)
	w := httptest.NewRecorder()
	test.IDP.Handler().ServeHTTP(w, r)
	assert.Check(t, is.Equal(w.Code, http.StatusFound))
	assert.Check(t, is.Len(provider.terminated, 1))
}

func TestLogoutRequestSessionIndexes(t *testing.T) {
	request := LogoutRequest{
		ID:             "id",
		Version:        "2.0",
		IssueInstant:   TimeNow(),
		NameID:         &NameID{Value: "alice"},
		SessionIndexes: []SessionIndex{{Value: "one"}, {Value: "two"}},
	}
	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)
	assert.Check(t, is.Equal(strings.Count(string(buf), "<samlp:SessionIndex"), 2))

	var parsed LogoutRequest
	assert.NilError(t, xml.Unmarshal(buf, &parsed))
	assert.Check(t, is.DeepEqual(parsed.SessionIndexes, request.SessionIndexes))

	// SessionIndex is in the protocol namespace, unlike the NameID before it.
	const assertionNamespace = `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id" Version="2.0"><saml:SessionIndex>wrong</saml:SessionIndex></samlp:LogoutRequest>`
	parsed = LogoutRequest{}
	assert.NilError(t, xml.Unmarshal([]byte(assertionNamespace), &parsed))
	assert.Check(t, is.Len(parsed.SessionIndexes, 0))
}

// ecdsaIdentityProviderKey returns a P-256 key and a certificate which is valid at the time that
// signatureTestIDP sets.
func ecdsaIdentityProviderKey(t *testing.T, test *IdentityProviderTest) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NilError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "idp"},
		NotBefore:    test.SPCertificate.NotBefore.Add(-time.Hour),
		NotAfter:     test.SPCertificate.NotBefore.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	assert.NilError(t, err)
	certificate, err := x509.ParseCertificate(der)
	assert.NilError(t, err)
	return key, certificate
}
