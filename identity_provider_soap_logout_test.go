package saml

import (
	"bytes"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"
)

const soapLogoutTestURL = "https://idp.example.com/saml/slo/soap"

// soapLogoutTestIDP is logoutTestIDP with a SOAP logout URL, and a logger which discards what the identity provider
// logs.
func soapLogoutTestIDP(t *testing.T) (*IdentityProviderTest, *logoutSessionProvider) {
	t.Helper()

	test, provider := logoutTestIDP(t)
	test.IDP.SOAPLogoutURL = mustParseURL(soapLogoutTestURL)
	test.IDP.Logger = log.New(io.Discard, "", 0)

	return test, provider
}

// soapLogoutRequestElement returns the LogoutRequest of sp to the SOAP logout URL, after mutate has changed it and
// signed if sp has a SignatureMethod, and its ID.
func soapLogoutRequestElement(t *testing.T, sp *ServiceProvider, mutate func(*LogoutRequest)) (*etree.Element, string) {
	t.Helper()

	unsigned := *sp
	unsigned.SignatureMethod = ""
	request, err := unsigned.MakeLogoutRequest(soapLogoutTestURL, "alice")
	assert.NilError(t, err)

	if mutate != nil {
		mutate(request)
	}

	if sp.SignatureMethod != "" {
		assert.NilError(t, sp.SignLogoutRequest(request))
	}

	return request.Element(), request.ID
}

// soapLogoutEnvelope returns a SOAP envelope carrying message.
func soapLogoutEnvelope(t *testing.T, message *etree.Element) []byte {
	t.Helper()

	doc, envelope := newSOAPEnvelope()
	envelope.CreateElement("soapenv:Body").AddChild(message)

	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)

	return buf
}

// soapLogoutPost returns a SOAP POST of body to the SOAP logout URL.
func soapLogoutPost(body []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPost, soapLogoutTestURL, bytes.NewReader(body))
	r.Header.Set("Content-Type", "text/xml")

	return r
}

// soapLogoutRequest returns a SOAP POST of the LogoutRequest of sp, after mutate has changed it and signed if sp has
// a SignatureMethod, and its ID.
func soapLogoutRequest(t *testing.T, sp *ServiceProvider, mutate func(*LogoutRequest)) (*http.Request, string) {
	t.Helper()

	el, id := soapLogoutRequestElement(t, sp, mutate)

	return soapLogoutPost(soapLogoutEnvelope(t, el)), id
}

// serveSOAPLogout sends r to ServeSOAPLogout.
func serveSOAPLogout(test *IdentityProviderTest, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	test.IDP.ServeSOAPLogout(w, r)

	return w
}

// soapLogoutResponse returns the LogoutResponse of a 200 SOAP response, verifying that the identity provider signed
// it.
func soapLogoutResponse(t *testing.T, w *httptest.ResponseRecorder) *LogoutResponse {
	t.Helper()

	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())

	envelope := soapTestParseResponse(t, w)

	var body *etree.Element

	for _, child := range envelope.ChildElements() {
		if child.Tag == "Body" && child.NamespaceURI() == soapEnvelopeNS {
			body = child
		}
	}

	assert.Assert(t, body != nil)
	assert.Assert(t, is.Len(body.ChildElements(), 1))

	message := detachSOAPBodyChild(body.ChildElements()[0])
	assert.Check(t, is.Equal(message.Tag, "LogoutResponse"))

	verified, err := verifyEnvelopedSignature(message, []*x509.Certificate{mustParseCertificate(golden.Get(t, "idp_cert.pem"))})
	assert.NilError(t, err)

	response := &LogoutResponse{}
	assert.NilError(t, unmarshalElement(verified, response))

	return response
}

// soapFaultCode returns the faultcode of a 500 SOAP fault.
func soapFaultCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()

	assert.Assert(t, is.Equal(w.Code, http.StatusInternalServerError), "body: %s", w.Body.String())

	envelope := soapTestParseResponse(t, w)

	fault := envelope.FindElement("./Body/Fault/faultcode")
	assert.Assert(t, fault != nil, "body: %s", w.Body.String())

	return fault.Text()
}

// assertLogoutStatus asserts the status codes of response.
func assertLogoutStatus(t *testing.T, response *LogoutResponse, top, second string) {
	t.Helper()

	assert.Check(t, is.Equal(response.Status.StatusCode.Value, top))

	if second == "" {
		assert.Check(t, response.Status.StatusCode.StatusCode == nil)

		return
	}

	assert.Assert(t, response.Status.StatusCode.StatusCode != nil)
	assert.Check(t, is.Equal(response.Status.StatusCode.StatusCode.Value, second))
}

func TestServeSOAPLogoutSuccess(t *testing.T) {
	test, provider := soapLogoutTestIDP(t)
	r, id := soapLogoutRequest(t, &test.SP, nil)
	w := serveSOAPLogout(test, r)

	assert.Check(t, is.Equal(w.Header().Get("Content-Type"), "text/xml; charset=utf-8"))
	assert.Check(t, is.Equal(w.Header().Get("Cache-Control"), "no-cache, no-store"))
	assert.Check(t, is.Equal(w.Header().Get("Pragma"), "no-cache"))

	response := soapLogoutResponse(t, w)
	assert.Check(t, is.Equal(response.InResponseTo, id))
	assert.Check(t, is.Equal(response.Destination, ""))
	assert.Assert(t, response.Issuer != nil)
	assert.Check(t, is.Equal(response.Issuer.Value, test.IDP.MetadataURL.String()))
	assertLogoutStatus(t, response, StatusSuccess, "")

	assert.Assert(t, is.Len(provider.lookups, 1))
	assert.Check(t, is.Equal(provider.lookups[0].ServiceProviderMetadata.EntityID, test.SP.MetadataURL.String()))
	assert.Check(t, is.Len(provider.terminated, 1))
}

func TestServeSOAPLogoutDestinationOptional(t *testing.T) {
	test, provider := soapLogoutTestIDP(t)
	r, id := soapLogoutRequest(t, &test.SP, func(request *LogoutRequest) { request.Destination = "" })

	response := soapLogoutResponse(t, serveSOAPLogout(test, r))
	assert.Check(t, is.Equal(response.InResponseTo, id))
	assertLogoutStatus(t, response, StatusSuccess, "")
	assert.Check(t, is.Len(provider.terminated, 1))
}

// soapLogoutServiceProviderB adds a second service provider to the identity provider of test, with its own key.
func soapLogoutServiceProviderB(t *testing.T, test *IdentityProviderTest) *ServiceProvider {
	t.Helper()

	b := test.SP
	b.MetadataURL = mustParseURL("https://sp-b.example.com/saml2/metadata")
	b.AcsURL = mustParseURL("https://sp-b.example.com/saml2/acs")
	b.Key, b.Certificate = propagationServiceProviderKey(t)

	a := &test.SP

	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			for _, sp := range []*ServiceProvider{a, &b} {
				if serviceProviderID == sp.MetadataURL.String() {
					return sp.Metadata(), nil
				}
			}

			return nil, os.ErrNotExist
		},
	}

	return &b
}

func TestServeSOAPLogoutRejects(t *testing.T) {
	testCases := []struct {
		name           string
		request        func(*testing.T, *IdentityProviderTest) (*http.Request, string)
		top, second    string
		noInResponseTo bool
	}{
		{
			name: "unsigned",
			request: func(t *testing.T, test *IdentityProviderTest) (*http.Request, string) {
				unsigned := test.SP
				unsigned.SignatureMethod = ""

				return soapLogoutRequest(t, &unsigned, nil)
			},
			top: StatusRequester, second: StatusRequestDenied,
		},
		{
			name: "signed by another service provider",
			request: func(t *testing.T, test *IdentityProviderTest) (*http.Request, string) {
				b := soapLogoutServiceProviderB(t, test)

				return soapLogoutRequest(t, &test.SP, func(request *LogoutRequest) { request.Issuer.Value = b.MetadataURL.String() })
			},
			top: StatusRequester, second: StatusRequestDenied,
		},
		{
			name: "unknown issuer",
			request: func(t *testing.T, test *IdentityProviderTest) (*http.Request, string) {
				return soapLogoutRequest(t, &test.SP, func(request *LogoutRequest) {
					request.Issuer.Value = "https://unknown.example.com/saml2/metadata"
				})
			},
			top: StatusRequester, second: StatusRequestDenied,
		},
		{
			name: "signature over altered content",
			request: func(t *testing.T, test *IdentityProviderTest) (*http.Request, string) {
				el, id := soapLogoutRequestElement(t, &test.SP, nil)
				body := bytes.Replace(soapLogoutEnvelope(t, el), []byte(">alice<"), []byte(">bob<"), 1)

				return soapLogoutPost(body), id
			},
			top: StatusRequester, second: StatusRequestDenied,
		},
		{
			name: "wrong destination",
			request: func(t *testing.T, test *IdentityProviderTest) (*http.Request, string) {
				return soapLogoutRequest(t, &test.SP, func(request *LogoutRequest) { request.Destination = "https://idp.example.com/other" })
			},
			top: StatusRequester, second: StatusRequestDenied,
		},
		{
			name: "expired",
			request: func(t *testing.T, test *IdentityProviderTest) (*http.Request, string) {
				return soapLogoutRequest(t, &test.SP, func(request *LogoutRequest) {
					request.IssueInstant = TimeNow().Add(-MaxIssueDelay - time.Second)
				})
			},
			top: StatusRequester, second: StatusRequestDenied,
		},
		{
			name: "version 3.0",
			request: func(t *testing.T, test *IdentityProviderTest) (*http.Request, string) {
				return soapLogoutRequest(t, &test.SP, func(request *LogoutRequest) { request.Version = "3.0" })
			},
			top: StatusVersionMismatch, second: StatusRequestVersionTooHigh,
		},
		{
			name: "no NameID",
			request: func(t *testing.T, test *IdentityProviderTest) (*http.Request, string) {
				return soapLogoutRequest(t, &test.SP, func(request *LogoutRequest) { request.NameID = nil })
			},
			top: StatusRequester, second: StatusRequestDenied,
		},
		{
			name: "bad id",
			request: func(t *testing.T, test *IdentityProviderTest) (*http.Request, string) {
				return soapLogoutRequest(t, &test.SP, func(request *LogoutRequest) { request.ID = "bad id" })
			},
			top: StatusRequester, second: StatusRequestDenied, noInResponseTo: true,
		},
		{
			name: "not a LogoutRequest",
			request: func(t *testing.T, test *IdentityProviderTest) (*http.Request, string) {
				request, err := test.SP.MakeAuthenticationRequest(signatureTestSSOURL, HTTPPostBinding, HTTPPostBinding)
				assert.NilError(t, err)

				return soapLogoutPost(soapLogoutEnvelope(t, request.Element())), request.ID
			},
			top: StatusRequester, second: StatusRequestUnsupported,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			test, provider := soapLogoutTestIDP(t)
			r, id := tc.request(t, test)

			response := soapLogoutResponse(t, serveSOAPLogout(test, r))
			assertLogoutStatus(t, response, tc.top, tc.second)
			assert.Check(t, response.Status.StatusMessage == nil)
			assert.Check(t, is.Equal(response.Destination, ""))

			if tc.noInResponseTo {
				assert.Check(t, is.Equal(response.InResponseTo, ""))
			} else {
				assert.Check(t, is.Equal(response.InResponseTo, id))
			}

			assert.Check(t, is.Len(provider.lookups, 0))
			assert.Check(t, is.Len(provider.terminated, 0))
		})
	}
}

func TestServeSOAPLogoutServiceProviderLookupError(t *testing.T) {
	test, provider := soapLogoutTestIDP(t)
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) {
			return nil, errors.New("storage unavailable")
		},
	}
	r, id := soapLogoutRequest(t, &test.SP, nil)

	response := soapLogoutResponse(t, serveSOAPLogout(test, r))
	assert.Check(t, is.Equal(response.InResponseTo, id))
	assertLogoutStatus(t, response, StatusResponder, "")
	assert.Check(t, is.Len(provider.terminated, 0))
}

func TestServeSOAPLogoutWithoutLogoutSessionProvider(t *testing.T) {
	test, _ := soapLogoutTestIDP(t)
	test.IDP.SessionProvider = &mockSessionProvider{}
	r, id := soapLogoutRequest(t, &test.SP, nil)

	response := soapLogoutResponse(t, serveSOAPLogout(test, r))
	assert.Check(t, is.Equal(response.InResponseTo, id))
	assertLogoutStatus(t, response, StatusResponder, "")
}

func TestServeSOAPLogoutLookupFailure(t *testing.T) {
	test, provider := soapLogoutTestIDP(t)
	provider.lookupError = errors.New("storage unavailable")
	r, _ := soapLogoutRequest(t, &test.SP, nil)

	response := soapLogoutResponse(t, serveSOAPLogout(test, r))
	assertLogoutStatus(t, response, StatusResponder, "")
	assert.Check(t, is.Len(provider.terminated, 0))
}

func TestServeSOAPLogoutTerminationFails(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		test, provider := soapLogoutTestIDP(t)
		provider.err = errors.New("alice has no session")
		r, _ := soapLogoutRequest(t, &test.SP, nil)

		response := soapLogoutResponse(t, serveSOAPLogout(test, r))
		assertLogoutStatus(t, response, StatusResponder, "")
		assert.Check(t, response.Status.StatusMessage == nil)
	})

	t.Run("partial", func(t *testing.T) {
		test, provider := soapLogoutTestIDP(t)
		provider.err = ErrPartialLogout
		r, _ := soapLogoutRequest(t, &test.SP, nil)

		response := soapLogoutResponse(t, serveSOAPLogout(test, r))
		assertLogoutStatus(t, response, StatusSuccess, StatusPartialLogout)
	})
}

func TestServeSOAPLogoutDiscardsSessionHeaders(t *testing.T) {
	test, provider := soapLogoutTestIDP(t)
	r, _ := soapLogoutRequest(t, &test.SP, nil)
	w := serveSOAPLogout(test, r)

	assertLogoutStatus(t, soapLogoutResponse(t, w), StatusSuccess, "")
	// logoutSessionProvider sets a cookie on the writer it is given.
	assert.Check(t, is.Len(provider.terminated, 1))
	assert.Check(t, is.Equal(w.Header().Get("Set-Cookie"), ""))
}

// soapLogoutInheritedNamespaces returns a SOAP POST of el with its namespace declarations moved onto the Envelope.
func soapLogoutInheritedNamespaces(t *testing.T, el *etree.Element) *http.Request {
	t.Helper()

	doc, envelope := newSOAPEnvelope()

	for _, prefix := range []string{"samlp", "saml"} {
		attr := el.SelectAttr("xmlns:" + prefix)
		assert.Assert(t, attr != nil)
		envelope.CreateAttr("xmlns:"+prefix, attr.Value)
		el.RemoveAttr("xmlns:" + prefix)
	}

	envelope.CreateElement("soapenv:Body").AddChild(el)

	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)
	assert.Assert(t, !bytes.Contains(buf, []byte(`<samlp:LogoutRequest xmlns:`)), "%s", buf)

	return soapLogoutPost(buf)
}

func TestServeSOAPLogoutInheritedNamespacePrefix(t *testing.T) {
	t.Run("signed", func(t *testing.T) {
		test, provider := soapLogoutTestIDP(t)
		el, id := soapLogoutRequestElement(t, &test.SP, nil)

		response := soapLogoutResponse(t, serveSOAPLogout(test, soapLogoutInheritedNamespaces(t, el)))
		assert.Check(t, is.Equal(response.InResponseTo, id))
		assertLogoutStatus(t, response, StatusSuccess, "")
		assert.Check(t, is.Len(provider.terminated, 1))
	})

	t.Run("unsigned", func(t *testing.T) {
		test, provider := soapLogoutTestIDP(t)
		unsigned := test.SP
		unsigned.SignatureMethod = ""
		el, id := soapLogoutRequestElement(t, &unsigned, nil)

		response := soapLogoutResponse(t, serveSOAPLogout(test, soapLogoutInheritedNamespaces(t, el)))
		assert.Check(t, is.Equal(response.InResponseTo, id))
		assertLogoutStatus(t, response, StatusRequester, StatusRequestDenied)
		assert.Check(t, is.Len(provider.terminated, 0))
	})
}

func TestServeSOAPLogoutFaults(t *testing.T) {
	t.Run("method", func(t *testing.T) {
		test, _ := soapLogoutTestIDP(t)
		w := serveSOAPLogout(test, httptest.NewRequest(http.MethodGet, soapLogoutTestURL, nil))
		assert.Check(t, is.Equal(w.Code, http.StatusMethodNotAllowed))
		assert.Check(t, is.Equal(w.Header().Get("Allow"), http.MethodPost))
	})

	t.Run("content type", func(t *testing.T) {
		test, provider := soapLogoutTestIDP(t)
		r, _ := soapLogoutRequest(t, &test.SP, nil)
		r.Header.Set("Content-Type", "application/json")
		assert.Check(t, is.Equal(soapFaultCode(t, serveSOAPLogout(test, r)), "soapenv:Client"))
		assert.Check(t, is.Len(provider.terminated, 0))
	})

	t.Run("must understand", func(t *testing.T) {
		test, provider := soapLogoutTestIDP(t)
		el, _ := soapLogoutRequestElement(t, &test.SP, nil)
		doc := etree.NewDocument()
		doc.SetRoot(el)
		message, err := doc.WriteToString()
		assert.NilError(t, err)

		body := soapTestEnvelope(soapTestHeader(`soapenv:mustUnderstand="1"`), message)
		w := serveSOAPLogout(test, soapLogoutPost([]byte(body)))
		assert.Check(t, is.Equal(soapFaultCode(t, w), "soapenv:MustUnderstand"))
		assert.Check(t, is.Len(provider.terminated, 0))
	})

	t.Run("signing fails", func(t *testing.T) {
		test, _ := soapLogoutTestIDP(t)
		test.IDP.Key = nil
		test.IDP.Signer = nil
		r, _ := soapLogoutRequest(t, &test.SP, nil)
		w := serveSOAPLogout(test, r)
		assert.Check(t, is.Equal(soapFaultCode(t, w), "soapenv:Server"))
		assert.Check(t, !strings.Contains(w.Body.String(), "LogoutResponse"))
	})
}

func TestMetadataSOAPLogoutURL(t *testing.T) {
	soapEndpoint := Endpoint{Binding: SOAPBinding, Location: soapLogoutTestURL}
	frontChannel := []Endpoint{
		{Binding: HTTPRedirectBinding, Location: logoutTestSLOURL},
		{Binding: HTTPPostBinding, Location: logoutTestSLOURL},
	}

	t.Run("listed", func(t *testing.T) {
		test, _ := soapLogoutTestIDP(t)
		services := test.IDP.Metadata().IDPSSODescriptors[0].SingleLogoutServices
		assert.Check(t, is.DeepEqual(services, append(append([]Endpoint{}, frontChannel...), soapEndpoint)))
	})

	t.Run("without LogoutURL", func(t *testing.T) {
		test, _ := soapLogoutTestIDP(t)
		test.IDP.LogoutURL = mustParseURL("")
		services := test.IDP.Metadata().IDPSSODescriptors[0].SingleLogoutServices
		assert.Check(t, is.DeepEqual(services, []Endpoint{soapEndpoint}))
	})

	t.Run("without LogoutSessionProvider", func(t *testing.T) {
		test, _ := soapLogoutTestIDP(t)
		test.IDP.SessionProvider = &mockSessionProvider{}
		services := test.IDP.Metadata().IDPSSODescriptors[0].SingleLogoutServices
		assert.Check(t, is.DeepEqual(services, frontChannel))
	})

	t.Run("unset", func(t *testing.T) {
		test, _ := logoutTestIDP(t)
		services := test.IDP.Metadata().IDPSSODescriptors[0].SingleLogoutServices
		assert.Check(t, is.DeepEqual(services, frontChannel))
	})

	t.Run("handler", func(t *testing.T) {
		test, provider := soapLogoutTestIDP(t)
		r, id := soapLogoutRequest(t, &test.SP, nil)
		w := httptest.NewRecorder()
		test.IDP.Handler().ServeHTTP(w, r)

		response := soapLogoutResponse(t, w)
		assert.Check(t, is.Equal(response.InResponseTo, id))
		assertLogoutStatus(t, response, StatusSuccess, "")
		assert.Check(t, is.Len(provider.terminated, 1))
	})

	t.Run("handler shared path", func(t *testing.T) {
		test, provider := soapLogoutTestIDP(t)
		test.IDP.LogoutURL = test.IDP.SOAPLogoutURL
		handler := test.IDP.Handler()

		r, id := soapLogoutRequest(t, &test.SP, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)

		response := soapLogoutResponse(t, w)
		assert.Check(t, is.Equal(response.InResponseTo, id))
		assertLogoutStatus(t, response, StatusSuccess, "")
		assert.Check(t, is.Len(provider.terminated, 1))

		w = httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, soapLogoutTestURL, nil))
		assert.Check(t, is.Equal(w.Code, http.StatusBadRequest))
		assert.Check(t, is.Len(provider.terminated, 1))
	})

	t.Run("handler empty path", func(t *testing.T) {
		test, _ := soapLogoutTestIDP(t)
		test.IDP.SOAPLogoutURL = mustParseURL("https://idp.example.com")

		r, id := soapLogoutRequest(t, &test.SP, nil)
		w := httptest.NewRecorder()
		test.IDP.Handler().ServeHTTP(w, r)

		response := soapLogoutResponse(t, w)
		assert.Check(t, is.Equal(response.InResponseTo, id))
	})
}
