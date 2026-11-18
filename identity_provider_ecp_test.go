package saml

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/dsig"
	"authelia.com/provider/saml/internal/golden"
)

const (
	ecpTestURL     = "https://idp.example.com/saml/ecp"
	ecpTestPAOSURL = "https://sp.example.com/saml2/paos"
)

// ecpSessionProvider is a SessionProvider which authenticates the Enhanced Client or Proxy with HTTP Basic
// credentials, and records what the identity provider asks of it.
type ecpSessionProvider struct {
	session      *Session
	requests     []*IdpAuthnRequest
	participants []SessionParticipant
	getSession   func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session
}

func (p *ecpSessionProvider) GetSession(w http.ResponseWriter, _ *http.Request, _ *IdpAuthnRequest) *Session {
	http.Error(w, "the browser login page", http.StatusTeapot)

	return nil
}

func (p *ecpSessionProvider) GetECPSession(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
	p.requests = append(p.requests, req)

	if p.getSession != nil {
		return p.getSession(w, r, req)
	}

	if username, password, ok := r.BasicAuth(); !ok || username != "alice" || password != "secret" {
		w.Header().Set("WWW-Authenticate", `Basic realm="idp"`)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)

		return nil
	}

	return p.session
}

func (p *ecpSessionProvider) AddSessionParticipant(_ *http.Request, _ *Session, participant SessionParticipant) error {
	p.participants = append(p.participants, participant)

	return nil
}

func (p *ecpSessionProvider) CloseSessionParticipants(*http.Request, *Session) ([]SessionParticipant, error) {
	return p.participants, nil
}

func (p *ecpSessionProvider) SessionParticipants(*http.Request, *Session) ([]SessionParticipant, error) {
	return p.participants, nil
}

// ecpTestMetadata is the metadata of sp with no encryption key, and with an AssertionConsumerService on the PAOS
// binding after those it has.
func ecpTestMetadata(sp *ServiceProvider) *EntityDescriptor {
	metadata := sp.Metadata()
	descriptor := &metadata.SPSSODescriptors[0]

	descriptor.KeyDescriptors = filterKeyDescriptors(descriptor.KeyDescriptors, "signing")
	descriptor.AssertionConsumerServices = append(descriptor.AssertionConsumerServices, IndexedEndpoint{
		Binding:  PAOSBinding,
		Location: ecpTestPAOSURL,
		Index:    3,
	})

	return metadata
}

func filterKeyDescriptors(keyDescriptors []KeyDescriptor, use string) []KeyDescriptor {
	var kept []KeyDescriptor

	for _, keyDescriptor := range keyDescriptors {
		if keyDescriptor.Use == use {
			kept = append(kept, keyDescriptor)
		}
	}

	return kept
}

// ecpTestIDP is an identity provider which serves the ECP profile to a service provider whose metadata is
// ecpTestMetadata, after mutate has changed it. The service provider signs its requests only if a test sets its
// SignatureMethod.
func ecpTestIDP(t *testing.T, mutate func(*EntityDescriptor)) (*IdentityProviderTest, *ecpSessionProvider) {
	t.Helper()

	test := signatureTestIDP(t)
	test.SP.SignatureMethod = ""
	test.IDP.ECPURL = mustParseURL(ecpTestURL)
	test.IDP.Observer = logObserver(io.Discard)

	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			if serviceProviderID != test.SP.MetadataURL.String() {
				return nil, os.ErrNotExist
			}

			metadata := ecpTestMetadata(&test.SP)

			if mutate != nil {
				mutate(metadata)
			}

			return metadata, nil
		},
	}

	provider := &ecpSessionProvider{session: &Session{
		ID:         "session-one",
		CreateTime: TimeNow(),
		Index:      "index-one",
		NameID:     "alice",
		UserName:   "alice",
	}}
	test.IDP.SessionProvider = provider

	return test, provider
}

// ecpAuthnRequest returns the AuthnRequest that the service provider gives the client, after mutate has changed it,
// and signed if the service provider has a SignatureMethod. As the service provider doesn't know the identity
// provider that the client will choose, it has no Destination.
func ecpAuthnRequest(t *testing.T, sp *ServiceProvider, mutate func(*AuthnRequest)) *AuthnRequest {
	t.Helper()

	unsigned := *sp
	unsigned.SignatureMethod = ""
	request, err := unsigned.MakeAuthenticationRequest("", SOAPBinding, PAOSBinding)
	require.NoError(t, err)

	request.AssertionConsumerServiceURL = ecpTestPAOSURL

	if mutate != nil {
		mutate(request)
	}

	if sp.SignatureMethod != "" {
		require.NoError(t, sp.SignAuthnRequest(request))
	}

	return request
}

// ecpEnvelope returns a SOAP envelope carrying the header blocks and message.
func ecpEnvelope(t *testing.T, message *etree.Element, headers ...*etree.Element) []byte {
	t.Helper()

	doc, envelope := newSOAPEnvelope()

	if len(headers) != 0 {
		header := envelope.CreateElement("soapenv:Header")

		for _, h := range headers {
			header.AddChild(h)
		}
	}

	envelope.CreateElement("soapenv:Body").AddChild(message)

	buf, err := doc.WriteToBytes()
	require.NoError(t, err)

	return buf
}

// ecpPost returns the POST of a SOAP envelope to the ECP URL by a client which authenticates as alice.
func ecpPost(body []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPost, ecpTestURL, bytes.NewReader(body))
	r.Header.Set("Content-Type", "text/xml")
	r.SetBasicAuth("alice", "secret")

	return r
}

// serveECP sends the request of the service provider to ServeECP, and returns the recorder and the request ID.
func serveECP(t *testing.T, test *IdentityProviderTest, mutate func(*AuthnRequest), headers ...*etree.Element) (*httptest.ResponseRecorder, string) {
	t.Helper()

	request := ecpAuthnRequest(t, &test.SP, mutate)

	w := httptest.NewRecorder()
	test.IDP.ServeECP(w, ecpPost(ecpEnvelope(t, request.Element(), headers...)))

	return w, request.ID
}

// ecpResponse is what the identity provider answered a client with.
type ecpResponse struct {
	Headers  []*etree.Element
	Response *Response
	// Element is the Response as the identity provider signed it.
	Element *etree.Element
}

// header returns the header block in the ECP namespace with the tag, or nil.
func (e *ecpResponse) header(tag string) *etree.Element {
	for _, header := range e.Headers {
		if header.Tag == tag && header.NamespaceURI() == ecpNS {
			return header
		}
	}

	return nil
}

// parseECPResponse returns the header blocks and Response of a 200 SOAP response, verifying that the identity
// provider signed the Response.
func parseECPResponse(t *testing.T, w *httptest.ResponseRecorder) *ecpResponse {
	t.Helper()

	require.Equal(t, w.Code, http.StatusOK, "body: %s", w.Body.String())

	// The envelope must also satisfy the parser that a client of the binding would use.
	_, headers, message, err := parseSOAPEnvelope(w.Body.Bytes())
	require.NoError(t, err)

	soapTestParseResponse(t, w)

	require.Equal(t, message.Tag, "Response")
	require.Equal(t, message.NamespaceURI(), samlProtocolNS)

	verified, err := verifyEnvelopedSignature(message, []*x509.Certificate{mustParseCertificate(golden.Get(t, "idp_cert.pem"))}, anySignaturePolicy)
	require.NoError(t, err)

	response := &Response{}
	require.NoError(t, unmarshalElement(verified, response))

	return &ecpResponse{Headers: headers, Response: response, Element: message}
}

// assertECPResponseHeader checks the ecp:Response header block, which every Response must come with (ECP v2.0
// §2.3.6, SAMLProf §4.2.4.4).
func assertECPResponseHeader(t *testing.T, response *ecpResponse, acs string) {
	t.Helper()

	header := response.header("Response")
	require.True(t, header != nil, "the envelope has no ecp:Response header block")

	assert.Equal(t, soapHeaderAttr(header, "mustUnderstand"), "1")
	assert.Equal(t, soapHeaderAttr(header, "actor"), soapActorNext)
	assert.Equal(t, header.SelectAttrValue("AssertionConsumerServiceURL", ""), acs)
	assert.Len(t, header.ChildElements(), 0)
	assert.Equal(t, header.Text(), "")
}

// assertECPStatus checks that the answer is an error Response to the request, with the statuses, in an envelope
// with the ecp:Response header block for the PAOS endpoint of the service provider.
func assertECPStatus(t *testing.T, w *httptest.ResponseRecorder, id, top, second string) *ecpResponse {
	t.Helper()

	response := parseECPResponse(t, w)
	assertECPResponseHeader(t, response, ecpTestPAOSURL)

	assert.Equal(t, response.Response.InResponseTo, id)
	assert.Equal(t, response.Response.Destination, ecpTestPAOSURL)
	assert.Equal(t, response.Response.Status.StatusCode.Value, top)

	if second == "" {
		assert.Nil(t, response.Response.Status.StatusCode.StatusCode)
	} else {
		require.NotNil(t, response.Response.Status.StatusCode.StatusCode)
		assert.Equal(t, response.Response.Status.StatusCode.StatusCode.Value, second)
	}

	// SAMLProf §4.1.4.2: an error carries no assertion.
	assert.True(t, statusSaysNothingOfTheRequest(response.Response.Status))
	assert.Nil(t, response.Response.Assertion)
	assert.Nil(t, response.Response.EncryptedAssertion)

	return response
}

func ecpChannelBindingsHeader() *etree.Element {
	header := etree.NewElement("cb:ChannelBindings")
	header.CreateAttr("xmlns:cb", channelBindingNS)
	header.CreateAttr("Type", "tls-server-end-point")
	header.CreateAttr("soapenv:mustUnderstand", "1")
	header.CreateAttr("soapenv:actor", soapActorNext)
	header.SetText("AAAA")

	return header
}

func TestServeECPSuccess(t *testing.T) {
	test, provider := ecpTestIDP(t, nil)

	w, id := serveECP(t, test, nil)
	response := parseECPResponse(t, w)

	assertECPResponseHeader(t, response, ecpTestPAOSURL)
	assert.True(t, response.header("RequestAuthenticated") == nil, "the request was not signed")
	assert.Len(t, response.Headers, 1)

	assert.Equal(t, response.Response.Status.StatusCode.Value, StatusSuccess)
	assert.Equal(t, response.Response.InResponseTo, id)
	assert.Equal(t, response.Response.Destination, ecpTestPAOSURL)
	assert.Equal(t, response.Response.Issuer.Value, test.IDP.MetadataURL.String())

	// SAMLProf §4.1.4.2, which ECP v2.0 §2.3.6 applies to a bearer assertion.
	assertion := response.Response.Assertion
	require.NotNil(t, assertion)
	assert.NotNil(t, assertion.Signature)
	assert.Equal(t, assertion.Issuer.Value, test.IDP.MetadataURL.String())
	assert.Equal(t, assertion.Subject.NameID.SPNameQualifier, test.SP.MetadataURL.String())

	require.Len(t, assertion.Subject.SubjectConfirmations, 1)
	confirmation := assertion.Subject.SubjectConfirmations[0]
	assert.Equal(t, confirmation.Method, bearerSubjectConfirmationMethod)
	assert.Equal(t, confirmation.SubjectConfirmationData.Recipient, ecpTestPAOSURL)
	assert.Equal(t, confirmation.SubjectConfirmationData.InResponseTo, id)
	assert.True(t, confirmation.SubjectConfirmationData.NotBefore.IsZero())
	assert.False(t, confirmation.SubjectConfirmationData.NotOnOrAfter.IsZero())
	assert.Equal(t, confirmation.SubjectConfirmationData.Address, "192.0.2.1", "the address of the client")

	assert.Equal(t, assertion.Conditions.AudienceRestrictions,
		[]AudienceRestriction{{Audiences: []Audience{{Value: test.SP.MetadataURL.String()}}}})
	require.Len(t, assertion.AuthnStatements, 1)
	assert.Equal(t, assertion.AuthnStatements[0].SessionIndex, "index-one")

	// The service provider is a participant of the session, so that a logout reaches it.
	require.Len(t, provider.participants, 1)
	assert.Equal(t, provider.participants[0].ServiceProviderEntityID, test.SP.MetadataURL.String())
	assert.Equal(t, provider.participants[0].SessionIndex, "index-one")

	require.Len(t, provider.requests, 1)
	assert.Equal(t, provider.requests[0].ACSEndpoint.Location, ecpTestPAOSURL)
	assert.Equal(t, provider.requests[0].ServiceProviderMetadata.EntityID, test.SP.MetadataURL.String())
}

func TestServeECPSignedRequestIsReportedAuthenticated(t *testing.T) {
	test, _ := ecpTestIDP(t, nil)
	test.SP.SignatureMethod = dsig.RSASHA256SignatureMethod
	test.IDP.WantAuthnRequestsSigned = true

	// The request has no Destination, which the service provider can't know (ECP v2.0 §2.3.3).
	w, id := serveECP(t, test, func(r *AuthnRequest) {
		require.Equal(t, r.Destination, "")
	})
	response := parseECPResponse(t, w)

	assertECPResponseHeader(t, response, ecpTestPAOSURL)
	assert.Equal(t, response.Response.Status.StatusCode.Value, StatusSuccess)
	assert.Equal(t, response.Response.InResponseTo, id)

	// ECP v2.0 §2.3.6.1.
	header := response.header("RequestAuthenticated")
	require.True(t, header != nil, "the envelope has no ecp:RequestAuthenticated header block")
	assert.Equal(t, soapHeaderAttr(header, "actor"), soapActorNext)
	assert.Len(t, header.ChildElements(), 0)
	assert.Len(t, response.Headers, 2)
}

func TestServeECPSignedRequestErrorIsReportedAuthenticated(t *testing.T) {
	test, _ := ecpTestIDP(t, nil)
	test.SP.SignatureMethod = dsig.RSASHA256SignatureMethod

	w, id := serveECP(t, test, func(r *AuthnRequest) { r.Version = "3.0" })
	response := assertECPStatus(t, w, id, StatusVersionMismatch, StatusRequestVersionTooHigh)

	assert.NotNil(t, response.header("RequestAuthenticated"))
}

func TestServeECPUsesDefaultPAOSEndpoint(t *testing.T) {
	test, _ := ecpTestIDP(t, nil)

	w, _ := serveECP(t, test, func(r *AuthnRequest) {
		r.AssertionConsumerServiceURL, r.ProtocolBinding = "", ""
	})
	response := parseECPResponse(t, w)

	assertECPResponseHeader(t, response, ecpTestPAOSURL)
	assert.Equal(t, response.Response.Status.StatusCode.Value, StatusSuccess)
	assert.Equal(t, response.Response.Assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.Recipient, ecpTestPAOSURL)
}

func TestServeECPUsesIndexedPAOSEndpoint(t *testing.T) {
	const second = "https://sp.example.com/saml2/paos/two"

	test, _ := ecpTestIDP(t, func(metadata *EntityDescriptor) {
		descriptor := &metadata.SPSSODescriptors[0]
		descriptor.AssertionConsumerServices = append(descriptor.AssertionConsumerServices,
			IndexedEndpoint{Binding: PAOSBinding, Location: second, Index: 4})
	})

	w, _ := serveECP(t, test, func(r *AuthnRequest) {
		r.AssertionConsumerServiceURL, r.ProtocolBinding, r.AssertionConsumerServiceIndex = "", "", "4"
	})
	response := parseECPResponse(t, w)

	assertECPResponseHeader(t, response, second)
	assert.Equal(t, response.Response.Destination, second)
}

func TestServeECPEnvelopeFailures(t *testing.T) {
	t.Run("not a POST", func(t *testing.T) {
		test, provider := ecpTestIDP(t, nil)

		w := httptest.NewRecorder()
		test.IDP.ServeECP(w, httptest.NewRequest(http.MethodGet, ecpTestURL, nil))

		assert.Equal(t, w.Code, http.StatusMethodNotAllowed)
		assert.Equal(t, w.Header().Get("Allow"), http.MethodPost)
		assert.Len(t, provider.requests, 0)
	})

	t.Run("wrong content type", func(t *testing.T) {
		test, provider := ecpTestIDP(t, nil)

		r := ecpPost(ecpEnvelope(t, ecpAuthnRequest(t, &test.SP, nil).Element()))
		r.Header.Set("Content-Type", "application/vnd.paos+xml")

		w := httptest.NewRecorder()
		test.IDP.ServeECP(w, r)

		assert.Equal(t, soapFaultCode(t, w), "soapenv:Client")
		assert.Len(t, provider.requests, 0)
	})

	t.Run("not an envelope", func(t *testing.T) {
		test, provider := ecpTestIDP(t, nil)

		doc := etree.NewDocument()
		doc.SetRoot(ecpAuthnRequest(t, &test.SP, nil).Element())
		buf, err := doc.WriteToBytes()
		require.NoError(t, err)

		w := httptest.NewRecorder()
		test.IDP.ServeECP(w, ecpPost(buf))

		assert.Equal(t, soapFaultCode(t, w), "soapenv:Client")
		assert.Len(t, provider.requests, 0)
	})

	t.Run("not an AuthnRequest", func(t *testing.T) {
		test, provider := ecpTestIDP(t, nil)

		request, err := test.SP.MakeLogoutRequest(ecpTestURL, "alice")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		test.IDP.ServeECP(w, ecpPost(ecpEnvelope(t, request.Element())))

		assert.Equal(t, soapFaultCode(t, w), "soapenv:Client")
		assert.Len(t, provider.requests, 0)
	})

	t.Run("header block that is not understood", func(t *testing.T) {
		test, provider := ecpTestIDP(t, nil)

		header := etree.NewElement("x:Unknown")
		header.CreateAttr("xmlns:x", "urn:example:unknown")
		header.CreateAttr("soapenv:mustUnderstand", "1")

		w, _ := serveECP(t, test, nil, header)

		assert.Equal(t, soapFaultCode(t, w), "soapenv:MustUnderstand")
		assert.Len(t, provider.requests, 0)
	})

	// SAMLProf §4.2.3.4: the client must remove the header blocks of the service provider, which are addressed to
	// the client and not to the identity provider.
	t.Run("RelayState header block that the client did not remove", func(t *testing.T) {
		test, provider := ecpTestIDP(t, nil)

		header := etree.NewElement("ecp:RelayState")
		header.CreateAttr("xmlns:ecp", ecpNS)
		header.CreateAttr("soapenv:mustUnderstand", "1")
		header.CreateAttr("soapenv:actor", soapActorNext)
		header.SetText("state")

		w, _ := serveECP(t, test, nil, header)

		assert.Equal(t, soapFaultCode(t, w), "soapenv:MustUnderstand")
		assert.Len(t, provider.requests, 0)
	})
}

// A request that fails before the endpoint of the service provider is established from its metadata can't be
// answered with a Response, which names that endpoint in its ecp:Response header block, so it gets a fault (ECP
// v2.0 §2.3.6). The principal is never authenticated.
func TestServeECPTrustFailuresAreFaults(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metadata func(*EntityDescriptor)
		idp      func(*IdentityProviderTest)
		request  func(*AuthnRequest)
	}{
		{
			name:    "unknown service provider",
			request: func(r *AuthnRequest) { r.Issuer.Value = "https://unknown.example.com/metadata" },
		},
		{
			name:    "no issuer",
			request: func(r *AuthnRequest) { r.Issuer = nil },
		},
		{
			name:    "invalid request ID",
			request: func(r *AuthnRequest) { r.ID = "an invalid id" },
		},
		{
			name: "unsigned and the identity provider requires signatures",
			idp:  func(test *IdentityProviderTest) { test.IDP.WantAuthnRequestsSigned = true },
		},
		{
			name: "unsigned and the service provider signs its requests",
			metadata: func(metadata *EntityDescriptor) {
				signed := true
				metadata.SPSSODescriptors[0].AuthnRequestsSigned = &signed
			},
		},
		{
			name: "signed by another key",
			idp: func(test *IdentityProviderTest) {
				test.SP.SignatureMethod = dsig.RSASHA256SignatureMethod
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				test.SP.Key = key
			},
		},
		{
			name:    "assertion consumer service URL that the metadata does not list",
			request: func(r *AuthnRequest) { r.AssertionConsumerServiceURL = "https://attacker.example.com/paos" },
		},
		{
			name:    "assertion consumer service URL of an HTTP-POST endpoint",
			request: func(r *AuthnRequest) { r.AssertionConsumerServiceURL = "https://sp.example.com/saml2/acs" },
		},
		{
			name: "assertion consumer service index of an HTTP-POST endpoint",
			request: func(r *AuthnRequest) {
				r.AssertionConsumerServiceURL, r.ProtocolBinding, r.AssertionConsumerServiceIndex = "", "", "1"
			},
		},
		{
			name:    "assertion consumer service index and URL",
			request: func(r *AuthnRequest) { r.AssertionConsumerServiceIndex = "3" },
		},
		{
			name: "no PAOS assertion consumer service",
			metadata: func(metadata *EntityDescriptor) {
				descriptor := &metadata.SPSSODescriptors[0]
				descriptor.AssertionConsumerServices = descriptor.AssertionConsumerServices[:2]
			},
			request: func(r *AuthnRequest) { r.AssertionConsumerServiceURL, r.ProtocolBinding = "", "" },
		},
		{
			name: "insecure PAOS assertion consumer service",
			metadata: func(metadata *EntityDescriptor) {
				metadata.SPSSODescriptors[0].AssertionConsumerServices[2].Location = "http://sp.example.com/saml2/paos"
			},
			request: func(r *AuthnRequest) { r.AssertionConsumerServiceURL = "http://sp.example.com/saml2/paos" },
		},
		{
			name: "unsupported binding with an assertion consumer service URL that the metadata does not list",
			request: func(r *AuthnRequest) {
				r.ProtocolBinding, r.AssertionConsumerServiceURL = HTTPPostBinding, "https://attacker.example.com/acs"
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test, provider := ecpTestIDP(t, tc.metadata)

			if tc.idp != nil {
				tc.idp(test)
			}

			w, _ := serveECP(t, test, tc.request)

			assert.Equal(t, soapFaultCode(t, w), "soapenv:Client")
			assert.Len(t, provider.requests, 0, "the principal must not be authenticated")
			assert.Len(t, provider.participants, 0)
		})
	}
}

// A tampered request with a signature is refused, even when no signature is required.
func TestServeECPInvalidSignatureIsFault(t *testing.T) {
	test, provider := ecpTestIDP(t, nil)
	test.SP.SignatureMethod = dsig.RSASHA256SignatureMethod

	el := ecpAuthnRequest(t, &test.SP, nil).Element()
	el.CreateAttr("ForceAuthn", "true")

	w := httptest.NewRecorder()
	test.IDP.ServeECP(w, ecpPost(ecpEnvelope(t, el)))

	assert.Equal(t, soapFaultCode(t, w), "soapenv:Client")
	assert.Len(t, provider.requests, 0)
}

// Once the endpoint of the service provider is established, a failure is a Response with an error status in the
// same envelope as a success (ECP v2.0 §2.3.6, SAMLProf §4.1.4.1).
func TestServeECPRequestStatuses(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request func(*AuthnRequest)
		top     string
		second  string
	}{
		{
			name:    "version too high",
			request: func(r *AuthnRequest) { r.Version = "3.0" },
			top:     StatusVersionMismatch, second: StatusRequestVersionTooHigh,
		},
		{
			name:    "expired",
			request: func(r *AuthnRequest) { r.IssueInstant = TimeNow().Add(-MaxIssueDelay - MaxClockSkew) },
			top:     StatusRequester, second: StatusRequestDenied,
		},
		{
			name:    "issued in the future",
			request: func(r *AuthnRequest) { r.IssueInstant = TimeNow().Add(time.Hour) },
			top:     StatusRequester, second: StatusRequestDenied,
		},
		{
			name:    "destination is the browser SSO endpoint",
			request: func(r *AuthnRequest) { r.Destination = "https://idp.example.com/saml/sso" },
			top:     StatusRequester, second: StatusRequestDenied,
		},
		{
			name:    "HTTP-POST protocol binding",
			request: func(r *AuthnRequest) { r.ProtocolBinding = HTTPPostBinding },
			top:     StatusResponder, second: StatusUnsupportedBinding,
		},
		{
			name:    "HTTP-POST protocol binding and no assertion consumer service URL",
			request: func(r *AuthnRequest) { r.ProtocolBinding, r.AssertionConsumerServiceURL = HTTPPostBinding, "" },
			top:     StatusResponder, second: StatusUnsupportedBinding,
		},
		{
			name:    "passive",
			request: func(r *AuthnRequest) { r.IsPassive = boolPointer(true) },
			top:     StatusResponder, second: StatusNoPassive,
		},
		{
			name: "passive and forced",
			request: func(r *AuthnRequest) {
				r.IsPassive, r.ForceAuthn = boolPointer(true), boolPointer(true)
			},
			top: StatusResponder, second: StatusNoPassive,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test, provider := ecpTestIDP(t, nil)

			w, id := serveECP(t, test, tc.request)
			response := assertECPStatus(t, w, id, tc.top, tc.second)

			assert.Nil(t, response.header("RequestAuthenticated"))
			assert.Len(t, provider.requests, 0, "the principal must not be authenticated")
			assert.Len(t, provider.participants, 0)
		})
	}
}

func boolPointer(v bool) *bool {
	return &v
}

func TestServeECPDestinationIsECPURL(t *testing.T) {
	test, _ := ecpTestIDP(t, nil)

	w, _ := serveECP(t, test, func(r *AuthnRequest) { r.Destination = ecpTestURL })

	assert.Equal(t, parseECPResponse(t, w).Response.Status.StatusCode.Value, StatusSuccess)
}

// Channel bindings aren't verified, and ECP v2.0 §2.3.6.2 requires an error Response rather than an assertion
// which doesn't state them.
func TestServeECPChannelBindingsAreRefused(t *testing.T) {
	t.Run("header block of the client", func(t *testing.T) {
		test, provider := ecpTestIDP(t, nil)

		w, id := serveECP(t, test, nil, ecpChannelBindingsHeader())

		assertECPStatus(t, w, id, StatusRequester, StatusRequestUnsupported)
		assert.Len(t, provider.requests, 0)
	})

	t.Run("header block of the client for its channel to the identity provider", func(t *testing.T) {
		test, provider := ecpTestIDP(t, nil)

		header := ecpChannelBindingsHeader()
		header.RemoveAttr("soapenv:actor")
		header.RemoveAttr("soapenv:mustUnderstand")

		w, id := serveECP(t, test, nil, header)

		assertECPStatus(t, w, id, StatusRequester, StatusRequestUnsupported)
		assert.Len(t, provider.requests, 0)
	})

	t.Run("extension of the service provider", func(t *testing.T) {
		test, provider := ecpTestIDP(t, nil)

		request := ecpAuthnRequest(t, &test.SP, nil)
		el := request.Element()

		extensions := etree.NewElement("samlp:Extensions")
		binding := extensions.CreateElement("cb:ChannelBindings")
		binding.CreateAttr("xmlns:cb", channelBindingNS)
		binding.SetText("AAAA")

		// Extensions follow the Issuer (SAMLCore §3.2.1).
		el.InsertChildAt(1, extensions)

		w := httptest.NewRecorder()
		test.IDP.ServeECP(w, ecpPost(ecpEnvelope(t, el)))

		assertECPStatus(t, w, request.ID, StatusRequester, StatusRequestUnsupported)
		assert.Len(t, provider.requests, 0)
	})
}

func TestServeECPWithoutECPSessionProvider(t *testing.T) {
	test, _ := ecpTestIDP(t, nil)

	browser := 0
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
			browser++

			return &Session{ID: "browser", NameID: "alice"}
		},
	}

	w, id := serveECP(t, test, nil)

	assertECPStatus(t, w, id, StatusResponder, StatusRequestUnsupported)
	assert.Equal(t, browser, 0, "a browser session must not be used")
}

// ECP v2.0 §2.3.4 lets the identity provider answer with other HTTP responses, such as a challenge, before it
// completes the exchange.
func TestServeECPUnauthenticatedIsChallenged(t *testing.T) {
	for _, tc := range []struct {
		name string
		auth func(*http.Request)
	}{
		{"no credentials", func(r *http.Request) { r.Header.Del("Authorization") }},
		{"wrong password", func(r *http.Request) { r.SetBasicAuth("alice", "wrong") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test, provider := ecpTestIDP(t, nil)

			r := ecpPost(ecpEnvelope(t, ecpAuthnRequest(t, &test.SP, nil).Element()))
			tc.auth(r)

			w := httptest.NewRecorder()
			test.IDP.ServeECP(w, r)

			assert.Equal(t, w.Code, http.StatusUnauthorized)
			assert.Equal(t, w.Header().Get("WWW-Authenticate"), `Basic realm="idp"`)
			assert.Len(t, provider.requests, 1)
			assert.Len(t, provider.participants, 0)
		})
	}
}

// ECP v2.0 §2.3.5: ForceAuthn obliges the identity provider to establish the identity freshly, which is for the
// ECPSessionProvider to do.
func TestServeECPForceAuthnReachesProvider(t *testing.T) {
	test, provider := ecpTestIDP(t, nil)

	w, _ := serveECP(t, test, func(r *AuthnRequest) { r.ForceAuthn = boolPointer(true) })

	assert.Equal(t, parseECPResponse(t, w).Response.Status.StatusCode.Value, StatusSuccess)
	require.Len(t, provider.requests, 1)
	require.NotNil(t, provider.requests[0].Request.ForceAuthn)
	assert.True(t, *provider.requests[0].Request.ForceAuthn)
}

// An ECPSessionProvider can refuse the principal with a SAML status of its own.
func TestServeECPProviderWritesErrorResponse(t *testing.T) {
	test, provider := ecpTestIDP(t, nil)
	provider.getSession = func(w http.ResponseWriter, _ *http.Request, req *IdpAuthnRequest) *Session {
		assert.NoError(t, req.WriteErrorResponse(w, ErrAuthnFailed))

		return nil
	}

	w, id := serveECP(t, test, nil)

	assertECPStatus(t, w, id, StatusResponder, StatusAuthnFailed)
}

func TestServeECPPolicyStatuses(t *testing.T) {
	persistent := "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

	for _, tc := range []struct {
		name    string
		idp     func(*IdentityProviderTest)
		request func(*AuthnRequest)
		top     string
		second  string
	}{
		{
			name:    "name ID policy",
			request: func(r *AuthnRequest) { r.NameIDPolicy = &NameIDPolicy{Format: &persistent} },
			top:     StatusRequester, second: StatusInvalidNameIDPolicy,
		},
		{
			name: "requested authentication context",
			request: func(r *AuthnRequest) {
				r.RequestedAuthnContext = &RequestedAuthnContext{
					Comparison:            AuthnContextComparisonExact,
					AuthnContextClassRefs: []string{"https://refeds.org/profile/mfa"},
				}
			},
			top: StatusResponder, second: StatusNoAuthnContext,
		},
		{
			name: "subject is another principal",
			request: func(r *AuthnRequest) {
				r.Subject = &Subject{NameID: &NameID{Value: "bob"}}
			},
			top: StatusResponder, second: StatusAuthnFailed,
		},
		{
			name: "assertion maker fails",
			idp: func(test *IdentityProviderTest) {
				test.IDP.AssertionMaker = failingAssertionMaker{}
			},
			top: StatusResponder,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test, provider := ecpTestIDP(t, nil)

			if tc.idp != nil {
				tc.idp(test)
			}

			w, id := serveECP(t, test, tc.request)

			assertECPStatus(t, w, id, tc.top, tc.second)
			assert.Len(t, provider.requests, 1)
			assert.Len(t, provider.participants, 0)
		})
	}
}

type failingAssertionMaker struct{}

func (failingAssertionMaker) MakeAssertion(*IdpAuthnRequest, *Session) error {
	return errors.New("the directory is unavailable")
}

// A Response that can't be signed can't be sent, so the client gets a fault.
func TestServeECPSigningFailureIsServerFault(t *testing.T) {
	test, _ := ecpTestIDP(t, nil)
	test.IDP.Key, test.IDP.Signer = nil, nil

	w, _ := serveECP(t, test, nil)

	assert.Equal(t, soapFaultCode(t, w), "soapenv:Server")
}

// A logout of the session that has begun stops the assertion, and the client is told with an error status.
func TestServeECPParticipantRefused(t *testing.T) {
	test, _ := ecpTestIDP(t, nil)
	test.IDP.SessionProvider = &closedParticipantsECPProvider{ecpSessionProvider{session: &Session{ID: "session-one", NameID: "alice"}}}

	w, id := serveECP(t, test, nil)

	assertECPStatus(t, w, id, StatusResponder, "")
}

type closedParticipantsECPProvider struct{ ecpSessionProvider }

func (*closedParticipantsECPProvider) AddSessionParticipant(*http.Request, *Session, SessionParticipant) error {
	return ErrSessionParticipantsClosed
}

func TestECPMetadata(t *testing.T) {
	soapEndpoint := Endpoint{Binding: SOAPBinding, Location: ecpTestURL}

	t.Run("advertised with the URL and an ECPSessionProvider", func(t *testing.T) {
		test, _ := ecpTestIDP(t, nil)

		// SAMLMeta §2.4.3 and ECP v2.0 §2.3.10.
		assert.Equal(t, test.IDP.Metadata().IDPSSODescriptors[0].SingleSignOnServices, []Endpoint{
			{Binding: HTTPRedirectBinding, Location: "https://idp.example.com/saml/sso"},
			{Binding: HTTPPostBinding, Location: "https://idp.example.com/saml/sso"},
			soapEndpoint,
		})
	})

	t.Run("not advertised without the URL", func(t *testing.T) {
		test, _ := ecpTestIDP(t, nil)
		test.IDP.ECPURL = mustParseURL("")

		assert.Len(t, test.IDP.Metadata().IDPSSODescriptors[0].SingleSignOnServices, 2)
	})

	t.Run("not advertised without an ECPSessionProvider", func(t *testing.T) {
		test, _ := ecpTestIDP(t, nil)
		test.IDP.SessionProvider = &mockSessionProvider{}

		assert.Len(t, test.IDP.Metadata().IDPSSODescriptors[0].SingleSignOnServices, 2)
	})
}

func TestHandlerServesECP(t *testing.T) {
	t.Run("at its own path", func(t *testing.T) {
		test, _ := ecpTestIDP(t, nil)

		w := httptest.NewRecorder()
		test.IDP.Handler().ServeHTTP(w, ecpPost(ecpEnvelope(t, ecpAuthnRequest(t, &test.SP, nil).Element())))

		assert.Equal(t, parseECPResponse(t, w).Response.Status.StatusCode.Value, StatusSuccess)
	})

	t.Run("at the path of the SSO URL", func(t *testing.T) {
		test, _ := ecpTestIDP(t, nil)
		test.IDP.ECPURL = test.IDP.SSOURL

		r := ecpPost(ecpEnvelope(t, ecpAuthnRequest(t, &test.SP, nil).Element()))
		r.URL.Path = test.IDP.SSOURL.Path

		w := httptest.NewRecorder()
		test.IDP.Handler().ServeHTTP(w, r)

		assert.Equal(t, parseECPResponse(t, w).Response.Status.StatusCode.Value, StatusSuccess)

		// A browser request at the same path still reaches the SSO service, which refuses this one as it has no
		// request.
		w = httptest.NewRecorder()
		test.IDP.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, test.IDP.SSOURL.String(), nil))

		assert.Equal(t, w.Code, http.StatusBadRequest)
	})
}

// A request on a browser binding is unaffected: it is answered with the HTTP-POST form, at an HTTP-POST endpoint.
func TestServeSSOIgnoresPAOSEndpoints(t *testing.T) {
	test, _ := ecpTestIDP(t, nil)

	w, _ := serveSSOModified(t, test, func(r *AuthnRequest) {
		r.AssertionConsumerServiceURL = ecpTestPAOSURL
	})

	assert.Equal(t, w.Code, http.StatusBadRequest)
}

// SAMLSec §6.1.2: as for ServeSSO, a request is used up once it is answered for an authenticated principal.
func TestServeECPRefusesReplay(t *testing.T) {
	test, provider := ecpTestIDP(t, nil)

	store := newRecordingReplayStore()
	test.IDP.ReplayStore = store

	request := ecpAuthnRequest(t, &test.SP, nil)
	body := ecpEnvelope(t, request.Element())

	serve := func(r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		test.IDP.ServeECP(w, r)

		return w
	}

	// A request that the client must send again with credentials is not recorded, so that one is not a replay.
	r := ecpPost(body)
	r.Header.Del("Authorization")

	assert.Equal(t, serve(r).Code, http.StatusUnauthorized)
	assert.Equal(t, store.calls(), 0)

	response := parseECPResponse(t, serve(ecpPost(body)))
	assert.Equal(t, response.Response.Status.StatusCode.Value, StatusSuccess)
	require.Equal(t, store.calls(), 1)
	assert.True(t, strings.HasPrefix(store.keys[0], replayKindAuthnRequest+":"))
	assert.Len(t, provider.participants, 1)

	// The same request again is refused, in the envelope of the profile, and states nothing.
	assertECPStatus(t, serve(ecpPost(body)), request.ID, StatusRequester, StatusRequestDenied)
	assert.Len(t, provider.participants, 1)

	// If the store fails, nothing is known about the request, and it is refused.
	store.err = errors.New("store down")

	w, id := serveECP(t, test, func(r *AuthnRequest) { r.ID = "id-another-request" })
	assertECPStatus(t, w, id, StatusResponder, "")
	assert.Len(t, provider.participants, 1)
}

func TestServeECPSavesAssertion(t *testing.T) {
	test, _ := ecpTestIDP(t, nil)

	store := &testAssertionStore{}
	test.IDP.AssertionStore = store

	w, _ := serveECP(t, test, nil)
	response := parseECPResponse(t, w)

	require.NotNil(t, response.Response.Assertion)
	require.Equal(t, store.saved, []string{response.Response.Assertion.ID})
	assert.Equal(t, store.assertions[store.saved[0]].serviceProviderID, test.SP.MetadataURL.String())

	// An error states nothing, so nothing is saved.
	w, id := serveECP(t, test, func(r *AuthnRequest) {
		r.ID = "id-another-request"
		r.IsPassive = boolPointer(true)
	})
	assertECPStatus(t, w, id, StatusResponder, StatusNoPassive)
	assert.Len(t, store.saved, 1)
}

// The HTTP-Artifact binding is a browser binding: when it is enabled, a request of the profile is still answered
// in the envelope, for a PAOS endpoint, and a browser request is still answered by artifact.
func TestServeECPWithArtifactBinding(t *testing.T) {
	const artifactACS = "https://sp.example.com/saml2/artifact"

	isDefault := true

	test, _ := ecpTestIDP(t, func(metadata *EntityDescriptor) {
		descriptor := &metadata.SPSSODescriptors[0]
		descriptor.AssertionConsumerServices = append([]IndexedEndpoint{
			{Binding: HTTPArtifactBinding, Location: artifactACS, Index: 9, IsDefault: &isDefault},
		}, descriptor.AssertionConsumerServices...)
	})

	artifacts := NewMemoryArtifactStore(0)
	test.IDP.ArtifactResolutionURL = mustParseURL(artifactTestURL)
	test.IDP.ArtifactStore = artifacts

	w, _ := serveECP(t, test, func(r *AuthnRequest) {
		r.ID = "id-default-endpoint"
		r.AssertionConsumerServiceURL, r.ProtocolBinding = "", ""
	})
	response := parseECPResponse(t, w)

	assertECPResponseHeader(t, response, ecpTestPAOSURL)
	assert.Equal(t, response.Response.Status.StatusCode.Value, StatusSuccess)
	assert.Equal(t, response.Response.Destination, ecpTestPAOSURL)
	assert.Equal(t, artifacts.Len(), 0)

	// The client can't deliver an artifact, so the binding is not one that the profile can be answered with.
	for name, mutate := range map[string]func(*AuthnRequest){
		"protocol binding": func(r *AuthnRequest) {
			r.AssertionConsumerServiceURL, r.ProtocolBinding = "", HTTPArtifactBinding
		},
		"protocol binding and endpoint": func(r *AuthnRequest) {
			r.AssertionConsumerServiceURL, r.ProtocolBinding = artifactACS, HTTPArtifactBinding
		},
	} {
		t.Run(name, func(t *testing.T) {
			w, id := serveECP(t, test, func(r *AuthnRequest) {
				r.ID = "id-artifact-binding"

				mutate(r)
			})

			assertECPStatus(t, w, id, StatusResponder, StatusUnsupportedBinding)
			assert.Equal(t, artifacts.Len(), 0)
		})
	}

	// The browser gets the artifact, at the default endpoint, and not the envelope.
	useSession(test)

	w, _ = serveSSOModified(t, test, func(r *AuthnRequest) {
		r.ID = "id-browser"
		r.AssertionConsumerServiceURL, r.ProtocolBinding = "", ""
	})
	assert.True(t, postedArtifact(t, w).Get("SAMLart") != "")
	assert.Equal(t, artifacts.Len(), 1)
}
