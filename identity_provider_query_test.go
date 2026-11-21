package saml

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/golden"
	"authelia.com/provider/saml/internal/xmlrv"
)

const (
	attributeServiceTestURL    = "https://idp.example.com/saml/attributes"
	authnQueryServiceTestURL   = "https://idp.example.com/saml/authn-query"
	assertionIDRequestTestURL  = "https://idp.example.com/saml/assertion-id"
	queryTestAffiliationID     = "https://affiliation.example.com"
	queryTestOtherProviderID   = "https://sp-other.example.com/saml2/metadata"
	queryTestPersistentNameID  = "0f1e2d3c4b5a"
	queryTestSurnameAttribute  = "urn:oid:2.5.4.4"
	queryTestUnknownIssuerID   = "https://unknown.example.com/saml2/metadata"
	queryTestStoredAssertionID = "id-stored"
)

// querySessionProvider is a QuerySessionProvider which records what it was asked.
type querySessionProvider struct {
	mockSessionProvider

	subject     *Session
	subjectErr  error
	sessions    []*Session
	sessionsErr error

	nameIDs          []NameID
	serviceProviders []string
}

func (p *querySessionProvider) GetQuerySubject(r *http.Request, req *IdpQueryRequest, nameID *NameID) (*Session, error) {
	p.record(r, req, nameID)

	return p.subject, p.subjectErr
}

func (p *querySessionProvider) GetAuthnSessions(r *http.Request, req *IdpQueryRequest, nameID *NameID) ([]*Session, error) {
	p.record(r, req, nameID)

	return p.sessions, p.sessionsErr
}

func (p *querySessionProvider) record(r *http.Request, req *IdpQueryRequest, nameID *NameID) {
	if r == nil || req == nil || req.ServiceProviderMetadata == nil {
		panic("the provider must get the HTTP request and the verified service provider")
	}

	p.nameIDs = append(p.nameIDs, *nameID)
	p.serviceProviders = append(p.serviceProviders, req.ServiceProviderMetadata.EntityID)
}

// testAssertionStore is an AssertionStore in memory which records what it was asked.
type testAssertionStore struct {
	assertions map[string]*StoredAssertion
	saved      []string
	gets       []string
	saveErr    error
	getErr     error
}

func (s *testAssertionStore) SaveAssertion(r *http.Request, assertion *StoredAssertion) error {
	if r == nil {
		panic("the store must get the HTTP request")
	}

	if s.saveErr != nil {
		return s.saveErr
	}

	if s.assertions == nil {
		s.assertions = map[string]*StoredAssertion{}
	}

	id := assertion.Assertion.SelectAttrValue("ID", "")
	s.assertions[id] = assertion
	s.saved = append(s.saved, id)

	return nil
}

func (s *testAssertionStore) GetAssertion(_ *http.Request, id string) (*StoredAssertion, error) {
	s.gets = append(s.gets, id)

	if s.getErr != nil {
		return nil, s.getErr
	}

	return s.assertions[id], nil
}

// queryFixture is an identity provider with every service of the assertion query and request protocol, and a
// service provider which signs its requests and has an encryption key.
type queryFixture struct {
	test     *IdentityProviderTest
	provider *querySessionProvider
	store    *testAssertionStore
	log      *bytes.Buffer

	// metadata changes the metadata of the service provider, if it is not nil.
	metadata func(*EntityDescriptor)

	// entities are other entities that the ServiceProviderProvider knows.
	entities map[string]*EntityDescriptor

	// providerErr is returned by the ServiceProviderProvider, if it is not nil.
	providerErr error

	// requests counts the requests that were made, each of which has an ID of its own, as a request with the
	// ID of an earlier one is a replay.
	requests int

	// lastID is the ID of the last of them.
	lastID string
}

// nextID returns an ID for a request that no other request of the fixture has.
func (f *queryFixture) nextID(prefix string) string {
	f.requests++
	f.lastID = prefix + "-" + strconv.Itoa(f.requests)

	return f.lastID
}

func newQueryFixture(t *testing.T) *queryFixture {
	t.Helper()

	f := &queryFixture{
		test:     signatureTestIDP(t),
		provider: &querySessionProvider{},
		store:    &testAssertionStore{},
		log:      &bytes.Buffer{},
		entities: map[string]*EntityDescriptor{},
	}

	f.provider.subject = attributeReleaseSession()
	f.provider.sessions = []*Session{
		{ID: "session-one", Index: "index-one", CreateTime: TimeNow().Add(-time.Hour)},
		{ID: "session-two", Index: "index-two", CreateTime: TimeNow().Add(-time.Minute), AuthnContextClassRef: strongClass, ClientAddress: "192.0.2.7"},
	}

	idp := &f.test.IDP
	idp.AttributeServiceURL = mustParseURL(attributeServiceTestURL)
	idp.AuthnQueryServiceURL = mustParseURL(authnQueryServiceTestURL)
	idp.AssertionIDRequestServiceURL = mustParseURL(assertionIDRequestTestURL)
	idp.SessionProvider = f.provider
	idp.AssertionStore = f.store
	idp.Observer = logObserver(f.log)
	idp.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			if f.providerErr != nil {
				return nil, f.providerErr
			}

			if entity, ok := f.entities[serviceProviderID]; ok {
				return entity, nil
			}

			if serviceProviderID != f.test.SP.MetadataURL.String() {
				return nil, os.ErrNotExist
			}

			metadata := f.test.SP.Metadata()
			if f.metadata != nil {
				f.metadata(metadata)
			}

			return metadata, nil
		},
	}

	return f
}

// requestAttributes makes the metadata of the service provider request attributes with a default
// AttributeConsumingService.
func (f *queryFixture) requestAttributes(attributes ...RequestedAttribute) {
	f.metadata = func(metadata *EntityDescriptor) {
		metadata.SPSSODescriptors[0].AttributeConsumingServices = []AttributeConsumingService{service(1, nil, attributes...)}
	}
}

// subject returns the Subject of a query for the principal, as the identity provider would have named it.
func (f *queryFixture) subject() *Subject {
	return &Subject{NameID: &NameID{
		Format:          string(PersistentNameIDFormat),
		NameQualifier:   f.test.IDP.MetadataURL.String(),
		SPNameQualifier: f.test.SP.MetadataURL.String(),
		Value:           queryTestPersistentNameID,
	}}
}

func (f *queryFixture) issuer() *Issuer {
	return &Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: f.test.SP.MetadataURL.String()}
}

func (f *queryFixture) attributeQuery(attributes ...Attribute) *AttributeQuery {
	return &AttributeQuery{
		ID:           f.nextID("id-attribute-query"),
		Version:      "2.0",
		IssueInstant: TimeNow(),
		Destination:  attributeServiceTestURL,
		Issuer:       f.issuer(),
		Subject:      f.subject(),
		Attributes:   attributes,
	}
}

func (f *queryFixture) authnQuery() *AuthnQuery {
	return &AuthnQuery{
		ID:           f.nextID("id-authn-query"),
		Version:      "2.0",
		IssueInstant: TimeNow(),
		Destination:  authnQueryServiceTestURL,
		Issuer:       f.issuer(),
		Subject:      f.subject(),
	}
}

func (f *queryFixture) assertionIDRequest(ids ...string) *AssertionIDRequest {
	request := &AssertionIDRequest{
		ID:           f.nextID("id-assertion-id-request"),
		Version:      "2.0",
		IssueInstant: TimeNow(),
		Destination:  assertionIDRequestTestURL,
		Issuer:       f.issuer(),
	}

	for _, id := range ids {
		request.AssertionIDRefs = append(request.AssertionIDRefs, AssertionIDRef{Value: id})
	}

	return request
}

// queryService is one of the services of the protocol, for the tests that apply to all of them.
type queryService struct {
	name    string
	url     string
	serve   func(*IdentityProvider) http.HandlerFunc
	message func(*queryFixture) *etree.Element
}

var queryServices = []queryService{
	{
		name:    attributeQueryMessage,
		url:     attributeServiceTestURL,
		serve:   func(idp *IdentityProvider) http.HandlerFunc { return idp.ServeAttributeQuery },
		message: func(f *queryFixture) *etree.Element { return f.attributeQuery().Element() },
	},
	{
		name:    authnQueryMessage,
		url:     authnQueryServiceTestURL,
		serve:   func(idp *IdentityProvider) http.HandlerFunc { return idp.ServeAuthnQuery },
		message: func(f *queryFixture) *etree.Element { return f.authnQuery().Element() },
	},
	{
		name:  assertionIDRequestMessage,
		url:   assertionIDRequestTestURL,
		serve: func(idp *IdentityProvider) http.HandlerFunc { return idp.ServeAssertionIDRequest },
		message: func(f *queryFixture) *etree.Element {
			return f.assertionIDRequest(queryTestStoredAssertionID).Element()
		},
	},
}

// signQueryElement signs el with the key of sp, and puts the signature after the Issuer, where SAMLCore §3.2.1
// has it.
func signQueryElement(t *testing.T, sp *ServiceProvider, el *etree.Element) *etree.Element {
	t.Helper()

	signingContext, err := GetSigningContext(sp)
	require.NoError(t, err)

	signed, err := signingContext.SignEnveloped(el)
	require.NoError(t, err)

	// SignEnveloped appends the signature without making it a child, so it is taken off the same way.
	signature := signed.Child[len(signed.Child)-1]
	signed.Child = signed.Child[:len(signed.Child)-1]

	if issuer := signed.FindElement("./Issuer"); issuer != nil {
		signed.InsertChildAt(issuer.Index()+1, signature)
	} else {
		signed.AddChild(signature)
	}

	return signed
}

// queryPost returns a SOAP POST of message to location.
func queryPost(t *testing.T, location string, message *etree.Element) *http.Request {
	t.Helper()

	r := httptest.NewRequest(http.MethodPost, location, bytes.NewReader(soapLogoutEnvelope(t, message)))
	r.Header.Set("Content-Type", "text/xml; charset=utf-8")

	return r
}

// queryResponse is the parsed answer to a query.
type queryResponse struct {
	Response Response

	// Assertions are the assertions of the response, decrypted, whose signatures have been verified.
	Assertions []*Assertion

	// AssertionEls are the elements of Assertions, as they were signed.
	AssertionEls []*etree.Element

	// Encrypted is how many of them were encrypted.
	Encrypted int
}

// parseQueryResponse parses the SOAP body of a 200 answer, verifying that the identity provider signed the
// Response and every assertion in it.
func parseQueryResponse(t *testing.T, sp *ServiceProvider, code int, header http.Header, body []byte) *queryResponse {
	t.Helper()

	require.Equal(t, code, http.StatusOK, "body: %s", body)
	assert.Equal(t, header.Get("Content-Type"), "text/xml; charset=utf-8")
	assert.Equal(t, header.Get("Cache-Control"), "no-cache, no-store")
	assert.Equal(t, header.Get("Pragma"), "no-cache")

	_, headers, message, err := parseSOAPEnvelope(body)
	require.NoError(t, err)
	assert.Len(t, headers, 0)
	require.Equal(t, message.Tag, "Response")
	require.Equal(t, message.NamespaceURI(), samlProtocolNS)

	certificates := []*x509.Certificate{mustParseCertificate(golden.Get(t, "idp_cert.pem"))}

	verified, err := verifyEnvelopedSignature(message, certificateVerificationKeys(certificates), anySignaturePolicy)
	require.NoError(t, err)

	// SAMLCore §3.2.2: the Issuer, then the Signature, then the Status.
	children := message.ChildElements()
	require.True(t, len(children) >= 3)
	assert.Equal(t, children[0].Tag, "Issuer")
	assert.Equal(t, children[1].Tag, "Signature")
	assert.Equal(t, children[2].Tag, "Status")

	out := &queryResponse{}
	require.NoError(t, unmarshalElement(verified, &out.Response))

	// What the signature covers has no Signature.
	children = verified.ChildElements()
	require.True(t, len(children) >= 2)
	assert.Equal(t, children[1].Tag, "Status")

	for _, child := range children[2:] {
		assertionEl := child

		switch child.Tag {
		case "Assertion":
		case "EncryptedAssertion":
			out.Encrypted++

			assertionEl, err = sp.decryptElement(child)
			require.NoError(t, err)
		default:
			t.Fatalf("unexpected %s in the response", child.Tag)
		}

		require.Equal(t, assertionEl.Tag, "Assertion")

		verifiedAssertion, err := verifyEnvelopedSignature(assertionEl, certificateVerificationKeys(certificates), anySignaturePolicy)
		require.NoError(t, err)

		assertion := &Assertion{}
		require.NoError(t, unmarshalElement(verifiedAssertion, assertion))

		out.Assertions = append(out.Assertions, assertion)
		out.AssertionEls = append(out.AssertionEls, assertionEl)
	}

	return out
}

// serve sends r to the handler of service and returns the recorder.
func (f *queryFixture) serve(service queryService, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	service.serve(&f.test.IDP)(w, r)

	return w
}

// query signs message, sends it to the service, and returns the parsed answer.
func (f *queryFixture) query(t *testing.T, service queryService, message *etree.Element) *queryResponse {
	t.Helper()

	return f.answer(t, f.serve(service, queryPost(t, service.url, signQueryElement(t, &f.test.SP, message))))
}

func (f *queryFixture) answer(t *testing.T, w *httptest.ResponseRecorder) *queryResponse {
	t.Helper()

	return parseQueryResponse(t, &f.test.SP, w.Code, w.Header(), w.Body.Bytes())
}

func (f *queryFixture) queryAttributes(t *testing.T, query *AttributeQuery) *queryResponse {
	t.Helper()

	return f.query(t, queryServices[0], query.Element())
}

func (f *queryFixture) queryAuthn(t *testing.T, query *AuthnQuery) *queryResponse {
	t.Helper()

	return f.query(t, queryServices[1], query.Element())
}

func (f *queryFixture) requestAssertions(t *testing.T, request *AssertionIDRequest) *queryResponse {
	t.Helper()

	return f.query(t, queryServices[2], request.Element())
}

// assertQueryStatus asserts the status codes of the response, that it carries no message, and that it carries
// assertions only with Success.
func assertQueryStatus(t *testing.T, response *queryResponse, top, second string) {
	t.Helper()

	status := response.Response.Status

	assert.Equal(t, status.StatusCode.Value, top)
	assert.True(t, statusSaysNothingOfTheRequest(status), "a StatusMessage is never sent")

	if second == "" {
		assert.Nil(t, status.StatusCode.StatusCode)
	} else {
		require.NotNil(t, status.StatusCode.StatusCode)
		assert.Equal(t, status.StatusCode.StatusCode.Value, second)
	}

	if top != StatusSuccess {
		assert.Len(t, response.Assertions, 0)
	}
}

// assertQueryAssertion asserts what every assertion in answer to a query has in common (SAMLCore §3.3.4).
func (f *queryFixture) assertQueryAssertion(t *testing.T, assertion *Assertion, subject *Subject) {
	t.Helper()

	assert.Equal(t, assertion.Version, "2.0")
	assert.Equal(t, assertion.Issuer.Value, f.test.IDP.MetadataURL.String())
	require.True(t, assertion.Subject != nil && assertion.Subject.NameID != nil)
	assert.Equal(t, *assertion.Subject.NameID, *subject.NameID)
	assert.Len(t, assertion.Subject.SubjectConfirmations, 0)
	require.NotNil(t, assertion.Conditions)
	assert.True(t, assertion.Conditions.NotBefore.Equal(TimeNow().Add(-MaxClockSkew)))
	assert.True(t, assertion.Conditions.NotOnOrAfter.Equal(TimeNow().Add(MaxIssueDelay)))
	require.Len(t, assertion.Conditions.AudienceRestrictions, 1)
	assert.Equal(t, assertion.Conditions.AudienceRestrictions[0].Audiences, []Audience{{Value: f.test.SP.MetadataURL.String()}})
}

func queryAttributeValues(attribute Attribute) []string {
	values := make([]string, 0, len(attribute.Values))
	for _, value := range attribute.Values {
		values = append(values, value.Value)
	}

	return values
}

func TestServeQueryRejects(t *testing.T) {
	mutated := func(mutate func(*queryFixture, *etree.Element)) func(*testing.T, *queryFixture, queryService) *http.Request {
		return func(t *testing.T, f *queryFixture, service queryService) *http.Request {
			message := service.message(f)
			mutate(f, message)

			return queryPost(t, service.url, signQueryElement(t, &f.test.SP, message))
		}
	}

	testCases := []struct {
		name           string
		request        func(*testing.T, *queryFixture, queryService) *http.Request
		top, second    string
		noInResponseTo bool
	}{
		{
			name: "unsigned",
			request: func(t *testing.T, f *queryFixture, service queryService) *http.Request {
				return queryPost(t, service.url, service.message(f))
			},
			top: StatusRequester, second: StatusRequestDenied,
		},
		{
			name: "signed by another key",
			request: func(t *testing.T, f *queryFixture, service queryService) *http.Request {
				other := f.test.SP
				other.Key, other.Certificate = propagationServiceProviderKey(t)

				return queryPost(t, service.url, signQueryElement(t, &other, service.message(f)))
			},
			top: StatusRequester, second: StatusRequestDenied,
		},
		{
			name: "signature over altered content",
			request: func(t *testing.T, f *queryFixture, service queryService) *http.Request {
				signed := signQueryElement(t, &f.test.SP, service.message(f))
				signed.CreateAttr("Consent", "urn:oasis:names:tc:SAML:2.0:consent:obtained")

				return queryPost(t, service.url, signed)
			},
			top: StatusRequester, second: StatusRequestDenied,
		},
		{
			name: "unknown service provider",
			request: mutated(func(_ *queryFixture, message *etree.Element) {
				message.FindElement("./Issuer").SetText(queryTestUnknownIssuerID)
			}),
			top: StatusRequester, second: StatusRequestDenied,
		},
		{
			name: "service provider lookup fails",
			request: func(t *testing.T, f *queryFixture, service queryService) *http.Request {
				f.providerErr = errors.New("storage unavailable")

				return queryPost(t, service.url, signQueryElement(t, &f.test.SP, service.message(f)))
			},
			top: StatusResponder,
		},
		{
			name: "no issuer",
			request: mutated(func(_ *queryFixture, message *etree.Element) {
				message.RemoveChild(message.FindElement("./Issuer"))
			}),
			top: StatusRequester, second: StatusRequestDenied,
		},
		{
			name: "invalid ID",
			request: mutated(func(_ *queryFixture, message *etree.Element) {
				message.CreateAttr("ID", "1 not an NCName")
			}),
			top: StatusRequester, second: StatusRequestDenied, noInResponseTo: true,
		},
		{
			name: "another destination",
			request: mutated(func(_ *queryFixture, message *etree.Element) {
				message.CreateAttr("Destination", "https://idp.example.com/saml/sso")
			}),
			top: StatusRequester, second: StatusRequestDenied,
		},
		{
			name: "version too low",
			request: mutated(func(_ *queryFixture, message *etree.Element) {
				message.CreateAttr("Version", "1.1")
			}),
			top: StatusVersionMismatch, second: StatusRequestVersionTooLow,
		},
		{
			name: "version too high",
			request: mutated(func(_ *queryFixture, message *etree.Element) {
				message.CreateAttr("Version", "3.0")
			}),
			top: StatusVersionMismatch, second: StatusRequestVersionTooHigh,
		},
		{
			name: "expired",
			request: mutated(func(_ *queryFixture, message *etree.Element) {
				message.CreateAttr("IssueInstant", TimeNow().Add(-MaxIssueDelay-MaxClockSkew).Format(timeFormat))
			}),
			top: StatusRequester, second: StatusRequestDenied,
		},
		{
			name: "issued in the future",
			request: mutated(func(_ *queryFixture, message *etree.Element) {
				message.CreateAttr("IssueInstant", TimeNow().Add(MaxClockSkew+time.Second).Format(timeFormat))
			}),
			top: StatusRequester, second: StatusRequestDenied,
		},
		{
			name: "another message",
			request: func(t *testing.T, f *queryFixture, service queryService) *http.Request {
				request, err := f.test.SP.MakeLogoutRequest(service.url, "alice")
				require.NoError(t, err)

				el := request.Element()
				el.CreateAttr("ID", service.message(f).SelectAttrValue("ID", ""))

				return queryPost(t, service.url, el)
			},
			top: StatusRequester, second: StatusRequestUnsupported,
		},
	}

	for _, service := range queryServices {
		for _, tc := range testCases {
			t.Run(service.name+"/"+tc.name, func(t *testing.T) {
				f := newQueryFixture(t)
				f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))
				f.store.assertions = map[string]*StoredAssertion{
					queryTestStoredAssertionID: {ServiceProvider: f.test.SP.MetadataURL.String(), Assertion: etree.NewElement("saml:Assertion")},
				}

				response := f.answer(t, f.serve(service, tc.request(t, f, service)))
				id := f.lastID

				assertQueryStatus(t, response, tc.top, tc.second)
				assert.Equal(t, response.Response.Destination, "")
				require.NotNil(t, response.Response.Issuer)
				assert.Equal(t, response.Response.Issuer.Value, f.test.IDP.MetadataURL.String())

				if tc.noInResponseTo {
					assert.Equal(t, response.Response.InResponseTo, "")
				} else {
					assert.Equal(t, response.Response.InResponseTo, id)
				}

				assert.Len(t, f.provider.nameIDs, 0, "the session provider must not be asked")
				assert.Len(t, f.store.gets, 0, "the assertion store must not be asked")
				assert.Len(t, f.store.saved, 0)
			})
		}
	}
}

func TestServeQuerySOAPErrors(t *testing.T) {
	for _, service := range queryServices {
		t.Run(service.name+"/not a POST", func(t *testing.T) {
			f := newQueryFixture(t)

			w := f.serve(service, httptest.NewRequest(http.MethodGet, service.url, nil))
			assert.Equal(t, w.Code, http.StatusMethodNotAllowed)
			assert.Equal(t, w.Header().Get("Allow"), http.MethodPost)
		})

		t.Run(service.name+"/not text/xml", func(t *testing.T) {
			f := newQueryFixture(t)

			r := queryPost(t, service.url, signQueryElement(t, &f.test.SP, service.message(f)))
			r.Header.Set("Content-Type", "application/soap+xml")

			assert.Equal(t, soapFaultCode(t, f.serve(service, r)), "soapenv:Client")
		})

		t.Run(service.name+"/not an envelope", func(t *testing.T) {
			f := newQueryFixture(t)

			doc := etree.NewDocument()
			doc.SetRoot(signQueryElement(t, &f.test.SP, service.message(f)))
			body, err := doc.WriteToBytes()
			require.NoError(t, err)

			r := httptest.NewRequest(http.MethodPost, service.url, bytes.NewReader(body))
			r.Header.Set("Content-Type", "text/xml")

			assert.Equal(t, soapFaultCode(t, f.serve(service, r)), "soapenv:Client")
		})

		t.Run(service.name+"/too large", func(t *testing.T) {
			f := newQueryFixture(t)

			message := service.message(f)
			message.CreateAttr("Consent", strings.Repeat("a", soapMaxMessageSize))

			r := queryPost(t, service.url, signQueryElement(t, &f.test.SP, message))

			assert.Equal(t, soapFaultCode(t, f.serve(service, r)), "soapenv:Client")
		})

		t.Run(service.name+"/header that must be understood", func(t *testing.T) {
			f := newQueryFixture(t)

			doc, envelope := newSOAPEnvelope()
			header := envelope.CreateElement("soapenv:Header").CreateElement("x:Unknown")
			header.CreateAttr("xmlns:x", "urn:example:unknown")
			header.CreateAttr("soapenv:mustUnderstand", "1")
			envelope.CreateElement("soapenv:Body").AddChild(signQueryElement(t, &f.test.SP, service.message(f)))

			body, err := doc.WriteToBytes()
			require.NoError(t, err)

			r := httptest.NewRequest(http.MethodPost, service.url, bytes.NewReader(body))
			r.Header.Set("Content-Type", "text/xml")

			assert.Equal(t, soapFaultCode(t, f.serve(service, r)), "soapenv:MustUnderstand")
		})

		t.Run(service.name+"/cannot sign the response", func(t *testing.T) {
			f := newQueryFixture(t)
			f.test.IDP.Key, f.test.IDP.Signer = nil, nil

			r := queryPost(t, service.url, service.message(f))

			assert.Equal(t, soapFaultCode(t, f.serve(service, r)), "soapenv:Server")
		})
	}
}

// Nothing of a request is logged before its signature is verified.
func TestServeQueryLogsNoUnverifiedContent(t *testing.T) {
	const marker = "SECRET-MARKER"

	for _, service := range queryServices {
		t.Run(service.name, func(t *testing.T) {
			f := newQueryFixture(t)

			message := service.message(f)
			message.CreateAttr("ID", "id-"+marker)
			message.FindElement("./Issuer").SetText("https://" + marker + ".example.com")

			for _, el := range message.FindElements(".//NameID") {
				el.SetText(marker)
			}

			for _, el := range message.FindElements(".//AssertionIDRef") {
				el.SetText(marker)
			}

			observer := &RecordingObserver{}
			f.test.IDP.Observer = observer

			response := f.answer(t, f.serve(service, queryPost(t, service.url, message)))
			assertQueryStatus(t, response, StatusRequester, StatusRequestDenied)

			// The Issuer and the ID of a request that is not verified are only reported as what they are: the
			// service provider of an event that is not verified, and the ID of its request. Nothing else of the
			// request is reported, and none of it is in the text of the error.
			events := observer.Events()
			require.Len(t, events, 1)

			event := events[0]
			assert.Equal(t, event.Outcome, OutcomeFailure)
			assert.False(t, event.Verified)
			assert.Equal(t, event.ServiceProvider, "https://"+marker+".example.com")
			assert.Equal(t, event.RequestID, "id-"+marker)
			assert.True(t, errors.Is(event.Err, ErrUnknownServiceProvider))

			event.ServiceProvider, event.RequestID = "", ""
			assert.False(t, strings.Contains(fmt.Sprintf("%+v", event), marker), "event: %+v", event)
		})
	}
}

func TestServeQueryDestinationOptional(t *testing.T) {
	for _, service := range queryServices {
		t.Run(service.name, func(t *testing.T) {
			f := newQueryFixture(t)

			message := service.message(f)
			message.RemoveAttr("Destination")

			response := f.query(t, service, message)
			assertQueryStatus(t, response, StatusSuccess, "")
			assert.Equal(t, response.Response.InResponseTo, message.SelectAttrValue("ID", ""))
		})
	}
}

func TestServeAttributeQuery(t *testing.T) {
	f := newQueryFixture(t)
	f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat), requested(uidAttributeName, uriAttrNameFormat))

	query := f.attributeQuery()

	response := f.queryAttributes(t, query)
	assertQueryStatus(t, response, StatusSuccess, "")
	assert.Equal(t, response.Response.InResponseTo, query.ID)
	assert.Equal(t, response.Response.Destination, "")
	assert.Equal(t, response.Response.Version, "2.0")
	require.NotNil(t, response.Response.Issuer)
	assert.Equal(t, response.Response.Issuer.Value, f.test.IDP.MetadataURL.String())
	assert.Equal(t, response.Response.Issuer.Format, "urn:oasis:names:tc:SAML:2.0:nameid-format:entity")

	require.Len(t, response.Assertions, 1)
	assert.Equal(t, response.Encrypted, 1, "the service provider has an encryption key")

	assertion := response.Assertions[0]
	f.assertQueryAssertion(t, assertion, query.Subject)
	assert.Len(t, assertion.AuthnStatements, 0)
	require.Len(t, assertion.AttributeStatements, 1)
	assert.Equal(t, attributeNames(assertion.AttributeStatements[0].Attributes), []string{uidAttributeName, mailAttributeName})

	// The provider is asked about the NameID of the query, for the service provider that signed it.
	assert.Equal(t, f.provider.nameIDs, []NameID{*query.Subject.NameID})
	assert.Equal(t, f.provider.serviceProviders, []string{f.test.SP.MetadataURL.String()})

	// The assertion is saved as it was signed, before it was encrypted.
	require.Equal(t, f.store.saved, []string{assertion.ID})

	saved := f.store.assertions[assertion.ID]
	assert.Equal(t, saved.ServiceProvider, f.test.SP.MetadataURL.String())
	assert.True(t, saved.NotOnOrAfter.Equal(assertion.Conditions.NotOnOrAfter))
	assert.Equal(t, saved.Assertion.Tag, "Assertion")
	assert.True(t, saved.Encrypted, "it was sent encrypted")

	_, err := verifyEnvelopedSignature(saved.Assertion, certificateVerificationKeys([]*x509.Certificate{f.test.Certificate}), anySignaturePolicy)
	assert.NoError(t, err)
}

func TestServeAttributeQueryNarrows(t *testing.T) {
	everything := []RequestedAttribute{
		requested(mailAttributeName, uriAttrNameFormat),
		requested(uidAttributeName, uriAttrNameFormat),
		requested(affiliationAttributeName, uriAttrNameFormat),
	}

	testCases := []struct {
		name     string
		ceiling  []RequestedAttribute
		query    []Attribute
		released map[string][]string
	}{
		{
			name:     "no attributes named asks for all that are allowed",
			ceiling:  everything,
			released: map[string][]string{uidAttributeName: {"alice"}, mailAttributeName: {"alice@example.com"}, affiliationAttributeName: {"Users", "Administrators"}},
		},
		{
			name:     "by name",
			ceiling:  everything,
			query:    []Attribute{{Name: mailAttributeName, NameFormat: uriAttrNameFormat}},
			released: map[string][]string{mailAttributeName: {"alice@example.com"}},
		},
		{
			name:     "a missing name format is unspecified, which matches any",
			ceiling:  everything,
			query:    []Attribute{{Name: mailAttributeName}},
			released: map[string][]string{mailAttributeName: {"alice@example.com"}},
		},
		{
			name:    "another name format",
			ceiling: everything,
			query:   []Attribute{{Name: mailAttributeName, NameFormat: basicAttrNameFormat}},
		},
		{
			name:    "the friendly name does not name an attribute",
			ceiling: everything,
			query:   []Attribute{{Name: "mail", FriendlyName: "mail"}},
		},
		{
			name:     "by value",
			ceiling:  everything,
			query:    []Attribute{{Name: affiliationAttributeName, NameFormat: uriAttrNameFormat, Values: []AttributeValue{{Type: "xs:string", Value: "Administrators"}, {Type: "xs:string", Value: "Auditors"}}}},
			released: map[string][]string{affiliationAttributeName: {"Administrators"}},
		},
		{
			name:    "by a value the principal does not have",
			ceiling: everything,
			query:   []Attribute{{Name: affiliationAttributeName, NameFormat: uriAttrNameFormat, Values: []AttributeValue{{Type: "xs:string", Value: "Auditors"}}}},
		},
		{
			name:    "an attribute that single sign-on would not state",
			ceiling: []RequestedAttribute{requested(mailAttributeName, uriAttrNameFormat)},
			query:   []Attribute{{Name: queryTestSurnameAttribute, NameFormat: uriAttrNameFormat}},
		},
		{
			name:     "only the part that single sign-on would state",
			ceiling:  []RequestedAttribute{requested(mailAttributeName, uriAttrNameFormat), requested(affiliationAttributeName, uriAttrNameFormat, "Users")},
			query:    []Attribute{{Name: affiliationAttributeName, NameFormat: uriAttrNameFormat}, {Name: queryTestSurnameAttribute, NameFormat: uriAttrNameFormat}},
			released: map[string][]string{affiliationAttributeName: {"Users"}},
		},
		{
			name:    "a value that single sign-on would not state",
			ceiling: []RequestedAttribute{requested(affiliationAttributeName, uriAttrNameFormat, "Users")},
			query:   []Attribute{{Name: affiliationAttributeName, NameFormat: uriAttrNameFormat, Values: []AttributeValue{{Type: "xs:string", Value: "Administrators"}}}},
		},
		{
			name:     "an attribute under the name the service provider chose",
			ceiling:  []RequestedAttribute{requested("email", basicAttrNameFormat)},
			query:    []Attribute{{Name: "email", NameFormat: basicAttrNameFormat}},
			released: map[string][]string{"email": {"alice@example.com"}},
		},
		{
			name: "nothing without an AttributeConsumingService",
		},
		{
			name:  "nothing named without an AttributeConsumingService",
			query: []Attribute{{Name: mailAttributeName, NameFormat: uriAttrNameFormat}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newQueryFixture(t)

			if tc.ceiling != nil {
				f.requestAttributes(tc.ceiling...)
			}

			response := f.queryAttributes(t, f.attributeQuery(tc.query...))
			assertQueryStatus(t, response, StatusSuccess, "")

			// SAMLCore §3.3.4: Success with no assertion when there is nothing to state.
			if len(tc.released) == 0 {
				assert.Len(t, response.Assertions, 0)
				assert.Len(t, f.store.saved, 0)

				return
			}

			require.Len(t, response.Assertions, 1)
			require.Len(t, response.Assertions[0].AttributeStatements, 1)

			released := map[string][]string{}
			for _, attribute := range response.Assertions[0].AttributeStatements[0].Attributes {
				released[attribute.Name] = queryAttributeValues(attribute)
			}

			assert.Equal(t, released, tc.released)
		})
	}
}

// The default AttributeConsumingService is the ceiling, as for single sign-on without an index.
func TestServeAttributeQueryUsesDefaultAttributeConsumingService(t *testing.T) {
	yes := true

	f := newQueryFixture(t)
	f.metadata = func(metadata *EntityDescriptor) {
		metadata.SPSSODescriptors[0].AttributeConsumingServices = []AttributeConsumingService{
			service(1, nil, requested(mailAttributeName, uriAttrNameFormat)),
			service(2, &yes, requested(uidAttributeName, uriAttrNameFormat)),
		}
	}

	response := f.queryAttributes(t, f.attributeQuery())
	assertQueryStatus(t, response, StatusSuccess, "")
	require.Len(t, response.Assertions, 1)
	assert.Equal(t, attributeNames(response.Assertions[0].AttributeStatements[0].Attributes), []string{uidAttributeName})
}

func TestServeAttributeQueryAttributeReleasePolicy(t *testing.T) {
	queried := Attribute{Name: affiliationAttributeName, NameFormat: uriAttrNameFormat, Values: []AttributeValue{{Type: "xs:string", Value: "Users"}}}

	t.Run("gets the query, its attributes and the ceiling", func(t *testing.T) {
		f := newQueryFixture(t)
		f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))

		var (
			got        AttributeReleaseRequest
			candidates []Attribute
		)

		f.test.IDP.AttributeReleasePolicy = attributeReleasePolicyFunc(func(req AttributeReleaseRequest, session *Session, c []Attribute) ([]Attribute, error) {
			got, candidates = req, c

			assert.True(t, session == f.provider.subject)

			return c, nil
		})

		response := f.queryAttributes(t, f.attributeQuery(queried))
		assertQueryStatus(t, response, StatusSuccess, "")

		require.True(t, got.Query != nil && got.Query.AttributeQuery != nil)
		assert.Nil(t, got.AuthnRequest)
		assert.NotNil(t, got.HTTPRequest)
		assert.Equal(t, got.ServiceProviderMetadata.EntityID, f.test.SP.MetadataURL.String())
		require.NotNil(t, got.Ceiling)
		assert.Equal(t, got.Ceiling.RequestedAttributes[0].Name, mailAttributeName)
		require.Len(t, got.Requested, 1)
		assert.Equal(t, got.Requested[0].Name, affiliationAttributeName)

		// The candidates are not narrowed to the query, so that the policy decides as for single sign-on. This
		// policy releases beyond the ceiling, and the answer is narrowed to the query.
		assert.Contains(t, attributeNames(candidates), mailAttributeName)
		assert.Contains(t, attributeNames(candidates), SubjectIDAttributeName)
		assert.Equal(t, queryAttributeValues(*attributeNamed(candidates, affiliationAttributeName)), []string{"Users", "Administrators"})
		require.Len(t, response.Assertions, 1)
		assert.Equal(t, queryAttributeValues(response.Assertions[0].AttributeStatements[0].Attributes[0]), []string{"Users"})
	})

	t.Run("cannot release what the query does not name", func(t *testing.T) {
		f := newQueryFixture(t)
		f.test.IDP.AttributeReleasePolicy = attributeReleasePolicyFunc(func(AttributeReleaseRequest, *Session, []Attribute) ([]Attribute, error) {
			return []Attribute{
				{Name: mailAttributeName, NameFormat: uriAttrNameFormat, Values: []AttributeValue{{Type: "xs:string", Value: "alice@example.com"}}},
				{Name: affiliationAttributeName, NameFormat: uriAttrNameFormat, Values: []AttributeValue{{Type: "xs:string", Value: "Users"}, {Type: "xs:string", Value: "Administrators"}}},
			}, nil
		})

		response := f.queryAttributes(t, f.attributeQuery(queried))
		assertQueryStatus(t, response, StatusSuccess, "")
		require.Len(t, response.Assertions, 1)

		attributes := response.Assertions[0].AttributeStatements[0].Attributes
		require.Len(t, attributes, 1)
		assert.Equal(t, attributes[0].Name, affiliationAttributeName)
		assert.Equal(t, queryAttributeValues(attributes[0]), []string{"Users"})
	})

	t.Run("refuses", func(t *testing.T) {
		f := newQueryFixture(t)
		f.test.IDP.AttributeReleasePolicy = attributeReleasePolicyFunc(func(AttributeReleaseRequest, *Session, []Attribute) ([]Attribute, error) {
			return nil, errors.New("policy store unavailable")
		})

		assertQueryStatus(t, f.queryAttributes(t, f.attributeQuery()), StatusResponder, "")
	})
}

func TestServeAttributeQueryPrincipal(t *testing.T) {
	t.Run("unknown", func(t *testing.T) {
		f := newQueryFixture(t)
		f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))
		f.provider.subject = nil

		// SAMLCore §3.3.4: there is nothing to state, so the answer is a Success with no assertion, which is also
		// what an AuthnQuery for an unknown principal gets, and doesn't tell which principals exist.
		response := f.queryAttributes(t, f.attributeQuery())
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Len(t, response.Assertions, 0)
		assert.Equal(t, response.Encrypted, 0)
	})

	t.Run("lookup fails", func(t *testing.T) {
		f := newQueryFixture(t)
		f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))
		f.provider.subjectErr = errors.New("directory unavailable")

		response := f.queryAttributes(t, f.attributeQuery())
		assertQueryStatus(t, response, StatusResponder, "")
		assert.Contains(t, f.log.String(), "directory unavailable")
	})

	t.Run("no QuerySessionProvider", func(t *testing.T) {
		f := newQueryFixture(t)
		f.test.IDP.SessionProvider = &f.provider.mockSessionProvider

		assertQueryStatus(t, f.queryAttributes(t, f.attributeQuery()), StatusResponder, StatusRequestUnsupported)
	})
}

// querySubjectCase is a Subject that a query is refused for, or accepted with.
type querySubjectCase struct {
	name        string
	setup       func(*queryFixture)
	mutate      func(*queryFixture, *etree.Element)
	top, second string
}

var querySubjectCases = []querySubjectCase{
	{
		name: "no subject",
		mutate: func(_ *queryFixture, message *etree.Element) {
			message.RemoveChild(message.FindElement("./Subject"))
		},
		top: StatusRequester,
	},
	{
		name: "EncryptedID beside a NameID",
		mutate: func(_ *queryFixture, message *etree.Element) {
			message.FindElement("./Subject").CreateElement("saml:EncryptedID")
		},
		top: StatusRequester, second: StatusRequestDenied,
	},
	{
		name: "two NameIDs",
		mutate: func(_ *queryFixture, message *etree.Element) {
			subject := message.FindElement("./Subject")
			subject.InsertChildAt(0, subject.FindElement("./NameID").Copy())
		},
		top: StatusRequester, second: StatusRequestDenied,
	},
	{
		name: "BaseID",
		mutate: func(_ *queryFixture, message *etree.Element) {
			subject := message.FindElement("./Subject")
			subject.RemoveChild(subject.FindElement("./NameID"))
			subject.CreateElement("saml:BaseID")
		},
		top: StatusRequester, second: StatusRequestUnsupported,
	},
	{
		name: "SubjectConfirmation",
		mutate: func(_ *queryFixture, message *etree.Element) {
			message.FindElement("./Subject").CreateElement("saml:SubjectConfirmation").CreateAttr("Method", bearerSubjectConfirmationMethod)
		},
		top: StatusRequester, second: StatusRequestUnsupported,
	},
	{
		name: "no identifier",
		mutate: func(_ *queryFixture, message *etree.Element) {
			subject := message.FindElement("./Subject")
			subject.RemoveChild(subject.FindElement("./NameID"))
		},
		top: StatusRequester, second: StatusUnknownPrincipal,
	},
	{
		name: "empty NameID",
		mutate: func(_ *queryFixture, message *etree.Element) {
			message.FindElement("./Subject/NameID").SetText("")
		},
		top: StatusRequester, second: StatusUnknownPrincipal,
	},
	{
		name: "SPNameQualifier of another service provider",
		mutate: func(_ *queryFixture, message *etree.Element) {
			message.FindElement("./Subject/NameID").CreateAttr("SPNameQualifier", queryTestOtherProviderID)
		},
		top: StatusRequester, second: StatusRequestDenied,
	},
	{
		name: "SPNameQualifier of an affiliation of other service providers",
		setup: func(f *queryFixture) {
			f.entities[queryTestAffiliationID] = &EntityDescriptor{
				EntityID:              queryTestAffiliationID,
				AffiliationDescriptor: &AffiliationDescriptor{AffiliationOwnerID: queryTestOtherProviderID, AffiliateMembers: []string{queryTestOtherProviderID}},
			}
		},
		mutate: func(_ *queryFixture, message *etree.Element) {
			message.FindElement("./Subject/NameID").CreateAttr("SPNameQualifier", queryTestAffiliationID)
		},
		top: StatusRequester, second: StatusRequestDenied,
	},
	{
		name: "SPNameQualifier of an affiliation of the service provider",
		setup: func(f *queryFixture) {
			f.entities[queryTestAffiliationID] = &EntityDescriptor{
				EntityID: queryTestAffiliationID,
				AffiliationDescriptor: &AffiliationDescriptor{
					AffiliationOwnerID: queryTestOtherProviderID,
					AffiliateMembers:   []string{queryTestOtherProviderID, f.test.SP.MetadataURL.String()},
				},
			}
		},
		mutate: func(_ *queryFixture, message *etree.Element) {
			message.FindElement("./Subject/NameID").CreateAttr("SPNameQualifier", queryTestAffiliationID)
		},
		top: StatusSuccess,
	},
	{
		name: "no SPNameQualifier",
		mutate: func(_ *queryFixture, message *etree.Element) {
			nameID := message.FindElement("./Subject/NameID")
			nameID.RemoveAttr("SPNameQualifier")
			nameID.RemoveAttr("NameQualifier")
			nameID.CreateAttr("Format", string(EmailAddressNameIDFormat))
			nameID.SetText("alice@example.com")
		},
		top: StatusSuccess,
	},
}

func TestServeQuerySubject(t *testing.T) {
	for _, service := range queryServices[:2] {
		for _, tc := range querySubjectCases {
			t.Run(service.name+"/"+tc.name, func(t *testing.T) {
				f := newQueryFixture(t)
				f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))

				if tc.setup != nil {
					tc.setup(f)
				}

				message := service.message(f)
				tc.mutate(f, message)

				response := f.query(t, service, message)
				assertQueryStatus(t, response, tc.top, tc.second)

				if tc.top != StatusSuccess {
					assert.Len(t, f.provider.nameIDs, 0, "the session provider must not be asked")

					return
				}

				// SAMLCore §3.3.4: the identifier of the assertion is identical to that of the query.
				queried := &Subject{}
				require.NoError(t, unmarshalElement(message.FindElement("./Subject"), queried))

				require.Len(t, response.Assertions, 1)
				f.assertQueryAssertion(t, response.Assertions[0], queried)
				assert.Equal(t, f.provider.nameIDs, []NameID{*queried.NameID})
			})
		}
	}
}

func TestServeQueryAffiliationLookupFails(t *testing.T) {
	f := newQueryFixture(t)

	lookup := f.test.IDP.ServiceProviderProvider

	f.test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(r *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			if serviceProviderID == queryTestAffiliationID {
				return nil, errors.New("storage unavailable")
			}

			return lookup.GetServiceProvider(r, serviceProviderID)
		},
	}

	query := f.attributeQuery()
	query.Subject.NameID.SPNameQualifier = queryTestAffiliationID

	assertQueryStatus(t, f.queryAttributes(t, query), StatusResponder, "")
	assert.Len(t, f.provider.nameIDs, 0)
}

func TestServeAttributeQueryInvalidAttributes(t *testing.T) {
	for name, attributes := range map[string][]Attribute{
		"no name":     {{NameFormat: uriAttrNameFormat}},
		"named twice": {{Name: mailAttributeName, NameFormat: uriAttrNameFormat}, {Name: mailAttributeName, NameFormat: uriAttrNameFormat}},
		"twice, where a missing format is unspecified": {{Name: mailAttributeName}, {Name: mailAttributeName, NameFormat: unspecifiedAttrNameFormat}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newQueryFixture(t)
			f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))

			assertQueryStatus(t, f.queryAttributes(t, f.attributeQuery(attributes...)), StatusRequester, StatusInvalidAttrNameOrValue)
			assert.Len(t, f.provider.nameIDs, 0)
		})
	}

	t.Run("the same name in two formats is two attributes", func(t *testing.T) {
		f := newQueryFixture(t)
		f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))

		response := f.queryAttributes(t, f.attributeQuery(
			Attribute{Name: mailAttributeName, NameFormat: uriAttrNameFormat},
			Attribute{Name: mailAttributeName, NameFormat: basicAttrNameFormat},
		))
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Len(t, response.Assertions, 1)
	})
}

func TestServeQueryEncryption(t *testing.T) {
	t.Run("signed and not encrypted without an encryption key", func(t *testing.T) {
		f := newQueryFixture(t)
		f.metadata = func(metadata *EntityDescriptor) {
			descriptor := &metadata.SPSSODescriptors[0]
			descriptor.AttributeConsumingServices = []AttributeConsumingService{service(1, nil, requested(mailAttributeName, uriAttrNameFormat))}

			signing := descriptor.KeyDescriptors[:0]
			for _, keyDescriptor := range descriptor.KeyDescriptors {
				if keyDescriptor.Use == "signing" {
					signing = append(signing, keyDescriptor)
				}
			}

			descriptor.KeyDescriptors = signing
		}

		response := f.queryAttributes(t, f.attributeQuery())
		assertQueryStatus(t, response, StatusSuccess, "")
		require.Len(t, response.Assertions, 1)
		assert.Equal(t, response.Encrypted, 0)
	})

	t.Run("never in plaintext when the encryption certificate is refused", func(t *testing.T) {
		for _, service := range queryServices {
			t.Run(service.name, func(t *testing.T) {
				f := newQueryFixture(t)
				f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))
				f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())

				// The certificate of the fixture expired before the mocked time, which the default refuses.
				f.test.IDP.EncryptionKeyEnforcer = nil

				response := f.query(t, service, service.message(f))
				assertQueryStatus(t, response, StatusResponder, "")
			})
		}
	})

	t.Run("the enforcer gets the service provider", func(t *testing.T) {
		f := newQueryFixture(t)
		f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))

		var entityID string

		f.test.IDP.EncryptionKeyEnforcer = encryptionKeyEnforcerFunc(func(req *IdpAuthnRequest, key ServiceProviderEncryptionKey) error {
			entityID = req.ServiceProviderMetadata.EntityID

			assert.NotNil(t, req.HTTPRequest)
			assert.True(t, req.Now.Equal(TimeNow()))
			assert.True(t, key.Certificate.Equal(f.test.SPCertificate))

			return nil
		})

		assertQueryStatus(t, f.queryAttributes(t, f.attributeQuery()), StatusSuccess, "")
		assert.Equal(t, entityID, f.test.SP.MetadataURL.String())
	})
}

func TestServeAuthnQuery(t *testing.T) {
	f := newQueryFixture(t)

	query := f.authnQuery()

	response := f.queryAuthn(t, query)
	assertQueryStatus(t, response, StatusSuccess, "")
	assert.Equal(t, response.Response.InResponseTo, query.ID)
	assert.Equal(t, response.Response.Destination, "")
	require.Len(t, response.Assertions, 1)
	assert.Equal(t, response.Encrypted, 1)

	assertion := response.Assertions[0]
	f.assertQueryAssertion(t, assertion, query.Subject)
	assert.Len(t, assertion.AttributeStatements, 0)
	require.Len(t, assertion.AuthnStatements, 2)

	one, two := assertion.AuthnStatements[0], assertion.AuthnStatements[1]
	assert.Equal(t, one.SessionIndex, "index-one")
	assert.True(t, one.AuthnInstant.Equal(TimeNow().Add(-time.Hour)))
	require.NotNil(t, one.AuthnContext.AuthnContextClassRef)
	assert.Equal(t, one.AuthnContext.AuthnContextClassRef.Value, transportClass)
	assert.True(t, one.SubjectLocality == nil, "the address of the service provider is not that of the principal")

	assert.Equal(t, two.SessionIndex, "index-two")
	assert.True(t, two.AuthnInstant.Equal(TimeNow().Add(-time.Minute)))
	require.NotNil(t, two.AuthnContext.AuthnContextClassRef)
	assert.Equal(t, two.AuthnContext.AuthnContextClassRef.Value, strongClass)
	require.NotNil(t, two.SubjectLocality)
	assert.Equal(t, two.SubjectLocality.Address, "192.0.2.7")

	assert.Equal(t, f.provider.nameIDs, []NameID{*query.Subject.NameID})
	assert.Equal(t, f.provider.serviceProviders, []string{f.test.SP.MetadataURL.String()})
	assert.Equal(t, f.store.saved, []string{assertion.ID})
}

func TestServeAuthnQueryFilters(t *testing.T) {
	ranked := DefaultAuthnContextEnforcer{Strength: map[string]int{weakClass: 1, transportClass: 2, strongClass: 3}}

	testCases := []struct {
		name         string
		sessionIndex string
		requested    *RequestedAuthnContext
		enforcer     AuthnContextEnforcer
		indexes      []string
	}{
		{name: "session index", sessionIndex: "index-two", indexes: []string{"index-two"}},
		{name: "unknown session index", sessionIndex: "index-three"},
		{name: "exact class", requested: &RequestedAuthnContext{AuthnContextClassRefs: []string{strongClass}}, indexes: []string{"index-two"}},
		{name: "the default class", requested: &RequestedAuthnContext{AuthnContextClassRefs: []string{transportClass}}, indexes: []string{"index-one"}},
		{name: "either class, in any order", requested: &RequestedAuthnContext{AuthnContextClassRefs: []string{strongClass, transportClass}}, indexes: []string{"index-one", "index-two"}},
		{name: "no session of the class", requested: &RequestedAuthnContext{AuthnContextClassRefs: []string{weakClass}}},
		{name: "declaration", requested: &RequestedAuthnContext{AuthnContextDeclRefs: []string{testDeclRef}}},
		{
			name:      "minimum with the configured enforcer",
			requested: &RequestedAuthnContext{Comparison: AuthnContextComparisonMinimum, AuthnContextClassRefs: []string{weakClass}},
			enforcer:  ranked,
			indexes:   []string{"index-one", "index-two"},
		},
		{
			name:      "better with the configured enforcer",
			requested: &RequestedAuthnContext{Comparison: AuthnContextComparisonBetter, AuthnContextClassRefs: []string{transportClass}},
			enforcer:  ranked,
			indexes:   []string{"index-two"},
		},
		{
			name:         "session index and class of different sessions",
			sessionIndex: "index-one",
			requested:    &RequestedAuthnContext{AuthnContextClassRefs: []string{strongClass}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newQueryFixture(t)
			f.test.IDP.AuthnContextEnforcer = tc.enforcer

			query := f.authnQuery()
			query.SessionIndex = tc.sessionIndex
			query.RequestedAuthnContext = tc.requested

			response := f.queryAuthn(t, query)
			assertQueryStatus(t, response, StatusSuccess, "")

			// SAMLCore §3.3.4: Success with no assertion when there is nothing to state.
			if len(tc.indexes) == 0 {
				assert.Len(t, response.Assertions, 0)

				return
			}

			require.Len(t, response.Assertions, 1)

			var indexes []string
			for _, statement := range response.Assertions[0].AuthnStatements {
				indexes = append(indexes, statement.SessionIndex)
			}

			assert.Equal(t, indexes, tc.indexes)
		})
	}
}

// A session is stated with its declaration reference and authorities, and a requested declaration
// reference is matched against that of the session.
func TestServeAuthnQueryDeclRef(t *testing.T) {
	f := newQueryFixture(t)
	f.provider.sessions[1].AuthnContextDeclRef = testDeclRef
	f.provider.sessions[1].AuthenticatingAuthorities = []string{upstreamAuthority}

	query := f.authnQuery()
	query.RequestedAuthnContext = &RequestedAuthnContext{AuthnContextDeclRefs: []string{testDeclRef}}

	response := f.queryAuthn(t, query)
	assertQueryStatus(t, response, StatusSuccess, "")
	require.Len(t, response.Assertions, 1)
	require.Len(t, response.Assertions[0].AuthnStatements, 1)

	statement := response.Assertions[0].AuthnStatements[0]
	assert.Equal(t, statement.SessionIndex, "index-two")
	assert.Equal(t, statement.AuthnContext, AuthnContext{
		AuthnContextClassRef:      &AuthnContextClassRef{Value: strongClass},
		AuthnContextDeclRef:       &AuthnContextDeclRef{Value: testDeclRef},
		AuthenticatingAuthorities: []string{upstreamAuthority},
	})
}

func TestServeAuthnQueryPrincipal(t *testing.T) {
	t.Run("no session", func(t *testing.T) {
		f := newQueryFixture(t)
		f.provider.sessions = nil

		response := f.queryAuthn(t, f.authnQuery())
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Len(t, response.Assertions, 0)
		assert.Len(t, f.store.saved, 0)
	})

	t.Run("lookup fails", func(t *testing.T) {
		f := newQueryFixture(t)
		f.provider.sessionsErr = errors.New("session store unavailable")

		assertQueryStatus(t, f.queryAuthn(t, f.authnQuery()), StatusResponder, "")
	})

	t.Run("no QuerySessionProvider", func(t *testing.T) {
		f := newQueryFixture(t)
		f.test.IDP.SessionProvider = &f.provider.mockSessionProvider

		assertQueryStatus(t, f.queryAuthn(t, f.authnQuery()), StatusResponder, StatusRequestUnsupported)
	})
}

// storeAssertion saves a signed assertion with that ID, issued to the service provider with that entity ID.
func (f *queryFixture) storeAssertion(t *testing.T, id, serviceProviderID string) *etree.Element {
	t.Helper()

	assertion := &Assertion{
		ID:           id,
		IssueInstant: TimeNow(),
		Version:      "2.0",
		Issuer:       Issuer{Value: f.test.IDP.MetadataURL.String()},
		Subject:      &Subject{NameID: &NameID{Value: "alice"}},
	}

	signingContext, err := f.test.IDP.signingContext()
	require.NoError(t, err)

	signed, err := signingContext.SignEnveloped(assertion.Element())
	require.NoError(t, err)

	if f.store.assertions == nil {
		f.store.assertions = map[string]*StoredAssertion{}
	}

	f.store.assertions[id] = &StoredAssertion{ServiceProvider: serviceProviderID, Assertion: signed, NotOnOrAfter: TimeNow().Add(MaxIssueDelay)}

	return signed
}

func TestServeAssertionIDRequest(t *testing.T) {
	f := newQueryFixture(t)
	stored := f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())

	before := elementString(t, stored)

	request := f.assertionIDRequest(queryTestStoredAssertionID)

	response := f.requestAssertions(t, request)
	assertQueryStatus(t, response, StatusSuccess, "")
	assert.Equal(t, response.Response.InResponseTo, request.ID)
	assert.Equal(t, response.Response.Destination, "")
	require.Len(t, response.Assertions, 1)
	assert.Equal(t, response.Encrypted, 1, "it is encrypted again for the service provider")
	assert.Equal(t, response.Assertions[0].ID, queryTestStoredAssertionID)
	assert.Equal(t, elementString(t, response.AssertionEls[0]), before, "it is returned as it was signed")

	assert.Equal(t, f.store.gets, []string{queryTestStoredAssertionID})
	assert.Len(t, f.store.saved, 0, "an assertion that is fetched is not issued again")
	assert.Equal(t, elementString(t, stored), before, "the stored assertion is not modified")
	assert.Nil(t, stored.Parent())
	assert.Len(t, f.provider.nameIDs, 0)
}

func elementString(t *testing.T, el *etree.Element) string {
	t.Helper()

	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())

	s, err := doc.WriteToString()
	require.NoError(t, err)

	return s
}

func TestServeAssertionIDRequestSelects(t *testing.T) {
	testCases := []struct {
		name   string
		refs   []string
		setup  func(*queryFixture)
		found  []string
		top    string
		second string
	}{
		{name: "unknown", refs: []string{"id-unknown"}, top: StatusSuccess},
		{name: "issued to another service provider", refs: []string{"id-other"}, top: StatusSuccess},
		{name: "known and unknown", refs: []string{"id-unknown", queryTestStoredAssertionID, "id-other"}, found: []string{queryTestStoredAssertionID}, top: StatusSuccess},
		{name: "several", refs: []string{"id-second", queryTestStoredAssertionID}, found: []string{"id-second", queryTestStoredAssertionID}, top: StatusSuccess},
		{name: "named twice", refs: []string{queryTestStoredAssertionID, queryTestStoredAssertionID}, found: []string{queryTestStoredAssertionID}, top: StatusSuccess},
		{name: "whitespace around the reference", refs: []string{"\n  " + queryTestStoredAssertionID + "\n"}, found: []string{queryTestStoredAssertionID}, top: StatusSuccess},
		{name: "empty reference", refs: []string{""}, top: StatusSuccess},
		{name: "no reference", top: StatusRequester},
		{
			name: "the store returns another assertion",
			refs: []string{"id-alias"},
			setup: func(f *queryFixture) {
				f.store.assertions["id-alias"] = f.store.assertions[queryTestStoredAssertionID]
			},
			top: StatusSuccess,
		},
		{
			name: "the store returns something that is not an assertion",
			refs: []string{"id-response"},
			setup: func(f *queryFixture) {
				el := etree.NewElement("samlp:Response")
				el.CreateAttr("xmlns:samlp", samlProtocolNS)
				el.CreateAttr("ID", "id-response")
				f.store.assertions["id-response"] = &StoredAssertion{ServiceProvider: f.test.SP.MetadataURL.String(), Assertion: el}
			},
			top: StatusSuccess,
		},
		{
			name:  "the store fails",
			refs:  []string{queryTestStoredAssertionID},
			setup: func(f *queryFixture) { f.store.getErr = errors.New("storage unavailable") },
			top:   StatusResponder,
		},
		{
			name:  "no AssertionStore",
			refs:  []string{queryTestStoredAssertionID},
			setup: func(f *queryFixture) { f.test.IDP.AssertionStore = nil },
			top:   StatusResponder, second: StatusRequestUnsupported,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newQueryFixture(t)
			f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())
			f.storeAssertion(t, "id-second", f.test.SP.MetadataURL.String())
			f.storeAssertion(t, "id-other", queryTestOtherProviderID)

			if tc.setup != nil {
				tc.setup(f)
			}

			response := f.requestAssertions(t, f.assertionIDRequest(tc.refs...))
			assertQueryStatus(t, response, tc.top, tc.second)

			var found []string
			for _, assertion := range response.Assertions {
				found = append(found, assertion.ID)
			}

			assert.Equal(t, found, tc.found)
		})
	}
}

func TestServeAssertionIDRequestKeepsEncryption(t *testing.T) {
	noEncryption := func(f *queryFixture) {
		encryption := NoAssertionEncryption
		f.test.IDP.IssuancePolicy = DefaultIssuancePolicy{ServiceProviders: map[string]ServiceProviderIssuance{
			f.test.SP.MetadataURL.String(): {AssertionEncryption: &encryption},
		}}
	}

	noKey := func(f *queryFixture) {
		f.metadata = func(metadata *EntityDescriptor) {
			descriptor := &metadata.SPSSODescriptors[0]

			signing := descriptor.KeyDescriptors[:0]
			for _, keyDescriptor := range descriptor.KeyDescriptors {
				if keyDescriptor.Use == "signing" {
					signing = append(signing, keyDescriptor)
				}
			}

			descriptor.KeyDescriptors = signing
		}
	}

	testCases := []struct {
		name      string
		sent      bool
		setup     []func(*queryFixture)
		top       string
		encrypted int
	}{
		{name: "sent in plaintext, now no assertion encryption", setup: []func(*queryFixture){noEncryption}, top: StatusSuccess},
		{name: "sent encrypted, now no assertion encryption", sent: true, setup: []func(*queryFixture){noEncryption}, top: StatusSuccess, encrypted: 1},
		{name: "sent in plaintext, now without a key", setup: []func(*queryFixture){noKey}, top: StatusSuccess},
		{name: "sent encrypted, now without a key", sent: true, setup: []func(*queryFixture){noKey}, top: StatusResponder},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newQueryFixture(t)
			f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())
			f.store.assertions[queryTestStoredAssertionID].Encrypted = tc.sent

			for _, setup := range tc.setup {
				setup(f)
			}

			response := f.requestAssertions(t, f.assertionIDRequest(queryTestStoredAssertionID))
			assertQueryStatus(t, response, tc.top, "")

			if tc.top == StatusSuccess {
				require.Len(t, response.Assertions, 1)
				assert.Equal(t, tc.encrypted, response.Encrypted)
			}
		})
	}
}

func TestServeAssertionIDRequestTooMany(t *testing.T) {
	refs := make([]string, 0, maxAssertionIDRefs+1)
	for i := range maxAssertionIDRefs + 1 {
		refs = append(refs, "id-"+strings.Repeat("a", i+1))
	}

	f := newQueryFixture(t)

	assertQueryStatus(t, f.requestAssertions(t, f.assertionIDRequest(refs...)), StatusResponder, StatusTooManyResponses)
	assert.Len(t, f.store.gets, 0)

	f = newQueryFixture(t)

	assertQueryStatus(t, f.requestAssertions(t, f.assertionIDRequest(refs[:maxAssertionIDRefs]...)), StatusSuccess, "")
	assert.Len(t, f.store.gets, maxAssertionIDRefs)
}

// An assertion that answers a query can be fetched again by its ID.
func TestServeAssertionIDRequestReturnsQueryAssertion(t *testing.T) {
	f := newQueryFixture(t)
	f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))

	issued := f.queryAttributes(t, f.attributeQuery())
	require.Len(t, issued.Assertions, 1)

	fetched := f.requestAssertions(t, f.assertionIDRequest(issued.Assertions[0].ID))
	assertQueryStatus(t, fetched, StatusSuccess, "")
	require.Len(t, fetched.Assertions, 1)
	assert.Equal(t, elementString(t, fetched.AssertionEls[0]), elementString(t, issued.AssertionEls[0]))
}

func TestAssertionStoreSaveFailureDoesNotFailTheRequest(t *testing.T) {
	f := newQueryFixture(t)
	f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))
	f.store.saveErr = errors.New("storage unavailable")

	response := f.queryAttributes(t, f.attributeQuery())
	assertQueryStatus(t, response, StatusSuccess, "")
	assert.Len(t, response.Assertions, 1)
	assert.Contains(t, f.log.String(), "failed to save assertion: storage unavailable")
}

// Single sign-on saves the assertion as it was signed, before it is encrypted.
func TestServeSSOSavesAssertion(t *testing.T) {
	f := newQueryFixture(t)
	f.provider.GetSessionFunc = func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
		return &Session{ID: "session-one", Index: "index-one", NameID: "alice", UserName: "alice"}
	}

	request, err := f.test.SP.MakeAuthenticationRequest(f.test.IDP.SSOURL.String(), HTTPPostBinding, HTTPPostBinding)
	require.NoError(t, err)

	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	body, err := doc.WriteToBytes()
	require.NoError(t, err)

	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}}
	r := httptest.NewRequest(http.MethodPost, f.test.IDP.SSOURL.String(), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	f.test.IDP.ServeSSO(w, r)
	require.Equal(t, w.Code, http.StatusOK, "body: %s", w.Body.String())

	posted, response := postedResponse(t, w.Body.String())
	require.Equal(t, response.Status.StatusCode.Value, StatusSuccess)

	assertionEl, err := f.test.SP.decryptElement(posted.FindElement("//EncryptedAssertion"))
	require.NoError(t, err)

	id := assertionEl.SelectAttrValue("ID", "")
	require.Equal(t, f.store.saved, []string{id})

	saved := f.store.assertions[id]
	assert.Equal(t, saved.ServiceProvider, f.test.SP.MetadataURL.String())
	assert.True(t, saved.NotOnOrAfter.Equal(TimeNow().Add(MaxIssueDelay)))
	assert.Equal(t, elementString(t, saved.Assertion), elementString(t, assertionEl))
	assert.True(t, saved.Encrypted, "it was sent encrypted")

	// The service provider can fetch what it was sent.
	fetched := f.requestAssertions(t, f.assertionIDRequest(id))
	assertQueryStatus(t, fetched, StatusSuccess, "")
	require.Len(t, fetched.Assertions, 1)
	assert.Equal(t, elementString(t, fetched.AssertionEls[0]), elementString(t, assertionEl))
}

func TestQueryMetadata(t *testing.T) {
	soap := func(location string) []Endpoint { return []Endpoint{{Binding: SOAPBinding, Location: location}} }

	t.Run("nothing without the URLs", func(t *testing.T) {
		f := newQueryFixture(t)
		f.test.IDP.AttributeServiceURL, f.test.IDP.AuthnQueryServiceURL, f.test.IDP.AssertionIDRequestServiceURL = url.URL{}, url.URL{}, url.URL{}

		metadata := f.test.IDP.Metadata()
		assert.Len(t, metadata.AttributeAuthorityDescriptors, 0)
		assert.Len(t, metadata.AuthnAuthorityDescriptors, 0)
		assert.Len(t, metadata.IDPSSODescriptors[0].AssertionIDRequestServices, 0)
	})

	t.Run("nothing without the interfaces", func(t *testing.T) {
		f := newQueryFixture(t)
		f.test.IDP.SessionProvider = &f.provider.mockSessionProvider
		f.test.IDP.AssertionStore = nil

		metadata := f.test.IDP.Metadata()
		assert.Len(t, metadata.AttributeAuthorityDescriptors, 0)
		assert.Len(t, metadata.AuthnAuthorityDescriptors, 0)
		assert.Len(t, metadata.IDPSSODescriptors[0].AssertionIDRequestServices, 0)
	})

	t.Run("everything", func(t *testing.T) {
		f := newQueryFixture(t)
		f.test.IDP.NameIDProvider = DefaultNameIDProvider{Formats: []string{string(PersistentNameIDFormat), string(TransientNameIDFormat)}}

		metadata := f.test.IDP.Metadata()
		formats := []NameIDFormat{PersistentNameIDFormat, TransientNameIDFormat}

		assert.Equal(t, metadata.IDPSSODescriptors[0].AssertionIDRequestServices, soap(assertionIDRequestTestURL))

		require.Len(t, metadata.AttributeAuthorityDescriptors, 1)

		attributes := metadata.AttributeAuthorityDescriptors[0]
		assert.Equal(t, attributes.ProtocolSupportEnumeration, "urn:oasis:names:tc:SAML:2.0:protocol")
		assert.Equal(t, attributes.AttributeServices, soap(attributeServiceTestURL))
		assert.Equal(t, attributes.AssertionIDRequestServices, soap(assertionIDRequestTestURL))
		assert.Equal(t, attributes.NameIDFormats, formats)
		require.Len(t, attributes.KeyDescriptors, 1)
		assert.Equal(t, attributes.KeyDescriptors[0].Use, "signing")
		assert.Equal(t, attributes.KeyDescriptors[0], metadata.IDPSSODescriptors[0].KeyDescriptors[0])

		require.Len(t, metadata.AuthnAuthorityDescriptors, 1)

		authn := metadata.AuthnAuthorityDescriptors[0]
		assert.Equal(t, authn.ProtocolSupportEnumeration, "urn:oasis:names:tc:SAML:2.0:protocol")
		assert.Equal(t, authn.AuthnQueryServices, soap(authnQueryServiceTestURL))
		assert.Equal(t, authn.AssertionIDRequestServices, soap(assertionIDRequestTestURL))
		assert.Equal(t, authn.NameIDFormats, formats)
		require.Len(t, authn.KeyDescriptors, 1)
		assert.Equal(t, authn.KeyDescriptors[0].Use, "signing")
	})

	t.Run("queries without an AssertionStore", func(t *testing.T) {
		f := newQueryFixture(t)
		f.test.IDP.AssertionStore = nil

		metadata := f.test.IDP.Metadata()
		require.Len(t, metadata.AttributeAuthorityDescriptors, 1)
		require.Len(t, metadata.AuthnAuthorityDescriptors, 1)
		assert.Len(t, metadata.AttributeAuthorityDescriptors[0].AssertionIDRequestServices, 0)
		assert.Len(t, metadata.AuthnAuthorityDescriptors[0].AssertionIDRequestServices, 0)
		assert.Len(t, metadata.IDPSSODescriptors[0].AssertionIDRequestServices, 0)
	})

	t.Run("an AssertionStore without queries", func(t *testing.T) {
		f := newQueryFixture(t)
		f.test.IDP.SessionProvider = &f.provider.mockSessionProvider

		metadata := f.test.IDP.Metadata()
		assert.Len(t, metadata.AttributeAuthorityDescriptors, 0)
		assert.Len(t, metadata.AuthnAuthorityDescriptors, 0)
		assert.Equal(t, metadata.IDPSSODescriptors[0].AssertionIDRequestServices, soap(assertionIDRequestTestURL))
	})

	t.Run("one query service", func(t *testing.T) {
		f := newQueryFixture(t)
		f.test.IDP.AuthnQueryServiceURL = url.URL{}

		metadata := f.test.IDP.Metadata()
		assert.Len(t, metadata.AttributeAuthorityDescriptors, 1)
		assert.Len(t, metadata.AuthnAuthorityDescriptors, 0)
	})

	t.Run("it is valid metadata that parses back", func(t *testing.T) {
		f := newQueryFixture(t)

		w := httptest.NewRecorder()
		f.test.IDP.ServeMetadata(w, httptest.NewRequest(http.MethodGet, f.test.IDP.MetadataURL.String(), nil))

		require.NoError(t, xmlrv.Validate(w.Body.Bytes()))

		parsed := &EntityDescriptor{}
		require.NoError(t, xml.Unmarshal(w.Body.Bytes(), parsed))
		require.Len(t, parsed.AttributeAuthorityDescriptors, 1)
		assert.Equal(t, parsed.AttributeAuthorityDescriptors[0].AttributeServices, soap(attributeServiceTestURL))
		require.Len(t, parsed.AuthnAuthorityDescriptors, 1)
		assert.Equal(t, parsed.AuthnAuthorityDescriptors[0].AuthnQueryServices, soap(authnQueryServiceTestURL))
		assert.Equal(t, parsed.IDPSSODescriptors[0].AssertionIDRequestServices, soap(assertionIDRequestTestURL))
	})
}

func TestHandlerServesQueries(t *testing.T) {
	f := newQueryFixture(t)
	f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))
	f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())

	handler := f.test.IDP.Handler()

	for _, service := range queryServices {
		t.Run(service.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, queryPost(t, service.url, signQueryElement(t, &f.test.SP, service.message(f))))

			response := f.answer(t, w)
			assertQueryStatus(t, response, StatusSuccess, "")
			assert.Len(t, response.Assertions, 1)
		})

		// Each service only accepts its own message.
		for _, other := range queryServices {
			if other.name == service.name {
				continue
			}

			t.Run(service.name+" refuses "+other.name, func(t *testing.T) {
				message := other.message(f)
				message.CreateAttr("Destination", service.url)

				w := httptest.NewRecorder()
				handler.ServeHTTP(w, queryPost(t, service.url, signQueryElement(t, &f.test.SP, message)))

				assertQueryStatus(t, f.answer(t, w), StatusRequester, StatusRequestUnsupported)
			})
		}
	}

	t.Run("not served without the URLs", func(t *testing.T) {
		f := newQueryFixture(t)
		f.test.IDP.AttributeServiceURL, f.test.IDP.AuthnQueryServiceURL, f.test.IDP.AssertionIDRequestServiceURL = url.URL{}, url.URL{}, url.URL{}

		handler := f.test.IDP.Handler()

		for _, service := range queryServices {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, queryPost(t, service.url, service.message(f)))
			assert.Equal(t, w.Code, http.StatusNotFound)
		}
	})
}

func TestServeQueryRefusesReplay(t *testing.T) {
	for i, service := range queryServices {
		t.Run(service.name, func(t *testing.T) {
			f := newQueryFixture(t)

			store := newRecordingReplayStore()
			f.test.IDP.ReplayStore = store

			message := service.message(f)

			// A request that can't be verified is refused without being recorded, so nobody but the service
			// provider can use up its IDs.
			assertQueryStatus(t, f.answer(t, f.serve(service, queryPost(t, service.url, message))), StatusRequester, StatusRequestDenied)
			assert.Equal(t, store.calls(), 0)

			// SAMLSec §6.1.2: the request is answered once, and is a replay after that.
			assertQueryStatus(t, f.query(t, service, message), StatusSuccess, "")
			require.Equal(t, store.calls(), 1)
			assert.True(t, store.expiries[0].Equal(TimeNow().Add(MaxIssueDelay+2*MaxClockSkew)))

			assertQueryStatus(t, f.query(t, service, message), StatusRequester, StatusRequestDenied)
			assert.Contains(t, f.log.String(), "is a replay")

			// Another request is not, and nor is the same ID from another kind of message.
			assertQueryStatus(t, f.query(t, service, service.message(f)), StatusSuccess, "")

			other := (i + 1) % len(queryServices)
			reused := queryServices[other].message(f)
			reused.CreateAttr("ID", message.SelectAttrValue("ID", ""))
			assertQueryStatus(t, f.query(t, queryServices[other], reused), StatusSuccess, "")

			// If the store fails the request is refused, as nothing is known about it.
			store.err = errors.New("store down")
			response := f.query(t, service, service.message(f))
			assertQueryStatus(t, response, StatusResponder, "")
			assert.Len(t, response.Assertions, 0)
		})
	}
}
