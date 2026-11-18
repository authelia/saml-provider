package saml

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// queryE2ESessionProvider has one logged in user, whom it finds by the NameID that single sign-on asserts for the
// session: the email address, qualified with the service provider it was asserted to.
type queryE2ESessionProvider struct {
	session *Session
}

func (p *queryE2ESessionProvider) GetSession(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
	return p.session
}

func (p *queryE2ESessionProvider) matches(req *IdpQueryRequest, nameID *NameID) bool {
	return nameID.Value == p.session.NameID && nameID.Format == p.session.NameIDFormat &&
		nameID.SPNameQualifier == req.ServiceProviderMetadata.EntityID
}

func (p *queryE2ESessionProvider) GetQuerySubject(_ *http.Request, req *IdpQueryRequest, nameID *NameID) (*Session, error) {
	if !p.matches(req, nameID) {
		return nil, nil
	}

	return p.session, nil
}

func (p *queryE2ESessionProvider) GetAuthnSessions(_ *http.Request, req *IdpQueryRequest, nameID *NameID) ([]*Session, error) {
	if !p.matches(req, nameID) {
		return nil, nil
	}

	return []*Session{p.session}, nil
}

// queryE2E is an identity provider served by Handler on a real listener, and what a service provider learned of
// it from its metadata.
type queryE2E struct {
	f      *queryFixture
	server *httptest.Server

	attributeService          string
	authnQueryService         string
	assertionIDRequestService string
}

func newQueryE2E(t *testing.T) *queryE2E {
	t.Helper()

	e := &queryE2E{f: newQueryFixture(t)}

	var handler http.Handler

	e.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(e.server.Close)

	session := attributeReleaseSession()
	session.NameID = "alice@example.com"
	session.Index = "index-e2e"
	session.CreateTime = TimeNow().Add(-10 * 60 * 1e9)
	session.AuthnContextClassRef = strongClass

	idp := &e.f.test.IDP
	idp.SessionProvider = &queryE2ESessionProvider{session: session}
	idp.MetadataURL = mustParseURL(e.server.URL + "/saml/metadata")
	idp.SSOURL = mustParseURL(e.server.URL + "/saml/sso")
	idp.AttributeServiceURL = mustParseURL(e.server.URL + "/saml/attributes")
	idp.AuthnQueryServiceURL = mustParseURL(e.server.URL + "/saml/authn-query")
	idp.AssertionIDRequestServiceURL = mustParseURL(e.server.URL + "/saml/assertion-id")

	handler = idp.Handler()

	e.f.test.SP.AuthnNameIDFormat = EmailAddressNameIDFormat
	e.f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat), requested(affiliationAttributeName, uriAttrNameFormat))

	// The service provider learns the services from the metadata that the identity provider serves.
	res, err := http.Get(idp.MetadataURL.String())
	require.NoError(t, err)

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	metadata := &EntityDescriptor{}
	require.NoError(t, xml.Unmarshal(body, metadata))

	e.f.test.SP.IDPMetadata = metadata

	soapLocation := func(endpoints []Endpoint) string {
		t.Helper()

		require.Len(t, endpoints, 1)
		require.Equal(t, endpoints[0].Binding, SOAPBinding)

		return endpoints[0].Location
	}

	require.Len(t, metadata.AttributeAuthorityDescriptors, 1)
	require.Len(t, metadata.AuthnAuthorityDescriptors, 1)

	e.attributeService = soapLocation(metadata.AttributeAuthorityDescriptors[0].AttributeServices)
	e.authnQueryService = soapLocation(metadata.AuthnAuthorityDescriptors[0].AuthnQueryServices)
	e.assertionIDRequestService = soapLocation(metadata.IDPSSODescriptors[0].AssertionIDRequestServices)

	return e
}

// sso logs the user in at the service provider, which validates the response as it would at its assertion consumer
// service, and returns the assertion.
func (e *queryE2E) sso(t *testing.T) *Assertion {
	t.Helper()

	sp := &e.f.test.SP

	request, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(HTTPPostBinding), HTTPPostBinding, HTTPPostBinding)
	require.NoError(t, err)

	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	body, err := doc.WriteToBytes()
	require.NoError(t, err)

	res, err := http.PostForm(request.Destination, url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}})
	require.NoError(t, err)

	defer res.Body.Close()

	page, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.Equal(t, res.StatusCode, http.StatusOK, "body: %s", page)

	posted, _ := postedResponse(t, string(page))
	responseXML, err := posted.WriteToBytes()
	require.NoError(t, err)

	assertion, err := sp.ParseXMLResponse(responseXML, []string{request.ID}, sp.AcsURL)
	require.NoError(t, err)

	return assertion
}

// post signs message as sp, if it has a signature method, posts it in a SOAP envelope to location, and returns the
// parsed answer.
func (e *queryE2E) post(t *testing.T, sp *ServiceProvider, location string, message *etree.Element) *queryResponse {
	t.Helper()

	if sp.SignatureMethod != "" {
		message = signQueryElement(t, sp, message)
	}

	req, err := http.NewRequest(http.MethodPost, location, bytes.NewReader(soapLogoutEnvelope(t, message)))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", `"`+soapActionSAML+`"`)

	res, err := e.server.Client().Do(req)
	require.NoError(t, err)

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	return parseQueryResponse(t, sp, res.StatusCode, res.Header, body)
}

func TestQueryEndToEnd(t *testing.T) {
	e := newQueryE2E(t)
	f, sp := e.f, &e.f.test.SP

	issued := e.sso(t)
	require.True(t, issued.Subject != nil && issued.Subject.NameID != nil)
	require.Len(t, issued.AuthnStatements, 1)
	assert.Equal(t, issued.Subject.NameID.SPNameQualifier, sp.MetadataURL.String())

	subject := &Subject{NameID: issued.Subject.NameID}

	t.Run("AssertionIDRequest returns the assertion of single sign-on", func(t *testing.T) {
		request := f.assertionIDRequest(issued.ID)
		request.Destination = e.assertionIDRequestService

		response := e.post(t, sp, e.assertionIDRequestService, request.Element())
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Equal(t, response.Response.InResponseTo, request.ID)
		require.Len(t, response.Assertions, 1)
		assert.Equal(t, response.Encrypted, 1)

		fetched := response.Assertions[0]
		assert.Equal(t, fetched.ID, issued.ID)
		assert.Equal(t, fetched.Subject.NameID, issued.Subject.NameID)
		assert.Equal(t, fetched.AttributeStatements, issued.AttributeStatements)
		assert.Equal(t, fetched.AuthnStatements[0].SessionIndex, "index-e2e")
	})

	t.Run("AttributeQuery states what single sign-on stated", func(t *testing.T) {
		query := f.attributeQuery()
		query.Destination, query.Subject = e.attributeService, subject

		response := e.post(t, sp, e.attributeService, query.Element())
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Equal(t, response.Response.InResponseTo, query.ID)
		assert.Equal(t, response.Response.Issuer.Value, f.test.IDP.MetadataURL.String())
		require.Len(t, response.Assertions, 1)
		assert.Equal(t, response.Encrypted, 1)

		assertion := response.Assertions[0]
		f.assertQueryAssertion(t, assertion, subject)
		assert.True(t, assertion.ID != issued.ID)
		assert.Equal(t, assertion.AttributeStatements, issued.AttributeStatements)
		assert.Equal(t, attributeNames(assertion.AttributeStatements[0].Attributes), []string{mailAttributeName, affiliationAttributeName})
	})

	t.Run("AttributeQuery for one value", func(t *testing.T) {
		query := f.attributeQuery(Attribute{
			Name:       affiliationAttributeName,
			NameFormat: uriAttrNameFormat,
			Values:     []AttributeValue{{Type: "xs:string", Value: "Administrators"}},
		})
		query.Destination, query.Subject = e.attributeService, subject

		response := e.post(t, sp, e.attributeService, query.Element())
		assertQueryStatus(t, response, StatusSuccess, "")
		require.Len(t, response.Assertions, 1)

		attributes := response.Assertions[0].AttributeStatements[0].Attributes
		require.Len(t, attributes, 1)
		assert.Equal(t, queryAttributeValues(attributes[0]), []string{"Administrators"})
	})

	t.Run("AuthnQuery states the session of single sign-on", func(t *testing.T) {
		query := f.authnQuery()
		query.Destination, query.Subject = e.authnQueryService, subject
		query.SessionIndex = issued.AuthnStatements[0].SessionIndex
		query.RequestedAuthnContext = &RequestedAuthnContext{AuthnContextClassRefs: []string{strongClass}}

		response := e.post(t, sp, e.authnQueryService, query.Element())
		assertQueryStatus(t, response, StatusSuccess, "")
		require.Len(t, response.Assertions, 1)

		assertion := response.Assertions[0]
		f.assertQueryAssertion(t, assertion, subject)
		require.Len(t, assertion.AuthnStatements, 1)

		statement := assertion.AuthnStatements[0]
		assert.Equal(t, statement.SessionIndex, issued.AuthnStatements[0].SessionIndex)
		assert.True(t, statement.AuthnInstant.Equal(issued.AuthnStatements[0].AuthnInstant))
		assert.Equal(t, statement.AuthnContext.AuthnContextClassRef, issued.AuthnStatements[0].AuthnContext.AuthnContextClassRef)

		// The assertion that answered the query can itself be fetched.
		request := f.assertionIDRequest(assertion.ID)
		request.Destination = e.assertionIDRequestService

		fetched := e.post(t, sp, e.assertionIDRequestService, request.Element())
		require.Len(t, fetched.Assertions, 1)
		assert.Equal(t, elementString(t, fetched.AssertionEls[0]), elementString(t, response.AssertionEls[0]))
	})

	t.Run("AuthnQuery for a context the session does not have", func(t *testing.T) {
		query := f.authnQuery()
		query.Destination, query.Subject = e.authnQueryService, subject
		query.RequestedAuthnContext = &RequestedAuthnContext{AuthnContextClassRefs: []string{weakClass}}

		response := e.post(t, sp, e.authnQueryService, query.Element())
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Len(t, response.Assertions, 0)
	})

	// Another service provider, with its own key, learns nothing of the first one's user or assertions.
	other := *sp
	other.MetadataURL = mustParseURL("https://sp-b.example.com/saml2/metadata")
	other.AcsURL = mustParseURL("https://sp-b.example.com/saml2/acs")
	other.Key, other.Certificate = propagationServiceProviderKey(t)
	f.entities[other.MetadataURL.String()] = other.Metadata()

	otherIssuer := &Issuer{Value: other.MetadataURL.String()}

	t.Run("another service provider cannot fetch the assertion", func(t *testing.T) {
		request := f.assertionIDRequest(issued.ID)
		request.Destination, request.Issuer = e.assertionIDRequestService, otherIssuer

		response := e.post(t, &other, e.assertionIDRequestService, request.Element())
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Len(t, response.Assertions, 0)
	})

	t.Run("another service provider cannot query the NameID", func(t *testing.T) {
		query := f.attributeQuery()
		query.Destination, query.Subject, query.Issuer = e.attributeService, subject, otherIssuer

		assertQueryStatus(t, e.post(t, &other, e.attributeService, query.Element()), StatusRequester, StatusRequestDenied)
	})

	t.Run("another service provider cannot pass for the first", func(t *testing.T) {
		query := f.attributeQuery()
		query.Destination, query.Subject = e.attributeService, subject

		assertQueryStatus(t, e.post(t, &other, e.attributeService, query.Element()), StatusRequester, StatusRequestDenied)
	})

	t.Run("an unsigned query is refused", func(t *testing.T) {
		unsigned := *sp
		unsigned.SignatureMethod = ""

		query := f.attributeQuery()
		query.Destination, query.Subject = e.attributeService, subject

		assertQueryStatus(t, e.post(t, &unsigned, e.attributeService, query.Element()), StatusRequester, StatusRequestDenied)
	})

	t.Run("a query sent to another service is refused", func(t *testing.T) {
		query := f.attributeQuery()
		query.Destination, query.Subject = e.attributeService, subject

		assertQueryStatus(t, e.post(t, sp, e.authnQueryService, query.Element()), StatusRequester, StatusRequestUnsupported)
	})

	t.Run("a GET is not SOAP", func(t *testing.T) {
		res, err := e.server.Client().Get(e.attributeService)
		require.NoError(t, err)

		defer res.Body.Close()

		assert.Equal(t, res.StatusCode, http.StatusMethodNotAllowed)
	})

	t.Run("a body that is not an envelope is a fault", func(t *testing.T) {
		res, err := e.server.Client().Post(e.attributeService, "text/xml", strings.NewReader("<not-soap/>"))
		require.NoError(t, err)

		defer res.Body.Close()

		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.Equal(t, res.StatusCode, http.StatusInternalServerError)
		assert.Contains(t, string(body), "soapenv:Client")
	})
}
