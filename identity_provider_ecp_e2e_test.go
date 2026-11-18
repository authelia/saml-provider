package saml

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/dsig"
)

// ecpTestClient is a minimal Enhanced Client: it relays the AuthnRequest of a service provider to the identity
// provider, authenticates with HTTP Basic credentials when challenged, and checks the answer as SAMLProf §4.2.3.7
// requires before it would deliver the Response.
type ecpTestClient struct {
	t                  *testing.T
	username, password string

	// statuses are the HTTP status codes of the identity provider's answers.
	statuses []int
}

// ecpTestPAOSRequest returns the envelope that the service provider answers the client with (SAMLProf §4.2.3.2): the
// request, and header blocks which are for the client.
func ecpTestPAOSRequest(t *testing.T, request *AuthnRequest, responseConsumerURL string) []byte {
	t.Helper()

	paos := etree.NewElement("paos:Request")
	paos.CreateAttr("xmlns:paos", "urn:liberty:paos:2003-08")
	paos.CreateAttr("responseConsumerURL", responseConsumerURL)
	paos.CreateAttr("service", ecpNS)
	paos.CreateAttr("soapenv:mustUnderstand", "1")
	paos.CreateAttr("soapenv:actor", soapActorNext)

	ecp := etree.NewElement("ecp:Request")
	ecp.CreateAttr("xmlns:ecp", ecpNS)
	ecp.CreateAttr("soapenv:mustUnderstand", "1")
	ecp.CreateAttr("soapenv:actor", soapActorNext)

	relayState := etree.NewElement("ecp:RelayState")
	relayState.CreateAttr("xmlns:ecp", ecpNS)
	relayState.CreateAttr("soapenv:mustUnderstand", "1")
	relayState.CreateAttr("soapenv:actor", soapActorNext)
	relayState.SetText("state")

	return ecpEnvelope(t, request.Element(), paos, ecp, relayState)
}

// exchange relays the request in the envelope of the service provider to the identity provider at idpURL, and
// returns the Response to deliver to the responseConsumerURL of the envelope.
func (c *ecpTestClient) exchange(paosRequest []byte, idpURL string) []byte {
	c.t.Helper()

	_, headers, message, err := parseSOAPEnvelope(paosRequest)
	require.NoError(c.t, err)

	responseConsumerURL := ""

	for _, header := range headers {
		if header.Tag == "Request" && header.NamespaceURI() == "urn:liberty:paos:2003-08" {
			responseConsumerURL = header.SelectAttrValue("responseConsumerURL", "")
		}
	}

	// SAMLProf §4.2.3.4: the header blocks of the service provider are removed.
	envelope := ecpEnvelope(c.t, message)

	res := c.post(idpURL, envelope, false)
	if res.StatusCode == http.StatusUnauthorized {
		assert.Equal(c.t, res.Header.Get("WWW-Authenticate"), `Basic realm="idp"`)
		res.Body.Close()

		res = c.post(idpURL, envelope, true)
	}

	defer res.Body.Close()

	require.Equal(c.t, res.StatusCode, http.StatusOK)

	body, err := io.ReadAll(res.Body)
	require.NoError(c.t, err)

	_, headers, response, err := parseSOAPEnvelope(body)
	require.NoError(c.t, err)

	// SAMLProf §4.2.4.4: the Response is only delivered to the endpoint that the service provider named.
	var ecpResponseHeader *etree.Element

	for _, header := range headers {
		if soapHeaderMustBeUnderstood(header, nil) {
			require.True(c.t, header.Tag == "Response" && header.NamespaceURI() == ecpNS, "header block %s is not understood", header.Tag)

			ecpResponseHeader = header
		}
	}

	require.True(c.t, ecpResponseHeader != nil)
	require.Equal(c.t, ecpResponseHeader.SelectAttrValue("AssertionConsumerServiceURL", ""), responseConsumerURL)

	doc := etree.NewDocument()
	doc.SetRoot(response)

	buf, err := doc.WriteToBytes()
	require.NoError(c.t, err)

	return buf
}

func (c *ecpTestClient) post(idpURL string, envelope []byte, authenticate bool) *http.Response {
	c.t.Helper()

	r, err := http.NewRequestWithContext(c.t.Context(), http.MethodPost, idpURL, bytes.NewReader(envelope))
	require.NoError(c.t, err)

	r.Header.Set("Content-Type", "text/xml; charset=utf-8")
	r.Header.Set("SOAPAction", `"`+soapActionSAML+`"`)

	if authenticate {
		r.SetBasicAuth(c.username, c.password)
	}

	res, err := http.DefaultClient.Do(r)
	require.NoError(c.t, err)

	c.statuses = append(c.statuses, res.StatusCode)

	return res
}

// newECPEndToEnd returns an identity provider served over HTTP by its Handler, and a service provider whose
// assertion consumer service is a PAOS endpoint, which signs its requests and has assertions encrypted.
func newECPEndToEnd(t *testing.T) (*IdentityProviderTest, *ecpSessionProvider, *ServiceProvider) {
	t.Helper()

	test := signatureTestIDP(t)
	test.IDP.Observer = logObserver(io.Discard)

	sp := test.SP
	sp.AcsURL = mustParseURL(ecpTestPAOSURL)
	sp.SignatureMethod = dsig.RSASHA256SignatureMethod

	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			if serviceProviderID != sp.MetadataURL.String() {
				return nil, os.ErrNotExist
			}

			metadata := sp.Metadata()
			metadata.SPSSODescriptors[0].AssertionConsumerServices = []IndexedEndpoint{
				{Binding: PAOSBinding, Location: ecpTestPAOSURL, Index: 1},
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		test.IDP.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)

	test.IDP.MetadataURL = mustParseURL(server.URL + "/saml/metadata")
	test.IDP.SSOURL = mustParseURL(server.URL + "/saml/sso")
	test.IDP.ECPURL = mustParseURL(server.URL + "/saml/ecp")

	sp.IDPMetadata = test.IDP.Metadata()

	return test, provider, &sp
}

func TestECPEndToEnd(t *testing.T) {
	test, provider, sp := newECPEndToEnd(t)

	// The client finds the identity provider's endpoint in its metadata (ECP v2.0 §2.3.10).
	idpURL := sp.GetSSOBindingLocation(SOAPBinding)
	require.Equal(t, idpURL, test.IDP.ECPURL.String())

	// The service provider issues the request without knowing which identity provider the client will choose.
	request, err := sp.MakeAuthenticationRequest("", HTTPPostBinding, PAOSBinding)
	require.NoError(t, err)
	require.NotNil(t, request.Signature)

	client := &ecpTestClient{t: t, username: "alice", password: "secret"}
	responseXML := client.exchange(ecpTestPAOSRequest(t, request, ecpTestPAOSURL), idpURL)

	assert.Equal(t, client.statuses, []int{http.StatusUnauthorized, http.StatusOK})

	// The service provider consumes the Response as it would one from the HTTP-POST binding (SAMLProf §4.2.3.8).
	assertion, err := sp.ParseXMLResponse(responseXML, []string{request.ID}, sp.AcsURL)
	if invalid := (&InvalidResponseError{}); errors.As(err, &invalid) {
		t.Fatalf("the service provider refused the response: %s", invalid.PrivateErr)
	}

	require.NoError(t, err)

	assert.Equal(t, assertion.Subject.NameID.SPNameQualifier, sp.MetadataURL.String())
	assert.Equal(t, assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.Recipient, ecpTestPAOSURL)
	assert.Equal(t, assertion.AuthnStatements[0].SessionIndex, "index-one")

	assert.Len(t, provider.requests, 2, "once for the challenge and once with credentials")
	require.Len(t, provider.participants, 1)
	assert.Equal(t, provider.participants[0].ServiceProviderEntityID, sp.MetadataURL.String())
	assert.Equal(t, provider.participants[0].NameID, *assertion.Subject.NameID)
}

func TestECPEndToEndWrongCredentials(t *testing.T) {
	_, provider, sp := newECPEndToEnd(t)

	request, err := sp.MakeAuthenticationRequest("", HTTPPostBinding, PAOSBinding)
	require.NoError(t, err)

	_, _, message, err := parseSOAPEnvelope(ecpTestPAOSRequest(t, request, ecpTestPAOSURL))
	require.NoError(t, err)

	client := &ecpTestClient{t: t, username: "alice", password: "wrong"}

	res := client.post(sp.GetSSOBindingLocation(SOAPBinding), ecpEnvelope(t, message), true)
	defer res.Body.Close()

	assert.Equal(t, res.StatusCode, http.StatusUnauthorized)
	assert.Len(t, provider.participants, 0)
}
