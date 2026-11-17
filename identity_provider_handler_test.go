package saml

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

const handlerTestSharedURL = "https://idp.example.com/saml/sso"

// handlerSessionProvider is a QuerySessionProvider which also serves the Enhanced Client or Proxy profile.
type handlerSessionProvider struct {
	*querySessionProvider
}

func (p *handlerSessionProvider) GetECPSession(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
	return &Session{ID: "session-one", Index: "index-one", CreateTime: TimeNow(), NameID: "alice", UserName: "alice"}
}

// newHandlerFixture is a queryFixture whose identity provider has every service, each at the URL that urlOf
// returns for the name of its field.
func newHandlerFixture(t *testing.T, urlOf func(field string) string) *queryFixture {
	t.Helper()

	f := newQueryFixture(t)
	f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())

	f.metadata = func(metadata *EntityDescriptor) {
		descriptor := &metadata.SPSSODescriptors[0]
		descriptor.AttributeConsumingServices = []AttributeConsumingService{service(1, nil, requested(mailAttributeName, uriAttrNameFormat))}
		descriptor.AssertionConsumerServices = append(descriptor.AssertionConsumerServices, IndexedEndpoint{
			Binding:  PAOSBinding,
			Location: ecpTestPAOSURL,
			Index:    3,
		})
	}

	idp := &f.test.IDP
	idp.SessionProvider = &handlerSessionProvider{f.provider}
	idp.MetadataURL = mustParseURL(urlOf("MetadataURL"))
	idp.SSOURL = mustParseURL(urlOf("SSOURL"))
	idp.LogoutURL = mustParseURL(urlOf("LogoutURL"))
	idp.SOAPLogoutURL = mustParseURL(urlOf("SOAPLogoutURL"))
	idp.ECPURL = mustParseURL(urlOf("ECPURL"))
	idp.ArtifactResolutionURL = mustParseURL(urlOf("ArtifactResolutionURL"))
	idp.AttributeServiceURL = mustParseURL(urlOf("AttributeServiceURL"))
	idp.AuthnQueryServiceURL = mustParseURL(urlOf("AuthnQueryServiceURL"))
	idp.AssertionIDRequestServiceURL = mustParseURL(urlOf("AssertionIDRequestServiceURL"))

	return f
}

// handlerSOAPPost returns a SOAP POST of body to the shared URL by a client which authenticates as alice.
func handlerSOAPPost(body []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPost, handlerTestSharedURL, bytes.NewReader(body))
	r.Header.Set("Content-Type", "text/xml; charset=utf-8")
	r.SetBasicAuth("alice", "secret")

	return r
}

// handlerAnswer returns the message in the envelope that w answered with.
func handlerAnswer(t *testing.T, w *httptest.ResponseRecorder) *etree.Element {
	t.Helper()

	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())

	_, _, message, err := parseSOAPEnvelope(w.Body.Bytes())
	assert.NilError(t, err)
	assert.Assert(t, is.Equal(message.NamespaceURI(), samlProtocolNS))

	return message
}

// Every service at one path: a SOAP request goes to the service of the message in its envelope, which answers it
// as it would at a path of its own, and anything else goes to the front-channel service.
func TestHandlerServesSOAPServicesAtOnePath(t *testing.T) {
	f := newHandlerFixture(t, func(field string) string {
		if field == "MetadataURL" {
			return "https://idp.example.com/saml/metadata"
		}

		return handlerTestSharedURL
	})

	sp := &f.test.SP
	handler := f.test.IDP.Handler()

	serve := func(r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)

		return w
	}

	for _, service := range queryServices {
		t.Run(service.name, func(t *testing.T) {
			message := service.message(f)
			message.CreateAttr("Destination", handlerTestSharedURL)

			response := f.answer(t, serve(queryPost(t, handlerTestSharedURL, signQueryElement(t, sp, message))))
			assertQueryStatus(t, response, StatusSuccess, "")
			assert.Check(t, is.Len(response.Assertions, 1))
		})
	}

	t.Run("LogoutRequest", func(t *testing.T) {
		el, id := soapLogoutRequestElement(t, sp, func(request *LogoutRequest) { request.Destination = handlerTestSharedURL })

		message := handlerAnswer(t, serve(handlerSOAPPost(soapLogoutEnvelope(t, el))))
		assert.Check(t, is.Equal(message.Tag, "LogoutResponse"))
		assert.Check(t, is.Equal(message.SelectAttrValue("InResponseTo", ""), id))
	})

	t.Run("AuthnRequest", func(t *testing.T) {
		request := ecpAuthnRequest(t, sp, nil)

		response := parseECPResponse(t, serve(handlerSOAPPost(ecpEnvelope(t, request.Element()))))
		assertECPResponseHeader(t, response, ecpTestPAOSURL)
		assert.Check(t, response.header("RequestAuthenticated") != nil)
		assert.Check(t, is.Equal(response.Response.InResponseTo, request.ID))
		assert.Check(t, is.Equal(response.Response.Status.StatusCode.Value, StatusSuccess))
	})

	t.Run("ArtifactResolve", func(t *testing.T) {
		request, err := sp.MakeArtifactResolveRequest("unknown")
		assert.NilError(t, err)

		message := handlerAnswer(t, serve(handlerSOAPPost(soapLogoutEnvelope(t, request.Element()))))
		assert.Check(t, is.Equal(message.Tag, "ArtifactResponse"))
		assert.Check(t, is.Equal(message.SelectAttrValue("InResponseTo", ""), request.ID))
	})

	// The first service on the SOAP binding, which is the logout service, refuses what none of them is for.
	t.Run("another message", func(t *testing.T) {
		el, _ := soapLogoutRequestElement(t, sp, nil)
		el.Tag = "ManageNameIDRequest"

		message := handlerAnswer(t, serve(handlerSOAPPost(soapLogoutEnvelope(t, el))))
		assert.Check(t, is.Equal(message.Tag, "LogoutResponse"))
		assert.Check(t, is.Equal(message.FindElement("./Status/StatusCode/StatusCode").SelectAttrValue("Value", ""), StatusRequestUnsupported))
	})

	t.Run("message of another namespace", func(t *testing.T) {
		el := etree.NewElement("x:AttributeQuery")
		el.CreateAttr("xmlns:x", "urn:example")

		message := handlerAnswer(t, serve(handlerSOAPPost(soapLogoutEnvelope(t, el))))
		assert.Check(t, is.Equal(message.Tag, "LogoutResponse"))
	})

	t.Run("not an envelope", func(t *testing.T) {
		w := serve(handlerSOAPPost([]byte("<not-soap/>")))
		assert.Check(t, is.Equal(w.Code, http.StatusInternalServerError))
		assert.Check(t, is.Contains(w.Body.String(), "soapenv:Client"))
	})

	// A body over the limit is not parsed to choose a service, and the service refuses it for its size.
	t.Run("too large", func(t *testing.T) {
		message := queryServices[0].message(f)
		message.CreateElement("saml:Padding").SetText(strings.Repeat("a", soapMaxMessageSize))

		w := serve(queryPost(t, handlerTestSharedURL, message))
		assert.Check(t, is.Equal(w.Code, http.StatusInternalServerError))
		assert.Check(t, is.Contains(w.Body.String(), "soapenv:Client"))
	})

	// Requests that are not SOAP requests reach the single sign-on service, which refuses these as they hold no
	// request.
	t.Run("front channel", func(t *testing.T) {
		w := serve(httptest.NewRequest(http.MethodGet, handlerTestSharedURL, nil))
		assert.Check(t, is.Equal(w.Code, http.StatusBadRequest))
		assert.Check(t, !strings.Contains(w.Body.String(), "soapenv"))

		r := httptest.NewRequest(http.MethodPost, handlerTestSharedURL, strings.NewReader(url.Values{"SAMLRequest": {"AAAA"}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w = serve(r)
		assert.Check(t, is.Equal(w.Code, http.StatusBadRequest))
		assert.Check(t, !strings.Contains(w.Body.String(), "soapenv"))
	})

	t.Run("metadata", func(t *testing.T) {
		w := serve(httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/metadata", nil))
		assert.Check(t, is.Equal(w.Code, http.StatusOK))
		assert.Check(t, is.Contains(w.Body.String(), "EntityDescriptor"))
	})
}

// Services on the SOAP binding that share a path with no front-channel service refuse a request that is not of
// the binding as each would alone.
func TestHandlerSOAPServicesWithoutFrontChannel(t *testing.T) {
	const soapURL = "https://idp.example.com/saml/soap"

	f := newHandlerFixture(t, func(field string) string {
		switch field {
		case "MetadataURL", "SSOURL", "LogoutURL":
			return "https://idp.example.com/saml/" + field
		default:
			return soapURL
		}
	})

	handler := f.test.IDP.Handler()

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, soapURL, nil))
	assert.Check(t, is.Equal(w.Code, http.StatusMethodNotAllowed))
	assert.Check(t, is.Equal(w.Header().Get("Allow"), http.MethodPost))

	r := httptest.NewRequest(http.MethodPost, soapURL, strings.NewReader("SAMLRequest=AAAA"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	assert.Check(t, is.Equal(w.Code, http.StatusInternalServerError))
	assert.Check(t, is.Contains(w.Body.String(), "soapenv:Client"))

	message := queryServices[1].message(f)
	message.CreateAttr("Destination", soapURL)

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, queryPost(t, soapURL, signQueryElement(t, &f.test.SP, message)))
	assertQueryStatus(t, f.answer(t, w), StatusSuccess, "")
}

// No configuration makes Handler panic, as registering a path twice with a mux would.
func TestHandlerDoesNotPanicOnSharedPaths(t *testing.T) {
	t.Run("nothing set", func(t *testing.T) {
		assert.Check(t, (&IdentityProvider{}).Handler() != nil)

		f := newQueryFixture(t)
		f.test.IDP.MetadataURL, f.test.IDP.SSOURL = url.URL{}, url.URL{}

		w := httptest.NewRecorder()
		f.test.IDP.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/anything", nil))

		// Both URLs are served at "/", where the metadata comes first.
		assert.Check(t, is.Equal(w.Code, http.StatusOK))
		assert.Check(t, is.Contains(w.Body.String(), "EntityDescriptor"))
	})

	t.Run("every URL the same", func(t *testing.T) {
		f := newHandlerFixture(t, func(string) string { return handlerTestSharedURL })
		handler := f.test.IDP.Handler()

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, handlerTestSharedURL, nil))
		assert.Check(t, is.Contains(w.Body.String(), "EntityDescriptor"))

		message := queryServices[0].message(f)
		message.CreateAttr("Destination", handlerTestSharedURL)

		w = httptest.NewRecorder()
		handler.ServeHTTP(w, queryPost(t, handlerTestSharedURL, signQueryElement(t, &f.test.SP, message)))
		assertQueryStatus(t, f.answer(t, w), StatusSuccess, "")
	})
}
