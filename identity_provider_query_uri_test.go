package saml

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const assertionURITestURL = "https://idp.example.com/saml/assertion"

// testURIRequesterAuthenticator is a URIRequesterAuthenticator which names a fixed service provider and counts
// how often it was asked.
type testURIRequesterAuthenticator struct {
	entityID string
	err      error
	calls    int
}

func (a *testURIRequesterAuthenticator) AuthenticateURIRequester(r *http.Request) (string, error) {
	if r == nil {
		panic("the authenticator must get the HTTP request")
	}

	a.calls++

	return a.entityID, a.err
}

// uriFixture is a queryFixture with the URI binding enabled, an authenticator that names the service provider of
// the fixture, a recording Observer, and a service provider with no encryption key, so that the default policy
// sends its assertions in plaintext.
type uriFixture struct {
	*queryFixture

	authenticator *testURIRequesterAuthenticator
	observer      *RecordingObserver
}

func newURIFixture(t *testing.T) *uriFixture {
	t.Helper()

	f := &uriFixture{
		queryFixture:  newQueryFixture(t),
		authenticator: &testURIRequesterAuthenticator{},
		observer:      &RecordingObserver{},
	}

	f.authenticator.entityID = f.test.SP.MetadataURL.String()
	f.test.IDP.AssertionURIURL = mustParseURL(assertionURITestURL)
	f.test.IDP.URIRequesterAuthenticator = f.authenticator
	f.test.IDP.Observer = f.observer
	f.metadata = stripEncryptionKeys

	return f
}

// stripEncryptionKeys removes every KeyDescriptor of the service provider that is not for signing.
func stripEncryptionKeys(metadata *EntityDescriptor) {
	descriptor := &metadata.SPSSODescriptors[0]

	signing := descriptor.KeyDescriptors[:0]
	for _, keyDescriptor := range descriptor.KeyDescriptors {
		if keyDescriptor.Use == "signing" {
			signing = append(signing, keyDescriptor)
		}
	}

	descriptor.KeyDescriptors = signing
}

func (f *uriFixture) get(rawQuery string) *httptest.ResponseRecorder {
	return f.do(http.MethodGet, rawQuery)
}

func (f *uriFixture) do(method, rawQuery string) *httptest.ResponseRecorder {
	target := assertionURITestURL
	if rawQuery != "" {
		target += "?" + rawQuery
	}

	w := httptest.NewRecorder()
	f.test.IDP.ServeAssertionURI(w, httptest.NewRequest(method, target, nil))

	return w
}

// lastEvent returns the only event of the request.
func (f *uriFixture) lastEvent(t *testing.T) Event {
	t.Helper()

	events := f.observer.Events()
	require.Len(t, events, 1)

	return events[0]
}

func assertNoCache(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()

	assert.Equal(t, "no-cache, no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
}

func TestServeAssertionURI(t *testing.T) {
	f := newURIFixture(t)
	stored := f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())
	before := elementString(t, stored)

	w := f.get("ID=" + queryTestStoredAssertionID)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/samlassertion+xml", w.Header().Get("Content-Type"))
	assertNoCache(t, w)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(w.Body.Bytes()))
	require.NotNil(t, doc.Root())
	assert.Equal(t, "Assertion", doc.Root().Tag)
	assert.Equal(t, before, elementString(t, doc.Root()), "it is returned as it was stored")

	assert.Equal(t, before, elementString(t, stored), "the stored assertion is not modified")
	assert.Nil(t, stored.Parent())
	assert.Equal(t, []string{queryTestStoredAssertionID}, f.store.gets)
	assert.Empty(t, f.store.saved)

	event := f.lastEvent(t)
	assert.Equal(t, EventAssertionURI, event.Kind)
	assert.Equal(t, OutcomeSuccess, event.Outcome)
	assert.Equal(t, f.test.SP.MetadataURL.String(), event.ServiceProvider)
	assert.True(t, event.Verified)
}

func TestServeAssertionURIMethod(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			f := newURIFixture(t)
			f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())

			w := f.do(method, "ID="+queryTestStoredAssertionID)

			assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
			assert.Equal(t, http.MethodGet, w.Header().Get("Allow"))
			assert.Equal(t, 0, f.authenticator.calls)
			assert.Empty(t, f.store.gets)
			assert.Equal(t, OutcomeFailure, f.lastEvent(t).Outcome)
		})
	}
}

func TestServeAssertionURIQuery(t *testing.T) {
	for _, rawQuery := range []string{"", "ID=", "ID=%20", "ID=a&ID=b", "ID=a&x=1", "id=" + queryTestStoredAssertionID} {
		t.Run(rawQuery, func(t *testing.T) {
			f := newURIFixture(t)
			f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())

			w := f.get(rawQuery)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assertNoCache(t, w)
			assert.Empty(t, w.Body.String())
			assert.Equal(t, 0, f.authenticator.calls)
			assert.Empty(t, f.store.gets)
			assert.Equal(t, OutcomeFailure, f.lastEvent(t).Outcome)
		})
	}

	t.Run("whitespace is collapsed", func(t *testing.T) {
		f := newURIFixture(t)
		f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())

		w := f.get("ID=%20" + queryTestStoredAssertionID + "%20")

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, []string{queryTestStoredAssertionID}, f.store.gets)
	})
}

func TestServeAssertionURIRequester(t *testing.T) {
	testCases := []struct {
		name   string
		setup  func(f *uriFixture)
		code   int
		lookup bool
	}{
		{
			name:  "not authenticated",
			setup: func(f *uriFixture) { f.authenticator.entityID = "" },
			code:  http.StatusForbidden,
		},
		{
			name:  "authenticator fails",
			setup: func(f *uriFixture) { f.authenticator.entityID, f.authenticator.err = "", errors.New("boom") },
			code:  http.StatusInternalServerError,
		},
		{
			name:  "unknown service provider",
			setup: func(f *uriFixture) { f.authenticator.entityID = queryTestUnknownIssuerID },
			code:  http.StatusForbidden,
		},
		{
			name:  "service provider lookup fails",
			setup: func(f *uriFixture) { f.providerErr = errors.New("boom") },
			code:  http.StatusInternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newURIFixture(t)
			f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())
			tc.setup(f)

			w := f.get("ID=" + queryTestStoredAssertionID)

			assert.Equal(t, tc.code, w.Code)
			assertNoCache(t, w)
			assert.Empty(t, w.Body.String())
			assert.Equal(t, 1, f.authenticator.calls)
			assert.Empty(t, f.store.gets, "the store is not asked for an unauthenticated requester")

			event := f.lastEvent(t)
			assert.Equal(t, OutcomeFailure, event.Outcome)
			assert.False(t, event.Verified)
		})
	}
}

func TestServeAssertionURIExpiredMetadata(t *testing.T) {
	f := newURIFixture(t)
	f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())
	f.metadata = func(metadata *EntityDescriptor) {
		stripEncryptionKeys(metadata)
		metadata.ValidUntil = TimeNow().Add(-time.Hour)
	}

	w := f.get("ID=" + queryTestStoredAssertionID)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Empty(t, w.Body.String())
	assert.Empty(t, f.store.gets, "the store is not asked for a requester whose metadata has expired")

	events := f.observer.Events()
	require.Len(t, events, 2)
	assert.Equal(t, EventMetadataExpired, events[0].Kind)
	assert.Equal(t, EventAssertionURI, events[1].Kind)
	assert.Equal(t, OutcomeFailure, events[1].Outcome)
	assert.False(t, events[1].Verified)
}

// failingResponseWriter is an http.ResponseWriter whose body can't be written, as when the connection is lost.
type failingResponseWriter struct {
	*httptest.ResponseRecorder
}

func (failingResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("connection reset")
}

func TestServeAssertionURIWriteFails(t *testing.T) {
	f := newURIFixture(t)
	f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())

	w := failingResponseWriter{httptest.NewRecorder()}
	f.test.IDP.ServeAssertionURI(w, httptest.NewRequest(http.MethodGet, assertionURITestURL+"?ID="+queryTestStoredAssertionID, nil))

	assert.Equal(t, http.StatusOK, w.Code, "the status was sent before the body failed")

	event := f.lastEvent(t)
	assert.Equal(t, EventAssertionURI, event.Kind)
	assert.Equal(t, OutcomeFailure, event.Outcome)
	assert.True(t, event.Verified)
	require.Error(t, event.Err)
	assert.ErrorContains(t, errors.Unwrap(event.Err), "connection reset")
}

func TestServeAssertionURIHidesOtherServiceProviders(t *testing.T) {
	answer := func(t *testing.T, setup func(f *uriFixture)) *httptest.ResponseRecorder {
		t.Helper()

		f := newURIFixture(t)
		setup(f)

		w := f.get("ID=" + queryTestStoredAssertionID)
		assert.Equal(t, OutcomeFailure, f.lastEvent(t).Outcome)

		return w
	}

	unknown := answer(t, func(*uriFixture) {})
	require.Equal(t, http.StatusNotFound, unknown.Code)
	assertNoCache(t, unknown)

	testCases := []struct {
		name  string
		setup func(f *uriFixture)
	}{
		{
			name: "issued to another service provider",
			setup: func(f *uriFixture) {
				f.storeAssertion(t, queryTestStoredAssertionID, queryTestOtherProviderID)
			},
		},
		{
			name: "store returns another assertion",
			setup: func(f *uriFixture) {
				other := f.storeAssertion(t, "id-else", f.test.SP.MetadataURL.String())
				f.store.assertions[queryTestStoredAssertionID] = storedAssertion{f.test.SP.MetadataURL.String(), other, TimeNow()}
			},
		},
		{
			name: "store returns something that is not an assertion",
			setup: func(f *uriFixture) {
				el := etree.NewElement("saml:Response")
				el.CreateAttr("xmlns:saml", samlAssertionNS)
				el.CreateAttr("ID", queryTestStoredAssertionID)
				f.store.assertions = map[string]storedAssertion{queryTestStoredAssertionID: {f.test.SP.MetadataURL.String(), el, TimeNow()}}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := answer(t, tc.setup)

			assert.Equal(t, unknown.Code, w.Code)
			assert.Equal(t, unknown.Header(), w.Header())
			assert.Equal(t, unknown.Body.String(), w.Body.String())
		})
	}

	t.Run("store fails", func(t *testing.T) {
		w := answer(t, func(f *uriFixture) { f.store.getErr = errors.New("boom") })
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestServeAssertionURIRefusesWhenEncrypted(t *testing.T) {
	policy := func(encryption AssertionEncryption) func(f *uriFixture) {
		return func(f *uriFixture) {
			f.test.IDP.IssuancePolicy = DefaultIssuancePolicy{ServiceProviders: map[string]ServiceProviderIssuance{
				f.test.SP.MetadataURL.String(): {AssertionEncryption: &encryption},
			}}
		}
	}

	keepKeys := func(f *uriFixture) { f.metadata = nil }

	testCases := []struct {
		name  string
		setup []func(f *uriFixture)
		code  int
	}{
		{name: "default policy with an encryption key", setup: []func(*uriFixture){keepKeys}, code: http.StatusForbidden},
		{name: "required encryption without a key", setup: []func(*uriFixture){policy(RequireAssertionEncryption)}, code: http.StatusForbidden},
		{name: "no assertion encryption with a key", setup: []func(*uriFixture){keepKeys, policy(NoAssertionEncryption)}, code: http.StatusOK},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newURIFixture(t)
			f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())

			for _, setup := range tc.setup {
				setup(f)
			}

			w := f.get("ID=" + queryTestStoredAssertionID)

			assert.Equal(t, tc.code, w.Code)

			if tc.code != http.StatusOK {
				assert.NotContains(t, w.Body.String(), queryTestStoredAssertionID)
				assert.Equal(t, OutcomeFailure, f.lastEvent(t).Outcome)
			}
		})
	}
}

func TestServeAssertionURIDisabled(t *testing.T) {
	testCases := map[string]func(f *uriFixture){
		"no store":         func(f *uriFixture) { f.test.IDP.AssertionStore = nil },
		"no authenticator": func(f *uriFixture) { f.test.IDP.URIRequesterAuthenticator = nil },
	}

	for name, setup := range testCases {
		t.Run(name, func(t *testing.T) {
			f := newURIFixture(t)
			f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())
			setup(f)

			w := f.get("ID=" + queryTestStoredAssertionID)

			assert.Equal(t, http.StatusNotFound, w.Code)
			assert.False(t, strings.Contains(w.Body.String(), queryTestStoredAssertionID))
			assert.Equal(t, 0, f.authenticator.calls)
			assert.Empty(t, f.store.gets)
		})
	}
}

func TestAssertionURIMetadata(t *testing.T) {
	soap := Endpoint{Binding: SOAPBinding, Location: assertionIDRequestTestURL}
	uri := Endpoint{Binding: URIBinding, Location: assertionURITestURL}

	services := func(t *testing.T, f *uriFixture) [][]Endpoint {
		t.Helper()

		metadata := f.test.IDP.Metadata()
		require.Len(t, metadata.AttributeAuthorityDescriptors, 1)
		require.Len(t, metadata.AuthnAuthorityDescriptors, 1)

		return [][]Endpoint{
			metadata.IDPSSODescriptors[0].AssertionIDRequestServices,
			metadata.AttributeAuthorityDescriptors[0].AssertionIDRequestServices,
			metadata.AuthnAuthorityDescriptors[0].AssertionIDRequestServices,
		}
	}

	testCases := []struct {
		name     string
		setup    func(f *uriFixture)
		expected []Endpoint
	}{
		{name: "both", setup: func(*uriFixture) {}, expected: []Endpoint{soap, uri}},
		{name: "uri only", setup: func(f *uriFixture) { f.test.IDP.AssertionIDRequestServiceURL = url.URL{} }, expected: []Endpoint{uri}},
		{name: "no authenticator", setup: func(f *uriFixture) { f.test.IDP.URIRequesterAuthenticator = nil }, expected: []Endpoint{soap}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newURIFixture(t)
			tc.setup(f)

			for _, endpoints := range services(t, f) {
				assert.Equal(t, tc.expected, endpoints)
			}
		})
	}
}

func TestHandlerServesAssertionURI(t *testing.T) {
	get := func(t *testing.T, f *uriFixture, location string) *httptest.ResponseRecorder {
		t.Helper()

		w := httptest.NewRecorder()
		f.test.IDP.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, location+"?ID="+queryTestStoredAssertionID, nil))

		return w
	}

	t.Run("own path", func(t *testing.T) {
		f := newURIFixture(t)
		f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())

		w := get(t, f, assertionURITestURL)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, assertionURIContentType, w.Header().Get("Content-Type"))
	})

	t.Run("shared path", func(t *testing.T) {
		f := newURIFixture(t)
		f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())
		f.test.IDP.AssertionURIURL = mustParseURL(assertionIDRequestTestURL)

		w := get(t, f, assertionIDRequestTestURL)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, assertionURIContentType, w.Header().Get("Content-Type"))

		w = httptest.NewRecorder()
		message := signQueryElement(t, &f.test.SP, f.assertionIDRequest(queryTestStoredAssertionID).Element())
		f.test.IDP.Handler().ServeHTTP(w, queryPost(t, assertionIDRequestTestURL, message))

		response := f.answer(t, w)
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Len(t, response.Assertions, 1)
	})

	t.Run("disabled", func(t *testing.T) {
		f := newURIFixture(t)
		f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())
		f.test.IDP.URIRequesterAuthenticator = nil

		w := get(t, f, assertionURITestURL)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestServeAssertionURIIssuancePolicyFails(t *testing.T) {
	f := newURIFixture(t)
	f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())
	f.test.IDP.IssuancePolicy = issuancePolicyFunc(func(IssuanceRequest) (Issuance, error) {
		return Issuance{}, errors.New("boom")
	})

	w := f.get("ID=" + queryTestStoredAssertionID)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, w.Body.String())

	event := f.lastEvent(t)
	assert.Equal(t, OutcomeFailure, event.Outcome)
	assert.Equal(t, ErrServerError.TopLevelField, event.Err.TopLevelField)
}
