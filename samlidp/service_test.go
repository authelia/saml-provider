package samlidp

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"
)

func TestServicesCrud(t *testing.T) {
	test := NewServerTest(t)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/services/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("{\"services\":[]}\n", w.Body.String()))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("PUT", "https://idp.example.com/services/sp",
		bytes.NewReader(golden.Get(t, "sp_metadata.xml")))
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/services/sp", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	golden.Assert(t, w.Body.String(), "sp_metadata.xml")

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/services/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("{\"services\":[\"sp\"]}\n", w.Body.String()))

	assert.Check(t, is.Len(test.Server.serviceProviders, 2))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("DELETE", "https://idp.example.com/services/sp", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/services/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("{\"services\":[]}\n", w.Body.String()))
	assert.Check(t, is.Len(test.Server.serviceProviders, 1))
}

func TestServiceEntityIDOwnership(t *testing.T) {
	type step struct {
		method   string
		id       string
		entityID string
		code     int
	}

	testCases := []struct {
		name       string
		steps      []step
		registered map[string]string
	}{
		{
			name: "another service cannot take over an entity ID",
			steps: []step{
				{method: http.MethodPut, id: "victim", entityID: "https://victim.example.com/metadata", code: http.StatusNoContent},
				{method: http.MethodPut, id: "attacker", entityID: "https://victim.example.com/metadata", code: http.StatusConflict},
			},
			registered: map[string]string{"https://victim.example.com/metadata": "victim"},
		},
		{
			name: "the owning service can update its metadata",
			steps: []step{
				{method: http.MethodPut, id: "sp", entityID: "https://sp.example.org/metadata", code: http.StatusNoContent},
				{method: http.MethodPut, id: "sp", entityID: "https://sp.example.org/metadata", code: http.StatusNoContent},
			},
			registered: map[string]string{"https://sp.example.org/metadata": "sp"},
		},
		{
			name: "changing the entity ID deregisters the old one",
			steps: []step{
				{method: http.MethodPut, id: "a", entityID: "https://one.example.com/metadata", code: http.StatusNoContent},
				{method: http.MethodPut, id: "a", entityID: "https://two.example.com/metadata", code: http.StatusNoContent},
			},
			registered: map[string]string{"https://one.example.com/metadata": "", "https://two.example.com/metadata": "a"},
		},
		{
			name: "changing the entity ID releases the old one",
			steps: []step{
				{method: http.MethodPut, id: "a", entityID: "https://one.example.com/metadata", code: http.StatusNoContent},
				{method: http.MethodPut, id: "a", entityID: "https://two.example.com/metadata", code: http.StatusNoContent},
				{method: http.MethodPut, id: "b", entityID: "https://one.example.com/metadata", code: http.StatusNoContent},
			},
			registered: map[string]string{"https://one.example.com/metadata": "b", "https://two.example.com/metadata": "a"},
		},
		{
			name: "delete deregisters the entity ID",
			steps: []step{
				{method: http.MethodPut, id: "a", entityID: "https://one.example.com/metadata", code: http.StatusNoContent},
				{method: http.MethodDelete, id: "a", code: http.StatusNoContent},
			},
			registered: map[string]string{"https://one.example.com/metadata": ""},
		},
		{
			name: "delete leaves an entity ID owned by another service",
			steps: []step{
				{method: http.MethodPut, id: "a", entityID: "https://one.example.com/metadata", code: http.StatusNoContent},
				{method: http.MethodPut, id: "a", entityID: "https://two.example.com/metadata", code: http.StatusNoContent},
				{method: http.MethodPut, id: "b", entityID: "https://one.example.com/metadata", code: http.StatusNoContent},
				{method: http.MethodDelete, id: "a", code: http.StatusNoContent},
			},
			registered: map[string]string{"https://one.example.com/metadata": "b", "https://two.example.com/metadata": ""},
		},
		{
			name: "an entity ID registered outside the API cannot be taken over",
			steps: []step{
				{method: http.MethodPut, id: "attacker", entityID: "https://sp.example.com/saml2/metadata", code: http.StatusConflict},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			test := NewServerTest(t)

			for _, step := range tc.steps {
				w := httptest.NewRecorder()
				r := httptest.NewRequest(step.method, "https://idp.example.com/services/"+step.id, strings.NewReader(testServiceMetadata(step.entityID, step.id)))
				r.SetPathValue("id", step.id)

				switch step.method {
				case http.MethodPut:
					test.Server.HandlePutService(w, r)
				case http.MethodDelete:
					test.Server.HandleDeleteService(w, r)
				}

				assert.Check(t, is.Equal(step.code, w.Code), "%s %s", step.method, step.id)
			}

			for entityID, id := range tc.registered {
				metadata, err := test.Server.GetServiceProvider(nil, entityID)
				if id == "" {
					assert.Check(t, errors.Is(err, os.ErrNotExist), "%s: got %v", entityID, err)
					continue
				}

				assert.NilError(t, err)
				assert.Check(t, is.Equal("https://"+id+".example.net/acs", metadata.SPSSODescriptors[0].AssertionConsumerServices[0].Location))
			}

			metadata, err := test.Server.GetServiceProvider(nil, "https://sp.example.com/saml2/metadata")
			assert.NilError(t, err)
			assert.Check(t, is.Equal("https://sp.example.com/saml2/acs", metadata.SPSSODescriptors[0].AssertionConsumerServices[0].Location))
		})
	}
}

func TestNewRejectsDuplicateServiceEntityID(t *testing.T) {
	store := &MemoryStore{}
	for _, id := range []string{"a", "b"} {
		metadata, err := getSPMetadata(strings.NewReader(testServiceMetadata("https://one.example.com/metadata", id)))
		assert.NilError(t, err)
		assert.NilError(t, store.Put("/services/"+id, &Service{Metadata: *metadata}))
	}

	_, err := New(Options{
		URL:   url.URL{Scheme: "https", Host: "idp.example.com"},
		Store: store,
	})
	assert.Check(t, is.Error(err, `services "a" and "b" both register entity ID "https://one.example.com/metadata"`))
}

func testServiceMetadata(entityID, id string) string {
	return `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + entityID + `">` +
		`<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://` + id + `.example.net/acs" index="1"/>` +
		`</SPSSODescriptor></EntityDescriptor>`
}
