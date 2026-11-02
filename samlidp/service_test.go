package samlidp

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
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
	assert.Check(t, is.Error(err, `services "a" and "b" both register entity ID "https://one.example.com/metadata": remove one of them from the store`))
}

func testServiceMetadata(entityID, id string) string {
	return `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + entityID + `">` +
		`<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://` + id + `.example.net/acs" index="1"/>` +
		`</SPSSODescriptor></EntityDescriptor>`
}

// reversedListStore lists keys in the opposite of sorted order.
type reversedListStore struct {
	*MemoryStore
}

func (s reversedListStore) List(prefix string) ([]string, error) {
	keys, err := s.MemoryStore.List(prefix)
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	return keys, err
}

func TestNewReportsDuplicateServicesInSortedOrder(t *testing.T) {
	store := &MemoryStore{}
	for _, id := range []string{"a", "b"} {
		metadata, err := getSPMetadata(strings.NewReader(testServiceMetadata("https://one.example.com/metadata", id)))
		assert.NilError(t, err)
		assert.NilError(t, store.Put("/services/"+id, &Service{Metadata: *metadata}))
	}

	_, err := New(Options{
		URL:   url.URL{Scheme: "https", Host: "idp.example.com"},
		Store: reversedListStore{store},
	})
	assert.Check(t, is.Error(err, `services "a" and "b" both register entity ID "https://one.example.com/metadata": remove one of them from the store`))
}

// failingGetStore fails reads of one key with an error other than ErrNotFound.
type failingGetStore struct {
	Store
	key string
}

func (s failingGetStore) Get(key string, value interface{}) error {
	if key == s.key {
		return errors.New("store unavailable")
	}
	return s.Store.Get(key, value)
}

func TestPutServiceFailsWhenThePreviousRecordCannotBeRead(t *testing.T) {
	const (
		oldEntityID = "https://old.example.com/metadata"
		newEntityID = "https://new.example.com/metadata"
	)

	test := NewServerTest(t)
	put := func(entityID string) int {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("PUT", "https://idp.example.com/services/a", strings.NewReader(testServiceMetadata(entityID, "a")))
		test.Server.ServeHTTP(w, r)
		return w.Code
	}
	assert.Check(t, is.Equal(http.StatusNoContent, put(oldEntityID)))

	test.Server.Store = failingGetStore{Store: &test.Store, key: "/services/a"}
	assert.Check(t, is.Equal(http.StatusInternalServerError, put(newEntityID)))

	stored := Service{}
	assert.NilError(t, test.Store.Get("/services/a", &stored))
	assert.Check(t, is.Equal(oldEntityID, stored.Metadata.EntityID), "the record must not be overwritten")

	_, err := test.Server.GetServiceProvider(nil, oldEntityID)
	assert.Check(t, err, "the old entity ID stays registered with the unchanged record")
	_, err = test.Server.GetServiceProvider(nil, newEntityID)
	assert.Check(t, is.Equal(os.ErrNotExist, err), "the new entity ID must not be registered")
}
