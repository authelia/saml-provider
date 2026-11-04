package samlidp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml"
)

const expiryEntityID = "https://expiry.example.com/metadata"

// expiryMetadata returns service provider metadata with the given validUntil attributes on the
// EntityDescriptor and the SPSSODescriptor, each left out if empty, inside an EntitiesDescriptor
// with the given validUntil if group isn't empty.
func expiryMetadata(entity, role, group string) string {
	attr := func(value string) string {
		if value == "" {
			return ""
		}
		return ` validUntil="` + value + `"`
	}
	metadata := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + expiryEntityID + `"` + attr(entity) + `>` +
		`<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"` + attr(role) + `>` +
		`<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://expiry.example.com/acs" index="1"/>` +
		`</SPSSODescriptor></EntityDescriptor>`
	if group != "" {
		metadata = `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"` + attr(group) + `>` + metadata + `</EntitiesDescriptor>`
	}
	return metadata
}

func putExpiryService(test *ServerTest, metadata string) int {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "https://idp.example.com/services/expiry", strings.NewReader(metadata))
	test.Server.ServeHTTP(w, r)
	return w.Code
}

const (
	beforeNow = "2015-12-01T01:57:08Z"
	atNow     = "2015-12-01T01:57:09Z"
	afterNow  = "2015-12-01T01:57:10Z"
	zeroTime  = "0001-01-01T00:00:00Z"
)

// Metadata stops being valid at its validUntil, SAMLMeta §2.3.1 and §2.3.2, which covers the
// elements it contains.
func TestPutServiceRejectsExpiredMetadata(t *testing.T) {
	for name, tc := range map[string]struct {
		entity, role, group string
		code                int
	}{
		"no expiry":            {code: http.StatusNoContent},
		"entity not expired":   {entity: afterNow, code: http.StatusNoContent},
		"role not expired":     {role: afterNow, code: http.StatusNoContent},
		"group not expired":    {group: afterNow, code: http.StatusNoContent},
		"entity expired":       {entity: beforeNow, code: http.StatusBadRequest},
		"entity expires now":   {entity: atNow, code: http.StatusBadRequest},
		"role expired":         {entity: afterNow, role: beforeNow, code: http.StatusBadRequest},
		"group expired":        {entity: afterNow, group: beforeNow, code: http.StatusBadRequest},
		"group expires first":  {group: atNow, entity: afterNow, code: http.StatusBadRequest},
		"entity expires first": {entity: beforeNow, group: afterNow, code: http.StatusBadRequest},
		"zero time":            {entity: zeroTime, role: zeroTime, group: zeroTime, code: http.StatusNoContent},
		"zero group":           {entity: beforeNow, group: zeroTime, code: http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewServerTest(t)
			assert.Check(t, is.Equal(putExpiryService(test, expiryMetadata(tc.entity, tc.role, tc.group)), tc.code))

			_, err := test.Server.GetServiceProvider(nil, expiryEntityID)
			if tc.code == http.StatusNoContent {
				assert.Check(t, err)
			} else {
				assert.Check(t, errors.Is(err, os.ErrNotExist), "%v", err)
			}
		})
	}
}

// Metadata which was valid when it was registered stops being trusted once it expires, including the
// expiry of an EntitiesDescriptor around it.
func TestServiceStopsBeingTrustedWhenMetadataExpires(t *testing.T) {
	for name, metadata := range map[string]string{
		"entity": expiryMetadata(afterNow, "", ""),
		"role":   expiryMetadata("", afterNow, ""),
		"group":  expiryMetadata("", "", afterNow),
	} {
		t.Run(name, func(t *testing.T) {
			test := NewServerTest(t)
			assert.Assert(t, is.Equal(putExpiryService(test, metadata), http.StatusNoContent))
			_, err := test.Server.GetServiceProvider(nil, expiryEntityID)
			assert.Check(t, err)

			now := saml.TimeNow().Add(time.Second)
			saml.TimeNow = func() time.Time { return now }
			_, err = test.Server.GetServiceProvider(nil, expiryEntityID)
			assert.Check(t, errors.Is(err, os.ErrNotExist), "%v", err)
		})
	}
}

// Expired metadata in the store is refused when the server starts, just as if it were registered.
func TestStoredExpiredServiceIsNotTrusted(t *testing.T) {
	test := NewServerTest(t)
	assert.Assert(t, is.Equal(putExpiryService(test, expiryMetadata(afterNow, "", "")), http.StatusNoContent))

	now := saml.TimeNow().Add(time.Second)
	saml.TimeNow = func() time.Time { return now }
	server, err := New(Options{
		Certificate: test.Certificate,
		Key:         test.Key,
		Store:       &test.Store,
		URL:         test.Server.IDP.MetadataURL,
	})
	assert.NilError(t, err)
	_, err = server.GetServiceProvider(nil, expiryEntityID)
	assert.Check(t, errors.Is(err, os.ErrNotExist), "%v", err)
}

// The validUntil of a descriptor covers only that descriptor, so an expired one is left out while
// another stays in use.
func TestExpiredDescriptorIsLeftOut(t *testing.T) {
	test := NewServerTest(t)
	descriptor := func(validUntil, acs string) string {
		return `<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" validUntil="` + validUntil + `">` +
			`<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + acs + `" index="1"/>` +
			`</SPSSODescriptor>`
	}
	metadata := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + expiryEntityID + `">` +
		descriptor(beforeNow, "https://expiry.example.com/expired") + descriptor(afterNow, "https://expiry.example.com/current") +
		`</EntityDescriptor>`
	assert.Assert(t, is.Equal(putExpiryService(test, metadata), http.StatusNoContent))

	current, err := test.Server.GetServiceProvider(nil, expiryEntityID)
	assert.NilError(t, err)
	assert.Assert(t, is.Len(current.SPSSODescriptors, 1))
	assert.Check(t, is.Equal(current.SPSSODescriptors[0].AssertionConsumerServices[0].Location, "https://expiry.example.com/current"))

	// The stored metadata keeps both, as it was registered.
	assert.Check(t, is.Len(test.Server.serviceProviders[expiryEntityID].SPSSODescriptors, 2))

	now := saml.TimeNow().Add(time.Second)
	saml.TimeNow = func() time.Time { return now }
	_, err = test.Server.GetServiceProvider(nil, expiryEntityID)
	assert.Check(t, errors.Is(err, os.ErrNotExist), "%v", err)
}
