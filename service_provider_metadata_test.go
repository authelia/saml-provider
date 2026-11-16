package saml

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestCurrentMetadataNil(t *testing.T) {
	assert.Check(t, CurrentMetadata(nil, time.Now()) == nil)
}

func TestCurrentMetadata(t *testing.T) {
	now := time.Date(2015, 12, 1, 1, 57, 9, 0, time.UTC)
	before, after := now.Add(-time.Second), now.Add(time.Second)

	descriptor := func(validUntil *time.Time, acs string) SPSSODescriptor {
		d := SPSSODescriptor{AssertionConsumerServices: []IndexedEndpoint{{Binding: HTTPPostBinding, Location: acs, Index: 1}}}
		d.ValidUntil = validUntil
		return d
	}

	zero := time.Time{}

	for name, tc := range map[string]struct {
		entity      time.Time
		descriptors []SPSSODescriptor
		locations   []string
	}{
		"no expiry":              {descriptors: []SPSSODescriptor{descriptor(nil, "a")}, locations: []string{"a"}},
		"entity not expired":     {entity: after, descriptors: []SPSSODescriptor{descriptor(nil, "a")}, locations: []string{"a"}},
		"entity expired":         {entity: before, descriptors: []SPSSODescriptor{descriptor(nil, "a")}},
		"entity expires now":     {entity: now, descriptors: []SPSSODescriptor{descriptor(nil, "a")}},
		"descriptor expired":     {descriptors: []SPSSODescriptor{descriptor(&before, "a")}},
		"descriptor expires now": {descriptors: []SPSSODescriptor{descriptor(&now, "a")}},
		"one of two expired":     {descriptors: []SPSSODescriptor{descriptor(&before, "a"), descriptor(&after, "b")}, locations: []string{"b"}},
		"zero time is none":      {descriptors: []SPSSODescriptor{descriptor(&zero, "a")}, locations: []string{"a"}},
		"no descriptors":         {},
	} {
		t.Run(name, func(t *testing.T) {
			metadata := &EntityDescriptor{EntityID: "https://sp.example.com/metadata", ValidUntil: tc.entity, SPSSODescriptors: tc.descriptors}
			original := len(metadata.SPSSODescriptors)

			current := CurrentMetadata(metadata, now)
			// The input is not modified.
			assert.Check(t, is.Len(metadata.SPSSODescriptors, original))

			if tc.locations == nil {
				assert.Check(t, is.Nil(current))
				return
			}
			assert.Assert(t, current != nil)
			var locations []string
			for _, d := range current.SPSSODescriptors {
				locations = append(locations, d.AssertionConsumerServices[0].Location)
			}
			assert.Check(t, is.DeepEqual(locations, tc.locations))
		})
	}
}

// Expired metadata is refused at every entry point as for an unknown service provider.
func TestIDPRefusesExpiredServiceProviderMetadata(t *testing.T) {
	expire := func(test *IdentityProviderTest) {
		metadata := test.SP.Metadata()
		expired := TimeNow().Add(-time.Minute)
		metadata.ValidUntil = expired
		test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
			GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) { return metadata, nil },
		}
	}

	t.Run("sso", func(t *testing.T) {
		test := signatureTestIDP(t)
		expire(test)
		u := signedRedirectURL(t, test)
		assert.Check(t, is.ErrorContains(validateURL(t, test, u.String()), "cannot handle request from unknown service provider "+test.SP.MetadataURL.String()))
	})

	t.Run("idp-initiated", func(t *testing.T) {
		test := NewIdentityProviderTest(t)
		expire(test)
		test.IDP.SessionProvider = &mockSessionProvider{
			GetSessionFunc: func(_ http.ResponseWriter, _ *http.Request, _ *IdpAuthnRequest) *Session {
				return &Session{ID: "session-id", NameID: "alice"}
			},
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/idp-initiated", nil)
		test.IDP.ServeIDPInitiated(w, r, test.SP.MetadataURL.String(), "")
		assert.Check(t, is.Equal(w.Code, http.StatusNotFound))
	})

	t.Run("logout", func(t *testing.T) {
		test, provider := logoutTestIDP(t)
		expire(test)
		r, _ := redirectLogoutRequest(t, &test.SP, nil)
		assert.Check(t, is.Equal(serveSLO(test, r).Code, http.StatusBadRequest))
		assert.Check(t, is.Len(provider.terminated, 0))
	})
}

func TestParseServiceProviderMetadata(t *testing.T) {
	good := "" +
		"<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2013-03-10T00:32:19.104Z\" cacheDuration=\"PT1H\" entityID=\"http://localhost:5000/e087a985171710fb9fb30f30f41384f9/saml2/metadata/\">\n" +
		"</EntityDescriptor>"
	_, err := ParseServiceProviderMetadata([]byte(good))
	assert.Check(t, err)

	bad := "" +
		"<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" ::attr=\"foo\" validUntil=\"2013-03-10T00:32:19.104Z\" cacheDuration=\"PT1H\" entityID=\"http://localhost:5000/e087a985171710fb9fb30f30f41384f9/saml2/metadata/\">]]>\n" +
		"</EntityDescriptor>"
	_, err = ParseServiceProviderMetadata([]byte(bad))
	assert.Check(t, err != nil)

	group := "<EntitiesDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\">" +
		"<EntityDescriptor entityID=\"idp\"><IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"></IDPSSODescriptor></EntityDescriptor>" +
		"<EntityDescriptor entityID=\"sp\"><SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"></SPSSODescriptor></EntityDescriptor>" +
		"</EntitiesDescriptor>"
	metadata, err := ParseServiceProviderMetadata([]byte(group))
	assert.NilError(t, err)
	assert.Check(t, is.Equal(metadata.EntityID, "sp"))

	none := "<EntitiesDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\">" +
		"<EntityDescriptor entityID=\"idp\"><IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"></IDPSSODescriptor></EntityDescriptor>" +
		"</EntitiesDescriptor>"
	_, err = ParseServiceProviderMetadata([]byte(none))
	assert.Check(t, is.Error(err, "metadata contained no service provider metadata"))
}

func TestParseServiceProviderMetadataGroupValidUntil(t *testing.T) {
	early, late := "2020-01-01T00:00:00Z", "2030-01-01T00:00:00Z"

	for name, tc := range map[string]struct {
		group, entity, expected string
	}{
		"group earlier": {early, late, early},
		"group later":   {late, early, early},
		"group absent":  {"", early, early},
		"entity absent": {early, "", early},
		"neither":       {"", "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			attr := func(v string) string {
				if v == "" {
					return ""
				}
				return fmt.Sprintf(" validUntil=%q", v)
			}
			data := fmt.Sprintf("<EntitiesDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"%s>"+
				"<EntityDescriptor entityID=\"sp\"%s><SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"></SPSSODescriptor></EntityDescriptor>"+
				"</EntitiesDescriptor>", attr(tc.group), attr(tc.entity))

			metadata, err := ParseServiceProviderMetadata([]byte(data))
			assert.NilError(t, err)

			if tc.expected == "" {
				assert.Check(t, metadata.ValidUntil.IsZero())
				return
			}
			expected, err := time.Parse(time.RFC3339, tc.expected)
			assert.NilError(t, err)
			assert.Check(t, metadata.ValidUntil.Equal(expected), metadata.ValidUntil)
		})
	}
}

func TestCheckServiceProviderMetadata(t *testing.T) {
	now := time.Date(2015, 12, 1, 1, 57, 9, 0, time.UTC)
	before, after := now.Add(-time.Second), now.Add(time.Second)

	descriptor := func(validUntil *time.Time, acs string) SPSSODescriptor {
		d := SPSSODescriptor{AssertionConsumerServices: []IndexedEndpoint{{Binding: HTTPPostBinding, Location: acs, Index: 1}}}
		d.ValidUntil = validUntil
		return d
	}

	withUse := descriptor(nil, "https://sp.example.com/acs")
	withUse.KeyDescriptors = []KeyDescriptor{{Use: "other"}}

	for name, tc := range map[string]struct {
		insecure    bool
		entity      time.Time
		descriptors []SPSSODescriptor
		err         string
		insecureErr bool
	}{
		"https":                 {descriptors: []SPSSODescriptor{descriptor(nil, "https://sp.example.com/acs")}},
		"unrecognized key use":  {descriptors: []SPSSODescriptor{withUse}, err: "other"},
		"no descriptors":        {err: "no service provider metadata"},
		"expired":               {entity: before, descriptors: []SPSSODescriptor{descriptor(nil, "https://sp.example.com/acs")}, err: "expired"},
		"http only":             {descriptors: []SPSSODescriptor{descriptor(nil, "http://sp.example.com/acs")}, insecureErr: true},
		"https only in expired": {descriptors: []SPSSODescriptor{descriptor(&before, "https://sp.example.com/acs")}, err: "expired"},
		"http in expired":       {descriptors: []SPSSODescriptor{descriptor(&before, "http://sp.example.com/acs"), descriptor(&after, "https://sp.example.com/acs")}},
		"loopback http":         {descriptors: []SPSSODescriptor{descriptor(nil, "http://localhost:8080/acs")}},
		"insecure allowed":      {insecure: true, descriptors: []SPSSODescriptor{descriptor(nil, "http://sp.example.com/acs")}},
		"no post acs":           {descriptors: []SPSSODescriptor{{AssertionConsumerServices: []IndexedEndpoint{{Binding: HTTPArtifactBinding, Location: "http://sp.example.com/acs"}}}}},
	} {
		t.Run(name, func(t *testing.T) {
			idp := &IdentityProvider{AllowInsecureServiceProviderEndpoints: tc.insecure}
			metadata := &EntityDescriptor{ValidUntil: tc.entity, SPSSODescriptors: tc.descriptors}

			err := idp.CheckServiceProviderMetadata(metadata, now)
			switch {
			case tc.insecureErr:
				assert.Check(t, errors.Is(err, ErrInsecureEndpoint), err)
			case tc.err != "":
				assert.Check(t, err != nil)
				if err != nil {
					assert.Check(t, is.Contains(err.Error(), tc.err))
				}
			default:
				assert.NilError(t, err)
			}
		})
	}
}
