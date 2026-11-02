package saml

import (
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml/xmlenc"
)

const interopEntityID = "https://sp.example.com/saml2/metadata"

func interopACS(index int, binding, location string, isDefault *bool) IndexedEndpoint {
	return IndexedEndpoint{Index: index, Binding: binding, Location: location, IsDefault: isDefault}
}

func interopSP(descriptors ...SPSSODescriptor) *EntityDescriptor {
	return &EntityDescriptor{EntityID: interopEntityID, SPSSODescriptors: descriptors}
}

func interopDescriptor(endpoints ...IndexedEndpoint) SPSSODescriptor {
	return SPSSODescriptor{AssertionConsumerServices: endpoints}
}

func interopIDP(t *testing.T, metadata *EntityDescriptor) *IdentityProviderTest {
	t.Helper()
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) {
			if metadata == nil {
				return nil, os.ErrNotExist
			}
			return metadata, nil
		},
	}
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
			return &Session{ID: "f00d", NameID: "alice", UserName: "alice"}
		},
	}
	return test
}

func interopValidate(test *IdentityProviderTest, attrs string) (*IdpAuthnRequest, error) {
	buf := `<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="id-1" Version="2.0" ` + attrs +
		` IssueInstant="` + TimeNow().UTC().Format(time.RFC3339) + `">` + hardeningIssuer + `</AuthnRequest>`
	return hardeningValidate(test, []byte(buf))
}

func TestIDPACSSelection(t *testing.T) {
	const (
		post     = HTTPPostBinding
		artifact = HTTPArtifactBinding
		redirect = HTTPRedirectBinding
	)
	yes, no := true, false

	for _, tc := range []struct {
		name     string
		attrs    string
		metadata *EntityDescriptor
		location string
	}{
		{
			name:     "url shared by artifact and post uses post",
			attrs:    `AssertionConsumerServiceURL="https://sp/acs" ProtocolBinding="` + post + `"`,
			metadata: interopSP(interopDescriptor(interopACS(0, artifact, "https://sp/acs", nil), interopACS(1, post, "https://sp/acs", nil))),
			location: "https://sp/acs",
		},
		{
			name:     "url with only artifact is rejected",
			attrs:    `AssertionConsumerServiceURL="https://sp/acs"`,
			metadata: interopSP(interopDescriptor(interopACS(0, artifact, "https://sp/acs", nil))),
		},
		{
			name:     "index of an artifact endpoint is rejected",
			attrs:    `AssertionConsumerServiceIndex="0"`,
			metadata: interopSP(interopDescriptor(interopACS(0, artifact, "https://sp/a", nil), interopACS(1, post, "https://sp/b", nil))),
		},
		{
			name:     "index of a post endpoint",
			attrs:    `AssertionConsumerServiceIndex="1"`,
			metadata: interopSP(interopDescriptor(interopACS(0, artifact, "https://sp/a", nil), interopACS(1, post, "https://sp/b", nil))),
			location: "https://sp/b",
		},
		{
			name:     "default skips redirect listed first",
			metadata: interopSP(interopDescriptor(interopACS(0, redirect, "https://sp/a", nil), interopACS(1, post, "https://sp/b", nil))),
			location: "https://sp/b",
		},
		{
			name:     "default skips redirect marked default",
			metadata: interopSP(interopDescriptor(interopACS(0, redirect, "https://sp/a", &yes), interopACS(1, post, "https://sp/b", nil))),
			location: "https://sp/b",
		},
		{
			name:     "no post endpoint is rejected",
			metadata: interopSP(interopDescriptor(interopACS(0, redirect, "https://sp/a", nil))),
		},
		{
			name:     "explicit default wins",
			metadata: interopSP(interopDescriptor(interopACS(0, post, "https://sp/a", nil), interopACS(1, post, "https://sp/b", &yes))),
			location: "https://sp/b",
		},
		{
			name:     "unset is preferred over false",
			metadata: interopSP(interopDescriptor(interopACS(0, post, "https://sp/a", &no), interopACS(1, post, "https://sp/b", nil))),
			location: "https://sp/b",
		},
		{
			name:     "all false uses the first",
			metadata: interopSP(interopDescriptor(interopACS(0, post, "https://sp/a", &no), interopACS(1, post, "https://sp/b", &no))),
			location: "https://sp/a",
		},
		{
			name: "explicit default in a later descriptor wins",
			metadata: interopSP(
				interopDescriptor(interopACS(0, post, "https://sp/a", nil)),
				interopDescriptor(interopACS(1, post, "https://sp/b", &yes)),
			),
			location: "https://sp/b",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := interopValidate(interopIDP(t, tc.metadata), tc.attrs)
			if tc.location == "" {
				assert.Check(t, is.ErrorContains(err, "cannot find assertion consumer service"))
				return
			}
			assert.NilError(t, err)
			assert.Check(t, is.Equal(tc.location, req.ACSEndpoint.Location))
			assert.Check(t, is.Equal(post, req.ACSEndpoint.Binding))
			assert.Check(t, req.SPSSODescriptor != nil)
		})
	}
}

func TestIDPInitiatedUsesDefaultACS(t *testing.T) {
	yes := true
	test := interopIDP(t, interopSP(interopDescriptor(
		interopACS(0, HTTPRedirectBinding, "https://sp/redirect", &yes),
		interopACS(1, HTTPPostBinding, "https://sp/legacy", nil),
		interopACS(2, HTTPPostBinding, "https://sp/new", &yes),
	)))

	w := httptest.NewRecorder()
	test.IDP.ServeIDPInitiated(w, httptest.NewRequest("GET", "https://idp.example.com/x", nil), interopEntityID, "")
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, strings.Contains(w.Body.String(), `action="https://sp/new"`), w.Body.String())
}

func TestIDPAssertionDeclaresQNamePrefixes(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req := &IdpAuthnRequest{Now: TimeNow(), IDP: &test.IDP, RequestBuffer: hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer)}
	req.HTTPRequest, _ = http.NewRequest("POST", "https://idp.example.com/saml/sso", nil)
	assert.NilError(t, req.Validate())
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice", UserName: "alice"}))
	assert.NilError(t, req.MakeAssertionEl())

	doc := etree.NewDocument()
	doc.SetRoot(req.AssertionEl)
	plaintext, err := xmlenc.Decrypt(test.SPKey, doc.FindElement("//EncryptedAssertion/EncryptedData"))
	assert.NilError(t, err)

	// The plaintext stands alone once decrypted, so every prefix it uses must be declared in it.
	decrypted := etree.NewDocument()
	assert.NilError(t, decrypted.ReadFromBytes(plaintext))
	assert.Check(t, is.Equal("http://www.w3.org/2001/XMLSchema", decrypted.Root().SelectAttrValue("xmlns:xs", "")), string(plaintext))
	assert.Check(t, strings.Contains(string(plaintext), `xsi:type="xs:string"`), string(plaintext))

	// Exclusive canonicalization drops the declaration, so the signature must still verify.
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{test.Certificate}})
	ctx.Clock = dsig.NewFakeClockAt(test.Certificate.NotBefore)
	_, err = ctx.Validate(decrypted.Root())
	assert.Check(t, err)
}

func TestAttributeValueOmitsEmptyType(t *testing.T) {
	assert.Check(t, (&AttributeValue{Value: "a"}).Element().SelectAttr("xsi:type") == nil)
	assert.Check(t, is.Equal("xs:string", (&AttributeValue{Type: "xs:string", Value: "a"}).Element().SelectAttrValue("xsi:type", "")))
}

func TestIDPOmitsEmptyAttributeStatement(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	assert.NilError(t, err)

	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice"}))
	assert.Check(t, is.Len(req.Assertion.AttributeStatements, 0))

	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice", UserName: "alice"}))
	assert.Check(t, is.Len(req.Assertion.AttributeStatements, 1))
}

func TestRoleCacheDurationUsesXSDDuration(t *testing.T) {
	const doc = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp">` +
		`<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" cacheDuration="PT1H"/>` +
		`<AffiliationDescriptor affiliationOwnerID="https://sp" cacheDuration="PT2H"/>` +
		`</EntityDescriptor>`

	metadata := EntityDescriptor{}
	assert.NilError(t, xml.Unmarshal([]byte(doc), &metadata))
	assert.Assert(t, is.Len(metadata.SPSSODescriptors, 1))
	assert.Check(t, is.Equal(Duration(time.Hour), metadata.SPSSODescriptors[0].CacheDuration))
	assert.Assert(t, metadata.AffiliationDescriptor != nil)
	assert.Check(t, is.Equal(Duration(2*time.Hour), metadata.AffiliationDescriptor.CacheDuration))

	buf, err := xml.Marshal(metadata)
	assert.NilError(t, err)
	assert.Check(t, strings.Contains(string(buf), `cacheDuration="PT1H"`), string(buf))
	assert.Check(t, strings.Contains(string(buf), `cacheDuration="PT2H"`), string(buf))

	buf, err = xml.Marshal(EntityDescriptor{AffiliationDescriptor: &AffiliationDescriptor{}})
	assert.NilError(t, err)
	assert.Check(t, !strings.Contains(string(buf), `cacheDuration`), "a zero duration must be omitted: %s", buf)
}

func TestDurationJSONAcceptsXSDDuration(t *testing.T) {
	var duration Duration
	assert.NilError(t, json.Unmarshal([]byte(`"PT1H"`), &duration))
	assert.Check(t, is.Equal(Duration(time.Hour), duration))
}

func TestRoleCacheDurationJSON(t *testing.T) {
	// Stored services are JSON, written by earlier versions when this field was a time.Duration.
	metadata := EntityDescriptor{}
	assert.NilError(t, json.Unmarshal([]byte(`{"SPSSODescriptors":[{"CacheDuration":3600000000000}]}`), &metadata))
	assert.Check(t, is.Equal(Duration(time.Hour), metadata.SPSSODescriptors[0].CacheDuration))

	for _, duration := range []Duration{0, Duration(time.Hour)} {
		buf, err := json.Marshal(SPSSODescriptor{SSODescriptor: SSODescriptor{RoleDescriptor: RoleDescriptor{CacheDuration: duration}}})
		assert.NilError(t, err)
		assert.Check(t, strings.Contains(string(buf), fmt.Sprintf(`"CacheDuration":%d`, int64(duration))), string(buf))

		decoded := SPSSODescriptor{}
		assert.NilError(t, json.Unmarshal(buf, &decoded))
		assert.Check(t, is.Equal(duration, decoded.CacheDuration))
	}
}
