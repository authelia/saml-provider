package saml

import (
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/dsig"
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
			name:     "index with url is rejected",
			attrs:    `AssertionConsumerServiceIndex="1" AssertionConsumerServiceURL="https://sp/b"`,
			metadata: interopSP(interopDescriptor(interopACS(1, post, "https://sp/b", nil))),
		},
		{
			name:     "index with protocol binding is rejected",
			attrs:    `AssertionConsumerServiceIndex="1" ProtocolBinding="` + post + `"`,
			metadata: interopSP(interopDescriptor(interopACS(1, post, "https://sp/b", nil))),
		},
		{
			name:     "unsupported protocol binding with an unlisted url is rejected",
			attrs:    `AssertionConsumerServiceURL="https://attacker/acs" ProtocolBinding="` + artifact + `"`,
			metadata: interopSP(interopDescriptor(interopACS(0, post, "https://sp/b", nil))),
		},
		{
			name:     "unsupported protocol binding with no post endpoint is rejected",
			attrs:    `ProtocolBinding="` + artifact + `"`,
			metadata: interopSP(interopDescriptor(interopACS(0, artifact, "https://sp/a", nil))),
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
				assert.True(t, errors.Is(err, ErrNoResponseEndpoint), "%v", err)
				assert.Contains(t, ToStatusError(err).Debug(), "cannot find assertion consumer service")
				assert.False(t, req.Respondable(), "a request with no usable endpoint can't be answered with a status")

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.location, req.ACSEndpoint.Location)
			assert.Equal(t, post, req.ACSEndpoint.Binding)
			assert.NotNil(t, req.SPSSODescriptor)
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
	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, strings.Contains(w.Body.String(), `action="https://sp/new"`), w.Body.String())
}

func TestIDPAssertionDeclaresQNamePrefixes(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	// An attribute is needed for the xs prefix to be used.
	test.IDP.AttributeReleasePolicy = releaseEveryAttribute
	req := &IdpAuthnRequest{Now: TimeNow(), IDP: &test.IDP, RequestBuffer: hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer)}
	req.HTTPRequest, _ = http.NewRequest("POST", "https://idp.example.com/saml/sso", nil)
	require.NoError(t, req.Validate())
	require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice", UserName: "alice"}))
	require.NoError(t, req.MakeAssertionEl())

	doc := etree.NewDocument()
	doc.SetRoot(req.AssertionEl)
	plaintext, err := xmlenc.Decrypt(test.SPKey, doc.FindElement("//EncryptedAssertion/EncryptedData"))
	require.NoError(t, err)

	// The plaintext stands alone once decrypted, so every prefix it uses must be declared in it.
	decrypted := etree.NewDocument()
	require.NoError(t, decrypted.ReadFromBytes(plaintext))
	assert.Equal(t, "http://www.w3.org/2001/XMLSchema", decrypted.Root().SelectAttrValue("xmlns:xs", ""), string(plaintext))
	assert.True(t, strings.Contains(string(plaintext), `xsi:type="xs:string"`), string(plaintext))

	// Exclusive canonicalization drops the declaration, so the signature must still verify.
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{test.Certificate}})
	ctx.Clock = dsig.NewFakeClockAt(test.Certificate.NotBefore)
	_, err = ctx.Validate(decrypted.Root())
	assert.NoError(t, err)
}

func TestAttributeValueOmitsEmptyType(t *testing.T) {
	assert.True(t, (&AttributeValue{Value: "a"}).Element().SelectAttr("xsi:type") == nil)
	assert.Equal(t, "xs:string", (&AttributeValue{Type: "xs:string", Value: "a"}).Element().SelectAttrValue("xsi:type", ""))
}

func TestIDPOmitsEmptyAttributeStatement(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	require.NoError(t, err)

	require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice"}))
	assert.Len(t, req.Assertion.AttributeStatements, 0)

	// The service provider requests no attributes, so none are released.
	require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice", UserName: "alice"}))
	assert.Len(t, req.Assertion.AttributeStatements, 0)

	test.IDP.AttributeReleasePolicy = releaseEveryAttribute

	require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice", UserName: "alice"}))
	assert.Len(t, req.Assertion.AttributeStatements, 1)

	test.IDP.AttributeReleasePolicy = attributeReleasePolicyFunc(func(AttributeReleaseRequest, *Session, []Attribute) ([]Attribute, error) {
		return []Attribute{}, nil
	})

	require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice", UserName: "alice"}))
	assert.Len(t, req.Assertion.AttributeStatements, 0)
}

func TestCacheDurationPreservesLexicalForm(t *testing.T) {
	for _, value := range []string{"P1M", "P1Y2M3DT4H5M6.5S", "-P1D", "PT0S", "PT1H"} {
		doc := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp">` +
			`<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" cacheDuration="` + value + `"/>` +
			`<AffiliationDescriptor affiliationOwnerID="https://sp" cacheDuration="` + value + `"/>` +
			`</EntityDescriptor>`

		metadata := EntityDescriptor{}
		require.NoError(t, xml.Unmarshal([]byte(doc), &metadata))
		require.Len(t, metadata.SPSSODescriptors, 1)
		assert.Equal(t, XSDDuration(value), metadata.SPSSODescriptors[0].CacheDuration)
		require.True(t, metadata.AffiliationDescriptor != nil && metadata.AffiliationDescriptor.CacheDuration != nil)
		assert.Equal(t, XSDDuration(value), *metadata.AffiliationDescriptor.CacheDuration)

		buf, err := xml.Marshal(metadata)
		require.NoError(t, err)
		assert.Equal(t, 2, strings.Count(string(buf), `cacheDuration="`+value+`"`), string(buf))
	}
}

func TestCacheDurationAbsentIsOmitted(t *testing.T) {
	const doc = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp">` +
		`<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>` +
		`<AffiliationDescriptor affiliationOwnerID="https://sp"/>` +
		`</EntityDescriptor>`

	metadata := EntityDescriptor{}
	require.NoError(t, xml.Unmarshal([]byte(doc), &metadata))
	assert.Nil(t, metadata.AffiliationDescriptor.CacheDuration)

	buf, err := xml.Marshal(metadata)
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(buf), `cacheDuration`), string(buf))

	empty := XSDDuration("")
	buf, err = xml.Marshal(AffiliationDescriptor{CacheDuration: &empty})
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(buf), `cacheDuration`), string(buf))
}

func TestCacheDurationRejectsInvalidValue(t *testing.T) {
	for _, value := range []string{"", "1h", "P", "PT1H "} {
		doc := `<AffiliationDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" affiliationOwnerID="https://sp" cacheDuration="` + value + `"/>`
		assert.True(t, xml.Unmarshal([]byte(doc), &AffiliationDescriptor{}) != nil, value)
	}

	var duration XSDDuration
	assert.True(t, json.Unmarshal([]byte(`"1h"`), &duration) != nil)
	assert.True(t, json.Unmarshal([]byte(`true`), &duration) != nil)
}

func TestCacheDurationJSON(t *testing.T) {
	// Stored services are JSON, written by earlier versions when these fields were a time.Duration.
	metadata := EntityDescriptor{}
	require.NoError(t, json.Unmarshal([]byte(`{"SPSSODescriptors":[{"CacheDuration":3600000000000}],"AffiliationDescriptor":{"CacheDuration":7200000000000}}`), &metadata))
	assert.Equal(t, XSDDuration("PT1H"), metadata.SPSSODescriptors[0].CacheDuration)
	assert.Equal(t, XSDDuration("PT2H"), *metadata.AffiliationDescriptor.CacheDuration)

	legacy := EntityDescriptor{}
	require.NoError(t, json.Unmarshal([]byte(`{"SPSSODescriptors":[{"CacheDuration":0}],"AffiliationDescriptor":{"CacheDuration":0}}`), &legacy))
	buf, err := xml.Marshal(legacy)
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(buf), `cacheDuration`), "an unset legacy duration must stay absent: %s", buf)

	month := XSDDuration("P1M")
	buf, err = json.Marshal(AffiliationDescriptor{CacheDuration: &month})
	require.NoError(t, err)

	decoded := AffiliationDescriptor{}
	require.NoError(t, json.Unmarshal(buf, &decoded))
	assert.Equal(t, month, *decoded.CacheDuration)

	buf, err = json.Marshal(AffiliationDescriptor{})
	require.NoError(t, err)

	decoded = AffiliationDescriptor{}
	require.NoError(t, json.Unmarshal(buf, &decoded))
	assert.Nil(t, decoded.CacheDuration)
}
