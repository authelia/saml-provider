package saml

import (
	"crypto/x509"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/golden"
)

const (
	testNSMD     = "urn:oasis:names:tc:SAML:2.0:metadata"
	testNSMDUI   = "urn:oasis:names:tc:SAML:metadata:ui"
	testNSMDAttr = "urn:oasis:names:tc:SAML:metadata:attribute"
	testNSMDRPI  = "urn:oasis:names:tc:SAML:metadata:rpi"
	testNSShibMD = "urn:mace:shibboleth:metadata:1.0"
	testNSSAML   = "urn:oasis:names:tc:SAML:2.0:assertion"
)

// parseExtensionsFixture parses the metadata of a service provider as a federation such as InCommon publishes it.
func parseExtensionsFixture(t *testing.T) *EntityDescriptor {
	t.Helper()

	metadata, err := ParseServiceProviderMetadata(golden.Get(t, "TestMetadataExtensions_sp.xml"))
	require.NoError(t, err)

	return metadata
}

func TestParseMetadataExtensionsOfAFederationServiceProvider(t *testing.T) {
	metadata := parseExtensionsFixture(t)

	require.NotNil(t, metadata.Extensions)

	assert.Equal(t, &RegistrationInfo{
		RegistrationAuthority: "https://incommon.org",
		RegistrationInstant:   time.Date(2019, 3, 14, 18, 22, 5, 0, time.UTC),
		RegistrationPolicies:  []LocalizedURI{{Lang: "en", Value: "http://incommon.org/participation-agreement"}},
	}, metadata.Extensions.RegistrationInfo)

	assert.Equal(t, &PublicationInfo{
		Publisher:       "https://incommon.org",
		CreationInstant: time.Date(2026, 11, 16, 20, 0, 0, 0, time.UTC),
		PublicationID:   "20261116T200000",
		UsagePolicies:   []LocalizedURI{{Lang: "en", Value: "https://incommon.org/terms"}},
	}, metadata.Extensions.PublicationInfo)

	require.NotNil(t, metadata.Extensions.EntityAttributes)
	assert.Equal(t, []Attribute{
		{
			Name:       "http://macedir.org/entity-category",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{Value: "http://refeds.org/category/research-and-scholarship"},
				{Type: "xs:string", Value: "http://www.geant.net/uri/dataprotection-code-of-conduct/v1"},
			},
		},
		{
			Name:       "urn:oasis:names:tc:SAML:attribute:assurance-certification",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values:     []AttributeValue{{Value: "https://refeds.org/sirtfi"}},
		},
		{
			Name:       "urn:oasis:names:tc:SAML:profiles:subject-id:req",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values:     []AttributeValue{{Value: "pairwise-id"}},
		},
	}, metadata.Extensions.EntityAttributes.Attributes)

	// The algorithm support extension is modelled, so only the extension that isn't is kept as it was.
	assert.Len(t, metadata.Extensions.DigestMethods, 1)
	assert.Len(t, metadata.Extensions.Other, 1)

	role := metadata.SPSSODescriptors[0]
	require.NotNil(t, role.Extensions)

	assert.Equal(t, &UIInfo{
		DisplayNames: []LocalizedName{
			{Lang: "en", Value: "Example University Research Wiki"},
			{Lang: "de", Value: "Forschungswiki der Beispieluniversität"},
		},
		Descriptions:         []LocalizedName{{Lang: "en", Value: "Collaboration wiki for research projects."}},
		Keywords:             []Keywords{{Lang: "en", Values: []string{"wiki", "research", "collaboration tools"}}},
		InformationURLs:      []LocalizedURI{{Lang: "en", Value: "https://wiki.example.edu/about"}},
		PrivacyStatementURLs: []LocalizedURI{{Lang: "en", Value: "https://wiki.example.edu/privacy"}},
		Logos: []Logo{
			{URL: "https://wiki.example.edu/logo-80x60.png", Height: 60, Width: 80},
			{URL: "https://wiki.example.edu/logo-de-160x120.png", Height: 120, Width: 160, Lang: "de"},
		},
	}, role.Extensions.UIInfo)

	assert.Equal(t, &DiscoHints{
		IPHints:          []string{"192.0.2.0/24"},
		DomainHints:      []string{"example.edu"},
		GeolocationHints: []string{"geo:47.37328,8.531126"},
	}, role.Extensions.DiscoHints)

	assert.Len(t, role.Extensions.Other, 1)

	// The entity has more than one ContactPerson, and the REFEDS contact type of the security contact, which is an
	// attribute named contactType in another namespace, is not mistaken for the contactType of SAMLMeta §2.3.2.2.
	assert.Equal(t, []ContactPerson{
		{ContactType: "technical", GivenName: "Wiki", SurName: "Admins", EmailAddresses: []string{"mailto:wiki-admins@example.edu"}},
		{
			ContactType:       "other",
			REFEDSContactType: REFEDSSecurityContactType,
			GivenName:         "Security Response Team",
			EmailAddresses:    []string{"mailto:security@example.edu"},
		},
	}, metadata.ContactPeople)

	assert.Equal(t, "Example University", metadata.Organization.OrganizationDisplayNames[0].Value)
}

func TestServiceProviderEntityAttributeAccessors(t *testing.T) {
	metadata := parseExtensionsFixture(t)

	assert.Equal(t, []string{
		"http://refeds.org/category/research-and-scholarship",
		"http://www.geant.net/uri/dataprotection-code-of-conduct/v1",
	}, metadata.EntityCategories())
	assert.True(t, metadata.HasEntityCategory(EntityCategoryResearchAndScholarship))
	assert.True(t, metadata.HasEntityCategory(EntityCategoryCodeOfConductV1))
	assert.False(t, metadata.HasEntityCategory(EntityCategoryPersonalized))
	assert.Equal(t, []string{AssuranceCertificationSIRTFI}, metadata.EntityAttributeValues(AssuranceCertificationAttributeName))
	assert.Len(t, metadata.EntityAttributeValues("urn:example:absent"), 0)
	assert.Equal(t, SubjectIDRequirementPairwiseID, metadata.SubjectIDRequirement())

	// Accessors are safe on metadata with no extensions, and on nil.
	empty := &EntityDescriptor{}
	assert.Len(t, empty.EntityCategories(), 0)
	assert.Equal(t, SubjectIDRequirementUnspecified, empty.SubjectIDRequirement())
	assert.Nil(t, empty.UIInfo())
	assert.Equal(t, SubjectIDRequirementUnspecified, (*EntityDescriptor)(nil).SubjectIDRequirement())
}

func TestSubjectIDRequirement(t *testing.T) {
	testCases := []struct {
		name     string
		values   []string
		expected SubjectIDRequirement
	}{
		{name: "subject-id", values: []string{"subject-id"}, expected: SubjectIDRequirementSubjectID},
		{name: "pairwise-id", values: []string{"pairwise-id"}, expected: SubjectIDRequirementPairwiseID},
		{name: "none", values: []string{"none"}, expected: SubjectIDRequirementNone},
		{name: "any", values: []string{"any"}, expected: SubjectIDRequirementAny},
		{name: "surrounding whitespace", values: []string{"\n  any\n"}, expected: SubjectIDRequirementAny},
		{name: "no value", values: nil, expected: SubjectIDRequirementUnspecified},
		{name: "unknown value", values: []string{"eduPersonTargetedID"}, expected: SubjectIDRequirementUnspecified},
		{name: "wrong case", values: []string{"Any"}, expected: SubjectIDRequirementUnspecified},
		{name: "conflicting values", values: []string{"subject-id", "pairwise-id"}, expected: SubjectIDRequirementUnspecified},
		{name: "repeated value", values: []string{"pairwise-id", "pairwise-id"}, expected: SubjectIDRequirementPairwiseID},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attribute := Attribute{Name: SubjectIDRequirementAttributeName, NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"}
			for _, value := range tc.values {
				attribute.Values = append(attribute.Values, AttributeValue{Value: value})
			}

			metadata := &EntityDescriptor{Extensions: &Extensions{EntityAttributes: &EntityAttributes{Attributes: []Attribute{attribute}}}}

			assert.Equal(t, tc.expected, metadata.SubjectIDRequirement())
		})
	}
}

func TestServiceProviderUIInfoAccessors(t *testing.T) {
	metadata := parseExtensionsFixture(t)

	ui := metadata.UIInfo()
	require.NotNil(t, ui)

	assert.Equal(t, "Example University Research Wiki", metadata.DisplayName())
	assert.Equal(t, "Forschungswiki der Beispieluniversität", metadata.DisplayName("de-AT", "en"))
	assert.Equal(t, "Example University Research Wiki", metadata.DisplayName("fr"))
	assert.Equal(t, "https://wiki.example.edu/privacy", ui.PrivacyStatementURL("de"))
	assert.Equal(t, "Collaboration wiki for research projects.", ui.Description())
	assert.Equal(t, "https://wiki.example.edu/about", ui.InformationURL("en"))

	// A logo in a requested language is preferred, then one with no language.
	assert.Equal(t, []Logo{{URL: "https://wiki.example.edu/logo-de-160x120.png", Height: 120, Width: 160, Lang: "de"}}, ui.LocalizedLogos("de"))
	assert.Equal(t, []Logo{{URL: "https://wiki.example.edu/logo-80x60.png", Height: 60, Width: 80}}, ui.LocalizedLogos("fr"))

	// Without MDUI the name of the service in the AttributeConsumingService is used, then that of the organization.
	metadata.SPSSODescriptors[0].Extensions = nil
	assert.Equal(t, "Research Wiki", metadata.DisplayName("en"))

	metadata.SPSSODescriptors[0].AttributeConsumingServices = nil
	assert.Equal(t, "Example University", metadata.DisplayName("en"))

	metadata.Organization = nil
	assert.Equal(t, "", metadata.DisplayName("en"))
}

// childrenOf returns the namespace and local name of each child element of el.
func childrenOf(el *etree.Element) []xml.Name {
	children := el.ChildElements()

	names := make([]xml.Name, 0, len(children))
	for _, child := range children {
		names = append(names, xml.Name{Space: child.NamespaceURI(), Local: child.Tag})
	}

	return names
}

func TestMetadataExtensionsRoundTrip(t *testing.T) {
	metadata := parseExtensionsFixture(t)

	buf, err := xml.MarshalIndent(metadata, "", "  ")
	require.NoError(t, err)

	// What was marshalled is well formed, each element is in its namespace, and the elements that aren't modelled
	// are kept with their attributes and content.
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(buf))

	extensions := doc.Root().ChildElements()[0]
	assert.Equal(t, "Extensions", extensions.Tag)
	assert.Equal(t, testNSMD, extensions.NamespaceURI())
	assert.Equal(t, []xml.Name{
		{Space: testNSMDRPI, Local: "RegistrationInfo"},
		{Space: testNSMDRPI, Local: "PublicationInfo"},
		{Space: testNSMDAttr, Local: "EntityAttributes"},
		{Space: "urn:oasis:names:tc:SAML:metadata:algsupport", Local: "DigestMethod"},
		{Space: "http://eduid.cz/schema/metadata/1.0", Local: "RepublishRequest"},
	}, childrenOf(extensions))

	digestMethod := extensions.ChildElements()[3]
	assert.Equal(t, "http://www.w3.org/2001/04/xmlenc#sha256", digestMethod.SelectAttrValue("Algorithm", ""))

	target := extensions.ChildElements()[4].ChildElements()[0]
	assert.Equal(t, "RepublishTarget", target.Tag)
	assert.Equal(t, "http://eduid.cz/schema/metadata/1.0", target.NamespaceURI())
	assert.Equal(t, "http://edugain.org/", target.Text())

	roleExtensions := doc.Root().FindElement("./SPSSODescriptor/Extensions")
	require.NotNil(t, roleExtensions)
	assert.Equal(t, []xml.Name{
		{Space: testNSMDUI, Local: "UIInfo"},
		{Space: testNSMDUI, Local: "DiscoHints"},
		{Space: "urn:oasis:names:tc:SAML:profiles:SSO:request-init", Local: "RequestInitiator"},
	}, childrenOf(roleExtensions))
	assert.Equal(t, "https://wiki.example.edu/Shibboleth.sso/Login", roleExtensions.ChildElements()[2].SelectAttrValue("Location", ""))

	// The schema puts Extensions before the keys of a role, and the organization and contacts after the roles.
	assert.Equal(t, "Extensions", doc.Root().FindElement("./SPSSODescriptor").ChildElements()[0].Tag)

	security := doc.Root().FindElements("./ContactPerson")[1]
	assert.Equal(t, "other", security.SelectAttrValue("contactType", ""))

	var refeds string

	for _, attr := range security.Attr {
		if attr.Key == "contactType" && attr.NamespaceURI() == "http://refeds.org/metadata" {
			refeds = attr.Value
		}
	}

	assert.Equal(t, REFEDSSecurityContactType, refeds)
	assert.Nil(t, security.FindElement("./Company"))

	// Parsing what was marshalled gives what was parsed the first time.
	var again EntityDescriptor
	require.NoError(t, xml.Unmarshal(buf, &again))
	assert.Equal(t, metadata, &again)
}

func TestMetadataExtensionsMarshalWithConventionalPrefixes(t *testing.T) {
	metadata := &EntityDescriptor{
		EntityID: "https://idp.example.org/metadata",
		Extensions: &Extensions{
			RegistrationInfo: &RegistrationInfo{
				RegistrationAuthority: "https://federation.example.org",
				RegistrationInstant:   time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC),
				RegistrationPolicies:  []LocalizedURI{{Lang: "en", Value: "https://federation.example.org/policy"}},
			},
			EntityAttributes: &EntityAttributes{Attributes: []Attribute{{
				Name:       EntityCategorySupportAttributeName,
				NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				Values: []AttributeValue{
					{Value: EntityCategoryResearchAndScholarship},
					{Type: "xs:string", Value: EntityCategoryCodeOfConductV1},
				},
			}}},
		},
		IDPSSODescriptors: []IDPSSODescriptor{{
			SSODescriptor: SSODescriptor{RoleDescriptor: RoleDescriptor{
				ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
				Extensions: &Extensions{
					Scopes: []Scope{{Value: "example.org"}},
					UIInfo: &UIInfo{
						DisplayNames: []LocalizedName{{Lang: "en", Value: "Example & Co"}},
						Keywords:     []Keywords{{Lang: "en", Values: []string{"sso", "single sign-on"}}},
						Logos:        []Logo{{URL: "https://idp.example.org/logo.png", Height: 60, Width: 80, Lang: "en"}},
					},
					DiscoHints: &DiscoHints{DomainHints: []string{"example.org"}},
				},
			}},
		}},
	}

	buf, err := xml.Marshal(metadata)
	require.NoError(t, err)

	out := string(buf)

	// The serialization that Shibboleth and SimpleSAMLphp publish and document: each extension with its
	// conventional prefix, declared on the extension itself so that it stands alone.
	for _, expected := range []string{
		`<mdrpi:RegistrationInfo xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" registrationAuthority="https://federation.example.org" registrationInstant="2026-11-17T00:00:00Z">` +
			`<mdrpi:RegistrationPolicy xml:lang="en">https://federation.example.org/policy</mdrpi:RegistrationPolicy></mdrpi:RegistrationInfo>`,
		`<mdattr:EntityAttributes xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
			`<saml:Attribute Name="http://macedir.org/entity-category-support" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">` +
			`<saml:AttributeValue>http://refeds.org/category/research-and-scholarship</saml:AttributeValue>` +
			`<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">http://www.geant.net/uri/dataprotection-code-of-conduct/v1</saml:AttributeValue>` +
			`</saml:Attribute></mdattr:EntityAttributes>`,
		`<mdui:UIInfo xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui">` +
			`<mdui:DisplayName xml:lang="en">Example &amp; Co</mdui:DisplayName>` +
			`<mdui:Keywords xml:lang="en">sso single+sign-on</mdui:Keywords>` +
			`<mdui:Logo height="60" width="80" xml:lang="en">https://idp.example.org/logo.png</mdui:Logo></mdui:UIInfo>`,
		`<mdui:DiscoHints xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"><mdui:DomainHint>example.org</mdui:DomainHint></mdui:DiscoHints>`,
		`<shibmd:Scope xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" regexp="false">example.org</shibmd:Scope>`,
	} {
		assert.True(t, strings.Contains(out, expected), "missing %s in %s", expected, out)
	}

	// A namespace aware parser, which is what a peer uses, resolves every one of them.
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(buf))

	assert.Equal(t, []xml.Name{
		{Space: testNSMDRPI, Local: "RegistrationInfo"},
		{Space: testNSMDAttr, Local: "EntityAttributes"},
	}, childrenOf(doc.Root().FindElement("./Extensions")))
	assert.Equal(t, testNSSAML, doc.Root().FindElement("./Extensions/EntityAttributes/Attribute/AttributeValue").NamespaceURI())
	assert.Equal(t, []xml.Name{
		{Space: testNSMDUI, Local: "UIInfo"},
		{Space: testNSMDUI, Local: "DiscoHints"},
		{Space: testNSShibMD, Local: "Scope"},
	}, childrenOf(doc.Root().FindElement("./IDPSSODescriptor/Extensions")))

	var again EntityDescriptor
	require.NoError(t, xml.Unmarshal(buf, &again))
	assert.Equal(t, metadata.Extensions, again.Extensions)
	assert.Equal(t, metadata.IDPSSODescriptors[0].Extensions, again.IDPSSODescriptors[0].Extensions)
}

func TestEmptyMetadataExtensionsAreNotMarshalled(t *testing.T) {
	// SAMLMeta §2.2.1 requires Extensions to have at least one child.
	buf, err := xml.Marshal(&EntityDescriptor{
		EntityID:   "https://idp.example.org/metadata",
		Extensions: &Extensions{UIInfo: &UIInfo{}, DiscoHints: &DiscoHints{}, EntityAttributes: &EntityAttributes{}},
	})
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(buf), "Extensions"), string(buf))
}

func TestMetadataExtensionsOfAnAggregate(t *testing.T) {
	const aggregate = `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" Name="urn:example:federation">` +
		`<md:Extensions><mdrpi:PublicationInfo publisher="https://federation.example.org" creationInstant="2026-11-17T01:02:03Z"/></md:Extensions>` +
		`<md:EntityDescriptor entityID="https://sp.example.org/"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.org/acs" index="0"/></md:SPSSODescriptor></md:EntityDescriptor>` +
		`</md:EntitiesDescriptor>`

	var group EntitiesDescriptor
	require.NoError(t, xml.Unmarshal([]byte(aggregate), &group))
	require.NotNil(t, group.Extensions)
	assert.Equal(t, &PublicationInfo{
		Publisher:       "https://federation.example.org",
		CreationInstant: time.Date(2026, 11, 17, 1, 2, 3, 0, time.UTC),
	}, group.Extensions.PublicationInfo)

	buf, err := xml.Marshal(group)
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(buf),
		`<Extensions><mdrpi:PublicationInfo xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" publisher="https://federation.example.org" creationInstant="2026-11-17T01:02:03Z"></mdrpi:PublicationInfo></Extensions>`), string(buf))
}

func TestSignedMetadataWithExtensionsFromAFederationIsVerified(t *testing.T) {
	TimeNow = func() time.Time { return time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC) }

	_, cert := negotiationKey()
	verifier := &MetadataVerifier{Certificates: []*x509.Certificate{cert}}

	fixture := strings.Replace(string(golden.Get(t, "TestMetadataExtensions_sp.xml")),
		`entityID="https://wiki.example.edu/shibboleth"`, `entityID="https://wiki.example.edu/shibboleth" ID="sp1"`, 1)

	verified, err := verifier.Verify([]byte(signMetadataXML(t, fixture)))
	require.NoError(t, err)

	// The extensions are read from the XML that the signature covers, and are the same as those of the fixture.
	metadata, err := ParseServiceProviderMetadata(verified)
	require.NoError(t, err)

	expected := parseExtensionsFixture(t)
	assert.Equal(t, expected.Extensions, metadata.Extensions)
	assert.Equal(t, expected.SPSSODescriptors[0].Extensions, metadata.SPSSODescriptors[0].Extensions)
	assert.Equal(t, expected.ContactPeople, metadata.ContactPeople)
	assert.Equal(t, SubjectIDRequirementPairwiseID, metadata.SubjectIDRequirement())

	// A change to an extension breaks the signature.
	tampered := strings.Replace(signMetadataXML(t, fixture), "pairwise-id", "subject-id", 1)
	_, err = verifier.Verify([]byte(tampered))
	assert.NotNil(t, err)
}

// federationMetadataInfo is what a deployment of SAML2Int publishes about its identity provider.
func federationMetadataInfo() MetadataInfo {
	return MetadataInfo{
		UIInfo: &UIInfo{
			DisplayNames:         []LocalizedName{{Lang: "en", Value: "Example Identity Provider"}},
			Descriptions:         []LocalizedName{{Lang: "en", Value: "Single sign-on for Example."}},
			Logos:                []Logo{{URL: "https://idp.example.com/logo.png", Height: 60, Width: 80}},
			InformationURLs:      []LocalizedURI{{Lang: "en", Value: "https://idp.example.com/about"}},
			PrivacyStatementURLs: []LocalizedURI{{Lang: "en", Value: "https://idp.example.com/privacy"}},
		},
		DiscoHints: &DiscoHints{DomainHints: []string{"example.com"}},
		Organization: &Organization{
			OrganizationNames:        []LocalizedName{{Lang: "en", Value: "Example"}},
			OrganizationDisplayNames: []LocalizedName{{Lang: "en", Value: "Example Inc."}},
			OrganizationURLs:         []LocalizedURI{{Lang: "en", Value: "https://www.example.com/"}},
		},
		ContactPeople: []ContactPerson{
			{ContactType: "technical", GivenName: "Identity Team", EmailAddresses: []string{"mailto:idp@example.com"}},
			{ContactType: "other", REFEDSContactType: REFEDSSecurityContactType, EmailAddresses: []string{"mailto:security@example.com"}},
		},
		ErrorURL: "https://idp.example.com/error",
		Scopes:   []string{"example.com", "example.org"},
		EntityAttributes: []Attribute{
			{
				Name:       AssuranceCertificationAttributeName,
				NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				Values:     []AttributeValue{{Value: AssuranceCertificationSIRTFI}},
			},
			{
				Name:       EntityCategorySupportAttributeName,
				NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				Values:     []AttributeValue{{Value: EntityCategoryResearchAndScholarship}},
			},
		},
	}
}

func TestIDPMetadataPublishesOnlyAlgorithmSupportByDefault(t *testing.T) {
	test := NewIdentityProviderTest(t)

	metadata := test.IDP.Metadata()

	// The algorithms that are accepted on a signature are always known, and nothing else is.
	require.NotNil(t, metadata.Extensions)
	assert.Equal(t, &Extensions{
		DigestMethods:  metadata.Extensions.DigestMethods,
		SigningMethods: metadata.Extensions.SigningMethods,
	}, metadata.Extensions)
	assert.Nil(t, metadata.Organization)
	assert.Len(t, metadata.ContactPeople, 0)
	assert.Nil(t, metadata.IDPSSODescriptors[0].Extensions)
	assert.Equal(t, "", metadata.IDPSSODescriptors[0].ErrorURL)

	buf, err := xml.Marshal(metadata)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(buf), "<Extensions>"))
}

func TestIDPMetadataPublishesMetadataInfo(t *testing.T) {
	test := NewIdentityProviderTest(t)
	test.IDP.MetadataInfo = federationMetadataInfo()

	metadata := test.IDP.Metadata()

	// SDP-MD09 and SDP-MD10: the UIInfo is an extension of the role. SDP-MD12: so is the errorURL.
	role := metadata.IDPSSODescriptors[0]
	require.NotNil(t, role.Extensions)
	assert.Equal(t, test.IDP.MetadataInfo.UIInfo, role.Extensions.UIInfo)
	assert.Equal(t, test.IDP.MetadataInfo.DiscoHints, role.Extensions.DiscoHints)
	assert.Equal(t, "https://idp.example.com/error", role.ErrorURL)

	// SDP-IDP14: the scopes are never regular expressions.
	assert.Equal(t, []Scope{{Value: "example.com"}, {Value: "example.org"}}, role.Extensions.Scopes)

	// SDP-MD11: the contacts, and the organization, are those of the entity.
	assert.Equal(t, test.IDP.MetadataInfo.ContactPeople, metadata.ContactPeople)
	assert.Equal(t, test.IDP.MetadataInfo.Organization, metadata.Organization)

	// Entity attributes describe the entity (MetaAttr §2.1).
	require.NotNil(t, metadata.Extensions)
	assert.Equal(t, test.IDP.MetadataInfo.EntityAttributes, metadata.Extensions.EntityAttributes.Attributes)
	assert.Equal(t, []string{AssuranceCertificationSIRTFI}, metadata.EntityAttributeValues(AssuranceCertificationAttributeName))

	// What is published is a copy, so a caller that changes it does not change the configuration.
	role.Extensions.UIInfo.DisplayNames[0].Value = "changed"
	metadata.ContactPeople[0].ContactType = "changed"
	metadata.Extensions.EntityAttributes.Attributes[0].Name = "changed"

	assert.Equal(t, "Example Identity Provider", test.IDP.MetadataInfo.UIInfo.DisplayNames[0].Value)
	assert.Equal(t, "technical", test.IDP.MetadataInfo.ContactPeople[0].ContactType)
	assert.Equal(t, AssuranceCertificationAttributeName, test.IDP.MetadataInfo.EntityAttributes[0].Name)
}

func TestIDPMetadataPublishesScopesOnTheAttributeAuthority(t *testing.T) {
	test := NewIdentityProviderTest(t)
	test.IDP.MetadataInfo = federationMetadataInfo()

	// An attribute authority asserts the same scoped attributes as the single sign-on service, so it lists the
	// scopes, but it has no user interface.
	ed := &EntityDescriptor{
		IDPSSODescriptors:             []IDPSSODescriptor{{}},
		AttributeAuthorityDescriptors: []AttributeAuthorityDescriptor{{}},
	}
	test.IDP.describeMetadata(ed)

	scopes := []Scope{{Value: "example.com"}, {Value: "example.org"}}
	assert.Equal(t, scopes, ed.IDPSSODescriptors[0].Extensions.Scopes)
	assert.Equal(t, scopes, ed.AttributeAuthorityDescriptors[0].Extensions.Scopes)
	assert.Nil(t, ed.AttributeAuthorityDescriptors[0].Extensions.UIInfo)
	assert.Equal(t, "", ed.AttributeAuthorityDescriptors[0].ErrorURL)
}

func TestIDPMetadataPublishesTheScopeOfTheNameIDProvider(t *testing.T) {
	test, _ := metadataSigningTest(t)

	// SDP-IDP14: the scope of the pairwise-id that the provider states is listed without being configured twice.
	test.IDP.NameIDProvider = PersistentNameIDProvider{Secret: persistentTestSecret, Scope: "example.net"}
	assert.Equal(t, []Scope{{Value: "example.net"}}, test.IDP.Metadata().IDPSSODescriptors[0].Extensions.Scopes)

	// It follows the scopes that are configured, and is not repeated, whatever its case.
	test.IDP.MetadataInfo.Scopes = []string{"example.com", "Example.NET"}
	assert.Equal(t, []Scope{{Value: "example.com"}, {Value: "Example.NET"}}, test.IDP.Metadata().IDPSSODescriptors[0].Extensions.Scopes)

	test.IDP.MetadataInfo.Scopes = []string{"example.com"}
	test.IDP.NameIDProvider = ManagedPersistentNameIDProvider{PersistentNameIDProvider: PersistentNameIDProvider{Secret: persistentTestSecret, Scope: "example.net"}}
	assert.Equal(t, []Scope{{Value: "example.com"}, {Value: "example.net"}}, test.IDP.Metadata().IDPSSODescriptors[0].Extensions.Scopes)

	// A provider with no scope, or none at all, adds nothing.
	test.IDP.NameIDProvider = PersistentNameIDProvider{Secret: persistentTestSecret}
	assert.Equal(t, []Scope{{Value: "example.com"}}, test.IDP.Metadata().IDPSSODescriptors[0].Extensions.Scopes)

	// A scope that the provider can't state is not signed into the metadata.
	test.IDP.NameIDProvider = PersistentNameIDProvider{Secret: persistentTestSecret, Scope: "not a scope"}
	_, err := test.IDP.SignedMetadata()
	assert.EqualError(t, err, `the scope "not a scope" of the NameIDProvider is not a scope`)
}

func TestSubjectIDRequirementRequests(t *testing.T) {
	assert.True(t, SubjectIDRequirementSubjectID.Requests(SubjectIDAttributeName))
	assert.False(t, SubjectIDRequirementSubjectID.Requests(PairwiseIDAttributeName))
	assert.True(t, SubjectIDRequirementPairwiseID.Requests(PairwiseIDAttributeName))
	assert.False(t, SubjectIDRequirementPairwiseID.Requests(SubjectIDAttributeName))
	assert.True(t, SubjectIDRequirementAny.Requests(SubjectIDAttributeName))
	assert.True(t, SubjectIDRequirementAny.Requests(PairwiseIDAttributeName))
	assert.False(t, SubjectIDRequirementAny.Requests("urn:oid:0.9.2342.19200300.100.1.3"))
	assert.False(t, SubjectIDRequirementNone.Requests(SubjectIDAttributeName))
	assert.False(t, SubjectIDRequirementNone.Requests(PairwiseIDAttributeName))
	assert.False(t, SubjectIDRequirementUnspecified.Requests(PairwiseIDAttributeName))
}

func TestIDPMetadataHook(t *testing.T) {
	test, verifier := metadataSigningTest(t)
	test.IDP.MetadataInfo = federationMetadataInfo()
	test.IDP.MetadataHook = func(metadata *EntityDescriptor) {
		// The hook runs after the metadata is complete, so it sees what MetadataInfo published.
		assert.True(t, metadata.Extensions != nil && metadata.Extensions.EntityAttributes != nil)

		metadata.Extensions.RegistrationInfo = &RegistrationInfo{RegistrationAuthority: "https://federation.example.org"}
	}

	assert.Equal(t, "https://federation.example.org", test.IDP.Metadata().Extensions.RegistrationInfo.RegistrationAuthority)

	// What the hook adds is signed.
	signed, err := test.IDP.SignedMetadata()
	require.NoError(t, err)

	verified, err := verifier.Verify(signed)
	require.NoError(t, err)

	var metadata EntityDescriptor
	require.NoError(t, xml.Unmarshal(verified, &metadata))
	assert.Equal(t, "https://federation.example.org", metadata.Extensions.RegistrationInfo.RegistrationAuthority)
}

func TestSignedIDPMetadataWithExtensionsIsVerified(t *testing.T) {
	test, verifier := metadataSigningTest(t)
	test.IDP.MetadataInfo = federationMetadataInfo()

	signed, err := test.IDP.SignedMetadata()
	require.NoError(t, err)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(signed))

	// The schema: Signature, then Extensions, then the roles, the organization and the contacts.
	children := doc.Root().ChildElements()

	tags := make([]string, 0, len(children))
	for _, child := range children {
		tags = append(tags, child.Tag)
	}

	assert.Equal(t, []string{"Signature", "Extensions", "IDPSSODescriptor", "Organization", "ContactPerson", "ContactPerson"}, tags)

	role := doc.Root().FindElement("./IDPSSODescriptor")
	assert.Equal(t, "https://idp.example.com/error", role.SelectAttrValue("errorURL", ""))
	assert.Equal(t, "Extensions", role.ChildElements()[0].Tag)
	assert.Equal(t, []xml.Name{
		{Space: testNSMDUI, Local: "UIInfo"},
		{Space: testNSMDUI, Local: "DiscoHints"},
		{Space: testNSShibMD, Local: "Scope"},
		{Space: testNSShibMD, Local: "Scope"},
	}, childrenOf(role.ChildElements()[0]))

	for _, scope := range role.ChildElements()[0].ChildElements()[2:] {
		assert.Equal(t, "false", scope.SelectAttrValue("regexp", ""))
	}

	verified, err := verifier.Verify(signed)
	require.NoError(t, err)

	var metadata EntityDescriptor
	require.NoError(t, xml.Unmarshal(verified, &metadata))

	expected := test.IDP.Metadata()
	assert.Equal(t, expected.Extensions, metadata.Extensions)
	assert.Equal(t, expected.IDPSSODescriptors[0].Extensions, metadata.IDPSSODescriptors[0].Extensions)
	assert.Equal(t, expected.Organization, metadata.Organization)
	assert.Equal(t, expected.ContactPeople, metadata.ContactPeople)
	assert.Equal(t, expected.IDPSSODescriptors[0].ErrorURL, metadata.IDPSSODescriptors[0].ErrorURL)

	// A change to an extension breaks the signature.
	_, err = verifier.Verify([]byte(strings.Replace(string(signed), ">example.org<", ">example.net<", 1)))
	assert.NotNil(t, err)
}

func TestMetadataInfoValidate(t *testing.T) {
	assert.NoError(t, MetadataInfo{}.Validate())
	assert.NoError(t, federationMetadataInfo().Validate())

	dataLogo := federationMetadataInfo()
	dataLogo.UIInfo.Logos = []Logo{{URL: "data:image/png;base64,iVBORw0KGgo=", Height: 16, Width: 16, Lang: "en"}}
	assert.NoError(t, dataLogo.Validate())

	testCases := []struct {
		name     string
		change   func(info *MetadataInfo)
		expected string
	}{
		{
			name:     "errorURL over http",
			change:   func(info *MetadataInfo) { info.ErrorURL = "http://idp.example.com/error" },
			expected: `MetadataInfo.ErrorURL: "http://idp.example.com/error" is not an https URL`,
		},
		{
			name:     "errorURL that is relative",
			change:   func(info *MetadataInfo) { info.ErrorURL = "/error" },
			expected: `MetadataInfo.ErrorURL: "/error" is not an https URL`,
		},
		{
			name:     "logo over http",
			change:   func(info *MetadataInfo) { info.UIInfo.Logos[0].URL = "http://idp.example.com/logo.png" },
			expected: `MetadataInfo.UIInfo.Logos[0]: "http://idp.example.com/logo.png" is neither an https URL nor a data URI`,
		},
		{
			name:     "logo without a size",
			change:   func(info *MetadataInfo) { info.UIInfo.Logos[0].Height = 0 },
			expected: "MetadataInfo.UIInfo.Logos[0]: the height and width must be positive",
		},
		{
			name:     "display name without a language",
			change:   func(info *MetadataInfo) { info.UIInfo.DisplayNames[0].Lang = "" },
			expected: "MetadataInfo.UIInfo.DisplayNames[0]: no language",
		},
		{
			name:     "display name without a value",
			change:   func(info *MetadataInfo) { info.UIInfo.DisplayNames[0].Value = " " },
			expected: "MetadataInfo.UIInfo.DisplayNames[0]: no value",
		},
		{
			name: "two display names in a language",
			change: func(info *MetadataInfo) {
				info.UIInfo.DisplayNames = append(info.UIInfo.DisplayNames, LocalizedName{Lang: "en", Value: "Another"})
			},
			expected: `MetadataInfo.UIInfo.DisplayNames[1]: more than one for the language "en"`,
		},
		{
			name:     "privacy statement that is not a URL",
			change:   func(info *MetadataInfo) { info.UIInfo.PrivacyStatementURLs[0].Value = "privacy.html" },
			expected: `MetadataInfo.UIInfo.PrivacyStatementURLs[0]: "privacy.html" is not an absolute URL`,
		},
		{
			name:     "keyword with a plus",
			change:   func(info *MetadataInfo) { info.UIInfo.Keywords = []Keywords{{Lang: "en", Values: []string{"c++"}}} },
			expected: `MetadataInfo.UIInfo.Keywords[0]: the keyword "c++" contains a plus`,
		},
		{
			name:     "organization URL without a language",
			change:   func(info *MetadataInfo) { info.Organization.OrganizationURLs[0].Lang = "" },
			expected: "MetadataInfo.Organization.OrganizationURLs[0]: no language",
		},
		{
			name:     "organization without a name",
			change:   func(info *MetadataInfo) { info.Organization.OrganizationNames = nil },
			expected: "MetadataInfo.Organization: a name, a display name and a URL are required",
		},
		{
			name:     "unknown contact type",
			change:   func(info *MetadataInfo) { info.ContactPeople[0].ContactType = "security" },
			expected: `MetadataInfo.ContactPeople[0]: unknown contact type "security"`,
		},
		{
			name:     "scope that is empty",
			change:   func(info *MetadataInfo) { info.Scopes = append(info.Scopes, "") },
			expected: `MetadataInfo.Scopes[2]: "" is not a scope`,
		},
		{
			name:     "scope with whitespace",
			change:   func(info *MetadataInfo) { info.Scopes[0] = "example com" },
			expected: `MetadataInfo.Scopes[0]: "example com" is not a scope`,
		},
		{
			name:     "entity attribute without a name",
			change:   func(info *MetadataInfo) { info.EntityAttributes[0].Name = "" },
			expected: "MetadataInfo.EntityAttributes[0]: no name",
		},
		{
			name:     "entity attribute without a value",
			change:   func(info *MetadataInfo) { info.EntityAttributes[1].Values = nil },
			expected: `MetadataInfo.EntityAttributes[1]: no values for "http://macedir.org/entity-category-support"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info := federationMetadataInfo()
			tc.change(&info)

			assert.EqualError(t, info.Validate(), tc.expected)
		})
	}
}

func TestInvalidMetadataInfoIsNotServed(t *testing.T) {
	test, _ := metadataSigningTest(t)
	test.IDP.MetadataInfo = federationMetadataInfo()
	test.IDP.MetadataInfo.ErrorURL = "http://idp.example.com/error"

	_, err := test.IDP.SignedMetadata()
	assert.EqualError(t, err, `MetadataInfo.ErrorURL: "http://idp.example.com/error" is not an https URL`)

	w := httptest.NewRecorder()
	test.IDP.ServeMetadata(w, httptest.NewRequest(http.MethodGet, test.IDP.MetadataURL.String(), nil))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.False(t, strings.Contains(w.Body.String(), "EntityDescriptor"))
}

func TestUnknownExtensionElementKeepsNamespacedAttributes(t *testing.T) {
	const data = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.org/">` +
		`<md:Extensions><ex:Thing xmlns:ex="urn:example:ext" xmlns:other="urn:example:other" other:flag="yes" plain="1" xml:lang="en">` +
		`<ex:Child>one</ex:Child><other:Child/></ex:Thing></md:Extensions></md:EntityDescriptor>`

	var metadata EntityDescriptor
	require.NoError(t, xml.Unmarshal([]byte(data), &metadata))
	require.NotNil(t, metadata.Extensions)
	assert.Equal(t, []ExtensionElement{{
		XMLName: xml.Name{Space: "urn:example:ext", Local: "Thing"},
		Attrs: []xml.Attr{
			{Name: xml.Name{Space: "urn:example:other", Local: "flag"}, Value: "yes"},
			{Name: xml.Name{Local: "plain"}, Value: "1"},
			{Name: xml.Name{Space: "http://www.w3.org/XML/1998/namespace", Local: "lang"}, Value: "en"},
		},
		Children: []ExtensionElement{
			{XMLName: xml.Name{Space: "urn:example:ext", Local: "Child"}, Content: "one"},
			{XMLName: xml.Name{Space: "urn:example:other", Local: "Child"}},
		},
	}}, metadata.Extensions.Other)

	buf, err := xml.Marshal(&metadata)
	require.NoError(t, err)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(buf))

	thing := doc.Root().FindElement("./Extensions").ChildElements()[0]
	assert.Equal(t, "urn:example:ext", thing.NamespaceURI())
	assert.Equal(t, "1", thing.SelectAttrValue("plain", ""))
	assert.Equal(t, "en", thing.SelectAttrValue("xml:lang", ""))

	var flag string

	for _, attr := range thing.Attr {
		if attr.Key == "flag" && attr.NamespaceURI() == "urn:example:other" {
			flag = attr.Value
		}
	}

	assert.Equal(t, "yes", flag)
	assert.Equal(t, []xml.Name{
		{Space: "urn:example:ext", Local: "Child"},
		{Space: "urn:example:other", Local: "Child"},
	}, childrenOf(thing))

	var again EntityDescriptor
	require.NoError(t, xml.Unmarshal(buf, &again))
	assert.Equal(t, metadata.Extensions, again.Extensions)
}
