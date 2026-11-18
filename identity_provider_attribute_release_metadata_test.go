package saml

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/golden"
)

func entityAttribute(name string, values ...string) Attribute {
	attribute := Attribute{Name: name, NameFormat: uriAttrNameFormat}
	for _, value := range values {
		attribute.Values = append(attribute.Values, AttributeValue{Value: value})
	}

	return attribute
}

// signal gives the metadata of the service provider of req the entity attributes.
func signal(req *IdpAuthnRequest, attributes ...Attribute) *IdpAuthnRequest {
	req.ServiceProviderMetadata.Extensions = &Extensions{EntityAttributes: &EntityAttributes{Attributes: attributes}}

	return req
}

func sortedAttributeNames(attributes []Attribute) []string {
	names := attributeNames(attributes)
	slices.Sort(names)

	return names
}

func sorted(names ...string) []string {
	names = append([]string{}, names...)
	slices.Sort(names)

	return names
}

// releaseError makes an assertion for req, which must fail, and returns the error.
func releaseError(t *testing.T, req *IdpAuthnRequest, session *Session) error {
	t.Helper()

	err := DefaultAssertionMaker{}.MakeAssertion(req, session)
	require.NotNil(t, err)

	return err
}

func assertRequiredAttributeUnavailable(t *testing.T, err error) {
	t.Helper()

	assert.True(t, errors.Is(err, ErrRequiredAttributeUnavailable), "%v", err)

	status := (&IdentityProvider{}).ErrorStatus(err)
	assert.Equal(t, status.StatusCode.Value, StatusResponder)
	assert.Nil(t, status.StatusCode.StatusCode)
}

func TestDefaultAttributeReleasePolicySubjectIDRequirement(t *testing.T) {
	testCases := []struct {
		name        string
		requirement string
		subjectID   bool
		pairwiseID  bool
		requested   []RequestedAttribute
		released    []string
		unmet       bool
	}{
		{name: "subject-id", requirement: "subject-id", subjectID: true, pairwiseID: true, released: []string{SubjectIDAttributeName}},
		{name: "subject-id without one", requirement: "subject-id", pairwiseID: true, unmet: true},
		{name: "pairwise-id", requirement: "pairwise-id", subjectID: true, pairwiseID: true, released: []string{PairwiseIDAttributeName}},
		{name: "pairwise-id without one", requirement: "pairwise-id", subjectID: true, unmet: true},
		{name: "any prefers the pairwise-id", requirement: "any", subjectID: true, pairwiseID: true, released: []string{PairwiseIDAttributeName}},
		{name: "any with only a subject-id", requirement: "any", subjectID: true, released: []string{SubjectIDAttributeName}},
		{name: "any with only a pairwise-id", requirement: "any", pairwiseID: true, released: []string{PairwiseIDAttributeName}},
		{name: "any with neither", requirement: "any", unmet: true},
		{name: "none", requirement: "none", subjectID: true, pairwiseID: true},
		{name: "none with neither", requirement: "none"},
		{
			name: "none withholds one that is requested by name", requirement: "none", subjectID: true, pairwiseID: true,
			requested: []RequestedAttribute{requested(SubjectIDAttributeName, uriAttrNameFormat), requested(mailAttributeName, uriAttrNameFormat)},
			released:  []string{mailAttributeName},
		},
		{
			name: "the requirement decides over a RequestedAttribute", requirement: "pairwise-id", subjectID: true, pairwiseID: true,
			requested: []RequestedAttribute{requested(SubjectIDAttributeName, uriAttrNameFormat)},
			released:  []string{PairwiseIDAttributeName},
		},
		{
			name: "the one that is required and requested is stated once", requirement: "subject-id", subjectID: true, pairwiseID: true,
			requested: []RequestedAttribute{requested(SubjectIDAttributeName, uriAttrNameFormat)},
			released:  []string{SubjectIDAttributeName},
		},
		{
			name: "with other requested attributes", requirement: "any", subjectID: true, pairwiseID: true,
			requested: []RequestedAttribute{requested(mailAttributeName, uriAttrNameFormat)},
			released:  []string{mailAttributeName, PairwiseIDAttributeName},
		},
		{name: "not signalled", subjectID: true, pairwiseID: true},
		{
			name: "not signalled and requested by name", subjectID: true, pairwiseID: true,
			requested: []RequestedAttribute{requested(SubjectIDAttributeName, uriAttrNameFormat), requested(PairwiseIDAttributeName, uriAttrNameFormat)},
			released:  []string{SubjectIDAttributeName, PairwiseIDAttributeName},
		},
		{
			name: "a value the profile does not define is no signal", requirement: "both", subjectID: true, pairwiseID: true,
			requested: []RequestedAttribute{requested(SubjectIDAttributeName, uriAttrNameFormat)},
			released:  []string{SubjectIDAttributeName},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setup := func(policy DefaultAttributeReleasePolicy) (*IdpAuthnRequest, *Session) {
				test := NewIdentityProviderTest(t, applyKey)
				test.IDP.AttributeReleasePolicy = policy

				if tc.pairwiseID {
					test.IDP.NameIDProvider = pairwiseTestProvider()
				}

				session := attributeReleaseSession()
				if !tc.subjectID {
					session.SubjectID = ""
				}

				var services []AttributeConsumingService
				if tc.requested != nil {
					services = append(services, service(0, nil, tc.requested...))
				}

				req := attributeReleaseRequest(t, test, "", services...)
				if tc.requirement != "" {
					signal(req, entityAttribute(SubjectIDRequirementAttributeName, tc.requirement))
				}

				return req, session
			}

			// By default what can't be stated is left out (SDP-IDP16).
			req, session := setup(DefaultAttributeReleasePolicy{})
			assert.Equal(t, sortedAttributeNames(releasedAttributes(t, req, session)), sorted(tc.released...))

			req, session = setup(DefaultAttributeReleasePolicy{EnforceSubjectIDRequirement: true})

			if tc.unmet {
				err := releaseError(t, req, session)
				assertRequiredAttributeUnavailable(t, err)
				assert.Contains(t, errorText(err), tc.requirement)

				return
			}

			assert.Equal(t, sortedAttributeNames(releasedAttributes(t, req, session)), sorted(tc.released...))
		})
	}
}

// The requirement is that of the entity, so it holds when the request names no service of the metadata.
func TestDefaultAttributeReleasePolicySubjectIDRequirementWithoutAService(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req := signal(attributeReleaseRequest(t, test, "7", service(0, nil, requested(mailAttributeName, uriAttrNameFormat))),
		entityAttribute(SubjectIDRequirementAttributeName, "subject-id"))

	attributes := releasedAttributes(t, req, attributeReleaseSession())
	require.Len(t, attributes, 1)
	assert.Equal(t, attributes[0], subjectIdentifierAttribute(SubjectIDAttributeName, "alice@example.com"))
}

// A custom attribute that has the name of an identifier in another format is not the identifier.
func TestDefaultAttributeReleasePolicySubjectIDRequirementIgnoresOtherFormats(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	session := &Session{ID: "s", UserName: "alice", CustomAttributes: []Attribute{{
		Name: SubjectIDAttributeName, NameFormat: basicAttrNameFormat, Values: []AttributeValue{{Type: "xs:string", Value: "local"}},
	}}}

	req := signal(attributeReleaseRequest(t, test, ""), entityAttribute(SubjectIDRequirementAttributeName, "subject-id"))
	assert.Len(t, releasedAttributes(t, req, session), 0)
}

func TestDefaultAttributeReleasePolicyLogsUnmetSubjectIDRequirement(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)

	var logged bytes.Buffer

	test.IDP.Observer = logObserver(&logged)

	req := signal(attributeReleaseRequest(t, test, ""), entityAttribute(SubjectIDRequirementAttributeName, "pairwise-id"))
	assert.Len(t, releasedAttributes(t, req, attributeReleaseSession()), 0)
	assert.Contains(t, logged.String(), "pairwise-id")
	assert.False(t, strings.Contains(logged.String(), "alice"))
}

// bundleSession is a session with a value for every attribute of the built-in bundles.
func bundleSession() *Session {
	session := attributeReleaseSession()
	session.UserDisplayName = "Alice S."
	session.CustomAttributes = append(session.CustomAttributes,
		Attribute{Name: EduPersonAssuranceAttributeName, NameFormat: uriAttrNameFormat, Values: []AttributeValue{
			{Type: "xs:string", Value: "https://refeds.org/assurance"},
			{Type: "xs:string", Value: "https://refeds.org/assurance/IAP/medium"},
		}},
		Attribute{Name: SchacHomeOrganizationAttributeName, NameFormat: uriAttrNameFormat, Values: []AttributeValue{{Type: "xs:string", Value: "example.com"}}},
	)

	return session
}

func everyBuiltInBundle() map[string][]Attribute {
	return map[string][]Attribute{
		EntityCategoryResearchAndScholarship: ResearchAndScholarshipAttributes(),
		EntityCategoryPersonalized:           PersonalizedAccessAttributes(),
		EntityCategoryPseudonymous:           PseudonymousAccessAttributes(),
		EntityCategoryAnonymous:              AnonymousAccessAttributes(),
	}
}

func TestDefaultAttributeReleasePolicyEntityCategoryBundles(t *testing.T) {
	const (
		displayName = "urn:oid:2.16.840.1.113730.3.1.241"
		givenName   = "urn:oid:2.5.4.42"
		sn          = "urn:oid:2.5.4.4"
		eppn        = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
		scoped      = "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
		assurance   = "urn:oid:1.3.6.1.4.1.5923.1.1.1.11"
		homeOrg     = "urn:oid:1.3.6.1.4.1.25178.1.2.9"
	)

	testCases := []struct {
		name       string
		categories []string
		enabled    map[string][]Attribute
		requested  []RequestedAttribute
		released   []string
	}{
		{
			name:       "research and scholarship",
			categories: []string{EntityCategoryResearchAndScholarship},
			enabled:    everyBuiltInBundle(),
			released:   []string{eppn, mailAttributeName, displayName, givenName, sn, scoped},
		},
		{
			name:       "personalized",
			categories: []string{EntityCategoryPersonalized},
			enabled:    everyBuiltInBundle(),
			released:   []string{SubjectIDAttributeName, displayName, givenName, sn, mailAttributeName, scoped, assurance, homeOrg},
		},
		{
			name:       "pseudonymous",
			categories: []string{EntityCategoryPseudonymous},
			enabled:    everyBuiltInBundle(),
			released:   []string{PairwiseIDAttributeName, scoped, assurance, homeOrg},
		},
		{
			name:       "anonymous",
			categories: []string{EntityCategoryAnonymous},
			enabled:    everyBuiltInBundle(),
			released:   []string{scoped, homeOrg},
		},
		{
			name:       "a category that is not enabled releases nothing",
			categories: []string{EntityCategoryResearchAndScholarship, EntityCategoryPersonalized},
			enabled:    map[string][]Attribute{EntityCategoryAnonymous: AnonymousAccessAttributes()},
		},
		{
			name:       "no category is enabled by default",
			categories: []string{EntityCategoryResearchAndScholarship, EntityCategoryPersonalized, EntityCategoryPseudonymous, EntityCategoryAnonymous},
		},
		{
			name:       "only the enabled category of several",
			categories: []string{EntityCategoryPersonalized, EntityCategoryAnonymous},
			enabled:    map[string][]Attribute{EntityCategoryAnonymous: AnonymousAccessAttributes()},
			released:   []string{scoped, homeOrg},
		},
		{
			name:     "a service provider in no category",
			enabled:  everyBuiltInBundle(),
			released: nil,
		},
		{
			name:       "code of conduct has no bundle",
			categories: []string{EntityCategoryCodeOfConductV1, EntityCategoryCodeOfConductV2},
			enabled:    everyBuiltInBundle(),
			requested:  []RequestedAttribute{requested(mailAttributeName, uriAttrNameFormat)},
			released:   []string{mailAttributeName},
		},
		{
			name:       "the union of the bundle and what is requested",
			categories: []string{EntityCategoryAnonymous},
			enabled:    everyBuiltInBundle(),
			requested:  []RequestedAttribute{requested(uidAttributeName, uriAttrNameFormat), requested(scoped, uriAttrNameFormat), requested("employeeNumber", "")},
			released:   []string{uidAttributeName, scoped, homeOrg, "employeeNumber"},
		},
		{
			name:       "the union of two bundles",
			categories: []string{EntityCategoryResearchAndScholarship, EntityCategoryPseudonymous},
			enabled:    everyBuiltInBundle(),
			released:   []string{eppn, mailAttributeName, displayName, givenName, sn, scoped, PairwiseIDAttributeName, assurance, homeOrg},
		},
		{
			name:       "a bundle of the operator",
			categories: []string{"https://federation.example.org/category/library"},
			enabled:    map[string][]Attribute{"https://federation.example.org/category/library": {{Name: "employeeNumber"}}},
			released:   []string{"employeeNumber"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			test.IDP.NameIDProvider = pairwiseTestProvider()
			test.IDP.AttributeReleasePolicy = DefaultAttributeReleasePolicy{EntityCategoryAttributes: tc.enabled}

			var services []AttributeConsumingService
			if tc.requested != nil {
				services = append(services, service(0, nil, tc.requested...))
			}

			req := attributeReleaseRequest(t, test, "", services...)
			if tc.categories != nil {
				signal(req, entityAttribute(EntityCategoryAttributeName, tc.categories...))
			}

			assert.Equal(t, sortedAttributeNames(releasedAttributes(t, req, bundleSession())), sorted(tc.released...))
		})
	}
}

func TestBuiltInBundlesNameAttributesByURI(t *testing.T) {
	for category, bundle := range everyBuiltInBundle() {
		assert.True(t, len(bundle) != 0, category)

		for _, attribute := range bundle {
			assert.Equal(t, attribute.NameFormat, uriAttrNameFormat, attribute.Name)
			assert.True(t, attribute.FriendlyName != "", attribute.Name)
			assert.Len(t, attribute.Values, 0, attribute.Name)
		}
	}

	// Each call returns a bundle of its own, which an operator may change.
	first := ResearchAndScholarshipAttributes()
	first[0].Name = "changed"

	assert.True(t, ResearchAndScholarshipAttributes()[0].Name != "changed")
}

// A bundle states what the session has and no more.
func TestDefaultAttributeReleasePolicyEntityCategoryBundleOmitsWhatTheSessionLacks(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.AttributeReleasePolicy = DefaultAttributeReleasePolicy{EntityCategoryAttributes: everyBuiltInBundle()}

	req := signal(attributeReleaseRequest(t, test, ""), entityAttribute(EntityCategoryAttributeName, EntityCategoryPersonalized))
	session := &Session{ID: "s", UserName: "alice", UserEmail: "alice@example.com", UserCommonName: "Alice Smith"}

	assert.Equal(t, attributeNames(releasedAttributes(t, req, session)), []string{mailAttributeName})
}

// A bundle entry that lists values releases only those values, as a RequestedAttribute does.
func TestDefaultAttributeReleasePolicyEntityCategoryBundleValues(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.AttributeReleasePolicy = DefaultAttributeReleasePolicy{EntityCategoryAttributes: map[string][]Attribute{
		EntityCategoryAnonymous: {{
			Name: EduPersonAssuranceAttributeName, NameFormat: uriAttrNameFormat,
			Values: []AttributeValue{{Type: "xs:string", Value: "https://refeds.org/assurance"}},
		}},
	}}

	req := signal(attributeReleaseRequest(t, test, ""), entityAttribute(EntityCategoryAttributeName, EntityCategoryAnonymous))
	attributes := releasedAttributes(t, req, bundleSession())
	require.Len(t, attributes, 1)
	assert.Equal(t, queryAttributeValues(attributes[0]), []string{"https://refeds.org/assurance"})
}

func TestDefaultAttributeReleasePolicyEntityCategoryTrust(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		test := NewIdentityProviderTest(t, applyKey)

		var asked *EntityDescriptor

		test.IDP.AttributeReleasePolicy = DefaultAttributeReleasePolicy{
			EntityCategoryAttributes: everyBuiltInBundle(),
			EntityCategoryTrust: func(serviceProvider *EntityDescriptor) bool {
				asked = serviceProvider

				return trusted
			},
		}

		req := signal(attributeReleaseRequest(t, test, "", service(0, nil, requested(uidAttributeName, uriAttrNameFormat))),
			entityAttribute(EntityCategoryAttributeName, EntityCategoryAnonymous),
			entityAttribute(SubjectIDRequirementAttributeName, "subject-id"))

		// What the service provider requests for itself doesn't depend on who vouches for its category.
		expected := []string{uidAttributeName, SubjectIDAttributeName}
		if trusted {
			expected = append(expected, "urn:oid:1.3.6.1.4.1.5923.1.1.1.9")
		}

		assert.Equal(t, sortedAttributeNames(releasedAttributes(t, req, attributeReleaseSession())), sorted(expected...))
		assert.True(t, asked == req.ServiceProviderMetadata)
	}
}

// The requirement of the service provider decides the identifier, whatever the bundles of its categories hold.
func TestDefaultAttributeReleasePolicySubjectIDRequirementDecidesOverBundles(t *testing.T) {
	for requirement, identifiers := range map[string][]string{
		"":            {SubjectIDAttributeName, PairwiseIDAttributeName},
		"subject-id":  {SubjectIDAttributeName},
		"pairwise-id": {PairwiseIDAttributeName},
		"any":         {PairwiseIDAttributeName},
		"none":        nil,
	} {
		t.Run(requirement, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			test.IDP.NameIDProvider = pairwiseTestProvider()
			test.IDP.AttributeReleasePolicy = DefaultAttributeReleasePolicy{EntityCategoryAttributes: map[string][]Attribute{
				EntityCategoryPersonalized: {{Name: SubjectIDAttributeName, NameFormat: uriAttrNameFormat}},
				EntityCategoryPseudonymous: {{Name: PairwiseIDAttributeName, NameFormat: uriAttrNameFormat}},
			}}

			attributes := []Attribute{entityAttribute(EntityCategoryAttributeName, EntityCategoryPersonalized, EntityCategoryPseudonymous)}
			if requirement != "" {
				attributes = append(attributes, entityAttribute(SubjectIDRequirementAttributeName, requirement))
			}

			req := signal(attributeReleaseRequest(t, test, ""), attributes...)
			assert.Equal(t, sortedAttributeNames(releasedAttributes(t, req, attributeReleaseSession())), sorted(identifiers...))
		})
	}
}

func TestDefaultAttributeReleasePolicyIsRequired(t *testing.T) {
	isRequired := func(attribute RequestedAttribute, required bool) RequestedAttribute {
		attribute.IsRequired = &required

		return attribute
	}

	const displayName = "urn:oid:2.16.840.1.113730.3.1.241"

	testCases := []struct {
		name        string
		requested   []RequestedAttribute
		requirement string
		released    []string
		missing     []string
	}{
		{
			name:      "available",
			requested: []RequestedAttribute{isRequired(requested(mailAttributeName, uriAttrNameFormat), true), requested(displayName, uriAttrNameFormat)},
			released:  []string{mailAttributeName},
		},
		{
			name:      "not available",
			requested: []RequestedAttribute{isRequired(requested(mailAttributeName, uriAttrNameFormat), true), isRequired(requested(displayName, uriAttrNameFormat), true)},
			released:  []string{mailAttributeName},
			missing:   []string{displayName},
		},
		{
			name:      "not required",
			requested: []RequestedAttribute{isRequired(requested(displayName, uriAttrNameFormat), false), requested(mailAttributeName, uriAttrNameFormat)},
			released:  []string{mailAttributeName},
		},
		{
			name:      "none of the values that are required",
			requested: []RequestedAttribute{isRequired(requested(affiliationAttributeName, uriAttrNameFormat, "Auditors"), true)},
			missing:   []string{affiliationAttributeName},
		},
		{
			name:      "one of the values that are required",
			requested: []RequestedAttribute{isRequired(requested(affiliationAttributeName, uriAttrNameFormat, "Auditors", "Users"), true)},
			released:  []string{affiliationAttributeName},
		},
		{
			name:      "under a name of the service provider",
			requested: []RequestedAttribute{isRequired(requested("email", basicAttrNameFormat), true), isRequired(requested("department", basicAttrNameFormat), true)},
			released:  []string{"email"},
			missing:   []string{"department"},
		},
		{
			name:        "filtered by the subject identifier requirement",
			requested:   []RequestedAttribute{isRequired(requested(SubjectIDAttributeName, uriAttrNameFormat), true)},
			requirement: "none",
			missing:     []string{SubjectIDAttributeName},
		},
		{
			name:        "met by the subject identifier requirement",
			requested:   []RequestedAttribute{isRequired(requested(SubjectIDAttributeName, uriAttrNameFormat), true)},
			requirement: "subject-id",
			released:    []string{SubjectIDAttributeName},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setup := func(policy AttributeReleasePolicy) *IdpAuthnRequest {
				test := NewIdentityProviderTest(t, applyKey)
				test.IDP.AttributeReleasePolicy = policy

				req := attributeReleaseRequest(t, test, "", service(0, nil, tc.requested...))
				if tc.requirement != "" {
					signal(req, entityAttribute(SubjectIDRequirementAttributeName, tc.requirement))
				}

				return req
			}

			// It is not enforced by default.
			assert.Equal(t, sortedAttributeNames(releasedAttributes(t, setup(nil), attributeReleaseSession())), sorted(tc.released...))

			req := setup(DefaultAttributeReleasePolicy{EnforceIsRequired: true})

			if tc.missing == nil {
				assert.Equal(t, sortedAttributeNames(releasedAttributes(t, req, attributeReleaseSession())), sorted(tc.released...))

				return
			}

			err := releaseError(t, req, attributeReleaseSession())
			assertRequiredAttributeUnavailable(t, err)

			for _, name := range tc.missing {
				assert.Contains(t, errorText(err), name)
			}

			// The error names attributes and holds no value of the principal.
			for _, value := range []string{"alice", "Smith", "Users"} {
				assert.False(t, strings.Contains(err.Error(), value))
			}
		})
	}
}

// A required attribute of a service that the request doesn't select is not required of this request.
func TestDefaultAttributeReleasePolicyIsRequiredOfTheSelectedService(t *testing.T) {
	required := true
	wanted := requested("urn:oid:2.16.840.1.113730.3.1.241", uriAttrNameFormat)
	wanted.IsRequired = &required

	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.AttributeReleasePolicy = DefaultAttributeReleasePolicy{EnforceIsRequired: true}

	req := attributeReleaseRequest(t, test, "1", service(0, nil, wanted), service(1, nil, requested(mailAttributeName, uriAttrNameFormat)))
	assert.Equal(t, attributeNames(releasedAttributes(t, req, attributeReleaseSession())), []string{mailAttributeName})
}

// A request that can't be given what the service provider requires is answered with a Responder status.
func TestServeSSOAnswersUnavailableRequiredAttributeWithResponder(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.AttributeReleasePolicy = DefaultAttributeReleasePolicy{EnforceIsRequired: true, EnforceSubjectIDRequirement: true}

	for name, change := range map[string]func(metadata *EntityDescriptor){
		"isRequired": func(metadata *EntityDescriptor) {
			required := true
			wanted := requested("urn:oid:2.16.840.1.113730.3.1.241", uriAttrNameFormat)
			wanted.IsRequired = &required
			metadata.SPSSODescriptors[0].AttributeConsumingServices = []AttributeConsumingService{service(0, nil, wanted)}
		},
		"subject-id:req": func(metadata *EntityDescriptor) {
			metadata.Extensions = &Extensions{EntityAttributes: &EntityAttributes{Attributes: []Attribute{
				entityAttribute(SubjectIDRequirementAttributeName, "pairwise-id"),
			}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			req := attributeReleaseRequest(t, test, "")
			change(req.ServiceProviderMetadata)

			err := releaseError(t, req, attributeReleaseSession())
			assertRequiredAttributeUnavailable(t, err)
			assert.Nil(t, req.Assertion)
		})
	}
}

// The fixture is a service provider of a federation: in Research and Scholarship and Code of Conduct, requiring a
// pairwise-id, and requesting only the eduPersonPrincipalName, which it marks as required.
func TestDefaultAttributeReleasePolicyFederationFixture(t *testing.T) {
	const (
		eppn        = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
		displayName = "urn:oid:2.16.840.1.113730.3.1.241"
		givenName   = "urn:oid:2.5.4.42"
		sn          = "urn:oid:2.5.4.4"
		scoped      = "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
	)

	setup := func(policy AttributeReleasePolicy, pairwise bool) *IdpAuthnRequest {
		metadata, err := ParseServiceProviderMetadata(golden.Get(t, "TestMetadataExtensions_sp.xml"))
		require.NoError(t, err)

		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.AttributeReleasePolicy = policy

		if pairwise {
			test.IDP.NameIDProvider = pairwiseTestProvider()
		}

		req := attributeReleaseRequest(t, test, "")
		req.ServiceProviderMetadata = metadata
		req.SPSSODescriptor = &metadata.SPSSODescriptors[0]
		req.ACSEndpoint = &metadata.SPSSODescriptors[0].AssertionConsumerServices[0]

		return req
	}

	t.Run("default policy", func(t *testing.T) {
		attributes := releasedAttributes(t, setup(nil, true), bundleSession())
		assert.Equal(t, sortedAttributeNames(attributes), sorted(eppn, PairwiseIDAttributeName))
	})

	t.Run("default policy without a pairwise-id", func(t *testing.T) {
		attributes := releasedAttributes(t, setup(nil, false), bundleSession())
		assert.Equal(t, attributeNames(attributes), []string{eppn})
	})

	t.Run("research and scholarship enabled", func(t *testing.T) {
		policy := DefaultAttributeReleasePolicy{
			EntityCategoryAttributes:    map[string][]Attribute{EntityCategoryResearchAndScholarship: ResearchAndScholarshipAttributes()},
			EnforceIsRequired:           true,
			EnforceSubjectIDRequirement: true,
		}

		attributes := releasedAttributes(t, setup(policy, true), bundleSession())
		assert.Equal(t, sortedAttributeNames(attributes),
			sorted(eppn, mailAttributeName, displayName, givenName, sn, scoped, PairwiseIDAttributeName))
	})

	t.Run("enforced without a pairwise-id", func(t *testing.T) {
		policy := DefaultAttributeReleasePolicy{EnforceSubjectIDRequirement: true}
		assertRequiredAttributeUnavailable(t, releaseError(t, setup(policy, false), bundleSession()))
	})

	t.Run("enforced without the required attribute", func(t *testing.T) {
		policy := DefaultAttributeReleasePolicy{EnforceIsRequired: true}
		session := &Session{ID: "s", UserName: "alice"}

		err := releaseError(t, setup(policy, true), session)
		assertRequiredAttributeUnavailable(t, err)
		assert.Contains(t, errorText(err), eppn)
	})
}

func TestServeAttributeQueryReleasesByMetadata(t *testing.T) {
	queryNames := func(response *queryResponse) []string {
		if len(response.Assertions) == 0 {
			return []string{}
		}

		return sortedAttributeNames(response.Assertions[0].AttributeStatements[0].Attributes)
	}

	named := func(names ...string) []Attribute {
		attributes := make([]Attribute, 0, len(names))
		for _, name := range names {
			attributes = append(attributes, Attribute{Name: name, NameFormat: uriAttrNameFormat})
		}

		return attributes
	}

	fixture := func(policy AttributeReleasePolicy, entityAttributes []Attribute, wanted ...RequestedAttribute) *queryFixture {
		f := newQueryFixture(t)
		f.test.IDP.AttributeReleasePolicy = policy
		f.test.IDP.NameIDProvider = pairwiseIDProviderFunc{value: "pseudonym@example.com"}
		f.metadata = func(metadata *EntityDescriptor) {
			metadata.Extensions = &Extensions{EntityAttributes: &EntityAttributes{Attributes: entityAttributes}}

			if wanted != nil {
				metadata.SPSSODescriptors[0].AttributeConsumingServices = []AttributeConsumingService{service(1, nil, wanted...)}
			}
		}

		return f
	}

	anyIdentifier := []Attribute{entityAttribute(SubjectIDRequirementAttributeName, "any")}

	t.Run("subject identifier requirement", func(t *testing.T) {
		f := fixture(nil, anyIdentifier)

		response := f.queryAttributes(t, f.attributeQuery())
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Equal(t, queryNames(response), []string{PairwiseIDAttributeName})
	})

	// Single sign-on states the pairwise-id for "any", so a query that names the subject-id is not told it.
	t.Run("a query does not choose the other identifier", func(t *testing.T) {
		f := fixture(nil, anyIdentifier)

		response := f.queryAttributes(t, f.attributeQuery(named(SubjectIDAttributeName)...))
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Len(t, response.Assertions, 0)

		response = f.queryAttributes(t, f.attributeQuery(named(PairwiseIDAttributeName)...))
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Equal(t, queryNames(response), []string{PairwiseIDAttributeName})
	})

	t.Run("entity category", func(t *testing.T) {
		policy := DefaultAttributeReleasePolicy{EntityCategoryAttributes: everyBuiltInBundle()}
		category := []Attribute{entityAttribute(EntityCategoryAttributeName, EntityCategoryAnonymous)}
		f := fixture(policy, category, requested(mailAttributeName, uriAttrNameFormat))

		response := f.queryAttributes(t, f.attributeQuery())
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Equal(t, queryNames(response), sorted(mailAttributeName, "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"))

		response = f.queryAttributes(t, f.attributeQuery(named("urn:oid:1.3.6.1.4.1.5923.1.1.1.9", uidAttributeName)...))
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Equal(t, queryNames(response), []string{"urn:oid:1.3.6.1.4.1.5923.1.1.1.9"})

		// Not enabled, the category releases nothing.
		f = fixture(nil, category, requested(mailAttributeName, uriAttrNameFormat))
		response = f.queryAttributes(t, f.attributeQuery())
		assert.Equal(t, queryNames(response), []string{mailAttributeName})
	})

	t.Run("isRequired", func(t *testing.T) {
		required := true
		wanted := requested("urn:oid:2.16.840.1.113730.3.1.241", uriAttrNameFormat)
		wanted.IsRequired = &required

		// A query for an attribute that can be released fails as single sign-on does, and not otherwise.
		f := fixture(DefaultAttributeReleasePolicy{EnforceIsRequired: true}, nil, wanted, requested(mailAttributeName, uriAttrNameFormat))
		assertQueryStatus(t, f.queryAttributes(t, f.attributeQuery(named(mailAttributeName)...)), StatusResponder, "")

		f = fixture(nil, nil, wanted, requested(mailAttributeName, uriAttrNameFormat))
		response := f.queryAttributes(t, f.attributeQuery(named(mailAttributeName)...))
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Equal(t, queryNames(response), []string{mailAttributeName})

		// A required attribute that is available is not missing from a query that doesn't name it.
		wanted = requested(uidAttributeName, uriAttrNameFormat)
		wanted.IsRequired = &required

		f = fixture(DefaultAttributeReleasePolicy{EnforceIsRequired: true}, nil, wanted, requested(mailAttributeName, uriAttrNameFormat))
		response = f.queryAttributes(t, f.attributeQuery(named(mailAttributeName)...))
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Equal(t, queryNames(response), []string{mailAttributeName})
	})

	t.Run("enforced subject identifier requirement", func(t *testing.T) {
		f := fixture(DefaultAttributeReleasePolicy{EnforceSubjectIDRequirement: true}, anyIdentifier)
		f.test.IDP.NameIDProvider = nil
		f.provider.subject.SubjectID = ""

		assertQueryStatus(t, f.queryAttributes(t, f.attributeQuery()), StatusResponder, "")
	})
}

func TestSessionDisplayNameIsACandidate(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req := attributeReleaseRequest(t, test, "", service(0, nil, requested(DisplayNameAttributeName, uriAttrNameFormat)))

	session := attributeReleaseSession()
	assert.Len(t, releasedAttributes(t, req, session), 0)

	session.UserDisplayName = "Alice S."
	attributes := releasedAttributes(t, req, session)
	require.Len(t, attributes, 1)
	assert.Equal(t, attributes[0], Attribute{
		FriendlyName: "displayName",
		Name:         "urn:oid:2.16.840.1.113730.3.1.241",
		NameFormat:   uriAttrNameFormat,
		Values:       []AttributeValue{{Type: "xs:string", Value: "Alice S."}},
	})
}

const inheritedEntityAttributesMetadata = `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <md:Extensions>
    <mdattr:EntityAttributes>
      <saml:Attribute Name="http://macedir.org/entity-category" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>https://refeds.org/category/anonymous</saml:AttributeValue>
      </saml:Attribute>
    </mdattr:EntityAttributes>
  </md:Extensions>
  <md:EntitiesDescriptor>
    <md:Extensions>
      <mdattr:EntityAttributes>
        <saml:Attribute Name="urn:oasis:names:tc:SAML:profiles:subject-id:req" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
          <saml:AttributeValue>pairwise-id</saml:AttributeValue>
        </saml:Attribute>
      </mdattr:EntityAttributes>
    </md:Extensions>
    <md:EntityDescriptor entityID="https://nested.example.org/sp">
      <md:Extensions>
        <mdattr:EntityAttributes>
          <saml:Attribute Name="http://macedir.org/entity-category" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:AttributeValue>http://refeds.org/category/research-and-scholarship</saml:AttributeValue>
          </saml:Attribute>
        </mdattr:EntityAttributes>
      </md:Extensions>
      <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://nested.example.org/acs" index="1"/>
      </md:SPSSODescriptor>
    </md:EntityDescriptor>
  </md:EntitiesDescriptor>
  <md:EntityDescriptor entityID="https://plain.example.org/sp">
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://plain.example.org/acs" index="1"/>
    </md:SPSSODescriptor>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://conflict.example.org/sp">
    <md:Extensions>
      <mdattr:EntityAttributes>
        <saml:Attribute Name="urn:oasis:names:tc:SAML:profiles:subject-id:req" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
          <saml:AttributeValue>subject-id</saml:AttributeValue>
        </saml:Attribute>
      </mdattr:EntityAttributes>
    </md:Extensions>
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://conflict.example.org/acs" index="1"/>
    </md:SPSSODescriptor>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`

// SAML V2.0 Metadata Extension for Entity Attributes §2.3: the attributes of an EntitiesDescriptor are bound to
// each EntityDescriptor within it.
func TestParseServiceProvidersMetadataInheritsEntityAttributes(t *testing.T) {
	entities, err := ParseServiceProvidersMetadata([]byte(inheritedEntityAttributesMetadata))
	require.NoError(t, err)
	require.Len(t, entities, 3)

	byID := map[string]*EntityDescriptor{}
	for _, entity := range entities {
		byID[entity.EntityID] = entity
	}

	plain := byID["https://plain.example.org/sp"]
	assert.Equal(t, plain.EntityCategories(), []string{EntityCategoryAnonymous})
	assert.Equal(t, plain.SubjectIDRequirement(), SubjectIDRequirementUnspecified)

	// The entity's own attributes come first, then those of the groups around it, the nearest first.
	nested := byID["https://nested.example.org/sp"]
	assert.Equal(t, nested.EntityCategories(), []string{EntityCategoryResearchAndScholarship, EntityCategoryAnonymous})
	assert.Equal(t, nested.SubjectIDRequirement(), SubjectIDRequirementPairwiseID)

	// The group of another entity is not around this one.
	conflict := byID["https://conflict.example.org/sp"]
	assert.Equal(t, conflict.SubjectIDRequirement(), SubjectIDRequirementSubjectID)
	assert.Equal(t, conflict.EntityCategories(), []string{EntityCategoryAnonymous})

	// An EntityDescriptor that is not in a group has only its own.
	single, err := ParseServiceProviderMetadata(golden.Get(t, "TestMetadataExtensions_sp.xml"))
	require.NoError(t, err)
	assert.Len(t, single.Extensions.EntityAttributes.Attributes, 3)
}

func TestServiceProvidersOfDoesNotChangeTheGroup(t *testing.T) {
	own := &Extensions{EntityAttributes: &EntityAttributes{Attributes: []Attribute{entityAttribute(EntityCategoryAttributeName, EntityCategoryPersonalized)}}}
	group := &EntitiesDescriptor{
		Extensions: &Extensions{EntityAttributes: &EntityAttributes{Attributes: []Attribute{entityAttribute(EntityCategoryAttributeName, EntityCategoryAnonymous)}}},
		EntityDescriptors: []EntityDescriptor{
			{EntityID: "https://one.example.org/sp", Extensions: own, SPSSODescriptors: []SPSSODescriptor{{}}},
			{EntityID: "https://two.example.org/sp", SPSSODescriptors: []SPSSODescriptor{{}}},
		},
	}

	entities := serviceProvidersOf(group, time.Time{}, nil, nil)
	require.Len(t, entities, 2)
	assert.Equal(t, entities[0].EntityCategories(), []string{EntityCategoryPersonalized, EntityCategoryAnonymous})
	assert.Equal(t, entities[1].EntityCategories(), []string{EntityCategoryAnonymous})

	assert.Len(t, own.EntityAttributes.Attributes, 1)
	assert.Len(t, group.Extensions.EntityAttributes.Attributes, 1)
	assert.Nil(t, group.EntityDescriptors[1].Extensions)
}
