package saml

import (
	"slices"
	"strings"
)

// The names of the entity attributes that federations use, each with the NameFormat
// urn:oasis:names:tc:SAML:2.0:attrname-format:uri.
const (
	// EntityCategoryAttributeName names the categories that an entity belongs to, which its registrar vouches for.
	EntityCategoryAttributeName = "http://macedir.org/entity-category"

	// EntityCategorySupportAttributeName names the categories that an entity supports: an identity provider
	// lists a category here when it releases the attributes of the category to the service providers in it.
	EntityCategorySupportAttributeName = "http://macedir.org/entity-category-support"

	// AssuranceCertificationAttributeName names the certifications that an entity has, such as
	// AssuranceCertificationSIRTFI (SAML V2.0 Identity Assurance Profiles §3).
	AssuranceCertificationAttributeName = "urn:oasis:names:tc:SAML:attribute:assurance-certification"

	// SubjectIDRequirementAttributeName names the subject identifier that a service provider requires. See
	// EntityDescriptor.SubjectIDRequirement.
	SubjectIDRequirementAttributeName = "urn:oasis:names:tc:SAML:profiles:subject-id:req"
)

// Values of the entity attributes that federations use.
const (
	// EntityCategoryResearchAndScholarship is the REFEDS Research and Scholarship category.
	EntityCategoryResearchAndScholarship = "http://refeds.org/category/research-and-scholarship"

	// EntityCategoryCodeOfConductV1 is the GÉANT Data Protection Code of Conduct, version 1.
	EntityCategoryCodeOfConductV1 = "http://www.geant.net/uri/dataprotection-code-of-conduct/v1"

	// EntityCategoryCodeOfConductV2 is the REFEDS Data Protection Code of Conduct, version 2.
	EntityCategoryCodeOfConductV2 = "https://refeds.org/category/code-of-conduct/v2"

	// EntityCategoryAnonymous, EntityCategoryPseudonymous and EntityCategoryPersonalized are the REFEDS access
	// categories.
	EntityCategoryAnonymous    = "https://refeds.org/category/anonymous"
	EntityCategoryPseudonymous = "https://refeds.org/category/pseudonymous"
	EntityCategoryPersonalized = "https://refeds.org/category/personalized"

	// AssuranceCertificationSIRTFI is the REFEDS Security Incident Response Trust Framework for Federated
	// Identity, a value of AssuranceCertificationAttributeName.
	AssuranceCertificationSIRTFI = "https://refeds.org/sirtfi"
)

// SubjectIDRequirement is the subject identifier attribute that a service provider says it requires in its
// metadata (SAML V2.0 Subject Identifier Attributes Profile §3.5.1).
type SubjectIDRequirement string

const (
	// SubjectIDRequirementUnspecified is that of a service provider which doesn't signal a requirement, or
	// doesn't signal exactly one that the profile defines. SAML2Int (SDP-IDP17) then leaves the identity provider
	// free to state either attribute, both or neither.
	SubjectIDRequirementUnspecified SubjectIDRequirement = ""

	// SubjectIDRequirementSubjectID requires the subject-id attribute.
	SubjectIDRequirementSubjectID SubjectIDRequirement = "subject-id"

	// SubjectIDRequirementPairwiseID requires the pairwise-id attribute.
	SubjectIDRequirementPairwiseID SubjectIDRequirement = "pairwise-id"

	// SubjectIDRequirementNone requires neither attribute.
	SubjectIDRequirementNone SubjectIDRequirement = "none"

	// SubjectIDRequirementAny requires either attribute, whichever the identity provider chooses.
	SubjectIDRequirementAny SubjectIDRequirement = "any"
)

// Requests reports whether the requirement is met by the attribute called name, which is SubjectIDAttributeName
// or PairwiseIDAttributeName. It is false for both when nothing is signalled, and for every other attribute.
func (r SubjectIDRequirement) Requests(name string) bool {
	switch r {
	case SubjectIDRequirementSubjectID:
		return name == SubjectIDAttributeName
	case SubjectIDRequirementPairwiseID:
		return name == PairwiseIDAttributeName
	case SubjectIDRequirementAny:
		return name == SubjectIDAttributeName || name == PairwiseIDAttributeName
	default:
		return false
	}
}

// EntityAttributeValues returns the values of the entity attribute called name in the Extensions of the entity,
// without the white space around them, or nil if there is none.
//
// An entity attribute is a claim about the entity, and is only worth what the source of the metadata is: the
// registrar of a federation vouches for the categories in an aggregate that it signs, which a MetadataVerifier
// verifies, while metadata that a service provider supplies itself can claim anything. Don't release attributes
// on the strength of a category unless the metadata comes from a source that is trusted to assign it.
func (m *EntityDescriptor) EntityAttributeValues(name string) []string {
	if m == nil || m.Extensions == nil || m.Extensions.EntityAttributes == nil {
		return nil
	}

	var values []string

	for _, attribute := range m.Extensions.EntityAttributes.Attributes {
		if attribute.Name != name {
			continue
		}

		for _, value := range attribute.Values {
			if trimmed := strings.TrimSpace(value.Value); trimmed != "" {
				values = append(values, trimmed)
			}
		}
	}

	return values
}

// EntityCategories returns the entity categories that the entity belongs to, the values of
// EntityCategoryAttributeName. See EntityAttributeValues for when they can be trusted.
func (m *EntityDescriptor) EntityCategories() []string {
	return m.EntityAttributeValues(EntityCategoryAttributeName)
}

// HasEntityCategory reports whether the entity belongs to category, such as
// EntityCategoryResearchAndScholarship. See EntityAttributeValues for when it can be trusted.
func (m *EntityDescriptor) HasEntityCategory(category string) bool {
	return slices.Contains(m.EntityCategories(), category)
}

// SubjectIDRequirement returns the subject identifier attribute that the service provider requires, from the
// entity attribute SubjectIDRequirementAttributeName of its metadata. The profile gives the attribute exactly one
// value, so SubjectIDRequirementUnspecified is returned if it has none, one that the profile doesn't define, or
// two that differ.
//
// SAML2Int (SDP-IDP15) requires an identity provider to honour it, and DefaultAttributeReleasePolicy does: it
// releases the attribute whose name Requests reports to a service provider that doesn't list it as a
// RequestedAttribute, the pairwise-id for SubjectIDRequirementAny if there is one, and neither for
// SubjectIDRequirementNone. Unlike an entity category the requirement is the service provider's own to state, and
// asks for no more than an identifier, but subject-id is one that every service provider shares, so a policy of
// the application may still want to decide who receives it.
func (m *EntityDescriptor) SubjectIDRequirement() SubjectIDRequirement {
	values := m.EntityAttributeValues(SubjectIDRequirementAttributeName)
	if len(values) == 0 {
		return SubjectIDRequirementUnspecified
	}

	for _, value := range values[1:] {
		if value != values[0] {
			return SubjectIDRequirementUnspecified
		}
	}

	switch requirement := SubjectIDRequirement(values[0]); requirement {
	case SubjectIDRequirementSubjectID, SubjectIDRequirementPairwiseID, SubjectIDRequirementNone, SubjectIDRequirementAny:
		return requirement
	default:
		return SubjectIDRequirementUnspecified
	}
}

// UIInfo returns the mdui:UIInfo of the entity, which is that of its first SPSSODescriptor that has one, then of
// its first IDPSSODescriptor that has one, or nil if there is none.
//
// What it holds is written by the entity it describes and is not vetted unless the source of the metadata does
// so. Escape the text when it is shown, and don't have the browser of the user fetch a logo from its URL or render
// one from a data URI, which may be an SVG with a script, without restricting what it can be.
func (m *EntityDescriptor) UIInfo() *UIInfo {
	if m == nil {
		return nil
	}

	for i := range m.SPSSODescriptors {
		if extensions := m.SPSSODescriptors[i].Extensions; extensions != nil && extensions.UIInfo != nil {
			return extensions.UIInfo
		}
	}

	for i := range m.IDPSSODescriptors {
		if extensions := m.IDPSSODescriptors[i].Extensions; extensions != nil && extensions.UIInfo != nil {
			return extensions.UIInfo
		}
	}

	return nil
}

// DisplayName returns a name of the entity to show to a user, such as on a consent page, in the first of langs
// that it has a name in, see UIInfo.DisplayName. It is the mdui:DisplayName, or else the ServiceName of the first
// AttributeConsumingService that has one, or else the OrganizationDisplayName, or "" if there is none of them, when
// the entity ID is all there is to show. See UIInfo for how far it can be trusted.
func (m *EntityDescriptor) DisplayName(langs ...string) string {
	if m == nil {
		return ""
	}

	if name := m.UIInfo().DisplayName(langs...); name != "" {
		return name
	}

	for i := range m.SPSSODescriptors {
		for _, service := range m.SPSSODescriptors[i].AttributeConsumingServices {
			if name := localizedValue(service.ServiceNames, langs); name != "" {
				return name
			}
		}
	}

	if m.Organization != nil {
		return localizedValue(m.Organization.OrganizationDisplayNames, langs)
	}

	return ""
}

// DisplayName returns the name of the entity in the first of langs that it has one in, or else in English, or
// else the first one, or "" if there is none. A language matches one that is more or less specific, so that de-AT
// finds de, and case is ignored.
func (m *UIInfo) DisplayName(langs ...string) string {
	if m == nil {
		return ""
	}

	return localizedValue(m.DisplayNames, langs)
}

// Description returns the description of the entity, in the language that DisplayName would choose.
func (m *UIInfo) Description(langs ...string) string {
	if m == nil {
		return ""
	}

	return localizedValue(m.Descriptions, langs)
}

// InformationURL returns the URL of information about the entity, in the language that DisplayName would choose.
func (m *UIInfo) InformationURL(langs ...string) string {
	if m == nil {
		return ""
	}

	return localizedValue(m.InformationURLs, langs)
}

// PrivacyStatementURL returns the URL of the privacy statement of the entity, in the language that DisplayName
// would choose.
func (m *UIInfo) PrivacyStatementURL(langs ...string) string {
	if m == nil {
		return ""
	}

	return localizedValue(m.PrivacyStatementURLs, langs)
}

// LocalizedLogos returns the logos for the first of langs that there is a logo for, or else those for every
// language, which have no Lang, or else all of them. The caller chooses among them by size.
func (m *UIInfo) LocalizedLogos(langs ...string) []Logo {
	if m == nil {
		return nil
	}

	for _, lang := range append(langs, "") {
		var logos []Logo

		for _, logo := range m.Logos {
			if (lang == "" && logo.Lang == "") || (lang != "" && languageMatches(logo.Lang, lang)) {
				logos = append(logos, logo)
			}
		}

		if len(logos) != 0 {
			return logos
		}
	}

	return m.Logos
}

// localizedValue returns the value in the first of langs that has one, or else in English, or else the first one.
func localizedValue[T LocalizedName | LocalizedURI](values []T, langs []string) string {
	for _, lang := range append(langs, "en") {
		for _, value := range values {
			if localized := LocalizedName(value); languageMatches(localized.Lang, lang) {
				return strings.TrimSpace(localized.Value)
			}
		}
	}

	if len(values) == 0 {
		return ""
	}

	return strings.TrimSpace(LocalizedName(values[0]).Value)
}

// languageMatches reports whether the language tags are the same, or one is the other with further subtags.
func languageMatches(a, b string) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	if a == "" || b == "" {
		return false
	}

	return a == b || strings.HasPrefix(a, b+"-") || strings.HasPrefix(b, a+"-")
}
