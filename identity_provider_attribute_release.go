package saml

import (
	"errors"
	"fmt"
	"strings"

	"authelia.com/provider/saml/logger"
)

// The names of the attributes that the attribute bundles of the REFEDS entity categories hold, each with the
// NameFormat urn:oasis:names:tc:SAML:2.0:attrname-format:uri. DefaultAssertionMaker states those of the fields of
// a Session under these names. A session has no field for EduPersonTargetedIDAttributeName,
// EduPersonAssuranceAttributeName and SchacHomeOrganizationAttributeName, which are stated when
// Session.CustomAttributes holds an attribute with the name.
const (
	// DisplayNameAttributeName names displayName, which is Session.UserDisplayName.
	DisplayNameAttributeName = "urn:oid:2.16.840.1.113730.3.1.241"

	// GivenNameAttributeName names givenName, which is Session.UserGivenName.
	GivenNameAttributeName = "urn:oid:2.5.4.42"

	// SurnameAttributeName names sn, which is Session.UserSurname.
	SurnameAttributeName = "urn:oid:2.5.4.4"

	// MailAttributeName names mail, which is Session.UserEmail.
	MailAttributeName = "urn:oid:0.9.2342.19200300.100.1.3"

	// EduPersonPrincipalNameAttributeName names eduPersonPrincipalName, which is Session.EduPersonPrincipalName,
	// or else Session.UserEmail.
	EduPersonPrincipalNameAttributeName = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"

	// EduPersonTargetedIDAttributeName names eduPersonTargetedID, whose value is a persistent NameID.
	EduPersonTargetedIDAttributeName = "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"

	// EduPersonScopedAffiliationAttributeName names eduPersonScopedAffiliation, which is
	// Session.UserScopedAffiliation.
	EduPersonScopedAffiliationAttributeName = "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"

	// EduPersonAssuranceAttributeName names eduPersonAssurance, whose values are those of the REFEDS Assurance
	// Framework.
	EduPersonAssuranceAttributeName = "urn:oid:1.3.6.1.4.1.5923.1.1.1.11"

	// SchacHomeOrganizationAttributeName names schacHomeOrganization, the domain name of the organization of the
	// principal.
	SchacHomeOrganizationAttributeName = "urn:oid:1.3.6.1.4.1.25178.1.2.9"
)

// ErrRequiredAttributeUnavailable is wrapped by the error of DefaultAttributeReleasePolicy when it is set to
// refuse a request that it can't release a required attribute for: a RequestedAttribute with isRequired, or the
// subject identifier that the subject-id:req entity attribute requires. The request is answered with a Responder
// status.
var ErrRequiredAttributeUnavailable = errors.New("an attribute that the service provider requires cannot be released")

// bundleAttribute returns an entry of an attribute bundle.
func bundleAttribute(friendlyName, name string) Attribute {
	return Attribute{FriendlyName: friendlyName, Name: name, NameFormat: subjectIdentifierNameFormat}
}

// ResearchAndScholarshipAttributes returns the attribute bundle of the REFEDS Research and Scholarship entity
// category, version 1.3, for DefaultAttributeReleasePolicy.EntityCategoryAttributes under
// EntityCategoryResearchAndScholarship. The bundle is a shared user identifier, which is eduPersonPrincipalName,
// with eduPersonTargetedID where the eduPersonPrincipalName may be given to another principal later, the name of
// the person, which is displayName and givenName with sn, the email address, which is mail, and the affiliation,
// which is eduPersonScopedAffiliation and is optional for the identity provider.
//
// A session with no EduPersonPrincipalName is stated with its UserEmail as the eduPersonPrincipalName, so set it
// if email addresses are ever given to another principal.
func ResearchAndScholarshipAttributes() []Attribute {
	return []Attribute{
		bundleAttribute("eduPersonPrincipalName", EduPersonPrincipalNameAttributeName),
		bundleAttribute("eduPersonTargetedID", EduPersonTargetedIDAttributeName),
		bundleAttribute("mail", MailAttributeName),
		bundleAttribute("displayName", DisplayNameAttributeName),
		bundleAttribute("givenName", GivenNameAttributeName),
		bundleAttribute("sn", SurnameAttributeName),
		bundleAttribute("eduPersonScopedAffiliation", EduPersonScopedAffiliationAttributeName),
	}
}

// PersonalizedAccessAttributes returns the attribute bundle of the REFEDS Personalized Access entity category,
// version 2, for DefaultAttributeReleasePolicy.EntityCategoryAttributes under EntityCategoryPersonalized: the
// subject-id, the name of the person as displayName, givenName and sn, mail, eduPersonScopedAffiliation,
// eduPersonAssurance and schacHomeOrganization.
func PersonalizedAccessAttributes() []Attribute {
	return []Attribute{
		bundleAttribute("subject-id", SubjectIDAttributeName),
		bundleAttribute("displayName", DisplayNameAttributeName),
		bundleAttribute("givenName", GivenNameAttributeName),
		bundleAttribute("sn", SurnameAttributeName),
		bundleAttribute("mail", MailAttributeName),
		bundleAttribute("eduPersonScopedAffiliation", EduPersonScopedAffiliationAttributeName),
		bundleAttribute("eduPersonAssurance", EduPersonAssuranceAttributeName),
		bundleAttribute("schacHomeOrganization", SchacHomeOrganizationAttributeName),
	}
}

// PseudonymousAccessAttributes returns the attribute bundle of the REFEDS Pseudonymous Access entity category,
// version 2, for DefaultAttributeReleasePolicy.EntityCategoryAttributes under EntityCategoryPseudonymous: the
// pairwise-id, eduPersonScopedAffiliation, eduPersonAssurance and schacHomeOrganization.
func PseudonymousAccessAttributes() []Attribute {
	return []Attribute{
		bundleAttribute("pairwise-id", PairwiseIDAttributeName),
		bundleAttribute("eduPersonScopedAffiliation", EduPersonScopedAffiliationAttributeName),
		bundleAttribute("eduPersonAssurance", EduPersonAssuranceAttributeName),
		bundleAttribute("schacHomeOrganization", SchacHomeOrganizationAttributeName),
	}
}

// AnonymousAccessAttributes returns the attribute bundle of the REFEDS Anonymous Access entity category, version
// 2, for DefaultAttributeReleasePolicy.EntityCategoryAttributes under EntityCategoryAnonymous:
// eduPersonScopedAffiliation and schacHomeOrganization, and nothing that identifies the principal.
func AnonymousAccessAttributes() []Attribute {
	return []Attribute{
		bundleAttribute("eduPersonScopedAffiliation", EduPersonScopedAffiliationAttributeName),
		bundleAttribute("schacHomeOrganization", SchacHomeOrganizationAttributeName),
	}
}

// DefaultAttributeReleasePolicy releases the attributes that the metadata of the service provider asks for. Its
// zero value, which is used if no AttributeReleasePolicy is specified, releases:
//
//   - the attributes that the service provider requests in the RequestedAttribute elements of its
//     AttributeConsumingService, which is the Ceiling of the AttributeReleaseRequest: the one
//     IdpAuthnRequest.AttributeConsumingService selects for single sign-on, and the default one for an
//     AttributeQuery;
//   - the subject identifier that the service provider requires with the subject-id:req entity attribute, see
//     below.
//
// To a service provider with neither, no attributes are released, and the assertion only identifies the
// principal by its NameID.
//
// A candidate is released if a RequestedAttribute has the same Name and a compatible NameFormat. The
// Name must be identical, as SAMLCore §1.3.1 requires an exact binary comparison. FriendlyName is never
// used, because SAMLCore §2.7.3.1 says it "MUST NOT be used as a basis for formally identifying SAML
// attributes". A missing NameFormat is urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified, as
// SAMLCore §2.7.3.1 and errata E89 say, and the unspecified format is compatible with any other,
// since it leaves the interpretation of the name to the implementation (SAMLCore §8.2.1).
//
// If the matching RequestedAttribute elements list values, only those values of the candidate are
// released, as SAMLMeta §2.4.4.2 says that only matching values are relevant to the service, and the
// candidate is withheld if it has none of them. Values are compared exactly, and a NameID value by its
// content and qualifiers.
//
// # Subject identifier requirement
//
// A service provider whose metadata has the entity attribute urn:oasis:names:tc:SAML:profiles:subject-id:req
// (EntityDescriptor.SubjectIDRequirement) is released the subject identifier attribute that it requires, whether
// or not it has an AttributeConsumingService (SAML2Int SDP-IDP15): the subject-id, the pairwise-id, for "any" the
// pairwise-id if the identity provider has one for the principal and otherwise the subject-id, and for "none"
// neither. The pairwise-id is preferred because service providers can't use it to correlate a principal. The
// requirement alone decides which of the two attributes is released: the other is withheld even from a service
// provider that requests it by name or is in an entity category whose attributes hold it. A service provider
// that doesn't signal a requirement, or doesn't signal one value that the profile defines, receives the two
// attributes as any other, which is only if it requests them or a category releases them.
//
// The attributes that an AttributeQuery names only narrow all of this further, so that a query is never answered
// with an attribute or a value that single sign-on would not state.
type DefaultAttributeReleasePolicy struct {
	// EntityCategoryAttributes holds, for each entity category that attributes are released by, the attributes
	// that a service provider in the category receives, with those that it requests. The key is a value of the
	// entity attribute http://macedir.org/entity-category of the metadata of the service provider, such as
	// EntityCategoryResearchAndScholarship, whose attributes ResearchAndScholarshipAttributes returns, see
	// also PersonalizedAccessAttributes, PseudonymousAccessAttributes and AnonymousAccessAttributes. An entry
	// releases a candidate as a RequestedAttribute does: by its Name and a compatible NameFormat, and only the
	// values that it lists if it lists any. A service provider in several of the categories receives the
	// attributes of each.
	//
	// No category releases anything unless it is listed, because a category is only worth what the source of the
	// metadata is: the registrar of a federation vouches for the categories in an aggregate that it signs, while
	// a service provider that supplies its own metadata can claim any. List a category only if every service
	// provider gets its metadata from a source that is trusted to assign the category, or set
	// EntityCategoryTrust.
	EntityCategoryAttributes map[string][]Attribute

	// EntityCategoryTrust reports whether the entity categories in the metadata of serviceProvider were assigned
	// by a source that is trusted to, for an identity provider that has service providers of a federation and
	// others. A service provider it returns false for is released nothing by a category. If it is nil the
	// categories of every service provider are trusted. The subject identifier requirement and the requested
	// attributes are the service provider's own to state and are not subject to it.
	EntityCategoryTrust func(serviceProvider *EntityDescriptor) bool

	// EnforceIsRequired refuses a request unless every RequestedAttribute of the AttributeConsumingService that
	// is marked isRequired is released, with at least one of the values it lists if it lists any. The error
	// wraps ErrRequiredAttributeUnavailable. By default isRequired is not acted on, and the service provider
	// receives an assertion without what the principal lacks, because metadata often marks attributes as
	// required that the service works without. An AttributeQuery is refused when single sign-on would be,
	// whichever attributes it names.
	EnforceIsRequired bool

	// EnforceSubjectIDRequirement refuses a request from a service provider that requires a subject identifier
	// which can't be stated: there is no Session.SubjectID, or no PairwiseIDProvider with a pairwise-id for the
	// principal. The error wraps ErrRequiredAttributeUnavailable. By default the assertion is made without the
	// identifier, and that is logged. SAML2Int SDP-IDP16 allows either.
	EnforceSubjectIDRequirement bool
}

// ReleaseAttributes implements AttributeReleasePolicy.
func (p DefaultAttributeReleasePolicy) ReleaseAttributes(req AttributeReleaseRequest, _ *Session, candidates []Attribute) ([]Attribute, error) {
	wanted := p.wantedAttributes(req)
	requirement := req.ServiceProviderMetadata.SubjectIDRequirement()
	identifier := requiredSubjectIdentifier(requirement, candidates)
	stated := false

	var released []Attribute

	for _, candidate := range candidates {
		if requirement != SubjectIDRequirementUnspecified && isSubjectIdentifierAttribute(candidate) {
			// The requirement decides, whatever is requested, and the identifier is stated once.
			if candidate.Name == identifier && !stated {
				released = append(released, candidate)
				stated = true
			}

			continue
		}

		if attribute, ok := narrowAttribute(wanted, candidate); ok {
			released = append(released, attribute)
		}
	}

	if requirement != SubjectIDRequirementUnspecified && requirement != SubjectIDRequirementNone && identifier == "" {
		if p.EnforceSubjectIDRequirement {
			return nil, requiredAttributeUnavailable(fmt.Sprintf("the subject identifier that subject-id:req requires (%s)", requirement))
		}

		releaseLogger(req).Printf("the service provider requires a subject identifier (%s) that can't be stated, which is left out", requirement)
	}

	if p.EnforceIsRequired && req.Ceiling != nil {
		if missing := missingRequiredAttributes(req.Ceiling.RequestedAttributes, released); len(missing) != 0 {
			return nil, requiredAttributeUnavailable(strings.Join(missing, ", "))
		}
	}

	return narrowToQueriedAttributes(req.Requested, released), nil
}

// wantedAttributes returns what the service provider of req is released, but for a subject identifier that it
// requires: the attributes that its service requests, and those of each of its entity categories that attributes
// are released by.
func (p DefaultAttributeReleasePolicy) wantedAttributes(req AttributeReleaseRequest) []Attribute {
	var wanted []Attribute

	if req.Ceiling != nil {
		for _, requested := range req.Ceiling.RequestedAttributes {
			wanted = append(wanted, requested.Attribute)
		}
	}

	if len(p.EntityCategoryAttributes) == 0 {
		return wanted
	}

	categories := req.ServiceProviderMetadata.EntityCategories()
	if len(categories) == 0 || (p.EntityCategoryTrust != nil && !p.EntityCategoryTrust(req.ServiceProviderMetadata)) {
		return wanted
	}

	for _, category := range categories {
		wanted = append(wanted, p.EntityCategoryAttributes[category]...)
	}

	return wanted
}

// isSubjectIdentifierAttribute reports whether attribute is the subject-id or the pairwise-id of the SAML V2.0
// Subject Identifier Attributes Profile, and not an attribute with the name of one in another NameFormat.
func isSubjectIdentifierAttribute(attribute Attribute) bool {
	if attribute.Name != SubjectIDAttributeName && attribute.Name != PairwiseIDAttributeName {
		return false
	}

	return compatibleAttrNameFormats(attribute.NameFormat, subjectIdentifierNameFormat)
}

// requiredSubjectIdentifier returns the name of the subject identifier attribute among candidates that meets
// requirement, or "" if none does. If both do it is the pairwise-id.
func requiredSubjectIdentifier(requirement SubjectIDRequirement, candidates []Attribute) string {
	for _, name := range []string{PairwiseIDAttributeName, SubjectIDAttributeName} {
		if !requirement.Requests(name) {
			continue
		}

		for _, candidate := range candidates {
			if candidate.Name == name && isSubjectIdentifierAttribute(candidate) {
				return name
			}
		}
	}

	return ""
}

// missingRequiredAttributes returns the quoted Name of each of requested that is marked isRequired and that
// released has no part of.
func missingRequiredAttributes(requested []RequestedAttribute, released []Attribute) []string {
	var missing []string

	for _, r := range requested {
		if r.IsRequired == nil || !*r.IsRequired {
			continue
		}

		found := false

		for _, attribute := range released {
			if _, found = narrowAttribute([]Attribute{r.Attribute}, attribute); found {
				break
			}
		}

		if !found {
			missing = append(missing, fmt.Sprintf("%q", r.Name))
		}
	}

	return missing
}

// requiredAttributeUnavailable returns the error for a request that is refused because what names can't be
// released. It holds no value of an attribute.
func requiredAttributeUnavailable(what string) error {
	return &statusError{TopLevel: StatusResponder, Err: fmt.Errorf("%w: %s", ErrRequiredAttributeUnavailable, what)}
}

// releaseLogger returns the logger of the identity provider that req is served by.
func releaseLogger(req AttributeReleaseRequest) logger.Interface {
	switch {
	case req.AuthnRequest != nil && req.AuthnRequest.IDP != nil:
		return req.AuthnRequest.IDP.logger()
	case req.Query != nil && req.Query.IDP != nil:
		return req.Query.IDP.logger()
	default:
		return logger.DefaultLogger
	}
}
