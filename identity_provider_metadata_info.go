package saml

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// MetadataInfo is what the metadata of an identity provider says about it beyond its keys and endpoints, which a
// federation, and the SAML V2.0 Deployment Profile for Federation Interoperability (SAML2Int), require. Nothing
// is published for a field that is empty. Validate reports what can't be published.
type MetadataInfo struct {
	// UIInfo describes the identity provider to a user, such as on a discovery service, and is published in the
	// Extensions of the IDPSSODescriptor. SAML2Int requires a DisplayName and a Logo (SDP-MD09), where the logo
	// is an https URL or a data URI (SDP-MD10).
	UIInfo *UIInfo

	// DiscoHints helps a discovery service to suggest the identity provider, and is published in the Extensions
	// of the IDPSSODescriptor.
	DiscoHints *DiscoHints

	// Organization is the organization that is responsible for the identity provider, and is published in the
	// EntityDescriptor. It has at least one name, display name and URL, each with a language.
	Organization *Organization

	// ContactPeople are published in the EntityDescriptor. SAML2Int requires one whose ContactType is technical,
	// with an EmailAddress (SDP-MD11), and Sirtfi one whose ContactType is other and whose REFEDSContactType is
	// REFEDSSecurityContactType.
	ContactPeople []ContactPerson

	// ErrorURL is the errorURL of the IDPSSODescriptor, a page that a service provider sends a user to when it
	// didn't receive what it needs, which explains who to ask. SAML2Int requires it, as an https URL (SDP-MD12).
	ErrorURL string

	// Scopes are the scopes of the scoped attributes that the identity provider asserts, such as example.com
	// for a subject-id of user@example.com, and are published as shibmd:Scope in the Extensions of the
	// IDPSSODescriptor and of the AttributeAuthorityDescriptor. A service provider refuses a scoped value
	// whose scope isn't published. SAML2Int requires them (SDP-IDP14), and none is a regular expression.
	//
	// The scope of a NameIDProvider that is a SubjectIdentifierScopeProvider, such as the Scope of a
	// PersistentNameIDProvider, is always published and need not be listed. The scope of each Session.SubjectID,
	// and of any other scoped attribute of a session, is not known here and must be listed.
	Scopes []string

	// EntityAttributes are published as mdattr:EntityAttributes in the Extensions of the EntityDescriptor: the
	// entity categories that the identity provider supports (EntityCategorySupportAttributeName), the
	// certifications it has (AssuranceCertificationAttributeName) and so on. A federation usually adds, or
	// removes, what it vouches for when it registers the metadata.
	EntityAttributes []Attribute
}

// SubjectIdentifierScopeProvider is an optional interface of a NameIDProvider that states scoped identifiers, such
// as the pairwise-id attribute, which allows the metadata to list their scope. PersistentNameIDProvider and
// ManagedPersistentNameIDProvider implement it.
type SubjectIdentifierScopeProvider interface {
	// SubjectIdentifierScope returns the scope of the identifiers, such as example.com, or "" if there is none.
	SubjectIdentifierScope() string
}

// SubjectIdentifierScope implements SubjectIdentifierScopeProvider. It returns Scope.
func (p PersistentNameIDProvider) SubjectIdentifierScope() string {
	return p.Scope
}

// contactTypes are the values of the contactType of a ContactPerson (SAMLMeta §2.3.2.2).
var contactTypes = []string{"technical", "support", "administrative", "billing", "other"}

// Validate returns an error if the info can't be published as valid metadata, or breaks a rule of SAML2Int about
// the form of what is published: a logo that is neither an https URL nor a data URI, or an errorURL that isn't an
// https URL. It doesn't require what SAML2Int requires to be present, as an identity provider outside a federation
// needs none of it. IdentityProvider.SignedMetadata fails with the same error, and so does ServeMetadata.
func (m MetadataInfo) Validate() error {
	if m.ErrorURL != "" && !isHTTPSURL(m.ErrorURL) {
		return fmt.Errorf("MetadataInfo.ErrorURL: %q is not an https URL", m.ErrorURL)
	}

	if err := m.UIInfo.validate("MetadataInfo.UIInfo"); err != nil {
		return err
	}

	if err := m.Organization.validate("MetadataInfo.Organization"); err != nil {
		return err
	}

	for i, contact := range m.ContactPeople {
		if !slices.Contains(contactTypes, contact.ContactType) {
			return fmt.Errorf("MetadataInfo.ContactPeople[%d]: unknown contact type %q", i, contact.ContactType)
		}
	}

	for i, scope := range m.Scopes {
		if !subjectIdentifierScope.MatchString(scope) {
			return fmt.Errorf("MetadataInfo.Scopes[%d]: %q is not a scope", i, scope)
		}
	}

	for i, attribute := range m.EntityAttributes {
		if attribute.Name == "" {
			return fmt.Errorf("MetadataInfo.EntityAttributes[%d]: no name", i)
		}

		if len(attribute.Values) == 0 {
			return fmt.Errorf("MetadataInfo.EntityAttributes[%d]: no values for %q", i, attribute.Name)
		}
	}

	return nil
}

func (m *UIInfo) validate(field string) error {
	if m == nil {
		return nil
	}

	if err := errors.Join(
		validateLocalized(field+".DisplayNames", m.DisplayNames, false),
		validateLocalized(field+".Descriptions", m.Descriptions, false),
		validateLocalized(field+".InformationURLs", m.InformationURLs, true),
		validateLocalized(field+".PrivacyStatementURLs", m.PrivacyStatementURLs, true),
	); err != nil {
		return unwrapFirst(err)
	}

	var langs []string

	for i, keywords := range m.Keywords {
		switch {
		case keywords.Lang == "":
			return fmt.Errorf("%s.Keywords[%d]: no language", field, i)
		case slices.Contains(langs, keywords.Lang):
			return fmt.Errorf("%s.Keywords[%d]: more than one for the language %q", field, i, keywords.Lang)
		case len(keywords.Values) == 0:
			return fmt.Errorf("%s.Keywords[%d]: no value", field, i)
		}

		langs = append(langs, keywords.Lang)

		for _, value := range keywords.Values {
			switch {
			case strings.TrimSpace(value) == "":
				return fmt.Errorf("%s.Keywords[%d]: a keyword is empty", field, i)
			case strings.Contains(value, "+"):
				return fmt.Errorf("%s.Keywords[%d]: the keyword %q contains a plus", field, i, value)
			}
		}
	}

	for i, logo := range m.Logos {
		// SDP-MD10. The data URI is not shown in the error, as it is the whole image.
		if !isHTTPSURL(logo.URL) && !strings.HasPrefix(strings.ToLower(logo.URL), "data:") {
			return fmt.Errorf("%s.Logos[%d]: %q is neither an https URL nor a data URI", field, i, logo.URL)
		}

		if logo.Height <= 0 || logo.Width <= 0 {
			return fmt.Errorf("%s.Logos[%d]: the height and width must be positive", field, i)
		}
	}

	return nil
}

func (m *Organization) validate(field string) error {
	if m == nil {
		return nil
	}

	if len(m.OrganizationNames) == 0 || len(m.OrganizationDisplayNames) == 0 || len(m.OrganizationURLs) == 0 {
		return fmt.Errorf("%s: a name, a display name and a URL are required", field)
	}

	return unwrapFirst(errors.Join(
		validateLocalized(field+".OrganizationNames", m.OrganizationNames, false),
		validateLocalized(field+".OrganizationDisplayNames", m.OrganizationDisplayNames, false),
		validateLocalized(field+".OrganizationURLs", m.OrganizationURLs, true),
	))
}

// unwrapFirst returns the first of the errors that were joined as err, or nil.
func unwrapFirst(err error) error {
	if joined, ok := err.(interface{ Unwrap() []error }); ok && len(joined.Unwrap()) != 0 {
		return joined.Unwrap()[0]
	}

	return err
}

// validateLocalized returns an error unless each of values has a language that no other has, and a value, which is
// an absolute http or https URL if isURL.
func validateLocalized[T LocalizedName | LocalizedURI](field string, values []T, isURL bool) error {
	var langs []string

	for i, value := range values {
		localized := LocalizedName(value)

		switch {
		case localized.Lang == "":
			return fmt.Errorf("%s[%d]: no language", field, i)
		case slices.Contains(langs, localized.Lang):
			return fmt.Errorf("%s[%d]: more than one for the language %q", field, i, localized.Lang)
		case strings.TrimSpace(localized.Value) == "":
			return fmt.Errorf("%s[%d]: no value", field, i)
		case isURL && !isWebURL(localized.Value):
			return fmt.Errorf("%s[%d]: %q is not an absolute URL", field, i, localized.Value)
		}

		langs = append(langs, localized.Lang)
	}

	return nil
}

// isHTTPSURL reports whether value is an absolute https URL with a host.
func isHTTPSURL(value string) bool {
	u, err := url.Parse(value)

	return err == nil && u.Scheme == "https" && u.Host != ""
}

// isWebURL reports whether value is an absolute http or https URL with a host.
func isWebURL(value string) bool {
	u, err := url.Parse(value)

	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

// metadataScopes returns the scopes that the metadata lists: those of MetadataInfo, then that of the
// NameIDProvider if it has one that isn't among them. Scopes are compared without regard to case, as the values
// they are part of are.
func (idp *IdentityProvider) metadataScopes() []string {
	scopes := make([]string, 0, len(idp.MetadataInfo.Scopes)+1)

	add := func(scope string) {
		if scope != "" && !slices.ContainsFunc(scopes, func(other string) bool { return strings.EqualFold(other, scope) }) {
			scopes = append(scopes, scope)
		}
	}

	for _, scope := range idp.MetadataInfo.Scopes {
		add(scope)
	}

	if provider, ok := idp.nameIDProvider().(SubjectIdentifierScopeProvider); ok {
		add(provider.SubjectIdentifierScope())
	}

	return scopes
}

// checkMetadataInfo returns an error if MetadataInfo, or the scope of the NameIDProvider that is published with
// it, is not valid.
func (idp *IdentityProvider) checkMetadataInfo() error {
	if err := idp.MetadataInfo.Validate(); err != nil {
		return err
	}

	if provider, ok := idp.nameIDProvider().(SubjectIdentifierScopeProvider); ok {
		if scope := provider.SubjectIdentifierScope(); scope != "" && !subjectIdentifierScope.MatchString(scope) {
			return fmt.Errorf("the scope %q of the NameIDProvider is not a scope", scope)
		}
	}

	return nil
}

// describeMetadata adds what MetadataInfo holds, and the scopes, to the metadata, and then calls MetadataHook. The
// metadata receives copies, so changing it doesn't change the MetadataInfo.
func (idp *IdentityProvider) describeMetadata(ed *EntityDescriptor) {
	info := idp.MetadataInfo

	if len(info.EntityAttributes) != 0 {
		ed.extensions().EntityAttributes = &EntityAttributes{Attributes: cloneAttributes(info.EntityAttributes)}
	}

	ed.Organization = info.Organization.clone()

	for _, contact := range info.ContactPeople {
		contact.EmailAddresses = slices.Clone(contact.EmailAddresses)
		contact.TelephoneNumbers = slices.Clone(contact.TelephoneNumbers)
		ed.ContactPeople = append(ed.ContactPeople, contact)
	}

	values := idp.metadataScopes()

	scopes := make([]Scope, 0, len(values))
	for _, scope := range values {
		scopes = append(scopes, Scope{Value: scope})
	}

	for i := range ed.IDPSSODescriptors {
		role := &ed.IDPSSODescriptors[i].RoleDescriptor
		role.ErrorURL = info.ErrorURL

		if ui := info.UIInfo.clone(); !ui.isEmpty() {
			role.extensions().UIInfo = ui
		}

		if hints := info.DiscoHints.clone(); !hints.isEmpty() {
			role.extensions().DiscoHints = hints
		}

		if len(scopes) != 0 {
			role.extensions().Scopes = slices.Clone(scopes)
		}
	}

	// An attribute authority asserts the same scoped attributes as the single sign-on service, and a service
	// provider looks for the scopes in the role that it received them from.
	for i := range ed.AttributeAuthorityDescriptors {
		if len(scopes) != 0 {
			ed.AttributeAuthorityDescriptors[i].extensions().Scopes = slices.Clone(scopes)
		}
	}

	if idp.MetadataHook != nil {
		idp.MetadataHook(ed)
	}
}

// extensions returns the Extensions of the entity, which it makes if there is none.
func (m *EntityDescriptor) extensions() *Extensions {
	if m.Extensions == nil {
		m.Extensions = &Extensions{}
	}

	return m.Extensions
}

// extensions returns the Extensions of the role, which it makes if there is none.
func (m *RoleDescriptor) extensions() *Extensions {
	if m.Extensions == nil {
		m.Extensions = &Extensions{}
	}

	return m.Extensions
}

func cloneAttributes(attributes []Attribute) []Attribute {
	cloned := slices.Clone(attributes)
	for i := range cloned {
		cloned[i].Values = slices.Clone(cloned[i].Values)
	}

	return cloned
}

func (m *UIInfo) clone() *UIInfo {
	if m == nil {
		return nil
	}

	cloned := &UIInfo{
		DisplayNames:         slices.Clone(m.DisplayNames),
		Descriptions:         slices.Clone(m.Descriptions),
		Keywords:             slices.Clone(m.Keywords),
		Logos:                slices.Clone(m.Logos),
		InformationURLs:      slices.Clone(m.InformationURLs),
		PrivacyStatementURLs: slices.Clone(m.PrivacyStatementURLs),
	}

	for i := range cloned.Keywords {
		cloned.Keywords[i].Values = slices.Clone(cloned.Keywords[i].Values)
	}

	return cloned
}

func (m *DiscoHints) clone() *DiscoHints {
	if m == nil {
		return nil
	}

	return &DiscoHints{
		IPHints:          slices.Clone(m.IPHints),
		DomainHints:      slices.Clone(m.DomainHints),
		GeolocationHints: slices.Clone(m.GeolocationHints),
	}
}

func (m *Organization) clone() *Organization {
	if m == nil {
		return nil
	}

	return &Organization{
		Extensions:               m.Extensions,
		OrganizationNames:        slices.Clone(m.OrganizationNames),
		OrganizationDisplayNames: slices.Clone(m.OrganizationDisplayNames),
		OrganizationURLs:         slices.Clone(m.OrganizationURLs),
	}
}
