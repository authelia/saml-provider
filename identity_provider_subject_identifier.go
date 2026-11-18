package saml

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
)

// SubjectIDAttributeName and PairwiseIDAttributeName are the names of the attributes of the SAML V2.0 Subject
// Identifier Attributes Profile, whose NameFormat is urn:oasis:names:tc:SAML:2.0:attrname-format:uri. Both have
// one value, of the form uniqueID@scope, which is compared without regard to case. A subject-id is the same for
// every service provider, and a pairwise-id is an opaque one that differs for each.
const (
	SubjectIDAttributeName  = "urn:oasis:names:tc:SAML:attribute:subject-id"
	PairwiseIDAttributeName = "urn:oasis:names:tc:SAML:attribute:pairwise-id"
)

// subjectIdentifierNameFormat is the NameFormat of both attributes.
const subjectIdentifierNameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"

// subjectIdentifier and subjectIdentifierScope are the syntax that the profile gives the value of both attributes
// and its scope: a uniqueID of 1 to 127 ASCII letters, digits, "=" and "-", then "@", then a scope of 1 to 127 ASCII
// letters, digits, "-" and ".", each of which starts with a letter or a digit. \z rather than $ is the end of the
// value, which a trailing newline is not part of.
var (
	subjectIdentifier      = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9=-]{0,126}@[A-Za-z0-9][A-Za-z0-9.-]{0,126}\z`)
	subjectIdentifierScope = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9.-]{0,126}\z`)
)

// ValidateSubjectIdentifier returns an error unless value has the syntax of the value of a subject-id or
// pairwise-id attribute: uniqueID@scope, where the uniqueID is 1 to 127 ASCII letters, digits, "=" and "-", the
// scope is 1 to 127 ASCII letters, digits, "-" and ".", and both start with a letter or a digit. The error doesn't
// hold the value.
func ValidateSubjectIdentifier(value string) error {
	if !subjectIdentifier.MatchString(value) {
		return errors.New("the value is not a subject identifier of the form uniqueID@scope")
	}

	return nil
}

// PairwiseIDProvider is an optional interface of a NameIDProvider, which is required for the pairwise-id attribute
// to be a candidate for release. The NameIDProvider issues the pseudonyms of a principal, so it is what can
// derive this one. PersistentNameIDProvider implements it.
//
// The attribute is offered to the AttributeReleasePolicy with the other attributes of the principal, for single
// sign-on and for an AttributeQuery, so it is only stated to a service provider that the policy releases it to:
// with DefaultAttributeReleasePolicy, one whose metadata requests it, requires it with the subject-id:req entity
// attribute, or is in an entity category whose attributes hold it.
type PairwiseIDProvider interface {
	// PairwiseID returns the value of the pairwise-id attribute of the principal of session for serviceProvider,
	// which is uniqueID@scope, or "" if there is none. idpEntityID is the entity ID of the identity provider.
	// The uniqueID must be the same whenever it is asked for, differ for each service provider, and not be
	// derivable from anything the service provider knows. A value that ValidateSubjectIdentifier refuses, or an
	// error, fails the request: no assertion is made.
	PairwiseID(r *http.Request, idpEntityID string, serviceProvider *EntityDescriptor, session *Session) (string, error)
}

// subjectIdentifierAttribute returns the attribute name with the one value.
func subjectIdentifierAttribute(name, value string) Attribute {
	return Attribute{
		Name:       name,
		NameFormat: subjectIdentifierNameFormat,
		Values:     []AttributeValue{{Type: "xs:string", Value: value}},
	}
}

// principalAttributes returns every attribute that can be stated to serviceProvider about the principal of
// session, which DefaultAssertionMaker and ServeAttributeQuery offer to the AttributeReleasePolicy: those that
// service requests under a name of its own, those of the session, and the pairwise-id, if the NameIDProvider is a
// PairwiseIDProvider.
//
// A Session.SubjectID that doesn't have the syntax of a subject-id is left out, and reported without the value, as
// the attribute is optional and the service provider would refuse it or, worse, accept it, as a warning of the
// request in state.
func (idp *IdentityProvider) principalAttributes(r *http.Request, state requestState, serviceProvider *EntityDescriptor, service *AttributeConsumingService, session *Session) ([]Attribute, error) {
	attributes := append(requestedNameAttributes(service, session), sessionAttributes(session)...)

	if session.SubjectID != "" {
		if err := ValidateSubjectIdentifier(session.SubjectID); err != nil {
			idp.observe(r, state.warning(EventAttributeRelease,
				ErrServerError.WithDebugf("not stating the subject-id of the session: %s", err).WithWrap(err)))
		} else {
			attributes = append(attributes, subjectIdentifierAttribute(SubjectIDAttributeName, session.SubjectID))
		}
	}

	provider, ok := idp.nameIDProvider().(PairwiseIDProvider)
	if !ok {
		return attributes, nil
	}

	pairwiseID, err := provider.PairwiseID(r, idp.entityID(), serviceProvider, session)
	if err != nil {
		return nil, fmt.Errorf("cannot derive the pairwise-id: %w", err)
	}

	if pairwiseID == "" {
		return attributes, nil
	}

	if err = ValidateSubjectIdentifier(pairwiseID); err != nil {
		return nil, fmt.Errorf("the PairwiseIDProvider returned an invalid pairwise-id: %w", err)
	}

	return append(attributes, subjectIdentifierAttribute(PairwiseIDAttributeName, pairwiseID)), nil
}
