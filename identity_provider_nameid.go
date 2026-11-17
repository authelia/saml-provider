package saml

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
)

// NameIDRequest describes the NameID that a NameIDProvider is asked to issue.
type NameIDRequest struct {
	// ServiceProvider is the metadata of the service provider the assertion is for.
	ServiceProvider *EntityDescriptor

	// Format is the format of the NameID, which is resolved: never empty, unspecified or the encrypted
	// format, which asks for an EncryptedID of a format that is resolved as if it were left open.
	Format string

	// NameQualifier is the entity ID of the identity provider, which is the NameQualifier of the NameID
	// (SAMLCore §8.3.7).
	NameQualifier string

	// SPNameQualifier is the SP entity ID, or an affiliation that it is a member of which the
	// NameIDPolicy of the request named, as SAMLCore §3.4.1.1 allows.
	SPNameQualifier string

	// AllowCreate is the AllowCreate of the NameIDPolicy, which is false when it is absent.
	AllowCreate bool
}

// NameIDProvider is an interface used by IdentityProvider to issue the NameID of an assertion for
// a format that the NameIDPolicy of its request, the metadata of the service provider and the
// session resolve. The default implementation is DefaultNameIDProvider, which is used if no
// NameIDProvider is specified. PersistentNameIDProvider and ManagedPersistentNameIDProvider also issue
// persistent identifiers.
//
// Applications that issue persistent identifiers must refuse to create one when AllowCreate is
// false, as SAMLCore §3.4.1.1 requires, but may still return one that already exists. AllowCreate
// doesn't apply to transient identifiers. Queries by a transient NameID, from SAMLCore Part 3, need a
// provider which stores the values it issues.
//
// IdpLogoutRequest.MatchesSession only finds Session.NameID by itself, when Session.NameIDFormat is
// set and the NameID was issued in that format. Single logout by any other NameID, such as a random
// transient one or one that names an affiliation, needs a SessionProvider which is a
// SessionParticipantProvider, which records the NameID asserted to each service provider.
type NameIDProvider interface {
	// NameIDFormats returns the formats the provider can issue, in order of preference. They're
	// advertised in the metadata of the identity provider.
	NameIDFormats() []string

	// NameID must return ErrInvalidNameIDPolicy (wrapped or not) before creating anything when it
	// can't issue req.Format, because resolution may try other formats after it. The NameID should
	// carry req.Format and req.SPNameQualifier. Any of Format, SPNameQualifier and NameQualifier left
	// empty is filled in with req.Format, req.SPNameQualifier and the entity ID of the identity
	// provider, on a copy.
	NameID(r *http.Request, req NameIDRequest, session *Session) (*NameID, error)
}

// DefaultNameIDProvider issues the NameID of the session when the requested format is the NameIDFormat
// of the session, and a random transient NameID, which it doesn't store, for the transient format. It
// refuses any other format. It doesn't check AllowCreate, because it creates no persistent identifiers.
//
// It never issues the persistent format, even when the session has it, as a persistent NameID must be an
// opaque pseudonym of the principal for one service provider or affiliation, which it can't derive
// (SAMLCore §8.3.7): PersistentNameIDProvider and ManagedPersistentNameIDProvider issue them, and use
// this provider for the other formats. A transient NameID is always random, rather than the NameID of a transient session, which would be the
// same for every service provider (SAMLCore §8.3.8).
//
// The identity provider asserts a transient NameID again to a service provider that already received
// one in the session, if the SessionProvider is a SessionParticipantProvider, so a random value is
// usually issued once for each service provider in a session. It is recorded only when the response is
// sent, so concurrent first requests to a service provider may each issue their own, which are each
// recorded and each sent a LogoutRequest.
type DefaultNameIDProvider struct {
	// Formats are the formats advertised in metadata, and that are offered to a service provider
	// whose request leaves the format open. Defaults to transient.
	Formats []string
}

// NameIDFormats implements NameIDProvider.
func (p DefaultNameIDProvider) NameIDFormats() []string {
	if len(p.Formats) == 0 {
		return []string{string(TransientNameIDFormat)}
	}

	return p.Formats
}

// NameID implements NameIDProvider. The NameQualifier is left empty, and is set to the entity ID of
// the identity provider when the NameID is resolved.
func (DefaultNameIDProvider) NameID(_ *http.Request, req NameIDRequest, session *Session) (*NameID, error) {
	var value string

	switch {
	case req.Format == string(PersistentNameIDFormat):
		return nil, fmt.Errorf("%w: persistent NameIDs need a NameIDProvider that issues them, such as PersistentNameIDProvider", ErrInvalidNameIDPolicy)
	case req.Format == string(TransientNameIDFormat):
		// 128 bits from RandReader, which is crypto/rand unless a test replaces it.
		value = base64.RawURLEncoding.EncodeToString(randomBytes(16))
	case session.NameIDFormat != "" && session.NameIDFormat == req.Format:
		// Not ErrInvalidNameIDPolicy, which would fall back to another format: the session is incomplete.
		if session.NameID == "" {
			return nil, fmt.Errorf("the session has the NameIDFormat %q but no NameID", session.NameIDFormat)
		}

		value = session.NameID
	default:
		return nil, fmt.Errorf("%w: cannot issue a NameID with the format %q", ErrInvalidNameIDPolicy, req.Format)
	}

	return &NameID{
		Format:          req.Format,
		SPNameQualifier: req.SPNameQualifier,
		Value:           value,
	}, nil
}

// nameIDProvider returns the NameIDProvider of idp, or DefaultNameIDProvider if there is none.
func (idp *IdentityProvider) nameIDProvider() NameIDProvider {
	if idp.NameIDProvider != nil {
		return idp.NameIDProvider
	}

	return DefaultNameIDProvider{}
}

// nameIDFormatHasQualifiers reports whether a NameID of format may carry NameQualifier, SPNameQualifier
// and SPProvidedID. SAMLCore §8.3.6 requires them to be omitted from one of the entity format.
func nameIDFormatHasQualifiers(format string) bool {
	return format != string(EntityNameIDFormat)
}

// isUnspecifiedNameIDFormat reports whether format leaves the format open, as SAMLCore §3.4.1.1
// describes.
func isUnspecifiedNameIDFormat(format string) bool {
	switch format {
	case "", string(UnspecifiedNameIDFormat), unspecifiedNameIDFormat:
		return true
	default:
		return false
	}
}

// resolveNameID returns the NameID of the assertion for session, following the NameIDPolicy of the
// request (SAMLCore §3.4.1.1). A format the policy names is the only candidate. A format left open,
// or the encrypted format, which asks for an EncryptedID of any format,
// is chosen from the format of the NameID in the Subject of the request, then those in the metadata
// of the service provider that the NameIDProvider supports, then the format of the session, then
// transient. A transient NameID already asserted to the service provider in the session is asserted
// again, rather than asking the NameIDProvider. The error wraps ErrInvalidNameIDPolicy when the
// policy can't be satisfied.
func (req *IdpAuthnRequest) resolveNameID(session *Session) (*NameID, error) {
	policy := req.Request.NameIDPolicy
	if policy == nil {
		policy = &NameIDPolicy{}
	}

	spEntityID := req.ServiceProviderMetadata.EntityID
	spNameQualifier := spEntityID

	if policy.SPNameQualifier != nil && *policy.SPNameQualifier != spEntityID {
		if err := req.IDP.checkAffiliation(req.HTTPRequest, spEntityID, *policy.SPNameQualifier); err != nil {
			return nil, err
		}

		spNameQualifier = *policy.SPNameQualifier
	}

	provider := req.IDP.nameIDProvider()

	var candidates []string

	format := ""
	if policy.Format != nil {
		format = *policy.Format
	}

	switch {
	case format == encryptedNameIDFormat:
		// The identifier that is encrypted can be of any type, and the service provider can't ask for a
		// particular one, so the format is chosen as if it were left open, which prefers the formats of its
		// metadata, as errata E6 suggests. MakeAssertionEl sends the NameID as an EncryptedID.
		if req.spEncryptionKeyDescriptor() == nil {
			return nil, fmt.Errorf("%w: the request requires an EncryptedID, and the service provider has no encryption key", ErrInvalidNameIDPolicy)
		}

		candidates = req.openNameIDFormats(provider, session)
	case !isUnspecifiedNameIDFormat(format):
		candidates = []string{format}
	default:
		candidates = req.openNameIDFormats(provider, session)
	}

	for _, candidate := range candidates {
		nameID, err := req.issueNameID(provider, NameIDRequest{
			ServiceProvider: req.ServiceProviderMetadata,
			Format:          candidate,
			NameQualifier:   req.IDP.entityID(),
			SPNameQualifier: spNameQualifier,
			AllowCreate:     policy.AllowCreate != nil && *policy.AllowCreate,
		}, session)

		if errors.Is(err, ErrInvalidNameIDPolicy) {
			continue
		}

		return nameID, err
	}

	return nil, fmt.Errorf("%w: no NameID could be issued for the formats %q", ErrInvalidNameIDPolicy, candidates)
}

// issueNameID returns the NameID of the format of nameIDReq: the transient NameID already asserted to the
// service provider in the session, if there is one, or otherwise the one the provider issues, completed.
func (req *IdpAuthnRequest) issueNameID(provider NameIDProvider, nameIDReq NameIDRequest, session *Session) (*NameID, error) {
	if nameIDReq.Format == string(TransientNameIDFormat) {
		reused, err := req.participantTransientNameID(session, nameIDReq.SPNameQualifier)
		if err != nil || reused != nil {
			return reused, err
		}
	}

	nameID, err := provider.NameID(req.HTTPRequest, nameIDReq, session)
	if err != nil {
		return nil, err
	}

	if nameID == nil || nameID.Value == "" {
		return nil, fmt.Errorf("the NameIDProvider returned no NameID for the format %q", nameIDReq.Format)
	}

	if nameID.Format == encryptedNameIDFormat {
		return nil, errors.New("the NameIDProvider returned a NameID of the encrypted format, which is not a format of an identifier")
	}

	return req.completeNameID(nameID, nameIDReq.Format, nameIDReq.SPNameQualifier), nil
}

// participantTransientNameID returns the transient NameID that was most recently asserted to the service
// provider in the session with spNameQualifier, as recorded by the SessionParticipantProvider, or nil if
// there is none or the SessionProvider isn't one. Asserting it again keeps the service provider one
// participant of a logout (SAMLProfiles §4.4.2), whose LogoutRequest names one NameID.
func (req *IdpAuthnRequest) participantTransientNameID(session *Session, spNameQualifier string) (*NameID, error) {
	provider, ok := req.IDP.SessionProvider.(SessionParticipantProvider)
	if !ok {
		return nil, nil
	}

	participants, err := provider.SessionParticipants(req.HTTPRequest, session)
	if err != nil {
		return nil, fmt.Errorf("cannot load the participants of the session: %w", err)
	}

	var latest *SessionParticipant

	for i := range participants {
		participant := &participants[i]

		if participant.ServiceProviderEntityID != req.ServiceProviderMetadata.EntityID ||
			participant.NameID.Format != string(TransientNameIDFormat) ||
			participant.NameID.SPNameQualifier != spNameQualifier {
			continue
		}

		if latest == nil || !participant.IssueInstant.Before(latest.IssueInstant) {
			latest = participant
		}
	}

	if latest == nil {
		return nil, nil
	}

	nameID := latest.NameID

	return &nameID, nil
}

// completeNameID returns a copy of the NameID a provider issued, with an empty Format,
// SPNameQualifier or NameQualifier filled with format, spNameQualifier or the entity ID of the
// identity provider. A NameID of the entity format has no qualifiers or SPProvidedID, which SAMLCore
// §8.3.6 requires to be omitted.
func (req *IdpAuthnRequest) completeNameID(nameID *NameID, format, spNameQualifier string) *NameID {
	issued := *nameID

	if issued.Format == "" {
		issued.Format = format
	}

	if !nameIDFormatHasQualifiers(issued.Format) {
		issued.NameQualifier, issued.SPNameQualifier, issued.SPProvidedID = "", "", ""

		return &issued
	}

	if issued.SPNameQualifier == "" {
		issued.SPNameQualifier = spNameQualifier
	}

	if issued.NameQualifier == "" {
		issued.NameQualifier = req.IDP.entityID()
	}

	return &issued
}

// openNameIDFormats returns the candidate formats when the request leaves the format open: the format
// of the NameID in the Subject of the request, which the assertion must have (SAMLCore §3.4.1), then
// those the metadata of the service provider lists that provider supports, in order, then the format
// of the session, then transient. An unspecified format is never a candidate, and neither is the
// encrypted format.
func (req *IdpAuthnRequest) openNameIDFormats(provider NameIDProvider, session *Session) []string {
	supported := provider.NameIDFormats()

	var candidates []string

	add := func(format string) {
		// The encrypted format is a request for an EncryptedID, never the format of an identifier.
		if !isUnspecifiedNameIDFormat(format) && format != encryptedNameIDFormat && !slices.Contains(candidates, format) {
			candidates = append(candidates, format)
		}
	}

	if subject := req.Request.Subject; subject != nil && subject.NameID != nil {
		add(subject.NameID.Format)
	}

	for _, descriptor := range req.ServiceProviderMetadata.SPSSODescriptors {
		for _, format := range descriptor.NameIDFormats {
			if slices.Contains(supported, string(format)) {
				add(string(format))
			}
		}
	}

	add(session.NameIDFormat)
	add(string(TransientNameIDFormat))

	return candidates
}

// checkAffiliation returns an error unless affiliationID is the entity ID of an affiliation, which is
// current and lists serviceProviderID as a member (SAMLMeta §2.5). It uses the ServiceProviderProvider
// directly, because an affiliation has no SPSSODescriptor. The error wraps ErrInvalidNameIDPolicy,
// unless the ServiceProviderProvider failed for another reason than that the entity doesn't exist.
func (idp *IdentityProvider) checkAffiliation(r *http.Request, serviceProviderID, affiliationID string) error {
	entity, err := idp.ServiceProviderProvider.GetServiceProvider(r, affiliationID)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("%w: the affiliation %q is unknown", ErrInvalidNameIDPolicy, affiliationID)
	case err != nil:
		return fmt.Errorf("cannot get the affiliation %q: %w", affiliationID, err)
	case entity == nil || entity.AffiliationDescriptor == nil:
		return fmt.Errorf("%w: the entity %q is not an affiliation", ErrInvalidNameIDPolicy, affiliationID)
	}

	now := TimeNow()

	if expiredAt(entity.ValidUntil, now) || expiredAt(entity.AffiliationDescriptor.ValidUntil, now) {
		return fmt.Errorf("%w: the affiliation %q has expired", ErrInvalidNameIDPolicy, affiliationID)
	}

	if !slices.Contains(entity.AffiliationDescriptor.AffiliateMembers, serviceProviderID) {
		return fmt.Errorf("%w: the service provider %q is not a member of the affiliation %q", ErrInvalidNameIDPolicy, serviceProviderID, affiliationID)
	}

	return nil
}
