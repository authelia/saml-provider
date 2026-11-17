package saml

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
)

// minPersistentNameIDSecretLength is the shortest PersistentNameIDProvider.Secret, in bytes, which is the size of
// the output of the HMAC that it keys.
const minPersistentNameIDSecretLength = 32

// persistentNameIDLabel is the first field of what the secret authenticates to derive an identifier, which keeps
// the derivation apart from any other use of the secret.
const persistentNameIDLabel = "saml-persistent-nameid-v1"

// persistentNameIDEncoding encodes a derived identifier. Base32 has one case, so the identifier survives a service
// provider that compares or stores it without regard to case, and it only has characters that the uniqueID of a
// pairwise-id may have.
var persistentNameIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// PersistentNameIDProvider is a NameIDProvider that issues persistent NameIDs (SAMLCore §8.3.7), and leaves every
// other format to Fallback, so that it is the one provider of an identity provider. It keeps nothing: the
// identifier of a principal for a service provider or affiliation is derived from Secret, as the HMAC-SHA256 of
// the entity ID of the identity provider, the SPNameQualifier and the key of the principal, in lowercase base32,
// which is 52 characters. It is the same in every session, differs for each service provider, and says nothing of
// the principal to anyone without the secret. The members of an affiliation which name it in the SPNameQualifier
// of their NameIDPolicy share one.
//
// AllowCreate is not checked. A derived identifier exists from the moment the secret does, so issuing one creates
// nothing, and without a store the provider can't tell whether the service provider has seen it before. Use
// ManagedPersistentNameIDProvider to honour it, or IdentityProvider.NameIDPolicyEnforcer to decide for each
// service provider.
//
// The secret can't be changed without changing every identifier at every service provider, so it must be kept for
// as long as the accounts that the identifiers name. The identifiers can't be mapped back to a principal, so this
// provider serves neither name identifier management nor mapping, which ManagedPersistentNameIDProvider does.
//
// It is also a PairwiseIDProvider when Scope is set.
type PersistentNameIDProvider struct {
	// Secret keys the derivation. It is required, and must be at least 32 bytes from a cryptographic random
	// source. Anyone who has it and knows the key of a principal can compute the identifiers of that principal.
	Secret []byte

	// Principal returns the key of the principal of the session, which the identifiers are derived from. It must
	// never change for a principal and never be given to another, so it can't be an email address or the NameID
	// of the session. If it is nil the key is Session.SubjectID, or Session.UserName if that is empty, which is
	// only suitable if a user is never renamed and a name is never used again. A session with no key is refused
	// a persistent identifier. Changing what this returns for a principal, which includes starting to set
	// Session.SubjectID, changes every identifier of that principal that isn't stored.
	Principal func(session *Session) string

	// Fallback issues every format but persistent. Defaults to DefaultNameIDProvider, which issues random
	// transient identifiers and the NameID of the session in the format of the session.
	Fallback NameIDProvider

	// Scope is the scope of the pairwise-id attribute, such as example.com, which is the uniqueID of the
	// principal for the service provider, then "@", then this. It should be a domain that the organization of
	// the identity provider controls. If it is empty there is no pairwise-id. See PairwiseIDProvider.
	Scope string
}

// Validate returns an error if the provider can't issue identifiers as it is configured, which an application can
// check when it starts.
func (p PersistentNameIDProvider) Validate() error {
	if len(p.Secret) < minPersistentNameIDSecretLength {
		return fmt.Errorf("the Secret of the persistent NameID provider must be at least %d bytes", minPersistentNameIDSecretLength)
	}

	if p.Scope != "" && !subjectIdentifierScope.MatchString(p.Scope) {
		return errors.New("the Scope of the persistent NameID provider is not a valid scope of a subject identifier")
	}

	return nil
}

// NameIDFormats implements NameIDProvider. It returns persistent, then the formats of Fallback.
func (p PersistentNameIDProvider) NameIDFormats() []string {
	formats := []string{string(PersistentNameIDFormat)}

	for _, format := range p.fallback().NameIDFormats() {
		if !slices.Contains(formats, format) {
			formats = append(formats, format)
		}
	}

	return formats
}

// NameID implements NameIDProvider. A persistent NameID is derived, whatever req.AllowCreate is, and carries
// req.NameQualifier and req.SPNameQualifier. Any other format is issued by Fallback.
func (p PersistentNameIDProvider) NameID(r *http.Request, req NameIDRequest, session *Session) (*NameID, error) {
	if req.Format != string(PersistentNameIDFormat) {
		return p.fallback().NameID(r, req, session)
	}

	principal, err := p.requestPrincipal(req, session)
	if err != nil {
		return nil, err
	}

	value, err := p.derive(req.NameQualifier, req.SPNameQualifier, principal, 0)
	if err != nil {
		return nil, err
	}

	return persistentNameID(req.NameQualifier, req.SPNameQualifier, value, ""), nil
}

// PairwiseID implements PairwiseIDProvider. The uniqueID is the identifier that is derived for the principal
// and the entity ID of the service provider, which is the value of the persistent NameID that this provider issues
// to it, so a service provider that moves from one to the other finds its accounts. It is not qualified by an
// affiliation, and doesn't change when the NameID is terminated. It returns "" if Scope is empty or the session
// has no key of the principal.
func (p PersistentNameIDProvider) PairwiseID(_ *http.Request, idpEntityID string, serviceProvider *EntityDescriptor, session *Session) (string, error) {
	if p.Scope == "" {
		return "", nil
	}

	if !subjectIdentifierScope.MatchString(p.Scope) {
		return "", errors.New("the Scope of the persistent NameID provider is not a valid scope of a subject identifier")
	}

	if idpEntityID == "" || serviceProvider == nil || serviceProvider.EntityID == "" {
		return "", errors.New("cannot derive a pairwise-id without the entity IDs of the identity provider and the service provider")
	}

	principal := p.principal(session)
	if principal == "" {
		return "", nil
	}

	uniqueID, err := p.derive(idpEntityID, serviceProvider.EntityID, principal, 0)
	if err != nil {
		return "", err
	}

	return uniqueID + "@" + p.Scope, nil
}

// fallback returns Fallback, or DefaultNameIDProvider if there is none.
func (p PersistentNameIDProvider) fallback() NameIDProvider {
	if p.Fallback != nil {
		return p.Fallback
	}

	return DefaultNameIDProvider{}
}

// principal returns the key of the principal of session, or "" if it has none.
func (p PersistentNameIDProvider) principal(session *Session) string {
	switch {
	case session == nil:
		return ""
	case p.Principal != nil:
		return p.Principal(session)
	case session.SubjectID != "":
		return session.SubjectID
	default:
		return session.UserName
	}
}

// requestPrincipal returns the key of the principal of session for a persistent identifier that req asks for. The
// errors don't wrap ErrInvalidNameIDPolicy, which would fall back to another format: the request can be served,
// and the session or the configuration is incomplete.
func (p PersistentNameIDProvider) requestPrincipal(req NameIDRequest, session *Session) (string, error) {
	if req.NameQualifier == "" || req.SPNameQualifier == "" {
		return "", errors.New("cannot issue a persistent NameID for a request without a NameQualifier and an SPNameQualifier")
	}

	principal := p.principal(session)
	if principal == "" {
		return "", errors.New("the session has no key of the principal to derive a persistent NameID from")
	}

	return principal, nil
}

// derive returns the identifier of the principal in the namespace of the identity provider nameQualifier and the
// service provider or affiliation spNameQualifier. Each field is preceded by its length, so that no two sets of
// fields are authenticated as the same bytes. The generation counts the identifiers that were terminated before
// this one, and is only a field when it is not zero, so the first is the same with and without a store.
func (p PersistentNameIDProvider) derive(nameQualifier, spNameQualifier, principal string, generation uint32) (string, error) {
	if len(p.Secret) < minPersistentNameIDSecretLength {
		return "", fmt.Errorf("the Secret of the persistent NameID provider must be at least %d bytes", minPersistentNameIDSecretLength)
	}

	mac := hmac.New(sha256.New, p.Secret)

	var length [4]byte

	field := func(value []byte) {
		binary.BigEndian.PutUint32(length[:], uint32(len(value))) //nolint:gosec // The fields are far shorter than 4 GiB.
		mac.Write(length[:])
		mac.Write(value)
	}

	field([]byte(persistentNameIDLabel))
	field([]byte(nameQualifier))
	field([]byte(spNameQualifier))
	field([]byte(principal))

	if generation != 0 {
		field(binary.BigEndian.AppendUint32(nil, generation))
	}

	return strings.ToLower(persistentNameIDEncoding.EncodeToString(mac.Sum(nil))), nil
}

// persistentNameID returns a persistent NameID.
func persistentNameID(nameQualifier, spNameQualifier, value, spProvidedID string) *NameID {
	return &NameID{
		Format:          string(PersistentNameIDFormat),
		NameQualifier:   nameQualifier,
		SPNameQualifier: spNameQualifier,
		SPProvidedID:    spProvidedID,
		Value:           value,
	}
}

// PersistentNameIDRecord is what a PersistentNameIDStore keeps of the persistent identifier of a principal. There
// is one for each NameQualifier, SPNameQualifier and Principal, which are its key.
type PersistentNameIDRecord struct {
	// NameQualifier is the entity ID of the identity provider.
	NameQualifier string

	// SPNameQualifier is the entity ID of the service provider or of the affiliation that the identifier is for.
	SPNameQualifier string

	// Principal is the key of the principal. See PersistentNameIDProvider.Principal.
	Principal string

	// Value is the identifier, which names no other principal in the namespace of the two qualifiers.
	Value string

	// Generation counts the identifiers of the principal in this namespace that were terminated before Value.
	Generation uint32

	// Terminated is whether a service provider ended the use of Value (SAMLCore §3.6.3). The record is kept
	// so that the identifier which replaces it is another.
	Terminated bool

	// SPProvidedIDs holds the alias that a service provider registered for the principal, by its entity ID
	// (SAMLCore §3.6.3). An identifier of an affiliation may have one for each member.
	SPProvidedIDs map[string]string
}

// PersistentNameIDStore keeps the persistent identifiers that a ManagedPersistentNameIDProvider issues. An
// identifier that doesn't exist is reported with an error that wraps [os.ErrNotExist].
//
// The provider reads a record, changes it and saves it without a lock. Two first logins of a principal save the
// same record, because the identifier is derived. A ManageNameIDRequest that races a login or another request
// may lose its change to the other, which a store can prevent by serializing the requests of a principal.
type PersistentNameIDStore interface {
	// GetPersistentNameID returns the record of the principal in the namespace of nameQualifier and
	// spNameQualifier, including one that is terminated.
	GetPersistentNameID(r *http.Request, nameQualifier, spNameQualifier, principal string) (*PersistentNameIDRecord, error)

	// FindPersistentNameID returns the record whose Value is value in the namespace of nameQualifier and
	// spNameQualifier, including one that is terminated. A value that a record had before it was replaced is
	// not found. The comparison must be exact.
	FindPersistentNameID(r *http.Request, nameQualifier, spNameQualifier, value string) (*PersistentNameIDRecord, error)

	// SavePersistentNameID creates the record, or replaces the one with its NameQualifier, SPNameQualifier and
	// Principal.
	SavePersistentNameID(r *http.Request, record PersistentNameIDRecord) error
}

// ManagedPersistentNameIDProvider is a PersistentNameIDProvider which records the identifiers it issues in a
// Store. That lets it honour AllowCreate, serve name identifier management as a NameIDManagementProvider, and
// serve name identifier mapping as a NameIDMappingProvider.
//
// The first identifier of a principal for a service provider is the one that PersistentNameIDProvider derives, so
// a Store can be added to a deployment without changing an identifier. An identifier that was issued before then
// is recorded when the principal next signs in, and can't be managed or mapped until it is. A record is made when
// the NameID of an assertion is resolved, which is before the response is sent.
//
// An identifier that is stored is issued as it is stored, so a change of Secret only changes the identifiers
// that are created after it, and the pairwise-id, which is always derived.
type ManagedPersistentNameIDProvider struct {
	PersistentNameIDProvider

	// Store keeps the identifiers. It is required.
	Store PersistentNameIDStore

	// IgnoreAllowCreate creates an identifier whether or not the NameIDPolicy of the request has AllowCreate
	// set, which SAMLCore §3.4.1.1 forbids. It is for service providers that expect a persistent identifier and
	// never send AllowCreate.
	IgnoreAllowCreate bool
}

// Validate returns an error if the provider can't issue identifiers as it is configured, which an application can
// check when it starts.
func (p ManagedPersistentNameIDProvider) Validate() error {
	if p.Store == nil {
		return errors.New("the managed persistent NameID provider has no Store")
	}

	return p.PersistentNameIDProvider.Validate()
}

// NameID implements NameIDProvider. A persistent NameID is the one that is stored for the principal, with the
// SPProvidedID that the service provider registered. If there is none, or it was terminated, one is created when
// req.AllowCreate is set, and the error wraps ErrInvalidNameIDPolicy otherwise (SAMLCore §3.4.1.1). Any other
// format is issued by Fallback.
func (p ManagedPersistentNameIDProvider) NameID(r *http.Request, req NameIDRequest, session *Session) (*NameID, error) {
	if req.Format != string(PersistentNameIDFormat) {
		return p.fallback().NameID(r, req, session)
	}

	principal, err := p.requestPrincipal(req, session)
	if err != nil {
		return nil, err
	}

	serviceProvider := req.SPNameQualifier
	if req.ServiceProvider != nil {
		serviceProvider = req.ServiceProvider.EntityID
	}

	return p.issue(r, req.NameQualifier, req.SPNameQualifier, principal, serviceProvider, req.AllowCreate)
}

// issue returns the persistent NameID of the principal in the namespace of nameQualifier and spNameQualifier for
// the service provider with the entity ID, creating it if there is none and it may be created.
func (p ManagedPersistentNameIDProvider) issue(r *http.Request, nameQualifier, spNameQualifier, principal, serviceProvider string, allowCreate bool) (*NameID, error) {
	if p.Store == nil {
		return nil, errors.New("the managed persistent NameID provider has no Store")
	}

	record, err := p.Store.GetPersistentNameID(r, nameQualifier, spNameQualifier, principal)

	switch {
	case errors.Is(err, os.ErrNotExist):
		record = nil
	case err != nil:
		return nil, fmt.Errorf("cannot load the persistent NameID: %w", err)
	case record != nil && !record.Terminated:
		return persistentNameID(nameQualifier, spNameQualifier, record.Value, record.SPProvidedIDs[serviceProvider]), nil
	}

	if !allowCreate && !p.IgnoreAllowCreate {
		return nil, fmt.Errorf("%w: the principal has no persistent NameID and the request does not allow one to be created", ErrInvalidNameIDPolicy)
	}

	created := PersistentNameIDRecord{NameQualifier: nameQualifier, SPNameQualifier: spNameQualifier, Principal: principal}

	// Errata E12: a request after a Terminate is handled as if there had been no identifier, and the one that the
	// service provider no longer accepts is not issued to it again.
	if record != nil {
		created.Generation = record.Generation + 1
	}

	if created.Value, err = p.derive(nameQualifier, spNameQualifier, principal, created.Generation); err != nil {
		return nil, err
	}

	if err = p.Store.SavePersistentNameID(r, created); err != nil {
		return nil, fmt.Errorf("cannot save the persistent NameID: %w", err)
	}

	return persistentNameID(nameQualifier, spNameQualifier, created.Value, ""), nil
}

// find returns the record of the persistent identifier nameID, which serviceProvider sent, in the namespace of
// the identity provider nameQualifier. The SPNameQualifier of nameID is that of the record, and when it is
// omitted it is the service provider (SAMLCore §3.6.3). The error wraps ErrUnknownPrincipal unless the identifier
// was issued and is still used. The store is asked before anything else is decided, so that every identifier
// which names nobody takes as long as one that was never issued.
func (p ManagedPersistentNameIDProvider) find(r *http.Request, nameQualifier, serviceProvider string, nameID *NameID) (*PersistentNameIDRecord, error) {
	if p.Store == nil {
		return nil, errors.New("the managed persistent NameID provider has no Store")
	}

	if nameID == nil {
		return nil, fmt.Errorf("%w: the request has no NameID", ErrUnknownPrincipal)
	}

	spNameQualifier := nameID.SPNameQualifier
	if spNameQualifier == "" {
		spNameQualifier = serviceProvider
	}

	record, err := p.Store.FindPersistentNameID(r, nameQualifier, spNameQualifier, nameID.Value)

	switch {
	case errors.Is(err, os.ErrNotExist) || (err == nil && record == nil):
		return nil, fmt.Errorf("%w: the NameID was not issued", ErrUnknownPrincipal)
	case err != nil:
		return nil, fmt.Errorf("cannot find the persistent NameID: %w", err)
	case nameID.Format != string(PersistentNameIDFormat) && !isUnspecifiedNameIDFormat(nameID.Format):
		return nil, fmt.Errorf("%w: the NameID is not of the persistent format", ErrUnknownPrincipal)
	case nameID.NameQualifier != "" && nameID.NameQualifier != nameQualifier:
		return nil, fmt.Errorf("%w: the NameID has the NameQualifier of another identity provider", ErrUnknownPrincipal)
	case record.Terminated:
		return nil, fmt.Errorf("%w: the NameID was terminated", ErrUnknownPrincipal)
	}

	return record, nil
}

// SetSPProvidedID implements NameIDManagementProvider. The alias is that of the service provider which sent the
// request, also for an identifier of an affiliation.
func (p ManagedPersistentNameIDProvider) SetSPProvidedID(r *http.Request, req *IdpManageNameIDRequest, spProvidedID string) error {
	serviceProvider := req.ServiceProviderMetadata.EntityID

	record, err := p.find(r, req.IDP.entityID(), serviceProvider, req.Request.NameID)
	if err != nil {
		return err
	}

	// The record may share its map with the store.
	record.SPProvidedIDs = maps.Clone(record.SPProvidedIDs)
	if record.SPProvidedIDs == nil {
		record.SPProvidedIDs = map[string]string{}
	}

	record.SPProvidedIDs[serviceProvider] = spProvidedID

	if err = p.Store.SavePersistentNameID(r, *record); err != nil {
		return fmt.Errorf("cannot save the persistent NameID: %w", err)
	}

	return nil
}

// SPProvidedID implements NameIDManagementProvider. An identifier without a NameQualifier has no alias, as the
// namespace of its record is not known.
func (p ManagedPersistentNameIDProvider) SPProvidedID(r *http.Request, serviceProviderEntityID string, nameID *NameID) (string, error) {
	if nameID == nil || nameID.NameQualifier == "" {
		return "", nil
	}

	record, err := p.find(r, nameID.NameQualifier, serviceProviderEntityID, nameID)
	if err != nil {
		return "", err
	}

	return record.SPProvidedIDs[serviceProviderEntityID], nil
}

// TerminateNameID implements NameIDManagementProvider. The identifier of the service provider is marked as
// terminated and its alias is deleted, and the next one that is created for the principal is another. For an
// identifier of an affiliation only the alias of the service provider which sent the request is deleted: the
// identifier is that of every member, and one of them doesn't decide what the others are sent.
func (p ManagedPersistentNameIDProvider) TerminateNameID(r *http.Request, req *IdpManageNameIDRequest) error {
	serviceProvider := req.ServiceProviderMetadata.EntityID

	record, err := p.find(r, req.IDP.entityID(), serviceProvider, req.Request.NameID)
	if err != nil {
		return err
	}

	if record.SPNameQualifier == serviceProvider {
		record.Terminated, record.SPProvidedIDs = true, nil
	} else {
		record.SPProvidedIDs = maps.Clone(record.SPProvidedIDs)
		delete(record.SPProvidedIDs, serviceProvider)
	}

	if err = p.Store.SavePersistentNameID(r, *record); err != nil {
		return fmt.Errorf("cannot save the persistent NameID: %w", err)
	}

	return nil
}

// MapNameID implements NameIDMappingProvider. The identifier of the request must be a persistent one that this
// provider recorded for the requester, or for an affiliation it is a member of, as no other is stored. The
// identifier that is returned is the persistent one of the principal for the target, which is created if there is
// none and req.AllowCreate is set. Another format than persistent can't be supplied, as there is no session to
// take it from.
func (p ManagedPersistentNameIDProvider) MapNameID(r *http.Request, req *IdpNameIDMappingRequest) (*NameID, error) {
	nameQualifier := req.IDP.entityID()

	record, err := p.find(r, nameQualifier, req.ServiceProviderMetadata.EntityID, req.Request.NameID)

	if req.Format != "" && req.Format != string(PersistentNameIDFormat) {
		return nil, fmt.Errorf("%w: only a persistent NameID can be mapped to", ErrInvalidNameIDPolicy)
	}

	if err != nil {
		return nil, err
	}

	target := req.TargetMetadata.EntityID

	return p.issue(r, nameQualifier, target, record.Principal, target, req.AllowCreate)
}

// MemoryPersistentNameIDStore is a PersistentNameIDStore that keeps the identifiers in memory, for tests and
// examples: they are lost when the process ends, and with them every SPProvidedID and termination. The zero value
// is ready to use.
type MemoryPersistentNameIDStore struct {
	mu      sync.Mutex
	records map[[3]string]PersistentNameIDRecord
}

// GetPersistentNameID implements PersistentNameIDStore.
func (s *MemoryPersistentNameIDStore) GetPersistentNameID(_ *http.Request, nameQualifier, spNameQualifier, principal string) (*PersistentNameIDRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.records[[3]string{nameQualifier, spNameQualifier, principal}]
	if !ok {
		return nil, os.ErrNotExist
	}

	record.SPProvidedIDs = maps.Clone(record.SPProvidedIDs)

	return &record, nil
}

// FindPersistentNameID implements PersistentNameIDStore.
func (s *MemoryPersistentNameIDStore) FindPersistentNameID(_ *http.Request, nameQualifier, spNameQualifier, value string) (*PersistentNameIDRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, record := range s.records {
		if key[0] == nameQualifier && key[1] == spNameQualifier && record.Value == value {
			record.SPProvidedIDs = maps.Clone(record.SPProvidedIDs)

			return &record, nil
		}
	}

	return nil, os.ErrNotExist
}

// SavePersistentNameID implements PersistentNameIDStore.
func (s *MemoryPersistentNameIDStore) SavePersistentNameID(_ *http.Request, record PersistentNameIDRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.records == nil {
		s.records = map[[3]string]PersistentNameIDRecord{}
	}

	record.SPProvidedIDs = maps.Clone(record.SPProvidedIDs)
	s.records[[3]string{record.NameQualifier, record.SPNameQualifier, record.Principal}] = record

	return nil
}

// Len returns the number of records, including those that are terminated.
func (s *MemoryPersistentNameIDStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.records)
}
