package saml

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	persistentTestIDP   = "https://idp.example.com/saml/metadata"
	persistentTestSP    = "https://sp.example.com/saml2/metadata"
	persistentTestOther = "https://other-sp.example.com/saml2/metadata"
)

var persistentTestSecret = []byte("0123456789abcdef0123456789abcdef")

// persistentValue is what a derived identifier looks like: 256 bits in lowercase base32, without padding.
var persistentValue = regexp.MustCompile(`^[a-z2-7]{52}$`)

func persistentTestProvider() PersistentNameIDProvider {
	return PersistentNameIDProvider{Secret: persistentTestSecret}
}

func managedTestProvider() (ManagedPersistentNameIDProvider, *MemoryPersistentNameIDStore) {
	store := &MemoryPersistentNameIDStore{}

	return ManagedPersistentNameIDProvider{PersistentNameIDProvider: persistentTestProvider(), Store: store}, store
}

// persistentPolicy returns a NameIDPolicy for the persistent format with AllowCreate.
func persistentPolicy(allowCreate bool) *NameIDPolicy {
	format := string(PersistentNameIDFormat)

	return &NameIDPolicy{Format: &format, AllowCreate: &allowCreate}
}

// persistentRequest is the NameIDRequest of the service provider with the entity ID for a persistent identifier
// of its own.
func persistentRequest(serviceProvider string, allowCreate bool) NameIDRequest {
	return NameIDRequest{
		ServiceProvider: &EntityDescriptor{EntityID: serviceProvider},
		Format:          string(PersistentNameIDFormat),
		NameQualifier:   persistentTestIDP,
		SPNameQualifier: serviceProvider,
		AllowCreate:     allowCreate,
	}
}

// nameIDTestRequestFrom is nameIDTestRequest for a service provider with another entity ID.
func nameIDTestRequestFrom(test *IdentityProviderTest, entityID string, policy *NameIDPolicy) *IdpAuthnRequest {
	req := nameIDTestRequest(test, policy)
	req.ServiceProviderMetadata.EntityID = entityID

	return req
}

// SAMLCore §8.3.7: the same principal has the same identifier at a service provider in every session, and it is
// qualified by the identity provider and that service provider.
func TestPersistentNameIDIsStableAndQualified(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.NameIDProvider = persistentTestProvider()

	first, err := nameIDTestRequest(test, persistentPolicy(true)).resolveNameID(&Session{ID: "one", Index: "i1", UserName: "alice", UserEmail: "alice@example.com"})
	require.NoError(t, err)

	// Another session, an address that changed, and no AllowCreate.
	second, err := nameIDTestRequest(test, persistentPolicy(false)).resolveNameID(&Session{ID: "two", Index: "i2", UserName: "alice", UserEmail: "alice@example.org"})
	require.NoError(t, err)

	assert.Equal(t, first, second)
	assert.Equal(t, first.Format, string(PersistentNameIDFormat))
	assert.Equal(t, first.NameQualifier, persistentTestIDP)
	assert.Equal(t, first.SPNameQualifier, persistentTestSP)
	assert.Equal(t, first.SPProvidedID, "")

	// Opaque, not longer than 256 characters, and nothing of the principal.
	assert.True(t, persistentValue.MatchString(first.Value), first.Value)
	assert.False(t, strings.Contains(first.Value, "alice"))
}

// The derivation must never change, as every service provider keeps what it produced. These values were computed
// independently: lowercase unpadded base32 of HMAC-SHA256 over the label, the two qualifiers and the principal,
// each preceded by its length as 32 bits in network order, and then the generation in the same way when it isn't
// zero.
func TestPersistentNameIDKnownAnswer(t *testing.T) {
	provider, _ := managedTestProvider()
	alice := &Session{UserName: "alice"}

	first, err := provider.NameID(nil, persistentRequest(persistentTestSP, true), alice)
	require.NoError(t, err)
	assert.Equal(t, first.Value, "m7gc2dz7n2xz56d2h6dwa5oqt4exvqgayhr3ypq3roachqp3ttka")

	require.NoError(t, provider.TerminateNameID(nil, &IdpManageNameIDRequest{
		IDP:                     &IdentityProvider{EntityID: persistentTestIDP},
		ServiceProviderMetadata: &EntityDescriptor{EntityID: persistentTestSP},
		Request:                 ManageNameIDRequest{NameID: first, Terminate: true},
	}))

	second, err := provider.NameID(nil, persistentRequest(persistentTestSP, true), alice)
	require.NoError(t, err)
	assert.Equal(t, second.Value, "5shklk6ovey5fwl4w53cuaiq7437drgedu4blmvucdm67r3numyq")
}

func TestPersistentNameIDDiffers(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.NameIDProvider = persistentTestProvider()

	alice := &Session{ID: "s", UserName: "alice"}

	base, err := nameIDTestRequest(test, persistentPolicy(true)).resolveNameID(alice)
	require.NoError(t, err)

	t.Run("for each service provider", func(t *testing.T) {
		other, err := nameIDTestRequestFrom(test, persistentTestOther, persistentPolicy(true)).resolveNameID(alice)
		require.NoError(t, err)
		assert.True(t, other.Value != base.Value)
		assert.Equal(t, other.SPNameQualifier, persistentTestOther)
	})

	t.Run("for each principal", func(t *testing.T) {
		other, err := nameIDTestRequest(test, persistentPolicy(true)).resolveNameID(&Session{ID: "s", UserName: "bob"})
		require.NoError(t, err)
		assert.True(t, other.Value != base.Value)
	})

	t.Run("for each identity provider", func(t *testing.T) {
		idp := test.IDP
		idp.EntityID = "https://login.example.com"

		req := nameIDTestRequest(test, persistentPolicy(true))
		req.IDP = &idp

		other, err := req.resolveNameID(alice)
		require.NoError(t, err)
		assert.True(t, other.Value != base.Value)
		assert.Equal(t, other.NameQualifier, "https://login.example.com")
	})

	t.Run("for each secret", func(t *testing.T) {
		test.IDP.NameIDProvider = PersistentNameIDProvider{Secret: []byte("another secret of thirty-two byte")}

		other, err := nameIDTestRequest(test, persistentPolicy(true)).resolveNameID(alice)
		require.NoError(t, err)
		assert.True(t, other.Value != base.Value)
	})

	// The fields are delimited, so no part of one can pass for part of the next.
	t.Run("for a boundary that moves", func(t *testing.T) {
		provider := persistentTestProvider()

		a, err := provider.NameID(nil, persistentRequest("https://sp.example.com/a", true), &Session{UserName: "lice"})
		require.NoError(t, err)

		b, err := provider.NameID(nil, persistentRequest("https://sp.example.com/", true), &Session{UserName: "alice"})
		require.NoError(t, err)
		assert.True(t, a.Value != b.Value)
	})
}

// SAMLCore §8.3.7: the members of an affiliation share the identifier that is qualified by it.
func TestPersistentNameIDAffiliation(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.NameIDProvider = persistentTestProvider()

	withAffiliation(test, func(entity *EntityDescriptor) {
		entity.AffiliationDescriptor.AffiliateMembers = append(entity.AffiliationDescriptor.AffiliateMembers, persistentTestOther)
	})

	alice := &Session{ID: "s", UserName: "alice"}
	affiliation := testAffiliationID
	policy := persistentPolicy(true)
	policy.SPNameQualifier = &affiliation

	first, err := nameIDTestRequest(test, policy).resolveNameID(alice)
	require.NoError(t, err)

	second, err := nameIDTestRequestFrom(test, persistentTestOther, policy).resolveNameID(alice)
	require.NoError(t, err)

	assert.Equal(t, first, second)
	assert.Equal(t, first.SPNameQualifier, testAffiliationID)
	assert.Equal(t, first.NameQualifier, persistentTestIDP)

	own, err := nameIDTestRequest(test, persistentPolicy(true)).resolveNameID(alice)
	require.NoError(t, err)
	assert.True(t, own.Value != first.Value)
}

func TestPersistentNameIDPrincipal(t *testing.T) {
	provider := persistentTestProvider()
	req := persistentRequest(persistentTestSP, true)

	byName, err := provider.NameID(nil, req, &Session{UserName: "alice"})
	require.NoError(t, err)

	t.Run("the subject identifier comes first", func(t *testing.T) {
		bySubject, err := provider.NameID(nil, req, &Session{UserName: "alice", SubjectID: "u1234@example.com"})
		require.NoError(t, err)
		assert.True(t, bySubject.Value != byName.Value)

		// It doesn't change when the user is renamed.
		renamed, err := provider.NameID(nil, req, &Session{UserName: "alicia", SubjectID: "u1234@example.com"})
		require.NoError(t, err)
		assert.Equal(t, renamed.Value, bySubject.Value)
	})

	t.Run("custom", func(t *testing.T) {
		provider.Principal = func(session *Session) string { return session.UserEmail }

		byEmail, err := provider.NameID(nil, req, &Session{UserName: "alice", UserEmail: "alice@example.com"})
		require.NoError(t, err)
		assert.True(t, byEmail.Value != byName.Value)
	})

	// The session is incomplete, which a format left open must not hide by falling back to transient.
	t.Run("none", func(t *testing.T) {
		_, err := persistentTestProvider().NameID(nil, req, &Session{ID: "s", NameID: "alice", UserEmail: "alice@example.com"})
		assert.ErrorContains(t, err, "principal")
		assert.False(t, errors.Is(err, ErrInvalidNameIDPolicy))
	})
}

func TestPersistentNameIDConfiguration(t *testing.T) {
	req := persistentRequest(persistentTestSP, true)
	alice := &Session{UserName: "alice"}

	t.Run("short secret", func(t *testing.T) {
		provider := PersistentNameIDProvider{Secret: []byte("short")}
		assert.ErrorContains(t, provider.Validate(), "Secret")

		_, err := provider.NameID(nil, req, alice)
		assert.ErrorContains(t, err, "Secret")
		assert.False(t, errors.Is(err, ErrInvalidNameIDPolicy))
	})

	t.Run("no name qualifier", func(t *testing.T) {
		req := req
		req.NameQualifier = ""

		_, err := persistentTestProvider().NameID(nil, req, alice)
		assert.ErrorContains(t, err, "NameQualifier")
	})

	t.Run("scope", func(t *testing.T) {
		provider := persistentTestProvider()
		assert.NoError(t, provider.Validate())

		provider.Scope = "example.com"
		assert.NoError(t, provider.Validate())

		provider.Scope = "example com"
		assert.ErrorContains(t, provider.Validate(), "Scope")
	})

	t.Run("managed without a store", func(t *testing.T) {
		provider := ManagedPersistentNameIDProvider{PersistentNameIDProvider: persistentTestProvider()}
		assert.ErrorContains(t, provider.Validate(), "Store")

		_, err := provider.NameID(nil, req, alice)
		assert.ErrorContains(t, err, "Store")
		assert.False(t, errors.Is(err, ErrInvalidNameIDPolicy))
	})

	t.Run("managed", func(t *testing.T) {
		provider, _ := managedTestProvider()
		assert.NoError(t, provider.Validate())
	})
}

// One provider serves every format: what isn't persistent is issued by the fallback.
func TestPersistentNameIDProviderFallback(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.NameIDProvider = persistentTestProvider()

	transient, email := string(TransientNameIDFormat), string(EmailAddressNameIDFormat)
	session := &Session{ID: "s", UserName: "alice", NameID: "alice@example.com", NameIDFormat: email}

	t.Run("transient", func(t *testing.T) {
		first, err := nameIDTestRequest(test, &NameIDPolicy{Format: &transient}).resolveNameID(session)
		require.NoError(t, err)
		second, err := nameIDTestRequest(test, &NameIDPolicy{Format: &transient}).resolveNameID(session)
		require.NoError(t, err)

		assert.Equal(t, first.Format, transient)
		assert.True(t, first.Value != second.Value)
	})

	t.Run("session format", func(t *testing.T) {
		nameID, err := nameIDTestRequest(test, &NameIDPolicy{Format: &email}).resolveNameID(session)
		require.NoError(t, err)
		assert.Equal(t, nameID.Format, email)
		assert.Equal(t, nameID.Value, "alice@example.com")
	})

	t.Run("open format prefers the metadata of the service provider", func(t *testing.T) {
		withSPNameIDFormats(test, PersistentNameIDFormat)

		req := nameIDTestRequest(test, nil)
		req.ServiceProviderMetadata.SPSSODescriptors[0].NameIDFormats = []NameIDFormat{PersistentNameIDFormat}

		nameID, err := req.resolveNameID(session)
		require.NoError(t, err)
		assert.Equal(t, nameID.Format, string(PersistentNameIDFormat))
	})

	t.Run("unknown format", func(t *testing.T) {
		kerberos := "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"

		_, err := nameIDTestRequest(test, &NameIDPolicy{Format: &kerberos}).resolveNameID(session)
		assert.True(t, errors.Is(err, ErrInvalidNameIDPolicy), "%v", err)
	})

	// A persistent session NameID would be the same for every service provider.
	t.Run("persistent session", func(t *testing.T) {
		nameID, err := nameIDTestRequest(test, persistentPolicy(true)).resolveNameID(&Session{
			ID: "s", UserName: "alice", NameID: "alice-everywhere", NameIDFormat: string(PersistentNameIDFormat),
		})
		require.NoError(t, err)
		assert.True(t, persistentValue.MatchString(nameID.Value), nameID.Value)
	})

	t.Run("custom fallback", func(t *testing.T) {
		provider := persistentTestProvider()
		provider.Fallback = DefaultNameIDProvider{Formats: []string{email, transient}}

		assert.Equal(t, provider.NameIDFormats(), []string{string(PersistentNameIDFormat), email, transient})
	})
}

func TestPersistentNameIDMetadata(t *testing.T) {
	persistent, transient := PersistentNameIDFormat, TransientNameIDFormat

	t.Run("derived", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.NameIDProvider = persistentTestProvider()

		assert.Equal(t, test.IDP.Metadata().IDPSSODescriptors[0].NameIDFormats, []NameIDFormat{persistent, transient})
	})

	t.Run("managed", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.NameIDProvider, _ = managedTestProvider()

		assert.Equal(t, test.IDP.Metadata().IDPSSODescriptors[0].NameIDFormats, []NameIDFormat{persistent, transient})
	})

	// A persistent format that the fallback also lists is advertised once.
	t.Run("no duplicates", func(t *testing.T) {
		provider := persistentTestProvider()
		provider.Fallback = DefaultNameIDProvider{Formats: []string{string(PersistentNameIDFormat), string(TransientNameIDFormat)}}

		assert.Equal(t, provider.NameIDFormats(), []string{string(PersistentNameIDFormat), string(TransientNameIDFormat)})
	})
}

// A derived identifier exists from the moment the secret does, so there is nothing to create and AllowCreate
// decides nothing.
func TestPersistentNameIDDerivedIgnoresAllowCreate(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.NameIDProvider = persistentTestProvider()

	alice := &Session{ID: "s", UserName: "alice"}
	persistent := string(PersistentNameIDFormat)

	for name, policy := range map[string]*NameIDPolicy{
		"false":  persistentPolicy(false),
		"absent": {Format: &persistent},
	} {
		t.Run(name, func(t *testing.T) {
			nameID, err := nameIDTestRequest(test, policy).resolveNameID(alice)
			require.NoError(t, err)
			assert.Equal(t, nameID.Format, persistent)
		})
	}
}

// SAMLCore §3.4.1.1: with a store, an identifier is only created when AllowCreate is true, and one that exists is
// returned whatever it says.
func TestManagedPersistentNameIDAllowCreate(t *testing.T) {
	alice := &Session{ID: "s", UserName: "alice"}

	t.Run("refused until allowed", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		provider, store := managedTestProvider()
		test.IDP.NameIDProvider = provider

		_, err := nameIDTestRequest(test, persistentPolicy(false)).resolveNameID(alice)
		assert.True(t, errors.Is(err, ErrInvalidNameIDPolicy), "%v", err)
		assert.Equal(t, store.Len(), 0, "nothing is created by a refusal")

		created, err := nameIDTestRequest(test, persistentPolicy(true)).resolveNameID(alice)
		require.NoError(t, err)
		assert.Equal(t, store.Len(), 1)

		again, err := nameIDTestRequest(test, persistentPolicy(false)).resolveNameID(alice)
		require.NoError(t, err)
		assert.Equal(t, again, created)

		// Another service provider has no identifier yet.
		_, err = nameIDTestRequestFrom(test, persistentTestOther, persistentPolicy(false)).resolveNameID(alice)
		assert.True(t, errors.Is(err, ErrInvalidNameIDPolicy), "%v", err)
	})

	// The first identifier is the one that the provider without a store derives, so a store can be added later.
	t.Run("same as derived", func(t *testing.T) {
		managed, _ := managedTestProvider()

		stored, err := managed.NameID(nil, persistentRequest(persistentTestSP, true), alice)
		require.NoError(t, err)

		derived, err := persistentTestProvider().NameID(nil, persistentRequest(persistentTestSP, true), alice)
		require.NoError(t, err)
		assert.Equal(t, stored, derived)
	})

	t.Run("open format falls back to transient", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.NameIDProvider, _ = managedTestProvider()

		req := nameIDTestRequest(test, nil)
		req.ServiceProviderMetadata.SPSSODescriptors[0].NameIDFormats = []NameIDFormat{PersistentNameIDFormat}

		nameID, err := req.resolveNameID(alice)
		require.NoError(t, err)
		assert.Equal(t, nameID.Format, string(TransientNameIDFormat))
	})

	t.Run("ignored", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		provider, store := managedTestProvider()
		provider.IgnoreAllowCreate = true
		test.IDP.NameIDProvider = provider

		nameID, err := nameIDTestRequest(test, persistentPolicy(false)).resolveNameID(alice)
		require.NoError(t, err)
		assert.Equal(t, nameID.Format, string(PersistentNameIDFormat))
		assert.Equal(t, store.Len(), 1)
	})

	// The stored identifier is what is issued, so the secret can change without changing it.
	t.Run("stored value survives another secret", func(t *testing.T) {
		provider, store := managedTestProvider()

		before, err := provider.NameID(nil, persistentRequest(persistentTestSP, true), alice)
		require.NoError(t, err)

		provider.Secret = []byte("another secret of thirty-two byte")

		after, err := provider.NameID(nil, persistentRequest(persistentTestSP, false), alice)
		require.NoError(t, err)
		assert.Equal(t, after, before)

		created, err := provider.NameID(nil, persistentRequest(persistentTestOther, true), alice)
		require.NoError(t, err)
		assert.Equal(t, store.Len(), 2)

		derived, err := persistentTestProvider().NameID(nil, persistentRequest(persistentTestOther, true), alice)
		require.NoError(t, err)
		assert.True(t, created.Value != derived.Value)
	})

	t.Run("store failure", func(t *testing.T) {
		boom := errors.New("boom")
		provider := ManagedPersistentNameIDProvider{PersistentNameIDProvider: persistentTestProvider(), Store: failingPersistentNameIDStore{boom}}

		_, err := provider.NameID(nil, persistentRequest(persistentTestSP, true), alice)
		assert.True(t, errors.Is(err, boom))
		assert.False(t, errors.Is(err, ErrInvalidNameIDPolicy))
	})
}

type failingPersistentNameIDStore struct{ err error }

func (s failingPersistentNameIDStore) GetPersistentNameID(*http.Request, string, string, string) (*PersistentNameIDRecord, error) {
	return nil, s.err
}

func (s failingPersistentNameIDStore) FindPersistentNameID(*http.Request, string, string, string) (*PersistentNameIDRecord, error) {
	return nil, s.err
}

func (s failingPersistentNameIDStore) SavePersistentNameID(*http.Request, PersistentNameIDRecord) error {
	return s.err
}

func TestMemoryPersistentNameIDStore(t *testing.T) {
	store := &MemoryPersistentNameIDStore{}

	_, err := store.GetPersistentNameID(nil, "idp", "sp", "alice")
	assert.True(t, errors.Is(err, os.ErrNotExist))

	_, err = store.FindPersistentNameID(nil, "idp", "sp", "v1")
	assert.True(t, errors.Is(err, os.ErrNotExist))

	record := PersistentNameIDRecord{NameQualifier: "idp", SPNameQualifier: "sp", Principal: "alice", Value: "v1", SPProvidedIDs: map[string]string{"sp": "a"}}
	require.NoError(t, store.SavePersistentNameID(nil, record))

	// The store keeps a copy.
	record.SPProvidedIDs["sp"] = "changed"

	got, err := store.GetPersistentNameID(nil, "idp", "sp", "alice")
	require.NoError(t, err)
	assert.Equal(t, got.SPProvidedIDs["sp"], "a")

	got.SPProvidedIDs["sp"] = "changed"

	found, err := store.FindPersistentNameID(nil, "idp", "sp", "v1")
	require.NoError(t, err)
	assert.Equal(t, found.Principal, "alice")
	assert.Equal(t, found.SPProvidedIDs["sp"], "a")

	// A value is found in its own namespace only.
	_, err = store.FindPersistentNameID(nil, "idp", "other", "v1")
	assert.True(t, errors.Is(err, os.ErrNotExist))

	// A record is replaced by its key, and the value it had is no longer found.
	require.NoError(t, store.SavePersistentNameID(nil, PersistentNameIDRecord{NameQualifier: "idp", SPNameQualifier: "sp", Principal: "alice", Value: "v2", Generation: 1}))
	assert.Equal(t, store.Len(), 1)

	_, err = store.FindPersistentNameID(nil, "idp", "sp", "v1")
	assert.True(t, errors.Is(err, os.ErrNotExist))
}

// The identifier that is sent as an EncryptedID is the persistent one.
func TestPersistentNameIDEncrypted(t *testing.T) {
	test, req := encryptedPartsRequest(t)
	test.IDP.NameIDProvider = persistentTestProvider()

	withSPNameIDFormats(test, PersistentNameIDFormat)
	req.ServiceProviderMetadata.SPSSODescriptors[0].NameIDFormats = []NameIDFormat{PersistentNameIDFormat}
	requestEncryptedID(req)

	body := respond(t, req)

	want, err := persistentTestProvider().NameID(nil, persistentRequest(persistentTestSP, true), encryptedPartsSession)
	require.NoError(t, err)

	sent := sentAssertionElement(t, test, body)
	assert.Nil(t, sent.FindElement("./Subject/NameID"))
	assert.NotNil(t, sent.FindElement("./Subject/EncryptedID"))
	assert.False(t, strings.Contains(elementToString(sent.FindElement("./Subject")), want.Value))

	assertion, err := test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
	require.NoError(t, err)
	require.True(t, assertion.Subject != nil && assertion.Subject.NameID != nil)
	assert.Equal(t, *assertion.Subject.NameID, *want)
}

// A logout by the persistent NameID finds the session through the participant that it was asserted to.
func TestPersistentNameIDLogoutMatchesSession(t *testing.T) {
	session := &Session{ID: "s", Index: "i1", UserName: "alice"}
	test, provider, capture := newParticipantTest(t, session)
	test.IDP.NameIDProvider = persistentTestProvider()

	w := serveParticipantSSO(t, test, persistentPolicy(true))
	require.Equal(t, w.Code, http.StatusOK, w.Body.String())
	require.Len(t, provider.added, 1)

	asserted := *capture.assertion.Subject.NameID
	assert.Equal(t, asserted.Format, string(PersistentNameIDFormat))
	assert.Equal(t, provider.added[0].participant.NameID, asserted)

	r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/slo", nil)
	logout := func(nameID NameID) error {
		req := &IdpLogoutRequest{IDP: &test.IDP, ServiceProviderMetadata: test.SP.Metadata(), Request: LogoutRequest{NameID: &nameID}}

		return req.MatchesSession(r, session)
	}

	assert.NoError(t, logout(asserted))

	// A later session of the principal is found by the same identifier.
	later := &Session{ID: "later", Index: "i2", UserName: "alice"}
	provider.GetSessionFunc = func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session { return later }

	serveParticipantSSO(t, test, persistentPolicy(true))
	require.Len(t, provider.added, 2)
	assert.Equal(t, provider.added[1].participant.NameID, asserted)

	other := asserted
	other.Value = strings.Repeat("a", 52)
	assert.NotNil(t, logout(other))
}

// managedManageNameIDTest is an identity provider for name identifier management whose provider is the managed one, with
// the identifier that alice was issued for the test service provider.
func managedManageNameIDTest(t *testing.T) (*IdentityProviderTest, ManagedPersistentNameIDProvider, *MemoryPersistentNameIDStore, *NameID) {
	t.Helper()

	test, _ := manageNameIDTestIDP(t)
	provider, store := managedTestProvider()
	test.IDP.NameIDProvider = provider

	issued, err := nameIDTestRequest(test, persistentPolicy(true)).resolveNameID(&Session{ID: "s", UserName: "alice"})
	require.NoError(t, err)

	return test, provider, store, issued
}

// SAMLCore §3.6.3, errata E55: the NewID of a service provider is the SPProvidedID of the identifier from then on.
func TestManagedPersistentNameIDSetSPProvidedID(t *testing.T) {
	for name, send := range manageNameIDBindings {
		t.Run(name, func(t *testing.T) {
			test, provider, _, issued := managedManageNameIDTest(t)

			result := send(t, test, manageNameIDOptions{mutate: func(request *ManageNameIDRequest) { request.NameID = issued }})
			require.True(t, result.Response != nil, "HTTP status %d", result.Code)
			checkStatus(t, result.Response.Status, StatusSuccess, "")

			again, err := nameIDTestRequest(test, persistentPolicy(false)).resolveNameID(&Session{ID: "s2", UserName: "alice"})
			require.NoError(t, err)
			assert.Equal(t, again.Value, issued.Value)
			assert.Equal(t, again.SPProvidedID, "sp-alias")

			alias, err := provider.SPProvidedID(nil, persistentTestSP, issued)
			require.NoError(t, err)
			assert.Equal(t, alias, "sp-alias")

			// It is the alias of that service provider, and of that identifier.
			alias, err = provider.SPProvidedID(nil, persistentTestOther, issued)
			require.NoError(t, err)
			assert.Equal(t, alias, "")

			unknown := *issued
			unknown.Value = strings.Repeat("a", 52)

			alias, err = provider.SPProvidedID(nil, persistentTestSP, &unknown)
			assert.True(t, err == nil || errors.Is(err, ErrUnknownPrincipal), "%v", err)
			assert.Equal(t, alias, "")
		})
	}
}

// SAMLCore §3.6.3, errata E12: after Terminate the identifier is no longer used, and a later request is handled as
// if there had been none, so it needs AllowCreate and creates another identifier.
func TestManagedPersistentNameIDTerminate(t *testing.T) {
	test, provider, _, issued := managedManageNameIDTest(t)
	send := manageNameIDBindings["soap"]
	alice := &Session{ID: "s2", UserName: "alice"}

	result := send(t, test, manageNameIDOptions{mutate: func(request *ManageNameIDRequest) { request.NameID = issued }})
	checkStatus(t, result.Response.Status, StatusSuccess, "")

	terminate := func(request *ManageNameIDRequest) {
		request.NameID, request.NewID, request.Terminate = issued, "", true
	}

	result = send(t, test, manageNameIDOptions{mutate: terminate})
	checkStatus(t, result.Response.Status, StatusSuccess, "")

	alias, err := provider.SPProvidedID(nil, persistentTestSP, issued)
	assert.True(t, err == nil || errors.Is(err, ErrUnknownPrincipal), "%v", err)
	assert.Equal(t, alias, "")

	// The identifier that was terminated is no longer recognized.
	result = send(t, test, manageNameIDOptions{mutate: terminate})
	checkStatus(t, result.Response.Status, StatusRequester, StatusUnknownPrincipal)

	_, err = nameIDTestRequest(test, persistentPolicy(false)).resolveNameID(alice)
	assert.True(t, errors.Is(err, ErrInvalidNameIDPolicy), "%v", err)

	replacement, err := nameIDTestRequest(test, persistentPolicy(true)).resolveNameID(alice)
	require.NoError(t, err)
	assert.True(t, replacement.Value != issued.Value)
	assert.True(t, persistentValue.MatchString(replacement.Value), replacement.Value)
	assert.Equal(t, replacement.SPProvidedID, "")

	// The replacement is stable, and is the one that can be managed now.
	again, err := nameIDTestRequest(test, persistentPolicy(false)).resolveNameID(alice)
	require.NoError(t, err)
	assert.Equal(t, again, replacement)

	result = send(t, test, manageNameIDOptions{mutate: func(request *ManageNameIDRequest) { request.NameID = replacement }})
	checkStatus(t, result.Response.Status, StatusSuccess, "")
}

// SAMLCore §3.6.3: an identifier that isn't recognized is answered with an error status, and nothing is created.
func TestManagedPersistentNameIDManagementUnknown(t *testing.T) {
	testCases := map[string]func(*NameID){
		"never issued":           func(n *NameID) { n.Value = strings.Repeat("a", 52) },
		"email format":           func(n *NameID) { n.Format = string(EmailAddressNameIDFormat) },
		"of another principal":   func(n *NameID) { n.Value = "p-alice" },
		"sp name qualifier gone": func(n *NameID) { n.SPNameQualifier = "" },
	}

	for name, change := range testCases {
		t.Run(name, func(t *testing.T) {
			test, _, store, issued := managedManageNameIDTest(t)

			nameID := *issued
			change(&nameID)

			result := manageNameIDBindings["soap"](t, test, manageNameIDOptions{mutate: func(request *ManageNameIDRequest) { request.NameID = &nameID }})

			// An omitted SPNameQualifier means the requester (SAMLCore §3.6.3), so that one is recognized.
			if name == "sp name qualifier gone" {
				checkStatus(t, result.Response.Status, StatusSuccess, "")
			} else {
				checkStatus(t, result.Response.Status, StatusRequester, StatusUnknownPrincipal)
			}

			assert.Equal(t, store.Len(), 1)
		})
	}

	// The identifier of another service provider is not one of the requester's.
	t.Run("of another service provider", func(t *testing.T) {
		test, provider, store, _ := managedManageNameIDTest(t)

		other, err := provider.NameID(nil, persistentRequest(persistentTestOther, true), &Session{UserName: "alice"})
		require.NoError(t, err)

		other.SPNameQualifier = persistentTestSP

		result := manageNameIDBindings["soap"](t, test, manageNameIDOptions{mutate: func(request *ManageNameIDRequest) { request.NameID = other }})
		checkStatus(t, result.Response.Status, StatusRequester, StatusUnknownPrincipal)
		assert.Equal(t, store.Len(), 2)
	})
}

// An identifier that is qualified by an affiliation belongs to all of its members: each has its own alias, and one
// of them can't retire the identifier of the others.
func TestManagedPersistentNameIDManagementAffiliation(t *testing.T) {
	provider, store := managedTestProvider()
	alice := &Session{UserName: "alice"}

	idp := &IdentityProvider{EntityID: persistentTestIDP}

	request := func(serviceProvider string) NameIDRequest {
		req := persistentRequest(serviceProvider, true)
		req.SPNameQualifier = testAffiliationID

		return req
	}

	manage := func(serviceProvider string, nameID *NameID, terminate bool) *IdpManageNameIDRequest {
		return &IdpManageNameIDRequest{
			IDP:                     idp,
			ServiceProviderMetadata: &EntityDescriptor{EntityID: serviceProvider},
			Request:                 ManageNameIDRequest{NameID: nameID, Terminate: terminate},
		}
	}

	issued, err := provider.NameID(nil, request(persistentTestSP), alice)
	require.NoError(t, err)
	assert.Equal(t, issued.SPNameQualifier, testAffiliationID)

	require.NoError(t, provider.SetSPProvidedID(nil, manage(persistentTestSP, issued, false), "alias-one"))
	require.NoError(t, provider.SetSPProvidedID(nil, manage(persistentTestOther, issued, false), "alias-two"))

	one, err := provider.NameID(nil, request(persistentTestSP), alice)
	require.NoError(t, err)
	assert.Equal(t, one.SPProvidedID, "alias-one")

	two, err := provider.NameID(nil, request(persistentTestOther), alice)
	require.NoError(t, err)
	assert.Equal(t, two.SPProvidedID, "alias-two")
	assert.Equal(t, two.Value, one.Value)

	require.NoError(t, provider.TerminateNameID(nil, manage(persistentTestSP, issued, true)))

	one, err = provider.NameID(nil, request(persistentTestSP), alice)
	require.NoError(t, err)
	assert.Equal(t, one.SPProvidedID, "")
	assert.Equal(t, one.Value, issued.Value)

	two, err = provider.NameID(nil, request(persistentTestOther), alice)
	require.NoError(t, err)
	assert.Equal(t, two.SPProvidedID, "alias-two")
	assert.Equal(t, two.Value, issued.Value)
	assert.Equal(t, store.Len(), 1)
}

// managedMappingFixture is the fixture of name identifier mapping with the managed provider, and the identifier
// that alice was issued for the requester A.
func managedMappingFixture(t *testing.T) (*nameIDMappingFixture, ManagedPersistentNameIDProvider, *NameID) {
	t.Helper()

	f := newNameIDMappingFixture(t)
	provider, _ := managedTestProvider()
	f.test.IDP.NameIDProvider = provider

	issued, err := provider.NameID(nil, persistentRequest(f.a.MetadataURL.String(), true), &Session{UserName: "alice"})
	require.NoError(t, err)

	return f, provider, issued
}

// SAMLCore §3.8: the identifier of the principal at the requester is mapped to the one it has at the target.
func TestManagedPersistentNameIDMapping(t *testing.T) {
	allow := true
	target := func(f *nameIDMappingFixture) *string {
		id := f.b.MetadataURL.String()

		return &id
	}

	t.Run("creates the identifier of the target when allowed", func(t *testing.T) {
		f, provider, issued := managedMappingFixture(t)

		result := f.send(t, nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) {
			request.NameID = issued
		}})
		result.checkNoIdentifier(t, StatusRequester, StatusInvalidNameIDPolicy)

		result = f.send(t, nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) {
			request.NameID = issued
			request.NameIDPolicy = &NameIDPolicy{SPNameQualifier: target(f), AllowCreate: &allow}
		}})
		checkStatus(t, result.Response.Status, StatusSuccess, "")

		mapped, err := f.b.DecryptNameID(reparse(t, result.Element.FindElement("./EncryptedID")))
		require.NoError(t, err)

		// It is the identifier that single sign-on to the target asserts.
		want, err := provider.NameID(nil, persistentRequest(f.b.MetadataURL.String(), false), &Session{UserName: "alice"})
		require.NoError(t, err)
		assert.Equal(t, mapped, want)
		assert.True(t, mapped.Value != issued.Value)

		// Now that it exists, it is mapped to without AllowCreate, with the alias of the target.
		require.NoError(t, provider.SetSPProvidedID(nil, &IdpManageNameIDRequest{
			IDP:                     &f.test.IDP,
			ServiceProviderMetadata: f.b.Metadata(),
			Request:                 ManageNameIDRequest{NameID: mapped},
		}, "b-alias"))

		result = f.send(t, nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) { request.NameID = issued }})
		checkStatus(t, result.Response.Status, StatusSuccess, "")

		mapped, err = f.b.DecryptNameID(reparse(t, result.Element.FindElement("./EncryptedID")))
		require.NoError(t, err)
		assert.Equal(t, mapped.Value, want.Value)
		assert.Equal(t, mapped.SPProvidedID, "b-alias")
	})

	t.Run("unknown principal", func(t *testing.T) {
		f, _, issued := managedMappingFixture(t)

		for name, change := range map[string]func(*NameID){
			"never issued": func(n *NameID) { n.Value = strings.Repeat("a", 52) },
			"transient":    func(n *NameID) { n.Format = string(TransientNameIDFormat) },
		} {
			t.Run(name, func(t *testing.T) {
				nameID := *issued
				change(&nameID)

				result := f.send(t, nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) {
					request.NameID = &nameID
					request.NameIDPolicy = &NameIDPolicy{SPNameQualifier: target(f), AllowCreate: &allow}
				}})
				result.checkNoIdentifier(t, StatusRequester, StatusUnknownPrincipal)
			})
		}
	})

	t.Run("terminated", func(t *testing.T) {
		f, provider, issued := managedMappingFixture(t)

		require.NoError(t, provider.TerminateNameID(nil, &IdpManageNameIDRequest{
			IDP:                     &f.test.IDP,
			ServiceProviderMetadata: f.a.Metadata(),
			Request:                 ManageNameIDRequest{NameID: issued, Terminate: true},
		}))

		result := f.send(t, nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) {
			request.NameID = issued
			request.NameIDPolicy = &NameIDPolicy{SPNameQualifier: target(f), AllowCreate: &allow}
		}})
		result.checkNoIdentifier(t, StatusRequester, StatusUnknownPrincipal)
	})

	// There is no session to take an identifier of another format from.
	t.Run("another format", func(t *testing.T) {
		f, _, issued := managedMappingFixture(t)
		email := string(EmailAddressNameIDFormat)

		result := f.send(t, nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) {
			request.NameID = issued
			request.NameIDPolicy = &NameIDPolicy{SPNameQualifier: target(f), AllowCreate: &allow, Format: &email}
		}})
		result.checkNoIdentifier(t, StatusRequester, StatusInvalidNameIDPolicy)
	})
}

// The provider without a store can't find the principal of an identifier, so it serves neither protocol and the
// metadata lists neither service.
func TestPersistentNameIDProviderInterfaces(t *testing.T) {
	var derived NameIDProvider = persistentTestProvider()

	_, ok := derived.(NameIDManagementProvider)
	assert.False(t, ok)

	_, ok = derived.(NameIDMappingProvider)
	assert.False(t, ok)

	_, ok = derived.(PairwiseIDProvider)
	assert.True(t, ok)

	managed, _ := managedTestProvider()

	var provider NameIDProvider = managed

	_, ok = provider.(NameIDManagementProvider)
	assert.True(t, ok)

	_, ok = provider.(NameIDMappingProvider)
	assert.True(t, ok)

	_, ok = provider.(PairwiseIDProvider)
	assert.True(t, ok)
}

func TestValidateSubjectIdentifier(t *testing.T) {
	long := strings.Repeat("a", 127)

	valid := []string{
		"alice@example.com",
		"a@b",
		"0=-=-@0-.",
		"ABC123@EXAMPLE.ORG",
		long + "@" + long,
	}

	invalid := []string{
		"",
		"alice",
		"@example.com",
		"alice@",
		"alice@example.com@example.com",
		"-alice@example.com",
		"=alice@example.com",
		"alice@-example.com",
		"alice@.example.com",
		"al ice@example.com",
		"alice.smith@example.com",
		"alice_smith@example.com",
		"alice+x@example.com",
		"alice@example_com",
		"alice@example.com\n",
		"älice@example.com",
		"alice@exämple.com",
		long + "a@example.com",
		"alice@" + long + "a",
	}

	for _, value := range valid {
		assert.NoError(t, ValidateSubjectIdentifier(value), value)
	}

	for _, value := range invalid {
		assert.True(t, ValidateSubjectIdentifier(value) != nil, "%q", value)
	}
}

func attributeNamed(attributes []Attribute, name string) *Attribute {
	for i := range attributes {
		if attributes[i].Name == name {
			return &attributes[i]
		}
	}

	return nil
}

func pairwiseTestProvider() PersistentNameIDProvider {
	provider := persistentTestProvider()
	provider.Scope = "example.com"

	return provider
}

// The pairwise-id is a candidate like any other attribute, so the release policy decides who receives it.
func TestPairwiseIDRelease(t *testing.T) {
	session := &Session{ID: "s", UserName: "alice", UserEmail: "alice@example.com"}

	t.Run("requested", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.NameIDProvider = pairwiseTestProvider()

		req := attributeReleaseRequest(t, test, "", service(0, nil, requested(PairwiseIDAttributeName, uriAttrNameFormat)))
		attributes := releasedAttributes(t, req, session)
		require.Len(t, attributes, 1)

		attribute := attributes[0]
		assert.Equal(t, attribute.Name, "urn:oasis:names:tc:SAML:attribute:pairwise-id")
		assert.Equal(t, attribute.NameFormat, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
		require.Len(t, attribute.Values, 1)
		assert.Equal(t, attribute.Values[0].Type, "xs:string")

		value := attribute.Values[0].Value
		assert.NoError(t, ValidateSubjectIdentifier(value), value)

		uniqueID, scope, _ := strings.Cut(value, "@")
		assert.Equal(t, scope, "example.com")
		assert.True(t, persistentValue.MatchString(uniqueID), uniqueID)
		assert.False(t, strings.Contains(value, "alice"))

		// It is the pseudonym that the service provider knows the principal by as a persistent NameID.
		nameID, err := pairwiseTestProvider().NameID(nil, persistentRequest(persistentTestSP, true), session)
		require.NoError(t, err)
		assert.Equal(t, uniqueID, nameID.Value)

		// It is the same in another session.
		again := releasedAttributes(t, req, &Session{ID: "later", UserName: "alice"})
		require.Len(t, again, 1)
		assert.Equal(t, again[0].Values[0].Value, value)
	})

	t.Run("not requested", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.NameIDProvider = pairwiseTestProvider()

		assert.Len(t, releasedAttributes(t, attributeReleaseRequest(t, test, ""), session), 0)

		req := attributeReleaseRequest(t, test, "", service(0, nil, requested(mailAttributeName, uriAttrNameFormat)))
		assert.Equal(t, attributeNames(releasedAttributes(t, req, session)), []string{mailAttributeName})
	})

	t.Run("differs for each service provider", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.NameIDProvider = pairwiseTestProvider()

		wanted := service(0, nil, requested(PairwiseIDAttributeName, uriAttrNameFormat))

		one := releasedAttributes(t, attributeReleaseRequest(t, test, "", wanted), session)
		require.Len(t, one, 1)

		req := attributeReleaseRequest(t, test, "", wanted)
		req.ServiceProviderMetadata.EntityID = persistentTestOther

		two := releasedAttributes(t, req, session)
		require.Len(t, two, 1)
		assert.True(t, one[0].Values[0].Value != two[0].Values[0].Value)
	})

	t.Run("a custom policy decides", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.NameIDProvider = pairwiseTestProvider()

		var candidates []string

		test.IDP.AttributeReleasePolicy = attributeReleasePolicyFunc(func(_ AttributeReleaseRequest, _ *Session, attributes []Attribute) ([]Attribute, error) {
			candidates = attributeNames(attributes)

			return nil, nil
		})

		req := attributeReleaseRequest(t, test, "", service(0, nil, requested(PairwiseIDAttributeName, uriAttrNameFormat)))
		assert.Len(t, releasedAttributes(t, req, session), 0)
		assert.Contains(t, candidates, PairwiseIDAttributeName)
	})

	t.Run("no scope", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.NameIDProvider = persistentTestProvider()

		req := attributeReleaseRequest(t, test, "", service(0, nil, requested(PairwiseIDAttributeName, uriAttrNameFormat)))
		assert.Len(t, releasedAttributes(t, req, session), 0)
	})

	t.Run("default provider", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)

		req := attributeReleaseRequest(t, test, "", service(0, nil, requested(PairwiseIDAttributeName, uriAttrNameFormat)))
		assert.Len(t, releasedAttributes(t, req, session), 0)
	})

	// The attribute is optional, so a session with nothing to derive it from has none.
	t.Run("no principal", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.NameIDProvider = pairwiseTestProvider()

		transient := string(TransientNameIDFormat)
		req := attributeReleaseRequest(t, test, "", service(0, nil, requested(PairwiseIDAttributeName, uriAttrNameFormat)))
		req.Request.NameIDPolicy = &NameIDPolicy{Format: &transient}

		assert.Len(t, releasedAttributes(t, req, &Session{ID: "s"}), 0)
	})

	t.Run("invalid scope", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		provider := pairwiseTestProvider()
		provider.Scope = "not a scope"
		test.IDP.NameIDProvider = provider

		req := attributeReleaseRequest(t, test, "", service(0, nil, requested(PairwiseIDAttributeName, uriAttrNameFormat)))
		assert.ErrorContains(t, DefaultAssertionMaker{}.MakeAssertion(req, session), "pairwise-id")
	})

	t.Run("managed provider derives it without the store", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		provider, store := managedTestProvider()
		provider.Scope = "example.com"
		provider.IgnoreAllowCreate = true
		test.IDP.NameIDProvider = provider

		req := attributeReleaseRequest(t, test, "", service(0, nil, requested(PairwiseIDAttributeName, uriAttrNameFormat)))
		transient := string(TransientNameIDFormat)
		req.Request.NameIDPolicy = &NameIDPolicy{Format: &transient}

		attributes := releasedAttributes(t, req, session)
		require.Len(t, attributes, 1)
		assert.NoError(t, ValidateSubjectIdentifier(attributes[0].Values[0].Value))
		assert.Equal(t, store.Len(), 0)
	})
}

type pairwiseIDProviderFunc struct {
	DefaultNameIDProvider

	value string
	err   error
}

func (p pairwiseIDProviderFunc) PairwiseID(*http.Request, string, *EntityDescriptor, *Session) (string, error) {
	return p.value, p.err
}

// What any PairwiseIDProvider returns is held to the syntax of the profile.
func TestPairwiseIDProviderResult(t *testing.T) {
	session := &Session{ID: "s", UserName: "alice"}
	wanted := service(0, nil, requested(PairwiseIDAttributeName, uriAttrNameFormat))

	t.Run("valid", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.NameIDProvider = pairwiseIDProviderFunc{value: "abc@example.com"}

		attributes := releasedAttributes(t, attributeReleaseRequest(t, test, "", wanted), session)
		require.Len(t, attributes, 1)
		assert.Equal(t, attributes[0].Values[0].Value, "abc@example.com")
	})

	t.Run("invalid", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.NameIDProvider = pairwiseIDProviderFunc{value: "abc"}

		err := DefaultAssertionMaker{}.MakeAssertion(attributeReleaseRequest(t, test, "", wanted), session)
		assert.ErrorContains(t, err, "pairwise-id")
	})

	t.Run("error", func(t *testing.T) {
		boom := errors.New("boom")
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.NameIDProvider = pairwiseIDProviderFunc{err: boom}

		err := DefaultAssertionMaker{}.MakeAssertion(attributeReleaseRequest(t, test, "", wanted), session)
		assert.True(t, errors.Is(err, boom))
	})
}

// The subject-id of the session is stated when it has the syntax of the profile, and to those that ask for it.
func TestSubjectIDRelease(t *testing.T) {
	wanted := service(0, nil, requested(SubjectIDAttributeName, uriAttrNameFormat))

	t.Run("valid", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)

		attributes := releasedAttributes(t, attributeReleaseRequest(t, test, "", wanted), &Session{ID: "s", NameID: "alice", SubjectID: "u1234@example.com"})
		require.Len(t, attributes, 1)
		assert.Equal(t, attributes[0].Name, "urn:oasis:names:tc:SAML:attribute:subject-id")
		assert.Equal(t, attributes[0].NameFormat, uriAttrNameFormat)
		require.Len(t, attributes[0].Values, 1)
		assert.Equal(t, attributes[0].Values[0].Value, "u1234@example.com")
	})

	t.Run("not requested", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)

		attributes := releasedAttributes(t, attributeReleaseRequest(t, test, ""), &Session{ID: "s", NameID: "alice", SubjectID: "u1234@example.com"})
		assert.Len(t, attributes, 0)
	})

	t.Run("invalid is left out", func(t *testing.T) {
		for _, value := range []string{"alice", "alice smith@example.com", "alice@example.com@example.com"} {
			test := NewIdentityProviderTest(t, applyKey)

			var logged bytes.Buffer

			test.IDP.Observer = logObserver(&logged)

			attributes := releasedAttributes(t, attributeReleaseRequest(t, test, "", wanted), &Session{ID: "s", NameID: "alice", SubjectID: value})
			assert.Len(t, attributes, 0, value)
			assert.Contains(t, logged.String(), "subject-id")
			assert.False(t, strings.Contains(logged.String(), value), "the value is not logged")
		}
	})
}

// An AttributeQuery is offered the same candidates as single sign-on, and narrowed in the same way.
func TestServeAttributeQueryPairwiseID(t *testing.T) {
	f := newQueryFixture(t)
	f.test.IDP.NameIDProvider = pairwiseTestProvider()

	t.Run("requested", func(t *testing.T) {
		f.requestAttributes(requested(PairwiseIDAttributeName, uriAttrNameFormat), requested(SubjectIDAttributeName, uriAttrNameFormat))

		response := f.queryAttributes(t, f.attributeQuery())
		assertQueryStatus(t, response, StatusSuccess, "")
		require.Len(t, response.Assertions, 1)

		attributes := response.Assertions[0].AttributeStatements[0].Attributes

		pairwise := attributeNamed(attributes, PairwiseIDAttributeName)
		require.NotNil(t, pairwise)

		want, err := pairwiseTestProvider().PairwiseID(nil, f.test.IDP.MetadataURL.String(), f.test.SP.Metadata(), f.provider.subject)
		require.NoError(t, err)
		assert.Equal(t, queryAttributeValues(*pairwise), []string{want})

		subject := attributeNamed(attributes, SubjectIDAttributeName)
		require.NotNil(t, subject)
		assert.Equal(t, queryAttributeValues(*subject), []string{"alice@example.com"})
	})

	t.Run("not requested", func(t *testing.T) {
		f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))

		response := f.queryAttributes(t, f.attributeQuery())
		assertQueryStatus(t, response, StatusSuccess, "")
		require.Len(t, response.Assertions, 1)
		assert.True(t, attributeNamed(response.Assertions[0].AttributeStatements[0].Attributes, PairwiseIDAttributeName) == nil)
	})
}
