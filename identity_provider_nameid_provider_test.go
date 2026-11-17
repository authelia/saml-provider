package saml

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

const testAffiliationID = "https://affiliation.example.com"

// withAffiliation makes the service provider provider of test also return an affiliation, whose only
// member is the test service provider, after modify, if not nil, has changed it.
func withAffiliation(test *IdentityProviderTest, modify func(*EntityDescriptor)) {
	withAffiliationResult(test, func() (*EntityDescriptor, error) {
		entity := &EntityDescriptor{
			EntityID: testAffiliationID,
			AffiliationDescriptor: &AffiliationDescriptor{
				AffiliateMembers: []string{"https://sp.example.com/saml2/metadata"},
			},
		}
		if modify != nil {
			modify(entity)
		}

		return entity, nil
	})
}

// withAffiliationResult makes the service provider provider of test return the result of get for the
// affiliation.
func withAffiliationResult(test *IdentityProviderTest, get func() (*EntityDescriptor, error)) {
	inner := test.IDP.ServiceProviderProvider
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(r *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			if serviceProviderID == testAffiliationID {
				return get()
			}

			return inner.GetServiceProvider(r, serviceProviderID)
		},
	}
}

// withSPNameIDFormats makes the metadata of the test service provider list formats.
func withSPNameIDFormats(test *IdentityProviderTest, formats ...NameIDFormat) {
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			if serviceProviderID != test.SP.MetadataURL.String() {
				return nil, os.ErrNotExist
			}

			metadata := test.SP.Metadata()
			metadata.SPSSODescriptors[0].NameIDFormats = formats

			return metadata, nil
		},
	}
}

// captureNameID makes the assertion maker of test record the NameID of the assertion it makes, which
// the response only holds encrypted.
func captureNameID(test *IdentityProviderTest) **NameID {
	var nameID *NameID

	test.IDP.AssertionMaker = assertionMakerFunc(func(req *IdpAuthnRequest, session *Session) error {
		err := DefaultAssertionMaker{}.MakeAssertion(req, session)
		if err == nil {
			nameID = req.Assertion.Subject.NameID
		}

		return err
	})

	return &nameID
}

type nameIDProviderFunc struct {
	formats []string
	f       func(*http.Request, NameIDRequest, *Session) (*NameID, error)
}

func (p nameIDProviderFunc) NameIDFormats() []string {
	return p.formats
}

func (p nameIDProviderFunc) NameID(r *http.Request, req NameIDRequest, session *Session) (*NameID, error) {
	return p.f(r, req, session)
}

// nameIDTestRequest returns a request from the test service provider with the given policy.
func nameIDTestRequest(test *IdentityProviderTest, policy *NameIDPolicy) *IdpAuthnRequest {
	return &IdpAuthnRequest{
		IDP:                     &test.IDP,
		HTTPRequest:             httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/sso", nil),
		Request:                 AuthnRequest{NameIDPolicy: policy},
		ServiceProviderMetadata: test.SP.Metadata(),
		Now:                     TimeNow(),
	}
}

func TestDefaultNameIDProviderTransientIsRandom(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	transient := string(TransientNameIDFormat)
	req := nameIDTestRequest(test, &NameIDPolicy{Format: &transient})
	session := &Session{ID: "s", NameID: "alice"}

	first, err := req.resolveNameID(session)
	assert.NilError(t, err)
	second, err := req.resolveNameID(session)
	assert.NilError(t, err)

	for _, nameID := range []*NameID{first, second} {
		assert.Check(t, len(nameID.Value) >= 22, nameID.Value)
		_, err = base64.RawURLEncoding.DecodeString(nameID.Value)
		assert.Check(t, err)
		assert.Check(t, nameID.Value != session.NameID)
		assert.Check(t, is.Equal(nameID.Format, transient))
		assert.Check(t, is.Equal(nameID.NameQualifier, "https://idp.example.com/saml/metadata"))
		assert.Check(t, is.Equal(nameID.SPNameQualifier, "https://sp.example.com/saml2/metadata"))
	}

	assert.Check(t, first.Value != second.Value)
}

func TestDefaultNameIDProviderSessionFormat(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	email := string(EmailAddressNameIDFormat)
	req := nameIDTestRequest(test, &NameIDPolicy{Format: &email})

	nameID, err := req.resolveNameID(&Session{ID: "s", NameID: "alice@example.com", NameIDFormat: email})
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(nameID, &NameID{
		Format:          email,
		NameQualifier:   "https://idp.example.com/saml/metadata",
		SPNameQualifier: "https://sp.example.com/saml2/metadata",
		Value:           "alice@example.com",
	}))
}

// SAMLCore §8.3.6 requires the qualifiers and SPProvidedID of an entity NameID to be omitted, whether the session
// carries it or a NameIDProvider fills them in.
func TestResolveNameIDEntityHasNoQualifiers(t *testing.T) {
	entity := string(EntityNameIDFormat)
	want := &NameID{Format: entity, Value: "https://principal.example.com"}

	t.Run("session format", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		req := nameIDTestRequest(test, &NameIDPolicy{Format: &entity})

		nameID, err := req.resolveNameID(&Session{ID: "s", NameID: want.Value, NameIDFormat: entity})
		assert.NilError(t, err)
		assert.Check(t, is.DeepEqual(nameID, want))
	})

	t.Run("provider sets qualifiers", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.NameIDProvider = nameIDProviderFunc{
			formats: []string{entity},
			f: func(*http.Request, NameIDRequest, *Session) (*NameID, error) {
				return &NameID{
					Format: entity, Value: want.Value,
					NameQualifier: "https://idp.example.com/saml/metadata", SPNameQualifier: "https://sp.example.com/saml2/metadata", SPProvidedID: "x",
				}, nil
			},
		}
		req := nameIDTestRequest(test, &NameIDPolicy{Format: &entity})

		nameID, err := req.resolveNameID(&Session{ID: "s", NameID: "alice"})
		assert.NilError(t, err)
		assert.Check(t, is.DeepEqual(nameID, want))
	})
}

// A persistent NameID must be an opaque pseudonym for one service provider or affiliation (SAMLCore §8.3.7), which
// DefaultNameIDProvider can't derive, so it never issues one, even from a persistent session.
func TestDefaultNameIDProviderRefusesPersistent(t *testing.T) {
	persistent := string(PersistentNameIDFormat)
	session := &Session{ID: "s", NameID: "alice@example.com", NameIDFormat: persistent}

	t.Run("requested", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		req := nameIDTestRequest(test, &NameIDPolicy{Format: &persistent})

		_, err := req.resolveNameID(session)
		assert.Check(t, errors.Is(err, ErrInvalidNameIDPolicy), "error: %v", err)
	})

	t.Run("open format falls back to transient", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		req := nameIDTestRequest(test, nil)

		nameID, err := req.resolveNameID(session)
		assert.NilError(t, err)
		assert.Check(t, is.Equal(nameID.Format, string(TransientNameIDFormat)))
		assert.Check(t, nameID.Value != session.NameID)
	})
}

// A session needs no NameID unless its own is asserted, so that a NameIDProvider can derive one from other fields of
// the session. No NameID is ever asserted without a value.
func TestResolveNameIDSessionWithoutNameID(t *testing.T) {
	transient, email := string(TransientNameIDFormat), string(EmailAddressNameIDFormat)

	t.Run("transient", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)

		nameID, err := nameIDTestRequest(test, &NameIDPolicy{Format: &transient}).resolveNameID(&Session{ID: "s"})
		assert.NilError(t, err)
		assert.Check(t, nameID.Value != "")
	})

	t.Run("session format", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)

		_, err := nameIDTestRequest(test, nil).resolveNameID(&Session{ID: "s", NameIDFormat: email})
		assert.Check(t, is.ErrorContains(err, "no NameID"))

		// The session is incomplete, so the format left open doesn't fall back to transient.
		assert.Check(t, !errors.Is(err, ErrInvalidNameIDPolicy), "error: %v", err)
	})

	t.Run("provider returns an empty value", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.NameIDProvider = nameIDProviderFunc{
			formats: []string{transient},
			f: func(*http.Request, NameIDRequest, *Session) (*NameID, error) {
				return &NameID{}, nil
			},
		}

		_, err := nameIDTestRequest(test, &NameIDPolicy{Format: &transient}).resolveNameID(&Session{ID: "s", NameID: "alice"})
		assert.Check(t, is.ErrorContains(err, "returned no NameID"))
	})
}

func TestDefaultNameIDProviderRefusesOtherFormat(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/sso", nil)
	req := NameIDRequest{Format: string(PersistentNameIDFormat), SPNameQualifier: "https://sp.example.com/saml2/metadata"}

	nameID, err := DefaultNameIDProvider{}.NameID(r, req, &Session{ID: "s", NameID: "alice@example.com", NameIDFormat: string(EmailAddressNameIDFormat)})
	assert.Check(t, errors.Is(err, ErrInvalidNameIDPolicy), "%v", err)
	assert.Check(t, nameID == nil)
}

func TestDefaultNameIDProviderFormats(t *testing.T) {
	assert.Check(t, is.DeepEqual(DefaultNameIDProvider{}.NameIDFormats(), []string{string(TransientNameIDFormat)}))

	formats := []string{string(EmailAddressNameIDFormat), string(TransientNameIDFormat)}
	assert.Check(t, is.DeepEqual(DefaultNameIDProvider{Formats: formats}.NameIDFormats(), formats))
}

func TestResolveNameID(t *testing.T) {
	transient := string(TransientNameIDFormat)
	email := string(EmailAddressNameIDFormat)
	persistent := string(PersistentNameIDFormat)
	encrypted := encryptedNameIDFormat
	requester := "https://sp.example.com/saml2/metadata"
	affiliation := testAffiliationID
	other := "https://other.example.com/affiliation"

	emailSession := &Session{ID: "s", NameID: "alice@example.com", NameIDFormat: email}
	plainSession := &Session{ID: "s", NameID: "alice"}

	type expected struct {
		invalid         bool
		format          string
		value           string // empty for a random transient value.
		spNameQualifier string
	}

	for name, tc := range map[string]struct {
		setup    func(*IdentityProviderTest)
		session  *Session
		policy   *NameIDPolicy
		expected expected
	}{
		"no policy": {
			session:  plainSession,
			expected: expected{format: transient, spNameQualifier: requester},
		},
		"explicit email, session email": {
			session:  emailSession,
			policy:   &NameIDPolicy{Format: &email},
			expected: expected{format: email, value: "alice@example.com", spNameQualifier: requester},
		},
		"explicit persistent, session email": {
			session:  emailSession,
			policy:   &NameIDPolicy{Format: &persistent},
			expected: expected{invalid: true},
		},
		"encrypted": {
			session:  plainSession,
			policy:   &NameIDPolicy{Format: &encrypted},
			expected: expected{invalid: true},
		},
		"open format, SP metadata lists email": {
			setup: func(test *IdentityProviderTest) {
				withSPNameIDFormats(test, EmailAddressNameIDFormat)
				test.IDP.NameIDProvider = DefaultNameIDProvider{Formats: []string{email, transient}}
			},
			session:  emailSession,
			expected: expected{format: email, value: "alice@example.com", spNameQualifier: requester},
		},
		"SPNameQualifier is the SP entity ID": {
			session:  plainSession,
			policy:   &NameIDPolicy{SPNameQualifier: &requester},
			expected: expected{format: transient, spNameQualifier: requester},
		},
		"affiliation member": {
			setup:    func(test *IdentityProviderTest) { withAffiliation(test, nil) },
			session:  plainSession,
			policy:   &NameIDPolicy{SPNameQualifier: &affiliation},
			expected: expected{format: transient, spNameQualifier: affiliation},
		},
		"not a member": {
			setup: func(test *IdentityProviderTest) {
				inner := test.IDP.ServiceProviderProvider
				test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
					GetServiceProviderFunc: func(r *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
						if serviceProviderID == other {
							return &EntityDescriptor{
								EntityID:              other,
								AffiliationDescriptor: &AffiliationDescriptor{AffiliateMembers: []string{"https://another.example.com"}},
							}, nil
						}

						return inner.GetServiceProvider(r, serviceProviderID)
					},
				}
			},
			session:  plainSession,
			policy:   &NameIDPolicy{SPNameQualifier: &other},
			expected: expected{invalid: true},
		},
		"expired affiliation": {
			setup: func(test *IdentityProviderTest) {
				withAffiliation(test, func(entity *EntityDescriptor) { entity.ValidUntil = TimeNow().Add(-time.Hour) })
			},
			session:  plainSession,
			policy:   &NameIDPolicy{SPNameQualifier: &affiliation},
			expected: expected{invalid: true},
		},
		"expired affiliation descriptor": {
			setup: func(test *IdentityProviderTest) {
				withAffiliation(test, func(entity *EntityDescriptor) {
					entity.AffiliationDescriptor.ValidUntil = TimeNow().Add(-time.Hour)
				})
			},
			session:  plainSession,
			policy:   &NameIDPolicy{SPNameQualifier: &affiliation},
			expected: expected{invalid: true},
		},
		"not an affiliation": {
			setup: func(test *IdentityProviderTest) {
				withAffiliation(test, func(entity *EntityDescriptor) { entity.AffiliationDescriptor = nil })
			},
			session:  plainSession,
			policy:   &NameIDPolicy{SPNameQualifier: &affiliation},
			expected: expected{invalid: true},
		},
		"unknown affiliation": {
			session:  plainSession,
			policy:   &NameIDPolicy{SPNameQualifier: &affiliation},
			expected: expected{invalid: true},
		},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			if tc.setup != nil {
				tc.setup(test)
			}

			captured := captureNameID(test)

			response := serveSSOWithPolicy(t, test, tc.session, tc.policy)
			if tc.expected.invalid {
				assertInvalidNameIDPolicy(t, response)
				return
			}

			assert.Assert(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))

			nameID := *captured
			assert.Assert(t, nameID != nil)
			assert.Check(t, is.Equal(nameID.Format, tc.expected.format))
			assert.Check(t, is.Equal(nameID.SPNameQualifier, tc.expected.spNameQualifier))
			assert.Check(t, is.Equal(nameID.NameQualifier, "https://idp.example.com/saml/metadata"))

			if tc.expected.value != "" {
				assert.Check(t, is.Equal(nameID.Value, tc.expected.value))
			} else {
				assert.Check(t, nameID.Value != tc.session.NameID)
				assert.Check(t, len(nameID.Value) >= 22, nameID.Value)
			}
		})
	}
}

// A failure of the ServiceProviderProvider says nothing about the policy, so it is the responder's.
func TestResolveNameIDAffiliationLookupFailure(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	withAffiliationResult(test, func() (*EntityDescriptor, error) { return nil, errors.New("the store is down") })

	affiliation := testAffiliationID

	response := serveSSOWithPolicy(t, test, &Session{ID: "s", NameID: "alice"}, &NameIDPolicy{SPNameQualifier: &affiliation})
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusResponder))
	assert.Check(t, response.Status.StatusCode.StatusCode == nil)
	assert.Check(t, response.Assertion == nil)
	assert.Check(t, response.EncryptedAssertion == nil)
}

// The library fills what the provider leaves out, on a copy of its NameID.
func TestResolveNameIDCompletesProviderNameID(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	withAffiliation(test, nil)

	provided := &NameID{Value: "opaque"}
	test.IDP.NameIDProvider = nameIDProviderFunc{
		formats: []string{string(TransientNameIDFormat)},
		f: func(*http.Request, NameIDRequest, *Session) (*NameID, error) {
			return provided, nil
		},
	}

	affiliation := testAffiliationID
	req := nameIDTestRequest(test, &NameIDPolicy{SPNameQualifier: &affiliation})

	nameID, err := req.resolveNameID(&Session{ID: "s", NameID: "alice"})
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(nameID, &NameID{
		Format:          string(TransientNameIDFormat),
		NameQualifier:   "https://idp.example.com/saml/metadata",
		SPNameQualifier: affiliation,
		Value:           "opaque",
	}))
	assert.Check(t, is.DeepEqual(provided, &NameID{Value: "opaque"}))
}

// With the format left open, the order of the formats in the metadata of the service provider decides,
// before the format of the session.
func TestResolveNameIDPrefersServiceProviderFormats(t *testing.T) {
	email := string(EmailAddressNameIDFormat)
	persistent := string(PersistentNameIDFormat)
	transient := string(TransientNameIDFormat)

	for name, tc := range map[string]struct {
		spFormats []NameIDFormat
		expected  string
	}{
		"SP lists email":                {[]NameIDFormat{EmailAddressNameIDFormat}, email},
		"SP lists transient then email": {[]NameIDFormat{TransientNameIDFormat, EmailAddressNameIDFormat}, transient},
		"SP lists email then transient": {[]NameIDFormat{EmailAddressNameIDFormat, TransientNameIDFormat}, email},
		"SP lists nothing supported":    {[]NameIDFormat{UnspecifiedNameIDFormat}, persistent},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			withSPNameIDFormats(test, tc.spFormats...)

			formats := []string{email, persistent, transient}
			test.IDP.NameIDProvider = nameIDProviderFunc{
				formats: formats,
				f: func(_ *http.Request, req NameIDRequest, _ *Session) (*NameID, error) {
					if !slices.Contains(formats, req.Format) {
						return nil, ErrInvalidNameIDPolicy
					}

					return &NameID{Format: req.Format, SPNameQualifier: req.SPNameQualifier, Value: "id-" + req.Format}, nil
				},
			}
			captured := captureNameID(test)

			response := serveSSOWithPolicy(t, test, &Session{ID: "s", NameID: "alice", NameIDFormat: persistent}, nil)
			assert.Assert(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
			assert.Assert(t, *captured != nil)
			assert.Check(t, is.Equal((*captured).Format, tc.expected))
		})
	}
}

func TestResolveNameIDFallsBackWhenSPFormatUnavailable(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	withSPNameIDFormats(test, PersistentNameIDFormat)
	test.IDP.NameIDProvider = DefaultNameIDProvider{Formats: []string{string(PersistentNameIDFormat), string(TransientNameIDFormat)}}

	captured := captureNameID(test)

	response := serveSSOWithPolicy(t, test, &Session{ID: "s", NameID: "alice"}, nil)
	assert.Assert(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	assert.Assert(t, *captured != nil)
	assert.Check(t, is.Equal((*captured).Format, string(TransientNameIDFormat)))
	assert.Check(t, (*captured).Value != "alice")
}

func TestResolveNameIDPassesAllowCreate(t *testing.T) {
	yes := true

	for name, tc := range map[string]struct {
		policy   *NameIDPolicy
		expected bool
	}{
		"allow create":     {&NameIDPolicy{AllowCreate: &yes}, true},
		"attribute absent": {&NameIDPolicy{}, false},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)

			var seen *bool

			test.IDP.NameIDProvider = nameIDProviderFunc{
				formats: []string{string(TransientNameIDFormat)},
				f: func(_ *http.Request, req NameIDRequest, _ *Session) (*NameID, error) {
					allowCreate := req.AllowCreate
					seen = &allowCreate

					return &NameID{Format: req.Format, SPNameQualifier: req.SPNameQualifier, Value: "opaque"}, nil
				},
			}

			response := serveSSOWithPolicy(t, test, &Session{ID: "s", NameID: "alice"}, tc.policy)
			assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
			assert.Assert(t, seen != nil)
			assert.Check(t, is.Equal(*seen, tc.expected))
		})
	}
}

func TestMetadataAdvertisesProviderFormats(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.NameIDProvider = DefaultNameIDProvider{Formats: []string{string(EmailAddressNameIDFormat), string(TransientNameIDFormat)}}

	assert.Check(t, is.DeepEqual(test.IDP.Metadata().IDPSSODescriptors[0].NameIDFormats,
		[]NameIDFormat{EmailAddressNameIDFormat, TransientNameIDFormat}))
}

// A session whose format is transient has its own transient NameID, which DefaultNameIDProvider issues.
func TestDefaultNameIDProviderTransientSessionFormat(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	transient := string(TransientNameIDFormat)

	for name, tc := range map[string]struct {
		policy *NameIDPolicy
	}{
		"explicit transient": {&NameIDPolicy{Format: &transient}},
		"open format":        {nil},
	} {
		t.Run(name, func(t *testing.T) {
			req := nameIDTestRequest(test, tc.policy)

			// The NameID of a transient session would be the same for every service provider, so a random one is
			// issued instead (SAMLCore §8.3.8).
			nameID, err := req.resolveNameID(&Session{ID: "s", NameID: "opaque-session-id", NameIDFormat: transient})
			assert.NilError(t, err)
			assert.Check(t, is.Equal(nameID.Format, transient))
			assert.Check(t, nameID.Value != "opaque-session-id")
		})
	}

	// Another format of the session still gets a random transient NameID.
	req := nameIDTestRequest(test, &NameIDPolicy{Format: &transient})
	nameID, err := req.resolveNameID(&Session{ID: "s", NameID: "alice@example.com", NameIDFormat: string(EmailAddressNameIDFormat)})
	assert.NilError(t, err)
	assert.Check(t, nameID.Value != "alice@example.com")
}

// A transient NameID that was asserted to the service provider in the session is asserted again, so that the
// service provider is one participant of a logout (SAMLProfiles §4.4.2).
func TestResolveNameIDReusesTransientParticipant(t *testing.T) {
	transient := string(TransientNameIDFormat)
	persistent := string(PersistentNameIDFormat)
	requester := "https://sp.example.com/saml2/metadata"
	idpEntityID := "https://idp.example.com/saml/metadata"
	affiliation := testAffiliationID
	start := TimeNow()

	participant := func(entityID, format, spNameQualifier, value string, issued time.Duration) SessionParticipant {
		return SessionParticipant{
			ServiceProviderEntityID: entityID,
			NameID:                  NameID{Format: format, NameQualifier: idpEntityID, SPNameQualifier: spNameQualifier, Value: value},
			IssueInstant:            start.Add(issued),
		}
	}

	for name, tc := range map[string]struct {
		participants []SessionParticipant
		policy       *NameIDPolicy
		// expected is the value that is reused, or empty for a new random value.
		expected string
	}{
		"no participants": {},
		"same service provider": {
			participants: []SessionParticipant{participant(requester, transient, requester, "earlier", 0)},
			expected:     "earlier",
		},
		"most recent": {
			participants: []SessionParticipant{
				participant(requester, transient, requester, "latest", 2*time.Second),
				participant(requester, transient, requester, "earlier", time.Second),
			},
			expected: "latest",
		},
		"explicit transient": {
			participants: []SessionParticipant{participant(requester, transient, requester, "earlier", 0)},
			policy:       &NameIDPolicy{Format: &transient},
			expected:     "earlier",
		},
		"another service provider": {
			participants: []SessionParticipant{participant("https://other-sp.example.com", transient, requester, "other", 0)},
		},
		"another format": {
			participants: []SessionParticipant{participant(requester, persistent, requester, "persistent", 0)},
		},
		"another SPNameQualifier": {
			participants: []SessionParticipant{participant(requester, transient, affiliation, "affiliated", 0)},
		},
		"affiliation": {
			participants: []SessionParticipant{
				participant(requester, transient, requester, "plain", 0),
				participant(requester, transient, affiliation, "affiliated", 0),
			},
			policy:   &NameIDPolicy{SPNameQualifier: &affiliation},
			expected: "affiliated",
		},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			withAffiliation(test, nil)
			test.IDP.SessionProvider = &fixedParticipantProvider{participants: tc.participants}

			req := nameIDTestRequest(test, tc.policy)
			session := &Session{ID: "s", NameID: "alice"}

			nameID, err := req.resolveNameID(session)
			assert.NilError(t, err)
			assert.Check(t, is.Equal(nameID.Format, transient))

			if tc.expected != "" {
				assert.Check(t, is.Equal(nameID.Value, tc.expected))
				return
			}

			for _, p := range tc.participants {
				assert.Check(t, nameID.Value != p.NameID.Value)
			}

			assert.Check(t, nameID.Value != session.NameID)
			assert.Check(t, len(nameID.Value) >= 22, nameID.Value)
		})
	}

	t.Run("participants error", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		boom := errors.New("boom")
		test.IDP.SessionProvider = &fixedParticipantProvider{err: boom}

		_, err := nameIDTestRequest(test, nil).resolveNameID(&Session{ID: "s", NameID: "alice"})
		assert.Check(t, errors.Is(err, boom), "%v", err)
		assert.Check(t, !errors.Is(err, ErrInvalidNameIDPolicy), "%v", err)
	})

	t.Run("participants error is a Responder status", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		provider := &fixedParticipantProvider{err: errors.New("boom")}
		provider.GetSessionFunc = func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
			return &Session{ID: "s", NameID: "alice"}
		}

		test.IDP.SessionProvider = provider

		response := postSSOWithPolicy(t, test, nil)
		assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusResponder))
		assert.Check(t, response.Status.StatusCode.StatusCode == nil)
		assert.Check(t, response.EncryptedAssertion == nil)
	})
}
