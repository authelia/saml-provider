package saml

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"maps"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/dsig"
	"authelia.com/provider/saml/xmlenc"
)

// The identity provider metadata that pysaml2 built its requests from must be what the identity provider still
// publishes, for each profile that publishes it. SAML_INTEROP_UPDATE=1 rewrites it, which generate.sh does before it
// runs pysaml2.
func TestInteropIDPMetadata(t *testing.T) {
	written := map[string]string{}

	for _, name := range slices.Sorted(maps.Keys(interopProfiles)) {
		file := interopProfiles[name].IDPMetadata
		if file == "" {
			continue
		}

		t.Run(name, func(t *testing.T) {
			got, err := xml.MarshalIndent(newInteropIDP(t, name).Metadata(), "", "  ")
			require.NoError(t, err)

			if other, ok := written[file]; ok {
				assert.Equal(t, other, string(got), "profiles that publish %s differ", file)
			}

			written[file] = string(got)

			path := filepath.Join("testdata", "interop", "idp", file)

			if os.Getenv("SAML_INTEROP_UPDATE") == "1" {
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
				require.NoError(t, os.WriteFile(path, got, 0o600))
			}

			want, err := os.ReadFile(path)
			require.NoError(t, err, "IdP metadata changed: run testdata/interop/generate.sh")
			assert.Equal(t, string(want), string(got), "IdP metadata changed: run testdata/interop/generate.sh")
		})
	}
}

// interopSeed seeds the RandReader of every replay.
var interopSeed = [32]byte([]byte("authelia saml-provider interop!!"))

// interopInstant is when every interop fixture was made, and what the clock of the identity provider says while
// one is replayed.
var interopInstant = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// interopManifest is testdata/interop/manifest.json, which generate.py writes. See testdata/interop/README.md.
type interopManifest struct {
	PySAML2 string        `json:"pysaml2"`
	XMLSec1 string        `json:"xmlsec1"`
	Instant time.Time     `json:"instant"`
	Cases   []interopCase `json:"cases"`
}

// interopCase is one request that pysaml2 made, how the identity provider is set up for it, and what its response
// must be.
type interopCase struct {
	ID           string        `json:"id"`
	Feature      string        `json:"feature"`
	MadeBy       string        `json:"made_by"`
	SP           string        `json:"sp"`
	IDPProfile   string        `json:"idp_profile"`
	Binding      string        `json:"binding"`
	Request      string        `json:"request"`
	RequestID    string        `json:"request_id"`
	Endpoint     string        `json:"endpoint,omitempty"`
	After        string        `json:"after,omitempty"`
	ArtifactOf   string        `json:"artifact_of,omitempty"`
	AssertionOf  string        `json:"assertion_of,omitempty"`
	Expect       interopExpect `json:"expect"`
	Verify       []string      `json:"verify"`
	VerifyWith   string        `json:"verify_with,omitempty"`
	VerifyReason string        `json:"verify_reason,omitempty"`
	Skip         string        `json:"skip,omitempty"`
}

// interopExpect is what the Go replay asserts of the response. It never configures anything.
type interopExpect struct {
	// Outcome is "success" or the URI of the top-level StatusCode.
	Outcome         string `json:"outcome"`
	SignatureMethod string `json:"signature_method"`

	// DigestMethod is the digest of the Reference of the signature of the Response, asserted only when it is set.
	DigestMethod       string `json:"digest_method,omitempty"`
	EncryptedAssertion bool   `json:"encrypted_assertion"`
	NameIDFormat       string `json:"name_id_format"`

	// KeyTransportMethod is the algorithm of the EncryptedKey of an EncryptedAssertion.
	KeyTransportMethod string `json:"key_transport_method,omitempty"`

	// ContentEncryptionMethod is the algorithm of the EncryptedData of an EncryptedAssertion, and
	// KeyTransportDigestMethod and KeyTransportMGF are the DigestMethod and MGF of its key transport. Each is
	// asserted only when it is set.
	ContentEncryptionMethod  string `json:"content_encryption_method,omitempty"`
	KeyTransportDigestMethod string `json:"key_transport_digest_method,omitempty"`
	KeyTransportMGF          string `json:"key_transport_mgf,omitempty"`

	// KeyAgreementMethod is the AgreementMethod of the EncryptedKey, for an elliptic curve key, and KeyWrapMethod
	// the algorithm of the EncryptedKey, which wraps the content key with the agreed one. KeyTransportMethod is not
	// asserted when KeyAgreementMethod is set.
	KeyAgreementMethod string `json:"key_agreement_method,omitempty"`
	KeyWrapMethod      string `json:"key_wrap_method,omitempty"`

	// EncryptedNameID is whether the NameID of the assertion is an EncryptedID, and EncryptedAttributes the value of
	// each attribute, by its name, that must be an EncryptedAttribute and no plaintext one.
	EncryptedNameID     bool              `json:"encrypted_name_id,omitempty"`
	EncryptedAttributes map[string]string `json:"encrypted_attributes,omitempty"`

	// NameID is the value the NameID of the assertion must have, when it is set, such as the one the Subject of an
	// AuthnRequest named. SecondLevel is the second-level StatusCode of a Response that reports an error.
	NameID      string `json:"name_id,omitempty"`
	SecondLevel string `json:"second_level,omitempty"`

	// Attributes are the value of each attribute, by its name, that the assertion must state in plaintext.
	Attributes map[string]string `json:"attributes,omitempty"`

	// NoAssertion is whether a successful Response carries no assertion, as for a query about a principal that is
	// not found (SAMLCore §3.3.4).
	NoAssertion bool `json:"no_assertion,omitempty"`

	// AuthnInstant is the AuthnInstant of the AuthnStatement of the assertion, asserted when it is set.
	AuthnInstant string `json:"authn_instant,omitempty"`

	// Artifact is whether the response is delivered by artifact, in place of the Response.
	Artifact bool `json:"artifact,omitempty"`

	// Destination is the Destination of the Response, when it is not the first assertion consumer service of the
	// service provider, such as the one of the HTTP-Artifact binding.
	Destination string `json:"destination,omitempty"`

	// IssuesAssertion is whether the ID of the assertion is recorded, for a later case to request it by.
	// AssertionOf is the case whose recorded assertion the assertion must be.
	IssuesAssertion bool   `json:"issues_assertion,omitempty"`
	AssertionOf     string `json:"assertion_of,omitempty"`
}

// interopProfile is how the identity provider is set up for a case, which SP metadata can't say.
type interopProfile struct {
	// IDPKey is the name of the key pair in testdata/interop/keys.
	IDPKey string

	// IDPMetadata is the file in testdata/interop/idp that the metadata of the identity provider is committed to,
	// for pysaml2 to make requests from, or empty if the profile publishes none of its own.
	IDPMetadata string

	// Session returns the session of the principal, or is nil for the session every case shares.
	Session func() *Session

	// Configure changes the identity provider after the settings every case shares.
	Configure func(tb testing.TB, idp *IdentityProvider)
}

var interopProfiles = map[string]interopProfile{
	"rsa": {
		IDPKey:      "idp-rsa",
		IDPMetadata: "idp-rsa.xml",
		Configure: func(_ testing.TB, idp *IdentityProvider) {
			idp.IssuancePolicy = DefaultIssuancePolicy{AssertionEncryption: NoAssertionEncryption}
		},
	},
	"rsa-encrypt-assertion": {
		IDPKey: "idp-rsa",
		Configure: func(_ testing.TB, idp *IdentityProvider) {
			idp.IssuancePolicy = DefaultIssuancePolicy{AssertionEncryption: RequireAssertionEncryption}
		},
	},
	"rsa-encrypt-name-id": {
		IDPKey: "idp-rsa",
		Configure: func(_ testing.TB, idp *IdentityProvider) {
			idp.IssuancePolicy = DefaultIssuancePolicy{AssertionEncryption: NoAssertionEncryption}
			idp.ElementEncryptionPolicy = DefaultElementEncryptionPolicy{
				NameIDServiceProviders: []string{interopServiceProviders["sp-rsa-mail"]},
			}
		},
	},
	"rsa-encrypt-attribute": {
		IDPKey: "idp-rsa",
		Configure: func(_ testing.TB, idp *IdentityProvider) {
			idp.IssuancePolicy = DefaultIssuancePolicy{AssertionEncryption: NoAssertionEncryption}
			idp.ElementEncryptionPolicy = DefaultElementEncryptionPolicy{
				AttributeServiceProviders: []string{interopServiceProviders["sp-rsa-mail"]},
			}
		},
	},
	"rsa-query": {
		IDPKey:  "idp-rsa",
		Session: interopEmailSession,
		Configure: func(_ testing.TB, idp *IdentityProvider) {
			idp.IssuancePolicy = DefaultIssuancePolicy{AssertionEncryption: NoAssertionEncryption}
		},
	},
	"rsa-query-encrypt-assertion": {
		IDPKey:  "idp-rsa",
		Session: interopEmailSession,
		Configure: func(_ testing.TB, idp *IdentityProvider) {
			idp.IssuancePolicy = DefaultIssuancePolicy{AssertionEncryption: RequireAssertionEncryption}
		},
	},
	"rsa-subject": {
		IDPKey:  "idp-rsa",
		Session: interopEmailSession,
		Configure: func(_ testing.TB, idp *IdentityProvider) {
			idp.IssuancePolicy = DefaultIssuancePolicy{AssertionEncryption: NoAssertionEncryption}
		},
	},
	"rsa-ec-encryption-subject": {
		IDPKey:  "idp-rsa",
		Session: interopEmailSession,
		Configure: func(tb testing.TB, idp *IdentityProvider) {
			idp.IssuancePolicy = DefaultIssuancePolicy{AssertionEncryption: NoAssertionEncryption}
			idp.EncryptionKey, idp.EncryptionCertificate = interopKey(tb, "idp-ec")
		},
	},
	"rsa-ec-encryption": {
		IDPKey:      "idp-rsa",
		IDPMetadata: "idp-rsa-ec-encryption.xml",
		Configure: func(tb testing.TB, idp *IdentityProvider) {
			idp.IssuancePolicy = DefaultIssuancePolicy{AssertionEncryption: NoAssertionEncryption}
			idp.EncryptionKey, idp.EncryptionCertificate = interopKey(tb, "idp-ec")
		},
	},
}

// interopEmailSession is the session of alice, whose NameID is her email address, for a request whose Subject names
// her that way.
func interopEmailSession() *Session {
	return &Session{
		ID:           "interop",
		CreateTime:   interopInstant,
		ExpireTime:   interopInstant.Add(time.Hour),
		NameID:       "alice@example.com",
		NameIDFormat: string(EmailAddressNameIDFormat),
		UserName:     "alice",
		UserEmail:    "alice@example.com",
	}
}

// interopServiceProviders are the service providers of the fixtures, by the name generate.py gives them.
var interopServiceProviders = map[string]string{
	"sp-rsa":           "https://sp-rsa.example.com/saml2/metadata",
	"sp-ec":            "https://sp-ec.example.com/saml2/metadata",
	"sp-rsa-negotiate": "https://sp-rsa-negotiate.example.com/saml2/metadata",
	"sp-rsa-cbc":       "https://sp-rsa-cbc.example.com/saml2/metadata",
	"sp-rsa-keyvalue":  "https://sp-rsa-keyvalue.example.com/saml2/metadata",
	"sp-ecdh":          "https://sp-ecdh.example.com/saml2/metadata",
	"sp-rsa-mail":      "https://sp-rsa-mail.example.com/saml2/metadata",
	"sp-rsa-artifact":  "https://sp-rsa-artifact.example.com/saml2/metadata",
}

// interopEncryptionKeys are the key pairs in testdata/interop/keys that each service provider decrypts with, by its
// name. Every other service provider decrypts with the key pair of its own name.
var interopEncryptionKeys = map[string]string{
	"sp-rsa-negotiate": "sp-rsa",
	"sp-rsa-cbc":       "sp-rsa",
	"sp-rsa-keyvalue":  "sp-rsa",
	"sp-ecdh":          "sp-ec",
	"sp-rsa-mail":      "sp-rsa",
	"sp-rsa-artifact":  "sp-rsa",
}

// interopEncryptionKey returns the name of the key pair a service provider of the fixtures decrypts with.
func interopEncryptionKey(sp string) string {
	if key, ok := interopEncryptionKeys[sp]; ok {
		return key
	}

	return sp
}

// newInteropIDP returns the identity provider of a profile, on clocks stopped at interopInstant.
func newInteropIDP(tb testing.TB, profile string) *IdentityProvider {
	tb.Helper()

	p, ok := interopProfiles[profile]
	if !ok {
		tb.Fatalf("unknown idp_profile %q", profile)

		return nil
	}

	// TimeNow is the clock of the identity provider, and Clock that of the signatures it verifies. RandReader is
	// deterministic, so that the identity provider issues the same artifacts and IDs on every replay, which pysaml2
	// made its requests for (see TestInteropIssued). Keys and IVs come from xmlenc.RandReader, which is left random.
	timeNow, clock, randReader := TimeNow, Clock, RandReader
	TimeNow, Clock = func() time.Time { return interopInstant }, dsig.NewFakeClockAt(interopInstant)
	RandReader = rand.NewChaCha8(interopSeed)

	tb.Cleanup(func() { TimeNow, Clock, RandReader = timeNow, clock, randReader })

	key, cert := interopKey(tb, p.IDPKey)

	idp := &IdentityProvider{
		Key:                          key,
		Certificate:                  cert,
		MetadataURL:                  mustParseURL("https://idp.example.com/saml/metadata"),
		SSOURL:                       mustParseURL("https://idp.example.com/saml/sso"),
		AttributeServiceURL:          mustParseURL("https://idp.example.com/saml/attribute"),
		AuthnQueryServiceURL:         mustParseURL("https://idp.example.com/saml/authn-query"),
		AssertionIDRequestServiceURL: mustParseURL("https://idp.example.com/saml/assertion-id"),
		AssertionURIURL:              mustParseURL("https://idp.example.com/saml/assertion-uri"),
		URIRequesterAuthenticator:    interopURIRequester{},
		ArtifactResolutionURL:        mustParseURL("https://idp.example.com/saml/artifact"),
		ArtifactStore:                NewMemoryArtifactStore(16),
		AssertionStore:               &interopAssertionStore{},
		ReplayStore:                  NewMemoryReplayStore(64),
		WantAuthnRequestsSigned:      true,
		ServiceProviderProvider: &mockServiceProviderProvider{
			GetServiceProviderFunc: func(_ *http.Request, entityID string) (*EntityDescriptor, error) {
				for name, id := range interopServiceProviders {
					if id == entityID {
						return interopSPMetadata(tb, name), nil
					}
				}

				return nil, os.ErrNotExist
			},
		},
		SessionProvider: interopSessionProvider{session: p.Session},
	}

	p.Configure(tb, idp)

	return idp
}

// interopSessionProvider is the SessionProvider of the fixtures. Every request finds the session of its profile, or
// the one every case shares, and a query finds it only when it names the NameID of that session.
type interopSessionProvider struct {
	session func() *Session
}

var _ QuerySessionProvider = interopSessionProvider{}

func (p interopSessionProvider) get() *Session {
	if p.session != nil {
		return p.session()
	}

	return &Session{
		ID:         "interop",
		CreateTime: interopInstant,
		ExpireTime: interopInstant.Add(time.Hour),
		NameID:     "alice",
		UserName:   "alice",
		UserEmail:  "alice@example.com",
	}
}

func (p interopSessionProvider) GetSession(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
	return p.get()
}

// names reports whether nameID is the NameID of the session, by its value and its format.
func (p interopSessionProvider) names(nameID *NameID) bool {
	session := p.get()

	return nameID != nil && nameID.Value == session.NameID && nameID.Format == session.NameIDFormat && session.NameIDFormat != ""
}

func (p interopSessionProvider) GetQuerySubject(_ *http.Request, _ *IdpQueryRequest, nameID *NameID) (*Session, error) {
	if !p.names(nameID) {
		return nil, nil
	}

	return p.get(), nil
}

func (p interopSessionProvider) GetAuthnSessions(_ *http.Request, _ *IdpQueryRequest, nameID *NameID) ([]*Session, error) {
	if !p.names(nameID) {
		return []*Session{}, nil
	}

	return []*Session{p.get()}, nil
}

// interopRequesterHeader is the header that the replay names the service provider of a request on the URI binding
// with, as a proxy that authenticated it would.
const interopRequesterHeader = "X-Interop-Requester"

// interopURIRequester is the URIRequesterAuthenticator of the fixtures, which trusts interopRequesterHeader.
type interopURIRequester struct{}

func (interopURIRequester) AuthenticateURIRequester(r *http.Request) (string, error) {
	return r.Header.Get(interopRequesterHeader), nil
}

// interopAssertionStore is an AssertionStore in memory, for one replay.
type interopAssertionStore struct {
	mu         sync.Mutex
	assertions map[string]interopStoredAssertion
}

type interopStoredAssertion struct {
	serviceProvider string
	assertion       *etree.Element
	notOnOrAfter    time.Time
}

func (s *interopAssertionStore) SaveAssertion(_ *http.Request, serviceProvider string, assertion *etree.Element, notOnOrAfter time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.assertions == nil {
		s.assertions = map[string]interopStoredAssertion{}
	}

	s.assertions[assertion.SelectAttrValue("ID", "")] = interopStoredAssertion{serviceProvider, assertion, notOnOrAfter}

	return nil
}

func (s *interopAssertionStore) GetAssertion(_ *http.Request, id string) (*etree.Element, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stored, ok := s.assertions[id]
	if !ok || !TimeNow().Before(stored.notOnOrAfter) {
		return nil, "", nil
	}

	return stored.assertion, stored.serviceProvider, nil
}

// interopSPMetadata returns the metadata that pysaml2 wrote for a service provider of the fixtures.
func interopSPMetadata(tb testing.TB, name string) *EntityDescriptor {
	tb.Helper()

	if _, ok := interopServiceProviders[name]; !ok {
		tb.Fatalf("unknown sp %q", name)

		return nil
	}

	data, err := os.ReadFile(filepath.Join("testdata", "interop", "sp", "metadata", name+".xml"))
	require.NoError(tb, err)

	metadata, err := ParseServiceProviderMetadata(data)
	require.NoError(tb, err)

	return metadata
}

// TestInterop replays every request of testdata/interop/manifest.json against the identity provider. With
// SAML_INTEROP_EMIT set to a directory, it also writes each response there, as <id>.b64, for verify.py.
func TestInterop(t *testing.T) {
	manifest := readInteropManifest(t)
	checkInteropManifest(t, manifest)

	for _, c := range manifest.Cases {
		t.Run(c.ID, func(t *testing.T) {
			if c.Skip != "" {
				t.Skip(c.Skip)
			}

			response := runInteropCase(t, c)

			if dir := os.Getenv("SAML_INTEROP_EMIT"); dir != "" {
				root, err := os.OpenRoot(dir)
				require.NoError(t, err)

				defer root.Close()

				require.NoError(t, root.WriteFile(c.ID+".b64", []byte(response), 0o600))
			}
		})
	}
}

// What the identity provider issues on a replay must be what pysaml2 made its later requests for: the artifact of a
// response delivered by artifact, and the ID of an assertion that is requested later. RandReader is deterministic, so a replay issues the same each time, unless the
// identity provider changes the order in which it draws random bytes. SAML_INTEROP_UPDATE=1 rewrites the record,
// which generate.sh does between its two passes.
func TestInteropIssued(t *testing.T) {
	got := map[string]interopIssued{}

	for _, c := range readInteropManifest(t).Cases {
		if !c.Expect.Artifact && !c.Expect.IssuesAssertion || c.Skip != "" {
			continue
		}

		t.Run(c.ID, func(t *testing.T) {
			checkInteropCase(t, c)

			r := newInteropReplay(t, c)
			r.run(t, c)
			got[c.ID] = r.issued[c.ID]
		})
	}

	data, err := json.MarshalIndent(got, "", "  ")
	require.NoError(t, err)

	data = append(data, '\n')
	path := filepath.Join("testdata", "interop", "idp", "issued.json")

	if os.Getenv("SAML_INTEROP_UPDATE") == "1" {
		require.NoError(t, os.WriteFile(path, data, 0o600))
	}

	want, err := os.ReadFile(path)
	require.NoError(t, err, "what the identity provider issues changed: run testdata/interop/generate.sh")
	assert.Equal(t, string(want), string(data), "what the identity provider issues changed: run testdata/interop/generate.sh")
}

// An artifact is resolved once: the identity provider gives out the message to the first ArtifactResolve, and
// answers the same request again with Success and no message (SAMLCore §3.5.3, SAMLBind §3.6.6).
func TestInteropArtifactIsResolvedOnce(t *testing.T) {
	c := interopManifestCase(t, "artifact-resolve")
	r := newInteropReplay(t, c)

	r.run(t, c)

	_, again := r.serve(t, c)
	require.Equal(t, "ArtifactResponse", again.Tag)

	if status := again.FindElement("./Status/StatusCode"); assert.NotNil(t, status) {
		assert.Equal(t, StatusSuccess, status.SelectAttrValue("Value", ""))
	}

	assert.Nil(t, again.FindElement("./Response"), "the message was given out twice")
}

// The replay never depends on the wall clock, however long after the fixtures were made it runs: both clocks of
// the package are moved past the end of the certificates, and a real case still passes.
func TestInteropReplayIgnoresWallClock(t *testing.T) {
	later := time.Date(2037, 1, 1, 0, 0, 0, 0, time.UTC)
	timeNow, clock := TimeNow, Clock
	TimeNow, Clock = func() time.Time { return later }, dsig.NewFakeClockAt(later)

	t.Cleanup(func() { TimeNow, Clock = timeNow, clock })

	t.Run("replay", func(t *testing.T) {
		runInteropCase(t, interopManifestCase(t, "authn-request-post-rsa-sha256"))
		runInteropCase(t, interopManifestCase(t, "authn-request-redirect-rsa-sha256"))
	})

	assert.True(t, TimeNow().Equal(later), "TimeNow was not restored after the replay")
	assert.Equal(t, later, Clock.Now(), "Clock was not restored after the replay")
}

// interopManifestCase returns a case of manifest.json by its id.
func interopManifestCase(tb testing.TB, id string) interopCase {
	tb.Helper()

	for _, c := range readInteropManifest(tb).Cases {
		if c.ID == id {
			return c
		}
	}

	tb.Fatalf("no case %q in manifest.json", id)

	return interopCase{}
}

// A case that names what doesn't exist fails, and names it. It is never skipped.
func TestInteropRejectsUnknownCaseFields(t *testing.T) {
	valid := interopCase{ID: "x", SP: "sp-rsa", IDPProfile: "rsa", Binding: "post-signed", Request: "sp/requests/authn-request-post-rsa-sha256.form"}

	for field, c := range map[string]interopCase{
		"idp_profile": func(c interopCase) interopCase { c.IDPProfile = "nope"; return c }(valid),
		"binding":     func(c interopCase) interopCase { c.Binding = "nope"; return c }(valid),
		"sp":          func(c interopCase) interopCase { c.SP = "nope"; return c }(valid),
	} {
		t.Run(field, func(t *testing.T) {
			tb := &fatalRecorder{TB: t}

			done := make(chan struct{})
			go func() {
				defer close(done)

				runInteropCase(tb, c)
			}()

			<-done

			require.NotEmpty(t, tb.fatal, "the case did not fail")
			assert.Contains(t, tb.fatal, `"nope"`)
		})
	}
}

// fatalRecorder is a testing.TB whose failures are recorded, and which stops the goroutine that fails.
type fatalRecorder struct {
	testing.TB
	fatal string
}

func (r *fatalRecorder) Fatalf(format string, args ...any) {
	r.fatal = fmt.Sprintf(format, args...)

	runtime.Goexit()
}

func (r *fatalRecorder) Errorf(format string, args ...any) { r.fatal += fmt.Sprintf(format, args...) }

func (r *fatalRecorder) FailNow() { runtime.Goexit() }

var (
	interopResponseInput = regexp.MustCompile(`name="SAMLResponse" value="([^"]*)"`)
	interopArtifactInput = regexp.MustCompile(`name="SAMLart" value="([^"]*)"`)
)

// runInteropCase replays the request of a case against the identity provider of its profile, after the requests of
// the cases it comes after, asserts what the case expects of the answer, and returns the answer as the base64 that
// is posted or sent back, or the artifact that is posted in its place.
func runInteropCase(tb testing.TB, c interopCase) string {
	tb.Helper()

	checkInteropCase(tb, c)

	return newInteropReplay(tb, c).run(tb, c)
}

// run replays the cases that a case comes after, and then the case, on the identity provider of the replay.
func (r *interopReplay) run(tb testing.TB, c interopCase) string {
	tb.Helper()

	if c.After != "" {
		after := interopManifestCase(tb, c.After)
		require.Equal(tb, c.IDPProfile, after.IDPProfile, "case %s comes after a case of another profile", c.ID)

		r.run(tb, after)
	}

	r.checkNamesIssued(tb, c)

	if c.Expect.Artifact {
		artifact := r.serveArtifact(tb, c)
		r.issued[c.ID] = interopIssued{Artifact: artifact}

		return artifact
	}

	encoded, message := r.serve(tb, c)

	switch message.Tag {
	case "Assertion":
		// The URI binding answers with the assertion alone.
		require.Equal(tb, "uri", c.Binding, "an Assertion answers a request on the %s binding", c.Binding)

		if method := message.FindElement("./Signature/SignedInfo/SignatureMethod"); assert.NotNil(tb, method, "the Assertion is not signed") {
			assert.Equal(tb, c.Expect.SignatureMethod, method.SelectAttrValue("Algorithm", ""))
		}

		r.checkAssertion(tb, c, message)

		return encoded
	case "ArtifactResponse":
		message = r.checkArtifactResponse(tb, &c, message)
	default:
		require.Equal(tb, "Response", message.Tag)
	}

	checkInteropResponse(tb, c, message)

	if c.Expect.Outcome != "success" && c.Expect.Outcome != StatusSuccess {
		return encoded
	}

	if c.Expect.NoAssertion {
		assert.Nil(tb, message.FindElement("./Assertion"), "an Assertion")
		assert.Nil(tb, message.FindElement("./EncryptedAssertion"), "an EncryptedAssertion")

		return encoded
	}

	assertion := message.FindElement("./Assertion")

	if c.Expect.EncryptedAssertion {
		assert.Nil(tb, assertion, "a plaintext Assertion beside the EncryptedAssertion")

		assertion = decryptInteropAssertion(tb, c, message)
	}

	if assert.NotNil(tb, assertion, "no Assertion") {
		r.checkAssertion(tb, c, assertion)
	}

	return encoded
}

// checkAssertion checks what the case expects of the assertion it was answered with, in plaintext, and records its
// ID if the case issues one for a later case to request.
func (r *interopReplay) checkAssertion(tb testing.TB, c interopCase, assertion *etree.Element) {
	tb.Helper()

	if c.Expect.IssuesAssertion {
		r.issued[c.ID] = interopIssued{AssertionID: assertion.SelectAttrValue("ID", "")}
	}

	if c.Expect.AssertionOf != "" {
		issued, ok := r.issued[c.Expect.AssertionOf]
		require.True(tb, ok, "case %s issued no assertion on this replay", c.Expect.AssertionOf)
		assert.Equal(tb, issued.AssertionID, assertion.SelectAttrValue("ID", ""), "the assertion of %s", c.Expect.AssertionOf)
	}

	checkInteropSubject(tb, c, assertion)
	checkInteropEncryptedAttributes(tb, c, assertion)
	checkInteropAttributes(tb, c, assertion)

	if c.Expect.AuthnInstant != "" {
		statements := assertion.FindElements("./AuthnStatement")
		if assert.Len(tb, statements, 1, "AuthnStatements") {
			assert.Equal(tb, c.Expect.AuthnInstant, statements[0].SelectAttrValue("AuthnInstant", ""))
		}
	}
}

// checkNamesIssued fails a case whose request names an artifact or assertion that the case it was made from did not
// issue on this replay, as when idp/issued.json is stale, rather than let the identity provider answer it as for an
// unknown one.
func (r *interopReplay) checkNamesIssued(tb testing.TB, c interopCase) {
	tb.Helper()

	for of, value := range map[string]func(interopIssued) string{
		c.ArtifactOf:  func(i interopIssued) string { return i.Artifact },
		c.AssertionOf: func(i interopIssued) string { return i.AssertionID },
	} {
		if of == "" {
			continue
		}

		issued, ok := r.issued[of]
		require.True(tb, ok, "case %s issued nothing on this replay", of)

		body, err := os.ReadFile(filepath.Join("testdata", "interop", c.Request))
		require.NoError(tb, err)
		require.Contains(tb, string(body), value(issued),
			"the request names what %s didn't issue on this replay: run testdata/interop/generate.sh", of)
	}
}

// serveArtifact serves the request of a case whose response is delivered by artifact, and returns the artifact
// that the browser is to post to the service provider, which must be one that this identity provider issued.
func (r *interopReplay) serveArtifact(tb testing.TB, c interopCase) string {
	tb.Helper()

	body, err := os.ReadFile(filepath.Join("testdata", "interop", c.Request))
	require.NoError(tb, err)

	req := httptest.NewRequest(http.MethodPost, r.idp.SSOURL.String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	r.idp.ServeSSO(w, req)
	require.Equal(tb, http.StatusOK, w.Code, "%s", w.Body.String())

	match := interopArtifactInput.FindStringSubmatch(w.Body.String())
	require.NotNil(tb, match, "no SAMLart in %s", w.Body.String())
	assert.Nil(tb, interopResponseInput.FindStringSubmatch(w.Body.String()), "a SAMLResponse beside the artifact")

	encoded := html.UnescapeString(match[1])

	artifact, err := ParseArtifact(encoded)
	require.NoError(tb, err)
	assert.Equal(tb, ArtifactSourceID(r.idp.entityID()), artifact.SourceID, "the SourceID of the artifact")
	assert.Equal(tb, uint16(0), artifact.EndpointIndex)

	return encoded
}

// checkArtifactResponse checks the ArtifactResponse of a case, and returns the Response it carries, with the case
// changed to expect what the Response answers: the request of the case it comes after.
func (r *interopReplay) checkArtifactResponse(tb testing.TB, c *interopCase, artifactResponse *etree.Element) *etree.Element {
	tb.Helper()

	if status := artifactResponse.FindElement("./Status/StatusCode"); assert.NotNil(tb, status) {
		assert.Equal(tb, StatusSuccess, status.SelectAttrValue("Value", ""))
	}

	assert.Equal(tb, c.RequestID, artifactResponse.SelectAttrValue("InResponseTo", ""))

	if method := artifactResponse.FindElement("./Signature/SignedInfo/SignatureMethod"); assert.NotNil(tb, method, "the ArtifactResponse is not signed") {
		assert.Equal(tb, c.Expect.SignatureMethod, method.SelectAttrValue("Algorithm", ""))
	}

	response := artifactResponse.FindElement("./Response")
	require.NotNil(tb, response, "the ArtifactResponse carries no Response")

	require.NotEmpty(tb, c.After, "an ArtifactResponse for a case that comes after none")

	c.RequestID = interopManifestCase(tb, c.After).RequestID
	c.Binding = "post-signed"

	return response
}

// interopReplay is the identity provider of one replay, whose stores outlive each request served on it, and what
// it issued on it, by case id.
type interopReplay struct {
	idp    *IdentityProvider
	issued map[string]interopIssued
}

// interopIssued is what the identity provider issued for a case: the artifact of a response delivered by artifact,
// or the ID of an assertion that a later case requests.
type interopIssued struct {
	Artifact    string `json:"artifact,omitempty"`
	AssertionID string `json:"assertion_id,omitempty"`
}

// newInteropReplay returns a replay on the identity provider of the profile of a case.
func newInteropReplay(tb testing.TB, c interopCase) *interopReplay {
	tb.Helper()

	return &interopReplay{idp: newInteropIDP(tb, c.IDPProfile), issued: map[string]interopIssued{}}
}

// serve serves the request of a case, and returns the SAML message the identity provider answers with: the
// Response posted to the service provider on the browser bindings, and the message in the SOAP Body on the SOAP
// binding.
func (r *interopReplay) serve(tb testing.TB, c interopCase) (string, *etree.Element) {
	tb.Helper()

	body, err := os.ReadFile(filepath.Join("testdata", "interop", c.Request))
	require.NoError(tb, err)

	var req *http.Request

	switch c.Binding {
	case "redirect-signed":
		req = httptest.NewRequest(http.MethodGet, r.idp.SSOURL.String()+"?"+string(body), nil)
	case "post-signed":
		req = httptest.NewRequest(http.MethodPost, r.idp.SSOURL.String(), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case "soap":
		return r.serveSOAP(tb, c, body)
	case "uri":
		return r.serveURI(tb, c, body)
	default:
		tb.Fatalf("unknown binding %q", c.Binding)

		return "", nil
	}

	w := httptest.NewRecorder()
	r.idp.ServeSSO(w, req)
	require.Equal(tb, http.StatusOK, w.Code, "%s", w.Body.String())

	match := interopResponseInput.FindStringSubmatch(w.Body.String())
	require.NotNil(tb, match, "no SAMLResponse in %s", w.Body.String())

	encoded := html.UnescapeString(match[1])

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(tb, err)

	doc := etree.NewDocument()
	require.NoError(tb, doc.ReadFromBytes(decoded))
	require.Equal(tb, "Response", doc.Root().Tag)

	return encoded, doc.Root()
}

// serveSOAP posts the SOAP envelope of a case to the service its endpoint names, and returns the envelope of the
// answer in base64 and the one SAML message in its Body, which must hold no Fault.
func (r *interopReplay) serveSOAP(tb testing.TB, c interopCase, body []byte) (string, *etree.Element) {
	tb.Helper()

	req := httptest.NewRequest(http.MethodPost, "https://idp.example.com/saml/"+c.Endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "text/xml")

	w := httptest.NewRecorder()
	interopEndpoints[c.Endpoint](r.idp)(w, req)
	require.Equal(tb, http.StatusOK, w.Code, "%s", w.Body.String())

	doc := etree.NewDocument()
	require.NoError(tb, doc.ReadFromBytes(w.Body.Bytes()))
	require.Equal(tb, "Envelope", doc.Root().Tag, "%s", w.Body.String())
	require.Equal(tb, "http://schemas.xmlsoap.org/soap/envelope/", doc.Root().NamespaceURI())

	soapBody := doc.Root().FindElement("./Body")
	require.NotNil(tb, soapBody, "no SOAP Body")
	require.Nil(tb, soapBody.FindElement("./Fault"), "a SOAP Fault: %s", w.Body.String())
	require.Len(tb, soapBody.ChildElements(), 1, "the SOAP Body holds other than one message")

	return base64.StdEncoding.EncodeToString(w.Body.Bytes()), soapBody.ChildElements()[0]
}

// serveURI gets the assertion that the query of a case names on the SAML URI binding, as the service provider of the
// case, and returns the body of the answer in base64 and the Assertion it is.
func (r *interopReplay) serveURI(tb testing.TB, c interopCase, query []byte) (string, *etree.Element) {
	tb.Helper()

	req := httptest.NewRequest(http.MethodGet, r.idp.AssertionURIURL.String()+"?"+string(query), nil)
	req.Header.Set(interopRequesterHeader, interopServiceProviders[c.SP])

	w := httptest.NewRecorder()
	r.idp.ServeAssertionURI(w, req)
	require.Equal(tb, http.StatusOK, w.Code, "%s", w.Body.String())
	assert.Equal(tb, "application/samlassertion+xml", w.Header().Get("Content-Type"))

	doc := etree.NewDocument()
	require.NoError(tb, doc.ReadFromBytes(w.Body.Bytes()))
	require.Equal(tb, "Assertion", doc.Root().Tag, "%s", w.Body.String())
	require.Equal(tb, samlAssertionNS, doc.Root().NamespaceURI())

	return base64.StdEncoding.EncodeToString(w.Body.Bytes()), doc.Root()
}

// checkInteropResponse checks what the case expects of the Response itself: its status, whom it answers and is
// for, its signature, and whether it carries an assertion encrypted as a whole, or none for an error.
func checkInteropResponse(tb testing.TB, c interopCase, response *etree.Element) {
	tb.Helper()

	outcome := c.Expect.Outcome
	if outcome == "success" {
		outcome = StatusSuccess
	}

	if status := response.FindElement("./Status/StatusCode"); assert.NotNil(tb, status) {
		assert.Equal(tb, outcome, status.SelectAttrValue("Value", ""))
	}

	assert.Equal(tb, c.RequestID, response.SelectAttrValue("InResponseTo", ""))

	// A Response on the SOAP binding goes back on the connection it answers, and has no Destination.
	if c.Binding != "soap" {
		destination := c.Expect.Destination
		if destination == "" {
			acs := interopSPMetadata(tb, c.SP).SPSSODescriptors[0].AssertionConsumerServices
			require.NotEmpty(tb, acs, "%s has no assertion consumer service", c.SP)

			destination = acs[0].Location
		}

		assert.Equal(tb, destination, response.SelectAttrValue("Destination", ""))
	}

	if method := response.FindElement("./Signature/SignedInfo/SignatureMethod"); assert.NotNil(tb, method, "the Response is not signed") {
		assert.Equal(tb, c.Expect.SignatureMethod, method.SelectAttrValue("Algorithm", ""))
	}

	if c.Expect.DigestMethod != "" {
		if method := response.FindElement("./Signature/SignedInfo/Reference/DigestMethod"); assert.NotNil(tb, method) {
			assert.Equal(tb, c.Expect.DigestMethod, method.SelectAttrValue("Algorithm", ""))
		}
	}

	if outcome == StatusSuccess {
		assert.Equal(tb, c.Expect.EncryptedAssertion, response.FindElement("./EncryptedAssertion") != nil, "EncryptedAssertion")

		return
	}

	if c.Expect.SecondLevel != "" {
		if status := response.FindElement("./Status/StatusCode/StatusCode"); assert.NotNil(tb, status, "no second-level StatusCode") {
			assert.Equal(tb, c.Expect.SecondLevel, status.SelectAttrValue("Value", ""))
		}
	}

	// A Response that reports an error carries no assertion, encrypted or not.
	assert.Nil(tb, response.FindElement("./Assertion"), "an Assertion in an error Response")
	assert.Nil(tb, response.FindElement("./EncryptedAssertion"), "an EncryptedAssertion in an error Response")
}

// checkInteropSubject checks the NameID of the assertion, after decrypting it if the case expects an EncryptedID.
func checkInteropSubject(tb testing.TB, c interopCase, assertion *etree.Element) {
	tb.Helper()

	nameID := assertion.FindElement("./Subject/NameID")

	if c.Expect.EncryptedNameID {
		assert.Nil(tb, nameID, "a plaintext NameID")

		if encryptedID := assertion.FindElement("./Subject/EncryptedID"); assert.NotNil(tb, encryptedID, "no EncryptedID") {
			nameID = decryptInteropElement(tb, c, encryptedID, "NameID")
		}
	}

	if !assert.NotNil(tb, nameID) {
		return
	}

	assert.Equal(tb, c.Expect.NameIDFormat, nameID.SelectAttrValue("Format", ""))
	assert.NotEmpty(tb, nameID.Text())

	if c.Expect.NameID != "" {
		assert.Equal(tb, c.Expect.NameID, nameID.Text())
	}
}

// checkInteropEncryptedAttributes checks that each attribute the case names is only in an EncryptedAttribute, and
// decrypts to the value expected.
func checkInteropEncryptedAttributes(tb testing.TB, c interopCase, assertion *etree.Element) {
	tb.Helper()

	for name, value := range c.Expect.EncryptedAttributes {
		assert.Nil(tb, assertion.FindElement(fmt.Sprintf("./AttributeStatement/Attribute[@Name=%q]", name)), "attribute %s in plaintext", name)

		var values []string

		for _, encrypted := range assertion.FindElements("./AttributeStatement/EncryptedAttribute") {
			attribute := decryptInteropElement(tb, c, encrypted, "Attribute")
			if attribute.SelectAttrValue("Name", "") != name {
				continue
			}

			for _, v := range attribute.FindElements("./AttributeValue") {
				values = append(values, v.Text())
			}
		}

		assert.Equal(tb, []string{value}, values, "decrypted values of attribute %s", name)
	}
}

// checkInteropAttributes checks that each attribute the case names is stated in plaintext with the value expected.
func checkInteropAttributes(tb testing.TB, c interopCase, assertion *etree.Element) {
	tb.Helper()

	for name, value := range c.Expect.Attributes {
		var values []string

		for _, attribute := range assertion.FindElements(fmt.Sprintf("./AttributeStatement/Attribute[@Name=%q]", name)) {
			for _, v := range attribute.FindElements("./AttributeValue") {
				values = append(values, v.Text())
			}
		}

		assert.Equal(tb, []string{value}, values, "values of attribute %s", name)
	}
}

// decryptInteropAssertion checks the key transport of the EncryptedAssertion of a Response, and decrypts it with the
// key of the service provider of the case.
func decryptInteropAssertion(tb testing.TB, c interopCase, response *etree.Element) *etree.Element {
	tb.Helper()

	encryptedData := response.FindElement("./EncryptedAssertion/EncryptedData")
	require.NotNil(tb, encryptedData, "no EncryptedData in the EncryptedAssertion")

	if c.Expect.ContentEncryptionMethod != "" {
		if method := encryptedData.FindElement("./EncryptionMethod"); assert.NotNil(tb, method) {
			assert.Equal(tb, c.Expect.ContentEncryptionMethod, method.SelectAttrValue("Algorithm", ""))
		}
	}

	if c.Expect.KeyAgreementMethod != "" {
		if agreement := encryptedData.FindElement("./KeyInfo/EncryptedKey/KeyInfo/AgreementMethod"); assert.NotNil(tb, agreement, "no AgreementMethod") {
			assert.Equal(tb, c.Expect.KeyAgreementMethod, agreement.SelectAttrValue("Algorithm", ""))
		}

		if method := encryptedData.FindElement("./KeyInfo/EncryptedKey/EncryptionMethod"); assert.NotNil(tb, method) {
			assert.Equal(tb, c.Expect.KeyWrapMethod, method.SelectAttrValue("Algorithm", ""))
		}
	} else if method := encryptedData.FindElement("./KeyInfo/EncryptedKey/EncryptionMethod"); assert.NotNil(tb, method) {
		assert.Equal(tb, c.Expect.KeyTransportMethod, method.SelectAttrValue("Algorithm", ""))

		for want, path := range map[string]string{
			c.Expect.KeyTransportDigestMethod: "./DigestMethod",
			c.Expect.KeyTransportMGF:          "./MGF",
		} {
			if want == "" {
				continue
			}

			if el := method.FindElement(path); assert.NotNil(tb, el, "no %s in the key transport", path) {
				assert.Equal(tb, want, el.SelectAttrValue("Algorithm", ""))
			}
		}
	}

	// A service provider whose metadata gives its encryption key without a certificate, such as a KeyValue, has
	// no certificate that the identity provider could name the key with.
	if keyValue := interopEncryptionKeyValue(tb, c.SP); keyValue != nil {
		assert.Nil(tb, encryptedData.FindElement(".//EncryptedKey/KeyInfo//X509Certificate"), "a certificate the metadata doesn't have")

		got := encryptedData.FindElement("./KeyInfo/EncryptedKey/KeyInfo/KeyValue/RSAKeyValue")
		if assert.NotNil(tb, got, "the EncryptedKey doesn't name the KeyValue it is encrypted to") {
			for want, path := range map[string]string{keyValue.Modulus: "./Modulus", keyValue.Exponent: "./Exponent"} {
				if el := got.FindElement(path); assert.NotNil(tb, el, "no %s in the KeyValue of the EncryptedKey", path) {
					assert.Equal(tb, interopCryptoBinary(want), interopCryptoBinary(el.Text()), "the EncryptedKey names another key than the KeyValue: %s", path)
				}
			}
		}
	}

	key, _ := interopKey(tb, interopEncryptionKey(c.SP))

	plaintext, err := xmlenc.Decrypt(key, encryptedData)
	require.NoError(tb, err)

	doc := etree.NewDocument()
	require.NoError(tb, doc.ReadFromBytes(plaintext))
	require.Equal(tb, "Assertion", doc.Root().Tag)

	return doc.Root()
}

// decryptInteropElement decrypts an EncryptedID or EncryptedAttribute with the key of the service provider of the
// case, and returns the element it held, which must be of the tag given.
func decryptInteropElement(tb testing.TB, c interopCase, encrypted *etree.Element, tag string) *etree.Element {
	tb.Helper()

	encryptedData := encrypted.FindElement("./EncryptedData")
	require.NotNil(tb, encryptedData, "no EncryptedData in %s", encrypted.Tag)

	key, _ := interopKey(tb, interopEncryptionKey(c.SP))

	plaintext, err := xmlenc.Decrypt(key, encryptedData)
	require.NoError(tb, err)

	doc := etree.NewDocument()
	require.NoError(tb, doc.ReadFromBytes(plaintext))
	require.Equal(tb, tag, doc.Root().Tag)

	return doc.Root()
}

// interopEncryptionKeyValue returns the RSAKeyValue that the metadata of a service provider of the fixtures gives
// its encryption key as, when it gives no certificate, or else nil.
func interopEncryptionKeyValue(tb testing.TB, sp string) *RSAKeyValue {
	tb.Helper()

	for _, kd := range interopSPMetadata(tb, sp).SPSSODescriptors[0].KeyDescriptors {
		if kd.Use != "encryption" || len(kd.KeyInfo.X509Data.X509Certificates) != 0 {
			continue
		}

		require.Len(tb, kd.KeyInfo.KeyValues, 1, "%s gives its encryption key without a certificate or a KeyValue", sp)
		require.NotNil(tb, kd.KeyInfo.KeyValues[0].RSAKeyValue)

		return kd.KeyInfo.KeyValues[0].RSAKeyValue
	}

	return nil
}

// interopCryptoBinary returns a ds:CryptoBinary without the whitespace that base64 in XML may be wrapped with.
func interopCryptoBinary(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// checkInteropManifest fails unless the manifest was made at interopInstant, no two cases have the same id, every
// case names a profile, service provider and binding that exist, whether or not it is skipped, and at least one case
// runs.
func checkInteropManifest(tb testing.TB, manifest interopManifest) {
	tb.Helper()

	if !manifest.Instant.Equal(interopInstant) {
		tb.Fatalf("manifest instant %s is not %s", manifest.Instant, interopInstant)
	}

	runs, ids := 0, map[string]bool{}

	for _, c := range manifest.Cases {
		if ids[c.ID] {
			tb.Fatalf("duplicate case id %q", c.ID)
		}

		ids[c.ID] = true

		checkInteropCase(tb, c)

		if c.Skip == "" {
			runs++
		}
	}

	if runs == 0 {
		tb.Fatalf("no case of the manifest runs: %d cases, all skipped", len(manifest.Cases))
	}
}

// checkInteropCase fails unless the profile, service provider and binding of a case exist.
func checkInteropCase(tb testing.TB, c interopCase) {
	tb.Helper()

	if _, ok := interopProfiles[c.IDPProfile]; !ok {
		tb.Fatalf("case %s: unknown idp_profile %q", c.ID, c.IDPProfile)
	}

	if _, ok := interopServiceProviders[c.SP]; !ok {
		tb.Fatalf("case %s: unknown sp %q", c.ID, c.SP)
	}

	if _, ok := interopBindings[c.Binding]; !ok {
		tb.Fatalf("case %s: unknown binding %q", c.ID, c.Binding)
	}

	if _, ok := interopEndpoints[c.Endpoint]; (c.Binding == "soap") != ok {
		tb.Fatalf("case %s: endpoint %q on binding %q", c.ID, c.Endpoint, c.Binding)
	}
}

// interopBindings are the bindings a request of the fixtures is sent with, and the HTTP method of each.
var interopBindings = map[string]string{
	"redirect-signed": http.MethodGet,
	"post-signed":     http.MethodPost,
	"soap":            http.MethodPost,
	"uri":             http.MethodGet,
}

// interopEndpoints are the services of the identity provider that a request on the SOAP binding is sent to, by the
// name a case gives them.
var interopEndpoints = map[string]func(idp *IdentityProvider) http.HandlerFunc{
	"attribute":    func(idp *IdentityProvider) http.HandlerFunc { return idp.ServeAttributeQuery },
	"authn-query":  func(idp *IdentityProvider) http.HandlerFunc { return idp.ServeAuthnQuery },
	"assertion-id": func(idp *IdentityProvider) http.HandlerFunc { return idp.ServeAssertionIDRequest },
	"artifact":     func(idp *IdentityProvider) http.HandlerFunc { return idp.ServeArtifactResolution },
}

// readInteropManifest reads testdata/interop/manifest.json.
func readInteropManifest(tb testing.TB) interopManifest {
	tb.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", "interop", "manifest.json"))
	require.NoError(tb, err)

	var manifest interopManifest
	require.NoError(tb, json.Unmarshal(data, &manifest))

	return manifest
}

// A manifest in which nothing runs fails, and so do a skipped case that names what doesn't exist and two cases with
// the same id.
func TestInteropRejectsManifestThatRunsNothing(t *testing.T) {
	runnable := interopCase{ID: "runs", SP: "sp-rsa", IDPProfile: "rsa", Binding: "post-signed"}
	skipped := interopCase{ID: "x", SP: "sp-rsa", IDPProfile: "rsa", Binding: "post-signed", Skip: "declared"}
	unknown := skipped
	unknown.IDPProfile = "nope"

	for name, tc := range map[string]struct {
		cases []interopCase
		want  string
	}{
		"every case skipped":   {[]interopCase{skipped}, "all skipped"},
		"skipped unknown name": {[]interopCase{runnable, unknown}, `unknown idp_profile "nope"`},
		"duplicate id":         {[]interopCase{runnable, runnable}, `duplicate case id "runs"`},
	} {
		t.Run(name, func(t *testing.T) {
			tb := &fatalRecorder{TB: t}

			done := make(chan struct{})

			go func() {
				defer close(done)

				checkInteropManifest(tb, interopManifest{Instant: interopInstant, Cases: tc.cases})
			}()

			<-done

			assert.Contains(t, tb.fatal, tc.want)
		})
	}
}
