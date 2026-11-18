package saml

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/dsig"
	"authelia.com/provider/saml/xmlenc"
)

// The identity provider metadata that pysaml2 built its requests from must be what the identity provider still
// publishes. SAML_INTEROP_UPDATE=1 rewrites it, which generate.sh does before it runs pysaml2.
func TestInteropIDPMetadata(t *testing.T) {
	idp := newInteropIDP(t, "rsa")

	got, err := xml.MarshalIndent(idp.Metadata(), "", "  ")
	require.NoError(t, err)

	path := filepath.Join("testdata", "interop", "idp", "idp-rsa.xml")

	if os.Getenv("SAML_INTEROP_UPDATE") == "1" {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, got, 0o600))
	}

	want, err := os.ReadFile(path)
	require.NoError(t, err, "IdP metadata changed: run testdata/interop/generate.sh")
	assert.Equal(t, string(want), string(got), "IdP metadata changed: run testdata/interop/generate.sh")
}

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
	Expect       interopExpect `json:"expect"`
	Verify       []string      `json:"verify"`
	VerifyWith   string        `json:"verify_with,omitempty"`
	VerifyReason string        `json:"verify_reason,omitempty"`
	Skip         string        `json:"skip,omitempty"`
}

// interopExpect is what the Go replay asserts of the response. It never configures anything.
type interopExpect struct {
	// Outcome is "success" or the URI of the top-level StatusCode.
	Outcome            string `json:"outcome"`
	SignatureMethod    string `json:"signature_method"`
	EncryptedAssertion bool   `json:"encrypted_assertion"`
	NameIDFormat       string `json:"name_id_format"`

	// KeyTransportMethod is the algorithm of the EncryptedKey of an EncryptedAssertion.
	KeyTransportMethod string `json:"key_transport_method,omitempty"`
}

// interopProfile is how the identity provider is set up for a case, which SP metadata can't say.
type interopProfile struct {
	// IDPKey is the name of the key pair in testdata/interop/keys.
	IDPKey string

	// Configure changes the identity provider after the settings every case shares.
	Configure func(idp *IdentityProvider)
}

var interopProfiles = map[string]interopProfile{
	"rsa": {
		IDPKey: "idp-rsa",
		Configure: func(idp *IdentityProvider) {
			idp.IssuancePolicy = DefaultIssuancePolicy{AssertionEncryption: NoAssertionEncryption}
		},
	},
	"rsa-encrypt-assertion": {
		IDPKey: "idp-rsa",
		Configure: func(idp *IdentityProvider) {
			idp.IssuancePolicy = DefaultIssuancePolicy{AssertionEncryption: RequireAssertionEncryption}
		},
	},
}

// interopServiceProviders are the service providers of the fixtures, by the name generate.py gives them.
var interopServiceProviders = map[string]string{
	"sp-rsa": "https://sp-rsa.example.com/saml2/metadata",
	"sp-ec":  "https://sp-ec.example.com/saml2/metadata",
}

// newInteropIDP returns the identity provider of a profile, on clocks stopped at interopInstant.
func newInteropIDP(tb testing.TB, profile string) *IdentityProvider {
	tb.Helper()

	p, ok := interopProfiles[profile]
	if !ok {
		tb.Fatalf("unknown idp_profile %q", profile)

		return nil
	}

	// TimeNow is the clock of the identity provider, and Clock that of the signatures it verifies.
	timeNow, clock := TimeNow, Clock
	TimeNow, Clock = func() time.Time { return interopInstant }, dsig.NewFakeClockAt(interopInstant)

	tb.Cleanup(func() { TimeNow, Clock = timeNow, clock })

	key, cert := interopKey(tb, p.IDPKey)

	idp := &IdentityProvider{
		Key:                     key,
		Certificate:             cert,
		MetadataURL:             mustParseURL("https://idp.example.com/saml/metadata"),
		SSOURL:                  mustParseURL("https://idp.example.com/saml/sso"),
		WantAuthnRequestsSigned: true,
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
		SessionProvider: &mockSessionProvider{
			GetSessionFunc: func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
				return &Session{
					ID:         "interop",
					CreateTime: interopInstant,
					ExpireTime: interopInstant.Add(time.Hour),
					NameID:     "alice",
					UserName:   "alice",
					UserEmail:  "alice@example.com",
				}
			},
		},
	}

	p.Configure(idp)

	return idp
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

var interopResponseInput = regexp.MustCompile(`name="SAMLResponse" value="([^"]*)"`)

// runInteropCase replays the request of a case against the identity provider of its profile, asserts what the case
// expects of the response, and returns the response as the base64 that the browser would post.
func runInteropCase(tb testing.TB, c interopCase) string {
	tb.Helper()

	checkInteropCase(tb, c)

	spMetadata := interopSPMetadata(tb, c.SP)
	idp := newInteropIDP(tb, c.IDPProfile)

	body, err := os.ReadFile(filepath.Join("testdata", "interop", c.Request))
	require.NoError(tb, err)

	var r *http.Request

	switch c.Binding {
	case "redirect-signed":
		r = httptest.NewRequest(http.MethodGet, idp.SSOURL.String()+"?"+string(body), nil)
	case "post-signed":
		r = httptest.NewRequest(http.MethodPost, idp.SSOURL.String(), bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	default:
		tb.Fatalf("unknown binding %q", c.Binding)

		return ""
	}

	w := httptest.NewRecorder()
	idp.ServeSSO(w, r)
	require.Equal(tb, http.StatusOK, w.Code, "%s", w.Body.String())

	match := interopResponseInput.FindStringSubmatch(w.Body.String())
	require.NotNil(tb, match, "no SAMLResponse in %s", w.Body.String())

	encoded := html.UnescapeString(match[1])

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(tb, err)

	doc := etree.NewDocument()
	require.NoError(tb, doc.ReadFromBytes(decoded))

	response := doc.Root()
	require.Equal(tb, "Response", response.Tag)

	outcome := c.Expect.Outcome
	if outcome == "success" {
		outcome = StatusSuccess
	}

	if status := response.FindElement("./Status/StatusCode"); assert.NotNil(tb, status) {
		assert.Equal(tb, outcome, status.SelectAttrValue("Value", ""))
	}

	assert.Equal(tb, c.RequestID, response.SelectAttrValue("InResponseTo", ""))
	assert.Equal(tb, spMetadata.SPSSODescriptors[0].AssertionConsumerServices[0].Location, response.SelectAttrValue("Destination", ""))

	if method := response.FindElement("./Signature/SignedInfo/SignatureMethod"); assert.NotNil(tb, method, "the Response is not signed") {
		assert.Equal(tb, c.Expect.SignatureMethod, method.SelectAttrValue("Algorithm", ""))
	}

	if outcome != StatusSuccess {
		// A Response that reports an error carries no assertion, encrypted or not.
		assert.Nil(tb, response.FindElement("./Assertion"), "an Assertion in an error Response")
		assert.Nil(tb, response.FindElement("./EncryptedAssertion"), "an EncryptedAssertion in an error Response")

		return encoded
	}

	assert.Equal(tb, c.Expect.EncryptedAssertion, response.FindElement("./EncryptedAssertion") != nil, "EncryptedAssertion")

	assertion := response.FindElement("./Assertion")

	if c.Expect.EncryptedAssertion {
		assert.Nil(tb, assertion, "a plaintext Assertion beside the EncryptedAssertion")

		assertion = decryptInteropAssertion(tb, c, response)
	}

	if !assert.NotNil(tb, assertion, "no Assertion") {
		return encoded
	}

	if nameID := assertion.FindElement("./Subject/NameID"); assert.NotNil(tb, nameID) {
		assert.Equal(tb, c.Expect.NameIDFormat, nameID.SelectAttrValue("Format", ""))
		assert.NotEmpty(tb, nameID.Text())
	}

	return encoded
}

// decryptInteropAssertion checks the key transport of the EncryptedAssertion of a Response, and decrypts it with the
// key of the service provider of the case.
func decryptInteropAssertion(tb testing.TB, c interopCase, response *etree.Element) *etree.Element {
	tb.Helper()

	encryptedData := response.FindElement("./EncryptedAssertion/EncryptedData")
	require.NotNil(tb, encryptedData, "no EncryptedData in the EncryptedAssertion")

	if method := encryptedData.FindElement("./KeyInfo/EncryptedKey/EncryptionMethod"); assert.NotNil(tb, method) {
		assert.Equal(tb, c.Expect.KeyTransportMethod, method.SelectAttrValue("Algorithm", ""))
	}

	key, _ := interopKey(tb, c.SP)

	plaintext, err := xmlenc.Decrypt(key, encryptedData)
	require.NoError(tb, err)

	doc := etree.NewDocument()
	require.NoError(tb, doc.ReadFromBytes(plaintext))
	require.Equal(tb, "Assertion", doc.Root().Tag)

	return doc.Root()
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
}

// interopBindings are the bindings a request of the fixtures is sent with, and the HTTP method of each.
var interopBindings = map[string]string{
	"redirect-signed": http.MethodGet,
	"post-signed":     http.MethodPost,
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
