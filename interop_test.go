package saml

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
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
}

// interopEncryptionKeys are the key pairs in testdata/interop/keys that each service provider decrypts with, by its
// name. Every other service provider decrypts with the key pair of its own name.
var interopEncryptionKeys = map[string]string{
	"sp-rsa-negotiate": "sp-rsa",
	"sp-rsa-cbc":       "sp-rsa",
	"sp-rsa-keyvalue":  "sp-rsa",
	"sp-ecdh":          "sp-ec",
	"sp-rsa-mail":      "sp-rsa",
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
				if p.Session != nil {
					return p.Session()
				}

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

	p.Configure(tb, idp)

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

	encoded, response := replayInteropRequest(tb, c)

	checkInteropResponse(tb, c, response)

	if c.Expect.Outcome != "success" && c.Expect.Outcome != StatusSuccess {
		return encoded
	}

	assertion := response.FindElement("./Assertion")

	if c.Expect.EncryptedAssertion {
		assert.Nil(tb, assertion, "a plaintext Assertion beside the EncryptedAssertion")

		assertion = decryptInteropAssertion(tb, c, response)
	}

	if assert.NotNil(tb, assertion, "no Assertion") {
		checkInteropSubject(tb, c, assertion)
		checkInteropEncryptedAttributes(tb, c, assertion)
	}

	return encoded
}

// replayInteropRequest serves the request of a case to the identity provider of its profile, and returns the
// Response, as the base64 the browser would post and as XML.
func replayInteropRequest(tb testing.TB, c interopCase) (string, *etree.Element) {
	tb.Helper()

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

		return "", nil
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
	require.Equal(tb, "Response", doc.Root().Tag)

	return encoded, doc.Root()
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

	acs := interopSPMetadata(tb, c.SP).SPSSODescriptors[0].AssertionConsumerServices
	require.NotEmpty(tb, acs, "%s has no assertion consumer service", c.SP)

	assert.Equal(tb, c.RequestID, response.SelectAttrValue("InResponseTo", ""))
	assert.Equal(tb, acs[0].Location, response.SelectAttrValue("Destination", ""))

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
