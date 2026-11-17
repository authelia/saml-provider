package saml

import (
	"crypto/x509"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"

	"authelia.com/provider/saml/internal/dsig"
)

// metadataSigningTest returns an identity provider which signs with negotiationKey, whose certificate is valid
// now, and a verifier which trusts it.
func metadataSigningTest(t *testing.T) (*IdentityProviderTest, *MetadataVerifier) {
	t.Helper()

	test := NewIdentityProviderTest(t)
	key, cert := negotiationKey()
	test.IDP.Key = key
	test.IDP.Certificate = cert

	return test, &MetadataVerifier{Certificates: []*x509.Certificate{cert}}
}

// signMetadataXML signs the root element of data with negotiationKey, places the signature as its first child, and
// returns the document.
func signMetadataXML(t *testing.T, data string) string {
	t.Helper()

	key, cert := negotiationKey()

	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(data))

	signingContext, err := dsig.NewSigningContext(key, [][]byte{cert.Raw})
	assert.NilError(t, err)

	signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	signed, err := signingContext.SignEnveloped(doc.Root())
	assert.NilError(t, err)

	last := len(signed.Child) - 1
	signature := signed.Child[last]
	signed.RemoveChildAt(last)
	signed.InsertChildAt(0, signature)
	doc.SetRoot(signed)

	out, err := doc.WriteToString()
	assert.NilError(t, err)

	return out
}

const testAggregate = `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="agg" validUntil="2015-12-10T00:00:00Z">` +
	`<md:EntityDescriptor entityID="https://idp.example.org/"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
	`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.org/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>` +
	`<md:EntityDescriptor entityID="https://sp1.example.org/" validUntil="2016-01-01T00:00:00Z"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
	`<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp1.example.org/acs" index="0"/></md:SPSSODescriptor></md:EntityDescriptor>` +
	`<md:EntitiesDescriptor validUntil="2015-12-05T00:00:00Z">` +
	`<md:EntityDescriptor entityID="https://sp2.example.org/" validUntil="2015-12-04T00:00:00Z"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
	`<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp2.example.org/acs" index="0"/></md:SPSSODescriptor></md:EntityDescriptor>` +
	`<md:EntityDescriptor entityID="https://sp3.example.org/"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
	`<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp3.example.org/acs" index="0"/></md:SPSSODescriptor></md:EntityDescriptor>` +
	`</md:EntitiesDescriptor></md:EntitiesDescriptor>`

func TestSignedMetadataIsVerified(t *testing.T) {
	test, verifier := metadataSigningTest(t)

	signed, err := test.IDP.SignedMetadata()
	assert.NilError(t, err)

	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(signed))

	// SAMLMeta §3.1.2: the signature refers to the ID of the EntityDescriptor, and is its first child (the schema).
	id := doc.Root().SelectAttrValue("ID", "")
	assert.Check(t, strings.HasPrefix(id, "id-"))
	assert.Check(t, is.Equal(dsig.SignatureTag, doc.Root().ChildElements()[0].Tag))
	assert.Check(t, is.Equal("#"+id, doc.Root().FindElement("./Signature/SignedInfo/Reference").SelectAttrValue("URI", "")))

	verified, err := verifier.Verify(signed)
	assert.NilError(t, err)

	var metadata EntityDescriptor
	assert.NilError(t, xml.Unmarshal(verified, &metadata))

	expected := test.IDP.Metadata()

	assert.Check(t, is.Equal(id, metadata.ID))
	assert.Check(t, is.Equal(expected.EntityID, metadata.EntityID))
	assert.Check(t, is.Equal(expected.ValidUntil, metadata.ValidUntil))
	assert.Check(t, is.DeepEqual(expected.IDPSSODescriptors[0].SingleSignOnServices, metadata.IDPSSODescriptors[0].SingleSignOnServices))
	assert.Check(t, is.Equal(expected.IDPSSODescriptors[0].KeyDescriptors[0].KeyInfo.X509Data.X509Certificates[0].Data,
		metadata.IDPSSODescriptors[0].KeyDescriptors[0].KeyInfo.X509Data.X509Certificates[0].Data))
}

func TestSignedMetadataIDIsFreshForEachCall(t *testing.T) {
	test, _ := metadataSigningTest(t)

	first, err := test.IDP.SignedMetadata()
	assert.NilError(t, err)
	second, err := test.IDP.SignedMetadata()
	assert.NilError(t, err)

	idOf := func(data []byte) string {
		doc := etree.NewDocument()
		assert.NilError(t, doc.ReadFromBytes(data))

		return doc.Root().SelectAttrValue("ID", "")
	}

	assert.Check(t, idOf(first) != idOf(second))
}

func TestServeMetadataIsSigned(t *testing.T) {
	test, verifier := metadataSigningTest(t)

	w := httptest.NewRecorder()
	test.IDP.ServeMetadata(w, httptest.NewRequest(http.MethodGet, test.IDP.MetadataURL.String(), nil))

	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("application/samlmetadata+xml", w.Header().Get("Content-Type")))

	_, err := verifier.Verify(w.Body.Bytes())
	assert.Check(t, err)
}

func TestServeMetadataFailsWithoutAKeyToSignWith(t *testing.T) {
	test, _ := metadataSigningTest(t)
	test.IDP.Key = struct{}{}

	w := httptest.NewRecorder()
	test.IDP.ServeMetadata(w, httptest.NewRequest(http.MethodGet, test.IDP.MetadataURL.String(), nil))

	assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
	assert.Check(t, !strings.Contains(w.Body.String(), "EntityDescriptor"))
}

func TestMetadataVerifierRefuses(t *testing.T) {
	test, verifier := metadataSigningTest(t)

	signed, err := test.IDP.SignedMetadata()
	assert.NilError(t, err)

	other := mustParseCertificate(golden.Get(t, "sp_cert.pem"))

	unsignedEntity := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ID="e" entityID="https://sp.example.org/"/>`

	testCases := map[string]struct {
		data     string
		verifier *MetadataVerifier
		err      string
	}{
		"tampered content": {
			data: strings.Replace(string(signed), "https://idp.example.com/saml/sso", "https://evil.example.com/sso", 1),
			err:  "cannot verify the signature of the metadata",
		},
		"another certificate": {
			data:     string(signed),
			verifier: &MetadataVerifier{Certificates: []*x509.Certificate{other}},
			err:      "cannot verify the signature of the metadata",
		},
		"no certificates": {
			data:     string(signed),
			verifier: &MetadataVerifier{},
			err:      "no certificates to verify the metadata with",
		},
		"unsigned": {
			data: unsignedEntity,
			err:  "metadata is not signed",
		},
		"no ID": {
			data: signMetadataXML(t, `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.org/"/>`),
			err:  "signed metadata must have an ID",
		},
		"two signatures": {
			data: strings.Replace(signMetadataXML(t, unsignedEntity), "<ds:Signature", "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/><ds:Signature", 1),
			err:  "metadata has more than one signature",
		},
		"reference to the document": {
			data: strings.Replace(signMetadataXML(t, unsignedEntity), `URI="#e"`, `URI=""`, 1),
			err:  "the signature of the metadata must have a single reference to its ID",
		},
		"signed element wrapped in an unsigned group": {
			data: `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ID="g">` + string(signed) + `</EntitiesDescriptor>`,
			err:  "metadata is not signed",
		},
		"not metadata": {
			data: signMetadataXML(t, `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="r"/>`),
			err:  "metadata must be an EntityDescriptor or an EntitiesDescriptor",
		},
		"expired": {
			data: signMetadataXML(t, `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ID="e" entityID="https://sp.example.org/" validUntil="2015-12-01T01:57:09Z"/>`),
			err:  "signed metadata has expired",
		},
		"no validUntil with MaxValidity": {
			data:     signMetadataXML(t, unsignedEntity),
			verifier: &MetadataVerifier{Certificates: verifier.Certificates, MaxValidity: 14 * 24 * time.Hour},
			err:      "signed metadata has no validUntil",
		},
		"validUntil beyond MaxValidity": {
			data:     signMetadataXML(t, `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ID="e" entityID="https://sp.example.org/" validUntil="2016-12-01T00:00:00Z"/>`),
			verifier: &MetadataVerifier{Certificates: verifier.Certificates, MaxValidity: 14 * 24 * time.Hour},
			err:      "signed metadata is valid for longer than 336h0m0s",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			v := verifier
			if tc.verifier != nil {
				v = tc.verifier
			}

			_, err := v.Verify([]byte(tc.data))
			assert.Check(t, is.ErrorContains(err, tc.err))
		})
	}
}

func TestMetadataVerifierAcceptsValidUntilWithinMaxValidity(t *testing.T) {
	_, verifier := metadataSigningTest(t)
	verifier.MaxValidity = 14 * 24 * time.Hour

	_, err := verifier.Verify([]byte(signMetadataXML(t, testAggregate)))
	assert.Check(t, err)
}

// Only the content that the signature covers is returned, so a comment outside the root is dropped.
func TestMetadataVerifierReturnsTheSignedContent(t *testing.T) {
	_, verifier := metadataSigningTest(t)

	verified, err := verifier.Verify([]byte(signMetadataXML(t, testAggregate) + "<!-- unsigned -->"))
	assert.NilError(t, err)
	assert.Check(t, !strings.Contains(string(verified), "unsigned"))
	assert.Check(t, !strings.Contains(string(verified), "Signature"))
}

func TestParseServiceProvidersMetadataOfAVerifiedAggregate(t *testing.T) {
	_, verifier := metadataSigningTest(t)

	verified, err := verifier.Verify([]byte(signMetadataXML(t, testAggregate)))
	assert.NilError(t, err)

	entities, err := ParseServiceProvidersMetadata(verified)
	assert.NilError(t, err)

	ids := make([]string, 0, len(entities))
	validUntil := map[string]time.Time{}

	for _, entity := range entities {
		ids = append(ids, entity.EntityID)
		validUntil[entity.EntityID] = entity.ValidUntil
	}

	// The identity provider is skipped, and an entity expires with the earliest group around it (SAMLMeta §2.3.1).
	assert.Check(t, is.DeepEqual([]string{"https://sp1.example.org/", "https://sp2.example.org/", "https://sp3.example.org/"}, ids))
	assert.Check(t, is.Equal(time.Date(2015, 12, 10, 0, 0, 0, 0, time.UTC), validUntil["https://sp1.example.org/"].UTC()))
	assert.Check(t, is.Equal(time.Date(2015, 12, 4, 0, 0, 0, 0, time.UTC), validUntil["https://sp2.example.org/"].UTC()))
	assert.Check(t, is.Equal(time.Date(2015, 12, 5, 0, 0, 0, 0, time.UTC), validUntil["https://sp3.example.org/"].UTC()))

	first, err := ParseServiceProviderMetadata(verified)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("https://sp1.example.org/", first.EntityID))
}

func TestParseServiceProvidersMetadataRefuses(t *testing.T) {
	_, err := ParseServiceProvidersMetadata([]byte(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><md:EntityDescriptor entityID="https://idp.example.org/"/></md:EntitiesDescriptor>`))
	assert.Check(t, is.ErrorContains(err, "metadata contained no service provider metadata"))

	_, err = ParseServiceProvidersMetadata([]byte(`<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol"/>`))
	assert.Check(t, is.ErrorContains(err, "expected element type <EntityDescriptor> or <EntitiesDescriptor> but have <Response>"))

	_, err = ParseServiceProvidersMetadata([]byte(`<EntityDescriptor xmlns="urn:example" entityID="x"/>`))
	assert.Check(t, is.ErrorContains(err, "expected element type"))
}

// xmlsec1Metadata writes data to a file, and returns the path of xmlsec1, of the file, and of negotiationKey and its
// certificate in PEM.
func xmlsec1Metadata(t *testing.T, data []byte) (xmlsec1, path, keyPath, certPath string) {
	t.Helper()

	xmlsec1, keyPath, certPath = xmlsec1Keys(t)

	path = filepath.Join(t.TempDir(), "metadata.xml")
	assert.NilError(t, os.WriteFile(path, data, 0o600))

	return xmlsec1, path, keyPath, certPath
}

// What the identity provider signs, xmlsec1 verifies.
func TestXMLSec1VerifiesSignedMetadata(t *testing.T) {
	test, _ := metadataSigningTest(t)

	signed, err := test.IDP.SignedMetadata()
	assert.NilError(t, err)

	xmlsec1, path, _, certPath := xmlsec1Metadata(t, signed)

	out, err := exec.Command(xmlsec1, "--verify", "--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor",
		"--trusted-pem", certPath, path).CombinedOutput()
	assert.NilError(t, err, "xmlsec1: %s", out)
}

// What xmlsec1 signs, the verifier accepts.
func TestMetadataVerifierAcceptsXMLSec1Signature(t *testing.T) {
	template := strings.Replace(testAggregate, `validUntil="2015-12-10T00:00:00Z">`, `validUntil="2015-12-10T00:00:00Z">`+
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>`+
		`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`+
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>`+
		`<ds:Reference URI="#agg"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>`+
		`<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>`+
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo>`+
		`<ds:SignatureValue/><ds:KeyInfo><ds:X509Data/></ds:KeyInfo></ds:Signature>`, 1)

	xmlsec1, path, keyPath, certPath := xmlsec1Metadata(t, []byte(template))

	signed, err := exec.Command(xmlsec1, "--sign", "--lax-key-search", "--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:metadata:EntitiesDescriptor",
		"--privkey-pem", keyPath+","+certPath, path).CombinedOutput()
	assert.NilError(t, err, "xmlsec1: %s", signed)

	_, verifier := metadataSigningTest(t)

	verified, err := verifier.Verify(signed)
	assert.NilError(t, err)

	entities, err := ParseServiceProvidersMetadata(verified)
	assert.NilError(t, err)
	assert.Check(t, is.Len(entities, 3))

	_, err = verifier.Verify([]byte(strings.Replace(string(signed), "https://sp3.example.org/acs", "https://evil.example.org/acs", 1)))
	assert.Check(t, is.ErrorContains(err, "cannot verify the signature of the metadata"))
}
