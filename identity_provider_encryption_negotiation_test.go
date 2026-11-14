package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml/xmlenc"
)

const (
	aes192GCM       = "http://www.w3.org/2009/xmlenc11#aes192-gcm"
	camellia128CBC  = "http://www.w3.org/2001/04/xmldsig-more#camellia128-cbc"
	rsaOAEP11       = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
	rsaPKCS1v15     = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	ecdhES          = "http://www.w3.org/2009/xmlenc11#ECDH-ES"
	digestSHA1      = "http://www.w3.org/2000/09/xmldsig#sha1"
	digestSHA256    = "http://www.w3.org/2001/04/xmlenc#sha256"
	digestSHA512    = "http://www.w3.org/2001/04/xmlenc#sha512"
	digestLegacy256 = "http://www.w3.org/2000/09/xmldsig#sha256"
	digestRIPEMD160 = "http://www.w3.org/2001/04/xmlenc#ripemd160"
	mgf1SHA1        = "http://www.w3.org/2009/xmlenc11#mgf1sha1"
	mgf1SHA224      = "http://www.w3.org/2009/xmlenc11#mgf1sha224"
	mgf1SHA256      = "http://www.w3.org/2009/xmlenc11#mgf1sha256"
	mgf1SHA512      = "http://www.w3.org/2009/xmlenc11#mgf1sha512"
)

var negotiationKey = sync.OnceValues(func() (*rsa.PrivateKey, *x509.Certificate) {
	// RSA-OAEP with SHA-512 needs a key of more than 1024 bits, which is the size of the key of the test SP.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sp.example.com"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Now().Add(100 * 365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return key, cert
})

func method(algorithm string) EncryptionMethod {
	return EncryptionMethod{Algorithm: algorithm}
}

func oaepMethod(algorithm, digest, mgf string) EncryptionMethod {
	m := EncryptionMethod{Algorithm: algorithm}
	if digest != "" {
		m.DigestMethod = &DigestMethod{Algorithm: digest}
	}
	if mgf != "" {
		m.MGF = &MGF{Algorithm: mgf}
	}
	return m
}

// negotiatedAssertion makes an assertion for a service provider whose encryption key lists methods, with the
// identity provider configured by configure, and returns the EncryptedData of the assertion.
func negotiatedAssertion(t *testing.T, configure func(*IdentityProvider), methods ...EncryptionMethod) (*etree.Element, error) {
	t.Helper()
	_, cert := negotiationKey()
	test := NewIdentityProviderTest(t, applyKey)
	if configure != nil {
		configure(&test.IDP)
	}
	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	assert.NilError(t, err)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: sessionFor}))
	descriptor := KeyDescriptor{Use: "encryption", EncryptionMethods: methods}
	descriptor.KeyInfo.X509Data.X509Certificates = []X509Certificate{{Data: base64.StdEncoding.EncodeToString(cert.Raw)}}
	req.SPSSODescriptor.KeyDescriptors = []KeyDescriptor{descriptor}
	if err := req.MakeAssertionEl(); err != nil {
		assert.Check(t, req.AssertionEl == nil, "no assertion may be sent when negotiation fails")
		return nil, err
	}

	doc := etree.NewDocument()
	doc.SetRoot(req.AssertionEl)
	serialized, err := doc.WriteToBytes()
	assert.NilError(t, err)
	parsed := etree.NewDocument()
	assert.NilError(t, parsed.ReadFromBytes(serialized))
	assert.Check(t, is.Equal("EncryptedAssertion", parsed.Root().Tag))
	encryptedData := parsed.Root().FindElement("./EncryptedData")
	assert.Assert(t, encryptedData != nil)
	return encryptedData, nil
}

// negotiated is what an encrypted assertion was encrypted with.
type negotiated struct {
	content      string
	keyTransport string
	digest       string
	mgf          string
}

// checkNegotiated checks that the assertion was encrypted with want, and that it decrypts both with the
// decrypter of this library and with an RSA-OAEP of the parameters the specifications define for what it states.
func checkNegotiated(t *testing.T, encryptedData *etree.Element, want negotiated) {
	t.Helper()
	key, _ := negotiationKey()
	keyMethod := encryptedData.FindElement("./KeyInfo/EncryptedKey/EncryptionMethod")
	assert.Assert(t, keyMethod != nil)
	got := negotiated{
		content:      encryptedData.FindElement("./EncryptionMethod").SelectAttrValue("Algorithm", ""),
		keyTransport: keyMethod.SelectAttrValue("Algorithm", ""),
	}
	if el := keyMethod.FindElement("./DigestMethod"); el != nil {
		got.digest = el.SelectAttrValue("Algorithm", "")
	}
	if el := keyMethod.FindElement("./MGF"); el != nil {
		assert.Check(t, is.Equal("http://www.w3.org/2009/xmlenc11#", el.NamespaceURI()))
		got.mgf = el.SelectAttrValue("Algorithm", "")
	}
	assert.Check(t, is.Equal(want, got))

	// RSA-OAEP-MGF1P always uses MGF1 with SHA-1 (XML Encryption §5.4.2), and XML Encryption 1.1 RSA-OAEP the one
	// its MGF names (§5.5.2), so check the key transport against crypto/rsa directly as well.
	hashes := map[string]crypto.Hash{digestSHA1: crypto.SHA1, digestSHA256: crypto.SHA256, digestSHA512: crypto.SHA512,
		mgf1SHA1: crypto.SHA1, mgf1SHA256: crypto.SHA256, mgf1SHA512: crypto.SHA512}
	mgfHash := crypto.SHA1
	if want.mgf != "" {
		mgfHash = hashes[want.mgf]
	}
	value := encryptedData.FindElement("./KeyInfo/EncryptedKey/CipherData/CipherValue")
	assert.Assert(t, value != nil)
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value.Text()))
	assert.NilError(t, err)
	_, err = key.Decrypt(nil, ciphertext, &rsa.OAEPOptions{Hash: hashes[want.digest], MGFHash: mgfHash})
	assert.Check(t, err, "the key transport must be what the EncryptedKey states")

	plaintext, err := xmlenc.Decrypt(key, encryptedData)
	assert.NilError(t, err)
	assert.Check(t, strings.Contains(string(plaintext), sessionFor))
}

func TestIDPNegotiatesEncryptionWithServiceProvider(t *testing.T) {
	defaults := negotiated{content: aes128CBC, keyTransport: rsaOAEP, digest: digestSHA1}
	with := func(change func(*negotiated)) negotiated {
		n := defaults
		change(&n)
		return n
	}

	for _, tc := range []struct {
		name    string
		methods []EncryptionMethod
		want    negotiated
	}{
		{"nothing listed", nil, defaults},
		{"only content listed", []EncryptionMethod{method(aes256CBC)}, with(func(n *negotiated) { n.content = aes256CBC })},
		{"only key transport listed", []EncryptionMethod{method(rsaOAEP)}, defaults},
		{"aes-256-gcm only", []EncryptionMethod{method(aes256GCM)}, with(func(n *negotiated) { n.content = aes256GCM })},
		{"aes-192-gcm preferred", []EncryptionMethod{method(aes192GCM), method(aes128CBC)}, with(func(n *negotiated) { n.content = aes192GCM })},
		{"unsupported content skipped", []EncryptionMethod{method(tripleDES), method(camellia128CBC), method(aes128GCM)}, with(func(n *negotiated) { n.content = aes128GCM })},
		{"unrecognised algorithm ignored", []EncryptionMethod{method("urn:example:unknown"), method(rsaOAEP)}, defaults},
		{"key size that cannot be skipped", []EncryptionMethod{{Algorithm: aes256GCM, KeySize: 128}, method(aes192GCM)}, with(func(n *negotiated) { n.content = aes192GCM })},
		{"key size that matches", []EncryptionMethod{{Algorithm: aes256GCM, KeySize: 256}}, with(func(n *negotiated) { n.content = aes256GCM })},
		{"mgf1p with sha-256", []EncryptionMethod{oaepMethod(rsaOAEP, digestSHA256, "")}, with(func(n *negotiated) { n.digest = digestSHA256 })},
		{"mgf1p with sha-512", []EncryptionMethod{oaepMethod(rsaOAEP, digestSHA512, "")}, with(func(n *negotiated) { n.digest = digestSHA512 })},
		{"mgf1p with explicit sha-1", []EncryptionMethod{oaepMethod(rsaOAEP, digestSHA1, "")}, defaults},
		{"legacy digest identifier written as standard", []EncryptionMethod{oaepMethod(rsaOAEP, digestLegacy256, "")}, with(func(n *negotiated) { n.digest = digestSHA256 })},
		{"unsupported digest skipped", []EncryptionMethod{oaepMethod(rsaOAEP, digestRIPEMD160, ""), oaepMethod(rsaOAEP, digestSHA256, "")}, with(func(n *negotiated) { n.digest = digestSHA256 })},
		{"pkcs1 v1.5 skipped", []EncryptionMethod{method(rsaPKCS1v15), method(rsaOAEP)}, defaults},
		{"xmlenc11 rsa-oaep defaults", []EncryptionMethod{method(rsaOAEP11)}, with(func(n *negotiated) { n.keyTransport, n.mgf = rsaOAEP11, mgf1SHA1 })},
		{"xmlenc11 rsa-oaep preferred", []EncryptionMethod{method(rsaOAEP11), method(rsaOAEP)}, with(func(n *negotiated) { n.keyTransport, n.mgf = rsaOAEP11, mgf1SHA1 })},
		{"xmlenc11 rsa-oaep with sha-256", []EncryptionMethod{oaepMethod(rsaOAEP11, digestSHA256, mgf1SHA256)}, with(func(n *negotiated) { n.keyTransport, n.digest, n.mgf = rsaOAEP11, digestSHA256, mgf1SHA256 })},
		{"xmlenc11 rsa-oaep with distinct mgf", []EncryptionMethod{oaepMethod(rsaOAEP11, digestSHA512, mgf1SHA1)}, with(func(n *negotiated) { n.keyTransport, n.digest, n.mgf = rsaOAEP11, digestSHA512, mgf1SHA1 })},
		{"xmlenc11 rsa-oaep with digest only", []EncryptionMethod{oaepMethod(rsaOAEP11, digestSHA256, "")}, with(func(n *negotiated) { n.keyTransport, n.digest, n.mgf = rsaOAEP11, digestSHA256, mgf1SHA1 })},
		{"unsupported mgf skipped", []EncryptionMethod{oaepMethod(rsaOAEP11, digestSHA256, mgf1SHA224), method(rsaOAEP)}, defaults},
		{"oaep label skipped", []EncryptionMethod{{Algorithm: rsaOAEP11, OAEPParams: "9lWu3Q=="}, method(rsaOAEP)}, defaults},
		{"both listed", []EncryptionMethod{method(aes256GCM), oaepMethod(rsaOAEP11, digestSHA256, mgf1SHA256), method(aes128CBC), method(rsaOAEP)}, negotiated{content: aes256GCM, keyTransport: rsaOAEP11, digest: digestSHA256, mgf: mgf1SHA256}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el, err := negotiatedAssertion(t, nil, tc.methods...)
			assert.NilError(t, err)
			checkNegotiated(t, el, tc.want)
		})
	}
}

func TestIDPRefusesToEncryptWithAnAlgorithmTheServiceProviderDoesNotList(t *testing.T) {
	for _, tc := range []struct {
		name    string
		methods []EncryptionMethod
		err     string
	}{
		{"only 3des", []EncryptionMethod{method(tripleDES), method(rsaOAEP)}, "content encryption"},
		{"only camellia", []EncryptionMethod{method(camellia128CBC)}, "content encryption"},
		{"key size that cannot be", []EncryptionMethod{{Algorithm: aes256GCM, KeySize: 128}}, "content encryption"},
		{"only pkcs1 v1.5", []EncryptionMethod{method(aes128CBC), method(rsaPKCS1v15)}, "key transport"},
		{"only key agreement", []EncryptionMethod{method(ecdhES)}, "key transport"},
		{"only an unsupported digest", []EncryptionMethod{oaepMethod(rsaOAEP, digestRIPEMD160, "")}, "key transport"},
		{"only an unsupported mgf", []EncryptionMethod{oaepMethod(rsaOAEP11, "", mgf1SHA224)}, "key transport"},
		{"mgf1p with another mgf", []EncryptionMethod{oaepMethod(rsaOAEP, "", mgf1SHA256)}, "key transport"},
		{"only an oaep label", []EncryptionMethod{{Algorithm: rsaOAEP, OAEPParams: "9lWu3Q=="}}, "key transport"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := negotiatedAssertion(t, nil, tc.methods...)
			assert.Check(t, is.ErrorContains(err, tc.err))
			assert.Check(t, is.ErrorContains(err, "https://sp.example.com/saml2/metadata"))
		})
	}
}

func TestIDPEncryptionAlgorithmConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*IdentityProvider)
		methods   []EncryptionMethod
		want      negotiated
		err       string
	}{
		{
			name:      "first content method is the default",
			configure: func(idp *IdentityProvider) { idp.ContentEncryptionMethods = []string{aes256GCM, aes128CBC} },
			want:      negotiated{content: aes256GCM, keyTransport: rsaOAEP, digest: digestSHA1},
		},
		{
			name:      "service provider order wins",
			configure: func(idp *IdentityProvider) { idp.ContentEncryptionMethods = []string{aes128GCM, aes256GCM} },
			methods:   []EncryptionMethod{method(aes256GCM), method(aes128GCM)},
			want:      negotiated{content: aes256GCM, keyTransport: rsaOAEP, digest: digestSHA1},
		},
		{
			name:      "content method not allowed",
			configure: func(idp *IdentityProvider) { idp.ContentEncryptionMethods = []string{aes256GCM} },
			methods:   []EncryptionMethod{method(aes128CBC)},
			err:       "content encryption",
		},
		{
			name:      "empty list means the defaults",
			configure: func(idp *IdentityProvider) { idp.ContentEncryptionMethods = []string{} },
			want:      negotiated{content: aes128CBC, keyTransport: rsaOAEP, digest: digestSHA1},
		},
		{
			name:      "first key transport is the default",
			configure: func(idp *IdentityProvider) { idp.KeyTransportMethods = []string{rsaOAEP11} },
			want:      negotiated{content: aes128CBC, keyTransport: rsaOAEP11, digest: digestSHA1, mgf: mgf1SHA1},
		},
		{
			name:      "key transport not allowed",
			configure: func(idp *IdentityProvider) { idp.KeyTransportMethods = []string{rsaOAEP11} },
			methods:   []EncryptionMethod{method(rsaOAEP)},
			err:       "key transport",
		},
		{
			name:      "first digest is the default",
			configure: func(idp *IdentityProvider) { idp.KeyTransportDigestMethods = []string{digestSHA256} },
			want:      negotiated{content: aes128CBC, keyTransport: rsaOAEP, digest: digestSHA256},
		},
		{
			name:      "first digest is the default mgf",
			configure: func(idp *IdentityProvider) { idp.KeyTransportDigestMethods = []string{digestSHA256} },
			methods:   []EncryptionMethod{method(rsaOAEP11)},
			want:      negotiated{content: aes128CBC, keyTransport: rsaOAEP11, digest: digestSHA256, mgf: mgf1SHA256},
		},
		{
			name:      "legacy digest identifier in configuration",
			configure: func(idp *IdentityProvider) { idp.KeyTransportDigestMethods = []string{digestLegacy256} },
			want:      negotiated{content: aes128CBC, keyTransport: rsaOAEP, digest: digestSHA256},
		},
		{
			name:      "digest not allowed",
			configure: func(idp *IdentityProvider) { idp.KeyTransportDigestMethods = []string{digestSHA256} },
			methods:   []EncryptionMethod{oaepMethod(rsaOAEP, digestSHA1, "")},
			err:       "key transport",
		},
		{
			name:      "mgf not allowed",
			configure: func(idp *IdentityProvider) { idp.KeyTransportDigestMethods = []string{digestSHA256} },
			methods:   []EncryptionMethod{oaepMethod(rsaOAEP11, digestSHA256, mgf1SHA1)},
			err:       "key transport",
		},
		{
			name:      "unsupported content method configured",
			configure: func(idp *IdentityProvider) { idp.ContentEncryptionMethods = []string{tripleDES} },
			err:       "ContentEncryptionMethods",
		},
		{
			name:      "unsupported key transport configured",
			configure: func(idp *IdentityProvider) { idp.KeyTransportMethods = []string{rsaPKCS1v15} },
			err:       "KeyTransportMethods",
		},
		{
			name:      "unsupported digest configured",
			configure: func(idp *IdentityProvider) { idp.KeyTransportDigestMethods = []string{digestRIPEMD160} },
			err:       "KeyTransportDigestMethods",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el, err := negotiatedAssertion(t, tc.configure, tc.methods...)
			if tc.err != "" {
				assert.Check(t, is.ErrorContains(err, tc.err))
				return
			}
			assert.NilError(t, err)
			checkNegotiated(t, el, tc.want)
		})
	}
}

func TestIDPEncryptionNegotiationLeavesPlaintextServiceProvidersAlone(t *testing.T) {
	// A service provider with no encryption key is sent a signed assertion in plaintext, which the configuration
	// of encryption algorithms must not change.
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.ContentEncryptionMethods = []string{tripleDES}
	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	assert.NilError(t, err)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: sessionFor}))
	req.SPSSODescriptor.KeyDescriptors = nil
	req.ServiceProviderMetadata = &EntityDescriptor{
		EntityID:         req.ServiceProviderMetadata.EntityID,
		SPSSODescriptors: []SPSSODescriptor{*req.SPSSODescriptor},
	}
	assert.NilError(t, req.MakeAssertionEl())
	assert.Check(t, is.Equal("Assertion", req.AssertionEl.Tag))
}

func TestSPOfThisLibraryNegotiatesWithIDPOfThisLibrary(t *testing.T) {
	key, cert := negotiationKey()
	sp := ServiceProvider{
		Key:         key,
		Certificate: cert,
		MetadataURL: mustParseURL("https://sp.example.com/saml2/metadata"),
		AcsURL:      mustParseURL("https://sp.example.com/saml2/acs"),
	}
	el, err := negotiatedAssertion(t, nil, sp.Metadata().SPSSODescriptors[0].KeyDescriptors[0].EncryptionMethods...)
	assert.NilError(t, err)
	checkNegotiated(t, el, negotiated{content: aes128GCM, keyTransport: rsaOAEP, digest: digestSHA1})
}
