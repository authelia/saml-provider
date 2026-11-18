package saml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
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
	kwAES128    = "http://www.w3.org/2001/04/xmlenc#kw-aes128"
	kwAES192    = "http://www.w3.org/2001/04/xmlenc#kw-aes192"
	kwAES256    = "http://www.w3.org/2001/04/xmlenc#kw-aes256"
	kwTripleDES = "http://www.w3.org/2001/04/xmlenc#kw-tripledes"
)

// ecdhKey is the elliptic curve key of a service provider that is encrypted to by ECDH-ES, and its certificate,
// which has no KeyUsage extension.
var ecdhKey = sync.OnceValues(func() (*ecdsa.PrivateKey, *x509.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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

// ecdhNegotiatedAssertion makes an assertion for a service provider whose elliptic curve encryption key lists
// methods, and returns the EncryptedData of the assertion.
func ecdhNegotiatedAssertion(t *testing.T, configure func(*IdentityProvider), issuance *ServiceProviderIssuance, methods ...EncryptionMethod) (*etree.Element, error) {
	t.Helper()

	_, cert := ecdhKey()

	test := NewIdentityProviderTest(t, applyKey)
	if configure != nil {
		configure(&test.IDP)
	}

	if issuance != nil {
		issuanceFor(test, *issuance)
	}

	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	assert.NilError(t, err)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: sessionFor, NameIDFormat: string(EmailAddressNameIDFormat)}))

	descriptor := KeyDescriptor{Use: "encryption", EncryptionMethods: methods}
	descriptor.KeyInfo.X509Data.X509Certificates = []X509Certificate{{Data: base64.StdEncoding.EncodeToString(cert.Raw)}}

	req.SPSSODescriptor.KeyDescriptors = []KeyDescriptor{descriptor}
	if err := req.MakeAssertionEl(); err != nil {
		assert.Check(t, req.AssertionEl == nil, "no assertion may be sent when negotiation fails")

		return nil, err
	}

	assert.Check(t, is.Equal("EncryptedAssertion", req.AssertionEl.Tag))

	encryptedData := req.AssertionEl.FindElement("./EncryptedData")
	assert.Assert(t, encryptedData != nil)

	return encryptedData, nil
}

// checkECDHNegotiated checks that the assertion was encrypted with content, by ECDH-ES with ConcatKDF and SHA-256,
// with keyWrap, and that the private key of the service provider decrypts it.
func checkECDHNegotiated(t *testing.T, encryptedData *etree.Element, content, keyWrap string) {
	t.Helper()

	assert.Check(t, is.Equal(encryptedData.FindElement("./EncryptionMethod").SelectAttrValue("Algorithm", ""), content))

	encryptedKey := encryptedData.FindElement("./KeyInfo/EncryptedKey")
	assert.Assert(t, encryptedKey != nil)
	assert.Check(t, is.Equal(encryptedKey.FindElement("./EncryptionMethod").SelectAttrValue("Algorithm", ""), keyWrap))
	assert.Check(t, encryptedKey.SelectAttr("Recipient") == nil, "the assertion is not encrypted to a named recipient")

	agreement := encryptedKey.FindElement("./KeyInfo/AgreementMethod")
	assert.Assert(t, agreement != nil)
	assert.Check(t, is.Equal(agreement.SelectAttrValue("Algorithm", ""), ecdhES))
	assert.Check(t, is.Equal(agreement.FindElement("./KeyDerivationMethod/ConcatKDFParams/DigestMethod").SelectAttrValue("Algorithm", ""), digestSHA256))

	key, _ := ecdhKey()

	plaintext, err := xmlenc.Decrypt(key, encryptedData)
	assert.NilError(t, err)
	assert.Check(t, strings.Contains(string(plaintext), sessionFor))
}

func TestIDPNegotiatesECDHWithServiceProvider(t *testing.T) {
	for name, tc := range map[string]struct {
		methods          []EncryptionMethod
		content, keyWrap string
	}{
		"nothing listed":                    {nil, aes128GCM, kwAES256},
		"key agreement listed":              {[]EncryptionMethod{method(ecdhES)}, aes128GCM, kwAES256},
		"key wrap listed":                   {[]EncryptionMethod{method(kwAES128)}, aes128GCM, kwAES128},
		"everything listed":                 {[]EncryptionMethod{method(aes256GCM), method(ecdhES), method(kwAES192)}, aes256GCM, kwAES192},
		"first key wrap that is allowed":    {[]EncryptionMethod{method(kwTripleDES), method(kwAES128), method(kwAES256)}, aes128GCM, kwAES128},
		"key agreement among transports":    {[]EncryptionMethod{method(rsaOAEP), method(ecdhES)}, aes128GCM, kwAES256},
		"key size of the key wrap":          {[]EncryptionMethod{{Algorithm: kwAES256, KeySize: 256}}, aes128GCM, kwAES256},
		"content and key wrap in any order": {[]EncryptionMethod{method(kwAES128), method(aes256CBC)}, aes256CBC, kwAES128},
	} {
		t.Run(name, func(t *testing.T) {
			encryptedData, err := ecdhNegotiatedAssertion(t, nil, nil, tc.methods...)
			assert.NilError(t, err)
			checkECDHNegotiated(t, encryptedData, tc.content, tc.keyWrap)
		})
	}
}

func TestIDPRefusesECDHWithAnAlgorithmTheServiceProviderDoesNotList(t *testing.T) {
	for name, tc := range map[string]struct {
		methods []EncryptionMethod
		err     string
	}{
		"only key transport":         {[]EncryptionMethod{method(rsaOAEP)}, "lists no key agreement algorithm"},
		"only an unsupported wrap":   {[]EncryptionMethod{method(kwTripleDES)}, "lists no key wrap algorithm"},
		"another key size of a wrap": {[]EncryptionMethod{{Algorithm: kwAES256, KeySize: 128}}, "lists no key wrap algorithm"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ecdhNegotiatedAssertion(t, nil, nil, tc.methods...)
			assert.Check(t, is.ErrorContains(err, tc.err))
		})
	}
}

func TestIDPECDHConfiguration(t *testing.T) {
	// KeyWrapMethods restricts and orders the key wraps.
	encryptedData, err := ecdhNegotiatedAssertion(t, func(idp *IdentityProvider) { idp.KeyWrapMethods = []string{kwAES128, kwAES256} }, nil)
	assert.NilError(t, err)
	checkECDHNegotiated(t, encryptedData, aes128GCM, kwAES128)

	_, err = ecdhNegotiatedAssertion(t, func(idp *IdentityProvider) { idp.KeyWrapMethods = []string{kwAES128} }, nil, method(kwAES256))
	assert.Check(t, is.ErrorContains(err, "lists no key wrap algorithm"))

	_, err = ecdhNegotiatedAssertion(t, func(idp *IdentityProvider) { idp.KeyWrapMethods = []string{kwTripleDES} }, nil)
	assert.Check(t, is.ErrorContains(err, "IdentityProvider.KeyWrapMethods"))

	// KeyTransportMethods and KeyTransportDigestMethods are for RSA, and don't restrict ECDH-ES.
	encryptedData, err = ecdhNegotiatedAssertion(t, func(idp *IdentityProvider) {
		idp.KeyTransportMethods = []string{rsaOAEP11}
		idp.KeyTransportDigestMethods = []string{digestSHA512}
	}, nil)
	assert.NilError(t, err)
	checkECDHNegotiated(t, encryptedData, aes128GCM, kwAES256)

	// ContentEncryptionMethods applies as it does for RSA.
	encryptedData, err = ecdhNegotiatedAssertion(t, func(idp *IdentityProvider) { idp.ContentEncryptionMethods = []string{aes256CBC} }, nil)
	assert.NilError(t, err)
	checkECDHNegotiated(t, encryptedData, aes256CBC, kwAES256)
}

func TestIssuanceChoosesECDH(t *testing.T) {
	// What the policy chooses is used whatever the key lists.
	encryptedData, err := ecdhNegotiatedAssertion(t, nil,
		&ServiceProviderIssuance{KeyTransportMethod: ecdhES, KeyWrapMethod: kwAES128, ContentEncryptionMethod: aes256GCM},
		method(kwAES256), method(aes128CBC))
	assert.NilError(t, err)
	checkECDHNegotiated(t, encryptedData, aes256GCM, kwAES128)

	// Without KeyTransportMethod the key agreement is still that of an elliptic curve key.
	encryptedData, err = ecdhNegotiatedAssertion(t, nil, &ServiceProviderIssuance{KeyWrapMethod: kwAES192}, method(rsaOAEP), method(ecdhES))
	assert.NilError(t, err)
	checkECDHNegotiated(t, encryptedData, aes128GCM, kwAES192)

	// A key transport chosen for an elliptic curve key, and ECDH-ES for an RSA key, can't be used.
	_, err = ecdhNegotiatedAssertion(t, nil, &ServiceProviderIssuance{KeyTransportMethod: rsaOAEP})
	assert.Check(t, is.ErrorContains(err, "can't encrypt to an elliptic curve key"))

	test := NewIdentityProviderTest(t, applyKey)
	issuanceFor(test, ServiceProviderIssuance{KeyTransportMethod: ecdhES})

	req := issuanceAssertion(t, test, &Session{ID: "f00d", NameID: "alice"})
	assert.Check(t, is.ErrorContains(req.MakeAssertionEl(), "needs an elliptic curve key"))
	assert.Check(t, req.AssertionEl == nil)

	// The key wrap of the policy is not used for an RSA key, so a policy for every service provider may set it.
	issuanceFor(test, ServiceProviderIssuance{KeyWrapMethod: kwAES128})

	req = issuanceAssertion(t, test, &Session{ID: "f00d", NameID: "alice"})
	assert.NilError(t, req.MakeAssertionEl())
	assert.Check(t, is.Equal(req.AssertionEl.Tag, "EncryptedAssertion"))
	assert.Check(t, req.AssertionEl.FindElement("./EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod") == nil)
}

// An EncryptedID and an EncryptedAttribute are encrypted to an elliptic curve key as an assertion is.
func TestElementEncrypterECDH(t *testing.T) {
	key, cert := ecdhKey()

	policy, err := (&IdentityProvider{}).encryptionPolicy()
	assert.NilError(t, err)

	encrypter, err := policy.encrypterFor(nil, Issuance{}, cert.PublicKey)
	assert.NilError(t, err)

	e := &elementEncrypter{certificate: cert, publicKey: cert.PublicKey, encrypter: encrypter, recipient: "https://sp.example.com/saml2/metadata"}

	encryptedID, err := e.encryptNameID(&testEncryptedNameID)
	assert.NilError(t, err)

	plaintext, err := xmlenc.Decrypt(key, encryptedID.FindElement("./EncryptedData"))
	assert.NilError(t, err)
	assert.Check(t, is.Contains(string(plaintext), ">p-1234</saml:NameID>"))
}

// What the identity provider encrypts to an elliptic curve key, xmlsec1 decrypts.
func TestXMLSec1DecryptsECDHAssertion(t *testing.T) {
	xmlsec1, err := exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("xmlsec1 is not installed")
	}

	key, cert := ecdhKey()

	der, err := x509.MarshalPKCS8PrivateKey(key)
	assert.NilError(t, err)

	dir := t.TempDir()
	keyPath, certPath := filepath.Join(dir, "key.pem"), filepath.Join(dir, "cert.pem")
	assert.NilError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	assert.NilError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600))

	encryptedData, err := ecdhNegotiatedAssertion(t, nil, nil)
	assert.NilError(t, err)

	doc := etree.NewDocument()
	doc.SetRoot(encryptedData)

	path := filepath.Join(dir, "encrypted.xml")
	assert.NilError(t, doc.WriteToFile(path))

	out, err := exec.Command(xmlsec1, "--decrypt", "--enabled-key-data", "agreement-method,enc-key,key-value,key-name,ec,x509",
		"--max-encrypted-key-level", "3", "--lax-key-search", "--privkey-pem", keyPath+","+certPath, path).CombinedOutput()
	assert.NilError(t, err, "xmlsec1: %s", out)
	assert.Check(t, is.Contains(string(out), sessionFor))
	assert.Check(t, !strings.Contains(string(out), "EncryptedData"))
}

// A service provider with an elliptic curve encryption key is sent an EncryptedAssertion by single sign-on, which
// its key decrypts, and whose signature verifies.
func TestIssuanceECDHEndToEnd(t *testing.T) {
	test := issuanceTestIDP(t)

	_, cert := ecdhKey()

	// The RSA key of the service provider stays its signing key, and the elliptic curve key replaces it for
	// encryption.
	issuanceMetadata(test, issuanceUnencrypted, func(descriptor *SPSSODescriptor) {
		descriptor.KeyDescriptors = append(descriptor.KeyDescriptors, KeyDescriptor{
			Use:     "encryption",
			KeyInfo: KeyInfo{X509Data: X509Data{X509Certificates: []X509Certificate{{Data: base64.StdEncoding.EncodeToString(cert.Raw)}}}},
		})
	})

	responseEl, _, _ := issuanceSSO(t, test)

	encryptedData := responseEl.FindElement("./EncryptedAssertion/EncryptedData")
	assert.Assert(t, encryptedData != nil)

	key, _ := ecdhKey()

	plaintext, err := xmlenc.Decrypt(key, encryptedData)
	assert.NilError(t, err)

	assertionDoc := etree.NewDocument()
	assert.NilError(t, assertionDoc.ReadFromBytes(plaintext))
	assert.Check(t, is.Equal(assertionDoc.Root().Tag, "Assertion"))
	assert.NilError(t, test.SP.validateSignature(assertionDoc.Root()))
}
