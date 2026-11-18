package saml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml/internal/dsig"
)

func TestSPVerifiesIDPSignatureInRawECDSAEncoding(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	assert.NilError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	assert.NilError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)

	test := NewIdentityProviderTest(t)
	test.IDP.Key = nil
	test.IDP.Signer = key
	test.IDP.Certificate = cert
	test.IDP.SignatureMethod = dsig.ECDSASHA384SignatureMethod

	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	assert.NilError(t, err)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice"}))
	assert.NilError(t, req.MakeResponse())

	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)
	serialized, err := doc.WriteToBytes()
	assert.NilError(t, err)

	parsed := etree.NewDocument()
	assert.NilError(t, parsed.ReadFromBytes(serialized))

	value, err := base64.StdEncoding.DecodeString(parsed.Root().FindElement("./Signature/SignatureValue").Text())
	assert.NilError(t, err)
	assert.Check(t, is.Len(value, 96))

	previous := Clock

	Clock = dsig.NewFakeClockAt(time.Now())
	defer func() { Clock = previous }()

	sp := ServiceProvider{IDPMetadata: test.IDP.Metadata()}
	assert.Check(t, sp.validateSignature(parsed.Root()))
}

func TestIDPSignsWithECDSAByDefaultForCurve(t *testing.T) {
	for _, tc := range ecdsaTestCurves {
		t.Run(tc.name, func(t *testing.T) {
			key, cert := newECDSATestKey(t, tc.curve)

			for name, apply := range map[string]func(test *IdentityProviderTest){
				"key":           func(test *IdentityProviderTest) { test.IDP.Key = key },
				"signer":        func(test *IdentityProviderTest) { test.IDP.Signer = key },
				"opaque signer": func(test *IdentityProviderTest) { test.IDP.Signer = opaqueSigner{key} },
			} {
				t.Run(name, func(t *testing.T) {
					test := NewIdentityProviderTest(t)
					test.IDP.Key = nil
					test.IDP.Signer = nil
					test.IDP.Certificate = cert
					apply(test)
					signature, _ := interopSignatureMethod(t, test)
					assert.Check(t, is.Equal(tc.method, signature))
				})
			}
		})
	}
}

func TestIDPRejectsSignatureMethodForOtherKeyType(t *testing.T) {
	key, cert := newECDSATestKey(t, elliptic.P256())
	test := NewIdentityProviderTest(t)
	test.IDP.Key = key
	test.IDP.Signer = nil
	test.IDP.Certificate = cert
	test.IDP.SignatureMethod = dsig.RSASHA256SignatureMethod
	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	assert.NilError(t, err)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice"}))
	assert.Check(t, is.ErrorContains(req.MakeResponse(), "incompatible"))
}

func TestIDPRejectsKeyWhichCannotSign(t *testing.T) {
	test := NewIdentityProviderTest(t)
	test.IDP.Key = "not a key"
	test.IDP.Signer = nil
	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	assert.NilError(t, err)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice"}))
	assert.Check(t, is.ErrorContains(req.MakeResponse(), "crypto.Signer"))
}

// SAML2Int SDP-MD07 requires an EC public key to be at least 256 bits in length.
func TestIDPRejectsECDSAKeyShorterThan256Bits(t *testing.T) {
	key, cert := newECDSATestKey(t, elliptic.P224())

	for name, apply := range map[string]func(test *IdentityProviderTest){
		"key":           func(test *IdentityProviderTest) { test.IDP.Key = key },
		"opaque signer": func(test *IdentityProviderTest) { test.IDP.Signer = opaqueSigner{key} },
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t)
			test.IDP.Key = nil
			test.IDP.Signer = nil
			test.IDP.Certificate = cert
			apply(test)

			req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
			assert.NilError(t, err)
			assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice"}))
			assert.Check(t, is.ErrorContains(req.MakeResponse(), "shorter than 256 bits"))

			_, err = test.IDP.SignedMetadata()
			assert.Check(t, is.ErrorContains(err, "shorter than 256 bits"))

			w := httptest.NewRecorder()
			test.IDP.ServeMetadata(w, httptest.NewRequest(http.MethodGet, test.IDP.MetadataURL.String(), nil))
			assert.Check(t, is.Equal(w.Code, http.StatusInternalServerError))
		})
	}
}

func TestIDPMetadataOmitsEncryptionForECDSACertificate(t *testing.T) {
	_, cert := newECDSATestKey(t, elliptic.P256())
	test := NewIdentityProviderTest(t)
	test.IDP.Certificate = cert
	descriptors := test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors
	assert.Check(t, is.DeepEqual([]string{"signing"}, keyDescriptorUses(descriptors)))
}

func TestIDPMetadataAdvertisesEncryptionForRSACertificate(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	descriptors := test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors
	assert.Check(t, is.DeepEqual([]string{"signing", "encryption"}, keyDescriptorUses(descriptors)))
}

// What is encrypted to the identity provider can only be decrypted with a private key that it holds.
func TestIDPMetadataOmitsEncryptionWithoutDecryptionKey(t *testing.T) {
	for name, opts := range map[string][]idpTestOpts{"no key": nil, "signer": {applySigner}} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, opts...)
			descriptors := test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors
			assert.Check(t, is.DeepEqual([]string{"signing"}, keyDescriptorUses(descriptors)))
		})
	}
}

func TestIDPMetadataListsTheEncryptionMethodsItAccepts(t *testing.T) {
	algorithms := func(test *IdentityProviderTest) []EncryptionMethod {
		return test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors[1].EncryptionMethods
	}

	t.Run("defaults put gcm first", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		assert.Check(t, is.DeepEqual([]EncryptionMethod{
			method(aes128GCM), method(aes192GCM), method(aes256GCM),
			method(aes128CBC), method(aes192CBC), method(aes256CBC),
			method(rsaOAEP), method(rsaOAEP11),
		}, algorithms(test)))
	})

	t.Run("restricted", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.ContentEncryptionMethods = []string{aes256CBC, aes256GCM}
		test.IDP.KeyTransportMethods = []string{rsaOAEP11}
		test.IDP.KeyTransportDigestMethods = []string{digestSHA256, digestSHA512}
		assert.Check(t, is.DeepEqual([]EncryptionMethod{
			method(aes256GCM), method(aes256CBC), oaepMethod(rsaOAEP11, digestSHA256, mgf1SHA256),
		}, algorithms(test)))
	})

	t.Run("misconfigured", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.ContentEncryptionMethods = []string{tripleDES}
		assert.Check(t, is.DeepEqual([]string{"signing"}, keyDescriptorUses(test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors)))
	})
}

// derSignatureVerifier accepts a peer which signs in DER, by converting the signature on the element
// to r||s before validating it.
type derSignatureVerifier struct{}

func (derSignatureVerifier) VerifySignature(validationContext *ValidationContext, el *etree.Element) error {
	certificates, err := validationContext.CertificateStore.Certificates()
	if err != nil {
		return err
	}

	public := certificates[0].PublicKey.(*ecdsa.PublicKey)
	size := (public.Params().N.BitLen() + 7) / 8

	value := el.FindElement("./Signature/SignatureValue")

	der, err := base64.StdEncoding.DecodeString(value.Text())
	if err != nil {
		return err
	}

	var signature struct{ R, S *big.Int }
	if _, err = asn1.Unmarshal(der, &signature); err != nil {
		return err
	}

	raw := make([]byte, 2*size)
	signature.R.FillBytes(raw[:size])
	signature.S.FillBytes(raw[size:])
	value.SetText(base64.StdEncoding.EncodeToString(raw))

	_, err = validationContext.Validate(el)

	return err
}

func TestSPAcceptsDERSignatureOnlyWithSignatureVerifier(t *testing.T) {
	key, cert := newECDSATestKey(t, elliptic.P256())
	test := NewIdentityProviderTest(t)
	test.IDP.Key = key
	test.IDP.Signer = nil
	test.IDP.Certificate = cert
	test.IDP.SignatureMethod = dsig.ECDSASHA256SignatureMethod
	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	assert.NilError(t, err)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice"}))
	assert.NilError(t, req.MakeResponse())

	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)
	serialized, err := doc.WriteToBytes()
	assert.NilError(t, err)

	parsed := etree.NewDocument()
	assert.NilError(t, parsed.ReadFromBytes(serialized))

	value := parsed.Root().FindElement("./Signature/SignatureValue")
	raw, err := base64.StdEncoding.DecodeString(value.Text())
	assert.NilError(t, err)
	der, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])})
	assert.NilError(t, err)
	value.SetText(base64.StdEncoding.EncodeToString(der))

	previous := Clock

	Clock = dsig.NewFakeClockAt(time.Now())
	defer func() { Clock = previous }()

	sp := ServiceProvider{IDPMetadata: test.IDP.Metadata()}
	assert.Check(t, is.ErrorContains(sp.validateSignature(parsed.Root().Copy()), "invalid ECDSA signature length"))

	sp.SignatureVerifier = derSignatureVerifier{}
	assert.Check(t, sp.validateSignature(parsed.Root().Copy()))
}
