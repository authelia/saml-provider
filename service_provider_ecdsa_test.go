package saml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"math/big"
	"net/url"
	"os"
	"strings"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml/internal/dsig"
)

// signedRedirectQuery splits a signed redirect query into what was signed and the decoded signature.
func signedRedirectQuery(t *testing.T, rawQuery string) (signed string, signature []byte) {
	t.Helper()
	signed, encoded, found := strings.Cut(rawQuery, "&Signature=")
	assert.Assert(t, found)
	unescaped, err := url.QueryUnescape(encoded)
	assert.NilError(t, err)
	signature, err = base64.StdEncoding.DecodeString(unescaped)
	assert.NilError(t, err)
	return signed, signature
}

func TestSPSignsRedirectRequestWithECDSA(t *testing.T) {
	for _, tc := range ecdsaTestCurves {
		for name, wrap := range map[string]func(*ecdsa.PrivateKey) ServiceProvider{
			"key":           func(key *ecdsa.PrivateKey) ServiceProvider { return ServiceProvider{Key: key} },
			"opaque signer": func(key *ecdsa.PrivateKey) ServiceProvider { return ServiceProvider{Key: opaqueSigner{key}} },
		} {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				test := NewServiceProviderTest(t)
				key, cert := newECDSATestKey(t, tc.curve)
				s := wrap(key)
				s.Certificate = cert
				s.MetadataURL = mustParseURL("https://15661444.ngrok.io/saml2/metadata")
				s.AcsURL = mustParseURL("https://15661444.ngrok.io/saml2/acs")
				s.IDPMetadata = &EntityDescriptor{}
				s.SignatureMethod = tc.method
				assert.NilError(t, xml.Unmarshal(test.IDPMetadata, s.IDPMetadata))

				redirectURL, err := s.MakeRedirectAuthenticationRequest("relayState")
				assert.NilError(t, err)
				assert.Check(t, is.Equal(tc.method, redirectURL.Query().Get("SigAlg")))

				signed, signature := signedRedirectQuery(t, redirectURL.RawQuery)
				size := (tc.curve.Params().N.BitLen() + 7) / 8
				assert.Assert(t, is.Len(signature, 2*size))
				hash := tc.newHash.New()
				hash.Write([]byte(signed))
				r := new(big.Int).SetBytes(signature[:size])
				sValue := new(big.Int).SetBytes(signature[size:])
				assert.Check(t, ecdsa.Verify(&key.PublicKey, hash.Sum(nil), r, sValue))
			})
		}
	}
}

func TestGetSigningContextChecksKeyType(t *testing.T) {
	ecdsaKey, ecdsaCert := newECDSATestKey(t, elliptic.P256())
	test := NewServiceProviderTest(t)

	testCases := []struct {
		name string
		sp   ServiceProvider
		err  string
	}{
		{"ecdsa key with rsa method", ServiceProvider{Key: ecdsaKey, Certificate: ecdsaCert, SignatureMethod: dsig.RSASHA256SignatureMethod}, "requires an RSA key"},
		{"rsa key with ecdsa method", ServiceProvider{Key: test.Key, Certificate: test.Certificate, SignatureMethod: dsig.ECDSASHA256SignatureMethod}, "requires an ECDSA key"},
		{"opaque rsa signer with ecdsa method", ServiceProvider{Key: opaqueSigner{test.Key}, Certificate: test.Certificate, SignatureMethod: dsig.ECDSASHA256SignatureMethod}, "requires an ECDSA key"},
		{"no key", ServiceProvider{Certificate: test.Certificate, SignatureMethod: dsig.RSASHA256SignatureMethod}, "requires an RSA key"},
		{"opaque rsa signer", ServiceProvider{Key: opaqueSigner{test.Key}, Certificate: test.Certificate, SignatureMethod: dsig.RSASHA256SignatureMethod}, ""},
		{"opaque ecdsa signer", ServiceProvider{Key: opaqueSigner{ecdsaKey}, Certificate: ecdsaCert, SignatureMethod: dsig.ECDSASHA256SignatureMethod}, ""},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GetSigningContext(&tc.sp)
			if tc.err == "" {
				assert.Check(t, err)
				return
			}
			assert.Check(t, is.ErrorContains(err, tc.err))
		})
	}
}

func TestSPMetadataAdvertisesEncryptionOnlyForRSACertificate(t *testing.T) {
	test := NewServiceProviderTest(t)
	_, ecdsaCert := newECDSATestKey(t, elliptic.P256())
	_, isRSA := test.Certificate.PublicKey.(*rsa.PublicKey)
	assert.Assert(t, isRSA)

	s := ServiceProvider{
		Certificate:     ecdsaCert,
		MetadataURL:     mustParseURL("https://sp.example.com/saml2/metadata"),
		AcsURL:          mustParseURL("https://sp.example.com/saml2/acs"),
		SignatureMethod: dsig.ECDSASHA256SignatureMethod,
	}
	descriptors := s.Metadata().SPSSODescriptors[0].KeyDescriptors
	assert.Check(t, is.DeepEqual([]string{"signing"}, keyDescriptorUses(descriptors)))

	s.SignatureMethod = ""
	descriptors = s.Metadata().SPSSODescriptors[0].KeyDescriptors
	assert.Check(t, is.DeepEqual([]string{}, keyDescriptorUses(descriptors)))

	s.Certificate = test.Certificate
	descriptors = s.Metadata().SPSSODescriptors[0].KeyDescriptors
	assert.Check(t, is.DeepEqual([]string{"encryption"}, keyDescriptorUses(descriptors)))
}

func TestIDPSendsPlaintextAssertionToSPWithECDSACertificate(t *testing.T) {
	key, ecdsaCert := newECDSATestKey(t, elliptic.P256())
	s := ServiceProvider{
		Key:             key,
		Certificate:     ecdsaCert,
		MetadataURL:     mustParseURL("https://sp.example.com/saml2/metadata"),
		AcsURL:          mustParseURL("https://sp.example.com/saml2/acs"),
		SignatureMethod: dsig.ECDSASHA256SignatureMethod,
	}
	metadata := s.Metadata()

	test := NewIdentityProviderTest(t, applyKey)
	req := IdpAuthnRequest{IDP: &test.IDP, ServiceProviderMetadata: metadata, SPSSODescriptor: &metadata.SPSSODescriptors[0]}
	_, err := req.getSPEncryptionCert()
	assert.Check(t, err == os.ErrNotExist, "expected os.ErrNotExist, got %v", err)
}

func TestIDPRejectsSPOfferingECDSACertificateForEncryption(t *testing.T) {
	_, ecdsaCert := newECDSATestKey(t, elliptic.P256())
	for _, use := range []string{"encryption", ""} {
		t.Run("use="+use, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
			assert.NilError(t, err)
			assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice"}))

			descriptor := KeyDescriptor{Use: use}
			descriptor.KeyInfo.X509Data.X509Certificates = []X509Certificate{{Data: base64.StdEncoding.EncodeToString(ecdsaCert.Raw)}}
			req.SPSSODescriptor.KeyDescriptors = []KeyDescriptor{descriptor}
			assert.Check(t, is.ErrorContains(req.MakeAssertionEl(), "RSA public key"))
		})
	}
}
