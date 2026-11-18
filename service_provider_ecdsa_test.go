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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/dsig"
	"authelia.com/provider/saml/xmlenc"
)

// signedRedirectQuery splits a signed redirect query into what was signed and the decoded signature.
func signedRedirectQuery(t *testing.T, rawQuery string) (signed string, signature []byte) {
	t.Helper()

	signed, encoded, found := strings.Cut(rawQuery, "&Signature=")
	require.True(t, found)

	unescaped, err := url.QueryUnescape(encoded)
	require.NoError(t, err)
	signature, err = base64.StdEncoding.DecodeString(unescaped)
	require.NoError(t, err)

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
				require.NoError(t, xml.Unmarshal(test.IDPMetadata, s.IDPMetadata))

				redirectURL, err := s.MakeRedirectAuthenticationRequest("relayState")
				require.NoError(t, err)
				assert.Equal(t, tc.method, redirectURL.Query().Get("SigAlg"))

				signed, signature := signedRedirectQuery(t, redirectURL.RawQuery)
				size := (tc.curve.Params().N.BitLen() + 7) / 8
				require.Len(t, signature, 2*size)

				hash := tc.newHash.New()
				hash.Write([]byte(signed))

				r := new(big.Int).SetBytes(signature[:size])
				sValue := new(big.Int).SetBytes(signature[size:])
				assert.True(t, ecdsa.Verify(&key.PublicKey, hash.Sum(nil), r, sValue))
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
				assert.NoError(t, err)
				return
			}

			assert.ErrorContains(t, err, tc.err)
		})
	}
}

func TestSPMetadataAdvertisesEncryptionOnlyForRSACertificate(t *testing.T) {
	test := NewServiceProviderTest(t)
	_, ecdsaCert := newECDSATestKey(t, elliptic.P256())
	_, isRSA := test.Certificate.PublicKey.(*rsa.PublicKey)
	require.True(t, isRSA)

	s := ServiceProvider{
		Certificate:     ecdsaCert,
		MetadataURL:     mustParseURL("https://sp.example.com/saml2/metadata"),
		AcsURL:          mustParseURL("https://sp.example.com/saml2/acs"),
		SignatureMethod: dsig.ECDSASHA256SignatureMethod,
	}
	descriptors := s.Metadata().SPSSODescriptors[0].KeyDescriptors
	assert.Equal(t, []string{"signing"}, keyDescriptorUses(descriptors))

	s.SignatureMethod = ""
	descriptors = s.Metadata().SPSSODescriptors[0].KeyDescriptors
	assert.Equal(t, []string{}, keyDescriptorUses(descriptors))

	s.Certificate = test.Certificate
	descriptors = s.Metadata().SPSSODescriptors[0].KeyDescriptors
	assert.Equal(t, []string{"encryption"}, keyDescriptorUses(descriptors))
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
	_, err := req.spEncryptionKey()
	assert.True(t, err == os.ErrNotExist, "expected os.ErrNotExist, got %v", err)
}

// An SP that offers an elliptic curve key for encryption is sent an assertion encrypted to it by ECDH-ES, which
// its private key decrypts.
func TestIDPEncryptsToSPOfferingECDSACertificate(t *testing.T) {
	key, ecdsaCert := newECDSATestKey(t, elliptic.P256())
	for _, use := range []string{"encryption", ""} {
		t.Run("use="+use, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
			require.NoError(t, err)
			require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice"}))

			descriptor := KeyDescriptor{Use: use}
			descriptor.KeyInfo.X509Data.X509Certificates = []X509Certificate{{Data: base64.StdEncoding.EncodeToString(ecdsaCert.Raw)}}
			req.SPSSODescriptor.KeyDescriptors = []KeyDescriptor{descriptor}
			require.NoError(t, req.MakeAssertionEl())
			require.Equal(t, req.AssertionEl.Tag, "EncryptedAssertion")

			encryptedData := req.AssertionEl.FindElement("./EncryptedData")
			require.NotNil(t, encryptedData)

			agreement := encryptedData.FindElement("./KeyInfo/EncryptedKey/KeyInfo/AgreementMethod")
			require.NotNil(t, agreement)
			assert.Equal(t, agreement.SelectAttrValue("Algorithm", ""), "http://www.w3.org/2009/xmlenc11#ECDH-ES")

			plaintext, err := xmlenc.Decrypt(key, encryptedData)
			require.NoError(t, err)
			assert.Contains(t, string(plaintext), `<saml:Assertion `)
			assert.Contains(t, string(plaintext), `Recipient="https://sp.example.com/saml2/acs"`)
		})
	}
}
