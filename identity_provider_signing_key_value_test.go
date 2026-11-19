package saml

import (
	"crypto/rsa"
	"encoding/xml"
	"net/http"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/dsig"
)

// signingKeyValueMetadata returns the metadata of the service provider as an identity provider reads it once
// each of its signing keys is given as keyInfo, in place of its certificate (MetaIOP §2.5.1). It is marshalled
// and parsed again, so that the key is the one the metadata types read from XML.
func signingKeyValueMetadata(t *testing.T, sp *ServiceProvider, keyInfo KeyInfo) *EntityDescriptor {
	t.Helper()

	metadata := sp.Metadata()
	replaced := 0

	for i := range metadata.SPSSODescriptors {
		keyDescriptors := metadata.SPSSODescriptors[i].KeyDescriptors

		for j := range keyDescriptors {
			if keyDescriptors[j].Use != "signing" {
				continue
			}

			keyDescriptors[j].KeyInfo = keyInfo
			replaced++
		}
	}

	require.NotZero(t, replaced, "the service provider has no signing key")

	buf, err := xml.Marshal(metadata)
	require.NoError(t, err)

	parsed := &EntityDescriptor{}

	require.NoError(t, xml.Unmarshal(buf, parsed))

	return parsed
}

// signingKeyValueIDP returns an identity provider which requires requests to be signed, and whose service
// provider signs with key and publishes published as a ds:KeyValue alone. The service provider still puts its
// certificate in the KeyInfo of what it signs, which is of another key and is in no metadata.
func signingKeyValueIDP(t *testing.T, key *rsa.PrivateKey, published *rsa.PublicKey) *IdentityProviderTest {
	t.Helper()

	test := signatureTestIDP(t)
	test.IDP.WantAuthnRequestsSigned = true
	test.SP.Key = key

	metadata := signingKeyValueMetadata(t, &test.SP, KeyInfo{KeyValues: []KeyValue{NewRSAKeyValue(published)}})

	keys, err := serviceProviderSigningKeys(metadata)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Nil(t, keys[0].certificate)
	assert.True(t, published.Equal(keys[0].publicKey))

	useServiceProviderMetadata(test, metadata)

	return test
}

// useServiceProviderMetadata makes metadata what the identity provider finds for its service provider.
func useServiceProviderMetadata(test *IdentityProviderTest, metadata *EntityDescriptor) {
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) { return metadata, nil },
	}
}

// MetaIOP §2.6.1: a key that the metadata gives as a ds:KeyValue must be supported. An enveloped signature made
// with it verifies, whatever certificate the signature holds.
func TestValidateAcceptsPostSignedWithKeyValueKey(t *testing.T) {
	key, _ := spCertTestKeys(t)
	test := signingKeyValueIDP(t, key, &key.PublicKey)

	body := signedPostBody(t, &test.SP, nil)
	require.Contains(t, string(body), "X509Certificate")
	require.NoError(t, validatePost(t, test, body))
}

// The signature of the HTTP-Redirect binding has no KeyInfo, and verifies with the key of the ds:KeyValue.
func TestValidateAcceptsRedirectSignedWithKeyValueKey(t *testing.T) {
	key, _ := spCertTestKeys(t)
	test := signingKeyValueIDP(t, key, &key.PublicKey)

	require.NoError(t, validateURL(t, test, signedRedirectURL(t, test).String()))
}

// A signature with no KeyInfo verifies with the key of the ds:KeyValue too.
func TestValidateAcceptsPostSignedWithKeyValueKeyAndNoKeyInfo(t *testing.T) {
	key, _ := spCertTestKeys(t)
	test := signingKeyValueIDP(t, key, &key.PublicKey)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(signedPostBody(t, &test.SP, nil)))

	keyInfo := doc.Root().FindElement("./Signature/KeyInfo")
	require.NotNil(t, keyInfo)
	keyInfo.Parent().RemoveChild(keyInfo)

	body, err := doc.WriteToBytes()
	require.NoError(t, err)
	require.NoError(t, validatePost(t, test, body))
}

func TestValidateRejectsSignatureByAnotherKeyThanTheKeyValue(t *testing.T) {
	key, _ := spCertTestKeys(t)

	// The key of the fixture is the one that the certificate in the signature holds, which is not trusted for it.
	t.Run("post", func(t *testing.T) {
		test := signingKeyValueIDP(t, key, &key.PublicKey)
		test.SP.Key = test.SPKey

		assert.ErrorContains(t, validatePost(t, test, signedPostBody(t, &test.SP, nil)), "signature")
	})

	t.Run("redirect", func(t *testing.T) {
		test := signingKeyValueIDP(t, key, &key.PublicKey)
		test.SP.Key = test.SPKey

		assert.ErrorContains(t, validateURL(t, test, signedRedirectURL(t, test).String()), "signature")
	})

	t.Run("altered", func(t *testing.T) {
		test := signingKeyValueIDP(t, key, &key.PublicKey)
		body := signedPostBody(t, &test.SP, nil)
		altered := strings.Replace(string(body), `AssertionConsumerServiceURL="https://sp.example.com/saml2/acs"`,
			`AssertionConsumerServiceURL="https://sp.example.com/saml2/acs" ProviderName="other"`, 1)
		require.NotEqual(t, string(body), altered)

		assert.ErrorContains(t, validatePost(t, test, []byte(altered)), "signature")
	})
}

// The algorithms that a signature is accepted with are those of the policy, whatever form the key is given in.
func TestValidateHoldsKeyValueKeyToSignatureMethods(t *testing.T) {
	key, _ := spCertTestKeys(t)

	t.Run("post", func(t *testing.T) {
		test := signingKeyValueIDP(t, key, &key.PublicKey)
		test.IDP.SignatureMethods = []string{dsig.RSASHA512SignatureMethod}

		assert.Contains(t, errorText(validatePost(t, test, signedPostBody(t, &test.SP, nil))), "is not allowed")
	})

	t.Run("redirect", func(t *testing.T) {
		test := signingKeyValueIDP(t, key, &key.PublicKey)
		test.IDP.SignatureMethods = []string{dsig.RSASHA512SignatureMethod}

		assert.Contains(t, errorText(validateURL(t, test, signedRedirectURL(t, test).String())), "is not allowed")
	})
}

// keyValueKeyDescriptor returns the signing KeyDescriptor that is read from a ds:KeyInfo with the given content.
func keyValueKeyDescriptor(t *testing.T, content string) KeyDescriptor {
	t.Helper()

	var keyDescriptor KeyDescriptor

	require.NoError(t, xml.Unmarshal([]byte(`<KeyDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" use="signing">`+
		`<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">`+content+`</KeyInfo></KeyDescriptor>`), &keyDescriptor))

	return keyDescriptor
}

const (
	dsaKeyValueXML = `<KeyValue><DSAKeyValue><P>/w==</P><Q>/w==</Q><G>Ag==</G><Y>Aw==</Y></DSAKeyValue></KeyValue>`
	ecKeyValueXML  = `<KeyValue><ECKeyValue xmlns="http://www.w3.org/2009/xmldsig11#">` +
		`<NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><PublicKey>BA==</PublicKey></ECKeyValue></KeyValue>`
)

func rsaKeyValueXML(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()

	buf, err := xml.Marshal(NewRSAKeyValue(key))
	require.NoError(t, err)

	return string(buf)
}

func signingKeysOf(keyDescriptors ...KeyDescriptor) ([]signatureVerificationKey, error) {
	return serviceProviderSigningKeys(&EntityDescriptor{SPSSODescriptors: []SPSSODescriptor{
		{SSODescriptor: SSODescriptor{RoleDescriptor: RoleDescriptor{KeyDescriptors: keyDescriptors}}},
	}})
}

// A ds:KeyValue which holds anything but an RSAKeyValue gives no key that can be used, and is passed over.
func TestSigningKeysSkipKeyValueOfAnotherType(t *testing.T) {
	key, _ := spCertTestKeys(t)

	keys, err := signingKeysOf(keyValueKeyDescriptor(t, dsaKeyValueXML+ecKeyValueXML))
	require.NoError(t, err)
	assert.Empty(t, keys)

	keys, err = signingKeysOf(
		keyValueKeyDescriptor(t, dsaKeyValueXML),
		keyValueKeyDescriptor(t, ecKeyValueXML+rsaKeyValueXML(t, &key.PublicKey)),
	)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Nil(t, keys[0].certificate)
	assert.True(t, key.PublicKey.Equal(keys[0].publicKey))

	// A request signed for a service provider with no other key is refused as one with no signing key is.
	test := signatureTestIDP(t)
	test.IDP.WantAuthnRequestsSigned = true

	metadata := test.SP.Metadata()
	for i := range metadata.SPSSODescriptors {
		metadata.SPSSODescriptors[i].KeyDescriptors = []KeyDescriptor{keyValueKeyDescriptor(t, dsaKeyValueXML)}
	}

	useServiceProviderMetadata(test, metadata)

	assert.Contains(t, errorText(validatePost(t, test, signedPostBody(t, &test.SP, nil))), "has no signing key")
}

// A key with no use is one for signing too (SAMLMeta §2.4.1.1).
func TestSigningKeysIncludeKeyValueWithNoUse(t *testing.T) {
	key, _ := spCertTestKeys(t)

	signing := keyValueKeyDescriptor(t, rsaKeyValueXML(t, &key.PublicKey))
	signing.Use = ""

	encryption := signing
	encryption.Use = "encryption"

	keys, err := signingKeysOf(encryption, signing)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.True(t, key.PublicKey.Equal(keys[0].publicKey))
}

// MetaIOP §2.5.1: a certificate and a ds:KeyValue of one KeyInfo represent the same key. The certificate is the
// one used, as it is for an encryption key.
func TestSigningKeysPreferCertificateToKeyValue(t *testing.T) {
	_, small := spCertTestKeys(t)
	test := signatureTestIDP(t)

	keyDescriptor := keyValueKeyDescriptor(t, rsaKeyValueXML(t, &small.PublicKey))
	keyDescriptor.KeyInfo.X509Data.X509Certificates = []X509Certificate{
		{Data: " "},
		{Data: encodeCertificate(test.SPCertificate)},
	}

	keys, err := signingKeysOf(keyDescriptor)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.NotNil(t, keys[0].certificate)
	assert.True(t, test.SPCertificate.Equal(keys[0].certificate))
	assert.True(t, test.SPKey.PublicKey.Equal(keys[0].publicKey))
}

// An RSAKeyValue which can't be parsed is broken metadata, and to pass over it would hide that.
func TestSigningKeysRefuseMalformedKeyValue(t *testing.T) {
	for name, content := range map[string]string{
		"modulus":  `<KeyValue><RSAKeyValue><Modulus>!</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue>`,
		"exponent": `<KeyValue><RSAKeyValue><Modulus>AQAB</Modulus><Exponent></Exponent></RSAKeyValue></KeyValue>`,
		"empty":    `<KeyValue><RSAKeyValue></RSAKeyValue></KeyValue>`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := signingKeysOf(keyValueKeyDescriptor(t, content))
			assert.ErrorContains(t, err, "cannot parse service provider key value")
		})
	}
}

// The key of a ds:KeyValue verifies what the service provider signs besides an AuthnRequest: a LogoutRequest is
// accepted on both bindings, and one that another key signed is not.
func TestServeSLOAcceptsRequestSignedWithKeyValueKey(t *testing.T) {
	key, _ := spCertTestKeys(t)

	setup := func(t *testing.T) (*IdentityProviderTest, *logoutSessionProvider) {
		t.Helper()

		test, provider := logoutTestIDP(t)
		test.SP.Key = key

		useServiceProviderMetadata(test, signingKeyValueMetadata(t, &test.SP, KeyInfo{KeyValues: []KeyValue{NewRSAKeyValue(&key.PublicKey)}}))

		return test, provider
	}

	t.Run("redirect", func(t *testing.T) {
		test, provider := setup(t)
		r, id := redirectLogoutRequest(t, &test.SP, nil)

		_, response := redirectedLogoutResponse(t, serveSLO(test, r))
		assert.Equal(t, id, response.InResponseTo)
		assert.Equal(t, StatusSuccess, response.Status.StatusCode.Value)
		assert.Len(t, provider.terminated, 1)
	})

	t.Run("post", func(t *testing.T) {
		test, provider := setup(t)
		r, id := postLogoutRequest(t, &test.SP, nil)

		_, _, response := postedLogoutResponse(t, serveSLO(test, r))
		assert.Equal(t, id, response.InResponseTo)
		assert.Equal(t, StatusSuccess, response.Status.StatusCode.Value)
		assert.Len(t, provider.terminated, 1)
	})

	t.Run("another key", func(t *testing.T) {
		test, provider := setup(t)
		test.SP.Key = test.SPKey

		for _, r := range []*http.Request{
			first(redirectLogoutRequest(t, &test.SP, nil)),
			first(postLogoutRequest(t, &test.SP, nil)),
		} {
			assert.Equal(t, http.StatusBadRequest, serveSLO(test, r).Code)
		}

		assert.Empty(t, provider.lookups)
		assert.Empty(t, provider.terminated)
	})
}

// first returns the request of a helper that also returns its ID.
func first(r *http.Request, _ string) *http.Request {
	return r
}
