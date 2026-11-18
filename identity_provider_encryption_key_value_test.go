package saml

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keyValueMetadata returns metadata as an identity provider reads it once each encryption key in it is given as
// a ds:KeyValue alone, in place of its certificate (MetaIOP §2.5.1). It is marshalled and parsed again, so that
// the key is the one the metadata types read from XML.
func keyValueMetadata(t *testing.T, metadata *EntityDescriptor) *EntityDescriptor {
	t.Helper()

	for i := range metadata.SPSSODescriptors {
		keyDescriptors := metadata.SPSSODescriptors[i].KeyDescriptors

		for j := range keyDescriptors {
			if keyDescriptors[j].Use != "encryption" {
				continue
			}

			cert, err := parseCert(firstCertificateData(keyDescriptors[j]))
			require.NoError(t, err)

			keyDescriptors[j].KeyInfo = KeyInfo{KeyValues: []KeyValue{NewRSAKeyValue(cert.PublicKey.(*rsa.PublicKey))}}
		}
	}

	buf, err := xml.Marshal(metadata)
	require.NoError(t, err)
	assert.Contains(t, string(buf), "<RSAKeyValue")

	parsed := &EntityDescriptor{}

	//nolint:gosec // G709: the XML is what was marshalled above, into a fixed type.
	require.NoError(t, xml.Unmarshal(buf, parsed))

	return parsed
}

// useKeyValueMetadata gives req the metadata of its service provider with the encryption key as a ds:KeyValue.
func useKeyValueMetadata(t *testing.T, req *IdpAuthnRequest) {
	t.Helper()

	req.ServiceProviderMetadata = keyValueMetadata(t, req.ServiceProviderMetadata)
	req.SPSSODescriptor = &req.ServiceProviderMetadata.SPSSODescriptors[0]
	req.ACSEndpoint = &req.SPSSODescriptor.AssertionConsumerServices[0]

	keyDescriptor := req.spEncryptionKeyDescriptor()
	require.True(t, keyDescriptor != nil, "the key value is not taken for an encryption key")
	require.Len(t, keyDescriptor.KeyInfo.X509Data.X509Certificates, 0)
}

// checkKeyValueKeyInfo checks that the EncryptedKey of encryptedEl identifies key by its ds:KeyValue, and not by
// a certificate, which the service provider never published.
func checkKeyValueKeyInfo(t *testing.T, encryptedEl *etree.Element, key *rsa.PublicKey) {
	t.Helper()

	encryptedKey := encryptedEl.FindElement("./EncryptedData/KeyInfo/EncryptedKey")
	require.NotNil(t, encryptedKey)

	keyInfo, err := findOneChild(encryptedKey, xmldsigNamespace, "KeyInfo")
	require.NoError(t, err)
	assert.Equal(t, childTags(keyInfo), []string{"KeyValue"})

	rsaKeyValue := keyInfo.FindElement("./KeyValue/RSAKeyValue")
	require.NotNil(t, rsaKeyValue)
	assert.Equal(t, rsaKeyValue.NamespaceURI(), xmldsigNamespace)
	assert.Equal(t, childTags(rsaKeyValue), []string{"Modulus", "Exponent"})

	want := NewRSAKeyValue(key).RSAKeyValue
	assert.Equal(t, rsaKeyValue.FindElement("./Modulus").Text(), want.Modulus)
	assert.Equal(t, rsaKeyValue.FindElement("./Exponent").Text(), want.Exponent)
}

// recordingEnforcer records the keys that the identity provider asks about, and refuses them with err.
type recordingEnforcer struct {
	keys []ServiceProviderEncryptionKey
	err  error
}

func (e *recordingEnforcer) EnforceEncryptionKey(_ *IdpAuthnRequest, key ServiceProviderEncryptionKey) error {
	e.keys = append(e.keys, key)

	return e.err
}

// MetaIOP §2.6.1: a key that the metadata gives as a ds:KeyValue must be supported. The assertion and its parts
// are encrypted to it, and the service provider of this library decrypts them.
func TestIDPEncryptsToKeyValueKey(t *testing.T) {
	test, req := encryptedPartsRequest(t)
	useKeyValueMetadata(t, req)
	requestEncryptedID(req)

	enforcer := &recordingEnforcer{}
	test.IDP.EncryptionKeyEnforcer = enforcer
	test.IDP.ElementEncryptionPolicy = DefaultElementEncryptionPolicy{AttributeServiceProviders: []string{test.SP.MetadataURL.String()}}

	spKey := test.SP.Certificate.PublicKey.(*rsa.PublicKey)

	body := respond(t, req)

	// The enforcer is asked before anything is encrypted, about a key that has no certificate.
	require.True(t, len(enforcer.keys) != 0)

	for _, key := range enforcer.keys {
		assert.Nil(t, key.Certificate)
		assert.True(t, spKey.Equal(key.PublicKey))
	}

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(body))

	encryptedAssertion := doc.Root().FindElement("./EncryptedAssertion")
	require.True(t, encryptedAssertion != nil, "the assertion is not encrypted: %s", body)
	checkKeyValueKeyInfo(t, encryptedAssertion, spKey)
	assert.Nil(t, encryptedAssertion.FindElement(".//X509Data"))

	sent := sentAssertionElement(t, test, body)
	assert.False(t, strings.Contains(elementToString(sent), "alice"))

	encryptedID := sent.FindElement("./Subject/EncryptedID")
	require.NotNil(t, encryptedID)
	checkKeyValueKeyInfo(t, encryptedID, spKey)
	assert.Equal(t, test.SP.MetadataURL.String(), encryptedID.FindElement("./EncryptedData/KeyInfo/EncryptedKey").SelectAttrValue("Recipient", ""))

	encryptedAttributes := sent.FindElements("./AttributeStatement/EncryptedAttribute")
	require.Len(t, encryptedAttributes, 4)
	assert.Nil(t, sent.FindElement("./AttributeStatement/Attribute"))

	for _, encryptedAttribute := range encryptedAttributes {
		checkKeyValueKeyInfo(t, encryptedAttribute, spKey)
		assert.Equal(t, test.SP.MetadataURL.String(), encryptedAttribute.FindElement("./EncryptedData/KeyInfo/EncryptedKey").SelectAttrValue("Recipient", ""))
	}

	// The algorithms are still negotiated from the EncryptionMethods of the descriptor.
	assert.Equal(t, aes128GCM, encryptedID.FindElement("./EncryptedData/EncryptionMethod").SelectAttrValue("Algorithm", ""))

	assertion, err := test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
	require.NoError(t, err)
	assert.Equal(t, *req.Assertion.Subject.NameID, *assertion.Subject.NameID)
	assert.Equal(t, req.Assertion.AttributeStatements, assertion.AttributeStatements)
}

// The key is refused like one in a certificate is: nothing is sent, in plaintext or to another key.
func TestIDPEnforcerRefusesKeyValueKey(t *testing.T) {
	refusal := errors.New("this key is not allowed")

	t.Run("custom enforcer", func(t *testing.T) {
		test, req := encryptedPartsRequest(t)
		useKeyValueMetadata(t, req)

		// A certificate after it, which the enforcer would accept, is not tried in its place.
		req.SPSSODescriptor.KeyDescriptors = append(req.SPSSODescriptor.KeyDescriptors, test.SP.Metadata().SPSSODescriptors[0].KeyDescriptors[0])

		enforcer := &recordingEnforcer{err: refusal}
		test.IDP.EncryptionKeyEnforcer = enforcer

		require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, encryptedPartsSession))

		err := req.MakeAssertionEl()
		assert.True(t, errors.Is(err, refusal), "err=%v", err)
		assert.False(t, errors.Is(err, os.ErrNotExist))
		assert.Nil(t, req.AssertionEl)
		assert.True(t, errors.Is(req.MakeResponse(), refusal))
		assert.Nil(t, req.ResponseEl)

		require.True(t, len(enforcer.keys) != 0)
		assert.Nil(t, enforcer.keys[0].Certificate)
	})

	rsa2048, rsa1024 := spCertTestKeys(t)

	for _, tc := range []struct {
		name     string
		key      *rsa.PrivateKey
		enforcer EncryptionKeyEnforcer
		err      string
	}{
		{name: "RSA-2048 with the default enforcer", key: rsa2048, enforcer: DefaultEncryptionKeyEnforcer{}},
		{name: "RSA-2048 with no enforcer", key: rsa2048},
		{name: "RSA-1024 with the default enforcer", key: rsa1024, enforcer: DefaultEncryptionKeyEnforcer{}, err: "1024-bit"},
		{name: "RSA-1024 with no enforcer", key: rsa1024, err: "1024-bit"},
		{name: "RSA-1024 allowed", key: rsa1024, enforcer: DefaultEncryptionKeyEnforcer{MinimumRSAKeySize: 1024}},
		{name: "RSA-2048 with a stricter minimum", key: rsa2048, enforcer: DefaultEncryptionKeyEnforcer{MinimumRSAKeySize: 3072}, err: "2048-bit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			idp := test.IDP
			idp.EncryptionKeyEnforcer = tc.enforcer

			descriptor := SPSSODescriptor{SSODescriptor: SSODescriptor{RoleDescriptor: RoleDescriptor{KeyDescriptors: []KeyDescriptor{
				{Use: "encryption", KeyInfo: KeyInfo{KeyValues: []KeyValue{NewRSAKeyValue(&tc.key.PublicKey)}}},
			}}}}
			req := &IdpAuthnRequest{
				IDP:                     &idp,
				Now:                     TimeNow(),
				SPSSODescriptor:         &descriptor,
				ServiceProviderMetadata: &EntityDescriptor{EntityID: "https://sp.example.com/saml2/metadata", SPSSODescriptors: []SPSSODescriptor{descriptor}},
			}

			key, err := req.spEncryptionKey()
			if tc.err == "" {
				require.NoError(t, err)
				assert.Nil(t, key.Certificate)
				assert.True(t, tc.key.PublicKey.Equal(key.PublicKey))

				return
			}

			assert.ErrorContains(t, err, tc.err)
			assert.False(t, errors.Is(err, os.ErrNotExist), "a refused key must not fall back to plaintext")
			assert.Nil(t, key)
		})
	}
}

// The enforcer is given the key, so one that is built without it is refused rather than let through, as is a key
// that is neither RSA nor elliptic curve. An elliptic curve key in a certificate with no key is read from it.
func TestDefaultEncryptionKeyEnforcerRequiresKey(t *testing.T) {
	_, ecdsaCert := newECDSATestKey(t, elliptic.P256())
	req := &IdpAuthnRequest{Now: ecdsaCert.NotBefore}
	enforcer := DefaultEncryptionKeyEnforcer{IgnoreValidityPeriod: true}

	assert.ErrorContains(t, enforcer.EnforceEncryptionKey(req, ServiceProviderEncryptionKey{}), "neither an RSA nor an elliptic curve")
	assert.ErrorContains(t, enforcer.EnforceEncryptionKey(req, ServiceProviderEncryptionKey{PublicKey: ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))}), "neither an RSA nor an elliptic curve")
	assert.NoError(t, enforcer.EnforceEncryptionKey(req, ServiceProviderEncryptionKey{Certificate: ecdsaCert}))
	assert.ErrorContains(t, enforcer.EnforceEncryptionKey(req, ServiceProviderEncryptionKey{PublicKey: (*ecdsa.PublicKey)(nil)}), "not an elliptic curve public key")
}

const (
	keyValueTestECKeyDescriptor = `<KeyDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" use="%USE%">` +
		`<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyValue>` +
		`<dsig11:ECKeyValue xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">` +
		`<dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/>` +
		`<dsig11:PublicKey>BOVKaiLPKEDChhkA64UEBOXTv/VFHnhrUPN+bXqCvEl7rroAYpH5tKzbiGTtMSlp4JO9Pxg44zeX7EoWDvOrpD0=</dsig11:PublicKey>` +
		`</dsig11:ECKeyValue></ds:KeyValue></ds:KeyInfo></KeyDescriptor>`

	keyValueTestDSAKeyDescriptor = `<KeyDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" use="%USE%">` +
		`<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyValue>` +
		`<ds:DSAKeyValue><ds:P>AQAB</ds:P><ds:Q>AQAB</ds:Q><ds:G>AQAB</ds:G><ds:Y>AQAB</ds:Y></ds:DSAKeyValue>` +
		`</ds:KeyValue></ds:KeyInfo></KeyDescriptor>`

	keyValueTestKeyNameDescriptor = `<KeyDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" use="%USE%">` +
		`<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyName>ServiceProvider.com Encrypt Key</ds:KeyName></ds:KeyInfo>` +
		`</KeyDescriptor>`
)

// parsedKeyDescriptor returns the KeyDescriptor of the template, as the metadata types read it, with use as its
// use attribute, or with none when use is empty.
func parsedKeyDescriptor(t *testing.T, template, use string) KeyDescriptor {
	t.Helper()

	if use == "" {
		template = strings.Replace(template, ` use="%USE%"`, "", 1)
	}

	var keyDescriptor KeyDescriptor

	require.NoError(t, xml.Unmarshal([]byte(strings.Replace(template, "%USE%", use, 1)), &keyDescriptor))
	assert.Equal(t, keyDescriptor.Use, use)

	return keyDescriptor
}

// The key that is encrypted to is the first that can be: a descriptor with none is passed over, and when the
// metadata allows encryption and no descriptor has one, nothing is sent in plaintext.
func TestIDPEncryptionKeySelection(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	rsa2048, _ := spCertTestKeys(t)
	now := TimeNow()

	certData := base64.StdEncoding.EncodeToString(test.SPCertificate.Raw)
	certKey := test.SPCertificate.PublicKey.(*rsa.PublicKey)

	_, ecdsaCert := newECDSATestKey(t, elliptic.P256())

	withCerts := func(use string, data ...string) KeyDescriptor {
		keyDescriptor := KeyDescriptor{Use: use}
		for _, d := range data {
			keyDescriptor.KeyInfo.X509Data.X509Certificates = append(keyDescriptor.KeyInfo.X509Data.X509Certificates, X509Certificate{Data: d})
		}

		return keyDescriptor
	}
	withKeyValue := func(use string, key *rsa.PublicKey) KeyDescriptor {
		return KeyDescriptor{Use: use, KeyInfo: KeyInfo{KeyValues: []KeyValue{NewRSAKeyValue(key)}}}
	}
	parsed := func(template, use string) KeyDescriptor { return parsedKeyDescriptor(t, template, use) }
	wrapped := "\n\t  " + certData[:64] + "\n  " + certData[64:] + "\r\n "
	ecData := base64.StdEncoding.EncodeToString(ecdsaCert.Raw)

	_, p224Cert := newECDSATestKey(t, elliptic.P224())
	p224Data := base64.StdEncoding.EncodeToString(p224Cert.Raw)

	const (
		failClosed = "fail closed"
		plaintext  = "plaintext"
		broken     = "broken"
		toCert     = "certificate"
		toECCert   = "elliptic curve certificate"
		toKeyValue = "key value"
	)

	for _, tc := range []struct {
		name        string
		descriptors []KeyDescriptor
		want        string
		key         *rsa.PublicKey
	}{
		// BUG-46: an X509Certificate that is empty and one that only holds whitespace are passed over alike.
		{name: "whitespace then good, across descriptors", descriptors: []KeyDescriptor{withCerts("encryption", " \n\t "), withCerts("encryption", certData)}, want: toCert},
		{name: "empty then good, across descriptors", descriptors: []KeyDescriptor{withCerts("encryption", ""), withCerts("encryption", certData)}, want: toCert},
		{name: "whitespace then good, in one descriptor", descriptors: []KeyDescriptor{withCerts("encryption", "\n  ", certData)}, want: toCert},
		{name: "empty then good, in one descriptor", descriptors: []KeyDescriptor{withCerts("encryption", "", certData)}, want: toCert},
		{name: "whitespace then good with no use", descriptors: []KeyDescriptor{withCerts("encryption", " "), withCerts("", certData)}, want: toCert},
		{name: "whitespace with no use then good with no use", descriptors: []KeyDescriptor{withCerts("", "\r\n"), withCerts("", certData)}, want: toCert},
		{name: "whitespace only", descriptors: []KeyDescriptor{withCerts("encryption", " \n ")}, want: failClosed},
		{name: "empty only", descriptors: []KeyDescriptor{withCerts("encryption", "")}, want: failClosed},
		{name: "whitespace only with no use", descriptors: []KeyDescriptor{withCerts("", " \n ")}, want: failClosed},
		{name: "whitespace and signing", descriptors: []KeyDescriptor{withCerts("encryption", " \n "), withCerts("signing", certData)}, want: failClosed},
		{name: "whitespace for signing only", descriptors: []KeyDescriptor{withCerts("signing", " \n ")}, want: plaintext},
		{name: "certificate wrapped in whitespace", descriptors: []KeyDescriptor{withCerts("encryption", wrapped)}, want: toCert},

		// A certificate that is there and can't be read is an error, and is not passed over.
		{name: "certificate that is not base64", descriptors: []KeyDescriptor{withCerts("encryption", "!!!"), withCerts("encryption", certData)}, want: broken},
		{name: "certificate that is not a certificate", descriptors: []KeyDescriptor{withCerts("encryption", "bm90IGEgY2VydGlmaWNhdGU="), withCerts("encryption", certData)}, want: broken},
		{name: "certificate that is not a certificate with no use", descriptors: []KeyDescriptor{withCerts("", "bm90IGEgY2VydGlmaWNhdGU=")}, want: broken},
		{name: "good then one that is not a certificate", descriptors: []KeyDescriptor{withCerts("encryption", certData), withCerts("encryption", "bm90IGEgY2VydGlmaWNhdGU=")}, want: toCert},

		// BUG-49: a ds:KeyValue with an RSAKeyValue is a key.
		{name: "key value", descriptors: []KeyDescriptor{withKeyValue("encryption", &rsa2048.PublicKey)}, want: toKeyValue, key: &rsa2048.PublicKey},
		{name: "key value with no use", descriptors: []KeyDescriptor{withKeyValue("", &rsa2048.PublicKey)}, want: toKeyValue, key: &rsa2048.PublicKey},
		{name: "key value for signing only", descriptors: []KeyDescriptor{withKeyValue("signing", &rsa2048.PublicKey)}, want: plaintext},
		{name: "key value for encryption before one with no use", descriptors: []KeyDescriptor{withCerts("", certData), withKeyValue("encryption", &rsa2048.PublicKey)}, want: toKeyValue, key: &rsa2048.PublicKey},
		{name: "key name then key value", descriptors: []KeyDescriptor{parsed(keyValueTestKeyNameDescriptor, "encryption"), withKeyValue("encryption", &rsa2048.PublicKey)}, want: toKeyValue, key: &rsa2048.PublicKey},
		{name: "empty certificate beside a key value", descriptors: []KeyDescriptor{{
			Use:     "encryption",
			KeyInfo: KeyInfo{KeyValues: []KeyValue{NewRSAKeyValue(&rsa2048.PublicKey)}, X509Data: X509Data{X509Certificates: []X509Certificate{{Data: " "}}}},
		}}, want: toKeyValue, key: &rsa2048.PublicKey},
		{name: "certificate beside its key value", descriptors: []KeyDescriptor{{
			Use:     "encryption",
			KeyInfo: KeyInfo{KeyValues: []KeyValue{NewRSAKeyValue(certKey)}, X509Data: X509Data{X509Certificates: []X509Certificate{{Data: certData}}}},
		}}, want: toCert},
		{name: "key value that is not base64", descriptors: []KeyDescriptor{
			{Use: "encryption", KeyInfo: KeyInfo{KeyValues: []KeyValue{{RSAKeyValue: &RSAKeyValue{Modulus: "!!!", Exponent: "AQAB"}}}}},
			withCerts("encryption", certData),
		}, want: broken},
		{name: "key value with no modulus", descriptors: []KeyDescriptor{
			{Use: "encryption", KeyInfo: KeyInfo{KeyValues: []KeyValue{{RSAKeyValue: &RSAKeyValue{Exponent: "AQAB"}}}}},
		}, want: broken},
		{name: "key value with no exponent", descriptors: []KeyDescriptor{
			{Use: "encryption", KeyInfo: KeyInfo{KeyValues: []KeyValue{{RSAKeyValue: &RSAKeyValue{Modulus: NewRSAKeyValue(certKey).RSAKeyValue.Modulus}}}}},
		}, want: broken},

		// A key value is only read as an RSAKeyValue, and a name is not a key.
		{name: "EC key value for encryption", descriptors: []KeyDescriptor{parsed(keyValueTestECKeyDescriptor, "encryption")}, want: failClosed},
		{name: "EC key value with no use", descriptors: []KeyDescriptor{parsed(keyValueTestECKeyDescriptor, "")}, want: failClosed},
		{name: "EC key value for signing only", descriptors: []KeyDescriptor{parsed(keyValueTestECKeyDescriptor, "signing")}, want: plaintext},
		{name: "DSA key value for encryption", descriptors: []KeyDescriptor{parsed(keyValueTestDSAKeyDescriptor, "encryption")}, want: failClosed},
		{name: "DSA key value for signing only", descriptors: []KeyDescriptor{parsed(keyValueTestDSAKeyDescriptor, "signing")}, want: plaintext},
		{name: "key name for encryption", descriptors: []KeyDescriptor{parsed(keyValueTestKeyNameDescriptor, "encryption")}, want: failClosed},
		{name: "key name with no use", descriptors: []KeyDescriptor{parsed(keyValueTestKeyNameDescriptor, "")}, want: failClosed},
		{name: "key name for signing only", descriptors: []KeyDescriptor{parsed(keyValueTestKeyNameDescriptor, "signing")}, want: plaintext},
		{name: "key name for encryption and a signing certificate", descriptors: []KeyDescriptor{parsed(keyValueTestKeyNameDescriptor, "encryption"), withCerts("signing", certData)}, want: failClosed},
		{name: "EC key value then certificate", descriptors: []KeyDescriptor{parsed(keyValueTestECKeyDescriptor, "encryption"), withCerts("encryption", certData)}, want: toCert},
		{name: "EC key value then RSA key value", descriptors: []KeyDescriptor{parsed(keyValueTestECKeyDescriptor, "encryption"), withKeyValue("", &rsa2048.PublicKey)}, want: toKeyValue, key: &rsa2048.PublicKey},

		// An elliptic curve key on P-256, P-384 or P-521 is agreed with by ECDH-ES, and one on another curve is not
		// a key that can be encrypted to.
		{name: "EC certificate", descriptors: []KeyDescriptor{withCerts("encryption", ecData)}, want: toECCert},
		{name: "EC certificate with no use", descriptors: []KeyDescriptor{withCerts("", ecData)}, want: toECCert},
		{name: "EC certificate then RSA certificate", descriptors: []KeyDescriptor{withCerts("encryption", ecData), withCerts("encryption", certData)}, want: toECCert},
		{name: "P-224 certificate", descriptors: []KeyDescriptor{withCerts("encryption", p224Data)}, want: failClosed},
		{name: "P-224 certificate then RSA certificate", descriptors: []KeyDescriptor{withCerts("encryption", p224Data), withCerts("encryption", certData)}, want: toCert},
	} {
		t.Run(tc.name, func(t *testing.T) {
			descriptor := SPSSODescriptor{SSODescriptor: SSODescriptor{RoleDescriptor: RoleDescriptor{KeyDescriptors: tc.descriptors}}}
			req := &IdpAuthnRequest{
				IDP:                     &test.IDP,
				Now:                     now,
				SPSSODescriptor:         &descriptor,
				ServiceProviderMetadata: &EntityDescriptor{EntityID: "https://sp.example.com/saml2/metadata", SPSSODescriptors: []SPSSODescriptor{descriptor}},
			}

			key, err := req.spEncryptionKey()

			switch tc.want {
			case toCert:
				require.NoError(t, err)
				assert.True(t, test.SPCertificate.Equal(key.Certificate))
				assert.True(t, certKey.Equal(key.PublicKey))
				assert.NotNil(t, req.spEncryptionKeyDescriptor())
			case toECCert:
				require.NoError(t, err)
				assert.True(t, ecdsaCert.Equal(key.Certificate))
				assert.True(t, ecdsaCert.PublicKey.(*ecdsa.PublicKey).Equal(key.PublicKey))
				assert.NotNil(t, req.spEncryptionKeyDescriptor())
			case toKeyValue:
				require.NoError(t, err)
				assert.Nil(t, key.Certificate)
				assert.True(t, tc.key.Equal(key.PublicKey))
				assert.NotNil(t, req.spEncryptionKeyDescriptor())
			case plaintext:
				assert.Equal(t, os.ErrNotExist, err)
				assert.Nil(t, key)
				assert.Nil(t, req.spEncryptionKeyDescriptor())
			case failClosed:
				// Not os.ErrNotExist, which would send the assertion in plaintext.
				assert.ErrorContains(t, err, "allows encryption but has no usable key")
				assert.False(t, errors.Is(err, os.ErrNotExist))
				assert.Nil(t, key)
				assert.Nil(t, req.spEncryptionKeyDescriptor())
			case broken:
				assert.ErrorContains(t, err, "cannot ")
				assert.False(t, errors.Is(err, os.ErrNotExist))
				assert.Nil(t, key)

				// The service provider is not taken to have no key, which is how a request for an EncryptedID
				// would be answered as if it could not be met rather than as the error it is.
				assert.NotNil(t, req.spEncryptionKeyDescriptor())
			}
		})
	}
}

// What the selection decides is what is sent: an assertion in plaintext only to a service provider whose
// metadata has no key that might be for encryption.
func TestIDPKeyValueFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name      string
		template  string
		use       string
		plaintext bool
	}{
		{name: "EC key value for encryption", template: keyValueTestECKeyDescriptor, use: "encryption"},
		{name: "EC key value with no use", template: keyValueTestECKeyDescriptor},
		{name: "EC key value for signing", template: keyValueTestECKeyDescriptor, use: "signing", plaintext: true},
		{name: "key name for encryption", template: keyValueTestKeyNameDescriptor, use: "encryption"},
		{name: "key name with no use", template: keyValueTestKeyNameDescriptor},
		{name: "key name for signing", template: keyValueTestKeyNameDescriptor, use: "signing", plaintext: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, req := encryptedPartsRequest(t)
			req.SPSSODescriptor.KeyDescriptors = []KeyDescriptor{parsedKeyDescriptor(t, tc.template, tc.use)}

			require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, encryptedPartsSession))

			err := req.MakeResponse()
			if !tc.plaintext {
				assert.ErrorContains(t, err, "allows encryption but has no usable key")
				assert.Nil(t, req.AssertionEl)
				assert.Nil(t, req.ResponseEl)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, req.AssertionEl.Tag, "Assertion")
			assert.NotNil(t, req.ResponseEl.FindElement("./Assertion"))
			assert.Nil(t, req.ResponseEl.FindElement("./EncryptedAssertion"))
		})
	}
}

// A whitespace-only certificate in the metadata as it is read from XML doesn't hide the key after it.
func TestIDPEncryptsPastWhitespaceCertificate(t *testing.T) {
	blank := KeyDescriptor{Use: "encryption", KeyInfo: KeyInfo{X509Data: X509Data{X509Certificates: []X509Certificate{{Data: "\n      "}}}}}

	for name, edit := range map[string]func(descriptor *SPSSODescriptor){
		"across descriptors": func(descriptor *SPSSODescriptor) {
			descriptor.KeyDescriptors = append([]KeyDescriptor{blank}, descriptor.KeyDescriptors...)
		},
		"in one descriptor": func(descriptor *SPSSODescriptor) {
			certificates := &descriptor.KeyDescriptors[0].KeyInfo.X509Data.X509Certificates
			*certificates = append([]X509Certificate{{Data: "\n      "}}, *certificates...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			test, req := encryptedPartsRequest(t)
			edit(req.SPSSODescriptor)

			buf, err := xml.Marshal(req.ServiceProviderMetadata)
			require.NoError(t, err)

			req.ServiceProviderMetadata = &EntityDescriptor{}
			require.NoError(t, xml.Unmarshal(buf, req.ServiceProviderMetadata))
			req.SPSSODescriptor = &req.ServiceProviderMetadata.SPSSODescriptors[0]
			req.ACSEndpoint = &req.SPSSODescriptor.AssertionConsumerServices[0]

			assert.Equal(t, req.SPSSODescriptor.KeyDescriptors[0].KeyInfo.X509Data.X509Certificates[0].Data, "\n      ")

			body := respond(t, req)

			encryptedKey := req.ResponseEl.FindElement("./EncryptedAssertion/EncryptedData/KeyInfo/EncryptedKey")
			require.True(t, encryptedKey != nil, "the assertion is not encrypted: %s", body)
			assert.Equal(t, encryptedKey.FindElement("./KeyInfo/X509Data/X509Certificate").Text(), base64.StdEncoding.EncodeToString(test.SP.Certificate.Raw))

			_, err = test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
			require.NoError(t, err)
		})
	}
}

// The NameID of a LogoutRequest is encrypted to the key the assertion was (SAMLProfiles §4.4.4.1).
func TestLogoutRequestToParticipantWithKeyValueKey(t *testing.T) {
	f := newPropagationFixture(t)
	nameIDTestServiceProviders(f.test, func(metadata *EntityDescriptor) { *metadata = *keyValueMetadata(t, metadata) }, f.a, f.b)
	f.encryptParticipants(f.a.MetadataURL.String())

	enforcer := &recordingEnforcer{}
	f.test.IDP.EncryptionKeyEnforcer = enforcer

	el := sentLogoutRequestElement(t, f.a, sentLogoutRequest(t, f.startLogout(t)))
	checkEncryptedLogoutRequest(t, f.test, f.a, el)

	encryptedID, err := findOneChild(el, samlAssertionNamespace, "EncryptedID")
	require.NoError(t, err)
	checkKeyValueKeyInfo(t, encryptedID, f.a.Certificate.PublicKey.(*rsa.PublicKey))

	require.Len(t, enforcer.keys, 1)
	assert.Nil(t, enforcer.keys[0].Certificate)
}

// The identifier of a NameIDMappingResponse is encrypted to the key of its target (SAMLProfiles §4.6.4.2).
func TestNameIDMappingToKeyValueKey(t *testing.T) {
	f := newNameIDMappingFixture(t)
	nameIDTestServiceProviders(f.test, func(metadata *EntityDescriptor) {
		if metadata.EntityID == f.b.MetadataURL.String() {
			*metadata = *keyValueMetadata(t, metadata)
		}
	}, f.a, f.b, f.c)

	enforcer := &recordingEnforcer{}
	f.test.IDP.EncryptionKeyEnforcer = enforcer

	result := f.send(t, nameIDMappingOptions{})
	checkStatus(t, result.Response.Status, StatusSuccess, "")

	encryptedID := result.Element.FindElement("./EncryptedID")
	require.NotNil(t, encryptedID)
	checkKeyValueKeyInfo(t, encryptedID, f.b.Certificate.PublicKey.(*rsa.PublicKey))
	assert.Equal(t, encryptedID.FindElement("./EncryptedData/KeyInfo/EncryptedKey").SelectAttrValue("Recipient", ""), f.b.MetadataURL.String())

	nameID, err := f.b.DecryptNameID(reparse(t, encryptedID))
	require.NoError(t, err)
	assert.Equal(t, nameID.Value, "b-alice")

	require.Len(t, enforcer.keys, 1)
	assert.Nil(t, enforcer.keys[0].Certificate)
	assert.True(t, f.b.Certificate.PublicKey.(*rsa.PublicKey).Equal(enforcer.keys[0].PublicKey))

	// A refusal of the key refuses the mapping.
	enforcer.err = errors.New("this key is not allowed")

	f.send(t, nameIDMappingOptions{}).checkNoIdentifier(t, StatusRequester, StatusInvalidNameIDPolicy)
}

// The answer to a query is encrypted to the key of the requester like the assertion of single sign-on.
func TestQueryAnswerEncryptedToKeyValueKey(t *testing.T) {
	f := newQueryFixture(t)
	f.metadata = func(metadata *EntityDescriptor) {
		metadata.SPSSODescriptors[0].AttributeConsumingServices = []AttributeConsumingService{service(1, nil, requested(mailAttributeName, uriAttrNameFormat))}
		*metadata = *keyValueMetadata(t, metadata)
	}

	enforcer := &recordingEnforcer{}
	f.test.IDP.EncryptionKeyEnforcer = enforcer

	// parseQueryResponse decrypts the assertion with the key of the service provider.
	response := f.queryAttributes(t, f.attributeQuery())
	assertQueryStatus(t, response, StatusSuccess, "")
	require.Len(t, response.Assertions, 1)
	assert.Equal(t, response.Encrypted, 1)

	require.True(t, len(enforcer.keys) != 0)
	assert.Nil(t, enforcer.keys[0].Certificate)
	assert.True(t, f.test.SP.Certificate.PublicKey.(*rsa.PublicKey).Equal(enforcer.keys[0].PublicKey))

	enforcer.err = errors.New("this key is not allowed")
	response = f.queryAttributes(t, f.attributeQuery())
	assertQueryStatus(t, response, StatusResponder, "")
	assert.Len(t, response.Assertions, 0)
}
