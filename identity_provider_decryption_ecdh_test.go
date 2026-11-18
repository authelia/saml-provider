package saml

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hsmKeyAgreer is an elliptic curve key that is not an *ecdh.PrivateKey or an *ecdsa.PrivateKey, as one in a
// hardware security module is not, whose Public returns an *ecdsa.PublicKey, and which counts its operations.
type hsmKeyAgreer struct {
	key   *ecdsa.PrivateKey
	calls int
}

func (h *hsmKeyAgreer) Public() crypto.PublicKey { return &h.key.PublicKey }

func (h *hsmKeyAgreer) ECDH(remote *ecdh.PublicKey) ([]byte, error) {
	h.calls++

	private, err := h.key.ECDH()
	if err != nil {
		return nil, err
	}

	return private.ECDH(remote)
}

// ecEncryptionPair returns an elliptic curve key on curve and a certificate for it with keyUsage.
func ecEncryptionPair(t *testing.T, curve elliptic.Curve, keyUsage x509.KeyUsage) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	now := TimeNow()

	return key, makeSPCert(t, spCertTemplate{key: key, notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour), keyUsage: keyUsage})
}

// ecdhIDP returns an identity provider whose encryption key is key, with cert, and whose service provider holds
// its metadata.
func ecdhIDP(t *testing.T, key crypto.PrivateKey, cert *x509.Certificate) *IdentityProviderTest {
	t.Helper()

	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = cert, key
	require.NoError(t, test.IDP.CheckEncryptionKeys())

	test.SP.IDPMetadata = test.IDP.Metadata()

	return test
}

// encrypterToIDPKey returns an encrypter of the service provider to cert, which the identity provider of test may
// hold, with the algorithms that are negotiated for it when its metadata lists nothing.
func encrypterToIDPKey(t *testing.T, test *IdentityProviderTest, cert *x509.Certificate) *elementEncrypter {
	t.Helper()

	policy, err := test.IDP.encryptionPolicy()
	require.NoError(t, err)

	encrypter, err := policy.encrypterFor(nil, Issuance{}, cert.PublicKey)
	require.NoError(t, err)

	return &elementEncrypter{certificate: cert, publicKey: cert.PublicKey, encrypter: encrypter, recipient: test.IDP.entityID()}
}

// decryptAtIDP decrypts the EncryptedID with the keys of the identity provider of test.
func decryptAtIDP(t *testing.T, test *IdentityProviderTest, encryptedID *etree.Element) (*NameID, error) {
	t.Helper()

	decrypter, err := test.IDP.elementDecrypter()
	require.NoError(t, err)

	return decrypter.decryptNameID(reparse(t, encryptedID))
}

func TestIDPCheckECEncryptionKeys(t *testing.T) {
	p256, p256Cert := ecEncryptionPair(t, elliptic.P256(), x509.KeyUsageKeyAgreement)
	p521, p521Cert := ecEncryptionPair(t, elliptic.P521(), 0)
	other, _ := ecEncryptionPair(t, elliptic.P256(), 0)
	p224, p224Cert := ecEncryptionPair(t, elliptic.P224(), 0)
	signing, signingCert := ecEncryptionPair(t, elliptic.P256(), x509.KeyUsageDigitalSignature)

	p256ECDH, err := p256.ECDH()
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		cert *x509.Certificate
		key  crypto.PrivateKey
		err  string
	}{
		"ecdsa key":                   {p256Cert, p256, ""},
		"ecdh key":                    {p256Cert, p256ECDH, ""},
		"key agreer":                  {p256Cert, &hsmKeyAgreer{key: p256}, ""},
		"P-521 without key usage":     {p521Cert, p521, ""},
		"another key":                 {p256Cert, other, "the private key is not that of the certificate"},
		"another key agreer":          {p256Cert, &hsmKeyAgreer{key: other}, "the private key is not that of the certificate"},
		"P-224":                       {p224Cert, p224, "not on P-256, P-384 or P-521"},
		"signing only":                {signingCert, signing, "does not include key agreement"},
		"nil ecdsa key":               {p256Cert, (*ecdsa.PrivateKey)(nil), "must be set together"},
		"nil ecdh key":                {p256Cert, (*ecdh.PrivateKey)(nil), "must be set together"},
		"something that is not a key": {p256Cert, "key", "must be an *ecdsa.PrivateKey or an xmlenc.KeyAgreer"},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = tc.cert, tc.key

			err := test.IDP.CheckEncryptionKeys()
			if tc.err == "" {
				require.NoError(t, err)

				return
			}

			assert.ErrorContains(t, err, tc.err)
		})
	}
}

// The metadata publishes an elliptic curve encryption key with ECDH-ES and the key wraps, and no key transport.
func TestIDPMetadataPublishesECEncryptionKey(t *testing.T) {
	key, cert := ecEncryptionPair(t, elliptic.P256(), x509.KeyUsageKeyAgreement)

	test := ecdhIDP(t, key, cert)

	descriptors := encryptionKeyDescriptors(test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors)
	require.Len(t, descriptors, 1)

	algorithms := make([]string, 0, len(descriptors[0].EncryptionMethods))
	for _, method := range descriptors[0].EncryptionMethods {
		algorithms = append(algorithms, method.Algorithm)
	}

	assert.Equal(t, algorithms, []string{aes128GCM, aes192GCM, aes256GCM, aes128CBC, aes192CBC, aes256CBC, ecdhES, kwAES256, kwAES192, kwAES128})

	test.IDP.KeyWrapMethods = []string{kwAES128}

	descriptors = encryptionKeyDescriptors(test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors)
	assert.Equal(t, descriptors[0].EncryptionMethods[len(descriptors[0].EncryptionMethods)-1].Algorithm, kwAES128)
}

// An elliptic curve signing key is never used to decrypt, so it is not published for encryption.
func TestIDPDoesNotDecryptWithECSigningKey(t *testing.T) {
	key, cert := newECDSATestKey(t, elliptic.P256())

	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.Key, test.IDP.Certificate = key, cert

	assert.Len(t, encryptionKeyDescriptors(test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors), 0)

	_, keys, err := test.IDP.encryptionKeys()
	require.NoError(t, err)
	assert.Len(t, keys, 0)
}

// The service provider of this package encrypts an EncryptedID to the elliptic curve key in the metadata of the
// identity provider, which decrypts it, whatever form its key is in.
func TestSPEncryptsToECKeyOfIDP(t *testing.T) {
	key, cert := ecEncryptionPair(t, elliptic.P256(), x509.KeyUsageKeyAgreement)

	ecdhKey, err := key.ECDH()
	require.NoError(t, err)

	for name, private := range map[string]crypto.PrivateKey{"ecdsa": key, "ecdh": ecdhKey, "key agreer": &hsmKeyAgreer{key: key}} {
		t.Run(name, func(t *testing.T) {
			test := ecdhIDP(t, private, cert)
			test.SP.EncryptNameID = true

			request, err := test.SP.MakeLogoutRequest("https://idp.example.com/saml/slo", "alice")
			require.NoError(t, err)
			require.NotNil(t, request.EncryptedID)
			assert.NotNil(t, request.EncryptedID.FindElement("./EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod"))

			nameID, err := decryptAtIDP(t, test, request.EncryptedID)
			require.NoError(t, err)
			assert.Equal(t, nameID.Value, "alice")

			if agreer, ok := private.(*hsmKeyAgreer); ok {
				assert.Equal(t, agreer.calls, 1)
			}
		})
	}
}

// Keys of either type may be the encryption key and DecryptionKeys at once, so that a key can be replaced by one of
// the other type, and what was encrypted to each is decrypted with it alone.
func TestIDPDecryptsWithRSAAndECKeysTogether(t *testing.T) {
	ecKey, ecCert := ecEncryptionPair(t, elliptic.P384(), 0)
	rsaPair := encryptionTestPair(t, 0, "rsa")

	ecAgreer := &hsmKeyAgreer{key: ecKey}
	rsaDecrypter := &countingDecrypter{key: encryptionTestKeys()[0]}

	for name, configure := range map[string]func(*IdentityProvider){
		"ec published": func(idp *IdentityProvider) {
			idp.EncryptionCertificate, idp.EncryptionKey = ecCert, ecAgreer
			idp.DecryptionKeys = []DecryptionKey{{Certificate: rsaPair.Certificate, Key: rsaDecrypter}}
		},
		"rsa published": func(idp *IdentityProvider) {
			idp.EncryptionCertificate, idp.EncryptionKey = rsaPair.Certificate, rsaDecrypter
			idp.DecryptionKeys = []DecryptionKey{{Certificate: ecCert, Key: ecAgreer}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			configure(&test.IDP)
			require.NoError(t, test.IDP.CheckEncryptionKeys())

			for _, cert := range []*x509.Certificate{ecCert, rsaPair.Certificate} {
				ecAgreer.calls, rsaDecrypter.calls = 0, 0

				encryptedID, err := encrypterToIDPKey(t, test, cert).encryptNameID(&testEncryptedNameID)
				require.NoError(t, err)

				nameID, err := decryptAtIDP(t, test, encryptedID)
				require.NoError(t, err)
				assert.Equal(t, nameID.Value, testEncryptedNameID.Value)

				// Only the key of the type that the EncryptedKey is for is asked.
				if cert == ecCert {
					assert.Equal(t, ecAgreer.calls, 1)
					assert.Equal(t, rsaDecrypter.calls, 0)
				} else {
					assert.Equal(t, ecAgreer.calls, 0)
					assert.Equal(t, rsaDecrypter.calls, 1)
				}
			}
		})
	}
}

// Of several elliptic curve keys, the one that the RecipientKeyInfo names is the one asked.
func TestIDPChoosesECKeyByRecipientKeyInfo(t *testing.T) {
	first, firstCert := ecEncryptionPair(t, elliptic.P256(), 0)
	second, secondCert := ecEncryptionPair(t, elliptic.P256(), 0)

	firstAgreer, secondAgreer := &hsmKeyAgreer{key: first}, &hsmKeyAgreer{key: second}

	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = firstCert, firstAgreer
	test.IDP.DecryptionKeys = []DecryptionKey{{Certificate: secondCert, Key: secondAgreer}}
	require.NoError(t, test.IDP.CheckEncryptionKeys())

	encryptedID, err := encrypterToIDPKey(t, test, secondCert).encryptNameID(&testEncryptedNameID)
	require.NoError(t, err)

	_, err = decryptAtIDP(t, test, encryptedID)
	require.NoError(t, err)
	assert.Equal(t, firstAgreer.calls, 0)
	assert.Equal(t, secondAgreer.calls, 1)

	// Without the hint, each key is asked, and the one that holds it decrypts.
	encryptedID.FindElement(".//AgreementMethod").RemoveChild(encryptedID.FindElement(".//RecipientKeyInfo"))

	firstAgreer.calls, secondAgreer.calls = 0, 0

	_, err = decryptAtIDP(t, test, encryptedID)
	require.NoError(t, err)
	assert.Equal(t, firstAgreer.calls, 1)
	assert.Equal(t, secondAgreer.calls, 1)
}

// What is encrypted to an elliptic curve key is only decrypted with the algorithms that the identity provider
// allows.
func TestIDPRefusesECDHItDoesNotAllow(t *testing.T) {
	key, cert := ecEncryptionPair(t, elliptic.P256(), 0)

	for name, tc := range map[string]struct {
		configure func(*IdentityProvider)
		mutate    func(encryptedKey *etree.Element)
		err       string
	}{
		"key wrap the identity provider excludes": {
			func(idp *IdentityProvider) { idp.KeyWrapMethods = []string{kwAES128} }, nil,
			`the key wrap algorithm "http://www.w3.org/2001/04/xmlenc#kw-aes256" is not allowed`,
		},
		"sha-1 key derivation": {nil, func(k *etree.Element) {
			k.FindElement(".//ConcatKDFParams/DigestMethod").CreateAttr("Algorithm", digestSHA1)
		}, "the key derivation digest"},
		"another key derivation": {nil, func(k *etree.Element) {
			k.FindElement(".//KeyDerivationMethod").CreateAttr("Algorithm", "http://www.w3.org/2009/xmlenc11#pbkdf2")
		}, "does not derive its key with ConcatKDF"},
		"another key agreement": {nil, func(k *etree.Element) {
			k.FindElement(".//AgreementMethod").CreateAttr("Algorithm", "http://www.w3.org/2009/xmlenc11#dh-es")
		}, "the key agreement algorithm"},
		"no key agreement": {nil, func(k *etree.Element) {
			k.RemoveChild(k.FindElement("./KeyInfo"))
		}, "not agreed with this entity"},
	} {
		t.Run(name, func(t *testing.T) {
			test := ecdhIDP(t, key, cert)

			encryptedID, err := encrypterToIDPKey(t, test, cert).encryptNameID(&testEncryptedNameID)
			require.NoError(t, err)

			if tc.configure != nil {
				tc.configure(&test.IDP)
			}

			if tc.mutate != nil {
				tc.mutate(encryptedID.FindElement("./EncryptedData/KeyInfo/EncryptedKey"))
			}

			_, err = decryptAtIDP(t, test, encryptedID)
			assert.ErrorContains(t, err, tc.err)
		})
	}
}

// What is encrypted to an RSA key isn't decrypted by an identity provider which only has an elliptic curve key, and
// the other way round, without asking either key.
func TestIDPRefusesEncryptedKeyOfAnotherType(t *testing.T) {
	ecKey, ecCert := ecEncryptionPair(t, elliptic.P256(), 0)
	ecAgreer := &hsmKeyAgreer{key: ecKey}

	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = ecCert, ecAgreer
	require.NoError(t, test.IDP.CheckEncryptionKeys())

	encryptedID, err := encrypterToIDPKey(t, test, encryptionTestPair(t, 0, "rsa").Certificate).encryptNameID(&testEncryptedNameID)
	require.NoError(t, err)

	_, err = decryptAtIDP(t, test, encryptedID)
	assert.ErrorContains(t, err, "no private key of the type")
	assert.Equal(t, ecAgreer.calls, 0)
}

// xmlsec1ECDHEncryptedIDTemplate is what xmlsec1 fills in to encrypt a NameID to the identity provider with ECDH-ES,
// for the key it has loaded as recipient, from an ephemeral key it has loaded as originator.
const xmlsec1ECDHEncryptedIDTemplate = `<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
	xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" Type="http://www.w3.org/2001/04/xmlenc#Element">
<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
<ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes256"/>
<ds:KeyInfo><xenc:AgreementMethod Algorithm="http://www.w3.org/2009/xmlenc11#ECDH-ES">
<xenc11:KeyDerivationMethod Algorithm="http://www.w3.org/2009/xmlenc11#ConcatKDF">
<xenc11:ConcatKDFParams AlgorithmID="00" PartyUInfo="00" PartyVInfo="00">
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></xenc11:ConcatKDFParams></xenc11:KeyDerivationMethod>
<xenc:OriginatorKeyInfo><ds:KeyName>originator</ds:KeyName><ds:KeyValue/></xenc:OriginatorKeyInfo>
<xenc:RecipientKeyInfo><ds:KeyName>recipient</ds:KeyName></xenc:RecipientKeyInfo>
</xenc:AgreementMethod></ds:KeyInfo><xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>
<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>`

// What xmlsec1 encrypts to the elliptic curve key of the identity provider, the identity provider decrypts.
func TestIDPDecryptsECDHOfXMLSec1(t *testing.T) {
	xmlsec1, err := exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("xmlsec1 is not installed")
	}

	key, cert := ecEncryptionPair(t, elliptic.P256(), x509.KeyUsageKeyAgreement)
	originator, _ := ecEncryptionPair(t, elliptic.P256(), 0)

	originatorDER, err := x509.MarshalPKCS8PrivateKey(originator)
	require.NoError(t, err)

	recipientDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, data, 0o600))

		return path
	}

	originatorPath := write("originator.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: originatorDER}))
	recipientPath := write("recipient.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: recipientDER}))
	templatePath := write("template.xml", []byte(xmlsec1ECDHEncryptedIDTemplate))

	nameID := testEncryptedNameID.Element()
	nameID.CreateAttr("xmlns:saml", samlAssertionNamespace)

	doc := etree.NewDocument()
	doc.SetRoot(nameID)

	data, err := doc.WriteToBytes()
	require.NoError(t, err)

	dataPath, outPath := write("data.xml", data), filepath.Join(dir, "out.xml")

	out, err := exec.Command(xmlsec1, "--encrypt", "--enabled-key-data", "agreement-method,enc-key,key-value,key-name,ec",
		"--max-encrypted-key-level", "3", "--session-key", "aes-256", "--privkey-pem:originator", originatorPath,
		"--pubkey-pem:recipient", recipientPath, "--xml-data", dataPath, "--output", outPath, templatePath).CombinedOutput()
	require.NoError(t, err, "xmlsec1: %s", out)

	encrypted := etree.NewDocument()
	require.NoError(t, encrypted.ReadFromFile(outPath))

	encryptedID := etree.NewElement("saml:EncryptedID")
	encryptedID.CreateAttr("xmlns:saml", samlAssertionNamespace)
	encryptedID.AddChild(encrypted.Root())

	test := ecdhIDP(t, key, cert)

	decrypted, err := decryptAtIDP(t, test, encryptedID)
	require.NoError(t, err)
	assert.Equal(t, decrypted.Value, testEncryptedNameID.Value)
}
