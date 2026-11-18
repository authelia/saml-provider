package xmlenc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	assert.NilError(t, err)

	return b
}

// RFC 3394 §4.1, §4.3 and §4.6.
func TestAESKeyWrapVectors(t *testing.T) {
	for name, tc := range map[string]struct {
		wrap               AESKeyWrap
		kek, key, expected string
	}{
		"128-bit key with a 128-bit kek": {
			AES128KW, "000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF",
			"1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5",
		},
		"128-bit key with a 256-bit kek": {
			AES256KW, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF",
			"64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7",
		},
		"256-bit key with a 256-bit kek": {
			AES256KW, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			"00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
			"28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21",
		},
	} {
		t.Run(name, func(t *testing.T) {
			kek, key, expected := mustHex(t, tc.kek), mustHex(t, tc.key), mustHex(t, tc.expected)

			wrapped, err := tc.wrap.Wrap(kek, key)
			assert.NilError(t, err)
			assert.Check(t, is.DeepEqual(wrapped, expected))

			unwrapped, err := tc.wrap.Unwrap(kek, wrapped)
			assert.NilError(t, err)
			assert.Check(t, is.DeepEqual(unwrapped, key))

			wrapped[len(wrapped)-1] ^= 1
			_, err = tc.wrap.Unwrap(kek, wrapped)
			assert.Check(t, is.ErrorContains(err, "integrity"))
		})
	}
}

func TestAESKeyWrapRefusesBadLengths(t *testing.T) {
	kek := make([]byte, 16)

	_, err := AES128KW.Wrap(kek, make([]byte, 12))
	assert.Check(t, is.ErrorContains(err, "multiple of 8"))

	_, err = AES128KW.Wrap(make([]byte, 32), make([]byte, 16))
	assert.Check(t, is.ErrorContains(err, "16 bytes"))

	_, err = AES128KW.Unwrap(kek, make([]byte, 16))
	assert.Check(t, is.ErrorContains(err, "at least 24"))
}

func TestKDFParamEncoding(t *testing.T) {
	assert.Check(t, is.Equal(encodeKDFParam(nil), "00"))
	assert.Check(t, is.Equal(encodeKDFParam([]byte{0xD8}), "00D8"))

	for value, want := range map[string][]byte{"": nil, "00": {}, "00d8": {0xD8}} {
		got, err := decodeKDFParam("AlgorithmID", value)
		assert.NilError(t, err)
		assert.Check(t, is.DeepEqual(got, want), value)
	}

	// XML Encryption 1.1 §5.4.1: 03D8 is the five bits 11011, which aren't whole octets.
	_, err := decodeKDFParam("PartyUInfo", "03D8")
	assert.Check(t, is.ErrorContains(err, "whole number of octets"))

	_, err = decodeKDFParam("PartyUInfo", "zz")
	assert.Check(t, is.ErrorContains(err, "hexBinary"))
}

// ecTestCertificate returns a key on curve and a self-signed certificate for it.
func ecTestCertificate(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	assert.NilError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sp.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	assert.NilError(t, err)

	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)

	return key, cert
}

func TestECDHESRoundTrip(t *testing.T) {
	RandReader = rand.Reader

	plaintext := []byte(`<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">alice</saml:NameID>`)

	for name, curve := range map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()} {
		for _, wrap := range []AESKeyWrap{AES128KW, AES192KW, AES256KW} {
			for _, cipher := range []BlockCipher{AES128GCM, AES256GCM, AES256CBC} {
				t.Run(name+" "+wrap.Algorithm()+" "+cipher.Algorithm(), func(t *testing.T) {
					key, cert := ecTestCertificate(t, curve)

					e := ECDHES{BlockCipher: cipher, KeyWrap: wrap}

					el, err := e.Encrypt(cert, plaintext, nil)
					assert.NilError(t, err)

					decrypted, err := Decrypt(key, el)
					assert.NilError(t, err)
					assert.Check(t, is.DeepEqual(decrypted, plaintext))

					ecdhKey, err := key.ECDH()
					assert.NilError(t, err)

					decrypted, err = Decrypt(ecdhKey, el)
					assert.NilError(t, err)
					assert.Check(t, is.DeepEqual(decrypted, plaintext))
				})
			}
		}
	}
}

func TestECDHESStructure(t *testing.T) {
	RandReader = rand.Reader

	key, cert := ecTestCertificate(t, elliptic.P256())

	el, err := ECDH_ES().Encrypt(cert, []byte("<a/>"), nil)
	assert.NilError(t, err)

	assert.Check(t, is.Equal(el.FindElement("./EncryptionMethod").SelectAttrValue("Algorithm", ""), AES128GCM.Algorithm()))

	encryptedKey := el.FindElement("./KeyInfo/EncryptedKey")
	assert.Assert(t, encryptedKey != nil)
	assert.Check(t, is.Equal(encryptedKey.FindElement("./EncryptionMethod").SelectAttrValue("Algorithm", ""), AES256KW.Algorithm()))

	agreement := encryptedKey.FindElement("./KeyInfo/AgreementMethod")
	assert.Assert(t, agreement != nil)
	assert.Check(t, is.Equal(agreement.SelectAttrValue("Algorithm", ""), "http://www.w3.org/2009/xmlenc11#ECDH-ES"))

	params := agreement.FindElement("./KeyDerivationMethod/ConcatKDFParams")
	assert.Assert(t, params != nil)
	assert.Check(t, is.Equal(params.SelectAttrValue("AlgorithmID", ""), encodeKDFParam([]byte(AES256KW.Algorithm()))))
	assert.Check(t, is.Equal(params.SelectAttrValue("PartyUInfo", ""), "00"))
	assert.Check(t, is.Equal(params.FindElement("./DigestMethod").SelectAttrValue("Algorithm", ""), SHA256.Algorithm()))

	assert.Check(t, is.Equal(agreement.FindElement("./OriginatorKeyInfo/KeyValue/ECKeyValue/NamedCurve").SelectAttrValue("URI", ""), "urn:oid:1.2.840.10045.3.1.7"))
	assert.Check(t, is.Equal(agreement.FindElement("./RecipientKeyInfo/X509Data/X509Certificate").Text(), base64.StdEncoding.EncodeToString(cert.Raw)))

	// A bare key is named by its ECKeyValue.
	el, err = ECDH_ES().Encrypt(&key.PublicKey, []byte("<a/>"), nil)
	assert.NilError(t, err)

	recipient := el.FindElement("./KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/RecipientKeyInfo/KeyValue/ECKeyValue/PublicKey")
	assert.Assert(t, recipient != nil)

	ecdhKey, err := key.PublicKey.ECDH()
	assert.NilError(t, err)
	assert.Check(t, is.Equal(recipient.Text(), base64.StdEncoding.EncodeToString(ecdhKey.Bytes())))
}

func TestECDHESRefusesUnsupportedKeys(t *testing.T) {
	RandReader = rand.Reader

	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	assert.NilError(t, err)

	_, err = ECDH_ES().Encrypt(&p224.PublicKey, []byte("<a/>"), nil)
	assert.Check(t, is.ErrorContains(err, "P-256, P-384 or P-521"))

	_, rsaCert := ecTestCertificate(t, elliptic.P256())
	rsaCert.PublicKey = nil

	_, err = ECDH_ES().Encrypt(rsaCert, []byte("<a/>"), nil)
	assert.Check(t, is.ErrorContains(err, "elliptic curve"))

	_, err = ECDHES{BlockCipher: AES128GCM}.Encrypt(rsaCert, []byte("<a/>"), nil)
	assert.Check(t, is.ErrorContains(err, "KeyWrap"))
}

// ecdhesEncrypted returns an EncryptedData for key, and its EncryptedKey.
func ecdhesEncrypted(t *testing.T, key *ecdsa.PrivateKey) (*etree.Element, *etree.Element) {
	t.Helper()

	el, err := ECDH_ES().Encrypt(&key.PublicKey, []byte("<a/>"), nil)
	assert.NilError(t, err)

	return el, el.FindElement("./KeyInfo/EncryptedKey")
}

func TestECDHESDecryptFailures(t *testing.T) {
	RandReader = rand.Reader

	key, _ := ecTestCertificate(t, elliptic.P256())
	other, _ := ecTestCertificate(t, elliptic.P256())
	p384, _ := ecTestCertificate(t, elliptic.P384())

	for name, tc := range map[string]struct {
		key    any
		mutate func(el, encryptedKey *etree.Element)
		err    string
	}{
		"another key":         {other, func(_, _ *etree.Element) {}, "integrity"},
		"another curve":       {p384, func(_, _ *etree.Element) {}, "not that of the private key"},
		"rsa key":             {&rsa.PrivateKey{}, func(_, _ *etree.Element) {}, "expected key"},
		"unsupported key":     {"key", func(_, _ *etree.Element) {}, "expected key"},
		"no agreement method": {key, func(_, k *etree.Element) { k.RemoveChild(k.FindElement("./KeyInfo")) }, "AgreementMethod"},
		"other agreement": {key, func(_, k *etree.Element) {
			k.FindElement("./KeyInfo/AgreementMethod").CreateAttr("Algorithm", "http://www.w3.org/2009/xmlenc11#dh-es")
		}, "not implemented"},
		"other derivation": {key, func(_, k *etree.Element) {
			k.FindElement("./KeyInfo/AgreementMethod/KeyDerivationMethod").CreateAttr("Algorithm", "http://www.w3.org/2009/xmlenc11#pbkdf2")
		}, "not implemented"},
		"supplementary info": {key, func(_, k *etree.Element) {
			k.FindElement("./KeyInfo/AgreementMethod/KeyDerivationMethod/ConcatKDFParams").CreateAttr("SuppPubInfo", "00")
		}, "SuppPubInfo"},
		"changed algorithm id": {key, func(_, k *etree.Element) {
			k.FindElement("./KeyInfo/AgreementMethod/KeyDerivationMethod/ConcatKDFParams").CreateAttr("AlgorithmID", "00")
		}, "integrity"},
		"unknown digest": {key, func(_, k *etree.Element) {
			k.FindElement("./KeyInfo/AgreementMethod/KeyDerivationMethod/ConcatKDFParams/DigestMethod").CreateAttr("Algorithm", "urn:example:digest")
		}, "not implemented"},
		"unknown curve": {key, func(_, k *etree.Element) {
			k.FindElement("./KeyInfo/AgreementMethod/OriginatorKeyInfo/KeyValue/ECKeyValue/NamedCurve").CreateAttr("URI", "urn:oid:1.3.132.0.33")
		}, "not implemented"},
		"point off the curve": {key, func(_, k *etree.Element) {
			publicKey := k.FindElement("./KeyInfo/AgreementMethod/OriginatorKeyInfo/KeyValue/ECKeyValue/PublicKey")
			point, _ := base64.StdEncoding.DecodeString(publicKey.Text())
			point[len(point)-1] ^= 1
			publicKey.SetText(base64.StdEncoding.EncodeToString(point))
		}, "not on curve"},
	} {
		t.Run(name, func(t *testing.T) {
			el, encryptedKey := ecdhesEncrypted(t, key)
			tc.mutate(el, encryptedKey)

			_, err := Decrypt(tc.key, el)
			assert.Check(t, is.ErrorContains(err, tc.err))
		})
	}
}

// The agreed key wraps with a key encryption key that the caller may also give directly.
func TestAESKeyWrapDecryptWithKeyEncryptionKey(t *testing.T) {
	cek := make([]byte, 16)
	kek := make([]byte, 32)

	wrapped, err := AES256KW.Wrap(kek, cek)
	assert.NilError(t, err)

	el := etree.NewElement("xenc:EncryptedKey")
	el.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", AES256KW.Algorithm())
	el.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(wrapped))

	got, err := Decrypt(kek, el)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(got, cek))
}
