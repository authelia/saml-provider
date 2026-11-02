package xmlenc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func gcmCipherValue(t *testing.T, el *etree.Element) string {
	t.Helper()
	value := el.FindElement("./CipherData/CipherValue")
	assert.Assert(t, value != nil)
	return value.Text()
}

func TestGCMRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, AES128GCM.KeySize())
	plaintext := []byte("<saml:Assertion>secret</saml:Assertion>")

	for name, nonce := range map[string][]byte{
		"generated nonce": nil,
		"supplied nonce":  bytes.Repeat([]byte{9}, 12),
	} {
		t.Run(name, func(t *testing.T) {
			el, err := AES128GCM.Encrypt(key, plaintext, nonce)
			assert.NilError(t, err)

			decrypted, err := AES128GCM.Decrypt(key, el)
			assert.NilError(t, err)
			assert.Check(t, is.DeepEqual(plaintext, decrypted))
		})
	}
}

func TestGCMEncryptUsesThePlaintextAndAFreshNonce(t *testing.T) {
	key := bytes.Repeat([]byte{7}, AES128GCM.KeySize())

	first, err := AES128GCM.Encrypt(key, []byte("first message!!!"), nil)
	assert.NilError(t, err)
	again, err := AES128GCM.Encrypt(key, []byte("first message!!!"), nil)
	assert.NilError(t, err)
	assert.Check(t, gcmCipherValue(t, first) != gcmCipherValue(t, again), "a nonce must not repeat")

	nonce := bytes.Repeat([]byte{9}, 12)
	a, err := AES128GCM.Encrypt(key, []byte("first message!!!"), nonce)
	assert.NilError(t, err)
	b, err := AES128GCM.Encrypt(key, []byte("other message!!!"), nonce)
	assert.NilError(t, err)
	assert.Check(t, gcmCipherValue(t, a) != gcmCipherValue(t, b), "the ciphertext must depend on the plaintext")
}

func TestGCMEncryptRejectsAWrongNonceLength(t *testing.T) {
	key := bytes.Repeat([]byte{7}, AES128GCM.KeySize())
	_, err := AES128GCM.Encrypt(key, []byte("message"), []byte{1, 2, 3})
	assert.Check(t, is.ErrorContains(err, "nonce"))
}

func TestGCMEncryptDoesNotModifyTheNonce(t *testing.T) {
	key := bytes.Repeat([]byte{7}, AES128GCM.KeySize())
	nonce := bytes.Repeat([]byte{9}, 12)
	withSpareCapacity := append(make([]byte, 0, 64), nonce...)
	_, err := AES128GCM.Encrypt(key, []byte("message"), withSpareCapacity)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(nonce, withSpareCapacity))
}

func TestGCMRoundTripThroughOAEP(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)

	encrypter := OAEP()
	encrypter.BlockCipher = AES128GCM
	encrypter.DigestMethod = &SHA1

	plaintext := []byte("<saml:Assertion>secret</saml:Assertion>")
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	assert.NilError(t, err)
	certificate, err := x509.ParseCertificate(der)
	assert.NilError(t, err)

	el, err := encrypter.Encrypt(certificate, plaintext, nil)
	assert.NilError(t, err)

	decrypted, err := Decrypt(key, el)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(plaintext, decrypted))
}

func TestGCMDecryptRejectsShortCiphertext(t *testing.T) {
	key := make([]byte, AES128GCM.KeySize())
	for _, size := range []int{0, 1, 11, 12, 27} {
		el, err := AES128GCM.Encrypt(key, []byte("plaintext"), nil)
		if err != nil {
			t.Fatal(err)
		}
		el.FindElement("./CipherData/CipherValue").SetText(base64.StdEncoding.EncodeToString(make([]byte, size)))
		if _, err = AES128GCM.Decrypt(key, el); err == nil {
			t.Errorf("expected an error for a ciphertext of %d bytes", size)
		}
	}
}
