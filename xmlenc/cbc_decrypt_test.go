package xmlenc

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func cbcElement(cipher BlockCipher, ciphertext []byte) *etree.Element {
	el := etree.NewElement("EncryptedData")
	el.CreateElement("EncryptionMethod").CreateAttr("Algorithm", cipher.Algorithm())
	el.CreateElement("CipherData").CreateElement("CipherValue").SetText(base64.StdEncoding.EncodeToString(ciphertext))
	return el
}

func TestCBCDecryptRejectsCiphertextOfInvalidLength(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cipher    BlockCipher
		blockSize int
	}{
		{"aes-128", AES128CBC, 16},
		{"aes-192", AES192CBC, 16},
		{"aes-256", AES256CBC, 16},
		{"3des", TripleDES, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, tc.cipher.KeySize())
			for size := 0; size < 3*tc.blockSize+2; size++ {
				plaintext, err := tc.cipher.Decrypt(key, cbcElement(tc.cipher, make([]byte, size)))
				assert.Check(t, err != nil || size%tc.blockSize == 0 && size > tc.blockSize, "size %d: %q", size, plaintext)
			}
		})
	}
}

func TestTripleDESIsThreeKeyTripleDES(t *testing.T) {
	assert.Check(t, is.Equal(24, TripleDES.KeySize()))
	assert.Check(t, is.Equal("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", TripleDES.Algorithm()))

	_, err := TripleDES.Decrypt(make([]byte, 8), cbcElement(TripleDES, make([]byte, 16)))
	assert.Check(t, is.ErrorContains(err, "expected key to be 24 bytes"))
}

// The ciphertext was produced by OpenSSL, independently of this package:
//
//	openssl enc -des-ede3-cbc -provider legacy -provider default -nopad -K <key> -iv <iv> -in <padded plaintext>
func TestTripleDESDecryptsOpenSSLCiphertext(t *testing.T) {
	key, err := hex.DecodeString("0123456789abcdeffedcba9876543210f0e1d2c3b4a59687")
	assert.NilError(t, err)
	ciphertext, err := hex.DecodeString("a1b2c3d4e5f60718" + "37b247b7d79271079ff107be5f49009ab7fde1abe673e918")
	assert.NilError(t, err)

	plaintext, err := TripleDES.Decrypt(key, cbcElement(TripleDES, ciphertext))
	assert.NilError(t, err)
	assert.Check(t, is.Equal("<saml:Assertion/>", string(plaintext)))
}

func TestTripleDESRoundTrip(t *testing.T) {
	key := make([]byte, TripleDES.KeySize())
	for i := range key {
		key[i] = byte(i * 7)
	}
	el, err := TripleDES.Encrypt(key, []byte("hello world"), nil)
	assert.NilError(t, err)
	plaintext, err := TripleDES.Decrypt(key, el)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("hello world", string(plaintext)))
}
