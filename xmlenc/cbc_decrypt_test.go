package xmlenc

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				assert.True(t, err != nil || size%tc.blockSize == 0 && size > tc.blockSize, "size %d: %q", size, plaintext)
			}
		})
	}
}

func TestTripleDESIsThreeKeyTripleDES(t *testing.T) {
	assert.Equal(t, 24, TripleDES.KeySize())
	assert.Equal(t, "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", TripleDES.Algorithm())

	_, err := TripleDES.Decrypt(make([]byte, 8), cbcElement(TripleDES, make([]byte, 16)))
	assert.ErrorContains(t, err, "expected key to be 24 bytes")
}

// The ciphertext was produced by OpenSSL, independently of this package:
//
//	openssl enc -des-ede3-cbc -provider legacy -provider default -nopad -K <key> -iv <iv> -in <padded plaintext>
func TestTripleDESDecryptsOpenSSLCiphertext(t *testing.T) {
	key, err := hex.DecodeString("0123456789abcdeffedcba9876543210f0e1d2c3b4a59687")
	require.NoError(t, err)
	ciphertext, err := hex.DecodeString("a1b2c3d4e5f60718" + "37b247b7d79271079ff107be5f49009ab7fde1abe673e918")
	require.NoError(t, err)

	plaintext, err := TripleDES.Decrypt(key, cbcElement(TripleDES, ciphertext))
	require.NoError(t, err)
	assert.Equal(t, "<saml:Assertion/>", string(plaintext))
}

func TestTripleDESRoundTrip(t *testing.T) {
	key := make([]byte, TripleDES.KeySize())
	for i := range key {
		key[i] = byte(i * 7)
	}

	el, err := TripleDES.Encrypt(key, []byte("hello world"), nil)
	require.NoError(t, err)
	plaintext, err := TripleDES.Decrypt(key, el)
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(plaintext))
}

// XML Encryption §5.2: the last byte of the plaintext is the number of bytes of padding, which is at least one and
// at most a block. A larger number would otherwise remove that many bytes of the content, up to 255 of them.
func TestCBCDecryptRejectsPaddingLongerThanABlock(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cipher CBC
	}{
		{"aes-128", AES128CBC.(CBC)},
		{"aes-192", AES192CBC.(CBC)},
		{"aes-256", AES256CBC.(CBC)},
		{"3des", TripleDES.(CBC)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, tc.cipher.KeySize())
			for i := range key {
				key[i] = byte(i * 7)
			}

			block, err := tc.cipher.cipher(key)
			require.NoError(t, err)

			blockSize := block.BlockSize()
			content := strings.Repeat("<saml:Assertion/>", 16)[:17*blockSize]

			for last := range 256 {
				// The last block is all padding, whatever its last byte claims.
				padded := append([]byte(content), make([]byte, blockSize)...)
				padded[len(padded)-1] = byte(last)

				ciphertext := make([]byte, blockSize+len(padded))
				cipher.NewCBCEncrypter(block, ciphertext[:blockSize]).CryptBlocks(ciphertext[blockSize:], padded) //nolint:gosec // A fixed IV makes the test deterministic.

				plaintext, err := tc.cipher.Decrypt(key, cbcElement(tc.cipher, ciphertext))

				switch {
				case last == 0:
					assert.EqualError(t, err, "padding must be at least one byte")
				case last > blockSize:
					assert.EqualError(t, err, "padding must be at most one block", "padding of %d bytes: %q", last, plaintext)
				default:
					require.NoError(t, err)
					assert.Equal(t, content+string(make([]byte, blockSize-last)), string(plaintext))
				}
			}
		})
	}
}
