package xmlenc

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"github.com/beevik/etree"
)

// keyWrapIV is the default initial value of the AES Key Wrap of RFC 3394 §2.2.3.1.
var keyWrapIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// KeyWrap is a symmetric key wrap algorithm of XML Encryption §5.6, which encrypts a key with a key encryption key.
// It is the EncryptionMethod of an EncryptedKey whose key encryption key is agreed with key agreement, such as
// ECDH-ES.
type KeyWrap interface {
	Decrypter

	// KeySize is the size in bytes of the key encryption key.
	KeySize() int

	// Wrap returns key encrypted with kek.
	Wrap(kek, key []byte) ([]byte, error)

	// Unwrap returns the key that wrapped encrypts with kek, or an error if it is not one that kek wrapped.
	Unwrap(kek, wrapped []byte) ([]byte, error)
}

// AESKeyWrap is the AES Key Wrap of RFC 3394, which XML Encryption §5.6.3 identifies by the size of its key
// encryption key.
type AESKeyWrap struct {
	keySize   int
	algorithm string
}

var (
	// AES128KW is AES Key Wrap with a 128-bit key encryption key, which XML Encryption 1.1 §5.1 requires.
	AES128KW = AESKeyWrap{keySize: 16, algorithm: "http://www.w3.org/2001/04/xmlenc#kw-aes128"}

	// AES192KW is AES Key Wrap with a 192-bit key encryption key.
	AES192KW = AESKeyWrap{keySize: 24, algorithm: "http://www.w3.org/2001/04/xmlenc#kw-aes192"}

	// AES256KW is AES Key Wrap with a 256-bit key encryption key, which XML Encryption 1.1 §5.1 requires.
	AES256KW = AESKeyWrap{keySize: 32, algorithm: "http://www.w3.org/2001/04/xmlenc#kw-aes256"}
)

// Algorithm returns the identifier of the algorithm.
func (w AESKeyWrap) Algorithm() string {
	return w.algorithm
}

// KeySize returns the size in bytes of the key encryption key.
func (w AESKeyWrap) KeySize() int {
	return w.keySize
}

// Wrap implements KeyWrap with the wrapping process of RFC 3394 §2.2.1. The key must be a multiple of 64 bits and
// at least 128 bits long.
func (w AESKeyWrap) Wrap(kek, key []byte) ([]byte, error) {
	if len(kek) != w.keySize {
		return nil, ErrIncorrectKeyLength(w.keySize)
	}

	if len(key) < 16 || len(key)%8 != 0 {
		return nil, errors.New("the key to wrap must be a multiple of 8 bytes and at least 16 bytes long")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(key) / 8
	out := make([]byte, 8+len(key))
	copy(out, keyWrapIV)
	copy(out[8:], key)

	buf := make([]byte, 16)

	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			copy(buf, out[:8])
			copy(buf[8:], out[i*8:i*8+8])
			block.Encrypt(buf, buf)

			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(out[:8], binary.BigEndian.Uint64(buf[:8])^t)
			copy(out[i*8:i*8+8], buf[8:])
		}
	}

	return out, nil
}

// Unwrap implements KeyWrap with the unwrapping process of RFC 3394 §2.2.2, and its integrity check of §2.2.3.
func (w AESKeyWrap) Unwrap(kek, wrapped []byte) ([]byte, error) {
	if len(kek) != w.keySize {
		return nil, ErrIncorrectKeyLength(w.keySize)
	}

	if len(wrapped) < 24 || len(wrapped)%8 != 0 {
		return nil, errors.New("the wrapped key must be a multiple of 8 bytes and at least 24 bytes long")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(wrapped)/8 - 1
	a := binary.BigEndian.Uint64(wrapped[:8])
	r := make([]byte, len(wrapped)-8)
	copy(r, wrapped[8:])

	buf := make([]byte, 16)

	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i) //nolint:gosec // n is at most a key's length in blocks, and j at most 5.
			binary.BigEndian.PutUint64(buf[:8], a^t)
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Decrypt(buf, buf)

			a = binary.BigEndian.Uint64(buf[:8])
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}

	check := make([]byte, 8)
	binary.BigEndian.PutUint64(check, a)

	if subtle.ConstantTimeCompare(check, keyWrapIV) != 1 {
		return nil, errors.New("the wrapped key failed its integrity check")
	}

	return r, nil
}

// Decrypt implements Decrypter for an EncryptedKey that this algorithm wraps. The key is the key encryption key,
// a []byte, or the private key that it is agreed with, as the AgreementMethod of the EncryptedKey says: an
// *[ecdsa.PrivateKey] or *[ecdh.PrivateKey] for ECDH-ES (XML Encryption 1.1 §5.6.4).
func (w AESKeyWrap) Decrypt(key interface{}, ciphertextEl *etree.Element) ([]byte, error) {
	kek, ok := key.([]byte)
	if !ok {
		var err error

		if kek, err = agreedKey(key, ciphertextEl, w.keySize); err != nil {
			return nil, err
		}
	}

	wrapped, err := getCiphertext(ciphertextEl)
	if err != nil {
		return nil, err
	}

	return w.Unwrap(kek, wrapped)
}

func init() {
	RegisterDecrypter(AES128KW)
	RegisterDecrypter(AES192KW)
	RegisterDecrypter(AES256KW)
}
