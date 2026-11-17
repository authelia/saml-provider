package xmlenc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// opaqueDecrypter is a key which is not an *rsa.PrivateKey, as one in a hardware security module is not. It records
// the options that it is given.
type opaqueDecrypter struct {
	key    *rsa.PrivateKey
	public crypto.PublicKey
	opts   []crypto.DecrypterOpts
}

func (d *opaqueDecrypter) Public() crypto.PublicKey { return d.public }

func (d *opaqueDecrypter) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	d.opts = append(d.opts, opts)

	return d.key.Decrypt(rand, msg, opts)
}

// A key that is held elsewhere decrypts through crypto.Decrypter, and is told the digest and the hash of the mask
// generation function, which differ for RSA-OAEP-MGF1P with a digest other than SHA-1.
func TestDecryptWithOpaqueDecrypter(t *testing.T) {
	key, cert := newDigestTestKey(t)

	for name, tc := range map[string]struct {
		encrypter RSA
		hash      crypto.Hash
		mgfHash   crypto.Hash
	}{
		"rsa-oaep-mgf1p": {OAEP(), crypto.SHA256, crypto.SHA1},
		"rsa-oaep":       {OAEP_SHA512(), crypto.SHA512, crypto.SHA512},
	} {
		t.Run(name, func(t *testing.T) {
			el, err := tc.encrypter.Encrypt(cert, []byte("plaintext"), nil)
			assert.NilError(t, err)

			decrypter := &opaqueDecrypter{key: key, public: key.Public()}

			plaintext, err := Decrypt(decrypter, el)
			assert.NilError(t, err)
			assert.Check(t, is.Equal("plaintext", string(plaintext)))

			assert.Assert(t, is.Len(decrypter.opts, 1))
			opts, ok := decrypter.opts[0].(*rsa.OAEPOptions)
			assert.Assert(t, ok)
			assert.Check(t, is.Equal(tc.hash, opts.Hash))
			assert.Check(t, is.Equal(tc.mgfHash, opts.MGFHash))
			assert.Check(t, is.Len(opts.Label, 0))
		})
	}
}

// A key which is not an RSA key is refused before it is asked to decrypt.
func TestDecryptRefusesKeyThatIsNotRSA(t *testing.T) {
	key, cert := newDigestTestKey(t)

	el, err := OAEP().Encrypt(cert, []byte("plaintext"), nil)
	assert.NilError(t, err)

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NilError(t, err)

	var nilKey *rsa.PrivateKey

	for name, k := range map[string]interface{}{
		"decrypter with another public key": &opaqueDecrypter{key: key, public: ecdsaKey.Public()},
		"ecdsa key":                         ecdsaKey,
		"nil rsa key":                       nilKey,
		"no key":                            nil,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Decrypt(k, el)
			assert.Check(t, is.Error(err, "expected key to be a *rsa.PrivateKey"))

			if decrypter, ok := k.(*opaqueDecrypter); ok {
				assert.Check(t, is.Len(decrypter.opts, 0))
			}
		})
	}
}
