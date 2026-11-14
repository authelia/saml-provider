package xmlenc

import (
	"crypto"
	"crypto/sha1" //nolint:gosec // required for protocol support
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	//nolint:staticcheck,gosec // We should support this for legacy reasons.
	"golang.org/x/crypto/ripemd160"
)

type digestMethod struct {
	algorithm string
	hash      func() hash.Hash
	id        crypto.Hash
}

func (dm digestMethod) Algorithm() string {
	return dm.algorithm
}

func (dm digestMethod) Hash() hash.Hash {
	return dm.hash()
}

// cryptoHash returns the identifier of the hash function, which crypto/rsa needs to use a distinct hash for MGF1.
func (dm digestMethod) cryptoHash() crypto.Hash {
	return dm.id
}

var (
	// SHA1 implements the SHA-1 digest method (which is considered insecure)
	SHA1 = digestMethod{
		algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
		hash:      sha1.New,
		id:        crypto.SHA1,
	}

	// SHA256 implements the SHA-256 digest method
	SHA256 = digestMethod{
		algorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
		hash:      sha256.New,
		id:        crypto.SHA256,
	}

	// SHA512 implements the SHA-512 digest method
	SHA512 = digestMethod{
		algorithm: "http://www.w3.org/2001/04/xmlenc#sha512",
		hash:      sha512.New,
		id:        crypto.SHA512,
	}

	// RIPEMD160 implements the RIPEMD160 digest method
	RIPEMD160 = digestMethod{
		algorithm: "http://www.w3.org/2001/04/xmlenc#ripemd160",
		hash:      ripemd160.New,
		id:        crypto.RIPEMD160,
	}
)

// The legacy digest methods use identifiers which are not part of any specification, but which some
// implementations write and expect. They are accepted when decrypting, and are only written if set
// as the DigestMethod of an encrypter, for a recipient which does not accept the standard identifiers.
var (
	// LegacySHA256 implements the SHA-256 digest method with its legacy identifier
	LegacySHA256 = digestMethod{
		algorithm: "http://www.w3.org/2000/09/xmldsig#sha256",
		hash:      sha256.New,
		id:        crypto.SHA256,
	}

	// LegacySHA512 implements the SHA-512 digest method with its legacy identifier
	LegacySHA512 = digestMethod{
		algorithm: "http://www.w3.org/2000/09/xmldsig#sha512",
		hash:      sha512.New,
		id:        crypto.SHA512,
	}
)

func init() {
	RegisterDigestMethod(SHA1)
	RegisterDigestMethod(SHA256)
	RegisterDigestMethod(SHA512)
	RegisterDigestMethod(RIPEMD160)
	RegisterDigestMethod(LegacySHA256)
	RegisterDigestMethod(LegacySHA512)
}
