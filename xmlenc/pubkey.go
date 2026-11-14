package xmlenc

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
)

const (
	algorithmRSAOAEPMGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	algorithmRSAOAEP2009  = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
	namespaceXMLEnc11     = "http://www.w3.org/2009/xmlenc11#"
	algorithmMGF1SHA1     = "http://www.w3.org/2009/xmlenc11#mgf1sha1"
	algorithmMGF1SHA224   = "http://www.w3.org/2009/xmlenc11#mgf1sha224"
	algorithmMGF1SHA256   = "http://www.w3.org/2009/xmlenc11#mgf1sha256"
	algorithmMGF1SHA384   = "http://www.w3.org/2009/xmlenc11#mgf1sha384"
	algorithmMGF1SHA512   = "http://www.w3.org/2009/xmlenc11#mgf1sha512"
)

// mgfAlgorithms are the mask generation functions of XML Encryption 1.1 §5.5.2, by the hash MGF1 uses.
var mgfAlgorithms = map[crypto.Hash]string{
	crypto.SHA1:   algorithmMGF1SHA1,
	crypto.SHA224: algorithmMGF1SHA224,
	crypto.SHA256: algorithmMGF1SHA256,
	crypto.SHA384: algorithmMGF1SHA384,
	crypto.SHA512: algorithmMGF1SHA512,
}

// mgfHashes are the hashes MGF1 uses, by the identifier of their mask generation function.
var mgfHashes = map[string]crypto.Hash{
	algorithmMGF1SHA1:   crypto.SHA1,
	algorithmMGF1SHA224: crypto.SHA224,
	algorithmMGF1SHA256: crypto.SHA256,
	algorithmMGF1SHA384: crypto.SHA384,
	algorithmMGF1SHA512: crypto.SHA512,
}

// RSA implements Encrypter and Decrypter using RSA public key encryption.
//
// Use function like OAEP(), or PKCS1v15() to get an instance of this type ready
// to use.
type RSA struct {
	BlockCipher BlockCipher

	// DigestMethod is the digest of OAEP, and is ignored by PKCS1v15. It is written as the DigestMethod of the
	// EncryptionMethod, and nil means SHA-1, the default of XML Encryption §5.4.2 when there is none.
	DigestMethod DigestMethod

	// MGFHash is the hash of the MGF1 mask generation function of XML Encryption 1.1 RSA-OAEP, and is written as
	// its MGF element. Zero means SHA-1, the default of XML Encryption 1.1 §5.5.2. It is ignored by RSA-OAEP-MGF1P,
	// which always uses MGF1 with SHA-1 (XML Encryption §5.4.2), and by PKCS1v15.
	MGFHash crypto.Hash

	algorithm    string
	keyEncrypter func(e RSA, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error)
	keyDecrypter func(e RSA, privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error)
}

// Algorithm returns the name of the algorithm
func (e RSA) Algorithm() string {
	return e.algorithm
}

// mgfHash returns the hash of the MGF1 mask generation function which the algorithm uses.
func (e RSA) mgfHash() crypto.Hash {
	if e.algorithm == algorithmRSAOAEP2009 && e.MGFHash != 0 {
		return e.MGFHash
	}
	return crypto.SHA1
}

// oaepOptions returns the options for crypto/rsa which match the digest and mask generation function of e.
func (e RSA) oaepOptions() (*rsa.OAEPOptions, error) {
	var digest DigestMethod = SHA1
	if e.DigestMethod != nil {
		digest = e.DigestMethod
	}
	hasher, ok := digest.(interface{ cryptoHash() crypto.Hash })
	if !ok || !hasher.cryptoHash().Available() {
		return nil, ErrAlgorithmNotImplemented(digest.Algorithm())
	}
	mgf := e.mgfHash()
	if !mgf.Available() {
		return nil, fmt.Errorf("MGF1 with %v is not available", mgf)
	}
	return &rsa.OAEPOptions{Hash: hasher.cryptoHash(), MGFHash: mgf}, nil
}

func encryptOAEP(e RSA, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	opts, err := e.oaepOptions()
	if err != nil {
		return nil, err
	}
	return rsa.EncryptOAEPWithOptions(RandReader, pubKey, plaintext, opts)
}

func decryptOAEP(e RSA, privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	opts, err := e.oaepOptions()
	if err != nil {
		return nil, err
	}
	return privKey.Decrypt(nil, ciphertext, opts)
}

// Encrypt implements encrypter. certificate must be a []byte containing the ASN.1 bytes
// of certificate containing an RSA public key.
func (e RSA) Encrypt(certificate interface{}, plaintext []byte, nonce []byte) (*etree.Element, error) {
	cert, ok := certificate.(*x509.Certificate)
	if !ok {
		return nil, ErrIncorrectKeyType("*x.509 certificate")
	}

	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrIncorrectKeyType("x.509 certificate with an RSA public key")
	}

	var mgfAlgorithm string
	if e.algorithm == algorithmRSAOAEP2009 {
		if mgfAlgorithm, ok = mgfAlgorithms[e.mgfHash()]; !ok {
			return nil, fmt.Errorf("MGF1 with %v has no XML Encryption 1.1 identifier", e.mgfHash())
		}
	}

	// generate a key
	key := make([]byte, e.BlockCipher.KeySize())
	if _, err := RandReader.Read(key); err != nil {
		return nil, err
	}

	keyInfoEl := etree.NewElement("ds:KeyInfo")
	keyInfoEl.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")

	encryptedKey := keyInfoEl.CreateElement("xenc:EncryptedKey")
	{
		randBuf := make([]byte, 16)
		if _, err := RandReader.Read(randBuf); err != nil {
			return nil, err
		}
		encryptedKey.CreateAttr("Id", fmt.Sprintf("_%x", randBuf))
	}
	encryptedKey.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")

	encryptionMethodEl := encryptedKey.CreateElement("xenc:EncryptionMethod")
	encryptionMethodEl.CreateAttr("Algorithm", e.algorithm)
	encryptionMethodEl.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	if e.DigestMethod != nil {
		dm := encryptionMethodEl.CreateElement("ds:DigestMethod")
		dm.CreateAttr("Algorithm", e.DigestMethod.Algorithm())
		dm.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	}
	if mgfAlgorithm != "" {
		// XML Encryption 1.1 §5.5.2 defaults to MGF1 with SHA-1, which is stated anyway so that no receiver can
		// mistake it for the digest.
		mgf := encryptionMethodEl.CreateElement("xenc11:MGF")
		mgf.CreateAttr("xmlns:xenc11", namespaceXMLEnc11)
		mgf.CreateAttr("Algorithm", mgfAlgorithm)
	}
	{
		innerKeyInfoEl := encryptedKey.CreateElement("ds:KeyInfo")
		x509data := innerKeyInfoEl.CreateElement("ds:X509Data")
		x509data.CreateElement("ds:X509Certificate").SetText(
			base64.StdEncoding.EncodeToString(cert.Raw),
		)
	}

	buf, err := e.keyEncrypter(e, pubKey, key)
	if err != nil {
		return nil, err
	}

	cd := encryptedKey.CreateElement("xenc:CipherData")
	cd.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	cd.CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(buf))
	encryptedDataEl, err := e.BlockCipher.Encrypt(key, plaintext, nonce)
	if err != nil {
		return nil, err
	}
	encryptedDataEl.InsertChildAt(encryptedDataEl.FindElement("./CipherData").Index(), keyInfoEl)

	return encryptedDataEl, nil
}

// Decrypt implements Decryptor. `key` must be an *rsa.PrivateKey.
func (e RSA) Decrypt(key interface{}, ciphertextEl *etree.Element) ([]byte, error) {
	rsaKey, err := validateRSAKeyIfPresent(key, ciphertextEl)
	if err != nil {
		return nil, err
	}

	ciphertext, err := getCiphertext(ciphertextEl)
	if err != nil {
		return nil, err
	}

	{
		digestMethodEl := ciphertextEl.FindElement("./EncryptionMethod/DigestMethod")
		if digestMethodEl == nil {
			e.DigestMethod = SHA1
		} else {
			hashAlgorithmStr := digestMethodEl.SelectAttrValue("Algorithm", "")
			digestMethod, ok := digestMethods[hashAlgorithmStr]
			if !ok {
				return nil, ErrAlgorithmNotImplemented(hashAlgorithmStr)
			}
			e.DigestMethod = digestMethod
		}
	}

	if e.algorithm == algorithmRSAOAEP2009 {
		// XML Encryption 1.1 §5.5.2: MGF1 with SHA-1 unless an MGF element names another.
		e.MGFHash = crypto.SHA1
		if mgfEl := ciphertextEl.FindElement("./EncryptionMethod/MGF"); mgfEl != nil {
			mgfAlgorithm := mgfEl.SelectAttrValue("Algorithm", "")
			mgfHash, ok := mgfHashes[mgfAlgorithm]
			if !ok {
				return nil, ErrAlgorithmNotImplemented(mgfAlgorithm)
			}
			e.MGFHash = mgfHash
		}
	}

	return e.keyDecrypter(e, rsaKey, ciphertext)
}

// OAEP returns a version of RSA that implements RSA-OAEP-MGF1P of XML Encryption §5.4.2. By
// default the block cipher used is AES-256 CBC and the digest method is SHA-256. You can
// specify other ciphers and digest methods by assigning to BlockCipher or DigestMethod. The
// mask generation function is always MGF1 with SHA-1, whatever the digest, as §5.4.2 requires.
//
// It is registered as a decrypter by default.
func OAEP() RSA {
	return RSA{
		BlockCipher:  AES256CBC,
		DigestMethod: SHA256,
		algorithm:    algorithmRSAOAEPMGF1P,
		keyEncrypter: encryptOAEP,
		keyDecrypter: decryptOAEP,
	}
}

// OAEP_SHA256 returns a version of RSA that implements the RSA-OAEP of XML Encryption 1.1
// §5.5.2. By default the block cipher used is AES-256 CBC, and the digest method and the hash
// of the MGF1 mask generation function are SHA-256. You can specify others by assigning to
// BlockCipher, DigestMethod or MGFHash.
//
// An instance is registered as a decrypter by default, which reads the digest and mask
// generation function from the EncryptedKey it decrypts.
func OAEP_SHA256() RSA { //nolint:revive
	return RSA{
		BlockCipher:  AES256CBC,
		DigestMethod: SHA256,
		MGFHash:      crypto.SHA256,
		algorithm:    algorithmRSAOAEP2009,
		keyEncrypter: encryptOAEP,
		keyDecrypter: decryptOAEP,
	}
}

// OAEP_SHA512 returns a version of RSA that implements the RSA-OAEP of XML Encryption 1.1
// §5.5.2. By default the block cipher used is AES-256 CBC, and the digest method and the hash
// of the MGF1 mask generation function are SHA-512. You can specify others by assigning to
// BlockCipher, DigestMethod or MGFHash.
func OAEP_SHA512() RSA { //nolint:revive
	return RSA{
		BlockCipher:  AES256CBC,
		DigestMethod: SHA512,
		MGFHash:      crypto.SHA512,
		algorithm:    algorithmRSAOAEP2009,
		keyEncrypter: encryptOAEP,
		keyDecrypter: decryptOAEP,
	}
}

// PKCS1v15 returns a version of RSA that implements RSA in PKCS1v15 mode. By default
// the block cipher used is AES-256 CBC. The DigestMethod field is ignored because PKCS1v15
// does not use a digest function.
//
// PKCS1v15 is not registered as a decrypter by default, because decrypting
// attacker-supplied PKCS1v15 ciphertexts exposes a padding oracle (Bleichenbacher)
// that allows recovery of any value encrypted to the private key. Only if an
// identity provider cannot be configured to use OAEP, opt in by calling
// RegisterDecrypter(PKCS1v15()) during program initialization.
func PKCS1v15() RSA {
	return RSA{
		BlockCipher:  AES256CBC,
		DigestMethod: nil,
		algorithm:    "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
		keyEncrypter: func(_ RSA, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
			return rsa.EncryptPKCS1v15(RandReader, pubKey, plaintext)
		},
		keyDecrypter: func(_ RSA, privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
			return rsa.DecryptPKCS1v15(RandReader, privKey, ciphertext)
		},
	}
}

func init() {
	RegisterDecrypter(OAEP())
	RegisterDecrypter(OAEP_SHA256())
}
