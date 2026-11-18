package xmlenc

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/beevik/etree"
)

const (
	algorithmECDHES    = namespaceXMLEnc11 + "ECDH-ES"
	algorithmConcatKDF = namespaceXMLEnc11 + "ConcatKDF"
	namespaceXMLDSig   = "http://www.w3.org/2000/09/xmldsig#"
	namespaceXMLEnc    = "http://www.w3.org/2001/04/xmlenc#"
	namespaceXMLDSig11 = "http://www.w3.org/2009/xmldsig11#"
)

// namedCurve is a prime curve that ECDH-ES can agree a key on, with the URI of its object identifier that a
// dsig11:NamedCurve names it by (XML Signature 1.1 §4.5.2.3.1).
type namedCurve struct {
	ecdh  ecdh.Curve
	ecdsa elliptic.Curve
	uri   string
}

// namedCurves are the curves of XML Encryption 1.1 §5.6.4: P-256, which it requires, and P-384 and P-521, which it
// recommends.
var namedCurves = []namedCurve{
	{ecdh.P256(), elliptic.P256(), "urn:oid:1.2.840.10045.3.1.7"},
	{ecdh.P384(), elliptic.P384(), "urn:oid:1.3.132.0.34"},
	{ecdh.P521(), elliptic.P521(), "urn:oid:1.3.132.0.35"},
}

// ECDHES implements Encrypter with the ephemeral-static Elliptic Curve Diffie-Hellman key agreement of XML
// Encryption 1.1 §5.6.4. A new key pair is made on the curve of the recipient for each message, and the key that
// is agreed with it, through ConcatKDF (§5.4.1), wraps the content encryption key with KeyWrap. The EncryptedKey
// describes it as Example 42 of XML Encryption 1.1 does.
//
// Decryption is done by the KeyWrap, which is registered as a decrypter, given the private key of the recipient.
type ECDHES struct {
	// BlockCipher encrypts the content.
	BlockCipher BlockCipher

	// KeyWrap wraps the content encryption key with the agreed key.
	KeyWrap KeyWrap

	// DigestMethod is the digest of ConcatKDF. Nil means SHA-256, which XML Encryption 1.1 §5.4.1 requires every
	// implementation to support.
	DigestMethod DigestMethod
}

// ECDH_ES returns an ECDHES with AES-128-GCM, AES Key Wrap with a 256-bit key, and ConcatKDF with SHA-256.
func ECDH_ES() ECDHES {
	return ECDHES{BlockCipher: AES128GCM, KeyWrap: AES256KW, DigestMethod: SHA256}
}

// Algorithm returns the identifier of the key agreement algorithm.
func (e ECDHES) Algorithm() string {
	return algorithmECDHES
}

// ecdhRecipient returns the elliptic curve key that recipient is, and the certificate that holds it if it is one.
func ecdhRecipient(recipient interface{}) (*x509.Certificate, *ecdsa.PublicKey, error) {
	switch k := recipient.(type) {
	case *x509.Certificate:
		if k == nil {
			return nil, nil, ErrIncorrectKeyType("*x.509 certificate")
		}

		pubKey, ok := k.PublicKey.(*ecdsa.PublicKey)
		if !ok || pubKey == nil {
			return nil, nil, ErrIncorrectKeyType("x.509 certificate with an elliptic curve public key")
		}

		return k, pubKey, nil
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, nil, ErrIncorrectKeyType("elliptic curve public key")
		}

		return nil, k, nil
	default:
		return nil, nil, ErrIncorrectKeyType("*x.509 certificate or *ecdsa.PublicKey")
	}
}

// curveOf returns the named curve of an ECDSA key, or false if ECDH-ES can't agree a key on it.
func curveOf(curve elliptic.Curve) (namedCurve, bool) {
	for _, c := range namedCurves {
		if c.ecdsa == curve {
			return c, true
		}
	}

	return namedCurve{}, false
}

// Encrypt implements Encrypter. recipient is the elliptic curve public key to encrypt to, on P-256, P-384 or P-521:
// an *[x509.Certificate] which holds one, or a bare *[ecdsa.PublicKey]. The RecipientKeyInfo identifies it in the
// form it was given, by its X509Certificate or by its dsig11:ECKeyValue.
func (e ECDHES) Encrypt(recipient interface{}, plaintext []byte, nonce []byte) (*etree.Element, error) {
	if e.BlockCipher == nil || e.KeyWrap == nil {
		return nil, errors.New("ECDH-ES needs a BlockCipher and a KeyWrap")
	}

	cert, ecdsaKey, err := ecdhRecipient(recipient)
	if err != nil {
		return nil, err
	}

	curve, ok := curveOf(ecdsaKey.Curve)
	if !ok {
		return nil, ErrIncorrectKeyType("elliptic curve public key on P-256, P-384 or P-521")
	}

	recipientKey, err := ecdsaKey.ECDH()
	if err != nil {
		return nil, err
	}

	digest := e.DigestMethod
	if digest == nil {
		digest = SHA256
	}

	hash, ok := digestCryptoHash(digest)
	if !ok {
		return nil, ErrAlgorithmNotImplemented(digest.Algorithm())
	}

	ephemeral, err := curve.ecdh.GenerateKey(RandReader)
	if err != nil {
		return nil, err
	}

	shared, err := ephemeral.ECDH(recipientKey)
	if err != nil {
		return nil, err
	}

	// SP 800-56A asks for the AlgorithmID, PartyUInfo and PartyVInfo, which XML Encryption 1.1 §5.4.1 writes as
	// hexBinary with a leading octet that counts the padding bits. The AlgorithmID is the identifier of the key
	// wrap algorithm that the agreed key is for, and the parties are not named.
	params := concatKDFParams{algorithmID: []byte(e.KeyWrap.Algorithm())}

	kek, err := concatKDF(hash, shared, params.otherInfo(), e.KeyWrap.KeySize())
	if err != nil {
		return nil, err
	}

	key := make([]byte, e.BlockCipher.KeySize())
	if _, err := io.ReadFull(RandReader, key); err != nil {
		return nil, err
	}

	wrapped, err := e.KeyWrap.Wrap(kek, key)
	if err != nil {
		return nil, err
	}

	keyInfoEl, err := e.keyInfo(cert, curve, recipientKey, ephemeral.PublicKey(), params, digest, wrapped)
	if err != nil {
		return nil, err
	}

	encryptedDataEl, err := e.BlockCipher.Encrypt(key, plaintext, nonce)
	if err != nil {
		return nil, err
	}

	encryptedDataEl.InsertChildAt(encryptedDataEl.FindElement("./CipherData").Index(), keyInfoEl)

	return encryptedDataEl, nil
}

// keyInfo returns the ds:KeyInfo of the EncryptedData, with the EncryptedKey that holds the wrapped content
// encryption key and the AgreementMethod by which the recipient agrees the key that wrapped it.
func (e ECDHES) keyInfo(cert *x509.Certificate, curve namedCurve, recipientKey, ephemeral *ecdh.PublicKey, params concatKDFParams, digest DigestMethod, wrapped []byte) (*etree.Element, error) {
	keyInfoEl := etree.NewElement("ds:KeyInfo")
	keyInfoEl.CreateAttr("xmlns:ds", namespaceXMLDSig)

	encryptedKey := keyInfoEl.CreateElement("xenc:EncryptedKey")
	{
		randBuf := make([]byte, 16)
		if _, err := io.ReadFull(RandReader, randBuf); err != nil {
			return nil, err
		}

		encryptedKey.CreateAttr("Id", fmt.Sprintf("_%x", randBuf))
	}

	encryptedKey.CreateAttr("xmlns:xenc", namespaceXMLEnc)
	encryptedKey.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", e.KeyWrap.Algorithm())

	agreement := encryptedKey.CreateElement("ds:KeyInfo").CreateElement("xenc:AgreementMethod")
	agreement.CreateAttr("Algorithm", algorithmECDHES)

	derivation := agreement.CreateElement("xenc11:KeyDerivationMethod")
	derivation.CreateAttr("xmlns:xenc11", namespaceXMLEnc11)
	derivation.CreateAttr("Algorithm", algorithmConcatKDF)

	kdfParams := derivation.CreateElement("xenc11:ConcatKDFParams")
	kdfParams.CreateAttr("AlgorithmID", encodeKDFParam(params.algorithmID))
	kdfParams.CreateAttr("PartyUInfo", encodeKDFParam(params.partyUInfo))
	kdfParams.CreateAttr("PartyVInfo", encodeKDFParam(params.partyVInfo))
	kdfParams.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", digest.Algorithm())

	writeECKeyValue(agreement.CreateElement("xenc:OriginatorKeyInfo"), curve, ephemeral.Bytes())

	recipientKeyInfo := agreement.CreateElement("xenc:RecipientKeyInfo")
	if cert != nil {
		recipientKeyInfo.CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").SetText(
			base64.StdEncoding.EncodeToString(cert.Raw),
		)
	} else {
		writeECKeyValue(recipientKeyInfo, curve, recipientKey.Bytes())
	}

	cd := encryptedKey.CreateElement("xenc:CipherData")
	cd.CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(wrapped))

	return keyInfoEl, nil
}

// writeECKeyValue adds to parent the ds:KeyValue with the dsig11:ECKeyValue of a public key on curve, whose point
// is in the uncompressed form of SEC 1 §2.3.3 (XML Signature 1.1 §4.5.2.3).
func writeECKeyValue(parent *etree.Element, curve namedCurve, point []byte) {
	keyValue := parent.CreateElement("ds:KeyValue").CreateElement("dsig11:ECKeyValue")
	keyValue.CreateAttr("xmlns:dsig11", namespaceXMLDSig11)
	keyValue.CreateElement("dsig11:NamedCurve").CreateAttr("URI", curve.uri)
	keyValue.CreateElement("dsig11:PublicKey").SetText(base64.StdEncoding.EncodeToString(point))
}

// concatKDFParams are the bit strings of ConcatKDF that XML Encryption 1.1 §5.4.1 carries, which are whole octets
// here. Those that SP 800-56A leaves optional are not supported.
type concatKDFParams struct {
	algorithmID, partyUInfo, partyVInfo []byte
}

// otherInfo returns the OtherInfo of SP 800-56A §5.8.1, the parameters concatenated.
func (p concatKDFParams) otherInfo() []byte {
	out := make([]byte, 0, len(p.algorithmID)+len(p.partyUInfo)+len(p.partyVInfo))

	return append(append(append(out, p.algorithmID...), p.partyUInfo...), p.partyVInfo...)
}

// encodeKDFParam returns a bit string of whole octets as XML Encryption 1.1 §5.4.1 writes it: as hexBinary with a
// leading octet that says no padding bits were added.
func encodeKDFParam(octets []byte) string {
	return strings.ToUpper(hex.EncodeToString(append([]byte{0}, octets...)))
}

// decodeKDFParam returns the bit string that XML Encryption 1.1 §5.4.1 writes as value. An empty value is an empty
// bit string. One with padding bits is not supported, as it isn't a whole number of octets.
func decodeKDFParam(name, value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}

	octets, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, fmt.Errorf("the %s of ConcatKDF is not hexBinary: %w", name, err)
	}

	if octets[0] != 0 {
		return nil, fmt.Errorf("the %s of ConcatKDF is not a whole number of octets", name)
	}

	return octets[1:], nil
}

// concatKDF returns keyLen bytes of keying material derived from the shared secret by the single-step key
// derivation function of SP 800-56A §5.8.1 with hash.
func concatKDF(hash crypto.Hash, shared, otherInfo []byte, keyLen int) ([]byte, error) {
	if !hash.Available() {
		return nil, ErrAlgorithmNotImplemented(hash.String())
	}

	out := make([]byte, 0, keyLen+hash.Size())
	counter := make([]byte, 4)

	for i := uint32(1); len(out) < keyLen; i++ {
		binary.BigEndian.PutUint32(counter, i)

		h := hash.New()
		h.Write(counter)
		h.Write(shared)
		h.Write(otherInfo)

		out = h.Sum(out)
	}

	return out[:keyLen], nil
}

// agreedKey returns the keySize bytes of the key encryption key of encryptedKeyEl that its AgreementMethod agrees
// with the private key of the recipient, which is an *[ecdsa.PrivateKey] or an *[ecdh.PrivateKey]. Only ECDH-ES
// with ConcatKDF is supported.
func agreedKey(key interface{}, encryptedKeyEl *etree.Element, keySize int) ([]byte, error) {
	private, err := ecdhPrivateKey(key)
	if err != nil {
		return nil, err
	}

	agreementEl := encryptedKeyEl.FindElement("./KeyInfo/AgreementMethod")
	if agreementEl == nil {
		return nil, ErrCannotFindRequiredElement("KeyInfo/AgreementMethod")
	}

	if algorithm := agreementEl.SelectAttrValue("Algorithm", ""); algorithm != algorithmECDHES {
		return nil, ErrAlgorithmNotImplemented(algorithm)
	}

	derivationEl := agreementEl.FindElement("./KeyDerivationMethod")
	if derivationEl == nil {
		return nil, ErrCannotFindRequiredElement("KeyDerivationMethod")
	}

	if algorithm := derivationEl.SelectAttrValue("Algorithm", ""); algorithm != algorithmConcatKDF {
		return nil, ErrAlgorithmNotImplemented(algorithm)
	}

	params, hash, err := readConcatKDFParams(derivationEl.FindElement("./ConcatKDFParams"))
	if err != nil {
		return nil, err
	}

	originator, err := readECKeyValue(agreementEl.FindElement("./OriginatorKeyInfo/KeyValue/ECKeyValue"), private.Curve())
	if err != nil {
		return nil, fmt.Errorf("the OriginatorKeyInfo: %w", err)
	}

	shared, err := private.ECDH(originator)
	if err != nil {
		return nil, err
	}

	return concatKDF(hash, shared, params.otherInfo(), keySize)
}

// ecdhPrivateKey returns the private key of the recipient of ECDH-ES, which is an *[ecdsa.PrivateKey] or an
// *[ecdh.PrivateKey].
func ecdhPrivateKey(key interface{}) (*ecdh.PrivateKey, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if k == nil {
			return nil, ErrIncorrectKeyType("*ecdsa.PrivateKey")
		}

		return k.ECDH()
	case *ecdh.PrivateKey:
		if k == nil {
			return nil, ErrIncorrectKeyType("*ecdh.PrivateKey")
		}

		return k, nil
	default:
		return nil, ErrIncorrectKeyType("[]byte, *ecdsa.PrivateKey or *ecdh.PrivateKey")
	}
}

// readConcatKDFParams returns the parameters and the hash of an xenc11:ConcatKDFParams element.
func readConcatKDFParams(paramsEl *etree.Element) (params concatKDFParams, hash crypto.Hash, err error) {
	if paramsEl == nil {
		return params, 0, ErrCannotFindRequiredElement("ConcatKDFParams")
	}

	for _, name := range []string{"SuppPubInfo", "SuppPrivInfo"} {
		if paramsEl.SelectAttr(name) != nil {
			return params, 0, ErrAlgorithmNotImplemented("ConcatKDF with " + name)
		}
	}

	if params.algorithmID, err = decodeKDFParam("AlgorithmID", paramsEl.SelectAttrValue("AlgorithmID", "")); err != nil {
		return params, 0, err
	}

	if params.partyUInfo, err = decodeKDFParam("PartyUInfo", paramsEl.SelectAttrValue("PartyUInfo", "")); err != nil {
		return params, 0, err
	}

	if params.partyVInfo, err = decodeKDFParam("PartyVInfo", paramsEl.SelectAttrValue("PartyVInfo", "")); err != nil {
		return params, 0, err
	}

	digestEl := paramsEl.FindElement("./DigestMethod")
	if digestEl == nil {
		return params, 0, ErrCannotFindRequiredElement("ConcatKDFParams/DigestMethod")
	}

	algorithm := digestEl.SelectAttrValue("Algorithm", "")

	digest, ok := digestMethods[algorithm]
	if !ok {
		return params, 0, ErrAlgorithmNotImplemented(algorithm)
	}

	if hash, ok = digestCryptoHash(digest); !ok {
		return params, 0, ErrAlgorithmNotImplemented(algorithm)
	}

	return params, hash, nil
}

// readECKeyValue returns the public key of a dsig11:ECKeyValue, which must be a point on curve, named by its
// NamedCurve. Explicit curve parameters are not supported.
func readECKeyValue(keyValueEl *etree.Element, curve ecdh.Curve) (*ecdh.PublicKey, error) {
	if keyValueEl == nil {
		return nil, ErrCannotFindRequiredElement("KeyValue/ECKeyValue")
	}

	namedCurveEl := keyValueEl.FindElement("./NamedCurve")
	if namedCurveEl == nil {
		return nil, ErrCannotFindRequiredElement("ECKeyValue/NamedCurve")
	}

	uri := namedCurveEl.SelectAttrValue("URI", "")

	var named *namedCurve

	for i := range namedCurves {
		if namedCurves[i].uri == uri {
			named = &namedCurves[i]
		}
	}

	if named == nil {
		return nil, ErrAlgorithmNotImplemented(uri)
	}

	if named.ecdh != curve {
		return nil, fmt.Errorf("the key is on the curve %s, not that of the private key", uri)
	}

	publicKeyEl := keyValueEl.FindElement("./PublicKey")
	if publicKeyEl == nil {
		return nil, ErrCannotFindRequiredElement("ECKeyValue/PublicKey")
	}

	point, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(publicKeyEl.Text()), ""))
	if err != nil {
		return nil, err
	}

	// NewPublicKey checks that the point is on the curve and not the point at infinity.
	return curve.NewPublicKey(point)
}
