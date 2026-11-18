package saml

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"

	"authelia.com/provider/saml/xmlenc"
)

const (
	samlAssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
	xmlencNamespace        = "http://www.w3.org/2001/04/xmlenc#"

	// xmlencElementType is the Type of an EncryptedData which replaces an element, the only one SAMLCore §6.1
	// allows.
	xmlencElementType = "http://www.w3.org/2001/04/xmlenc#Element"

	// maxEncryptedKeys is the most EncryptedKey elements beside an EncryptedData that are tried, so that an
	// encrypted element can't be made to cost an unbounded number of private key operations.
	maxEncryptedKeys = 4
)

// EncryptedNameIDFormat is the Format of a NameIDPolicy which requests that the identifier is sent as an
// EncryptedID (SAMLCore §3.4.1.1). It is never the Format of a NameID: the identifier that is encrypted has a
// format of its own, which the service provider can't choose (errata E6). A ServiceProvider requests it with
// EncryptNameID, rather than as its AuthnNameIDFormat.
const EncryptedNameIDFormat NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"

// elementEncrypter encrypts SAML elements to one entity, as SAMLCore §6.1 describes: the EncryptedData takes the
// place of the element, with its EncryptedKey inside it, which errata E43 allows.
type elementEncrypter struct {
	// certificate holds the key of the entity, from the KeyDescriptor of its metadata. It is nil when the metadata
	// gives the key only as a ds:KeyValue (MetaIOP §2.5.1).
	certificate *x509.Certificate

	// publicKey is the key of the entity, which is encrypted to when there is no certificate: an *rsa.PublicKey,
	// or an *ecdsa.PublicKey for ECDH-ES. The EncryptedKey then identifies it by its ds:KeyValue, as the metadata
	// does.
	publicKey crypto.PublicKey

	// encrypter has the key transport or key agreement and content encryption algorithms negotiated with the
	// entity: an xmlenc.RSA for an RSA key, and an xmlenc.ECDHES for an elliptic curve key.
	encrypter xmlenc.Encrypter

	// recipient is the identifier of the entity, written as the Recipient of the EncryptedKey (SAMLCore §2.2.4).
	recipient string
}

// encrypt returns a SAML element named tag, of the EncryptedElementType of SAMLCore §2.2.4, which holds
// plaintext. Each call uses a new content encryption key and a new IV or nonce, so the ciphertext is unique to
// it, as §2.2.4 requires. The plaintext must declare the namespaces it uses, because it stands alone once
// decrypted.
func (e *elementEncrypter) encrypt(tag string, plaintext *etree.Element) (*etree.Element, error) {
	doc := etree.NewDocument()
	doc.SetRoot(plaintext)

	buf, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}

	// The key is given in the form the metadata has it, which is the form the EncryptedKey identifies it in.
	var recipientKey any = e.publicKey
	if e.certificate != nil {
		recipientKey = e.certificate
	}

	encryptedDataEl, err := e.encrypter.Encrypt(recipientKey, buf, nil)
	if err != nil {
		return nil, err
	}

	// SAMLCore §6.1: the Type SHOULD be used, and MUST be this value.
	encryptedDataEl.CreateAttr("Type", xmlencElementType)

	// SAMLCore §2.2.4 and §2.7.3.2: each wrapped key SHOULD name the entity it was encrypted for.
	if encryptedKeyEl := encryptedDataEl.FindElement("./KeyInfo/EncryptedKey"); encryptedKeyEl != nil && e.recipient != "" {
		encryptedKeyEl.CreateAttr("Recipient", e.recipient)
	}

	el := etree.NewElement("saml:" + tag)
	el.CreateAttr("xmlns:saml", samlAssertionNamespace)
	el.AddChild(encryptedDataEl)

	return el, nil
}

// encryptNameID returns the EncryptedID element of SAMLCore §2.2.4 for nameID. It must take the place of the
// NameID before the assertion or message that contains it is signed (SAMLCore §6.2).
func (e *elementEncrypter) encryptNameID(nameID *NameID) (*etree.Element, error) {
	el := nameID.Element()
	el.CreateAttr("xmlns:saml", samlAssertionNamespace)

	return e.encrypt("EncryptedID", el)
}

// encryptAttribute returns the EncryptedAttribute element of SAMLCore §2.7.3.2 for attribute. It must take the
// place of the Attribute before the assertion that contains it is signed (SAMLCore §6.2).
func (e *elementEncrypter) encryptAttribute(attribute *Attribute) (*etree.Element, error) {
	el := attribute.Element()
	el.CreateAttr("xmlns:saml", samlAssertionNamespace)

	return e.encrypt("EncryptedAttribute", el)
}

// elementDecrypter decrypts SAML elements of the EncryptedElementType of SAMLCore §2.2.4 which were encrypted to
// this entity. It must only be given an element that is covered by a verified signature or was received from an
// authenticated peer, as errata E93 asks, because the block ciphers in CBC mode don't protect their own integrity.
type elementDecrypter struct {
	// keys are the private keys of this entity, in the order to try them. See candidateKeys.
	keys []decryptionKey

	// recipient is the identifier of this entity, which selects among several EncryptedKey elements.
	recipient string

	// policy restricts the algorithms that are accepted. Nil accepts every algorithm registered with xmlenc.
	policy *encryptionPolicy
}

// decrypt returns the element that encryptedEl holds, parsed on its own. The key is taken from an EncryptedKey
// inside the EncryptedData or beside it. One that the receiver would have to find by other means isn't supported.
func (d elementDecrypter) decrypt(encryptedEl *etree.Element) (*etree.Element, error) {
	encryptedDataEl, err := findOneChild(encryptedEl, xmlencNamespace, "EncryptedData")
	if err != nil {
		return nil, err
	}

	// SAMLCore §6.1: the Type may be omitted, and otherwise MUST be this value.
	if t := encryptedDataEl.SelectAttrValue("Type", xmlencElementType); t != xmlencElementType {
		return nil, fmt.Errorf("the EncryptedData has the Type %q, which is not an element", t)
	}

	if d.policy != nil {
		if err = d.policy.acceptsContentEncryption(encryptedDataEl); err != nil {
			return nil, err
		}
	}

	// The content encryption key is decrypted here, with each of the keys of this entity that may hold it, and
	// xmlenc is given the EncryptedData without the EncryptedKey that it would decrypt with a single key.
	dataEl := encryptedDataEl

	var encryptedKeyEls []*etree.Element

	if embeddedKeyEl := encryptedDataEl.FindElement("./KeyInfo/EncryptedKey"); embeddedKeyEl != nil {
		encryptedKeyEls = []*etree.Element{embeddedKeyEl}

		dataEl = encryptedDataEl.Copy()
		dataEl.RemoveChild(dataEl.FindElement("./KeyInfo"))
	} else if encryptedKeyEls, err = d.encryptedKeys(encryptedEl, encryptedDataEl); err != nil {
		return nil, err
	}

	if len(encryptedKeyEls) == 0 {
		return nil, errors.New("the EncryptedData has no EncryptedKey")
	}

	key, err := d.decryptKey(encryptedKeyEls)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key from response: %s", err)
	}

	plaintext, err := xmlenc.Decrypt(key, dataEl)
	if err != nil {
		return nil, err
	}

	if err := xrv.Validate(bytes.NewReader(plaintext)); err != nil {
		return nil, fmt.Errorf("plaintext response contains invalid XML: %s", err)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(plaintext); err != nil {
		return nil, fmt.Errorf("cannot parse plaintext response %v", err)
	}

	if doc.Root() == nil {
		return nil, errors.New("plaintext response has no element")
	}

	return doc.Root(), nil
}

// encryptedKeys returns the EncryptedKey elements beside encryptedDataEl, in the order to try them. Errata E43
// has the EncryptedData reference its key with a RetrievalMethod, which is followed when it names a key that is
// present, and describes the Recipient as a hint to which key is meant for whom: those for this entity come
// first, then those which name no recipient, then the rest.
func (d elementDecrypter) encryptedKeys(encryptedEl, encryptedDataEl *etree.Element) ([]*etree.Element, error) {
	encryptedKeyEls, err := findChildren(encryptedEl, xmlencNamespace, "EncryptedKey")
	if err != nil {
		return nil, err
	}

	if retrievalMethodEl := encryptedDataEl.FindElement("./KeyInfo/RetrievalMethod"); retrievalMethodEl != nil {
		if id, ok := strings.CutPrefix(retrievalMethodEl.SelectAttrValue("URI", ""), "#"); ok && id != "" {
			var referenced []*etree.Element

			for _, encryptedKeyEl := range encryptedKeyEls {
				if encryptedKeyEl.SelectAttrValue("Id", "") == id {
					referenced = append(referenced, encryptedKeyEl)
				}
			}

			if len(referenced) != 0 {
				encryptedKeyEls = referenced
			}
		}
	}

	rank := func(encryptedKeyEl *etree.Element) int {
		switch encryptedKeyEl.SelectAttrValue("Recipient", "") {
		case "":
			return 1
		case d.recipient:
			return 0
		default:
			return 2
		}
	}

	slices.SortStableFunc(encryptedKeyEls, func(a, b *etree.Element) int { return rank(a) - rank(b) })

	if len(encryptedKeyEls) > maxEncryptedKeys {
		encryptedKeyEls = encryptedKeyEls[:maxEncryptedKeys]
	}

	return encryptedKeyEls, nil
}

// decryptKey returns the content encryption key of the first of encryptedKeyEls that this entity can decrypt, as
// errata E43 recommends, or the error of the first one.
func (d elementDecrypter) decryptKey(encryptedKeyEls []*etree.Element) ([]byte, error) {
	var firstErr error

	for _, encryptedKeyEl := range encryptedKeyEls {
		key, err := d.decryptOneKey(encryptedKeyEl)
		if err == nil {
			return key, nil
		}

		if firstErr == nil {
			firstErr = err
		}
	}

	return nil, firstErr
}

// decryptOneKey returns the content encryption key that encryptedKeyEl wraps, decrypted with the first of the
// candidate keys of this entity which can, or the error of the first one.
//
// Every candidate is used, also after one has decrypted the key. The number of private key operations then only
// depends on the keys of this entity and on the KeyInfo, which the sender wrote in the clear, and never on which
// key decrypts or on whether one does. The time that an answer takes would otherwise tell a requester so, which is
// more than errata E93 lets it learn about a ciphertext it may not have made.
func (d elementDecrypter) decryptOneKey(encryptedKeyEl *etree.Element) ([]byte, error) {
	if d.policy != nil {
		if err := d.policy.acceptsKeyTransport(encryptedKeyEl); err != nil {
			return nil, err
		}
	}

	if len(d.keys) == 0 {
		return nil, errors.New("there is no private key to decrypt with")
	}

	var (
		decrypted []byte
		firstErr  error
	)

	for _, candidate := range d.candidateKeys(encryptedKeyEl) {
		key, err := xmlenc.Decrypt(candidate.key, encryptedKeyEl)

		switch {
		case err != nil && firstErr == nil:
			firstErr = err
		case err == nil && decrypted == nil:
			decrypted = key
		}
	}

	if decrypted == nil {
		return nil, firstErr
	}

	return decrypted, nil
}

// candidateKeys returns the keys of this entity to decrypt encryptedKeyEl with: those whose certificate its
// KeyInfo identifies, or all of them if it identifies none. The KeyInfo is a hint, which the Metadata
// Interoperability Profile §2.5.1 says of every form but the key itself, so several keys may be identified, such as
// by a name that the certificates of one entity share. A hint for a key that this entity doesn't hold rules
// nothing out, except that xmlenc refuses to decrypt with a key which is not that of an X509Certificate.
func (d elementDecrypter) candidateKeys(encryptedKeyEl *etree.Element) []decryptionKey {
	if len(d.keys) < 2 {
		return d.keys
	}

	keyInfoEl, err := findChild(encryptedKeyEl, xmldsigNamespace, "KeyInfo")
	if err != nil || keyInfoEl == nil {
		return d.keys
	}

	var identified []decryptionKey

	for _, key := range d.keys {
		if key.certificate != nil && keyInfoIdentifies(keyInfoEl, key.certificate) {
			identified = append(identified, key)
		}
	}

	if len(identified) == 0 {
		return d.keys
	}

	return identified
}

const (
	xmldsigNamespace   = "http://www.w3.org/2000/09/xmldsig#"
	xmldsig11Namespace = "http://www.w3.org/2009/xmldsig11#"
)

// x509DigestHashes are the hashes of the X509Digest of XML Signature 1.1 §4.5.4.1 that are compared, by the
// identifier of the digest.
var x509DigestHashes = map[string]crypto.Hash{
	"http://www.w3.org/2000/09/xmldsig#sha1":        crypto.SHA1,
	"http://www.w3.org/2001/04/xmlenc#sha256":       crypto.SHA256,
	"http://www.w3.org/2001/04/xmldsig-more#sha384": crypto.SHA384,
	"http://www.w3.org/2001/04/xmlenc#sha512":       crypto.SHA512,
}

// keyInfoIdentifies returns whether a child of keyInfoEl identifies cert (XML Signature §4.4): a KeyName which is
// its subject or the common name of its subject, the RSAKeyValue of its key, or in an X509Data the certificate,
// its subject key identifier, its subject or its digest. An X509IssuerSerial is not compared, as the forms in
// which a distinguished name can be written differ.
func keyInfoIdentifies(keyInfoEl *etree.Element, cert *x509.Certificate) bool {
	for _, el := range keyInfoEl.ChildElements() {
		if el.NamespaceURI() != xmldsigNamespace {
			continue
		}

		switch el.Tag {
		case "KeyName":
			if name := strings.TrimSpace(el.Text()); name != "" && (name == cert.Subject.String() || name == cert.Subject.CommonName) {
				return true
			}
		case "KeyValue":
			if rsaKeyValueIs(el, cert) {
				return true
			}
		case "X509Data":
			if slices.ContainsFunc(el.ChildElements(), func(child *etree.Element) bool { return x509DataIdentifies(child, cert) }) {
				return true
			}
		}
	}

	return false
}

// x509DataIdentifies returns whether el, a child of an X509Data, identifies cert.
func x509DataIdentifies(el *etree.Element, cert *x509.Certificate) bool {
	text := strings.TrimSpace(el.Text())

	switch {
	case el.NamespaceURI() == xmldsigNamespace && el.Tag == "X509Certificate":
		return base64Equal(text, cert.Raw)
	case el.NamespaceURI() == xmldsigNamespace && el.Tag == "X509SKI":
		return base64Equal(text, cert.SubjectKeyId)
	case el.NamespaceURI() == xmldsigNamespace && el.Tag == "X509SubjectName":
		return text != "" && text == cert.Subject.String()
	case el.NamespaceURI() == xmldsig11Namespace && el.Tag == "X509Digest":
		hash, ok := x509DigestHashes[el.SelectAttrValue("Algorithm", "")]
		if !ok || !hash.Available() {
			return false
		}

		digest := hash.New()
		digest.Write(cert.Raw)

		return base64Equal(text, digest.Sum(nil))
	}

	return false
}

// rsaKeyValueIs returns whether keyValueEl, a KeyValue, holds the RSA key of cert (XML Signature §4.4.2.2).
func rsaKeyValueIs(keyValueEl *etree.Element, cert *x509.Certificate) bool {
	public, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false
	}

	rsaKeyValueEl, err := findChild(keyValueEl, xmldsigNamespace, "RSAKeyValue")
	if err != nil || rsaKeyValueEl == nil {
		return false
	}

	modulusEl, err := findChild(rsaKeyValueEl, xmldsigNamespace, "Modulus")
	if err != nil || modulusEl == nil {
		return false
	}

	exponentEl, err := findChild(rsaKeyValueEl, xmldsigNamespace, "Exponent")
	if err != nil || exponentEl == nil {
		return false
	}

	return base64Equal(modulusEl.Text(), public.N.Bytes()) && base64Equal(exponentEl.Text(), big.NewInt(int64(public.E)).Bytes())
}

// base64Equal returns whether text is the base64 encoding of value, which is not empty. Whitespace in the text
// is ignored, as the encoding of a long value is wrapped.
func base64Equal(text string, value []byte) bool {
	if len(value) == 0 {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text), ""))

	return err == nil && bytes.Equal(decoded, value)
}

// decryptElement returns the element that encryptedEl holds, which must be the SAML assertion element named tag.
// The plaintext stands alone, so it must declare the namespace itself.
func (d elementDecrypter) decryptElement(encryptedEl *etree.Element, tag string) (*etree.Element, error) {
	el, err := d.decrypt(encryptedEl)
	if err != nil {
		return nil, err
	}

	if el.Tag != tag || el.NamespaceURI() != samlAssertionNamespace {
		return nil, fmt.Errorf("the %s holds a %s element, not a %s of the SAML assertion namespace", encryptedEl.Tag, el.Tag, tag)
	}

	return el, nil
}

// decryptNameID returns the NameID that the EncryptedID element holds (SAMLCore §2.2.4). An EncryptedID which
// holds an Assertion or an element derived from BaseID isn't supported. The NameID has the Format of the
// identifier that was encrypted, as the encrypted format is only a request (SAMLCore §3.4.1.1, errata E6).
func (d elementDecrypter) decryptNameID(encryptedIDEl *etree.Element) (*NameID, error) {
	el, err := d.decryptElement(encryptedIDEl, "NameID")
	if err != nil {
		return nil, err
	}

	var nameID NameID
	if err = unmarshalElement(el, &nameID); err != nil {
		return nil, err
	}

	if nameID.Value == "" {
		return nil, errors.New("the EncryptedID holds a NameID with no value")
	}

	if nameID.Format == string(EncryptedNameIDFormat) {
		return nil, errors.New("the EncryptedID holds a NameID of the encrypted format, which is not a format of an identifier")
	}

	return &nameID, nil
}

// acceptsContentEncryption returns an error unless the policy allows the block cipher of encryptedDataEl.
func (policy *encryptionPolicy) acceptsContentEncryption(encryptedDataEl *etree.Element) error {
	algorithm := ""
	if methodEl := encryptedDataEl.FindElement("./EncryptionMethod"); methodEl != nil {
		algorithm = methodEl.SelectAttrValue("Algorithm", "")
	}

	if !slices.ContainsFunc(policy.content, func(c xmlenc.BlockCipher) bool { return c.Algorithm() == algorithm }) {
		return fmt.Errorf("the content encryption algorithm %q is not allowed", algorithm)
	}

	return nil
}

// acceptsKeyTransport returns an error unless the policy allows the key transport algorithm of encryptedKeyEl
// with its digest and mask generation function. Those it doesn't name are SHA-1 and MGF1 with SHA-1 (XML
// Encryption §5.4.2 and XML Encryption 1.1 §5.5.2).
func (policy *encryptionPolicy) acceptsKeyTransport(encryptedKeyEl *etree.Element) error {
	methodEl := encryptedKeyEl.FindElement("./EncryptionMethod")
	if methodEl == nil {
		return errors.New("the EncryptedKey has no EncryptionMethod")
	}

	algorithm := methodEl.SelectAttrValue("Algorithm", "")
	if !slices.Contains(policy.keyTransports, algorithm) {
		return fmt.Errorf("the key transport algorithm %q is not allowed", algorithm)
	}

	digest := keyTransportDigests[0].method.Algorithm()
	if digestEl := methodEl.FindElement("./DigestMethod"); digestEl != nil {
		digest = digestEl.SelectAttrValue("Algorithm", "")
	}

	if _, ok := lookupKeyTransportDigest(policy.digests, digest); !ok {
		return fmt.Errorf("the key transport digest %q is not allowed", digest)
	}

	// XML Encryption §5.4.2 fixes the mask generation function of RSA-OAEP-MGF1P.
	if algorithm != algorithmRSAOAEP2009 {
		return nil
	}

	mgf := keyTransportDigests[0].mgf
	if mgfEl := methodEl.FindElement("./MGF"); mgfEl != nil {
		mgf = mgfEl.SelectAttrValue("Algorithm", "")
	}

	if !slices.ContainsFunc(policy.digests, func(d keyTransportDigest) bool { return d.mgf == mgf }) {
		return fmt.Errorf("the mask generation function %q is not allowed", mgf)
	}

	return nil
}

// encrypter returns the encrypter for the key whose KeyDescriptor lists methods, negotiated as the Metadata
// Profile for Algorithm Support §2.5 requires. See IdpAuthnRequest.assertionEncrypter.
func (policy *encryptionPolicy) encrypter(methods []EncryptionMethod) (xmlenc.RSA, error) {
	content, err := policy.contentEncryption(methods)
	if err != nil {
		return xmlenc.RSA{}, err
	}

	encrypter, err := policy.keyTransport(methods)
	if err != nil {
		return xmlenc.RSA{}, err
	}

	encrypter.BlockCipher = content

	return encrypter, nil
}
