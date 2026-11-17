package saml

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
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
	// certificate holds the RSA key of the entity, from the KeyDescriptor of its metadata.
	certificate *x509.Certificate

	// encrypter has the key transport and content encryption algorithms negotiated with the entity.
	encrypter xmlenc.RSA

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

	encryptedDataEl, err := e.encrypter.Encrypt(e.certificate, buf, nil)
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
	// key is the private key of this entity, which must be an *rsa.PrivateKey.
	key crypto.PrivateKey

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

	var key any = d.key

	if embeddedKeyEl := encryptedDataEl.FindElement("./KeyInfo/EncryptedKey"); embeddedKeyEl != nil {
		// xmlenc decrypts a key inside the EncryptedData itself.
		if d.policy != nil {
			if err = d.policy.acceptsKeyTransport(embeddedKeyEl); err != nil {
				return nil, err
			}
		}
	} else {
		encryptedKeyEls, err := d.encryptedKeys(encryptedEl, encryptedDataEl)
		if err != nil {
			return nil, err
		}

		if len(encryptedKeyEls) != 0 {
			if key, err = d.decryptKey(encryptedKeyEls); err != nil {
				return nil, fmt.Errorf("failed to decrypt key from response: %s", err)
			}
		}
	}

	plaintext, err := xmlenc.Decrypt(key, encryptedDataEl)
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

// decryptOneKey returns the content encryption key that encryptedKeyEl wraps.
func (d elementDecrypter) decryptOneKey(encryptedKeyEl *etree.Element) ([]byte, error) {
	if d.policy != nil {
		if err := d.policy.acceptsKeyTransport(encryptedKeyEl); err != nil {
			return nil, err
		}
	}

	return xmlenc.Decrypt(d.key, encryptedKeyEl)
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
