package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

const encryptedElementRecipient = "https://sp.example.com/saml2/metadata"

// testElementEncrypter returns an encrypter to the negotiation key, with the algorithms negotiated from methods.
func testElementEncrypter(t *testing.T, methods ...EncryptionMethod) *elementEncrypter {
	t.Helper()

	_, cert := negotiationKey()

	policy, err := (*IdentityProvider)(nil).encryptionPolicy()
	assert.NilError(t, err)

	encrypter, err := policy.encrypter(methods)
	assert.NilError(t, err)

	return &elementEncrypter{certificate: cert, encrypter: encrypter, recipient: encryptedElementRecipient}
}

func testElementDecrypter() elementDecrypter {
	key, _ := negotiationKey()

	return elementDecrypter{key: key, recipient: encryptedElementRecipient}
}

// reparse serializes el and parses it again, as a receiver would see it.
func reparse(t *testing.T, el *etree.Element) *etree.Element {
	t.Helper()

	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())

	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)

	parsed := etree.NewDocument()
	assert.NilError(t, parsed.ReadFromBytes(buf))

	return parsed.Root()
}

var testEncryptedNameID = NameID{
	Format:          string(PersistentNameIDFormat),
	NameQualifier:   "https://idp.example.com/saml/metadata",
	SPNameQualifier: encryptedElementRecipient,
	Value:           "p-1234",
}

func TestElementEncrypterNameIDRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name    string
		methods []EncryptionMethod
		content string
		key     string
	}{
		{"defaults", nil, aes128CBC, rsaOAEP},
		{"aes-128-gcm", []EncryptionMethod{method(aes128GCM)}, aes128GCM, rsaOAEP},
		{"aes-192-gcm", []EncryptionMethod{method(aes192GCM)}, aes192GCM, rsaOAEP},
		{"aes-256-gcm", []EncryptionMethod{method(aes256GCM)}, aes256GCM, rsaOAEP},
		{"aes-192-cbc", []EncryptionMethod{method(aes192CBC)}, aes192CBC, rsaOAEP},
		{"aes-256-cbc", []EncryptionMethod{method(aes256CBC)}, aes256CBC, rsaOAEP},
		{"oaep 1.1 sha-256", []EncryptionMethod{method(aes128GCM), oaepMethod(rsaOAEP11, digestSHA256, mgf1SHA256)}, aes128GCM, rsaOAEP11},
		{"oaep mgf1p sha-512", []EncryptionMethod{oaepMethod(rsaOAEP, digestSHA512, "")}, aes128CBC, rsaOAEP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encryptedID, err := testElementEncrypter(t, tc.methods...).encryptNameID(&testEncryptedNameID)
			assert.NilError(t, err)

			encryptedID = reparse(t, encryptedID)
			assert.Check(t, is.Equal("EncryptedID", encryptedID.Tag))
			assert.Check(t, is.Equal(samlAssertionNamespace, encryptedID.NamespaceURI()))

			// SAMLCore §2.2.4 and §6.1.
			data := encryptedID.FindElement("./EncryptedData")
			assert.Assert(t, data != nil)
			assert.Check(t, is.Equal(xmlencElementType, data.SelectAttrValue("Type", "")))
			assert.Check(t, is.Equal(tc.content, data.FindElement("./EncryptionMethod").SelectAttrValue("Algorithm", "")))

			key := data.FindElement("./KeyInfo/EncryptedKey")
			assert.Assert(t, key != nil)
			assert.Check(t, is.Equal(encryptedElementRecipient, key.SelectAttrValue("Recipient", "")))
			assert.Check(t, is.Equal(tc.key, key.FindElement("./EncryptionMethod").SelectAttrValue("Algorithm", "")))

			// The identifier isn't visible in what is sent.
			assert.Check(t, !strings.Contains(elementToString(encryptedID), testEncryptedNameID.Value))

			nameID, err := testElementDecrypter().decryptNameID(encryptedID)
			assert.NilError(t, err)
			assert.Check(t, is.DeepEqual(testEncryptedNameID, *nameID))
		})
	}
}

func TestElementEncrypterAttributeRoundTrip(t *testing.T) {
	attribute := Attribute{
		FriendlyName: "mail",
		Name:         "urn:oid:0.9.2342.19200300.100.1.3",
		NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
		Values:       []AttributeValue{{Type: "xs:string", Value: "alice@example.com"}, {Type: "xs:string", Value: "a@example.com"}},
	}

	encrypted, err := testElementEncrypter(t, method(aes128GCM)).encryptAttribute(&attribute)
	assert.NilError(t, err)

	encrypted = reparse(t, encrypted)
	assert.Check(t, is.Equal("EncryptedAttribute", encrypted.Tag))
	assert.Check(t, !strings.Contains(elementToString(encrypted), "alice@example.com"))

	el, err := testElementDecrypter().decryptElement(encrypted, "Attribute")
	assert.NilError(t, err)

	var got Attribute

	assert.NilError(t, unmarshalElement(el, &got))
	assert.Check(t, is.DeepEqual(attribute, got))
}

func TestElementEncrypterCiphertextIsUnique(t *testing.T) {
	// SAMLCore §2.2.4: the ciphertext MUST be unique to any given encryption operation.
	encrypter := testElementEncrypter(t, method(aes128GCM))

	seen := map[string]bool{}

	for range 4 {
		el, err := encrypter.encryptNameID(&testEncryptedNameID)
		assert.NilError(t, err)

		for _, value := range el.FindElements(".//CipherValue") {
			assert.Check(t, !seen[value.Text()], "a cipher value was repeated")

			seen[value.Text()] = true
		}
	}

	assert.Check(t, is.Len(seen, 8))
}

func TestElementDecrypterRejects(t *testing.T) {
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)

	gcmOnly, err := (&IdentityProvider{ContentEncryptionMethods: []string{aes128GCM}}).encryptionPolicy()
	assert.NilError(t, err)

	sha256Only, err := (&IdentityProvider{KeyTransportDigestMethods: []string{digestSHA256}}).encryptionPolicy()
	assert.NilError(t, err)

	flip := func(path string) func(*testing.T, *etree.Element) {
		return func(t *testing.T, el *etree.Element) {
			value := el.FindElement(path)
			assert.Assert(t, value != nil)

			buf, err := base64.StdEncoding.DecodeString(value.Text())
			assert.NilError(t, err)

			buf[len(buf)-1] ^= 0x01
			value.SetText(base64.StdEncoding.EncodeToString(buf))
		}
	}

	for _, tc := range []struct {
		name      string
		content   string
		decrypter func(*elementDecrypter)
		mutate    func(*testing.T, *etree.Element)
		plaintext *etree.Element
		err       string
	}{
		{name: "wrong key", content: aes128GCM, decrypter: func(d *elementDecrypter) { d.key = otherKey }, err: "certificate does not match provided key"},
		{name: "no key", content: aes128GCM, decrypter: func(d *elementDecrypter) { d.key = nil }, err: "expected key to be a *rsa.PrivateKey"},
		{name: "tampered gcm ciphertext", content: aes128GCM, mutate: flip("./EncryptedData/CipherData/CipherValue"), err: "message authentication failed"},
		{name: "tampered cbc ciphertext", content: aes128CBC, mutate: flip("./EncryptedData/CipherData/CipherValue"), err: ""},
		{name: "tampered key", content: aes128GCM, mutate: flip("./EncryptedData/KeyInfo/EncryptedKey/CipherData/CipherValue"), err: "decryption error"},
		{
			name: "type is content", content: aes128GCM,
			mutate: func(_ *testing.T, el *etree.Element) {
				el.FindElement("./EncryptedData").CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Content")
			},
			err: "which is not an element",
		},
		{
			name: "no encrypted data", content: aes128GCM,
			mutate: func(_ *testing.T, el *etree.Element) { el.RemoveChild(el.FindElement("./EncryptedData")) },
			err:    "cannot find http://www.w3.org/2001/04/xmlenc#:EncryptedData element",
		},
		{name: "content algorithm outside the policy", content: aes128CBC, decrypter: func(d *elementDecrypter) { d.policy = gcmOnly }, err: `the content encryption algorithm "http://www.w3.org/2001/04/xmlenc#aes128-cbc" is not allowed`},
		{name: "digest outside the policy", content: aes128GCM, decrypter: func(d *elementDecrypter) { d.policy = sha256Only }, err: `the key transport digest "http://www.w3.org/2000/09/xmldsig#sha1" is not allowed`},
		{
			name: "plaintext is not a name id", content: aes128GCM,
			plaintext: func() *etree.Element {
				el := etree.NewElement("saml:Issuer")
				el.CreateAttr("xmlns:saml", samlAssertionNamespace)
				el.SetText("p-1234")

				return el
			}(),
			err: "the EncryptedID holds a Issuer element, not a NameID of the SAML assertion namespace",
		},
		{
			name: "plaintext is a name id of another namespace", content: aes128GCM,
			plaintext: func() *etree.Element {
				el := etree.NewElement("NameID")
				el.CreateAttr("xmlns", "urn:example:other")
				el.SetText("p-1234")

				return el
			}(),
			err: "the EncryptedID holds a NameID element, not a NameID of the SAML assertion namespace",
		},
		{
			name: "plaintext does not declare its namespace", content: aes128GCM,
			plaintext: func() *etree.Element {
				el := etree.NewElement("saml:NameID")
				el.SetText("p-1234")

				return el
			}(),
			err: "not a NameID of the SAML assertion namespace",
		},
		{
			name: "name id has no value", content: aes128GCM,
			plaintext: func() *etree.Element {
				el := etree.NewElement("saml:NameID")
				el.CreateAttr("xmlns:saml", samlAssertionNamespace)

				return el
			}(),
			err: "the EncryptedID holds a NameID with no value",
		},
		{
			name: "name id has the encrypted format", content: aes128GCM,
			plaintext: func() *etree.Element {
				el := etree.NewElement("saml:NameID")
				el.CreateAttr("xmlns:saml", samlAssertionNamespace)
				el.CreateAttr("Format", string(EncryptedNameIDFormat))
				el.SetText("p-1234")

				return el
			}(),
			err: "which is not a format of an identifier",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encrypter := testElementEncrypter(t, method(tc.content))

			var (
				encryptedID *etree.Element
				err         error
			)

			if tc.plaintext != nil {
				encryptedID, err = encrypter.encrypt("EncryptedID", tc.plaintext)
			} else {
				encryptedID, err = encrypter.encryptNameID(&testEncryptedNameID)
			}

			assert.NilError(t, err)

			encryptedID = reparse(t, encryptedID)
			if tc.mutate != nil {
				tc.mutate(t, encryptedID)
			}

			decrypter := testElementDecrypter()
			if tc.decrypter != nil {
				tc.decrypter(&decrypter)
			}

			nameID, err := decrypter.decryptNameID(encryptedID)
			assert.Check(t, nameID == nil)

			if tc.err == "" {
				// CBC has no integrity protection, so what the tampering breaks varies: the padding, the XML or
				// the element. It must never yield the identifier.
				assert.Check(t, err != nil)
			} else {
				assert.Check(t, is.ErrorContains(err, tc.err))
			}
		})
	}
}

// siblingKey moves the EncryptedKey of encryptedEl out of its EncryptedData, to be its sibling, which is the
// other placement errata E43 describes, and returns it.
func siblingKey(t *testing.T, encryptedEl *etree.Element) *etree.Element {
	t.Helper()

	data := encryptedEl.FindElement("./EncryptedData")
	keyInfo := data.FindElement("./KeyInfo")
	key := keyInfo.FindElement("./EncryptedKey")
	assert.Assert(t, key != nil)

	keyInfo.RemoveChild(key)

	retrieval := keyInfo.CreateElement("ds:RetrievalMethod")
	retrieval.CreateAttr("URI", "#"+key.SelectAttrValue("Id", ""))
	retrieval.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#EncryptedKey")

	encryptedEl.AddChild(key)

	return key
}

func TestElementDecrypterSiblingKeys(t *testing.T) {
	encrypt := func(t *testing.T) *etree.Element {
		t.Helper()

		el, err := testElementEncrypter(t, method(aes128GCM)).encryptNameID(&testEncryptedNameID)
		assert.NilError(t, err)

		return el
	}

	// decoy returns a key which this entity can't unwrap, as if it were wrapped for another.
	decoy := func(t *testing.T, recipient string) *etree.Element {
		t.Helper()

		key := encrypt(t).FindElement("./EncryptedData/KeyInfo/EncryptedKey")
		key.RemoveAttr("Recipient")

		if recipient != "" {
			key.CreateAttr("Recipient", recipient)
		}

		value := key.FindElement("./CipherData/CipherValue")

		buf, err := base64.StdEncoding.DecodeString(value.Text())
		assert.NilError(t, err)

		buf[0] ^= 0x01
		value.SetText(base64.StdEncoding.EncodeToString(buf))

		return key
	}

	t.Run("referenced key", func(t *testing.T) {
		el := encrypt(t)
		siblingKey(t, el)

		nameID, err := testElementDecrypter().decryptNameID(reparse(t, el))
		assert.NilError(t, err)
		assert.Check(t, is.Equal(testEncryptedNameID.Value, nameID.Value))
	})

	t.Run("key for this recipient among others", func(t *testing.T) {
		el := encrypt(t)
		key := siblingKey(t, el)
		el.RemoveChild(key)

		// The reference is dropped, so only the Recipient tells the keys apart.
		keyInfo := el.FindElement("./EncryptedData/KeyInfo")
		keyInfo.RemoveChild(keyInfo.FindElement("./RetrievalMethod"))

		el.AddChild(decoy(t, "https://other.example.com/"))
		el.AddChild(decoy(t, ""))
		el.AddChild(key)

		decrypter := testElementDecrypter()

		ordered, err := decrypter.encryptedKeys(el, el.FindElement("./EncryptedData"))
		assert.NilError(t, err)
		assert.Assert(t, is.Len(ordered, 3))
		assert.Check(t, is.Equal(encryptedElementRecipient, ordered[0].SelectAttrValue("Recipient", "")))
		assert.Check(t, is.Equal("", ordered[1].SelectAttrValue("Recipient", "")))

		nameID, err := decrypter.decryptNameID(reparse(t, el))
		assert.NilError(t, err)
		assert.Check(t, is.Equal(testEncryptedNameID.Value, nameID.Value))
	})

	t.Run("first key understood is used", func(t *testing.T) {
		el := encrypt(t)
		key := siblingKey(t, el)
		el.RemoveChild(key)
		key.RemoveAttr("Recipient")

		keyInfo := el.FindElement("./EncryptedData/KeyInfo")
		keyInfo.RemoveChild(keyInfo.FindElement("./RetrievalMethod"))

		el.AddChild(decoy(t, ""))
		el.AddChild(key)

		nameID, err := testElementDecrypter().decryptNameID(reparse(t, el))
		assert.NilError(t, err)
		assert.Check(t, is.Equal(testEncryptedNameID.Value, nameID.Value))
	})

	t.Run("too many keys", func(t *testing.T) {
		el := encrypt(t)
		key := siblingKey(t, el)
		el.RemoveChild(key)
		key.RemoveAttr("Recipient")

		keyInfo := el.FindElement("./EncryptedData/KeyInfo")
		keyInfo.RemoveChild(keyInfo.FindElement("./RetrievalMethod"))

		for range maxEncryptedKeys {
			el.AddChild(decoy(t, ""))
		}

		el.AddChild(key)

		_, err := testElementDecrypter().decryptNameID(reparse(t, el))
		assert.Check(t, is.ErrorContains(err, "failed to decrypt key from response"))
	})

	t.Run("no key", func(t *testing.T) {
		el := encrypt(t)
		el.RemoveChild(siblingKey(t, el))

		_, err := testElementDecrypter().decryptNameID(reparse(t, el))
		assert.Check(t, err != nil)
	})
}

func TestEncryptedIDReplacesNameIDWhenSerialized(t *testing.T) {
	encryptedID, err := testElementEncrypter(t).encryptNameID(&testEncryptedNameID)
	assert.NilError(t, err)

	nameID := testEncryptedNameID

	subject := Subject{NameID: &nameID, EncryptedID: encryptedID}
	el := subject.Element()
	assert.Check(t, el.FindElement("./NameID") == nil)
	assert.Check(t, el.FindElement("./EncryptedID") != nil)

	confirmation := SubjectConfirmation{Method: bearerSubjectConfirmationMethod, NameID: &nameID, EncryptedID: encryptedID}
	el = confirmation.Element()
	assert.Check(t, el.FindElement("./NameID") == nil)
	assert.Check(t, el.FindElement("./EncryptedID") != nil)

	request := LogoutRequest{ID: "id-1", Version: "2.0", NameID: &nameID, EncryptedID: encryptedID, SessionIndexes: []SessionIndex{{Value: "1"}}}
	el = request.Element()
	assert.Check(t, el.FindElement("./NameID") == nil)
	assert.Check(t, !strings.Contains(elementToString(el), nameID.Value))

	// SAMLCore §3.7.1: the identifier comes before the SessionIndex elements.
	children := el.ChildElements()
	assert.Assert(t, is.Len(children, 2))
	assert.Check(t, is.Equal("EncryptedID", children[0].Tag))

	encryptedAttribute, err := testElementEncrypter(t).encryptAttribute(&Attribute{Name: "secret", Values: []AttributeValue{{Value: "s3cret"}}})
	assert.NilError(t, err)

	statement := AttributeStatement{
		Attributes:          []Attribute{{Name: "public", Values: []AttributeValue{{Value: "p"}}}},
		EncryptedAttributes: []*etree.Element{encryptedAttribute},
	}
	el = statement.Element()
	assert.Assert(t, is.Len(el.ChildElements(), 2))
	assert.Check(t, is.Equal("Attribute", el.ChildElements()[0].Tag))
	assert.Check(t, is.Equal("EncryptedAttribute", el.ChildElements()[1].Tag))
	assert.Check(t, !strings.Contains(elementToString(el), "s3cret"))
}
