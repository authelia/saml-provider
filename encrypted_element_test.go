package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const encryptedElementRecipient = "https://sp.example.com/saml2/metadata"

// testElementEncrypter returns an encrypter to the negotiation key, with the algorithms negotiated from methods.
func testElementEncrypter(t *testing.T, methods ...EncryptionMethod) *elementEncrypter {
	t.Helper()

	_, cert := negotiationKey()

	policy, err := (*IdentityProvider)(nil).encryptionPolicy()
	require.NoError(t, err)

	encrypter, err := policy.encrypter(methods)
	require.NoError(t, err)

	return &elementEncrypter{certificate: cert, encrypter: encrypter, recipient: encryptedElementRecipient}
}

func testElementDecrypter() elementDecrypter {
	key, cert := negotiationKey()

	return elementDecrypter{keys: []decryptionKey{{certificate: cert, key: key}}, recipient: encryptedElementRecipient}
}

// reparse serializes el and parses it again, as a receiver would see it.
func reparse(t *testing.T, el *etree.Element) *etree.Element {
	t.Helper()

	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())

	buf, err := doc.WriteToBytes()
	require.NoError(t, err)

	parsed := etree.NewDocument()
	require.NoError(t, parsed.ReadFromBytes(buf))

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
		{"defaults", nil, aes128GCM, rsaOAEP},
		{"aes-128-gcm", []EncryptionMethod{method(aes128GCM)}, aes128GCM, rsaOAEP},
		{"aes-192-gcm", []EncryptionMethod{method(aes192GCM)}, aes192GCM, rsaOAEP},
		{"aes-256-gcm", []EncryptionMethod{method(aes256GCM)}, aes256GCM, rsaOAEP},
		{"aes-192-cbc", []EncryptionMethod{method(aes192CBC)}, aes192CBC, rsaOAEP},
		{"aes-256-cbc", []EncryptionMethod{method(aes256CBC)}, aes256CBC, rsaOAEP},
		{"oaep 1.1 sha-256", []EncryptionMethod{method(aes128GCM), oaepMethod(rsaOAEP11, digestSHA256, mgf1SHA256)}, aes128GCM, rsaOAEP11},
		{"oaep mgf1p sha-512", []EncryptionMethod{oaepMethod(rsaOAEP, digestSHA512, "")}, aes128GCM, rsaOAEP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encryptedID, err := testElementEncrypter(t, tc.methods...).encryptNameID(&testEncryptedNameID)
			require.NoError(t, err)

			encryptedID = reparse(t, encryptedID)
			assert.Equal(t, "EncryptedID", encryptedID.Tag)
			assert.Equal(t, samlAssertionNamespace, encryptedID.NamespaceURI())

			// SAMLCore §2.2.4 and §6.1.
			data := encryptedID.FindElement("./EncryptedData")
			require.NotNil(t, data)
			assert.Equal(t, xmlencElementType, data.SelectAttrValue("Type", ""))
			assert.Equal(t, tc.content, data.FindElement("./EncryptionMethod").SelectAttrValue("Algorithm", ""))

			key := data.FindElement("./KeyInfo/EncryptedKey")
			require.NotNil(t, key)
			assert.Equal(t, encryptedElementRecipient, key.SelectAttrValue("Recipient", ""))
			assert.Equal(t, tc.key, key.FindElement("./EncryptionMethod").SelectAttrValue("Algorithm", ""))

			// The identifier isn't visible in what is sent.
			assert.False(t, strings.Contains(elementToString(encryptedID), testEncryptedNameID.Value))

			nameID, err := testElementDecrypter().decryptNameID(encryptedID)
			require.NoError(t, err)
			assert.Equal(t, testEncryptedNameID, *nameID)
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
	require.NoError(t, err)

	encrypted = reparse(t, encrypted)
	assert.Equal(t, "EncryptedAttribute", encrypted.Tag)
	assert.False(t, strings.Contains(elementToString(encrypted), "alice@example.com"))

	el, err := testElementDecrypter().decryptElement(encrypted, "Attribute")
	require.NoError(t, err)

	var got Attribute

	require.NoError(t, unmarshalElement(el, &got))
	assert.Equal(t, attribute, got)
}

func TestElementEncrypterCiphertextIsUnique(t *testing.T) {
	// SAMLCore §2.2.4: the ciphertext MUST be unique to any given encryption operation.
	encrypter := testElementEncrypter(t, method(aes128GCM))

	seen := map[string]bool{}

	for range 4 {
		el, err := encrypter.encryptNameID(&testEncryptedNameID)
		require.NoError(t, err)

		for _, value := range el.FindElements(".//CipherValue") {
			assert.False(t, seen[value.Text()], "a cipher value was repeated")

			seen[value.Text()] = true
		}
	}

	assert.Len(t, seen, 8)
}

func TestElementDecrypterRejects(t *testing.T) {
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	gcmOnly, err := (&IdentityProvider{ContentEncryptionMethods: []string{aes128GCM}}).encryptionPolicy()
	require.NoError(t, err)

	sha256Only, err := (&IdentityProvider{KeyTransportDigestMethods: []string{digestSHA256}}).encryptionPolicy()
	require.NoError(t, err)

	flip := func(path string) func(*testing.T, *etree.Element) {
		return func(t *testing.T, el *etree.Element) { flipCipherValueBit(t, el, path, -1) }
	}

	for _, tc := range []struct {
		name      string
		content   string
		decrypter func(*elementDecrypter)
		mutate    func(*testing.T, *etree.Element)
		plaintext *etree.Element
		err       string
	}{
		{name: "wrong key", content: aes128GCM, decrypter: func(d *elementDecrypter) { d.keys = []decryptionKey{{key: otherKey}} }, err: "certificate does not match provided key"},
		{name: "no key", content: aes128GCM, decrypter: func(d *elementDecrypter) { d.keys = nil }, err: "there is no private key to decrypt with"},
		{name: "tampered gcm ciphertext", content: aes128GCM, mutate: flip("./EncryptedData/CipherData/CipherValue"), err: "message authentication failed"},
		{
			// CBC has no integrity protection, so a change is only found by what it does to the plaintext. One to the
			// IV makes the same change to the first block and no other, which here turns the "<" that opens the
			// element into a "=". See TestElementDecrypterTamperedCBCPadding for a change that may not be found.
			name: "tampered cbc initialization vector", content: aes128CBC,
			mutate: func(t *testing.T, el *etree.Element) {
				flipCipherValueBit(t, el, "./EncryptedData/CipherData/CipherValue", 0)
			},
			err: "cannot parse plaintext response",
		},
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

			require.NoError(t, err)

			encryptedID = reparse(t, encryptedID)
			if tc.mutate != nil {
				tc.mutate(t, encryptedID)
			}

			decrypter := testElementDecrypter()
			if tc.decrypter != nil {
				tc.decrypter(&decrypter)
			}

			nameID, err := decrypter.decryptNameID(encryptedID)
			assert.Nil(t, nameID)

			assert.ErrorContains(t, err, tc.err)
		})
	}
}

// flipCipherValueBit changes one bit of the byte at index of the CipherValue at path in el. A negative index
// counts from the end.
func flipCipherValueBit(t *testing.T, el *etree.Element, path string, index int) {
	t.Helper()

	value := el.FindElement(path)
	require.NotNil(t, value)

	buf, err := base64.StdEncoding.DecodeString(value.Text())
	require.NoError(t, err)

	if index < 0 {
		index += len(buf)
	}

	buf[index] ^= 0x01
	value.SetText(base64.StdEncoding.EncodeToString(buf))
}

// A change to the last block of a CBC ciphertext replaces the last block of the plaintext with bytes that nobody
// chose. The identifier here is a whole number of blocks, so that block holds nothing but the padding of XML
// Encryption §5.2, of which only the last byte has a meaning. The change is therefore refused, as it nearly always
// is, or the bytes happen to be padding again and the identifier is the one that was encrypted. It can never be
// another one. This is why the elementDecrypter must only be given what a signature or the peer vouches for.
func TestElementDecrypterTamperedCBCPadding(t *testing.T) {
	el := testEncryptedNameID.Element()
	el.CreateAttr("xmlns:saml", samlAssertionNamespace)

	doc := etree.NewDocument()
	doc.SetRoot(el)

	plaintext, err := doc.WriteToBytes()
	require.NoError(t, err)
	require.Equal(t, 0, len(plaintext)%16, "the last block must hold only padding")

	for range 64 {
		encryptedID, err := testElementEncrypter(t, method(aes128CBC)).encryptNameID(&testEncryptedNameID)
		require.NoError(t, err)

		encryptedID = reparse(t, encryptedID)
		flipCipherValueBit(t, encryptedID, "./EncryptedData/CipherData/CipherValue", -1)

		nameID, err := testElementDecrypter().decryptNameID(encryptedID)
		if err != nil {
			assert.Nil(t, nameID)

			continue
		}

		assert.Equal(t, testEncryptedNameID, *nameID)
	}
}

// siblingKey moves the EncryptedKey of encryptedEl out of its EncryptedData, to be its sibling, which is the
// other placement errata E43 describes, and returns it.
func siblingKey(t *testing.T, encryptedEl *etree.Element) *etree.Element {
	t.Helper()

	data := encryptedEl.FindElement("./EncryptedData")
	keyInfo := data.FindElement("./KeyInfo")
	key := keyInfo.FindElement("./EncryptedKey")
	require.NotNil(t, key)

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
		require.NoError(t, err)

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
		require.NoError(t, err)

		buf[0] ^= 0x01
		value.SetText(base64.StdEncoding.EncodeToString(buf))

		return key
	}

	t.Run("referenced key", func(t *testing.T) {
		el := encrypt(t)
		siblingKey(t, el)

		nameID, err := testElementDecrypter().decryptNameID(reparse(t, el))
		require.NoError(t, err)
		assert.Equal(t, testEncryptedNameID.Value, nameID.Value)
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
		require.NoError(t, err)
		require.Len(t, ordered, 3)
		assert.Equal(t, encryptedElementRecipient, ordered[0].SelectAttrValue("Recipient", ""))
		assert.Equal(t, "", ordered[1].SelectAttrValue("Recipient", ""))

		nameID, err := decrypter.decryptNameID(reparse(t, el))
		require.NoError(t, err)
		assert.Equal(t, testEncryptedNameID.Value, nameID.Value)
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
		require.NoError(t, err)
		assert.Equal(t, testEncryptedNameID.Value, nameID.Value)
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
		assert.ErrorContains(t, err, "failed to decrypt key from response")
	})

	t.Run("no key", func(t *testing.T) {
		el := encrypt(t)
		el.RemoveChild(siblingKey(t, el))

		_, err := testElementDecrypter().decryptNameID(reparse(t, el))
		assert.NotNil(t, err)
	})
}

func TestEncryptedIDReplacesNameIDWhenSerialized(t *testing.T) {
	encryptedID, err := testElementEncrypter(t).encryptNameID(&testEncryptedNameID)
	require.NoError(t, err)

	nameID := testEncryptedNameID

	subject := Subject{NameID: &nameID, EncryptedID: encryptedID}
	el := subject.Element()
	assert.Nil(t, el.FindElement("./NameID"))
	assert.NotNil(t, el.FindElement("./EncryptedID"))

	confirmation := SubjectConfirmation{Method: bearerSubjectConfirmationMethod, NameID: &nameID, EncryptedID: encryptedID}
	el = confirmation.Element()
	assert.Nil(t, el.FindElement("./NameID"))
	assert.NotNil(t, el.FindElement("./EncryptedID"))

	request := LogoutRequest{ID: "id-1", Version: "2.0", NameID: &nameID, EncryptedID: encryptedID, SessionIndexes: []SessionIndex{{Value: "1"}}}
	el = request.Element()
	assert.Nil(t, el.FindElement("./NameID"))
	assert.False(t, strings.Contains(elementToString(el), nameID.Value))

	// SAMLCore §3.7.1: the identifier comes before the SessionIndex elements.
	children := el.ChildElements()
	require.Len(t, children, 2)
	assert.Equal(t, "EncryptedID", children[0].Tag)

	encryptedAttribute, err := testElementEncrypter(t).encryptAttribute(&Attribute{Name: "secret", Values: []AttributeValue{{Value: "s3cret"}}})
	require.NoError(t, err)

	statement := AttributeStatement{
		Attributes:          []Attribute{{Name: "public", Values: []AttributeValue{{Value: "p"}}}},
		EncryptedAttributes: []*etree.Element{encryptedAttribute},
	}
	el = statement.Element()
	require.Len(t, el.ChildElements(), 2)
	assert.Equal(t, "Attribute", el.ChildElements()[0].Tag)
	assert.Equal(t, "EncryptedAttribute", el.ChildElements()[1].Tag)
	assert.False(t, strings.Contains(elementToString(el), "s3cret"))
}
