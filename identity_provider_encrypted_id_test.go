package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/dsig"
)

// elementEncryptionPolicyFunc is an ElementEncryptionPolicy made of two functions, either of which may be nil.
type elementEncryptionPolicyFunc struct {
	nameID    func(*IdpAuthnRequest) bool
	attribute func(*IdpAuthnRequest, Attribute) bool
}

func (p elementEncryptionPolicyFunc) EncryptNameID(req *IdpAuthnRequest) bool {
	return p.nameID != nil && p.nameID(req)
}

func (p elementEncryptionPolicyFunc) EncryptAttribute(req *IdpAuthnRequest, attribute Attribute) bool {
	return p.attribute != nil && p.attribute(req, attribute)
}

var encryptedPartsSession = &Session{
	ID:           "session",
	Index:        "index-one",
	NameID:       "alice@example.com",
	NameIDFormat: string(EmailAddressNameIDFormat),
	UserName:     "alice",
	UserEmail:    "alice@example.com",
	Groups:       []string{"admins", "users"},
}

// encryptedPartsRequest returns an identity provider which releases every attribute, and a validated request to it
// with the ID id-request from the test service provider, whose metadata has its encryption key.
func encryptedPartsRequest(t *testing.T) (*IdentityProviderTest, *IdpAuthnRequest) {
	t.Helper()

	test := NewIdentityProviderTest(t, applyKey)
	test.SP.IDPMetadata = test.IDP.Metadata()
	test.IDP.AttributeReleasePolicy = attributeReleasePolicyFunc(func(_ AttributeReleaseRequest, _ *Session, candidates []Attribute) ([]Attribute, error) {
		return candidates, nil
	})

	previousClock := Clock

	t.Cleanup(func() { Clock = previousClock })

	Clock = dsig.NewFakeClockAt(test.Certificate.NotBefore)

	metadata := test.SP.Metadata()
	descriptor := &metadata.SPSSODescriptors[0]
	req := &IdpAuthnRequest{
		IDP:                     &test.IDP,
		HTTPRequest:             httptest.NewRequest("GET", "/", nil),
		Now:                     TimeNow(),
		ServiceProviderMetadata: metadata,
		SPSSODescriptor:         descriptor,
		ACSEndpoint:             &descriptor.AssertionConsumerServices[0],
	}
	req.Request.ID = "id-request"
	req.Request.Issuer = &Issuer{Value: test.SP.MetadataURL.String()}

	return test, req
}

func requestEncryptedID(req *IdpAuthnRequest) {
	format := string(EncryptedNameIDFormat)
	req.Request.NameIDPolicy = &NameIDPolicy{Format: &format}
}

// respond makes the assertion and the response of req, and returns the response as it is sent.
func respond(t *testing.T, req *IdpAuthnRequest) string {
	t.Helper()

	require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, encryptedPartsSession))
	require.NoError(t, req.MakeResponse())

	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)

	body, err := doc.WriteToString()
	require.NoError(t, err)

	return body
}

// sentAssertionElement returns the assertion of a response as the service provider finds it once the
// EncryptedAssertion is decrypted, with its parts still encrypted.
func sentAssertionElement(t *testing.T, test *IdentityProviderTest, body string) *etree.Element {
	t.Helper()

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(body))

	encryptedAssertion := doc.Root().FindElement("./EncryptedAssertion")
	require.True(t, encryptedAssertion != nil, "the assertion is not encrypted: %s", body)

	el, err := test.SP.decryptElement(encryptedAssertion)
	require.NoError(t, err)

	return el
}

func friendlyNames(statements []AttributeStatement) []string {
	var names []string

	for _, statement := range statements {
		for _, attribute := range statement.Attributes {
			names = append(names, attribute.FriendlyName)
		}
	}

	return names
}

func TestIDPIssuesEncryptedIDWhenRequested(t *testing.T) {
	test, req := encryptedPartsRequest(t)
	requestEncryptedID(req)

	body := respond(t, req)

	// What the identity provider keeps is in plaintext, for the enforcers and the participant record.
	require.NotNil(t, req.Assertion.Subject.NameID)
	assert.Nil(t, req.Assertion.Subject.EncryptedID)

	sent := sentAssertionElement(t, test, body)
	assert.Nil(t, sent.FindElement("./Subject/NameID"))
	assert.False(t, strings.Contains(elementToString(sent.FindElement("./Subject")), req.Assertion.Subject.NameID.Value))

	// SAMLCore §2.2.4 and §6.1.
	encryptedID := sent.FindElement("./Subject/EncryptedID")
	require.NotNil(t, encryptedID)
	assert.Equal(t, encryptedID.Index(), 0)
	assert.Equal(t, xmlencElementType, encryptedID.FindElement("./EncryptedData").SelectAttrValue("Type", ""))
	assert.Equal(t, test.SP.MetadataURL.String(), encryptedID.FindElement("./EncryptedData/KeyInfo/EncryptedKey").SelectAttrValue("Recipient", ""))

	// The service provider of this library lists AES-128-GCM first, which is therefore what is negotiated.
	assert.Equal(t, aes128GCM, encryptedID.FindElement("./EncryptedData/EncryptionMethod").SelectAttrValue("Algorithm", ""))

	// SAMLCore §6.2: the NameID is encrypted first, so the signature of the assertion covers the EncryptedID.
	assert.NoError(t, test.SP.validateSignature(sent))

	assertion, err := test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
	require.NoError(t, err)
	require.True(t, assertion.Subject != nil && assertion.Subject.NameID != nil)

	// Errata E6: the identifier that was encrypted has a format of its own, not the encrypted one, which here
	// is that of the session.
	assert.Equal(t, *req.Assertion.Subject.NameID, *assertion.Subject.NameID)
	assert.Equal(t, assertion.Subject.NameID.Format, string(EmailAddressNameIDFormat))
	assert.Equal(t, assertion.Subject.NameID.Value, "alice@example.com")
	assert.Len(t, assertion.Subject.SubjectConfirmations, 1)
}

func TestIDPDoesNotEncryptPartsUnasked(t *testing.T) {
	test, req := encryptedPartsRequest(t)

	sent := sentAssertionElement(t, test, respond(t, req))
	assert.NotNil(t, sent.FindElement("./Subject/NameID"))
	assert.Nil(t, sent.FindElement("./Subject/EncryptedID"))
	assert.Nil(t, sent.FindElement("./AttributeStatement/EncryptedAttribute"))

	participant, err := (&IdpAuthnRequest{IDP: &test.IDP}).sessionParticipant()
	require.NoError(t, err)
	assert.Nil(t, participant)
}

func TestIDPEncryptsNameIDByPolicy(t *testing.T) {
	for name, tc := range map[string]struct {
		providers []string
		encrypted bool
	}{
		"listed":     {[]string{"https://other.example.com", "https://sp.example.com/saml2/metadata"}, true},
		"not listed": {[]string{"https://other.example.com"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			test, req := encryptedPartsRequest(t)
			test.IDP.ElementEncryptionPolicy = DefaultElementEncryptionPolicy{NameIDServiceProviders: tc.providers}

			body := respond(t, req)
			sent := sentAssertionElement(t, test, body)
			assert.Equal(t, tc.encrypted, sent.FindElement("./Subject/EncryptedID") != nil)
			assert.Equal(t, tc.encrypted, sent.FindElement("./Subject/NameID") == nil)

			assertion, err := test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
			require.NoError(t, err)
			assert.Equal(t, *req.Assertion.Subject.NameID, *assertion.Subject.NameID)
		})
	}
}

func TestIDPEncryptsAttributesByPolicy(t *testing.T) {
	t.Run("every attribute of a listed service provider", func(t *testing.T) {
		test, req := encryptedPartsRequest(t)
		test.IDP.ElementEncryptionPolicy = DefaultElementEncryptionPolicy{AttributeServiceProviders: []string{test.SP.MetadataURL.String()}}

		body := respond(t, req)
		sent := sentAssertionElement(t, test, body)
		assert.Nil(t, sent.FindElement("./AttributeStatement/Attribute"))
		assert.Len(t, sent.FindElements("./AttributeStatement/EncryptedAttribute"), 4)
		assert.NotNil(t, sent.FindElement("./Subject/NameID"))

		// The NameID is the email address here, so only the other values show that the attributes are hidden.
		assert.False(t, strings.Contains(elementToString(sent), "admins"))
		assert.NoError(t, test.SP.validateSignature(sent))

		assertion, err := test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
		require.NoError(t, err)
		assert.Equal(t, req.Assertion.AttributeStatements, assertion.AttributeStatements)
		assert.Equal(t, []string{"uid", "mail", "eduPersonPrincipalName", "eduPersonAffiliation"}, friendlyNames(assertion.AttributeStatements))
	})

	t.Run("chosen attributes", func(t *testing.T) {
		test, req := encryptedPartsRequest(t)

		var asked []string

		test.IDP.ElementEncryptionPolicy = elementEncryptionPolicyFunc{attribute: func(req *IdpAuthnRequest, attribute Attribute) bool {
			assert.Equal(t, req.ServiceProviderMetadata.EntityID, test.SP.MetadataURL.String())

			asked = append(asked, attribute.FriendlyName)

			return attribute.FriendlyName == "mail" || attribute.FriendlyName == "eduPersonAffiliation"
		}}

		body := respond(t, req)
		assert.Equal(t, []string{"uid", "mail", "eduPersonPrincipalName", "eduPersonAffiliation"}, asked)

		sent := sentAssertionElement(t, test, body)

		children := sent.FindElement("./AttributeStatement").ChildElements()

		tags := make([]string, 0, len(children))
		for _, child := range children {
			tags = append(tags, child.Tag)
		}

		assert.Equal(t, []string{"Attribute", "Attribute", "EncryptedAttribute", "EncryptedAttribute"}, tags)
		assert.False(t, strings.Contains(elementToString(sent), "admins"))

		assertion, err := test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
		require.NoError(t, err)
		assert.Equal(t, []string{"uid", "eduPersonPrincipalName", "mail", "eduPersonAffiliation"}, friendlyNames(assertion.AttributeStatements))

		groups := assertion.AttributeStatements[0].Attributes[3]
		assert.Equal(t, []AttributeValue{{Type: "xs:string", Value: "admins"}, {Type: "xs:string", Value: "users"}}, groups.Values)

		// The assertion the identity provider keeps is not changed.
		assert.Equal(t, []string{"uid", "mail", "eduPersonPrincipalName", "eduPersonAffiliation"}, friendlyNames(req.Assertion.AttributeStatements))
		assert.Len(t, req.Assertion.AttributeStatements[0].EncryptedAttributes, 0)
	})

	t.Run("name id and attributes", func(t *testing.T) {
		test, req := encryptedPartsRequest(t)
		requestEncryptedID(req)

		test.IDP.ElementEncryptionPolicy = DefaultElementEncryptionPolicy{AttributeServiceProviders: []string{test.SP.MetadataURL.String()}}

		body := respond(t, req)
		sent := sentAssertionElement(t, test, body)
		assert.False(t, strings.Contains(elementToString(sent), "alice"))

		assertion, err := test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
		require.NoError(t, err)
		assert.Equal(t, *req.Assertion.Subject.NameID, *assertion.Subject.NameID)
		assert.Equal(t, req.Assertion.AttributeStatements, assertion.AttributeStatements)
	})
}

// A part that must be encrypted is never sent in plaintext.
func TestIDPSendsNothingWhenAPartCannotBeEncrypted(t *testing.T) {
	withoutKey := func(req *IdpAuthnRequest) {
		req.SPSSODescriptor.KeyDescriptors = nil
	}

	t.Run("requested", func(t *testing.T) {
		_, req := encryptedPartsRequest(t)
		requestEncryptedID(req)
		withoutKey(req)

		// A custom AssertionMaker doesn't go through resolveNameID.
		req.Assertion = &Assertion{Subject: &Subject{NameID: &NameID{Value: "alice"}}}

		err := req.MakeAssertionEl()
		assert.True(t, errors.Is(err, ErrInvalidNameIDPolicy), "error: %v", err)
		assert.Nil(t, req.AssertionEl)
		assert.ErrorContains(t, DefaultNameIDPolicyEnforcer{}.EnforceNameIDPolicy(req, nil), "the service provider has no encryption key")

		_, err = req.resolveNameID(encryptedPartsSession)
		assert.True(t, errors.Is(err, ErrInvalidNameIDPolicy), "error: %v", err)
	})

	t.Run("name id by policy", func(t *testing.T) {
		test, req := encryptedPartsRequest(t)
		withoutKey(req)

		test.IDP.ElementEncryptionPolicy = elementEncryptionPolicyFunc{nameID: func(*IdpAuthnRequest) bool { return true }}

		require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, encryptedPartsSession))

		err := req.MakeResponse()
		assert.ErrorContains(t, err, "the NameID must be encrypted, and the service provider has no encryption key")
		assert.False(t, errors.Is(err, ErrInvalidNameIDPolicy))
		assert.True(t, req.AssertionEl == nil && req.ResponseEl == nil)
	})

	t.Run("attribute by policy", func(t *testing.T) {
		test, req := encryptedPartsRequest(t)
		withoutKey(req)

		test.IDP.ElementEncryptionPolicy = elementEncryptionPolicyFunc{attribute: func(_ *IdpAuthnRequest, attribute Attribute) bool {
			return attribute.FriendlyName == "mail"
		}}

		require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, encryptedPartsSession))
		assert.ErrorContains(t, req.MakeResponse(), `the attribute "urn:oid:0.9.2342.19200300.100.1.3" must be encrypted`)
		assert.True(t, req.AssertionEl == nil && req.ResponseEl == nil)
	})

	t.Run("served", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.SP.Certificate = nil

		encrypted := string(EncryptedNameIDFormat)
		assertInvalidNameIDPolicy(t, serveSSOWithPolicy(t, test, &Session{ID: "s", NameID: "alice"}, &NameIDPolicy{Format: &encrypted}))
	})
}

func TestServeSSOIssuesEncryptedID(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	captured := captureNameID(test)
	encrypted := string(EncryptedNameIDFormat)

	response := serveSSOWithPolicy(t, test, &Session{ID: "s", NameID: "alice"}, &NameIDPolicy{Format: &encrypted})
	assert.Equal(t, response.Status.StatusCode.Value, StatusSuccess)
	assert.NotNil(t, response.EncryptedAssertion)
	require.NotNil(t, *captured)
	assert.Equal(t, (*captured).Format, string(TransientNameIDFormat))
}

func TestSessionParticipantRecordsEncryptedNameID(t *testing.T) {
	for name, requested := range map[string]bool{"encrypted": true, "plaintext": false} {
		t.Run(name, func(t *testing.T) {
			test, req := encryptedPartsRequest(t)

			provider := &propagationSessionProvider{participants: map[string][]SessionParticipant{}}
			test.IDP.SessionProvider = provider
			req.Session = encryptedPartsSession

			if requested {
				requestEncryptedID(req)
			}

			respond(t, req)
			require.NoError(t, req.PublishResponse(func() error { return nil }))

			participants := provider.participants[encryptedPartsSession.ID]
			require.Len(t, participants, 1)
			assert.Equal(t, requested, participants[0].NameIDEncrypted)

			// The record has the identifier itself, which a logout is matched against.
			assert.Equal(t, *req.Assertion.Subject.NameID, participants[0].NameID)
		})
	}
}

// plaintextAssertionResponse returns the response of req with its assertion signed and not encrypted, as an
// identity provider sends it which encrypts the parts alone.
func plaintextAssertionResponse(t *testing.T, req *IdpAuthnRequest, mutate func(sent *Assertion)) string {
	t.Helper()

	require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, encryptedPartsSession))

	sent, err := req.sentAssertion(req.elementEncrypter)
	require.NoError(t, err)

	if mutate != nil {
		mutate(sent)
	}

	signingContext, err := req.IDP.signingContext()
	require.NoError(t, err)

	signed, err := signingContext.SignEnveloped(sent.Element())
	require.NoError(t, err)

	sent.Signature = signed.ChildElements()[len(signed.ChildElements())-1]
	req.AssertionEl = sent.Element()

	require.NoError(t, req.MakeResponse())

	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)

	body, err := doc.WriteToString()
	require.NoError(t, err)

	return body
}

func TestSPDecryptsPartsOfPlaintextAssertion(t *testing.T) {
	test, req := encryptedPartsRequest(t)
	requestEncryptedID(req)

	test.IDP.ElementEncryptionPolicy = DefaultElementEncryptionPolicy{AttributeServiceProviders: []string{test.SP.MetadataURL.String()}}

	body := plaintextAssertionResponse(t, req, func(sent *Assertion) {
		// SAMLCore §2.4.1.1: a SubjectConfirmation may identify the confirming entity with an EncryptedID too.
		sent.Subject.SubjectConfirmations[0].EncryptedID = sent.Subject.EncryptedID
	})
	assert.True(t, strings.Contains(body, "<saml:Assertion"))
	assert.False(t, strings.Contains(body, "EncryptedAssertion"))
	assert.False(t, strings.Contains(body, "admins"))
	assert.False(t, strings.Contains(body, req.Assertion.Subject.NameID.Value))

	assertion, err := test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
	require.NoError(t, err)
	assert.Equal(t, *req.Assertion.Subject.NameID, *assertion.Subject.NameID)
	assert.Equal(t, *req.Assertion.Subject.NameID, *assertion.Subject.SubjectConfirmations[0].NameID)
	assert.Equal(t, req.Assertion.AttributeStatements, assertion.AttributeStatements)
}

func TestSPRejectsEncryptedPartsItCannotDecrypt(t *testing.T) {
	response := func(t *testing.T) (*IdentityProviderTest, string) {
		t.Helper()

		test, req := encryptedPartsRequest(t)
		requestEncryptedID(req)

		return test, plaintextAssertionResponse(t, req, nil)
	}

	t.Run("another key", func(t *testing.T) {
		test, body := response(t)

		other, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		test.SP.Key = other

		assertion, err := test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
		assert.Nil(t, assertion)
		require.NotNil(t, err)

		// The reason is for the service provider's own log, never for the user agent.
		invalid := &InvalidResponseError{}
		require.True(t, errors.As(err, &invalid))
		assert.ErrorContains(t, invalid.PrivateErr, "failed to decrypt EncryptedID")
		assert.False(t, strings.Contains(err.Error(), "decrypt"))
	})

	t.Run("no key", func(t *testing.T) {
		test, body := response(t)
		test.SP.Key = nil

		_, err := test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
		require.NotNil(t, err)
	})

	// The signature covers the ciphertext, so a change to it is found before anything is decrypted.
	t.Run("tampered ciphertext", func(t *testing.T) {
		test, body := response(t)

		doc := etree.NewDocument()
		require.NoError(t, doc.ReadFromString(body))

		value := doc.Root().FindElement("./Assertion/Subject/EncryptedID/EncryptedData/CipherData/CipherValue")
		require.NotNil(t, value)

		text := value.Text()
		value.SetText(text[:10] + "AAAA" + text[14:])

		// The response signature is removed, so that the signature of the assertion is what is verified.
		doc.Root().RemoveChild(doc.Root().FindElement("./Signature"))

		altered, err := doc.WriteToString()
		require.NoError(t, err)

		_, err = test.SP.ParseXMLResponse([]byte(altered), []string{"id-request"}, test.SP.AcsURL)

		invalid := &InvalidResponseError{}
		require.True(t, errors.As(err, &invalid))
		assert.False(t, strings.Contains(invalid.PrivateErr.Error(), "decrypt"), "error: %v", invalid.PrivateErr)
	})
}

func TestSPRejectsSubjectWithTwoIdentifiers(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)

	encrypter := &elementEncrypter{certificate: test.SPCertificate, encrypter: testElementEncrypter(t).encrypter}

	encryptedID, err := encrypter.encryptNameID(&testEncryptedNameID)
	require.NoError(t, err)

	for name, build := range map[string]func(subject *etree.Element){
		"name id and encrypted id": func(subject *etree.Element) {
			subject.AddChild((&NameID{Value: "mallory"}).Element())
			subject.AddChild(encryptedID.Copy())
		},
		"two encrypted ids": func(subject *etree.Element) {
			subject.AddChild(encryptedID.Copy())
			subject.AddChild(encryptedID.Copy())
		},
	} {
		t.Run(name, func(t *testing.T) {
			assertion := etree.NewElement("saml:Assertion")
			assertion.CreateAttr("xmlns:saml", samlAssertionNamespace)
			build(assertion.CreateElement("saml:Subject"))

			err := test.SP.decryptAssertionParts(reparse(t, assertion))
			assert.ErrorContains(t, err, "the Subject has more than one of NameID and EncryptedID")
		})
	}

	t.Run("one encrypted id", func(t *testing.T) {
		assertion := etree.NewElement("saml:Assertion")
		assertion.CreateAttr("xmlns:saml", samlAssertionNamespace)
		assertion.CreateElement("saml:Subject").AddChild(encryptedID.Copy())

		el := reparse(t, assertion)
		require.NoError(t, test.SP.decryptAssertionParts(el))
		assert.Nil(t, el.FindElement("./Subject/EncryptedID"))
		assert.Equal(t, testEncryptedNameID.Value, el.FindElement("./Subject/NameID").Text())
	})
}

// The answer to a query is made like the assertion of single sign-on, so the policy applies to it, and the
// AssertionStore is given what was signed, which has the parts encrypted.
func TestQueryAnswerEncryptsPartsByPolicy(t *testing.T) {
	f := newQueryFixture(t)
	f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))

	serviceProviders := []string{f.test.SP.MetadataURL.String()}
	f.test.IDP.ElementEncryptionPolicy = DefaultElementEncryptionPolicy{
		NameIDServiceProviders:    serviceProviders,
		AttributeServiceProviders: serviceProviders,
	}

	response := f.queryAttributes(t, f.attributeQuery())
	assertQueryStatus(t, response, StatusSuccess, "")
	require.Len(t, response.AssertionEls, 1)
	assert.Equal(t, response.Encrypted, 1)

	require.Len(t, f.store.saved, 1)

	for name, el := range map[string]*etree.Element{
		"sent":  response.AssertionEls[0],
		"saved": f.store.assertions[f.store.saved[0]].Assertion,
	} {
		t.Run(name, func(t *testing.T) {
			assert.NotNil(t, el.FindElement("./Subject/EncryptedID"))
			assert.Nil(t, el.FindElement("./Subject/NameID"))
			assert.NotNil(t, el.FindElement("./AttributeStatement/EncryptedAttribute"))
			assert.Nil(t, el.FindElement("./AttributeStatement/Attribute"))
			assert.NotNil(t, el.FindElement("./Signature"))
		})
	}
}
