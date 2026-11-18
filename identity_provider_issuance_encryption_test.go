package saml

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issuanceEncryptionSP is the entity ID of the service provider of hardeningIssuer.
const issuanceEncryptionSP = "https://sp.example.com/saml2/metadata"

// issuanceEncryptionOf returns what the EncryptedData of encryptedEl, which is an EncryptedAssertion, EncryptedID,
// NewEncryptedID or EncryptedAttribute, states that it was encrypted with.
func issuanceEncryptionOf(t *testing.T, encryptedEl *etree.Element) negotiated {
	t.Helper()

	require.True(t, encryptedEl != nil, "there is no encrypted element")

	contentMethod := encryptedEl.FindElement("./EncryptedData/EncryptionMethod")
	keyMethod := encryptedEl.FindElement("./EncryptedData/KeyInfo/EncryptedKey/EncryptionMethod")
	require.True(t, contentMethod != nil && keyMethod != nil)

	got := negotiated{
		content:      contentMethod.SelectAttrValue("Algorithm", ""),
		keyTransport: keyMethod.SelectAttrValue("Algorithm", ""),
	}

	if el := keyMethod.FindElement("./DigestMethod"); el != nil {
		got.digest = el.SelectAttrValue("Algorithm", "")
	}

	if el := keyMethod.FindElement("./MGF"); el != nil {
		got.mgf = el.SelectAttrValue("Algorithm", "")
	}

	return got
}

// issuanceEncryptionFor returns what configures an identity provider to issue to the service provider of
// hardeningIssuer as issuance says.
func issuanceEncryptionFor(issuance ServiceProviderIssuance) func(*IdentityProvider) {
	return func(idp *IdentityProvider) {
		idp.IssuancePolicy = DefaultIssuancePolicy{ServiceProviders: map[string]ServiceProviderIssuance{
			issuanceEncryptionSP: issuance,
		}}
	}
}

var (
	// issuanceLegacyEncryption is the encryption of a service provider that decrypts nothing newer.
	issuanceLegacyEncryption = ServiceProviderIssuance{
		ContentEncryptionMethod:  aes256CBC,
		KeyTransportMethod:       rsaOAEP11,
		KeyTransportDigestMethod: digestSHA256,
	}

	// issuanceLegacyEncrypted is what issuanceLegacyEncryption encrypts with. The mask generation function that
	// isn't named is the default of the algorithm, as it is for an EncryptionMethod in metadata.
	issuanceLegacyEncrypted = negotiated{content: aes256CBC, keyTransport: rsaOAEP11, digest: digestSHA256, mgf: mgf1SHA1}
)

// A policy that names no encryption algorithm leaves the negotiation from metadata as it was.
func TestIssuanceEncryptionIsNegotiatedByDefault(t *testing.T) {
	configure := issuanceEncryptionFor(ServiceProviderIssuance{Sign: SignAssertion})

	encryptedData, err := negotiatedAssertion(t, configure)
	require.NoError(t, err)
	checkNegotiated(t, encryptedData, negotiated{content: aes128GCM, keyTransport: rsaOAEP, digest: digestSHA1})

	encryptedData, err = negotiatedAssertion(t, configure, method(aes256CBC), oaepMethod(rsaOAEP11, digestSHA256, mgf1SHA256))
	require.NoError(t, err)
	checkNegotiated(t, encryptedData, negotiated{content: aes256CBC, keyTransport: rsaOAEP11, digest: digestSHA256, mgf: mgf1SHA256})

	_, err = negotiatedAssertion(t, configure, method(tripleDES))
	assert.ErrorContains(t, err, "content encryption")
}

func TestIssuanceEncryptionMethods(t *testing.T) {
	defaults := negotiated{content: aes128GCM, keyTransport: rsaOAEP, digest: digestSHA1}

	for _, tc := range []struct {
		name     string
		issuance ServiceProviderIssuance
		methods  []EncryptionMethod
		want     negotiated
	}{
		{
			name:     "CBC for a service provider that lists nothing",
			issuance: ServiceProviderIssuance{ContentEncryptionMethod: aes128CBC},
			want:     negotiated{content: aes128CBC, keyTransport: rsaOAEP, digest: digestSHA1},
		},
		{
			name:     "the choice replaces what the service provider lists",
			issuance: ServiceProviderIssuance{ContentEncryptionMethod: aes128CBC},
			methods:  []EncryptionMethod{method(aes256GCM), method(rsaOAEP)},
			want:     negotiated{content: aes128CBC, keyTransport: rsaOAEP, digest: digestSHA1},
		},
		{
			name:     "the choice is used when nothing the service provider lists can be",
			issuance: ServiceProviderIssuance{ContentEncryptionMethod: aes256GCM, KeyTransportMethod: rsaOAEP},
			methods:  []EncryptionMethod{method(tripleDES), method(rsaPKCS1v15)},
			want:     negotiated{content: aes256GCM, keyTransport: rsaOAEP, digest: digestSHA1},
		},
		{
			name:     "the key transport is still negotiated when only the content encryption is chosen",
			issuance: ServiceProviderIssuance{ContentEncryptionMethod: aes192CBC},
			methods:  []EncryptionMethod{oaepMethod(rsaOAEP11, digestSHA512, mgf1SHA256)},
			want:     negotiated{content: aes192CBC, keyTransport: rsaOAEP11, digest: digestSHA512, mgf: mgf1SHA256},
		},
		{
			name:     "the content encryption is still negotiated when only the key transport is chosen",
			issuance: ServiceProviderIssuance{KeyTransportMethod: rsaOAEP11},
			methods:  []EncryptionMethod{method(aes256CBC), method(rsaOAEP)},
			want:     negotiated{content: aes256CBC, keyTransport: rsaOAEP11, digest: digestSHA1, mgf: mgf1SHA1},
		},
		{
			name:     "a digest for RSA-OAEP-MGF1P",
			issuance: ServiceProviderIssuance{KeyTransportMethod: rsaOAEP, KeyTransportDigestMethod: digestSHA256},
			want:     negotiated{content: aes128GCM, keyTransport: rsaOAEP, digest: digestSHA256},
		},
		{
			name:     "the legacy identifier of a digest",
			issuance: ServiceProviderIssuance{KeyTransportMethod: rsaOAEP, KeyTransportDigestMethod: digestLegacy256},
			want:     negotiated{content: aes128GCM, keyTransport: rsaOAEP, digest: digestSHA256},
		},
		{
			name:     "a digest and its mask generation function",
			issuance: ServiceProviderIssuance{KeyTransportMethod: rsaOAEP11, KeyTransportDigestMethod: digestSHA256, KeyTransportMGF: mgf1SHA256},
			want:     negotiated{content: aes128GCM, keyTransport: rsaOAEP11, digest: digestSHA256, mgf: mgf1SHA256},
		},
		{
			name:     "a mask generation function of another hash than the digest",
			issuance: ServiceProviderIssuance{KeyTransportMethod: rsaOAEP11, KeyTransportDigestMethod: digestSHA1, KeyTransportMGF: mgf1SHA512},
			want:     negotiated{content: aes128GCM, keyTransport: rsaOAEP11, digest: digestSHA1, mgf: mgf1SHA512},
		},
		{
			name:     "the mask generation function of RSA-OAEP-MGF1P may be named",
			issuance: ServiceProviderIssuance{KeyTransportMethod: rsaOAEP, KeyTransportMGF: mgf1SHA1},
			want:     defaults,
		},
		{
			name:     "all of it",
			issuance: issuanceLegacyEncryption,
			methods:  []EncryptionMethod{method(aes128GCM), method(rsaOAEP)},
			want:     issuanceLegacyEncrypted,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encryptedData, err := negotiatedAssertion(t, issuanceEncryptionFor(tc.issuance), tc.methods...)
			require.NoError(t, err)
			checkNegotiated(t, encryptedData, tc.want)
		})
	}
}

// A policy of the application leaves the fields of Defaults empty to have the algorithms negotiated, and sets
// them to choose.
func TestIssuanceEncryptionMethodsOfCustomPolicy(t *testing.T) {
	var defaults []Issuance

	configure := func(idp *IdentityProvider) {
		idp.IssuancePolicy = issuancePolicyFunc(func(req IssuanceRequest) (Issuance, error) {
			defaults = append(defaults, req.Defaults)

			issuance := req.Defaults
			issuance.ContentEncryptionMethod = aes128CBC

			return issuance, nil
		})
	}

	encryptedData, err := negotiatedAssertion(t, configure, method(aes256GCM))
	require.NoError(t, err)
	checkNegotiated(t, encryptedData, negotiated{content: aes128CBC, keyTransport: rsaOAEP, digest: digestSHA1})

	require.True(t, len(defaults) > 0)

	for _, issuance := range defaults {
		assert.Equal(t, issuance.ContentEncryptionMethod, "")
		assert.Equal(t, issuance.KeyTransportMethod, "")
		assert.Equal(t, issuance.KeyTransportDigestMethod, "")
		assert.Equal(t, issuance.KeyTransportMGF, "")
		assert.Equal(t, issuance.AssertionEncryption, EncryptAssertionWhenPossible)
	}
}

// What the policy chose and the identity provider can't or may not use is refused when the policy is asked,
// whether or not anything is encrypted, and nothing is sent with another algorithm.
func TestIssuanceRefusesEncryptionMethods(t *testing.T) {
	gcmOnly := func(idp *IdentityProvider) { idp.ContentEncryptionMethods = []string{aes128GCM, aes256GCM} }

	for _, tc := range []struct {
		name      string
		issuance  ServiceProviderIssuance
		configure func(*IdentityProvider)
		reason    string
	}{
		{"triple DES", ServiceProviderIssuance{ContentEncryptionMethod: tripleDES}, nil, "unsupported content encryption method"},
		{"unknown content encryption", ServiceProviderIssuance{ContentEncryptionMethod: "urn:example:unknown"}, nil, "unsupported content encryption method"},
		{"a key transport algorithm as content encryption", ServiceProviderIssuance{ContentEncryptionMethod: rsaOAEP}, nil, "unsupported content encryption method"},
		{"content encryption the identity provider excludes", ServiceProviderIssuance{ContentEncryptionMethod: aes128CBC}, gcmOnly, "IdentityProvider.ContentEncryptionMethods"},
		{"RSA PKCS#1 v1.5", ServiceProviderIssuance{KeyTransportMethod: rsaPKCS1v15}, nil, "unsupported key transport method"},
		{"key agreement with a digest", ServiceProviderIssuance{KeyTransportMethod: ecdhES, KeyTransportDigestMethod: digestSHA256}, nil, "has no KeyTransportDigestMethod"},
		{"key agreement with a mask generation function", ServiceProviderIssuance{KeyTransportMethod: ecdhES, KeyTransportMGF: mgf1SHA256}, nil, "has no KeyTransportDigestMethod"},
		{"unknown key wrap", ServiceProviderIssuance{KeyWrapMethod: "http://www.w3.org/2001/04/xmlenc#kw-tripledes"}, nil, "unsupported key wrap method"},
		{
			"key wrap the identity provider excludes",
			ServiceProviderIssuance{KeyWrapMethod: "http://www.w3.org/2001/04/xmlenc#kw-aes256"},
			func(idp *IdentityProvider) {
				idp.KeyWrapMethods = []string{"http://www.w3.org/2001/04/xmlenc#kw-aes128"}
			},
			"IdentityProvider.KeyWrapMethods",
		},
		{
			"key wrap the identity provider doesn't support",
			ServiceProviderIssuance{KeyWrapMethod: "http://www.w3.org/2001/04/xmlenc#kw-aes256"},
			func(idp *IdentityProvider) {
				idp.KeyWrapMethods = []string{"http://www.w3.org/2001/04/xmlenc#kw-tripledes"}
			},
			"IdentityProvider.KeyWrapMethods",
		},
		{
			"key transport the identity provider excludes",
			ServiceProviderIssuance{KeyTransportMethod: rsaOAEP11},
			func(idp *IdentityProvider) { idp.KeyTransportMethods = []string{rsaOAEP} },
			"IdentityProvider.KeyTransportMethods",
		},
		{"a digest without a key transport", ServiceProviderIssuance{KeyTransportDigestMethod: digestSHA256}, nil, "without a KeyTransportMethod"},
		{"a mask generation function without a key transport", ServiceProviderIssuance{KeyTransportMGF: mgf1SHA256}, nil, "without a KeyTransportMethod"},
		{"unknown digest", ServiceProviderIssuance{KeyTransportMethod: rsaOAEP, KeyTransportDigestMethod: digestRIPEMD160}, nil, "unsupported key transport digest method"},
		{
			"a digest the identity provider excludes",
			ServiceProviderIssuance{KeyTransportMethod: rsaOAEP, KeyTransportDigestMethod: digestSHA512},
			func(idp *IdentityProvider) { idp.KeyTransportDigestMethods = []string{digestSHA1, digestSHA256} },
			"IdentityProvider.KeyTransportDigestMethods",
		},
		{
			"the default digest, which the identity provider excludes",
			ServiceProviderIssuance{KeyTransportMethod: rsaOAEP},
			func(idp *IdentityProvider) { idp.KeyTransportDigestMethods = []string{digestSHA256} },
			"IdentityProvider.KeyTransportDigestMethods",
		},
		{"another mask generation function for RSA-OAEP-MGF1P", ServiceProviderIssuance{KeyTransportMethod: rsaOAEP, KeyTransportMGF: mgf1SHA256}, nil, "mask generation function"},
		{"unknown mask generation function", ServiceProviderIssuance{KeyTransportMethod: rsaOAEP11, KeyTransportMGF: mgf1SHA224}, nil, "unsupported key transport mask generation function"},
		{
			"a mask generation function the identity provider excludes",
			ServiceProviderIssuance{KeyTransportMethod: rsaOAEP11, KeyTransportDigestMethod: digestSHA256, KeyTransportMGF: mgf1SHA512},
			func(idp *IdentityProvider) { idp.KeyTransportDigestMethods = []string{digestSHA256} },
			"IdentityProvider.KeyTransportDigestMethods",
		},
		{
			"algorithms of the identity provider that are not supported",
			ServiceProviderIssuance{ContentEncryptionMethod: aes128CBC},
			func(idp *IdentityProvider) { idp.ContentEncryptionMethods = []string{tripleDES} },
			"IdentityProvider.ContentEncryptionMethods",
		},
	} {
		for _, encrypted := range []bool{true, false} {
			name := tc.name
			if !encrypted {
				name += ", to a service provider with no encryption key"
			}

			t.Run(name, func(t *testing.T) {
				test := issuanceTestIDP(t)
				issuanceFor(test, tc.issuance)

				if tc.configure != nil {
					tc.configure(&test.IDP)
				}

				if !encrypted {
					issuanceMetadata(test, issuanceUnencrypted)
				}

				logs := &bytes.Buffer{}
				test.IDP.Observer = logObserver(logs)

				w := serveSSO(test, replayPostRequest(signedPostBody(t, &test.SP, nil), nil))
				assert.Equal(t, w.Code, http.StatusInternalServerError)
				assert.False(t, strings.Contains(w.Body.String(), "SAMLResponse"))
				assert.Contains(t, logs.String(), "IssuancePolicy")
				assert.Contains(t, logs.String(), tc.reason)

				// Nor is any other message signed for that service provider.
				_, err := test.IDP.signingContextFor(httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/slo", nil), test.SP.Metadata())
				assert.ErrorContains(t, err, tc.reason)
			})
		}
	}
}

// The assertion of single sign-on is encrypted with what the policy chose, although the metadata of the service
// provider of this package lists other algorithms first, and the service provider decrypts it.
func TestIssuanceEncryptionSSOEndToEnd(t *testing.T) {
	test := issuanceTestIDP(t)
	issuanceFor(test, issuanceLegacyEncryption)

	responseEl, responseXML, id := issuanceSSO(t, test)

	assert.Equal(t, issuanceEncryptionOf(t, responseEl.FindElement("./EncryptedAssertion")), issuanceLegacyEncrypted)

	assertion := issuanceAccept(t, &test.SP, responseXML, []string{id})
	assert.NotNil(t, assertion.Subject)

	// Another service provider is not affected.
	test.IDP.IssuancePolicy = DefaultIssuancePolicy{ServiceProviders: map[string]ServiceProviderIssuance{
		"https://other.example.com/metadata": issuanceLegacyEncryption,
	}}

	responseEl, _, _ = issuanceSSO(t, test)
	assert.Equal(t, issuanceEncryptionOf(t, responseEl.FindElement("./EncryptedAssertion")).content, aes128GCM)
}

// The EncryptedID and each EncryptedAttribute of an assertion are encrypted as the assertion is.
func TestIssuanceEncryptionOfParts(t *testing.T) {
	test, req := encryptedPartsRequest(t)
	issuanceFor(test, issuanceLegacyEncryption)

	serviceProviders := []string{test.SP.MetadataURL.String()}
	test.IDP.ElementEncryptionPolicy = DefaultElementEncryptionPolicy{
		NameIDServiceProviders:    serviceProviders,
		AttributeServiceProviders: serviceProviders,
	}

	body := respond(t, req)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(body))
	assert.Equal(t, issuanceEncryptionOf(t, doc.Root().FindElement("./EncryptedAssertion")), issuanceLegacyEncrypted)

	assertionEl := sentAssertionElement(t, test, body)

	encryptedID := assertionEl.FindElement("./Subject/EncryptedID")
	assert.Equal(t, issuanceEncryptionOf(t, encryptedID), issuanceLegacyEncrypted)

	nameID, err := test.SP.DecryptNameID(reparse(t, encryptedID))
	require.NoError(t, err)
	assert.True(t, nameID.Value != "")

	encryptedAttributes := assertionEl.FindElements("./AttributeStatement/EncryptedAttribute")
	require.True(t, len(encryptedAttributes) > 0)

	for _, encryptedAttribute := range encryptedAttributes {
		assert.Equal(t, issuanceEncryptionOf(t, encryptedAttribute), issuanceLegacyEncrypted)

		_, err = test.SP.decryptElement(reparse(t, encryptedAttribute))
		assert.NoError(t, err)
	}

	_, err = test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
	assert.NoError(t, err)
}

func TestIssuanceEncryptionArtifact(t *testing.T) {
	t.Run("the Response of the ArtifactResponse", func(t *testing.T) {
		test, _ := artifactTestIDP(t)
		issuanceFor(test, issuanceLegacyEncryption)

		artifact, _ := issueTestArtifact(t, test, &test.SP)
		r, _ := artifactResolvePost(t, &test.SP, artifact, nil)

		envelope := soapTestParseResponse(t, serveArtifactResolution(test, r))

		encryptedAssertion := envelope.FindElement("./Body/ArtifactResponse/Response/EncryptedAssertion")
		assert.Equal(t, issuanceEncryptionOf(t, encryptedAssertion), issuanceLegacyEncrypted)

		_, err := test.SP.decryptElement(reparse(t, encryptedAssertion))
		assert.NoError(t, err)
	})

	t.Run("end to end", func(t *testing.T) {
		test, logs := artifactTestIDP(t)
		issuanceFor(test, issuanceLegacyEncryption)

		artifactEndToEnd(t, test, logs)
	})
}

// issuanceQueryMessage sends message, signed, to the service and returns the Response as it was sent, and parsed
// with its assertions decrypted and their signatures verified.
func issuanceQueryMessage(t *testing.T, f *queryFixture, service queryService, message *etree.Element) (*etree.Element, *queryResponse) {
	t.Helper()

	w := f.serve(service, queryPost(t, service.url, signQueryElement(t, &f.test.SP, message)))
	require.Equal(t, w.Code, http.StatusOK, "body: %s", w.Body.String())

	_, _, responseEl, err := parseSOAPEnvelope(w.Body.Bytes())
	require.NoError(t, err)

	return responseEl, f.answer(t, w)
}

func TestIssuanceEncryptionQueryResponses(t *testing.T) {
	t.Run("AttributeQuery", func(t *testing.T) {
		f := newQueryFixture(t)
		f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))
		issuanceFor(f.test, issuanceLegacyEncryption)

		responseEl, response := issuanceQueryMessage(t, f, queryServices[0], f.attributeQuery().Element())
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Equal(t, response.Encrypted, 1)
		assert.Equal(t, issuanceEncryptionOf(t, responseEl.FindElement("./EncryptedAssertion")), issuanceLegacyEncrypted)
	})

	t.Run("AuthnQuery", func(t *testing.T) {
		f := newQueryFixture(t)
		issuanceFor(f.test, issuanceLegacyEncryption)

		responseEl, response := issuanceQueryMessage(t, f, queryServices[1], f.authnQuery().Element())
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Equal(t, response.Encrypted, 1)
		assert.Equal(t, issuanceEncryptionOf(t, responseEl.FindElement("./EncryptedAssertion")), issuanceLegacyEncrypted)
	})

	t.Run("AssertionIDRequest", func(t *testing.T) {
		f := newQueryFixture(t)
		f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())
		issuanceFor(f.test, issuanceLegacyEncryption)

		responseEl, response := issuanceQueryMessage(t, f, queryServices[2], f.assertionIDRequest(queryTestStoredAssertionID).Element())
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Equal(t, response.Encrypted, 1)
		assert.Equal(t, issuanceEncryptionOf(t, responseEl.FindElement("./EncryptedAssertion")), issuanceLegacyEncrypted)
	})
}

// The EncryptedID and NewEncryptedID of a ManageNameIDRequest that the identity provider sends.
func TestIssuanceEncryptionManageNameIDRequest(t *testing.T) {
	test, sp, _ := sendManageNameIDFixture(t)
	issuanceFor(test, issuanceLegacyEncryption)

	require.NoError(t, sendManageNameID(test, NameIDChange{NameID: *testNameID(test, &test.SP), NewID: "p-alice-2", Encrypt: true}))
	require.Len(t, sp.requests, 1)

	assert.Equal(t, issuanceEncryptionOf(t, sp.elements[0].FindElement("./EncryptedID")), issuanceLegacyEncrypted)
	assert.Equal(t, issuanceEncryptionOf(t, sp.elements[0].FindElement("./NewEncryptedID")), issuanceLegacyEncrypted)

	// The service provider decrypted both.
	assert.Equal(t, *sp.nameIDs[0], *testNameID(test, &test.SP))
	assert.Equal(t, sp.newIDs[0], "p-alice-2")
}

// The EncryptedID of a LogoutRequest that the identity provider sends to a session participant.
func TestIssuanceEncryptionLogoutRequest(t *testing.T) {
	f := newPropagationFixture(t)
	f.test.IDP.IssuancePolicy = DefaultIssuancePolicy{ServiceProviders: map[string]ServiceProviderIssuance{
		f.a.MetadataURL.String(): issuanceLegacyEncryption,
	}}
	f.encryptParticipants(f.a.MetadataURL.String())

	el := sentLogoutRequestElement(t, f.a, sentLogoutRequest(t, f.startLogout(t)))
	assert.Nil(t, el.FindElement("./NameID"))

	encryptedID, err := findOneChild(el, samlAssertionNamespace, "EncryptedID")
	require.NoError(t, err)
	assert.Equal(t, issuanceEncryptionOf(t, encryptedID), issuanceLegacyEncrypted)

	nameID, err := f.a.DecryptNameID(encryptedID)
	require.NoError(t, err)
	assert.Equal(t, nameID.Value, "alice")
}

// The EncryptedID of a NameIDMappingResponse is encrypted as the policy says for the service provider that the
// identifier is for, which is not the requester.
func TestIssuanceEncryptionNameIDMapping(t *testing.T) {
	f := newNameIDMappingFixture(t)
	f.test.IDP.IssuancePolicy = DefaultIssuancePolicy{ServiceProviders: map[string]ServiceProviderIssuance{
		f.b.MetadataURL.String(): issuanceLegacyEncryption,
	}}

	result := f.send(t, nameIDMappingOptions{})
	checkStatus(t, result.Response.Status, StatusSuccess, "")

	encryptedID := result.Element.FindElement("./EncryptedID")
	assert.Equal(t, issuanceEncryptionOf(t, encryptedID), issuanceLegacyEncrypted)

	nameID, err := f.b.DecryptNameID(reparse(t, encryptedID))
	require.NoError(t, err)
	assert.Equal(t, nameID.Value, "b-alice")
}

func TestIssuanceRequireAssertionEncryption(t *testing.T) {
	yes, no := RequireAssertionEncryption, EncryptAssertionWhenPossible

	// No assertion is sent, and the service provider is told that the identity provider failed, in a Response
	// that is signed as every one that reports an error is.
	refused := func(t *testing.T, test *IdentityProviderTest) {
		t.Helper()

		logs := &bytes.Buffer{}
		test.IDP.Observer = logObserver(logs)

		w := serveSSO(test, replayPostRequest(signedPostBody(t, &test.SP, nil), nil))
		require.Equal(t, w.Code, http.StatusOK, "body: %s", w.Body.String())
		assert.Contains(t, logs.String(), "has no encryption key")

		doc, _ := postedResponse(t, w.Body.String())
		responseEl := doc.Root()

		assert.Nil(t, responseEl.FindElement("./Assertion"))
		assert.Nil(t, responseEl.FindElement("./EncryptedAssertion"))
		assert.NotNil(t, responseEl.FindElement("./Signature"))

		statusCode := responseEl.FindElement("./Status/StatusCode")
		require.NotNil(t, statusCode)
		assert.Equal(t, statusCode.SelectAttrValue("Value", ""), StatusResponder)
	}

	plaintext := func(t *testing.T, test *IdentityProviderTest) {
		t.Helper()

		responseEl, responseXML, id := issuanceSSO(t, test)
		assert.NotNil(t, responseEl.FindElement("./Assertion"))
		assert.Nil(t, responseEl.FindElement("./EncryptedAssertion"))

		issuanceAccept(t, &test.SP, responseXML, []string{id})
	}

	t.Run("off by default", func(t *testing.T) {
		test := issuanceTestIDP(t)
		issuanceMetadata(test, issuanceUnencrypted)
		issuanceFor(test, ServiceProviderIssuance{Sign: SignAssertion})

		plaintext(t, test)
	})

	t.Run("an assertion that is encrypted is sent", func(t *testing.T) {
		test := issuanceTestIDP(t)
		issuanceFor(test, ServiceProviderIssuance{AssertionEncryption: &yes})

		responseEl, responseXML, id := issuanceSSO(t, test)
		assert.Nil(t, responseEl.FindElement("./Assertion"))
		assert.NotNil(t, responseEl.FindElement("./EncryptedAssertion"))

		issuanceAccept(t, &test.SP, responseXML, []string{id})
	})

	t.Run("for one service provider", func(t *testing.T) {
		test := issuanceTestIDP(t)
		issuanceMetadata(test, issuanceUnencrypted)
		issuanceFor(test, ServiceProviderIssuance{AssertionEncryption: &yes})

		refused(t, test)
	})

	t.Run("for every service provider", func(t *testing.T) {
		test := issuanceTestIDP(t)
		issuanceMetadata(test, issuanceUnencrypted)
		test.IDP.IssuancePolicy = DefaultIssuancePolicy{AssertionEncryption: RequireAssertionEncryption}

		refused(t, test)
	})

	t.Run("for every service provider, with an entry that says nothing of it", func(t *testing.T) {
		test := issuanceTestIDP(t)
		issuanceMetadata(test, issuanceUnencrypted)
		test.IDP.IssuancePolicy = DefaultIssuancePolicy{
			AssertionEncryption: RequireAssertionEncryption,
			ServiceProviders:    map[string]ServiceProviderIssuance{test.SP.MetadataURL.String(): {Sign: SignAssertion}},
		}

		refused(t, test)
	})

	t.Run("for every service provider but one", func(t *testing.T) {
		test := issuanceTestIDP(t)
		issuanceMetadata(test, issuanceUnencrypted)
		test.IDP.IssuancePolicy = DefaultIssuancePolicy{
			AssertionEncryption: RequireAssertionEncryption,
			ServiceProviders:    map[string]ServiceProviderIssuance{test.SP.MetadataURL.String(): {AssertionEncryption: &no}},
		}

		plaintext(t, test)
	})

	t.Run("by a policy of the application", func(t *testing.T) {
		test := issuanceTestIDP(t)
		issuanceMetadata(test, issuanceUnencrypted)
		test.IDP.IssuancePolicy = issuancePolicyFunc(func(req IssuanceRequest) (Issuance, error) {
			issuance := req.Defaults
			issuance.AssertionEncryption = RequireAssertionEncryption

			return issuance, nil
		})

		refused(t, test)
	})

	t.Run("initiated by the identity provider", func(t *testing.T) {
		test := issuanceTestIDP(t)
		issuanceMetadata(test, issuanceUnencrypted)
		issuanceFor(test, ServiceProviderIssuance{AssertionEncryption: &yes})

		logs := &bytes.Buffer{}
		test.IDP.Observer = logObserver(logs)

		w := httptest.NewRecorder()
		test.IDP.ServeIDPInitiated(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/services/sp/whoami", nil), test.SP.MetadataURL.String(), "")
		assert.Equal(t, w.Code, http.StatusInternalServerError)
		assert.False(t, strings.Contains(w.Body.String(), "SAMLResponse"))
		assert.Contains(t, logs.String(), "has no encryption key")
	})

	t.Run("the assertion of a query", func(t *testing.T) {
		f := newQueryFixture(t)
		f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))
		issuanceMetadata(f.test, issuanceUnencrypted)
		issuanceFor(f.test, ServiceProviderIssuance{AssertionEncryption: &yes})

		response := f.queryAttributes(t, f.attributeQuery())
		assert.True(t, response.Response.Status.StatusCode.Value != StatusSuccess)
		assert.Len(t, response.Assertions, 0)
		assert.Contains(t, f.log.String(), "has no encryption key")
	})

	t.Run("an assertion that is requested by its ID", func(t *testing.T) {
		f := newQueryFixture(t)
		f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())
		issuanceMetadata(f.test, issuanceUnencrypted)
		issuanceFor(f.test, ServiceProviderIssuance{AssertionEncryption: &yes})

		response := f.requestAssertions(t, f.assertionIDRequest(queryTestStoredAssertionID))
		assert.True(t, response.Response.Status.StatusCode.Value != StatusSuccess)
		assert.Len(t, response.Assertions, 0)
		assert.Contains(t, f.log.String(), "has no encryption key")
	})
}

// refusingEncryptionCertificate has the identity provider refuse the encryption certificate of every service
// provider, and returns how often it was asked about one.
func refusingEncryptionCertificate(idp *IdentityProvider) *int {
	asked := new(int)

	idp.EncryptionKeyEnforcer = encryptionKeyEnforcerFunc(func(*IdpAuthnRequest, ServiceProviderEncryptionKey) error {
		*asked++

		return errors.New("the certificate is refused")
	})

	return asked
}

// plainAssertionElement returns the assertion of a response, which must not be encrypted as a whole.
func plainAssertionElement(t *testing.T, body string) *etree.Element {
	t.Helper()

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(body))

	assert.True(t, doc.Root().FindElement("./EncryptedAssertion") == nil, "the assertion is encrypted")

	assertionEl := doc.Root().FindElement("./Assertion")
	require.True(t, assertionEl != nil, "the response has no assertion: %s", body)

	return assertionEl
}

// NoAssertionEncryption sends a service provider that has an encryption key its assertion signed and not
// encrypted.
func TestIssuanceNoAssertionEncryption(t *testing.T) {
	none, whenPossible, required := NoAssertionEncryption, EncryptAssertionWhenPossible, RequireAssertionEncryption

	plaintext := func(t *testing.T, test *IdentityProviderTest) {
		t.Helper()

		responseEl, responseXML, id := issuanceSSO(t, test)
		assert.Nil(t, responseEl.FindElement("./EncryptedAssertion"))

		assertionEl := responseEl.FindElement("./Assertion")
		require.NotNil(t, assertionEl)
		assert.NotNil(t, assertionEl.FindElement("./Signature"))
		assert.NotNil(t, assertionEl.FindElement("./Subject/NameID"))
		assert.False(t, strings.Contains(string(responseXML), "EncryptedData"))

		issuanceAccept(t, &test.SP, responseXML, []string{id})
	}

	encrypted := func(t *testing.T, test *IdentityProviderTest) {
		t.Helper()

		responseEl, responseXML, id := issuanceSSO(t, test)
		assert.Nil(t, responseEl.FindElement("./Assertion"))
		assert.NotNil(t, responseEl.FindElement("./EncryptedAssertion"))

		issuanceAccept(t, &test.SP, responseXML, []string{id})
	}

	t.Run("for one service provider", func(t *testing.T) {
		test := issuanceTestIDP(t)
		issuanceFor(test, ServiceProviderIssuance{AssertionEncryption: &none})

		plaintext(t, test)
	})

	t.Run("not for another service provider", func(t *testing.T) {
		test := issuanceTestIDP(t)
		test.IDP.IssuancePolicy = DefaultIssuancePolicy{ServiceProviders: map[string]ServiceProviderIssuance{
			"https://other.example.com/metadata": {AssertionEncryption: &none},
		}}

		encrypted(t, test)
	})

	t.Run("with only the Response signed", func(t *testing.T) {
		test := issuanceTestIDP(t)
		issuanceMetadata(test, issuanceWantAssertionsSigned(nil))
		issuanceFor(test, ServiceProviderIssuance{Sign: SignResponse, AssertionEncryption: &none})

		responseEl, responseXML, id := issuanceSSO(t, test)
		assert.Nil(t, responseEl.FindElement("./EncryptedAssertion"))
		assert.NotNil(t, responseEl.FindElement("./Signature"))
		require.NotNil(t, responseEl.FindElement("./Assertion"))
		assert.Nil(t, responseEl.FindElement("./Assertion/Signature"))

		issuanceAccept(t, &test.SP, responseXML, []string{id})
	})

	t.Run("for every service provider", func(t *testing.T) {
		test := issuanceTestIDP(t)
		test.IDP.IssuancePolicy = DefaultIssuancePolicy{AssertionEncryption: NoAssertionEncryption}

		plaintext(t, test)
	})

	t.Run("for every service provider, with an entry that says nothing of it", func(t *testing.T) {
		test := issuanceTestIDP(t)
		test.IDP.IssuancePolicy = DefaultIssuancePolicy{
			AssertionEncryption: NoAssertionEncryption,
			ServiceProviders:    map[string]ServiceProviderIssuance{test.SP.MetadataURL.String(): {Sign: SignAssertion}},
		}

		plaintext(t, test)
	})

	t.Run("for every service provider but one", func(t *testing.T) {
		test := issuanceTestIDP(t)
		test.IDP.IssuancePolicy = DefaultIssuancePolicy{
			AssertionEncryption: NoAssertionEncryption,
			ServiceProviders:    map[string]ServiceProviderIssuance{test.SP.MetadataURL.String(): {AssertionEncryption: &whenPossible}},
		}

		encrypted(t, test)
	})

	t.Run("for every service provider but one, which must be encrypted to", func(t *testing.T) {
		test := issuanceTestIDP(t)
		test.IDP.IssuancePolicy = DefaultIssuancePolicy{
			AssertionEncryption: NoAssertionEncryption,
			ServiceProviders:    map[string]ServiceProviderIssuance{test.SP.MetadataURL.String(): {AssertionEncryption: &required}},
		}

		encrypted(t, test)
	})

	t.Run("for one service provider where every other must be encrypted to", func(t *testing.T) {
		test := issuanceTestIDP(t)
		test.IDP.IssuancePolicy = DefaultIssuancePolicy{
			AssertionEncryption: RequireAssertionEncryption,
			ServiceProviders:    map[string]ServiceProviderIssuance{test.SP.MetadataURL.String(): {AssertionEncryption: &none}},
		}

		plaintext(t, test)
	})

	t.Run("by a policy of the application", func(t *testing.T) {
		test := issuanceTestIDP(t)
		test.IDP.IssuancePolicy = issuancePolicyFunc(func(req IssuanceRequest) (Issuance, error) {
			issuance := req.Defaults
			issuance.AssertionEncryption = NoAssertionEncryption

			return issuance, nil
		})

		plaintext(t, test)
	})

	t.Run("to a service provider with no encryption key", func(t *testing.T) {
		test := issuanceTestIDP(t)
		issuanceMetadata(test, issuanceUnencrypted)
		issuanceFor(test, ServiceProviderIssuance{AssertionEncryption: &none})

		plaintext(t, test)
	})

	t.Run("initiated by the identity provider", func(t *testing.T) {
		test := issuanceTestIDP(t)
		issuanceFor(test, ServiceProviderIssuance{AssertionEncryption: &none})

		w := httptest.NewRecorder()
		test.IDP.ServeIDPInitiated(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/services/sp/whoami", nil), test.SP.MetadataURL.String(), "")
		require.Equal(t, w.Code, http.StatusOK, "body: %s", w.Body.String())

		doc, _ := postedResponse(t, w.Body.String())
		assert.Nil(t, doc.Root().FindElement("./EncryptedAssertion"))
		assert.NotNil(t, doc.Root().FindElement("./Assertion/Signature"))
	})

	t.Run("the Response of an ArtifactResponse", func(t *testing.T) {
		test, _ := artifactTestIDP(t)
		issuanceFor(test, ServiceProviderIssuance{AssertionEncryption: &none})

		artifact, _ := issueTestArtifact(t, test, &test.SP)
		r, _ := artifactResolvePost(t, &test.SP, artifact, nil)

		envelope := soapTestParseResponse(t, serveArtifactResolution(test, r))

		responseEl := envelope.FindElement("./Body/ArtifactResponse/Response")
		require.NotNil(t, responseEl)
		assert.Nil(t, responseEl.FindElement("./EncryptedAssertion"))
		assert.NotNil(t, responseEl.FindElement("./Assertion/Signature"))
	})

	t.Run("the artifact binding end to end", func(t *testing.T) {
		test, logs := artifactTestIDP(t)
		issuanceFor(test, ServiceProviderIssuance{AssertionEncryption: &none})

		artifactEndToEnd(t, test, logs)
	})
}

// An EncryptedID and an EncryptedAttribute are sent in an assertion that is not encrypted as a whole, and the
// signature of the assertion covers them (SAMLCore §6.2).
func TestIssuanceNoAssertionEncryptionEncryptsParts(t *testing.T) {
	none := NoAssertionEncryption

	t.Run("an EncryptedID that the NameIDPolicy asks for", func(t *testing.T) {
		test, req := encryptedPartsRequest(t)
		requestEncryptedID(req)
		issuanceFor(test, ServiceProviderIssuance{AssertionEncryption: &none})

		body := respond(t, req)
		assertionEl := plainAssertionElement(t, body)

		assert.Nil(t, assertionEl.FindElement("./Subject/NameID"))
		assert.False(t, strings.Contains(elementToString(assertionEl.FindElement("./Subject")), req.Assertion.Subject.NameID.Value))
		assert.True(t, req.nameIDEncrypted)

		encryptedID := assertionEl.FindElement("./Subject/EncryptedID")
		require.NotNil(t, encryptedID)

		nameID, err := test.SP.DecryptNameID(reparse(t, encryptedID))
		require.NoError(t, err)
		assert.Equal(t, *nameID, *req.Assertion.Subject.NameID)

		// The signature covers the EncryptedID: it verifies, and no longer does once the ciphertext is changed.
		assert.NotNil(t, assertionEl.FindElement("./Signature"))
		assert.NoError(t, test.SP.validateSignature(reparse(t, assertionEl)))

		tampered := reparse(t, assertionEl)
		cipherValue := tampered.FindElement("./Subject/EncryptedID/EncryptedData/CipherData/CipherValue")
		require.NotNil(t, cipherValue)
		cipherValue.SetText("AAAA" + cipherValue.Text())
		assert.NotNil(t, test.SP.validateSignature(tampered))

		assertion, err := test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
		require.NoError(t, err)
		assert.Equal(t, *req.Assertion.Subject.NameID, *assertion.Subject.NameID)
	})

	t.Run("an EncryptedID and EncryptedAttribute elements that the ElementEncryptionPolicy asks for", func(t *testing.T) {
		test, req := encryptedPartsRequest(t)
		issuanceFor(test, ServiceProviderIssuance{AssertionEncryption: &none})

		serviceProviders := []string{test.SP.MetadataURL.String()}
		test.IDP.ElementEncryptionPolicy = DefaultElementEncryptionPolicy{
			NameIDServiceProviders:    serviceProviders,
			AttributeServiceProviders: serviceProviders,
		}

		body := respond(t, req)
		assertionEl := plainAssertionElement(t, body)

		assert.Nil(t, assertionEl.FindElement("./Subject/NameID"))
		assert.NotNil(t, assertionEl.FindElement("./Subject/EncryptedID"))
		assert.Len(t, assertionEl.FindElements("./AttributeStatement/Attribute"), 0)
		assert.False(t, strings.Contains(body, "admins"))

		encryptedAttributes := assertionEl.FindElements("./AttributeStatement/EncryptedAttribute")
		require.True(t, len(encryptedAttributes) > 0)

		for _, encryptedAttribute := range encryptedAttributes {
			_, err := test.SP.decryptElement(reparse(t, encryptedAttribute))
			assert.NoError(t, err)
		}

		assert.NoError(t, test.SP.validateSignature(reparse(t, assertionEl)))

		assertion, err := test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
		require.NoError(t, err)
		assert.Equal(t, *req.Assertion.Subject.NameID, *assertion.Subject.NameID)
		assert.Equal(t, friendlyNames(req.Assertion.AttributeStatements), friendlyNames(assertion.AttributeStatements))
	})

	t.Run("the parts are encrypted with what the policy chose", func(t *testing.T) {
		test, req := encryptedPartsRequest(t)
		requestEncryptedID(req)

		issuance := issuanceLegacyEncryption
		issuance.AssertionEncryption = &none
		issuanceFor(test, issuance)

		assertionEl := plainAssertionElement(t, respond(t, req))
		assert.Equal(t, issuanceEncryptionOf(t, assertionEl.FindElement("./Subject/EncryptedID")), issuanceLegacyEncrypted)
	})

	t.Run("a part can't be encrypted to a service provider with no encryption key", func(t *testing.T) {
		test, req := encryptedPartsRequest(t)
		issuanceUnencrypted(req.SPSSODescriptor)
		issuanceFor(test, ServiceProviderIssuance{AssertionEncryption: &none})

		requestEncryptedID(req)

		err := DefaultAssertionMaker{}.MakeAssertion(req, encryptedPartsSession)
		if err == nil {
			err = req.MakeAssertionEl()
		}

		assert.True(t, errors.Is(err, ErrInvalidNameIDPolicy), "got %v", err)
		assert.Nil(t, req.AssertionEl)

		_, req = encryptedPartsRequest(t)
		issuanceUnencrypted(req.SPSSODescriptor)
		req.IDP.IssuancePolicy = test.IDP.IssuancePolicy
		req.IDP.ElementEncryptionPolicy = DefaultElementEncryptionPolicy{AttributeServiceProviders: []string{test.SP.MetadataURL.String()}}

		require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, encryptedPartsSession))
		assert.ErrorContains(t, req.MakeAssertionEl(), "has no encryption key")
		assert.Nil(t, req.AssertionEl)
	})
}

// An encryption certificate that can't be used only stops an assertion that is not encrypted as a whole if a part
// of it is encrypted.
func TestIssuanceNoAssertionEncryptionAndUnusableCertificate(t *testing.T) {
	none := NoAssertionEncryption

	t.Run("a refused certificate is not asked about when nothing is encrypted", func(t *testing.T) {
		test, req := encryptedPartsRequest(t)
		issuanceFor(test, ServiceProviderIssuance{AssertionEncryption: &none})

		asked := refusingEncryptionCertificate(&test.IDP)

		body := respond(t, req)
		assertionEl := plainAssertionElement(t, body)
		assert.NotNil(t, assertionEl.FindElement("./Subject/NameID"))
		assert.NotNil(t, assertionEl.FindElement("./Signature"))
		assert.Equal(t, *asked, 0)

		_, err := test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
		assert.NoError(t, err)
	})

	t.Run("a refused certificate over single sign-on", func(t *testing.T) {
		test := issuanceTestIDP(t)
		issuanceFor(test, ServiceProviderIssuance{AssertionEncryption: &none})
		refusingEncryptionCertificate(&test.IDP)

		responseEl, responseXML, id := issuanceSSO(t, test)
		assert.Nil(t, responseEl.FindElement("./EncryptedAssertion"))
		assert.NotNil(t, responseEl.FindElement("./Assertion/Signature"))

		issuanceAccept(t, &test.SP, responseXML, []string{id})
	})

	t.Run("a certificate that can't be parsed", func(t *testing.T) {
		test, req := encryptedPartsRequest(t)
		issuanceFor(test, ServiceProviderIssuance{AssertionEncryption: &none})

		for i := range req.SPSSODescriptor.KeyDescriptors {
			if key := &req.SPSSODescriptor.KeyDescriptors[i]; key.Use != "signing" {
				key.KeyInfo.X509Data.X509Certificates = []X509Certificate{{Data: "bm90IGEgY2VydGlmaWNhdGU="}}
			}
		}

		_, err := req.elementEncrypter()
		require.ErrorContains(t, err, "cannot parse certificate")

		plainAssertionElement(t, respond(t, req))
	})

	t.Run("a refused certificate stops an EncryptedID that the request asks for", func(t *testing.T) {
		test, req := encryptedPartsRequest(t)
		requestEncryptedID(req)
		issuanceFor(test, ServiceProviderIssuance{AssertionEncryption: &none})

		asked := refusingEncryptionCertificate(&test.IDP)

		require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, encryptedPartsSession))
		assert.ErrorContains(t, req.MakeAssertionEl(), "the certificate is refused")
		assert.Nil(t, req.AssertionEl)
		assert.Equal(t, *asked, 1)
	})

	t.Run("a refused certificate stops an EncryptedAttribute that the policy asks for", func(t *testing.T) {
		test, req := encryptedPartsRequest(t)
		issuanceFor(test, ServiceProviderIssuance{AssertionEncryption: &none})
		test.IDP.ElementEncryptionPolicy = DefaultElementEncryptionPolicy{AttributeServiceProviders: []string{test.SP.MetadataURL.String()}}

		asked := refusingEncryptionCertificate(&test.IDP)

		require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, encryptedPartsSession))
		assert.ErrorContains(t, req.MakeAssertionEl(), "the certificate is refused")
		assert.Nil(t, req.AssertionEl)
		assert.Equal(t, *asked, 1)
	})

	// What is not the opt-out is as it was: the assertion is never sent in plaintext because the key was refused.
	for name, encryption := range map[string]AssertionEncryption{
		"a refused certificate stops an assertion that is encrypted when possible": EncryptAssertionWhenPossible,
		"a refused certificate stops an assertion that must be encrypted":          RequireAssertionEncryption,
	} {
		t.Run(name, func(t *testing.T) {
			test, req := encryptedPartsRequest(t)
			issuanceFor(test, ServiceProviderIssuance{AssertionEncryption: &encryption})

			asked := refusingEncryptionCertificate(&test.IDP)

			require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, encryptedPartsSession))
			assert.ErrorContains(t, req.MakeAssertionEl(), "the certificate is refused")
			assert.Nil(t, req.AssertionEl)
			assert.Equal(t, *asked, 1)
		})
	}
}

// The answers of the assertion query and request protocol are not encrypted either.
func TestIssuanceNoAssertionEncryptionQueryResponses(t *testing.T) {
	none := NoAssertionEncryption

	t.Run("AttributeQuery", func(t *testing.T) {
		f := newQueryFixture(t)
		f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))
		issuanceFor(f.test, ServiceProviderIssuance{AssertionEncryption: &none})

		response := f.queryAttributes(t, f.attributeQuery())
		assertQueryStatus(t, response, StatusSuccess, "")
		require.Len(t, response.Assertions, 1)
		assert.Equal(t, response.Encrypted, 0)
		assert.NotNil(t, response.AssertionEls[0].FindElement("./Subject/NameID"))
	})

	t.Run("AuthnQuery", func(t *testing.T) {
		f := newQueryFixture(t)
		issuanceFor(f.test, ServiceProviderIssuance{AssertionEncryption: &none})

		response := f.queryAuthn(t, f.authnQuery())
		assertQueryStatus(t, response, StatusSuccess, "")
		require.Len(t, response.Assertions, 1)
		assert.Equal(t, response.Encrypted, 0)
	})

	t.Run("a query whose Subject is an EncryptedID", func(t *testing.T) {
		f := newQueryFixture(t)
		f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))
		issuanceFor(f.test, ServiceProviderIssuance{AssertionEncryption: &none})

		nameID := f.subject().NameID
		message := queryServices[0].message(f)
		encryptQuerySubject(t, idpEncrypter(t, f.test), message, nameID)

		response := f.query(t, queryServices[0], message)
		assertQueryStatus(t, response, StatusSuccess, "")
		require.Len(t, response.Assertions, 1)
		assert.Equal(t, response.Encrypted, 0)

		subjectEl := response.AssertionEls[0].FindElement("./Subject")
		require.NotNil(t, subjectEl)
		assert.Nil(t, subjectEl.FindElement("./NameID"))

		encryptedID := subjectEl.FindElement("./EncryptedID")
		require.NotNil(t, encryptedID)

		decrypted, err := f.test.SP.DecryptNameID(encryptedID)
		require.NoError(t, err)
		assert.Equal(t, *decrypted, *nameID)
	})

	t.Run("a query to a service provider whose certificate is refused", func(t *testing.T) {
		f := newQueryFixture(t)
		f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))
		issuanceFor(f.test, ServiceProviderIssuance{AssertionEncryption: &none})
		refusingEncryptionCertificate(&f.test.IDP)

		response := f.queryAttributes(t, f.attributeQuery())
		assertQueryStatus(t, response, StatusSuccess, "")
		require.Len(t, response.Assertions, 1)
		assert.Equal(t, response.Encrypted, 0)
	})

	t.Run("AssertionIDRequest", func(t *testing.T) {
		f := newQueryFixture(t)
		f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())
		issuanceFor(f.test, ServiceProviderIssuance{AssertionEncryption: &none})

		asked := refusingEncryptionCertificate(&f.test.IDP)

		response := f.requestAssertions(t, f.assertionIDRequest(queryTestStoredAssertionID))
		assertQueryStatus(t, response, StatusSuccess, "")
		require.Len(t, response.Assertions, 1)
		assert.Equal(t, response.Encrypted, 0)
		assert.Equal(t, response.Assertions[0].ID, queryTestStoredAssertionID)
		assert.Equal(t, *asked, 0)
	})

	t.Run("an AssertionIDRequest is still encrypted to by default", func(t *testing.T) {
		f := newQueryFixture(t)
		f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())

		response := f.requestAssertions(t, f.assertionIDRequest(queryTestStoredAssertionID))
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Equal(t, response.Encrypted, 1)
	})
}

// A value that is none of the constants is refused when the policy is asked, and nothing is sent.
func TestIssuanceRefusesUnknownAssertionEncryption(t *testing.T) {
	for _, encryption := range []AssertionEncryption{NoAssertionEncryption + 1, -1} {
		for _, encrypted := range []bool{true, false} {
			t.Run(fmt.Sprintf("%d, encryption key %t", encryption, encrypted), func(t *testing.T) {
				test := issuanceTestIDP(t)
				issuanceFor(test, ServiceProviderIssuance{AssertionEncryption: &encryption})

				if !encrypted {
					issuanceMetadata(test, issuanceUnencrypted)
				}

				logs := &bytes.Buffer{}
				test.IDP.Observer = logObserver(logs)

				w := serveSSO(test, replayPostRequest(signedPostBody(t, &test.SP, nil), nil))
				assert.Equal(t, w.Code, http.StatusInternalServerError)
				assert.False(t, strings.Contains(w.Body.String(), "SAMLResponse"))
				assert.Contains(t, logs.String(), "unknown AssertionEncryption")

				_, err := test.IDP.signingContextFor(httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/slo", nil), test.SP.Metadata())
				assert.ErrorContains(t, err, "unknown AssertionEncryption")
			})
		}
	}
}
