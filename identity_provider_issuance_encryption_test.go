package saml

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// issuanceEncryptionSP is the entity ID of the service provider of hardeningIssuer.
const issuanceEncryptionSP = "https://sp.example.com/saml2/metadata"

// issuanceEncryptionOf returns what the EncryptedData of encryptedEl, which is an EncryptedAssertion, EncryptedID,
// NewEncryptedID or EncryptedAttribute, states that it was encrypted with.
func issuanceEncryptionOf(t *testing.T, encryptedEl *etree.Element) negotiated {
	t.Helper()

	assert.Assert(t, encryptedEl != nil, "there is no encrypted element")

	contentMethod := encryptedEl.FindElement("./EncryptedData/EncryptionMethod")
	keyMethod := encryptedEl.FindElement("./EncryptedData/KeyInfo/EncryptedKey/EncryptionMethod")
	assert.Assert(t, contentMethod != nil && keyMethod != nil)

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
	assert.NilError(t, err)
	checkNegotiated(t, encryptedData, negotiated{content: aes128GCM, keyTransport: rsaOAEP, digest: digestSHA1})

	encryptedData, err = negotiatedAssertion(t, configure, method(aes256CBC), oaepMethod(rsaOAEP11, digestSHA256, mgf1SHA256))
	assert.NilError(t, err)
	checkNegotiated(t, encryptedData, negotiated{content: aes256CBC, keyTransport: rsaOAEP11, digest: digestSHA256, mgf: mgf1SHA256})

	_, err = negotiatedAssertion(t, configure, method(tripleDES))
	assert.Check(t, is.ErrorContains(err, "content encryption"))
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
			assert.NilError(t, err)
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
	assert.NilError(t, err)
	checkNegotiated(t, encryptedData, negotiated{content: aes128CBC, keyTransport: rsaOAEP, digest: digestSHA1})

	assert.Assert(t, len(defaults) > 0)

	for _, issuance := range defaults {
		assert.Check(t, is.Equal(issuance.ContentEncryptionMethod, ""))
		assert.Check(t, is.Equal(issuance.KeyTransportMethod, ""))
		assert.Check(t, is.Equal(issuance.KeyTransportDigestMethod, ""))
		assert.Check(t, is.Equal(issuance.KeyTransportMGF, ""))
		assert.Check(t, !issuance.RequireEncryption)
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
		{"key agreement", ServiceProviderIssuance{KeyTransportMethod: ecdhES}, nil, "unsupported key transport method"},
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
				test.IDP.Logger = log.New(logs, "", 0)

				w := serveSSO(test, replayPostRequest(signedPostBody(t, &test.SP, nil), nil))
				assert.Check(t, is.Equal(w.Code, http.StatusInternalServerError))
				assert.Check(t, !strings.Contains(w.Body.String(), "SAMLResponse"))
				assert.Check(t, is.Contains(logs.String(), "IssuancePolicy"))
				assert.Check(t, is.Contains(logs.String(), tc.reason))

				// Nor is any other message signed for that service provider.
				_, err := test.IDP.signingContextFor(httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/slo", nil), test.SP.Metadata())
				assert.Check(t, is.ErrorContains(err, tc.reason))
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

	assert.Check(t, is.Equal(issuanceEncryptionOf(t, responseEl.FindElement("./EncryptedAssertion")), issuanceLegacyEncrypted))

	assertion := issuanceAccept(t, &test.SP, responseXML, []string{id})
	assert.Check(t, assertion.Subject != nil)

	// Another service provider is not affected.
	test.IDP.IssuancePolicy = DefaultIssuancePolicy{ServiceProviders: map[string]ServiceProviderIssuance{
		"https://other.example.com/metadata": issuanceLegacyEncryption,
	}}

	responseEl, _, _ = issuanceSSO(t, test)
	assert.Check(t, is.Equal(issuanceEncryptionOf(t, responseEl.FindElement("./EncryptedAssertion")).content, aes128GCM))
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
	assert.NilError(t, doc.ReadFromString(body))
	assert.Check(t, is.Equal(issuanceEncryptionOf(t, doc.Root().FindElement("./EncryptedAssertion")), issuanceLegacyEncrypted))

	assertionEl := sentAssertionElement(t, test, body)

	encryptedID := assertionEl.FindElement("./Subject/EncryptedID")
	assert.Check(t, is.Equal(issuanceEncryptionOf(t, encryptedID), issuanceLegacyEncrypted))

	nameID, err := test.SP.DecryptNameID(reparse(t, encryptedID))
	assert.NilError(t, err)
	assert.Check(t, nameID.Value != "")

	encryptedAttributes := assertionEl.FindElements("./AttributeStatement/EncryptedAttribute")
	assert.Assert(t, len(encryptedAttributes) > 0)

	for _, encryptedAttribute := range encryptedAttributes {
		assert.Check(t, is.Equal(issuanceEncryptionOf(t, encryptedAttribute), issuanceLegacyEncrypted))

		_, err = test.SP.decryptElement(reparse(t, encryptedAttribute))
		assert.Check(t, err)
	}

	_, err = test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
	assert.Check(t, err)
}

func TestIssuanceEncryptionArtifact(t *testing.T) {
	t.Run("the Response of the ArtifactResponse", func(t *testing.T) {
		test, _ := artifactTestIDP(t)
		issuanceFor(test, issuanceLegacyEncryption)

		artifact, _ := issueTestArtifact(t, test, &test.SP)
		r, _ := artifactResolvePost(t, &test.SP, artifact, nil)

		envelope := soapTestParseResponse(t, serveArtifactResolution(test, r))

		encryptedAssertion := envelope.FindElement("./Body/ArtifactResponse/Response/EncryptedAssertion")
		assert.Check(t, is.Equal(issuanceEncryptionOf(t, encryptedAssertion), issuanceLegacyEncrypted))

		_, err := test.SP.decryptElement(reparse(t, encryptedAssertion))
		assert.Check(t, err)
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
	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())

	_, _, responseEl, err := parseSOAPEnvelope(w.Body.Bytes())
	assert.NilError(t, err)

	return responseEl, f.answer(t, w)
}

func TestIssuanceEncryptionQueryResponses(t *testing.T) {
	t.Run("AttributeQuery", func(t *testing.T) {
		f := newQueryFixture(t)
		f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))
		issuanceFor(f.test, issuanceLegacyEncryption)

		responseEl, response := issuanceQueryMessage(t, f, queryServices[0], f.attributeQuery().Element())
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Check(t, is.Equal(response.Encrypted, 1))
		assert.Check(t, is.Equal(issuanceEncryptionOf(t, responseEl.FindElement("./EncryptedAssertion")), issuanceLegacyEncrypted))
	})

	t.Run("AuthnQuery", func(t *testing.T) {
		f := newQueryFixture(t)
		issuanceFor(f.test, issuanceLegacyEncryption)

		responseEl, response := issuanceQueryMessage(t, f, queryServices[1], f.authnQuery().Element())
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Check(t, is.Equal(response.Encrypted, 1))
		assert.Check(t, is.Equal(issuanceEncryptionOf(t, responseEl.FindElement("./EncryptedAssertion")), issuanceLegacyEncrypted))
	})

	t.Run("AssertionIDRequest", func(t *testing.T) {
		f := newQueryFixture(t)
		f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())
		issuanceFor(f.test, issuanceLegacyEncryption)

		responseEl, response := issuanceQueryMessage(t, f, queryServices[2], f.assertionIDRequest(queryTestStoredAssertionID).Element())
		assertQueryStatus(t, response, StatusSuccess, "")
		assert.Check(t, is.Equal(response.Encrypted, 1))
		assert.Check(t, is.Equal(issuanceEncryptionOf(t, responseEl.FindElement("./EncryptedAssertion")), issuanceLegacyEncrypted))
	})
}

// The EncryptedID and NewEncryptedID of a ManageNameIDRequest that the identity provider sends.
func TestIssuanceEncryptionManageNameIDRequest(t *testing.T) {
	test, sp, _ := sendManageNameIDFixture(t)
	issuanceFor(test, issuanceLegacyEncryption)

	assert.NilError(t, sendManageNameID(test, NameIDChange{NameID: *testNameID(test, &test.SP), NewID: "p-alice-2", Encrypt: true}))
	assert.Assert(t, is.Len(sp.requests, 1))

	assert.Check(t, is.Equal(issuanceEncryptionOf(t, sp.elements[0].FindElement("./EncryptedID")), issuanceLegacyEncrypted))
	assert.Check(t, is.Equal(issuanceEncryptionOf(t, sp.elements[0].FindElement("./NewEncryptedID")), issuanceLegacyEncrypted))

	// The service provider decrypted both.
	assert.Check(t, is.DeepEqual(*sp.nameIDs[0], *testNameID(test, &test.SP)))
	assert.Check(t, is.Equal(sp.newIDs[0], "p-alice-2"))
}

// The EncryptedID of a LogoutRequest that the identity provider sends to a session participant.
func TestIssuanceEncryptionLogoutRequest(t *testing.T) {
	f := newPropagationFixture(t)
	f.test.IDP.IssuancePolicy = DefaultIssuancePolicy{ServiceProviders: map[string]ServiceProviderIssuance{
		f.a.MetadataURL.String(): issuanceLegacyEncryption,
	}}
	f.encryptParticipants(f.a.MetadataURL.String())

	el := sentLogoutRequestElement(t, f.a, sentLogoutRequest(t, f.startLogout(t)))
	assert.Check(t, el.FindElement("./NameID") == nil)

	encryptedID, err := findOneChild(el, samlAssertionNamespace, "EncryptedID")
	assert.NilError(t, err)
	assert.Check(t, is.Equal(issuanceEncryptionOf(t, encryptedID), issuanceLegacyEncrypted))

	nameID, err := f.a.DecryptNameID(encryptedID)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(nameID.Value, "alice"))
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
	assert.Check(t, is.Equal(issuanceEncryptionOf(t, encryptedID), issuanceLegacyEncrypted))

	nameID, err := f.b.DecryptNameID(reparse(t, encryptedID))
	assert.NilError(t, err)
	assert.Check(t, is.Equal(nameID.Value, "b-alice"))
}

func TestIssuanceRequireEncryption(t *testing.T) {
	yes, no := true, false

	// No assertion is sent, and the service provider is told that the identity provider failed, in a Response
	// that is signed as every one that reports an error is.
	refused := func(t *testing.T, test *IdentityProviderTest) {
		t.Helper()

		logs := &bytes.Buffer{}
		test.IDP.Logger = log.New(logs, "", 0)

		w := serveSSO(test, replayPostRequest(signedPostBody(t, &test.SP, nil), nil))
		assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())
		assert.Check(t, is.Contains(logs.String(), "has no encryption key"))

		doc, _ := postedResponse(t, w.Body.String())
		responseEl := doc.Root()

		assert.Check(t, responseEl.FindElement("./Assertion") == nil)
		assert.Check(t, responseEl.FindElement("./EncryptedAssertion") == nil)
		assert.Check(t, responseEl.FindElement("./Signature") != nil)

		statusCode := responseEl.FindElement("./Status/StatusCode")
		assert.Assert(t, statusCode != nil)
		assert.Check(t, is.Equal(statusCode.SelectAttrValue("Value", ""), StatusResponder))
	}

	plaintext := func(t *testing.T, test *IdentityProviderTest) {
		t.Helper()

		responseEl, responseXML, id := issuanceSSO(t, test)
		assert.Check(t, responseEl.FindElement("./Assertion") != nil)
		assert.Check(t, responseEl.FindElement("./EncryptedAssertion") == nil)

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
		issuanceFor(test, ServiceProviderIssuance{RequireEncryption: &yes})

		responseEl, responseXML, id := issuanceSSO(t, test)
		assert.Check(t, responseEl.FindElement("./Assertion") == nil)
		assert.Check(t, responseEl.FindElement("./EncryptedAssertion") != nil)

		issuanceAccept(t, &test.SP, responseXML, []string{id})
	})

	t.Run("for one service provider", func(t *testing.T) {
		test := issuanceTestIDP(t)
		issuanceMetadata(test, issuanceUnencrypted)
		issuanceFor(test, ServiceProviderIssuance{RequireEncryption: &yes})

		refused(t, test)
	})

	t.Run("for every service provider", func(t *testing.T) {
		test := issuanceTestIDP(t)
		issuanceMetadata(test, issuanceUnencrypted)
		test.IDP.IssuancePolicy = DefaultIssuancePolicy{RequireEncryption: true}

		refused(t, test)
	})

	t.Run("for every service provider, with an entry that says nothing of it", func(t *testing.T) {
		test := issuanceTestIDP(t)
		issuanceMetadata(test, issuanceUnencrypted)
		test.IDP.IssuancePolicy = DefaultIssuancePolicy{
			RequireEncryption: true,
			ServiceProviders:  map[string]ServiceProviderIssuance{test.SP.MetadataURL.String(): {Sign: SignAssertion}},
		}

		refused(t, test)
	})

	t.Run("for every service provider but one", func(t *testing.T) {
		test := issuanceTestIDP(t)
		issuanceMetadata(test, issuanceUnencrypted)
		test.IDP.IssuancePolicy = DefaultIssuancePolicy{
			RequireEncryption: true,
			ServiceProviders:  map[string]ServiceProviderIssuance{test.SP.MetadataURL.String(): {RequireEncryption: &no}},
		}

		plaintext(t, test)
	})

	t.Run("by a policy of the application", func(t *testing.T) {
		test := issuanceTestIDP(t)
		issuanceMetadata(test, issuanceUnencrypted)
		test.IDP.IssuancePolicy = issuancePolicyFunc(func(req IssuanceRequest) (Issuance, error) {
			issuance := req.Defaults
			issuance.RequireEncryption = true

			return issuance, nil
		})

		refused(t, test)
	})

	t.Run("initiated by the identity provider", func(t *testing.T) {
		test := issuanceTestIDP(t)
		issuanceMetadata(test, issuanceUnencrypted)
		issuanceFor(test, ServiceProviderIssuance{RequireEncryption: &yes})

		logs := &bytes.Buffer{}
		test.IDP.Logger = log.New(logs, "", 0)

		w := httptest.NewRecorder()
		test.IDP.ServeIDPInitiated(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/services/sp/whoami", nil), test.SP.MetadataURL.String(), "")
		assert.Check(t, is.Equal(w.Code, http.StatusInternalServerError))
		assert.Check(t, !strings.Contains(w.Body.String(), "SAMLResponse"))
		assert.Check(t, is.Contains(logs.String(), "has no encryption key"))
	})

	t.Run("the assertion of a query", func(t *testing.T) {
		f := newQueryFixture(t)
		f.requestAttributes(requested(mailAttributeName, uriAttrNameFormat))
		issuanceMetadata(f.test, issuanceUnencrypted)
		issuanceFor(f.test, ServiceProviderIssuance{RequireEncryption: &yes})

		response := f.queryAttributes(t, f.attributeQuery())
		assert.Check(t, response.Response.Status.StatusCode.Value != StatusSuccess)
		assert.Check(t, is.Len(response.Assertions, 0))
		assert.Check(t, is.Contains(f.log.String(), "has no encryption key"))
	})

	t.Run("an assertion that is requested by its ID", func(t *testing.T) {
		f := newQueryFixture(t)
		f.storeAssertion(t, queryTestStoredAssertionID, f.test.SP.MetadataURL.String())
		issuanceMetadata(f.test, issuanceUnencrypted)
		issuanceFor(f.test, ServiceProviderIssuance{RequireEncryption: &yes})

		response := f.requestAssertions(t, f.assertionIDRequest(queryTestStoredAssertionID))
		assert.Check(t, response.Response.Status.StatusCode.Value != StatusSuccess)
		assert.Check(t, is.Len(response.Assertions, 0))
		assert.Check(t, is.Contains(f.log.String(), "has no encryption key"))
	})
}
