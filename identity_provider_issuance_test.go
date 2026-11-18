package saml

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml/internal/dsig"
	"authelia.com/provider/saml/xmlenc"
)

const (
	issuanceSHA1Digest   = "http://www.w3.org/2000/09/xmldsig#sha1"
	issuanceSHA256Digest = "http://www.w3.org/2001/04/xmlenc#sha256"
	issuanceSHA512Digest = "http://www.w3.org/2001/04/xmlenc#sha512"
)

// issuancePolicyFunc is an IssuancePolicy made of a function.
type issuancePolicyFunc func(req IssuanceRequest) (Issuance, error)

func (f issuancePolicyFunc) Issuance(req IssuanceRequest) (Issuance, error) { return f(req) }

// issuanceTestIDP returns an identity provider with a session, whose service provider signs its requests.
func issuanceTestIDP(t *testing.T) *IdentityProviderTest {
	t.Helper()

	test := signatureTestIDP(t)
	useSession(test)

	previousRand, previousEncryptionRand := RandReader, xmlenc.RandReader

	t.Cleanup(func() { RandReader, xmlenc.RandReader = previousRand, previousEncryptionRand })

	RandReader, xmlenc.RandReader = rand.Reader, rand.Reader

	return test
}

// issuanceFor sets the policy of the identity provider to issuance for the service provider of test.
func issuanceFor(test *IdentityProviderTest, issuance ServiceProviderIssuance) {
	test.IDP.IssuancePolicy = DefaultIssuancePolicy{ServiceProviders: map[string]ServiceProviderIssuance{
		test.SP.MetadataURL.String(): issuance,
	}}
}

// issuanceMetadata changes the first SPSSODescriptor of the metadata that the identity provider is given.
func issuanceMetadata(test *IdentityProviderTest, mutate ...func(*SPSSODescriptor)) {
	inner := test.IDP.ServiceProviderProvider

	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(r *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			metadata, err := inner.GetServiceProvider(r, serviceProviderID)
			if err != nil {
				return nil, err
			}

			for _, f := range mutate {
				f(&metadata.SPSSODescriptors[0])
			}

			return metadata, nil
		},
	}
}

// issuanceUnencrypted removes the encryption key, so that the assertion is sent in the clear.
func issuanceUnencrypted(descriptor *SPSSODescriptor) {
	descriptor.KeyDescriptors = slices.DeleteFunc(descriptor.KeyDescriptors, func(key KeyDescriptor) bool {
		return key.Use != "signing"
	})
}

// issuanceWantAssertionsSigned sets WantAssertionsSigned, or removes it if want is nil.
func issuanceWantAssertionsSigned(want *bool) func(*SPSSODescriptor) {
	return func(descriptor *SPSSODescriptor) { descriptor.WantAssertionsSigned = want }
}

// issuanceSSO sends a signed request of the service provider to the identity provider, and returns the Response
// that is posted back, its XML and the ID of the request.
func issuanceSSO(t *testing.T, test *IdentityProviderTest) (*etree.Element, []byte, string) {
	t.Helper()

	body := signedPostBody(t, &test.SP, nil)

	w := serveSSO(test, replayPostRequest(body, nil))
	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())

	doc, _ := postedResponse(t, w.Body.String())

	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)

	return doc.Root(), buf, authnRequestID(t, body)
}

// issuanceSignatures returns the Signature of the Response and that of its assertion, which is decrypted with the
// key of sp if it is encrypted. Each is nil if there is none.
func issuanceSignatures(t *testing.T, sp *ServiceProvider, responseEl *etree.Element) (response, assertion *etree.Element, encrypted bool) {
	t.Helper()

	response, err := findChild(responseEl, "http://www.w3.org/2000/09/xmldsig#", "Signature")
	assert.NilError(t, err)

	assertionEl, err := findChild(responseEl, samlAssertionNS, "Assertion")
	assert.NilError(t, err)

	if assertionEl == nil {
		encryptedEl, err := findChild(responseEl, samlAssertionNS, "EncryptedAssertion")
		assert.NilError(t, err)
		assert.Assert(t, encryptedEl != nil, "the response has no assertion")

		encrypted = true

		assertionEl, err = sp.decryptElement(encryptedEl)
		assert.NilError(t, err)
	}

	assertion, err = findChild(assertionEl, "http://www.w3.org/2000/09/xmldsig#", "Signature")
	assert.NilError(t, err)

	return response, assertion, encrypted
}

// issuanceAlgorithms returns the SignatureMethod and the DigestMethod of a Signature.
func issuanceAlgorithms(t *testing.T, signature *etree.Element) (signatureMethod, digestMethod string) {
	t.Helper()

	assert.Assert(t, signature != nil, "no signature")

	methodEl := signature.FindElement("./SignedInfo/SignatureMethod")
	digestEl := signature.FindElement("./SignedInfo/Reference/DigestMethod")
	assert.Assert(t, methodEl != nil && digestEl != nil)

	return methodEl.SelectAttrValue("Algorithm", ""), digestEl.SelectAttrValue("Algorithm", "")
}

// issuanceAccept has sp consume the response, and fails the test with the reason if it is refused.
func issuanceAccept(t *testing.T, sp *ServiceProvider, responseXML []byte, possibleRequestIDs []string) *Assertion {
	t.Helper()

	assertion, err := sp.ParseXMLResponse(responseXML, possibleRequestIDs, sp.AcsURL)
	if invalid := (&InvalidResponseError{}); errors.As(err, &invalid) {
		t.Fatalf("the service provider refused the response: %s", invalid.PrivateErr)
	}

	assert.NilError(t, err)

	return assertion
}

func TestIssuanceDefaults(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)

	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	assert.NilError(t, err)

	issuance, err := req.Issuance(nil)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(issuance, Issuance{
		Sign:              SignResponseAndAssertion,
		SignatureMethod:   dsig.RSASHA256SignatureMethod,
		AssertionLifetime: MaxIssueDelay,
	}))

	test.IDP.SignatureMethod = dsig.RSASHA512SignatureMethod
	test.IDP.AssertionLifetime = time.Minute
	test.IDP.IncludeSessionNotOnOrAfter = true

	issuance, err = req.Issuance(nil)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(issuance, Issuance{
		Sign:                       SignResponseAndAssertion,
		SignatureMethod:            dsig.RSASHA512SignatureMethod,
		AssertionLifetime:          time.Minute,
		IncludeSessionNotOnOrAfter: true,
	}))
}

func TestIssuanceSigningShapes(t *testing.T) {
	for _, tc := range []struct {
		name                string
		sign                ResponseSigning
		response, assertion bool
	}{
		{"default", SignResponseAndAssertion, true, true},
		{"assertion only", SignAssertion, false, true},
		{"response only", SignResponse, true, false},
	} {
		for _, encrypted := range []bool{true, false} {
			name := tc.name + ", in the clear"
			if encrypted {
				name = tc.name + ", encrypted"
			}

			t.Run(name, func(t *testing.T) {
				test := issuanceTestIDP(t)
				issuanceFor(test, ServiceProviderIssuance{Sign: tc.sign})

				if encrypted {
					issuanceMetadata(test, issuanceWantAssertionsSigned(nil))
				} else {
					issuanceMetadata(test, issuanceWantAssertionsSigned(nil), issuanceUnencrypted)
				}

				responseEl, responseXML, id := issuanceSSO(t, test)

				responseSignature, assertionSignature, wasEncrypted := issuanceSignatures(t, &test.SP, responseEl)
				assert.Check(t, is.Equal(responseSignature != nil, tc.response), "response signature")
				assert.Check(t, is.Equal(assertionSignature != nil, tc.assertion), "assertion signature")
				assert.Check(t, is.Equal(wasEncrypted, encrypted))

				assertion := issuanceAccept(t, &test.SP, responseXML, []string{id})
				assert.Check(t, is.Equal(assertion.Issuer.Value, test.IDP.Metadata().EntityID))
			})
		}
	}
}

func TestIssuanceWithoutPolicySignsBoth(t *testing.T) {
	test := issuanceTestIDP(t)
	issuanceMetadata(test, issuanceWantAssertionsSigned(nil))

	responseEl, responseXML, id := issuanceSSO(t, test)

	responseSignature, assertionSignature, _ := issuanceSignatures(t, &test.SP, responseEl)

	for _, signature := range []*etree.Element{responseSignature, assertionSignature} {
		signatureMethod, digestMethod := issuanceAlgorithms(t, signature)
		assert.Check(t, is.Equal(signatureMethod, dsig.RSASHA256SignatureMethod))
		assert.Check(t, is.Equal(digestMethod, issuanceSHA256Digest))
	}

	issuanceAccept(t, &test.SP, responseXML, []string{id})
}

func TestIssuanceHonoursWantAssertionsSigned(t *testing.T) {
	yes, no := true, false

	for _, tc := range []struct {
		name      string
		want      *bool
		assertion bool
	}{
		{"true", &yes, true},
		{"false", &no, false},
		{"absent", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := issuanceTestIDP(t)
			issuanceFor(test, ServiceProviderIssuance{Sign: SignResponse})
			issuanceMetadata(test, issuanceWantAssertionsSigned(tc.want))

			responseEl, responseXML, id := issuanceSSO(t, test)

			responseSignature, assertionSignature, _ := issuanceSignatures(t, &test.SP, responseEl)
			assert.Check(t, responseSignature != nil)
			assert.Check(t, is.Equal(assertionSignature != nil, tc.assertion))

			issuanceAccept(t, &test.SP, responseXML, []string{id})
		})
	}
}

func TestIssuanceErrorResponseIsAlwaysSigned(t *testing.T) {
	for _, sign := range []ResponseSigning{SignResponseAndAssertion, SignAssertion, SignResponse} {
		test := issuanceTestIDP(t)
		issuanceFor(test, ServiceProviderIssuance{Sign: sign, SignatureMethod: dsig.RSASHA1SignatureMethod})

		test.IDP.AssertionMaker = assertionMakerFunc(func(*IdpAuthnRequest, *Session) error { return errors.New("boom") })

		body := signedPostBody(t, &test.SP, nil)
		w := serveSSO(test, replayPostRequest(body, nil))
		assertRequestStatus(t, w, authnRequestID(t, body), StatusResponder, "")

		doc, _ := postedResponse(t, w.Body.String())

		signature, err := findChild(doc.Root(), "http://www.w3.org/2000/09/xmldsig#", "Signature")
		assert.NilError(t, err)

		signatureMethod, _ := issuanceAlgorithms(t, signature)
		assert.Check(t, is.Equal(signatureMethod, dsig.RSASHA1SignatureMethod))

		assert.NilError(t, test.SP.validateSignature(doc.Root()))
	}
}

func TestIssuanceSignatureMethod(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		issuance                 ServiceProviderIssuance
		signatureMethod, digests string
	}{
		{"sha-1 for the service provider", ServiceProviderIssuance{SignatureMethod: dsig.RSASHA1SignatureMethod},
			dsig.RSASHA1SignatureMethod, issuanceSHA1Digest},
		{"sha-1 with another digest", ServiceProviderIssuance{SignatureMethod: dsig.RSASHA1SignatureMethod, DigestMethod: issuanceSHA256Digest},
			dsig.RSASHA1SignatureMethod, issuanceSHA256Digest},
		{"digest only", ServiceProviderIssuance{DigestMethod: issuanceSHA512Digest},
			dsig.RSASHA256SignatureMethod, issuanceSHA512Digest},
		{"sha-512", ServiceProviderIssuance{SignatureMethod: dsig.RSASHA512SignatureMethod},
			dsig.RSASHA512SignatureMethod, issuanceSHA512Digest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := issuanceTestIDP(t)
			issuanceFor(test, tc.issuance)

			responseEl, responseXML, id := issuanceSSO(t, test)

			responseSignature, assertionSignature, _ := issuanceSignatures(t, &test.SP, responseEl)

			for _, signature := range []*etree.Element{responseSignature, assertionSignature} {
				signatureMethod, digestMethod := issuanceAlgorithms(t, signature)
				assert.Check(t, is.Equal(signatureMethod, tc.signatureMethod))
				assert.Check(t, is.Equal(digestMethod, tc.digests))
			}

			issuanceAccept(t, &test.SP, responseXML, []string{id})
		})
	}
}

func TestIssuanceSignatureMethodIsForOneServiceProvider(t *testing.T) {
	test := issuanceTestIDP(t)
	test.IDP.IssuancePolicy = DefaultIssuancePolicy{ServiceProviders: map[string]ServiceProviderIssuance{
		"https://legacy.example.com/metadata": {Sign: SignAssertion, SignatureMethod: dsig.RSASHA1SignatureMethod},
	}}

	responseEl, _, _ := issuanceSSO(t, test)

	responseSignature, assertionSignature, _ := issuanceSignatures(t, &test.SP, responseEl)

	for _, signature := range []*etree.Element{responseSignature, assertionSignature} {
		signatureMethod, _ := issuanceAlgorithms(t, signature)
		assert.Check(t, is.Equal(signatureMethod, dsig.RSASHA256SignatureMethod))
	}
}

func TestIssuanceRefusesWhatCannotBeDone(t *testing.T) {
	for name, issuance := range map[string]ServiceProviderIssuance{
		"signature method of another key type": {SignatureMethod: dsig.ECDSASHA256SignatureMethod},
		"unknown signature method":             {SignatureMethod: "http://www.w3.org/2001/04/xmldsig-more#rsa-md5"},
		"unknown digest method":                {DigestMethod: "http://www.w3.org/2001/04/xmldsig-more#md5"},
		"unknown signing":                      {Sign: ResponseSigning(42)},
		"negative lifetime":                    {AssertionLifetime: -time.Second},
		"empty audience":                       {AdditionalAudiences: []string{""}},
	} {
		t.Run(name, func(t *testing.T) {
			test := issuanceTestIDP(t)
			issuanceFor(test, issuance)

			logs := &bytes.Buffer{}
			test.IDP.Observer = logObserver(logs)

			w := serveSSO(test, replayPostRequest(signedPostBody(t, &test.SP, nil), nil))
			assert.Check(t, is.Equal(w.Code, http.StatusInternalServerError))
			assert.Check(t, !strings.Contains(w.Body.String(), "SAMLResponse"))
			assert.Check(t, is.Contains(logs.String(), "IssuancePolicy"))
		})
	}
}

func TestIssuancePolicyReceivesTheRequest(t *testing.T) {
	test := issuanceTestIDP(t)

	var requests []IssuanceRequest

	test.IDP.IssuancePolicy = issuancePolicyFunc(func(req IssuanceRequest) (Issuance, error) {
		requests = append(requests, req)

		issuance := req.Defaults
		issuance.Sign = SignAssertion

		return issuance, nil
	})

	responseEl, responseXML, id := issuanceSSO(t, test)

	responseSignature, assertionSignature, _ := issuanceSignatures(t, &test.SP, responseEl)
	assert.Check(t, responseSignature == nil)
	assert.Check(t, assertionSignature != nil)

	issuanceAccept(t, &test.SP, responseXML, []string{id})

	assert.Assert(t, len(requests) > 0)

	for _, req := range requests {
		assert.Check(t, req.HTTPRequest != nil)
		assert.Assert(t, req.ServiceProviderMetadata != nil && req.SPSSODescriptor != nil && req.ACSEndpoint != nil)
		assert.Check(t, is.Equal(req.ServiceProviderMetadata.EntityID, test.SP.MetadataURL.String()))
		assert.Check(t, is.Equal(req.ACSEndpoint.Location, test.SP.AcsURL.String()))
		assert.Assert(t, req.AuthnRequest != nil)
		assert.Check(t, is.Equal(req.AuthnRequest.Request.ID, id))
		assert.Assert(t, req.Session != nil)
		assert.Check(t, is.Equal(req.Session.ID, "f00f00"))
		assert.Check(t, is.DeepEqual(req.Defaults, Issuance{
			SignatureMethod:   dsig.RSASHA256SignatureMethod,
			AssertionLifetime: MaxIssueDelay,
		}))
	}
}

func TestIssuancePolicyErrorFailsTheLogin(t *testing.T) {
	test := issuanceTestIDP(t)
	test.IDP.IssuancePolicy = issuancePolicyFunc(func(IssuanceRequest) (Issuance, error) {
		return Issuance{}, errors.New("boom")
	})

	w := serveSSO(test, replayPostRequest(signedPostBody(t, &test.SP, nil), nil))
	assert.Check(t, is.Equal(w.Code, http.StatusInternalServerError))
	assert.Check(t, !strings.Contains(w.Body.String(), "SAMLResponse"))
	assert.Check(t, !strings.Contains(w.Body.String(), "boom"))
}

// issuanceAssertion validates a current request and makes an assertion for session.
func issuanceAssertion(t *testing.T, test *IdentityProviderTest, session *Session) *IdpAuthnRequest {
	t.Helper()

	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	assert.NilError(t, err)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, session))

	return req
}

func TestIssuanceAssertionLifetime(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.AssertionLifetime = 30 * time.Second
	issuanceFor(test, ServiceProviderIssuance{AssertionLifetime: 10 * time.Minute})

	req := issuanceAssertion(t, test, &Session{ID: "f00d", NameID: "alice"})

	confirmation := req.Assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData
	assert.Check(t, req.Assertion.Conditions.NotOnOrAfter.Equal(TimeNow().Add(10*time.Minute)))
	assert.Check(t, confirmation.NotOnOrAfter.Equal(TimeNow().Add(10*time.Minute)))
	assert.Check(t, req.Assertion.Conditions.NotBefore.Equal(TimeNow().Add(-MaxClockSkew)))

	// A service provider that the policy doesn't name gets the lifetime of the identity provider.
	test.IDP.IssuancePolicy = DefaultIssuancePolicy{ServiceProviders: map[string]ServiceProviderIssuance{
		"https://other.example.com/metadata": {AssertionLifetime: 10 * time.Minute},
	}}

	req = issuanceAssertion(t, test, &Session{ID: "f00d", NameID: "alice"})
	assert.Check(t, req.Assertion.Conditions.NotOnOrAfter.Equal(TimeNow().Add(30*time.Second)))
}

func TestIssuanceSessionNotOnOrAfter(t *testing.T) {
	yes, no := true, false
	expire := TimeNow().Add(time.Hour)

	for _, tc := range []struct {
		name     string
		idp      bool
		override *bool
		stated   bool
	}{
		{"on for the service provider", false, &yes, true},
		{"off for the service provider", true, &no, false},
		{"as the identity provider, on", true, nil, true},
		{"as the identity provider, off", false, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			test.IDP.IncludeSessionNotOnOrAfter = tc.idp
			issuanceFor(test, ServiceProviderIssuance{IncludeSessionNotOnOrAfter: tc.override})

			req := issuanceAssertion(t, test, &Session{ID: "f00d", NameID: "alice", ExpireTime: expire})

			got := req.Assertion.AuthnStatements[0].SessionNotOnOrAfter
			assert.Assert(t, is.Equal(got != nil, tc.stated))

			if tc.stated {
				assert.Check(t, got.Equal(expire))
			}
		})
	}
}

func TestIssuanceAdditionalAudiences(t *testing.T) {
	test := issuanceTestIDP(t)
	issuanceFor(test, ServiceProviderIssuance{AdditionalAudiences: []string{
		"https://alias.example.com/sp",
		test.SP.MetadataURL.String(),
		"urn:example:proxy",
		"https://alias.example.com/sp",
	}})

	_, responseXML, id := issuanceSSO(t, test)

	assertion := issuanceAccept(t, &test.SP, responseXML, []string{id})

	assert.Assert(t, is.Len(assertion.Conditions.AudienceRestrictions, 1))
	assert.Check(t, is.DeepEqual(assertion.Conditions.AudienceRestrictions[0].Audiences, []Audience{
		{Value: test.SP.MetadataURL.String()},
		{Value: "https://alias.example.com/sp"},
		{Value: "urn:example:proxy"},
	}))
}

func TestIssuanceIDPInitiated(t *testing.T) {
	test := issuanceTestIDP(t)
	issuanceFor(test, ServiceProviderIssuance{Sign: SignAssertion, SignatureMethod: dsig.RSASHA1SignatureMethod})

	w := httptest.NewRecorder()
	test.IDP.ServeIDPInitiated(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/services/sp", nil),
		test.SP.MetadataURL.String(), "relay")
	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())

	doc, _ := postedResponse(t, w.Body.String())

	responseSignature, assertionSignature, _ := issuanceSignatures(t, &test.SP, doc.Root())
	assert.Check(t, responseSignature == nil)

	signatureMethod, _ := issuanceAlgorithms(t, assertionSignature)
	assert.Check(t, is.Equal(signatureMethod, dsig.RSASHA1SignatureMethod))

	responseXML, err := doc.WriteToBytes()
	assert.NilError(t, err)

	test.SP.AllowIDPInitiated = true
	issuanceAccept(t, &test.SP, responseXML, nil)
}

func TestIssuanceArtifactEndToEnd(t *testing.T) {
	for name, sign := range map[string]ResponseSigning{"assertion only": SignAssertion, "response only": SignResponse} {
		for _, encrypted := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s, encrypted %t", name, encrypted), func(t *testing.T) {
				test, logs := artifactTestIDP(t)
				issuanceFor(test, ServiceProviderIssuance{Sign: sign})

				if encrypted {
					issuanceMetadata(test, issuanceWantAssertionsSigned(nil))
				} else {
					issuanceMetadata(test, issuanceWantAssertionsSigned(nil), issuanceUnencrypted)
				}

				artifactEndToEnd(t, test, logs)
			})
		}
	}
}

func TestIssuanceArtifactResponse(t *testing.T) {
	test, _ := artifactTestIDP(t)
	issuanceFor(test, ServiceProviderIssuance{Sign: SignAssertion, SignatureMethod: dsig.RSASHA1SignatureMethod})
	issuanceMetadata(test, issuanceUnencrypted)

	artifact, _ := issueTestArtifact(t, test, &test.SP)
	r, _ := artifactResolvePost(t, &test.SP, artifact, nil)

	envelope := soapTestParseResponse(t, serveArtifactResolution(test, r))

	artifactResponseEl := envelope.FindElement("./Body/ArtifactResponse")
	assert.Assert(t, artifactResponseEl != nil)

	// The ArtifactResponse is how the identity provider authenticates itself, so it is signed whatever is signed
	// in the Response, with the algorithm of the service provider.
	signature, err := findChild(artifactResponseEl, "http://www.w3.org/2000/09/xmldsig#", "Signature")
	assert.NilError(t, err)

	signatureMethod, digestMethod := issuanceAlgorithms(t, signature)
	assert.Check(t, is.Equal(signatureMethod, dsig.RSASHA1SignatureMethod))
	assert.Check(t, is.Equal(digestMethod, issuanceSHA1Digest))

	responseEl, err := findChild(artifactResponseEl, samlProtocolNS, "Response")
	assert.NilError(t, err)
	assert.Assert(t, responseEl != nil)

	responseSignature, assertionSignature, _ := issuanceSignatures(t, &test.SP, responseEl)
	assert.Check(t, responseSignature == nil)

	signatureMethod, _ = issuanceAlgorithms(t, assertionSignature)
	assert.Check(t, is.Equal(signatureMethod, dsig.RSASHA1SignatureMethod))
}

func TestIssuanceECPEndToEnd(t *testing.T) {
	for _, tc := range []struct {
		name                string
		sign                ResponseSigning
		response, assertion bool
	}{
		{"assertion only", SignAssertion, false, true},
		{"response only", SignResponse, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test, _, sp := newECPEndToEnd(t)
			issuanceMetadata(test, issuanceWantAssertionsSigned(nil))

			test.IDP.IssuancePolicy = DefaultIssuancePolicy{ServiceProviders: map[string]ServiceProviderIssuance{
				sp.MetadataURL.String(): {Sign: tc.sign, SignatureMethod: dsig.RSASHA384SignatureMethod},
			}}

			request, err := sp.MakeAuthenticationRequest("", HTTPPostBinding, PAOSBinding)
			assert.NilError(t, err)

			client := &ecpTestClient{t: t, username: "alice", password: "secret"}
			responseXML := client.exchange(ecpTestPAOSRequest(t, request, ecpTestPAOSURL), sp.GetSSOBindingLocation(SOAPBinding))

			doc := etree.NewDocument()
			assert.NilError(t, doc.ReadFromBytes(responseXML))

			responseSignature, assertionSignature, _ := issuanceSignatures(t, sp, doc.Root())
			assert.Check(t, is.Equal(responseSignature != nil, tc.response))
			assert.Check(t, is.Equal(assertionSignature != nil, tc.assertion))

			for _, signature := range []*etree.Element{responseSignature, assertionSignature} {
				if signature != nil {
					signatureMethod, _ := issuanceAlgorithms(t, signature)
					assert.Check(t, is.Equal(signatureMethod, dsig.RSASHA384SignatureMethod))
				}
			}

			issuanceAccept(t, sp, responseXML, []string{request.ID})
		})
	}
}

func TestIssuanceQueryResponse(t *testing.T) {
	e := newQueryE2E(t)
	f, sp := e.f, &e.f.test.SP

	issuanceMetadata(f.test, issuanceWantAssertionsSigned(nil))
	issuanceFor(f.test, ServiceProviderIssuance{Sign: SignResponse, SignatureMethod: dsig.RSASHA1SignatureMethod})

	issued := e.sso(t)

	query := f.attributeQuery()
	query.Destination, query.Subject = e.attributeService, &Subject{NameID: issued.Subject.NameID}

	req, err := http.NewRequest(http.MethodPost, e.attributeService, bytes.NewReader(soapLogoutEnvelope(t, signQueryElement(t, sp, query.Element()))))
	assert.NilError(t, err)

	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", `"`+soapActionSAML+`"`)

	res, err := e.server.Client().Do(req)
	assert.NilError(t, err)

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	assert.NilError(t, err)
	assert.Assert(t, is.Equal(res.StatusCode, http.StatusOK), "body: %s", body)

	_, _, message, err := parseSOAPEnvelope(body)
	assert.NilError(t, err)
	assert.Assert(t, is.Equal(message.Tag, "Response"))

	// The Response to a query is always signed, with the algorithm of the service provider, and its assertion
	// is signed as one of single sign-on is.
	responseSignature, assertionSignature, _ := issuanceSignatures(t, sp, message)
	assert.Check(t, assertionSignature == nil)

	signatureMethod, digestMethod := issuanceAlgorithms(t, responseSignature)
	assert.Check(t, is.Equal(signatureMethod, dsig.RSASHA1SignatureMethod))
	assert.Check(t, is.Equal(digestMethod, issuanceSHA1Digest))

	assert.NilError(t, sp.validateSignature(message))
}

func TestIssuanceLogoutRequestSignatureMethod(t *testing.T) {
	f := newPropagationFixture(t)

	f.test.IDP.IssuancePolicy = DefaultIssuancePolicy{ServiceProviders: map[string]ServiceProviderIssuance{
		f.a.MetadataURL.String(): {SignatureMethod: dsig.RSASHA1SignatureMethod},
		f.b.MetadataURL.String(): {SignatureMethod: dsig.RSASHA512SignatureMethod},
	}}

	location := sentLogoutRequest(t, f.startLogout(t))

	expected := map[string]string{
		f.a.SloURL.Host: dsig.RSASHA1SignatureMethod,
		f.b.SloURL.Host: dsig.RSASHA512SignatureMethod,
	}

	assert.Check(t, is.Equal(location.Query().Get("SigAlg"), expected[location.Host]))
}

func TestIssuanceSigningContextForServiceProvider(t *testing.T) {
	test := issuanceTestIDP(t)
	issuanceFor(test, ServiceProviderIssuance{SignatureMethod: dsig.RSASHA1SignatureMethod, DigestMethod: issuanceSHA256Digest})

	r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/slo", nil)

	// Every message that is signed for the service provider uses its algorithms.
	signingContext, err := test.IDP.signingContextFor(r, test.SP.Metadata())
	assert.NilError(t, err)
	assert.Check(t, is.Equal(signingContext.GetSignatureMethodIdentifier(), dsig.RSASHA1SignatureMethod))
	assert.Check(t, is.Equal(signingContext.GetDigestAlgorithmIdentifier(), issuanceSHA256Digest))

	// A service provider that isn't known, or isn't named, gets those of the identity provider.
	for _, metadata := range []*EntityDescriptor{nil, {EntityID: "https://other.example.com/metadata"}} {
		signingContext, err = test.IDP.signingContextFor(r, metadata)
		assert.NilError(t, err)
		assert.Check(t, is.Equal(signingContext.GetSignatureMethodIdentifier(), dsig.RSASHA256SignatureMethod))
		assert.Check(t, is.Equal(signingContext.GetDigestAlgorithmIdentifier(), issuanceSHA256Digest))
	}

	// The policy is only asked about the service provider.
	var requests []IssuanceRequest

	test.IDP.IssuancePolicy = issuancePolicyFunc(func(req IssuanceRequest) (Issuance, error) {
		requests = append(requests, req)

		return req.Defaults, nil
	})

	_, err = test.IDP.signingContextFor(r, test.SP.Metadata())
	assert.NilError(t, err)
	assert.Assert(t, is.Len(requests, 1))
	assert.Check(t, requests[0].HTTPRequest == r)
	assert.Check(t, is.Equal(requests[0].ServiceProviderMetadata.EntityID, test.SP.MetadataURL.String()))
	assert.Check(t, requests[0].SPSSODescriptor == nil && requests[0].ACSEndpoint == nil)
	assert.Check(t, requests[0].AuthnRequest == nil && requests[0].Session == nil)
}
