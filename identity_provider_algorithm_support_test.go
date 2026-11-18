package saml

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/dsig"
)

func signingMethods(algorithms ...string) []SigningMethod {
	methods := make([]SigningMethod, 0, len(algorithms))
	for _, algorithm := range algorithms {
		methods = append(methods, SigningMethod{Algorithm: algorithm})
	}

	return methods
}

func digestMethods(algorithms ...string) []DigestMethod {
	methods := make([]DigestMethod, 0, len(algorithms))
	for _, algorithm := range algorithms {
		methods = append(methods, DigestMethod{Algorithm: algorithm})
	}

	return methods
}

func TestIDPMetadataPublishesTheAlgorithmsItAccepts(t *testing.T) {
	test := NewIdentityProviderTest(t)

	metadata := test.IDP.Metadata()

	// By default, what the identity provider accepts on a signature: everything it can verify but SHA-1.
	require.NotNil(t, metadata.Extensions)
	assert.Equal(t, signingMethods(
		dsig.RSASHA256SignatureMethod, dsig.RSASHA384SignatureMethod, dsig.RSASHA512SignatureMethod,
		dsig.ECDSASHA256SignatureMethod, dsig.ECDSASHA384SignatureMethod, dsig.ECDSASHA512SignatureMethod,
	), metadata.Extensions.SigningMethods)
	assert.Equal(t, digestMethods(
		dsig.SHA256DigestMethod, dsig.SHA384DigestMethod, dsig.SHA512DigestMethod,
	), metadata.Extensions.DigestMethods)

	buf, err := xml.Marshal(metadata)
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(buf), "sha1"))
	assert.False(t, strings.Contains(string(buf), "KeySize"))

	// The lists are those of the entity, which every role has, so no role repeats them.
	assert.Nil(t, metadata.IDPSSODescriptors[0].Extensions)
	assert.Equal(t, metadata.Extensions.SigningMethods, metadata.SigningMethods(&metadata.IDPSSODescriptors[0].RoleDescriptor))

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(buf))
	assert.Equal(t, "Extensions", doc.Root().ChildElements()[0].Tag)
	assert.Equal(t, "IDPSSODescriptor", doc.Root().ChildElements()[1].Tag)
}

func TestIDPMetadataPublishesTheConfiguredAlgorithmsInOrder(t *testing.T) {
	test := NewIdentityProviderTest(t)
	test.IDP.SignatureMethods = []string{dsig.ECDSASHA384SignatureMethod, dsig.RSASHA256SignatureMethod}
	test.IDP.DigestMethods = []string{dsig.SHA512DigestMethod, dsig.SHA256DigestMethod}

	metadata := test.IDP.Metadata()

	assert.Equal(t, signingMethods(dsig.ECDSASHA384SignatureMethod, dsig.RSASHA256SignatureMethod), metadata.Extensions.SigningMethods)
	assert.Equal(t, digestMethods(dsig.SHA512DigestMethod, dsig.SHA256DigestMethod), metadata.Extensions.DigestMethods)

	// Each list is published on its own.
	test.IDP.SignatureMethods = nil

	metadata = test.IDP.Metadata()
	assert.Len(t, metadata.Extensions.SigningMethods, 6)
	assert.Equal(t, digestMethods(dsig.SHA512DigestMethod, dsig.SHA256DigestMethod), metadata.Extensions.DigestMethods)
}

func TestIDPMetadataPublishesSHA1OnlyWhenItIsAccepted(t *testing.T) {
	test := NewIdentityProviderTest(t)
	test.IDP.SignatureMethods = []string{dsig.RSASHA256SignatureMethod, dsig.RSASHA1SignatureMethod}
	test.IDP.DigestMethods = []string{dsig.SHA256DigestMethod, dsig.SHA1DigestMethod}

	metadata := test.IDP.Metadata()

	assert.Equal(t, signingMethods(dsig.RSASHA256SignatureMethod, dsig.RSASHA1SignatureMethod), metadata.Extensions.SigningMethods)
	assert.Equal(t, digestMethods(dsig.SHA256DigestMethod, dsig.SHA1DigestMethod), metadata.Extensions.DigestMethods)
}

func TestIDPMetadataPublishesNothingItWouldRefuse(t *testing.T) {
	for name, configure := range map[string]func(*IdentityProvider){
		"default": func(*IdentityProvider) {},
		"custom": func(idp *IdentityProvider) {
			idp.SignatureMethods = []string{dsig.ECDSASHA512SignatureMethod, dsig.RSASHA1SignatureMethod}
			idp.DigestMethods = []string{dsig.SHA384DigestMethod}
		},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t)
			configure(&test.IDP)

			policy, err := test.IDP.signaturePolicy()
			require.NoError(t, err)

			metadata := test.IDP.Metadata()

			published := make([]string, 0, len(metadata.Extensions.SigningMethods))
			for _, method := range metadata.Extensions.SigningMethods {
				published = append(published, method.Algorithm)
			}

			assert.Equal(t, policy.signatureMethods, published)

			published = published[:0]
			for _, method := range metadata.Extensions.DigestMethods {
				published = append(published, method.Algorithm)
			}

			assert.Equal(t, policy.digestMethods, published)
		})
	}

	// Lists that can't be used refuse every signed message, so there is nothing to publish.
	test := NewIdentityProviderTest(t)
	test.IDP.SignatureMethods = []string{"http://www.w3.org/2007/05/xmldsig-more#rsa-pss"}

	metadata := test.IDP.Metadata()
	assert.Nil(t, metadata.Extensions)
}

func TestIDPMetadataAlgorithmsAreOfTheEntityForEveryRole(t *testing.T) {
	test := NewIdentityProviderTest(t)

	ed := &EntityDescriptor{
		IDPSSODescriptors:             []IDPSSODescriptor{{}},
		AttributeAuthorityDescriptors: []AttributeAuthorityDescriptor{{}},
	}
	test.IDP.describeMetadata(ed)

	assert.Len(t, ed.Extensions.SigningMethods, 6)
	assert.Nil(t, ed.IDPSSODescriptors[0].Extensions)
	assert.Nil(t, ed.AttributeAuthorityDescriptors[0].Extensions)
	assert.Len(t, ed.SigningMethods(&ed.AttributeAuthorityDescriptors[0].RoleDescriptor), 6)
	assert.Len(t, ed.DigestMethods(&ed.AttributeAuthorityDescriptors[0].RoleDescriptor), 3)
}

func TestIDPMetadataHookCanRemoveTheAlgorithms(t *testing.T) {
	test := NewIdentityProviderTest(t)
	test.IDP.MetadataInfo = federationMetadataInfo()
	test.IDP.MetadataHook = func(metadata *EntityDescriptor) {
		assert.Len(t, metadata.Extensions.SigningMethods, 6)

		metadata.Extensions.SigningMethods, metadata.Extensions.DigestMethods = nil, nil
	}

	buf, err := xml.Marshal(test.IDP.Metadata())
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(buf), "algsupport"))
	assert.True(t, strings.Contains(string(buf), "EntityAttributes"))
}

func TestSignedIDPMetadataWithAlgorithmsIsVerified(t *testing.T) {
	test, verifier := metadataSigningTest(t)

	signed, err := test.IDP.SignedMetadata()
	require.NoError(t, err)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(signed))

	extensions := doc.Root().FindElement("./Extensions")
	require.NotNil(t, extensions)
	assert.Len(t, extensions.ChildElements(), 9)

	for i, child := range extensions.ChildElements() {
		assert.Equal(t, "alg", child.Space)
		assert.Equal(t, testNSAlg, child.NamespaceURI())

		if i < 3 {
			assert.Equal(t, "DigestMethod", child.Tag)
		} else {
			assert.Equal(t, "SigningMethod", child.Tag)
		}
	}

	verified, err := verifier.Verify(signed)
	require.NoError(t, err)

	var metadata EntityDescriptor
	require.NoError(t, xml.Unmarshal(verified, &metadata))
	assert.Equal(t, test.IDP.Metadata().Extensions, metadata.Extensions)

	// A change to an algorithm breaks the signature.
	require.Equal(t, 1, strings.Count(string(signed), "ecdsa-sha256"))

	_, err = verifier.Verify([]byte(strings.Replace(string(signed), "ecdsa-sha256", "ecdsa-sha1", 1)))
	assert.NotNil(t, err)
}

// algorithmMetadata changes the metadata of the service provider that the identity provider is given.
func algorithmMetadata(test *IdentityProviderTest, mutate func(*EntityDescriptor)) {
	inner := test.IDP.ServiceProviderProvider

	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(r *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			metadata, err := inner.GetServiceProvider(r, serviceProviderID)
			if err != nil {
				return nil, err
			}

			mutate(metadata)

			return metadata, nil
		},
	}
}

// algorithmsListed lists algorithms in the Extensions of the entity.
func algorithmsListed(signing []SigningMethod, digests []DigestMethod) func(*EntityDescriptor) {
	return func(metadata *EntityDescriptor) {
		metadata.Extensions = &Extensions{SigningMethods: signing, DigestMethods: digests}
	}
}

// algorithmLog collects what the identity provider logs.
func algorithmLog(test *IdentityProviderTest) *bytes.Buffer {
	var buf bytes.Buffer

	test.IDP.Observer = logObserver(&buf)

	return &buf
}

// algorithmsNegotiated runs single sign-on, checks that the Response and the Assertion are both signed with the
// algorithms, and has the service provider accept the response.
func algorithmsNegotiated(t *testing.T, test *IdentityProviderTest, signatureMethod, digestMethod string) {
	t.Helper()

	responseEl, responseXML, id := issuanceSSO(t, test)

	responseSignature, assertionSignature, _ := issuanceSignatures(t, &test.SP, responseEl)

	for _, signature := range []*etree.Element{responseSignature, assertionSignature} {
		gotSignatureMethod, gotDigestMethod := issuanceAlgorithms(t, signature)
		assert.Equal(t, gotSignatureMethod, signatureMethod)
		assert.Equal(t, gotDigestMethod, digestMethod)
	}

	issuanceAccept(t, &test.SP, responseXML, []string{id})
}

func TestIDPNegotiatesSignatureAlgorithmsWithServiceProvider(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		signing                       []SigningMethod
		digests                       []DigestMethod
		signatureMethod, digestMethod string
	}{
		{
			name:            "none listed keeps the method of the identity provider",
			signatureMethod: dsig.RSASHA256SignatureMethod, digestMethod: dsig.SHA256DigestMethod,
		},
		{
			name:            "the first of each that can be used, in the order of the service provider",
			signing:         signingMethods(dsig.ECDSASHA384SignatureMethod, "http://www.w3.org/2007/05/xmldsig-more#rsa-pss", dsig.RSASHA512SignatureMethod, dsig.RSASHA256SignatureMethod),
			digests:         digestMethods("http://www.w3.org/2007/05/xmldsig-more#sha3-256", dsig.SHA384DigestMethod, dsig.SHA256DigestMethod),
			signatureMethod: dsig.RSASHA512SignatureMethod, digestMethod: dsig.SHA384DigestMethod,
		},
		{
			name:            "signing methods only, and the digest follows",
			signing:         signingMethods(dsig.RSASHA384SignatureMethod),
			signatureMethod: dsig.RSASHA384SignatureMethod, digestMethod: dsig.SHA384DigestMethod,
		},
		{
			name:            "digest methods only",
			digests:         digestMethods(dsig.SHA512DigestMethod),
			signatureMethod: dsig.RSASHA256SignatureMethod, digestMethod: dsig.SHA512DigestMethod,
		},
		{
			name:            "sha-1 is never negotiated",
			signing:         signingMethods(dsig.RSASHA1SignatureMethod, dsig.RSASHA512SignatureMethod),
			digests:         digestMethods(dsig.SHA1DigestMethod, dsig.SHA384DigestMethod),
			signatureMethod: dsig.RSASHA512SignatureMethod, digestMethod: dsig.SHA384DigestMethod,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := issuanceTestIDP(t)
			logged := algorithmLog(test)

			algorithmMetadata(test, algorithmsListed(tc.signing, tc.digests))

			algorithmsNegotiated(t, test, tc.signatureMethod, tc.digestMethod)
			assert.Equal(t, "", logged.String())
		})
	}
}

func TestIDPSignsWithItsDefaultWhenNoListedAlgorithmCanBeUsed(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		signing                       []SigningMethod
		digests                       []DigestMethod
		signatureMethod, digestMethod string
		lines                         int
		logged                        []string
	}{
		{
			name:            "no signing method for the key",
			signing:         signingMethods(dsig.ECDSASHA256SignatureMethod, "http://www.w3.org/2007/05/xmldsig-more#rsa-pss"),
			signatureMethod: dsig.RSASHA256SignatureMethod, digestMethod: dsig.SHA256DigestMethod,
			lines: 1, logged: []string{"alg:SigningMethod", dsig.RSASHA256SignatureMethod},
		},
		{
			name:            "only sha-1",
			signing:         signingMethods(dsig.RSASHA1SignatureMethod),
			digests:         digestMethods(dsig.SHA1DigestMethod),
			signatureMethod: dsig.RSASHA256SignatureMethod, digestMethod: dsig.SHA256DigestMethod,
			lines: 2, logged: []string{"alg:SigningMethod", "alg:DigestMethod"},
		},
		{
			name:            "no digest, with a signing method that can be used",
			signing:         signingMethods(dsig.RSASHA512SignatureMethod),
			digests:         digestMethods("http://www.w3.org/2007/05/xmldsig-more#sha3-256"),
			signatureMethod: dsig.RSASHA512SignatureMethod, digestMethod: dsig.SHA512DigestMethod,
			lines: 1, logged: []string{"alg:DigestMethod"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := issuanceTestIDP(t)
			logged := algorithmLog(test)

			algorithmMetadata(test, algorithmsListed(tc.signing, tc.digests))

			// The message is still signed, with what the identity provider would have used, and the reason is
			// logged once for the response.
			algorithmsNegotiated(t, test, tc.signatureMethod, tc.digestMethod)

			lines := strings.Split(strings.TrimSpace(logged.String()), "\n")
			require.Len(t, lines, tc.lines, logged.String())

			for _, line := range lines {
				assert.Contains(t, line, test.SP.MetadataURL.String())
			}

			for _, expected := range tc.logged {
				assert.Contains(t, logged.String(), expected)
			}
		})
	}
}

func TestIDPNegotiatesSHA1OnlyWhenItIsItsOwnMethod(t *testing.T) {
	test := issuanceTestIDP(t)
	test.IDP.SignatureMethod = dsig.RSASHA1SignatureMethod

	algorithmMetadata(test, algorithmsListed(
		signingMethods(dsig.RSASHA1SignatureMethod, dsig.RSASHA256SignatureMethod),
		digestMethods(dsig.SHA1DigestMethod, dsig.SHA256DigestMethod),
	))

	algorithmsNegotiated(t, test, dsig.RSASHA1SignatureMethod, dsig.SHA1DigestMethod)
}

func TestIDPNegotiationRespectsKeySizes(t *testing.T) {
	test := issuanceTestIDP(t)

	bits := test.IDP.Key.(*rsa.PrivateKey).N.BitLen()

	for _, tc := range []struct {
		name            string
		signing         []SigningMethod
		signatureMethod string
		logged          bool
	}{
		{
			name: "a minimum above and a maximum below the key are skipped",
			signing: []SigningMethod{
				{Algorithm: dsig.RSASHA512SignatureMethod, MinKeySize: bits + 1},
				{Algorithm: dsig.RSASHA384SignatureMethod, MaxKeySize: bits - 1},
				{Algorithm: dsig.RSASHA256SignatureMethod, MinKeySize: bits, MaxKeySize: bits},
			},
			signatureMethod: dsig.RSASHA256SignatureMethod,
		},
		{
			name: "bounds that hold the key",
			signing: []SigningMethod{
				{Algorithm: dsig.RSASHA512SignatureMethod, MinKeySize: bits - 1, MaxKeySize: bits + 1},
				{Algorithm: dsig.RSASHA384SignatureMethod},
			},
			signatureMethod: dsig.RSASHA512SignatureMethod,
		},
		{
			name:            "no method for a key of this size",
			signing:         []SigningMethod{{Algorithm: dsig.RSASHA512SignatureMethod, MinKeySize: bits * 2}},
			signatureMethod: dsig.RSASHA256SignatureMethod,
			logged:          true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logged := algorithmLog(test)
			test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
				GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) {
					metadata := test.SP.Metadata()
					algorithmsListed(tc.signing, nil)(metadata)

					return metadata, nil
				},
			}

			issuance, err := test.IDP.issuance(IssuanceRequest{ServiceProviderMetadata: mustGetServiceProvider(t, test)})
			require.NoError(t, err)
			assert.Equal(t, issuance.SignatureMethod, tc.signatureMethod)
			assert.Equal(t, logged.Len() != 0, tc.logged, logged.String())
		})
	}
}

func mustGetServiceProvider(t *testing.T, test *IdentityProviderTest) *EntityDescriptor {
	t.Helper()

	metadata, err := test.IDP.ServiceProviderProvider.GetServiceProvider(httptest.NewRequest(http.MethodGet, "/", nil), test.SP.MetadataURL.String())
	require.NoError(t, err)

	return metadata
}

func TestIDPNegotiatesWithAnECDSAKey(t *testing.T) {
	for name, apply := range map[string]func(*IdentityProvider, *ecdsa.PrivateKey){
		"key":           func(idp *IdentityProvider, key *ecdsa.PrivateKey) { idp.Key = key },
		"opaque signer": func(idp *IdentityProvider, key *ecdsa.PrivateKey) { idp.Key, idp.Signer = nil, opaqueSigner{key} },
	} {
		t.Run(name, func(t *testing.T) {
			test := issuanceTestIDP(t)

			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			// The clock of these tests is at the start of the certificate of the service provider.
			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject:      pkix.Name{CommonName: "idp"},
				NotBefore:    time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:     time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
			}

			der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
			require.NoError(t, err)

			certificate, err := x509.ParseCertificate(der)
			require.NoError(t, err)

			apply(&test.IDP, key)
			test.IDP.Certificate = certificate
			test.SP.IDPMetadata = test.IDP.Metadata()

			// The RSA method is for another type of key, and the key of 256 bits is too short for the first ECDSA
			// method as the service provider bounds it.
			algorithmMetadata(test, algorithmsListed([]SigningMethod{
				{Algorithm: dsig.RSASHA512SignatureMethod},
				{Algorithm: dsig.ECDSASHA512SignatureMethod, MinKeySize: 384},
				{Algorithm: dsig.ECDSASHA384SignatureMethod, MinKeySize: 256, MaxKeySize: 511},
				{Algorithm: dsig.ECDSASHA256SignatureMethod},
			}, digestMethods(dsig.SHA512DigestMethod)))

			algorithmsNegotiated(t, test, dsig.ECDSASHA384SignatureMethod, dsig.SHA512DigestMethod)
		})
	}
}

func TestIDPNegotiationPrefersTheRoleOfTheServiceProvider(t *testing.T) {
	test := issuanceTestIDP(t)

	algorithmMetadata(test, func(metadata *EntityDescriptor) {
		metadata.Extensions = &Extensions{
			SigningMethods: signingMethods(dsig.RSASHA512SignatureMethod),
			DigestMethods:  digestMethods(dsig.SHA256DigestMethod),
		}
		metadata.SPSSODescriptors[0].Extensions = &Extensions{SigningMethods: signingMethods(dsig.RSASHA384SignatureMethod)}
	})

	// The signing method of the role, and the digest of the entity as the role lists none.
	algorithmsNegotiated(t, test, dsig.RSASHA384SignatureMethod, dsig.SHA256DigestMethod)

	// A message that isn't for one role of the service provider is signed as for its first.
	signingContext, err := test.IDP.signingContextFor(httptest.NewRequest(http.MethodGet, "/", nil), mustGetServiceProvider(t, test))
	require.NoError(t, err)
	assert.Equal(t, signingContext.GetSignatureMethodIdentifier(), dsig.RSASHA384SignatureMethod)
	assert.Equal(t, signingContext.GetDigestAlgorithmIdentifier(), dsig.SHA256DigestMethod)
}

func TestIssuancePolicyOverridesNegotiatedAlgorithms(t *testing.T) {
	listed := algorithmsListed(signingMethods(dsig.RSASHA512SignatureMethod), digestMethods(dsig.SHA384DigestMethod))

	for _, tc := range []struct {
		name                          string
		issuance                      ServiceProviderIssuance
		signatureMethod, digestMethod string
	}{
		{"both", ServiceProviderIssuance{SignatureMethod: dsig.RSASHA384SignatureMethod, DigestMethod: dsig.SHA256DigestMethod},
			dsig.RSASHA384SignatureMethod, dsig.SHA256DigestMethod},
		{"the method of the identity provider, chosen for the service provider", ServiceProviderIssuance{SignatureMethod: dsig.RSASHA256SignatureMethod, DigestMethod: dsig.SHA256DigestMethod},
			dsig.RSASHA256SignatureMethod, dsig.SHA256DigestMethod},
		{"sha-1", ServiceProviderIssuance{SignatureMethod: dsig.RSASHA1SignatureMethod, DigestMethod: dsig.SHA1DigestMethod},
			dsig.RSASHA1SignatureMethod, dsig.SHA1DigestMethod},
		{"the signature method only, and the digest is still negotiated", ServiceProviderIssuance{SignatureMethod: dsig.RSASHA384SignatureMethod},
			dsig.RSASHA384SignatureMethod, dsig.SHA384DigestMethod},
		{"the digest only, and the signature method is still negotiated", ServiceProviderIssuance{DigestMethod: dsig.SHA256DigestMethod},
			dsig.RSASHA512SignatureMethod, dsig.SHA256DigestMethod},
		{"neither", ServiceProviderIssuance{Sign: SignResponseAndAssertion},
			dsig.RSASHA512SignatureMethod, dsig.SHA384DigestMethod},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := issuanceTestIDP(t)
			issuanceFor(test, tc.issuance)
			algorithmMetadata(test, listed)

			algorithmsNegotiated(t, test, tc.signatureMethod, tc.digestMethod)
		})
	}
}

func TestIssuancePolicyReceivesTheNegotiatedAlgorithms(t *testing.T) {
	test := issuanceTestIDP(t)
	algorithmMetadata(test, algorithmsListed(signingMethods(dsig.RSASHA512SignatureMethod), digestMethods(dsig.SHA384DigestMethod)))

	var defaults []Issuance

	// A policy that makes an Issuance of its own and names no algorithm gets those that were negotiated.
	test.IDP.IssuancePolicy = issuancePolicyFunc(func(req IssuanceRequest) (Issuance, error) {
		defaults = append(defaults, req.Defaults)

		return Issuance{IncludeSessionNotOnOrAfter: true}, nil
	})

	algorithmsNegotiated(t, test, dsig.RSASHA512SignatureMethod, dsig.SHA384DigestMethod)

	require.True(t, len(defaults) != 0)

	for _, issuance := range defaults {
		assert.Equal(t, issuance.SignatureMethod, dsig.RSASHA512SignatureMethod)
		assert.Equal(t, issuance.DigestMethod, dsig.SHA384DigestMethod)
	}
}

func TestIDPNegotiatesTheAlgorithmOfALogoutRequest(t *testing.T) {
	f := newPropagationFixture(t)
	logged := algorithmLog(f.test)

	// The service provider that is sent the LogoutRequest is the one that didn't ask for the logout.
	inner := f.test.IDP.ServiceProviderProvider
	f.test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(r *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			metadata, err := inner.GetServiceProvider(r, serviceProviderID)
			if err != nil {
				return nil, err
			}

			switch serviceProviderID {
			case f.a.MetadataURL.String():
				algorithmsListed(signingMethods(dsig.RSASHA1SignatureMethod, dsig.RSASHA384SignatureMethod), nil)(metadata)
			case f.b.MetadataURL.String():
				algorithmsListed(signingMethods(dsig.ECDSASHA256SignatureMethod, dsig.RSASHA512SignatureMethod), nil)(metadata)
			}

			return metadata, nil
		},
	}

	expected := map[string]string{
		f.a.SloURL.Host: dsig.RSASHA384SignatureMethod,
		f.b.SloURL.Host: dsig.RSASHA512SignatureMethod,
	}

	// The LogoutRequest, on the HTTP-Redirect binding, where the method is the SigAlg.
	w, id := f.serveSLOFromA(t)

	location := sentLogoutRequest(t, w)
	assert.Equal(t, location.Host, f.b.SloURL.Host)
	assert.Equal(t, location.Query().Get("SigAlg"), expected[location.Host])
	sentLogoutRequestElement(t, f.b, location)

	// And the LogoutResponse to the service provider that asked.
	w = serveSLO(f.test, respondAsSP(t, f.b, location))

	location, _ = redirectedLogoutResponse(t, w)
	assert.Equal(t, location.Host, f.a.SloURL.Host)
	assert.Equal(t, location.Query().Get("SigAlg"), expected[location.Host])
	assert.NoError(t, f.a.ValidateLogoutResponseRedirect(location, []string{id}))

	assert.Equal(t, "", logged.String())
}

func TestIDPSignsForAnUnknownServiceProviderWithItsOwnMethod(t *testing.T) {
	test := issuanceTestIDP(t)

	signingContext, err := test.IDP.signingContextFor(httptest.NewRequest(http.MethodGet, "/", nil), nil)
	require.NoError(t, err)
	assert.Equal(t, signingContext.GetSignatureMethodIdentifier(), dsig.RSASHA256SignatureMethod)
}

func TestIssuancePolicyDecidesTheAlgorithmOfAPropagatedLogoutResponse(t *testing.T) {
	f := newPropagationFixture(t)

	// The response that ends a propagated logout is for the service provider that asked, like one sent at once.
	f.test.IDP.IssuancePolicy = DefaultIssuancePolicy{ServiceProviders: map[string]ServiceProviderIssuance{
		f.a.MetadataURL.String(): {SignatureMethod: dsig.RSASHA512SignatureMethod},
	}}

	w, id := f.serveSLOFromA(t)
	w = serveSLO(f.test, respondAsSP(t, f.b, sentLogoutRequest(t, w)))

	location, _ := redirectedLogoutResponse(t, w)
	assert.Equal(t, location.Query().Get("SigAlg"), dsig.RSASHA512SignatureMethod)
	assert.NoError(t, f.a.ValidateLogoutResponseRedirect(location, []string{id}))
}
