package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml/internal/dsig"
)

const signatureTestSSOURL = "https://idp.example.com/saml/sso"

// signatureTestIDP returns an identity provider whose service provider signs its requests with a
// certificate that is currently valid.
func signatureTestIDP(t *testing.T) *IdentityProviderTest {
	t.Helper()
	test := NewIdentityProviderTest(t, applyKey)
	test.SP.SignatureMethod = dsig.RSASHA256SignatureMethod

	previousClock := Clock
	t.Cleanup(func() { Clock = previousClock })
	Clock = dsig.NewFakeClockAt(test.SPCertificate.NotBefore)
	return test
}

// signedRedirectURL returns the URL of a signed HTTP-Redirect request.
func signedRedirectURL(t *testing.T, test *IdentityProviderTest) *url.URL {
	t.Helper()
	request, err := test.SP.MakeAuthenticationRequest(signatureTestSSOURL, HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)
	u, err := request.Redirect("relay", &test.SP)
	assert.NilError(t, err)
	return u
}

func validateURL(t *testing.T, test *IdentityProviderTest, target string) error {
	t.Helper()
	req, err := NewIdpAuthnRequest(&test.IDP, httptest.NewRequest(http.MethodGet, target, nil))
	if err != nil {
		return err
	}
	return req.Validate()
}

// signedPostBody returns the XML of a request with an enveloped signature, after mutate has changed
// the request and before it is signed.
func signedPostBody(t *testing.T, sp *ServiceProvider, mutate func(*AuthnRequest)) []byte {
	t.Helper()
	unsigned := *sp
	unsigned.SignatureMethod = ""
	request, err := unsigned.MakeAuthenticationRequest(signatureTestSSOURL, HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	if mutate != nil {
		mutate(request)
	}
	assert.NilError(t, sp.SignAuthnRequest(request))
	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)
	return buf
}

func validatePost(t *testing.T, test *IdentityProviderTest, body []byte) error {
	t.Helper()
	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}}
	r := httptest.NewRequest(http.MethodPost, signatureTestSSOURL, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req, err := NewIdpAuthnRequest(&test.IDP, r)
	assert.NilError(t, err)
	return req.Validate()
}

// serviceProviderWithOtherKey returns a copy of the service provider which signs with a key that its
// metadata doesn't list, while still presenting the listed certificate. The identity provider and
// service provider test fixtures share a key, so this generates one.
func serviceProviderWithOtherKey(t *testing.T, test *IdentityProviderTest) ServiceProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	other := test.SP
	other.Key = key
	return other
}

func TestValidateAcceptsSignedRedirect(t *testing.T) {
	test := signatureTestIDP(t)
	assert.NilError(t, validateURL(t, test, signedRedirectURL(t, test).String()))
}

func TestValidateRejectsAlteredRedirect(t *testing.T) {
	for name, alter := range map[string]func(q string) string{
		"relay state": func(q string) string { return strings.Replace(q, "RelayState=relay", "RelayState=other", 1) },
		"added relay state": func(q string) string {
			return strings.Replace(q, "&RelayState=relay", "", 1) + "&RelayState=relay2"
		},
		"removed relay state": func(q string) string { return strings.Replace(q, "&RelayState=relay", "", 1) },
		"signature":           func(q string) string { return strings.Replace(q, "&Signature=", "&Signature=AAAA", 1) },
		"no signature": func(q string) string {
			before, _, _ := strings.Cut(q, "&Signature=")
			return before
		},
		"no algorithm": func(q string) string {
			before, after, _ := strings.Cut(q, "&SigAlg=")
			_, signature, _ := strings.Cut(after, "&Signature=")
			return before + "&Signature=" + signature
		},
		"other algorithm": func(q string) string {
			return strings.Replace(q, url.QueryEscape(dsig.RSASHA256SignatureMethod), url.QueryEscape(dsig.RSASHA512SignatureMethod), 1)
		},
		"unknown algorithm": func(q string) string {
			return strings.Replace(q, url.QueryEscape(dsig.RSASHA256SignatureMethod), "none", 1)
		},
		"duplicate parameter":        func(q string) string { return q + "&RelayState=other" },
		"encoded duplicate request":  func(q string) string { return "SAML%52equest=AAAA&" + q },
		"encoded duplicate relay":    func(q string) string { return "Relay%53tate=other&" + q },
		"encoded duplicate sigalg":   func(q string) string { return "Sig%41lg=none&" + q },
		"invalid parameter encoding": func(q string) string { return q + "&%zz=1" },
	} {
		t.Run(name, func(t *testing.T) {
			test := signatureTestIDP(t)
			u := signedRedirectURL(t, test)
			u.RawQuery = alter(u.RawQuery)
			assert.Check(t, validateURL(t, test, u.String()) != nil)
		})
	}
}

func TestValidateRejectsRedirectSignedByAnotherKey(t *testing.T) {
	test := signatureTestIDP(t)
	other := serviceProviderWithOtherKey(t, test)
	request, err := other.MakeAuthenticationRequest(signatureTestSSOURL, HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)
	u, err := request.Redirect("relay", &other)
	assert.NilError(t, err)

	assert.Check(t, is.ErrorContains(validateURL(t, test, u.String()), "signature"))
}

func TestValidateRejectsRedirectSignedWithExpiredCertificate(t *testing.T) {
	test := signatureTestIDP(t)
	u := signedRedirectURL(t, test)
	Clock = dsig.NewFakeClockAt(test.SPCertificate.NotAfter.Add(time.Hour))

	assert.Check(t, validateURL(t, test, u.String()) != nil)
}

// A service provider which doesn't declare that it signs still can't send a bad signature.
func TestValidateRejectsBadSignatureFromUndeclaredSigner(t *testing.T) {
	test := signatureTestIDP(t)
	u := signedRedirectURL(t, test)
	no := false
	metadata := test.SP.Metadata()
	metadata.SPSSODescriptors[0].AuthnRequestsSigned = &no
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) { return metadata, nil },
	}
	u.RawQuery = strings.Replace(u.RawQuery, "&Signature=", "&Signature=AAAA", 1)

	assert.Check(t, is.ErrorContains(validateURL(t, test, u.String()), "signature"))
}

func TestValidateRequiresSignatureWhenDeclaredBySP(t *testing.T) {
	test := signatureTestIDP(t)
	unsigned := test.SP
	unsigned.SignatureMethod = ""
	request, err := unsigned.MakeAuthenticationRequest(signatureTestSSOURL, HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)
	u, err := request.Redirect("relay", &unsigned)
	assert.NilError(t, err)

	assert.Check(t, is.ErrorContains(validateURL(t, test, u.String()), "not signed"))
}

// The descriptor in use is selected by the unauthenticated request, so it must not be able to choose
// one that doesn't declare signing.
func TestValidateRequiresSignatureWhenDeclaredByAnyDescriptor(t *testing.T) {
	test := signatureTestIDP(t)
	yes, no := true, false
	metadata := test.SP.Metadata()
	metadata.SPSSODescriptors[0].AuthnRequestsSigned = &no
	second := metadata.SPSSODescriptors[0]
	second.AuthnRequestsSigned = &yes
	metadata.SPSSODescriptors = append(metadata.SPSSODescriptors, second)
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) { return metadata, nil },
	}

	unsigned := test.SP
	unsigned.SignatureMethod = ""
	request, err := unsigned.MakeAuthenticationRequest(signatureTestSSOURL, HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)
	u, err := request.Redirect("", &unsigned)
	assert.NilError(t, err)

	assert.Check(t, is.ErrorContains(validateURL(t, test, u.String()), "not signed"))
}

func TestValidateRequiresSignatureWhenWantedByIDP(t *testing.T) {
	test := signatureTestIDP(t)
	test.SP.SignatureMethod = ""
	test.IDP.WantAuthnRequestsSigned = true

	request, err := test.SP.MakeAuthenticationRequest(signatureTestSSOURL, HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)
	u, err := request.Redirect("", &test.SP)
	assert.NilError(t, err)

	assert.Check(t, is.ErrorContains(validateURL(t, test, u.String()), "not signed"))
}

func TestValidateAcceptsSignedRequestWhenWantedByIDP(t *testing.T) {
	test := signatureTestIDP(t)
	test.IDP.WantAuthnRequestsSigned = true
	assert.NilError(t, validateURL(t, test, signedRedirectURL(t, test).String()))
}

func TestMetadataDeclaresWantAuthnRequestsSigned(t *testing.T) {
	test := signatureTestIDP(t)
	assert.Check(t, test.IDP.Metadata().IDPSSODescriptors[0].WantAuthnRequestsSigned == nil)

	test.IDP.WantAuthnRequestsSigned = true
	want := test.IDP.Metadata().IDPSSODescriptors[0].WantAuthnRequestsSigned
	assert.Assert(t, want != nil)
	assert.Check(t, *want)
}

// ecdsaServiceProvider makes the test service provider's metadata list a new ECDSA certificate.
func ecdsaServiceProvider(t *testing.T, test *IdentityProviderTest) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NilError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sp"},
		NotBefore:    test.SPCertificate.NotBefore.Add(-time.Hour),
		NotAfter:     test.SPCertificate.NotAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	assert.NilError(t, err)
	test.SP.Certificate, err = x509.ParseCertificate(der)
	assert.NilError(t, err)
	return key
}

// ecdsaRedirectURL returns a request signed with key, encoded by encode.
func ecdsaRedirectURL(t *testing.T, test *IdentityProviderTest, key *ecdsa.PrivateKey, encode func(r, s *big.Int, digest []byte) []byte) string {
	t.Helper()
	unsigned := test.SP
	unsigned.SignatureMethod = ""
	request, err := unsigned.MakeAuthenticationRequest(signatureTestSSOURL, HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)
	u, err := request.Redirect("", &unsigned)
	assert.NilError(t, err)

	query := u.RawQuery + "&SigAlg=" + url.QueryEscape(dsig.ECDSASHA256SignatureMethod)
	h := crypto.SHA256.New()
	h.Write([]byte(query))
	digest := h.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	assert.NilError(t, err)

	u.RawQuery = query + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(encode(r, s, digest)))
	return u.String()
}

func TestValidateAcceptsECDSARedirectInXMLSignatureForm(t *testing.T) {
	test := signatureTestIDP(t)
	key := ecdsaServiceProvider(t, test)
	target := ecdsaRedirectURL(t, test, key, func(r, s *big.Int, _ []byte) []byte {
		return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	})

	assert.NilError(t, validateURL(t, test, target))
}

func TestValidateRejectsECDSARedirectInDERForm(t *testing.T) {
	test := signatureTestIDP(t)
	key := ecdsaServiceProvider(t, test)
	target := ecdsaRedirectURL(t, test, key, func(_, _ *big.Int, digest []byte) []byte {
		der, err := ecdsa.SignASN1(rand.Reader, key, digest)
		assert.NilError(t, err)
		return der
	})

	assert.Check(t, validateURL(t, test, target) != nil)
}

func TestValidateRejectsAlgorithmForAnotherKeyType(t *testing.T) {
	test := signatureTestIDP(t)
	key := ecdsaServiceProvider(t, test)
	target := ecdsaRedirectURL(t, test, key, func(r, s *big.Int, _ []byte) []byte {
		return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	})
	target = strings.Replace(target, url.QueryEscape(dsig.ECDSASHA256SignatureMethod), url.QueryEscape(dsig.RSASHA256SignatureMethod), 1)

	assert.Check(t, validateURL(t, test, target) != nil)
}

func TestValidateAcceptsSignedPost(t *testing.T) {
	test := signatureTestIDP(t)
	assert.NilError(t, validatePost(t, test, signedPostBody(t, &test.SP, nil)))
}

func TestValidateRejectsAlteredSignedPost(t *testing.T) {
	test := signatureTestIDP(t)
	body := signedPostBody(t, &test.SP, nil)
	altered := strings.Replace(string(body), `AssertionConsumerServiceURL="https://sp.example.com/saml2/acs"`,
		`AssertionConsumerServiceURL="https://sp.example.com/saml2/acs" ProviderName="other"`, 1)
	assert.Assert(t, altered != string(body))

	assert.Check(t, is.ErrorContains(validatePost(t, test, []byte(altered)), "signature"))
}

func TestValidateRejectsPostSignedByAnotherKey(t *testing.T) {
	test := signatureTestIDP(t)
	other := serviceProviderWithOtherKey(t, test)

	assert.Check(t, is.ErrorContains(validatePost(t, test, signedPostBody(t, &other, nil)), "signature"))
}

func TestValidateRequiresSignatureOnPostWhenDeclaredBySP(t *testing.T) {
	test := signatureTestIDP(t)
	unsigned := test.SP
	unsigned.SignatureMethod = ""
	request, err := unsigned.MakeAuthenticationRequest(signatureTestSSOURL, HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	body, err := doc.WriteToBytes()
	assert.NilError(t, err)

	assert.Check(t, is.ErrorContains(validatePost(t, test, body), "not signed"))
}

// SAMLBind §3.5.5.2 requires a signed message to carry the Destination.
func TestValidateRequiresDestinationOnSignedRequest(t *testing.T) {
	test := signatureTestIDP(t)
	body := signedPostBody(t, &test.SP, func(r *AuthnRequest) { r.Destination = "" })

	assert.Check(t, is.ErrorContains(validatePost(t, test, body), "destination"))
}

// The login form carries the signed query, because the signature doesn't survive as a POST.
func TestSignedRedirectResumesThroughFormField(t *testing.T) {
	test := signatureTestIDP(t)
	u := signedRedirectURL(t, test)

	first, err := NewIdpAuthnRequest(&test.IDP, httptest.NewRequest(http.MethodGet, u.String(), nil))
	assert.NilError(t, err)
	assert.Check(t, is.Equal(first.RedirectQuery, u.RawQuery))

	// The form's other fields are unsigned, so they must not take the place of the signed values.
	form := url.Values{
		"SAMLRequest":          {base64.StdEncoding.EncodeToString([]byte("<forged/>"))},
		"RelayState":           {"forged"},
		RedirectQueryFormField: {first.RedirectQuery},
	}
	r := httptest.NewRequest(http.MethodPost, signatureTestSSOURL, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	second, err := NewIdpAuthnRequest(&test.IDP, r)
	assert.NilError(t, err)

	assert.Check(t, is.DeepEqual(second.RequestBuffer, first.RequestBuffer))
	assert.Check(t, is.Equal(second.RelayState, "relay"))
	assert.Check(t, second.Validate())
}

func TestResumedRedirectWithAlteredQueryIsRejected(t *testing.T) {
	test := signatureTestIDP(t)
	u := signedRedirectURL(t, test)

	form := url.Values{RedirectQueryFormField: {strings.Replace(u.RawQuery, "RelayState=relay", "RelayState=other", 1)}}
	r := httptest.NewRequest(http.MethodPost, signatureTestSSOURL, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req, err := NewIdpAuthnRequest(&test.IDP, r)
	assert.NilError(t, err)

	assert.Check(t, is.ErrorContains(req.Validate(), "signature"))
}

func TestUnsignedRedirectHasNoRedirectQuery(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	request, err := test.SP.MakeAuthenticationRequest(signatureTestSSOURL, HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)
	u, err := request.Redirect("relay", &test.SP)
	assert.NilError(t, err)

	req, err := NewIdpAuthnRequest(&test.IDP, httptest.NewRequest(http.MethodGet, u.String(), nil))
	assert.NilError(t, err)
	assert.Check(t, is.Equal(req.RedirectQuery, ""))
	assert.Check(t, req.Validate())
}

// smuggleRootAttributes adds attributes to the root of a signed request. Exclusive canonicalization
// drops unused namespace declarations, so these don't change the digest, while encoding/xml matches
// attributes by local name in any namespace.
func smuggleRootAttributes(t *testing.T, body []byte, attributes string) []byte {
	t.Helper()
	return []byte(appendAttributes(t, string(body), "<samlp:AuthnRequest ", attributes))
}

// appendAttributes adds attributes to the end of the first tag that starts with prefix, because
// encoding/xml keeps the last of two attributes with the same local name.
func appendAttributes(t *testing.T, body, prefix, attributes string) string {
	t.Helper()
	start := strings.Index(body, prefix)
	assert.Assert(t, start >= 0, "no %s in %s", prefix, body)
	end := start + strings.Index(body[start:], ">")
	if body[end-1] == '/' {
		end--
	}
	return body[:end] + " " + attributes + body[end:]
}

func TestValidateIgnoresAttributesSmuggledIntoSignedPost(t *testing.T) {
	test := signatureTestIDP(t)
	metadata := test.SP.Metadata()
	metadata.SPSSODescriptors[0].AssertionConsumerServices = append(metadata.SPSSODescriptors[0].AssertionConsumerServices,
		IndexedEndpoint{Binding: HTTPPostBinding, Location: "https://sp.example.com/saml2/other-acs", Index: 9})
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) { return metadata, nil },
	}
	acsAttr := `xmlns:AssertionConsumerServiceURL="https://sp.example.com/saml2/other-acs"`

	for name, tc := range map[string]struct {
		mutate     func(*AuthnRequest)
		attributes string
	}{
		"acs url":                {nil, acsAttr},
		"is passive":             {nil, `xmlns:IsPassive="true"`},
		"force authn":            {nil, `xmlns:ForceAuthn="true"`},
		"used only in signature": {nil, `xmlns:IsPassive="true"`},
		"expired": {
			func(r *AuthnRequest) { r.IssueInstant = TimeNow().Add(-30 * 24 * time.Hour) },
			`xmlns:IssueInstant="` + TimeNow().UTC().Format(time.RFC3339) + `"`,
		},
		"other destination": {
			func(r *AuthnRequest) { r.Destination = "https://other-idp.example.com/sso" },
			`xmlns:Destination="` + signatureTestSSOURL + `"`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			signed := signedPostBody(t, &test.SP, tc.mutate)
			if name == "used only in signature" {
				signed = []byte(strings.Replace(string(signed), "</ds:Signature>", "<IsPassive:x/></ds:Signature>", 1))
			}
			body := smuggleRootAttributes(t, signed, tc.attributes)
			form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}}
			r := httptest.NewRequest(http.MethodPost, signatureTestSSOURL, strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req, err := NewIdpAuthnRequest(&test.IDP, r)
			assert.NilError(t, err)

			err = req.Validate()
			if tc.mutate != nil {
				assert.Check(t, err != nil, "the signed values must be the ones checked")
				return
			}
			if err != nil {
				return // refusing the request is also safe
			}
			assert.Check(t, is.Equal(req.ACSEndpoint.Location, "https://sp.example.com/saml2/acs"))
			assert.Check(t, req.Request.IsPassive == nil)
			assert.Check(t, req.Request.ForceAuthn == nil)
		})
	}
}

func TestValidateIgnoresSmuggledNameIDPolicyFormat(t *testing.T) {
	test := signatureTestIDP(t)
	format := "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	body := signedPostBody(t, &test.SP, func(r *AuthnRequest) {
		r.NameIDPolicy = &NameIDPolicy{Format: &format}
	})
	altered := appendAttributes(t, string(body), "<samlp:NameIDPolicy ", `xmlns:Format="forged"`)

	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(altered))}}
	r := httptest.NewRequest(http.MethodPost, signatureTestSSOURL, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req, err := NewIdpAuthnRequest(&test.IDP, r)
	assert.NilError(t, err)

	if err := req.Validate(); err != nil {
		return
	}
	assert.Check(t, is.Equal(*req.Request.NameIDPolicy.Format, format))
}

// A signature must not turn a document that is too deep to process into a panic.
func TestValidateDoesNotPanicOnOversizedSignedDocument(t *testing.T) {
	test := signatureTestIDP(t)
	unsigned := test.SP
	unsigned.SignatureMethod = ""
	request, err := unsigned.MakeAuthenticationRequest(signatureTestSSOURL, HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	doc.Root().AddChild(etree.NewElement("ds:Signature"))
	doc.Root().FindElement("./Signature").CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	for i := 0; i < 1100; i++ {
		doc.Root().AddChild(etree.NewElement("x"))
	}
	body, err := doc.WriteToBytes()
	assert.NilError(t, err)

	assert.Check(t, validatePost(t, test, body) != nil)
}

// A chain in the metadata must not make the issuer of the certificate a trusted signer.
func TestSigningCertificatesExcludeChain(t *testing.T) {
	test := signatureTestIDP(t)
	key := ecdsaServiceProvider(t, test)
	leaf := test.SP.Certificate
	test.SP.Certificate = test.SPCertificate
	test.SP.Intermediates = []*x509.Certificate{leaf}
	test.SP.SignatureMethod = dsig.RSASHA256SignatureMethod
	metadata := test.SP.Metadata()
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) { return metadata, nil },
	}
	target := ecdsaRedirectURL(t, test, key, func(r, s *big.Int, _ []byte) []byte {
		return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	})

	assert.Check(t, validateURL(t, test, target) != nil)
}

// The relay state is often a URL, and a signature must survive it unchanged.
func TestSignedRedirectPreservesRelayState(t *testing.T) {
	for _, relayState := range []string{"a&b=c", "https://app.example.com/x?a=1&b=2", "100%", "a+b", "a b"} {
		t.Run(relayState, func(t *testing.T) {
			test := signatureTestIDP(t)
			request, err := test.SP.MakeAuthenticationRequest(signatureTestSSOURL, HTTPRedirectBinding, HTTPPostBinding)
			assert.NilError(t, err)
			u, err := request.Redirect(relayState, &test.SP)
			assert.NilError(t, err)

			req, err := NewIdpAuthnRequest(&test.IDP, httptest.NewRequest(http.MethodGet, u.String(), nil))
			assert.NilError(t, err)
			assert.Check(t, req.Validate())
			assert.Check(t, is.Equal(req.RelayState, relayState))
		})
	}
}

// SAMLBind §3.4.4.1 signs only the SAML parameters, not others already in the SSO URL.
func TestSignedRedirectExcludesOtherQueryParameters(t *testing.T) {
	test := signatureTestIDP(t)
	request, err := test.SP.MakeAuthenticationRequest(signatureTestSSOURL, HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)
	request.Destination = signatureTestSSOURL + "?tenant=1"
	test.IDP.SSOURL.RawQuery = "tenant=1"
	u, err := request.Redirect("relay", &test.SP)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(u.Query().Get("tenant"), "1"))

	assert.Check(t, validateURL(t, test, u.String()))
}
