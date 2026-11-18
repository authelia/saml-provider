package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml/internal/dsig"
)

var signatureMethodTestHashes = map[string]crypto.Hash{
	dsig.RSASHA1SignatureMethod:   crypto.SHA1,
	dsig.RSASHA256SignatureMethod: crypto.SHA256,
	dsig.SHA1DigestMethod:         crypto.SHA1,
	dsig.SHA256DigestMethod:       crypto.SHA256,
}

// signatureMethodCases are the combinations of algorithms that every path which verifies an enveloped signature
// is tested with.
var signatureMethodCases = []struct {
	name      string
	signature string
	digest    string
	sha1      bool
}{
	{"sha-256", dsig.RSASHA256SignatureMethod, dsig.SHA256DigestMethod, false},
	{"sha-1 signature and digest", dsig.RSASHA1SignatureMethod, dsig.SHA1DigestMethod, true},
	{"sha-1 signature", dsig.RSASHA1SignatureMethod, dsig.SHA256DigestMethod, true},
	{"sha-1 digest", dsig.RSASHA256SignatureMethod, dsig.SHA1DigestMethod, true},
}

// allowSHA1 opts the identity provider in to the SHA-1 algorithms of an RSA key.
func allowSHA1(idp *IdentityProvider) {
	idp.SignatureMethods = []string{dsig.RSASHA256SignatureMethod, dsig.RSASHA1SignatureMethod}
	idp.DigestMethods = []string{dsig.SHA256DigestMethod, dsig.SHA1DigestMethod}
}

// signElementWithMethods returns el with an enveloped RSA signature whose SignatureMethod and DigestMethod are
// chosen separately, which a SigningContext can't do. mutate, if it isn't nil, changes the SignedInfo before it
// is signed.
func signElementWithMethods(t *testing.T, el *etree.Element, key crypto.Signer, cert *x509.Certificate, signatureMethod, digestMethod string, mutate func(signedInfo *etree.Element)) *etree.Element {
	t.Helper()

	signingContext, err := dsig.NewSigningContext(key, [][]byte{cert.Raw})
	assert.NilError(t, err)

	signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signingContext.Hash = signatureMethodTestHashes[digestMethod]

	signed, err := signingContext.SignEnveloped(el)
	assert.NilError(t, err)

	signature := signed.ChildElements()[len(signed.ChildElements())-1]
	signedInfo := signature.ChildElements()[0]
	assert.Assert(t, is.Equal(signedInfo.Tag, dsig.SignedInfoTag))
	signedInfo.FindElement("./SignatureMethod").CreateAttr("Algorithm", signatureMethod)

	if mutate != nil {
		mutate(signedInfo)
	}

	detached := signedInfo.Copy()
	detached.CreateAttr("xmlns:ds", dsig.Namespace)

	canonical, err := signingContext.Canonicalizer.Canonicalize(detached)
	assert.NilError(t, err)

	hash := signatureMethodTestHashes[signatureMethod]
	h := hash.New()
	h.Write(canonical)

	value, err := key.Sign(rand.Reader, h.Sum(nil), hash)
	assert.NilError(t, err)

	signature.FindElement("./SignatureValue").SetText(base64.StdEncoding.EncodeToString(value))

	// As it is when it is received, which is not how etree holds an element that it was told to build.
	return reparse(t, signed)
}

// signAsTestSP signs el as the service provider of the test.
func signAsTestSP(t *testing.T, test *IdentityProviderTest, el *etree.Element, signatureMethod, digestMethod string) *etree.Element {
	t.Helper()

	return signElementWithMethods(t, el, test.SP.Key, test.SP.Certificate, signatureMethod, digestMethod, nil)
}

func elementBytes(t *testing.T, el *etree.Element) []byte {
	t.Helper()

	doc := etree.NewDocument()
	doc.SetRoot(el)
	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)

	return buf
}

// unsignedSP returns a copy of the service provider of the test that doesn't sign what it makes.
func unsignedSP(test *IdentityProviderTest) *ServiceProvider {
	unsigned := test.SP
	unsigned.SignatureMethod = ""

	return &unsigned
}

func unsignedTestLogoutRequest(t *testing.T, test *IdentityProviderTest, destination string) *etree.Element {
	t.Helper()

	request, err := unsignedSP(test).MakeLogoutRequest(destination, "alice")
	assert.NilError(t, err)

	return request.Element()
}

// envelopedSignaturePaths are the paths on which the identity provider verifies an enveloped signature. Each
// returns the error of a message signed with the algorithms, by an identity provider that configure has changed.
var envelopedSignaturePaths = map[string]func(t *testing.T, configure func(*IdentityProvider), signature, digest string) error{
	"AuthnRequest": func(t *testing.T, configure func(*IdentityProvider), signature, digest string) error {
		test := signatureTestIDP(t)
		configure(&test.IDP)

		request, err := unsignedSP(test).MakeAuthenticationRequest(signatureTestSSOURL, HTTPPostBinding, HTTPPostBinding)
		assert.NilError(t, err)

		return validatePost(t, test, elementBytes(t, signAsTestSP(t, test, request.Element(), signature, digest)))
	},
	"LogoutRequest": func(t *testing.T, configure func(*IdentityProvider), signature, digest string) error {
		test, _ := logoutTestIDP(t)
		configure(&test.IDP)

		el := signAsTestSP(t, test, unsignedTestLogoutRequest(t, test, logoutTestSLOURL), signature, digest)

		req, err := NewIdpLogoutRequest(&test.IDP, postLogoutBody(elementBytes(t, el)))
		assert.NilError(t, err)

		return req.Validate()
	},
	"LogoutResponse": func(t *testing.T, configure func(*IdentityProvider), signature, digest string) error {
		test, _ := logoutTestIDP(t)
		configure(&test.IDP)

		response, err := unsignedSP(test).MakeLogoutResponse(logoutTestSLOURL, logoutResponseTestRequestID)
		assert.NilError(t, err)

		body := elementBytes(t, signAsTestSP(t, test, response.Element(), signature, digest))
		form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(body)}, "RelayState": {"state-id"}}
		r := httptest.NewRequest(http.MethodPost, logoutTestSLOURL, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err = validateLogoutResponse(test, r, logoutResponseState(test))

		return err
	},
	"SOAP": func(t *testing.T, configure func(*IdentityProvider), signature, digest string) error {
		test, _ := soapLogoutTestIDP(t)
		configure(&test.IDP)

		el := signAsTestSP(t, test, unsignedTestLogoutRequest(t, test, soapLogoutTestURL), signature, digest)

		_, _, err := test.IDP.verifySOAPRequester(soapLogoutPost(nil), el, test.SP.MetadataURL.String())
		if err != nil {
			var statusErr *StatusError

			assert.Assert(t, errors.As(err, &statusErr))
			assert.Check(t, errors.Is(err, ErrInvalidSignature), "%v", err)
			assert.Check(t, is.Equal(statusErr.TopLevelField, StatusRequester))
			assert.Check(t, is.Equal(statusErr.SecondLevelField, StatusRequestDenied))
		}

		return err
	},
	"front channel requester": func(t *testing.T, configure func(*IdentityProvider), signature, digest string) error {
		test, _ := logoutTestIDP(t)
		configure(&test.IDP)

		el := signAsTestSP(t, test, unsignedTestLogoutRequest(t, test, logoutTestSLOURL), signature, digest)

		_, _, err := test.IDP.verifyFrontChannelRequester(httptest.NewRequest(http.MethodPost, logoutTestSLOURL, nil), el, "", test.SP.MetadataURL.String())

		return err
	},
	"ManageNameIDResponse": func(t *testing.T, configure func(*IdentityProvider), signature, digest string) error {
		test, _ := logoutTestIDP(t)
		configure(&test.IDP)

		response := &ManageNameIDResponse{ID: "id-response", Version: "2.0", IssueInstant: TimeNow()}
		el := signAsTestSP(t, test, response.Element(), signature, digest)

		policy, err := test.IDP.signaturePolicy()
		assert.NilError(t, err)

		_, err = verifyManageNameIDResponseSignature(el, response, true, test.SP.Metadata(), policy)

		return err
	},
	"metadata": func(t *testing.T, configure func(*IdentityProvider), signature, digest string) error {
		key, cert := negotiationKey()

		// The verifier is configured with the same lists as an identity provider.
		idp := &IdentityProvider{}
		configure(idp)

		verifier := &MetadataVerifier{
			Certificates:     []*x509.Certificate{cert},
			SignatureMethods: idp.SignatureMethods,
			DigestMethods:    idp.DigestMethods,
		}

		NewIdentityProviderTest(t)

		doc := etree.NewDocument()
		assert.NilError(t, doc.ReadFromString(testAggregate))

		signed := signElementWithMethods(t, doc.Root(), key, cert, signature, digest, nil)
		last := len(signed.Child) - 1
		signatureEl := signed.Child[last]
		signed.RemoveChildAt(last)
		signed.InsertChildAt(0, signatureEl)

		_, err := verifier.Verify(elementBytes(t, signed))

		return err
	},
}

func TestEnvelopedSignatureMethods(t *testing.T) {
	for path, verify := range envelopedSignaturePaths {
		for _, tc := range signatureMethodCases {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				err := verify(t, func(*IdentityProvider) {}, tc.signature, tc.digest)
				if tc.sha1 {
					assert.Check(t, is.Contains(errorText(err), "is not allowed"))
					assert.Check(t, is.ErrorContains(err, "signature"))
				} else {
					assert.Check(t, err)
				}
			})

			t.Run(path+"/"+tc.name+" with sha-1 allowed", func(t *testing.T) {
				assert.Check(t, verify(t, allowSHA1, tc.signature, tc.digest))
			})
		}

		t.Run(path+"/only the listed methods are accepted", func(t *testing.T) {
			err := verify(t, func(idp *IdentityProvider) {
				idp.SignatureMethods = []string{dsig.RSASHA512SignatureMethod}
			}, dsig.RSASHA256SignatureMethod, dsig.SHA256DigestMethod)
			assert.Check(t, is.Contains(errorText(err), "is not allowed"))

			err = verify(t, func(idp *IdentityProvider) {
				idp.DigestMethods = []string{dsig.SHA512DigestMethod}
			}, dsig.RSASHA256SignatureMethod, dsig.SHA256DigestMethod)
			assert.Check(t, is.Contains(errorText(err), "is not allowed"))
		})
	}
}

// The digest of every Reference is held to the list, and not only that of the Reference to the message, so that a
// signature is never accepted on the strength of a SignedInfo that names an algorithm which was refused.
func TestEnvelopedSignatureRefusesSHA1DigestOfAnotherReference(t *testing.T) {
	test := signatureTestIDP(t)

	request, err := unsignedSP(test).MakeAuthenticationRequest(signatureTestSSOURL, HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)

	sign := func(mutate func(*etree.Element)) []byte {
		return elementBytes(t, signElementWithMethods(t, request.Element(), test.SP.Key, test.SP.Certificate,
			dsig.RSASHA256SignatureMethod, dsig.SHA256DigestMethod, mutate))
	}

	otherReference := func(digestMethod string) func(*etree.Element) {
		return func(signedInfo *etree.Element) {
			reference := signedInfo.FindElement("./Reference").Copy()
			reference.CreateAttr("URI", "#other")
			reference.FindElement("./DigestMethod").CreateAttr("Algorithm", digestMethod)
			signedInfo.AddChild(reference)
		}
	}

	assert.Check(t, validatePost(t, test, sign(otherReference(dsig.SHA256DigestMethod))))
	assert.Check(t, is.Contains(errorText(validatePost(t, test, sign(otherReference(dsig.SHA1DigestMethod)))), "is not allowed"))
}

func TestRedirectSignatureMethods(t *testing.T) {
	paths := map[string]func(t *testing.T, configure func(*IdentityProvider), signature string) error{
		"AuthnRequest": func(t *testing.T, configure func(*IdentityProvider), signature string) error {
			test := signatureTestIDP(t)
			configure(&test.IDP)
			test.SP.SignatureMethod = signature

			return validateURL(t, test, signedRedirectURL(t, test).String())
		},
		"LogoutRequest": func(t *testing.T, configure func(*IdentityProvider), signature string) error {
			test, _ := logoutTestIDP(t)
			configure(&test.IDP)
			test.SP.SignatureMethod = signature

			r, _ := redirectLogoutRequest(t, &test.SP, nil)

			req, err := NewIdpLogoutRequest(&test.IDP, r)
			assert.NilError(t, err)

			return req.Validate()
		},
		"LogoutResponse": func(t *testing.T, configure func(*IdentityProvider), signature string) error {
			test, _ := logoutTestIDP(t)
			configure(&test.IDP)
			test.SP.SignatureMethod = signature

			r := signedLogoutResponse(t, HTTPRedirectBinding, &test.SP, &test.SP, nil)
			_, err := validateLogoutResponse(test, r, logoutResponseState(test))

			return err
		},
		"front channel requester": func(t *testing.T, configure func(*IdentityProvider), signature string) error {
			test, _ := logoutTestIDP(t)
			configure(&test.IDP)
			test.SP.SignatureMethod = signature

			r, _ := redirectLogoutRequest(t, &test.SP, nil)
			root := unsignedTestLogoutRequest(t, test, logoutTestSLOURL)

			_, _, err := test.IDP.verifyFrontChannelRequester(r, root, r.URL.RawQuery, test.SP.MetadataURL.String())

			return err
		},
	}

	for path, verify := range paths {
		t.Run(path+"/sha-256", func(t *testing.T) {
			assert.Check(t, verify(t, func(*IdentityProvider) {}, dsig.RSASHA256SignatureMethod))
		})

		t.Run(path+"/sha-1", func(t *testing.T) {
			err := verify(t, func(*IdentityProvider) {}, dsig.RSASHA1SignatureMethod)
			assert.Check(t, is.Contains(errorText(err), "signature: signature method "+dsig.RSASHA1SignatureMethod+" is not allowed"))
		})

		t.Run(path+"/sha-1 allowed", func(t *testing.T) {
			assert.Check(t, verify(t, allowSHA1, dsig.RSASHA1SignatureMethod))
		})

		// The digest methods have no part in a signature of the query, which has no Reference.
		t.Run(path+"/sha-1 signature allowed without its digest", func(t *testing.T) {
			assert.Check(t, verify(t, func(idp *IdentityProvider) {
				idp.SignatureMethods = []string{dsig.RSASHA1SignatureMethod}
			}, dsig.RSASHA1SignatureMethod))
		})

		t.Run(path+"/only the listed methods are accepted", func(t *testing.T) {
			err := verify(t, func(idp *IdentityProvider) {
				idp.SignatureMethods = []string{dsig.RSASHA512SignatureMethod}
			}, dsig.RSASHA256SignatureMethod)
			assert.Check(t, is.Contains(errorText(err), "is not allowed"))
		})
	}
}

// A refused algorithm is answered as any other invalid signature is.
func TestRefusedSignatureMethodIsAnsweredAsAnInvalidSignature(t *testing.T) {
	t.Run("ServeSSO", func(t *testing.T) {
		test := signatureTestIDP(t)
		test.SP.SignatureMethod = dsig.RSASHA1SignatureMethod

		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, httptest.NewRequest(http.MethodGet, signedRedirectURL(t, test).String(), nil))
		assert.Check(t, is.Equal(w.Code, http.StatusBadRequest))
	})

	t.Run("ServeSLO", func(t *testing.T) {
		test, provider := logoutTestIDP(t)
		test.SP.SignatureMethod = dsig.RSASHA1SignatureMethod

		for _, request := range []func(*testing.T, *ServiceProvider, func(*LogoutRequest)) (*http.Request, string){redirectLogoutRequest, postLogoutRequest} {
			r, _ := request(t, &test.SP, nil)
			w := serveSLO(test, r)
			assert.Check(t, is.Equal(w.Code, http.StatusBadRequest))
			assert.Check(t, is.Len(provider.terminated, 0))
		}
	})

	t.Run("ServeSOAPLogout", func(t *testing.T) {
		test, provider := soapLogoutTestIDP(t)
		test.SP.SignatureMethod = dsig.RSASHA1SignatureMethod

		r, _ := soapLogoutRequest(t, &test.SP, nil)
		response := soapLogoutResponse(t, serveSOAPLogout(test, r))
		assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusRequester))
		assert.Assert(t, response.Status.StatusCode.StatusCode != nil)
		assert.Check(t, is.Equal(response.Status.StatusCode.StatusCode.Value, StatusRequestDenied))
		assert.Check(t, is.Len(provider.terminated, 0))
	})
}

func TestDefaultSignatureMethodsExcludeSHA1(t *testing.T) {
	policy, err := (&IdentityProvider{}).signaturePolicy()
	assert.NilError(t, err)

	assert.Check(t, is.DeepEqual(policy.signatureMethods, []string{
		dsig.RSASHA256SignatureMethod, dsig.RSASHA384SignatureMethod, dsig.RSASHA512SignatureMethod,
		dsig.ECDSASHA256SignatureMethod, dsig.ECDSASHA384SignatureMethod, dsig.ECDSASHA512SignatureMethod,
	}))
	assert.Check(t, is.DeepEqual(policy.digestMethods, []string{
		dsig.SHA256DigestMethod, dsig.SHA384DigestMethod, dsig.SHA512DigestMethod,
	}))

	// Whatever can be verified can be listed, and no more.
	for _, method := range []string{dsig.RSASHA1SignatureMethod, dsig.ECDSASHA1SignatureMethod} {
		assert.Check(t, !slices.Contains(policy.signatureMethods, method))

		_, err = (&IdentityProvider{SignatureMethods: []string{method}}).signaturePolicy()
		assert.Check(t, err)
	}

	_, err = (&IdentityProvider{DigestMethods: []string{dsig.SHA1DigestMethod}}).signaturePolicy()
	assert.Check(t, err)
}

func TestUnsupportedSignatureMethodsAreAConfigurationError(t *testing.T) {
	const dsaSHA1 = "http://www.w3.org/2000/09/xmldsig#dsa-sha1"

	t.Run("signature method", func(t *testing.T) {
		test := signatureTestIDP(t)
		test.IDP.SignatureMethods = []string{dsig.RSASHA256SignatureMethod, dsaSHA1}

		err := validateURL(t, test, signedRedirectURL(t, test).String())
		assert.Check(t, is.Contains(errorText(err), `IdentityProvider.SignatureMethods: unsupported algorithm "`+dsaSHA1+`"`))
	})

	t.Run("digest method", func(t *testing.T) {
		test := signatureTestIDP(t)
		// A digest is not a signature method, and the other way around.
		test.IDP.DigestMethods = []string{dsig.RSASHA256SignatureMethod}

		err := validateURL(t, test, signedRedirectURL(t, test).String())
		assert.Check(t, is.Contains(errorText(err), `IdentityProvider.DigestMethods: unsupported algorithm "`+dsig.RSASHA256SignatureMethod+`"`))
	})

	t.Run("SOAP", func(t *testing.T) {
		test, _ := soapLogoutTestIDP(t)
		test.IDP.SignatureMethods = []string{dsaSHA1}

		el := signAsTestSP(t, test, unsignedTestLogoutRequest(t, test, soapLogoutTestURL), dsig.RSASHA256SignatureMethod, dsig.SHA256DigestMethod)

		_, _, err := test.IDP.verifySOAPRequester(soapLogoutPost(nil), el, test.SP.MetadataURL.String())

		var statusErr *StatusError

		assert.Assert(t, errors.As(err, &statusErr))
		assert.Check(t, errors.Is(err, ErrServerError), "%v", err)
		assert.Check(t, is.Equal(statusErr.TopLevelField, StatusResponder))
	})

	t.Run("metadata verifier", func(t *testing.T) {
		test, verifier := metadataSigningTest(t)
		signed, err := test.IDP.SignedMetadata()
		assert.NilError(t, err)

		verifier.SignatureMethods = []string{dsaSHA1}
		_, err = verifier.Verify(signed)
		assert.Check(t, is.ErrorContains(err, `MetadataVerifier.SignatureMethods: unsupported algorithm "`+dsaSHA1+`"`))

		verifier.SignatureMethods = nil
		verifier.DigestMethods = []string{"sha256"}
		_, err = verifier.Verify(signed)
		assert.Check(t, is.ErrorContains(err, `MetadataVerifier.DigestMethods: unsupported algorithm "sha256"`))
	})
}

// The lists are for what the identity provider receives. The service provider of this package is not changed.
func TestServiceProviderSignaturePolicyIsNotRestricted(t *testing.T) {
	for _, method := range []string{dsig.RSASHA1SignatureMethod, dsig.ECDSASHA1SignatureMethod, dsig.RSASHA256SignatureMethod} {
		assert.Check(t, slices.Contains(anySignaturePolicy.signatureMethods, method))
	}

	// Left nil, so that the digest of every Reference isn't checked as it is for the identity provider.
	assert.Check(t, anySignaturePolicy.digestMethods == nil)
	assert.Check(t, slices.Contains(supportedDigestMethods, dsig.SHA1DigestMethod))
}
