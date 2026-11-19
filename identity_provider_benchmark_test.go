package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/dsig"
	"authelia.com/provider/saml/internal/dsig/etreeutils"
)

// benchmarkRequestSizes are the sizes of the requests that are made to cost the most, up to maxAuthnRequestSize. A
// signed request with nothing added is more than a kilobyte, so the sizes start at two.
var benchmarkRequestSizes = []int{2 << 10, 4 << 10, 8 << 10, maxAuthnRequestSize}

// A benchmarkSignature is what an anonymous client can put in the place of the signature of a request.
type benchmarkSignature int

const (
	// benchmarkSignatureNone is no signature, which is refused once the request is parsed and searched for one.
	benchmarkSignatureNone benchmarkSignature = iota

	// benchmarkSignatureForged is a signature whose SignatureValue is not that of its SignedInfo, which is refused
	// once the signature is found and the SignedInfo is canonicalized.
	benchmarkSignatureForged

	// benchmarkSignatureReplayed is the signature of another request of the service provider, which any of its
	// users is given. Its SignedInfo verifies, so it is only refused once the whole request is canonicalized
	// and its digest is found to differ. This is the most work that a request which isn't authenticated causes.
	benchmarkSignatureReplayed
)

// A benchmarkShape is a way to fill a request with content that is costly to process.
type benchmarkShape struct {
	name      string
	signature benchmarkSignature

	// fill returns the attributes to add to the root element, and the content to add before and after its
	// Signature, which together are at most budget bytes.
	fill func(budget int) (attrs, before, after string)

	// refusal is in the debug message of the error that the request is refused with, which tells that the
	// request got as far as it is meant to.
	refusal string
}

const (
	benchmarkRefusalUnsigned  = "request is not signed"
	benchmarkRefusalSignature = "crypto/rsa: verification error"
	benchmarkRefusalDigest    = "Signature could not be verified"
	benchmarkRefusalPrefix    = "undeclared namespace prefix"
)

// benchmarkElements is the most elements that can be added before the signature of a request. A request with an
// element more is refused sooner and for less, as internal/dsig visits at most a thousand elements to find a
// signature, and those of the signed request are visited too.
const benchmarkElements = 975

var benchmarkShapes = []benchmarkShape{
	{
		// The cost of the size alone: text that every parser reads and nothing looks into.
		name:      "text",
		signature: benchmarkSignatureReplayed,
		refusal:   benchmarkRefusalDigest,
		fill: func(budget int) (attrs, before, after string) {
			return "", strings.Repeat("x", budget), ""
		},
	},
	{
		name:      "elements",
		signature: benchmarkSignatureReplayed,
		refusal:   benchmarkRefusalDigest,
		fill: func(budget int) (attrs, before, after string) {
			before = strings.Repeat("<a/>", min(benchmarkElements, budget/len("<a/>")))

			return "", before + strings.Repeat("x", budget-len(before)), ""
		},
	},
	{
		name:      "nested elements",
		signature: benchmarkSignatureReplayed,
		refusal:   benchmarkRefusalDigest,
		fill: func(budget int) (attrs, before, after string) {
			depth := min(benchmarkElements, budget/len("<a></a>"))

			return "", strings.Repeat("<a>", depth) + strings.Repeat("x", budget-depth*len("<a></a>")) + strings.Repeat("</a>", depth), ""
		},
	},
	{
		name:      "attributes",
		signature: benchmarkSignatureReplayed,
		refusal:   benchmarkRefusalDigest,
		fill: func(budget int) (attrs, before, after string) {
			return benchmarkRepeat(budget, func(i int) string { return " " + benchmarkName(i) + `=""` }), "", ""
		},
	},
	{
		// Attributes with a prefix each, for which the round trip check of internal/xmlrv undoes a namespace
		// declaration each. The prefixes aren't declared, as a declaration would take the place of an attribute,
		// so the request is refused when its canonicalization begins.
		name:      "prefixed attributes",
		signature: benchmarkSignatureReplayed,
		refusal:   benchmarkRefusalPrefix,
		fill: func(budget int) (attrs, before, after string) {
			return benchmarkRepeat(budget, func(i int) string { return " " + benchmarkName(i) + `:a=""` }), "", ""
		},
	},
	{
		// Namespace declarations on the root element, and elements that are named as the signature is and declare a
		// namespace each, for each of which the namespaces in scope are copied and looked into to tell whether it is
		// one. It needs no signature, so it is what a request to a service provider that doesn't sign its requests
		// can cost too.
		name:      "namespaces and signature named elements, unsigned",
		signature: benchmarkSignatureNone,
		refusal:   benchmarkRefusalUnsigned,
		fill: func(budget int) (attrs, before, after string) {
			return benchmarkFillNamespaces(budget, `<Signature xmlns:x="u"/>`)
		},
	},
	{
		// Namespace declarations on the root element, and elements before the signature that declare a namespace
		// each, for each of which the search for the signature copies the namespaces in scope.
		name:      "namespaces and elements, forged",
		signature: benchmarkSignatureForged,
		refusal:   benchmarkRefusalSignature,
		fill:      benchmarkFillNamespacesAndElements,
	},
	{
		// The same with a signature that is only refused once the request is canonicalized, which copies the
		// namespaces in scope for each element again. This is the request that was found to cost the most.
		name:      "namespaces and elements, replayed",
		signature: benchmarkSignatureReplayed,
		refusal:   benchmarkRefusalDigest,
		fill:      benchmarkFillNamespacesAndElements,
	},
}

// benchmarkFillNamespacesAndElements fills the request with namespaces and elements that each declare one more,
// before the signature.
func benchmarkFillNamespacesAndElements(budget int) (attrs, before, after string) {
	return benchmarkFillNamespaces(budget, `<a xmlns:x="u"/>`)
}

// benchmarkDeclarations is the most namespace declarations that can be added to the root element of a request:
// internal/dsig refuses a request with more than etreeutils.MaxPrefixes namespace prefixes in scope, and the
// request has six in scope before any are added, with those of the signature, and an element added declares one.
const benchmarkDeclarations = etreeutils.MaxPrefixes - 8

// benchmarkFillNamespaces declares as many namespaces on the root element as can be in half of the budget, and gives
// the rest to as many of element as can be added, as declarations that nothing uses don't change the digest. Each element declares a namespace, so its context is a copy of
// every namespace in scope, which is what makes the most pairs of an element and a namespace in scope.
func benchmarkFillNamespaces(budget int, element string) (attrs, before, after string) {
	var declarations strings.Builder

	for i := range benchmarkDeclarations {
		declaration := benchmarkDeclaration(i)
		if declarations.Len()+len(declaration) > budget/2 {
			break
		}

		declarations.WriteString(declaration)
	}

	attrs = declarations.String()
	before = strings.Repeat(element, min(benchmarkElements, (budget-len(attrs))/len(element)))

	return attrs, before, ""
}

// benchmarkDeclaration returns the declaration of namespace prefix i.
func benchmarkDeclaration(i int) string {
	return " xmlns:" + benchmarkName(i) + `="u"`
}

// benchmarkName returns name i of a sequence of distinct XML names that are as short as they can be. The names are
// in lower case and without an x, so that none is an attribute of the request or begins with xml.
func benchmarkName(i int) string {
	const letters = "abcdefghijklmnopqrstuvwyz"

	name := []byte{}

	for i++; i > 0; i = (i - 1) / len(letters) {
		name = append(name, letters[(i-1)%len(letters)])
	}

	return string(name)
}

// benchmarkRepeat returns item(0), item(1) and so on, for as many as fit in budget bytes.
func benchmarkRepeat(budget int, item func(i int) string) string {
	var b strings.Builder

	for i := 0; ; i++ {
		s := item(i)
		if b.Len()+len(s) > budget {
			return b.String()
		}

		b.WriteString(s)
	}
}

// benchmarkIDP returns an identity provider with a service provider that signs its requests, and whose metadata
// is at hand as that of a deployment is.
func benchmarkIDP(b *testing.B) (*IdentityProvider, *ServiceProvider) {
	b.Helper()

	idpKey, idpCertificate := interopKey(b, "idp-rsa")
	spKey, spCertificate := interopKey(b, "sp-rsa")

	idp := &IdentityProvider{
		Key:         idpKey,
		Certificate: idpCertificate,
		MetadataURL: mustParseURL("https://idp.example.com/saml/metadata"),
		SSOURL:      mustParseURL(signatureTestSSOURL),
	}

	sp := &ServiceProvider{
		Key:             spKey,
		Certificate:     spCertificate,
		MetadataURL:     mustParseURL("https://sp.example.com/saml2/metadata"),
		AcsURL:          mustParseURL("https://sp.example.com/saml2/acs"),
		IDPMetadata:     idp.Metadata(),
		SignatureMethod: dsig.RSASHA256SignatureMethod,
	}

	metadata := sp.Metadata()

	idp.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			if serviceProviderID == metadata.EntityID {
				return metadata, nil
			}

			return nil, os.ErrNotExist
		},
	}

	return idp, sp
}

// benchmarkSignedRequest returns a request that the service provider signed, without its KeyInfo, which the
// signature doesn't cover and the identity provider doesn't need.
func benchmarkSignedRequest(b *testing.B, sp *ServiceProvider) string {
	b.Helper()

	unsigned := *sp
	unsigned.SignatureMethod = ""

	request, err := unsigned.MakeAuthenticationRequest(signatureTestSSOURL, HTTPPostBinding, HTTPPostBinding)
	require.NoError(b, err)
	require.NoError(b, sp.SignAuthnRequest(request))

	root := request.Element()

	signature := root.FindElement("./Signature")
	require.NotNil(b, signature)
	signature.RemoveChild(signature.FindElement("./KeyInfo"))

	doc := etree.NewDocument()
	doc.SetRoot(root)

	buf, err := doc.WriteToString()
	require.NoError(b, err)

	return buf
}

// benchmarkRequest returns a request of size bytes that is the signed request filled as the shape has it.
func benchmarkRequest(b *testing.B, signed string, shape benchmarkShape, size int) []byte {
	b.Helper()

	const (
		signatureStart = "<ds:Signature "
		signatureEnd   = "</ds:Signature>"
		valueStart     = "<ds:SignatureValue>"
	)

	rootEnd := strings.Index(signed, ">")
	start := strings.Index(signed, signatureStart)
	end := strings.Index(signed, signatureEnd) + len(signatureEnd)

	require.True(b, rootEnd > 0 && start > rootEnd && end > start, "the request is not as expected: %s", signed)

	signature := signed[start:end]

	switch shape.signature {
	case benchmarkSignatureNone:
		signature = ""
	case benchmarkSignatureForged:
		i := strings.Index(signature, valueStart) + len(valueStart)

		// The first character of the base64 becomes another, which leaves the length of the signature as it was.
		signature = signature[:i] + map[bool]string{true: "B", false: "A"}[signature[i] == 'A'] + signature[i+1:]
	case benchmarkSignatureReplayed:
	}

	budget := size - (len(signed) - (end - start) + len(signature))
	require.True(b, budget >= 0, "a request of %d bytes has no room for the signed request", size)

	attrs, before, after := shape.fill(budget)

	request := signed[:rootEnd] + attrs + signed[rootEnd:start] + before + signature + after + signed[end:]
	require.LessOrEqual(b, len(request), size)

	return []byte(request)
}

// benchmarkPost returns what makes an HTTP request of the HTTP-POST binding for the request.
func benchmarkPost(request []byte) func() *http.Request {
	body := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(request)}}.Encode()

	return func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, signatureTestSSOURL, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		return r
	}
}

// benchmarkRedirect returns what makes an HTTP request of the HTTP-Redirect binding for the request.
func benchmarkRedirect(b *testing.B, request []byte) func() *http.Request {
	b.Helper()

	var deflated bytes.Buffer

	w, err := flate.NewWriter(&deflated, flate.BestCompression)
	require.NoError(b, err)

	_, err = w.Write(request)
	require.NoError(b, err)
	require.NoError(b, w.Close())

	target := signatureTestSSOURL + "?" + url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(deflated.Bytes())}}.Encode()

	return func() *http.Request {
		return httptest.NewRequest(http.MethodGet, target, nil)
	}
}

// BenchmarkIdpAuthnRequestValidateUnauthenticated measures the work that the identity provider does for a request
// of an anonymous client before it refuses it: the request is decoded, checked by internal/xmlrv, parsed, and
// searched for a signature, which is then found not to be valid. The requests are filled up to each size with the
// content that was found to cost the most at each of those steps.
func BenchmarkIdpAuthnRequestValidateUnauthenticated(b *testing.B) {
	idp, sp := benchmarkIDP(b)

	for _, shape := range benchmarkShapes {
		for _, size := range benchmarkRequestSizes {
			b.Run(fmt.Sprintf("%s/%dKiB", shape.name, size>>10), func(b *testing.B) {
				request := benchmarkRequest(b, benchmarkSignedRequest(b, sp), shape, size)

				benchmarkValidate(b, idp, benchmarkPost(request), len(request), shape.refusal)
			})
		}
	}

	// The request that costs the most fits in a URL, as it deflates to a small part of its size.
	b.Run("namespaces and elements, replayed, redirect binding/16KiB", func(b *testing.B) {
		shape := benchmarkShapes[len(benchmarkShapes)-1]
		request := benchmarkRequest(b, benchmarkSignedRequest(b, sp), shape, maxAuthnRequestSize)

		benchmarkValidate(b, idp, benchmarkRedirect(b, request), len(request), shape.refusal)
	})
}

// BenchmarkIdpAuthnRequestValidate measures the same work for a request as the service provider makes it, which
// is accepted, to compare.
func BenchmarkIdpAuthnRequestValidate(b *testing.B) {
	idp, sp := benchmarkIDP(b)

	request := []byte(benchmarkSignedRequest(b, sp))

	benchmarkValidate(b, idp, benchmarkPost(request), len(request), "")
}

// benchmarkValidate reads and validates the HTTP request that newRequest returns. The request is refused with
// the refusal in the debug message of the error, or is accepted if refusal is empty.
func benchmarkValidate(b *testing.B, idp *IdentityProvider, newRequest func() *http.Request, size int, refusal string) {
	b.Helper()

	// Every request is validated at the same time, so that a long run doesn't outlive the IssueInstant of the
	// request, which is signed and so can't be made again, and see it refused as no longer current.
	now := TimeNow()

	validate := func() error {
		req, err := NewIdpAuthnRequest(idp, newRequest())
		if err != nil {
			return err
		}

		req.Now = now

		return req.Validate()
	}

	// A request that is refused sooner than it is meant to be would measure less than the benchmark is for.
	if err := validate(); refusal == "" {
		require.NoError(b, err)
	} else {
		require.Error(b, err)
		require.Contains(b, errorDebug(err), refusal)
	}

	b.ReportAllocs()
	b.SetBytes(int64(size))

	for b.Loop() {
		if err := validate(); (err == nil) != (refusal == "") {
			b.Fatal(err)
		}
	}
}
