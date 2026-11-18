package saml

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // The SourceID of an artifact is a SHA-1 hash.
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"html"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"

	"authelia.com/provider/saml/xmlenc"
)

const artifactTestURL = "https://idp.example.com/saml/artifact"

// artifactTestIDP is signatureTestIDP with an artifact resolution URL, a session for every request, random
// numbers that don't repeat, and a logger which keeps what the identity provider logs.
func artifactTestIDP(t *testing.T) (*IdentityProviderTest, *bytes.Buffer) {
	t.Helper()

	test := signatureTestIDP(t)
	useSession(test)

	previousRand, previousEncryptionRand := RandReader, xmlenc.RandReader

	t.Cleanup(func() { RandReader, xmlenc.RandReader = previousRand, previousEncryptionRand })

	RandReader, xmlenc.RandReader = rand.Reader, rand.Reader

	logs := &bytes.Buffer{}

	test.IDP.ArtifactResolutionURL = mustParseURL(artifactTestURL)
	test.IDP.Logger = log.New(logs, "", 0)
	test.SP.IDPMetadata = test.IDP.Metadata()

	return test, logs
}

// artifactSSO sends the signed AuthnRequest of sp, which asks for the HTTP-Artifact binding, to the identity
// provider, and returns the response and the ID of the request.
func artifactSSO(t *testing.T, test *IdentityProviderTest, sp *ServiceProvider, mutate func(*AuthnRequest)) (*httptest.ResponseRecorder, string) {
	t.Helper()

	body := signedPostBody(t, sp, func(request *AuthnRequest) {
		request.ProtocolBinding = HTTPArtifactBinding

		if mutate != nil {
			mutate(request)
		}
	})

	return serveSSO(test, replayPostRequest(body, url.Values{"RelayState": {"relay state&"}})), authnRequestID(t, body)
}

// redirectedArtifact returns the location that w redirects to, and the artifact in its query.
func redirectedArtifact(t *testing.T, w *httptest.ResponseRecorder) (*url.URL, string) {
	t.Helper()

	assert.Assert(t, is.Equal(w.Code, http.StatusFound), "body: %s", w.Body.String())
	assert.Check(t, is.Equal(w.Header().Get("Cache-Control"), "no-cache, no-store"))
	assert.Check(t, is.Equal(w.Header().Get("Pragma"), "no-cache"))

	location, err := url.Parse(w.Header().Get("Location"))
	assert.NilError(t, err)

	artifact := location.Query().Get("SAMLart")
	assert.Assert(t, artifact != "")

	return location, artifact
}

// postedArtifact returns the controls of the form in w, which posts an artifact, the default encoding.
func postedArtifact(t *testing.T, w *httptest.ResponseRecorder) url.Values {
	t.Helper()

	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())
	assert.Check(t, is.Equal(w.Header().Get("Location"), ""))
	assert.Check(t, is.Equal(w.Header().Get("Cache-Control"), "no-cache, no-store"))
	assert.Check(t, is.Equal(w.Header().Get("Pragma"), "no-cache"))

	body := w.Body.String()
	form := url.Values{}

	for _, name := range []string{"SAMLart", "RelayState"} {
		marker := `<input type="hidden" name="` + name + `" value="`

		start := strings.Index(body, marker)
		if start < 0 {
			continue
		}

		value, _, _ := strings.Cut(body[start+len(marker):], `"`)
		form.Set(name, html.UnescapeString(value))
	}

	assert.Assert(t, form.Get("SAMLart") != "", "body: %s", body)

	return form
}

// issueTestArtifact has the identity provider answer a request of sp by artifact, and returns the artifact and
// the ID of the request.
func issueTestArtifact(t *testing.T, test *IdentityProviderTest, sp *ServiceProvider) (string, string) {
	t.Helper()

	w, id := artifactSSO(t, test, sp, nil)

	if test.IDP.ArtifactRedirectEncoding {
		_, artifact := redirectedArtifact(t, w)

		return artifact, id
	}

	return postedArtifact(t, w).Get("SAMLart"), id
}

// artifactResolvePost returns a SOAP POST of the ArtifactResolve of sp for artifact, after mutate has changed it
// and signed if sp has a SignatureMethod, and its ID.
func artifactResolvePost(t *testing.T, sp *ServiceProvider, artifact string, mutate func(*ArtifactResolve)) (*http.Request, string) {
	t.Helper()

	unsigned := *sp
	unsigned.SignatureMethod = ""
	request, err := unsigned.MakeArtifactResolveRequest(artifact)
	assert.NilError(t, err)

	if mutate != nil {
		mutate(request)
	}

	if sp.SignatureMethod != "" {
		assert.NilError(t, sp.SignArtifactResolve(request))
	}

	return artifactSOAPPost(soapLogoutEnvelope(t, request.Element())), request.ID
}

func artifactSOAPPost(body []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPost, artifactTestURL, bytes.NewReader(body))
	r.Header.Set("Content-Type", "text/xml")

	return r
}

func serveArtifactResolution(test *IdentityProviderTest, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	test.IDP.ServeArtifactResolution(w, r)

	return w
}

// artifactResponse returns the ArtifactResponse in the SOAP envelope of w, whose signature it verifies, and the
// message in it, or nil.
func artifactResponse(t *testing.T, w *httptest.ResponseRecorder) (*ArtifactResponse, *etree.Element) {
	t.Helper()

	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())

	envelope := soapTestParseResponse(t, w)

	var body *etree.Element

	for _, child := range envelope.ChildElements() {
		if child.Tag == "Body" && child.NamespaceURI() == soapEnvelopeNS {
			body = child
		}
	}

	assert.Assert(t, body != nil)
	assert.Assert(t, is.Len(body.ChildElements(), 1))

	el := detachSOAPBodyChild(body.ChildElements()[0])
	assert.Assert(t, is.Equal(el.Tag, "ArtifactResponse"))

	// SAMLCore §3.2.2: Issuer, Signature, Extensions, Status, and then the message.
	names := make([]string, 0, 4)
	for _, child := range el.ChildElements() {
		names = append(names, child.Tag)
	}

	assert.Assert(t, len(names) >= 3)
	assert.Check(t, is.DeepEqual(names[:3], []string{"Issuer", "Signature", "Status"}))

	verified, err := verifyEnvelopedSignature(el, []*x509.Certificate{mustParseCertificate(golden.Get(t, "idp_cert.pem"))}, anySignaturePolicy)
	assert.NilError(t, err)

	response := &ArtifactResponse{}
	assert.NilError(t, unmarshalElement(verified, response))

	assert.Check(t, is.Equal(response.Version, "2.0"))
	assert.Assert(t, response.Issuer != nil)
	assert.Check(t, is.Equal(response.Issuer.Value, "https://idp.example.com/saml/metadata"))
	assert.Check(t, response.Status.StatusMessage == nil)
	assert.Check(t, is.Equal(verified.SelectAttrValue("Destination", ""), ""))

	var message *etree.Element

	// The content that the signature covers, which is without the signature.
	for _, child := range verified.ChildElements() {
		if child.Tag == "Issuer" || child.Tag == "Status" {
			continue
		}

		assert.Assert(t, message == nil, "more than one message")

		message = child
	}

	return response, message
}

// assertEmptyArtifactResponse checks that w is an empty response to the request with the ID: Success and no
// message (SAMLCore §3.5.3).
func assertEmptyArtifactResponse(t *testing.T, w *httptest.ResponseRecorder, id string) {
	t.Helper()

	response, message := artifactResponse(t, w)

	assert.Check(t, is.Equal(response.InResponseTo, id))
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	assert.Check(t, response.Status.StatusCode.StatusCode == nil)
	assert.Check(t, message == nil, "the response has a message")
}

// assertResolvedArtifactResponse checks that w is a Success response to the request with the ID, with a Response
// to the AuthnRequest with the ID inResponseTo.
func assertResolvedArtifactResponse(t *testing.T, w *httptest.ResponseRecorder, id, inResponseTo string) *etree.Element {
	t.Helper()

	response, message := artifactResponse(t, w)

	assert.Check(t, is.Equal(response.InResponseTo, id))
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	assert.Assert(t, message != nil, "the response has no message")
	assert.Check(t, is.Equal(message.Tag, "Response"))
	assert.Check(t, is.Equal(message.SelectAttrValue("InResponseTo", ""), inResponseTo))
	assert.Assert(t, response.Response != nil)
	assert.Check(t, is.Equal(response.Response.Status.StatusCode.Value, StatusSuccess))

	return message
}

func assertArtifactResponseStatus(t *testing.T, w *httptest.ResponseRecorder, id, top, second string) {
	t.Helper()

	response, message := artifactResponse(t, w)

	assert.Check(t, is.Equal(response.InResponseTo, id))
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, top))

	if second == "" {
		assert.Check(t, response.Status.StatusCode.StatusCode == nil)
	} else {
		assert.Assert(t, response.Status.StatusCode.StatusCode != nil)
		assert.Check(t, is.Equal(response.Status.StatusCode.StatusCode.Value, second))
	}

	assert.Check(t, message == nil, "the response has a message")
}

func TestArtifactString(t *testing.T) {
	artifact := Artifact{EndpointIndex: 0x0102, SourceID: ArtifactSourceID("https://idp.example.com/saml/metadata")}
	for i := range artifact.MessageHandle {
		artifact.MessageHandle[i] = byte(0xa0 + i)
	}

	// SAMLBind §3.6.4: the SourceID is the SHA-1 hash of the entity ID, not encoded.
	sourceID := sha1.Sum([]byte("https://idp.example.com/saml/metadata")) //nolint:gosec // As above.
	assert.Check(t, is.DeepEqual(artifact.SourceID, sourceID))

	buf, err := base64.StdEncoding.DecodeString(artifact.String())
	assert.NilError(t, err)

	// SAMLBind §3.6.4.2: TypeCode 0x0004, EndpointIndex, SourceID and MessageHandle of 20 bytes each.
	assert.Assert(t, is.Len(buf, 44))
	assert.Check(t, is.DeepEqual(buf[:4], []byte{0x00, 0x04, 0x01, 0x02}))
	assert.Check(t, is.DeepEqual(buf[4:24], sourceID[:]))
	assert.Check(t, is.DeepEqual(buf[24:], artifact.MessageHandle[:]))

	parsed, err := ParseArtifact(artifact.String())
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(parsed, artifact))
}

func TestParseArtifactRejects(t *testing.T) {
	valid := Artifact{SourceID: ArtifactSourceID("https://idp.example.com/saml/metadata")}.String()

	raw, err := base64.StdEncoding.DecodeString(valid)
	assert.NilError(t, err)

	retyped := func(first, second byte) string {
		buf := bytes.Clone(raw)
		buf[0], buf[1] = first, second

		return base64.StdEncoding.EncodeToString(buf)
	}

	for name, value := range map[string]string{
		"empty":             "",
		"not base64":        strings.Repeat("!", len(valid)),
		"short":             base64.StdEncoding.EncodeToString(raw[:43]),
		"long":              base64.StdEncoding.EncodeToString(append(bytes.Clone(raw), 0)),
		"SAML 1.1 type 1":   retyped(0x00, 0x01),
		"SAML 1.1 type 2":   retyped(0x00, 0x02),
		"type 0x0400":       retyped(0x04, 0x00),
		"url encoding":      base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 44)),
		"surrounding space": " " + valid[1:],
		"line break":        valid[:30] + "\n" + valid[31:],
		"unpadded":          strings.TrimRight(valid, "=") + "A",
		"noncanonical bits": valid[:len(valid)-2] + "B=",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseArtifact(value)
			assert.Check(t, err != nil, "%q was parsed", value)
		})
	}
}

func TestMemoryArtifactStore(t *testing.T) {
	advance := replayTestClock(t)
	ctx := context.Background()
	store := NewMemoryArtifactStore(2)

	entry, err := store.GetArtifact(ctx, "a")
	assert.NilError(t, err)
	assert.Check(t, entry == nil)

	message := []byte("<message/>")
	assert.NilError(t, store.SaveArtifact(ctx, "a", ArtifactEntry{ServiceProviderEntityID: "sp", Message: message, Expires: TimeNow().Add(time.Minute)}))

	// The store keeps its own copy, and gives out copies.
	message[0] = '!'

	entry, err = store.GetArtifact(ctx, "a")
	assert.NilError(t, err)
	assert.Assert(t, entry != nil)
	assert.Check(t, is.Equal(entry.ServiceProviderEntityID, "sp"))
	assert.Check(t, is.Equal(string(entry.Message), "<message/>"))
	assert.Check(t, entry.Expires.Equal(TimeNow().Add(time.Minute)))

	entry.Message[0] = '!'

	entry, err = store.GetArtifact(ctx, "a")
	assert.NilError(t, err)
	assert.Check(t, is.Equal(string(entry.Message), "<message/>"))

	// It never forgets a message that has not expired to make room for another.
	assert.NilError(t, store.SaveArtifact(ctx, "b", ArtifactEntry{Expires: TimeNow().Add(2 * time.Minute)}))
	assert.Check(t, errors.Is(store.SaveArtifact(ctx, "c", ArtifactEntry{Expires: TimeNow().Add(time.Minute)}), ErrArtifactStoreFull))
	assert.Check(t, is.Equal(store.Len(), 2))

	assert.NilError(t, store.DeleteArtifact(ctx, "b"))
	assert.NilError(t, store.DeleteArtifact(ctx, "b"))
	assert.NilError(t, store.SaveArtifact(ctx, "b", ArtifactEntry{Expires: TimeNow().Add(2 * time.Minute)}))

	// A message that has expired is not returned, and makes room.
	advance(time.Minute)

	entry, err = store.GetArtifact(ctx, "a")
	assert.NilError(t, err)
	assert.Check(t, entry == nil)

	advance(time.Minute)
	assert.NilError(t, store.SaveArtifact(ctx, "c", ArtifactEntry{Expires: TimeNow().Add(time.Minute)}))
	assert.Check(t, is.Equal(store.Len(), 1))

	assert.Check(t, is.Equal(NewMemoryArtifactStore(0).capacity, DefaultMemoryArtifactStoreCapacity))
}

func TestMemoryArtifactStoreConcurrentUse(t *testing.T) {
	store := NewMemoryArtifactStore(0)
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)

	var wg sync.WaitGroup

	for i := range 16 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			key := strconv.Itoa(i)

			for range 100 {
				assert.Check(t, store.SaveArtifact(ctx, key, ArtifactEntry{Message: []byte(key), Expires: expires}))

				entry, err := store.GetArtifact(ctx, key)
				assert.Check(t, err)
				assert.Check(t, entry != nil && string(entry.Message) == key)
				assert.Check(t, store.DeleteArtifact(ctx, key))

				store.Len()
			}
		}()
	}

	wg.Wait()
	assert.Check(t, is.Equal(store.Len(), 0))
}

func TestIdentityProviderDefaultArtifactStore(t *testing.T) {
	idp := &IdentityProvider{}

	store := idp.artifactStore()
	assert.Assert(t, store != nil)
	assert.Check(t, store == idp.artifactStore())

	// A copy made after first use shares the store, and go vet accepts the copy.
	clone := *idp
	assert.Check(t, clone.artifactStore() == store)

	custom := NewMemoryArtifactStore(1)
	idp.ArtifactStore = custom
	assert.Check(t, idp.artifactStore() == ArtifactStore(custom))

	assert.Check(t, is.Equal(idp.artifactLifetime(), DefaultArtifactLifetime))

	idp.ArtifactLifetime = 5 * time.Second
	assert.Check(t, is.Equal(idp.artifactLifetime(), 5*time.Second))
}

func TestMetadataArtifactResolutionService(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)

	// It is not listed unless it is served.
	assert.Check(t, is.Len(test.IDP.Metadata().IDPSSODescriptors[0].ArtifactResolutionServices, 0))

	test.IDP.ArtifactResolutionURL = mustParseURL(artifactTestURL)

	buf, err := xml.Marshal(test.IDP.Metadata())
	assert.NilError(t, err)

	// SAMLMeta §2.4.2: an indexed endpoint of the SSO descriptor, on the SOAP binding (SAMLProf §5.5).
	assert.Check(t, is.Contains(string(buf), `<ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://idp.example.com/saml/artifact" index="0"></ArtifactResolutionService>`))

	var parsed EntityDescriptor

	assert.NilError(t, xml.Unmarshal(buf, &parsed))
	assert.Check(t, is.DeepEqual(parsed.IDPSSODescriptors[0].ArtifactResolutionServices, []IndexedEndpoint{
		{Binding: SOAPBinding, Location: artifactTestURL, Index: 0},
	}))

	// Requests are not received by artifact, so the SSO service doesn't list the binding.
	for _, endpoint := range parsed.IDPSSODescriptors[0].SingleSignOnServices {
		assert.Check(t, endpoint.Binding != HTTPArtifactBinding)
	}

	// The service provider of this package finds it.
	test.SP.IDPMetadata = &parsed
	assert.Check(t, is.Equal(test.SP.GetArtifactBindingLocation(SOAPBinding), artifactTestURL))
}

func TestHandlerServesArtifactResolution(t *testing.T) {
	test, _ := artifactTestIDP(t)

	w := httptest.NewRecorder()
	test.IDP.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, artifactTestURL, nil))
	assert.Check(t, is.Equal(w.Code, http.StatusMethodNotAllowed))

	test.IDP.ArtifactResolutionURL = url.URL{}

	w = httptest.NewRecorder()
	test.IDP.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, artifactTestURL, nil))
	assert.Check(t, is.Equal(w.Code, http.StatusNotFound))

	// Nor does the handler itself answer when it is mounted without the URL.
	r, _ := artifactResolvePost(t, &test.SP, Artifact{}.String(), nil)
	assert.Check(t, is.Equal(serveArtifactResolution(test, r).Code, http.StatusNotFound))
}

// artifactACSMetadata returns the metadata of the service provider with these assertion consumer services.
func artifactACSMetadata(test *IdentityProviderTest, endpoints ...IndexedEndpoint) {
	sp := test.SP

	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			if serviceProviderID != sp.MetadataURL.String() {
				return nil, os.ErrNotExist
			}

			metadata := sp.Metadata()
			metadata.SPSSODescriptors[0].AssertionConsumerServices = endpoints

			return metadata, nil
		},
	}
}

func TestArtifactACSSelection(t *testing.T) {
	isDefault, notDefault := true, false

	const (
		post         = "https://sp.example.com/saml2/acs"
		artifact     = "https://sp.example.com/saml2/artifact"
		shared       = "https://sp.example.com/saml2/shared"
		insecure     = "http://sp.example.com/saml2/artifact"
		unregistered = "https://evil.example.com/saml2/acs"
	)

	both := []IndexedEndpoint{
		{Binding: HTTPPostBinding, Location: post, Index: 1},
		{Binding: HTTPArtifactBinding, Location: artifact, Index: 2},
		{Binding: HTTPArtifactBinding, Location: shared, Index: 3},
		{Binding: HTTPPostBinding, Location: shared, Index: 4},
	}

	type want struct {
		binding, location string
		// refused means that Validate fails without an endpoint, and unsupported that it fails with the
		// UnsupportedBinding status for the endpoint.
		refused, unsupported bool
	}

	for _, tc := range []struct {
		name      string
		endpoints []IndexedEndpoint
		mutate    func(*AuthnRequest)
		enabled   want
		disabled  want
	}{
		{
			name:      "ProtocolBinding and URL",
			endpoints: both,
			mutate: func(r *AuthnRequest) {
				r.ProtocolBinding, r.AssertionConsumerServiceURL = HTTPArtifactBinding, artifact
			},
			enabled:  want{binding: HTTPArtifactBinding, location: artifact},
			disabled: want{binding: HTTPPostBinding, location: post, unsupported: true},
		},
		{
			name:      "ProtocolBinding and a URL with both bindings",
			endpoints: both,
			mutate: func(r *AuthnRequest) {
				r.ProtocolBinding, r.AssertionConsumerServiceURL = HTTPArtifactBinding, shared
			},
			enabled:  want{binding: HTTPArtifactBinding, location: shared},
			disabled: want{binding: HTTPPostBinding, location: post, unsupported: true},
		},
		{
			name:      "ProtocolBinding HTTP-POST and a URL with both bindings",
			endpoints: both,
			mutate: func(r *AuthnRequest) {
				r.ProtocolBinding, r.AssertionConsumerServiceURL = HTTPPostBinding, shared
			},
			enabled:  want{binding: HTTPPostBinding, location: shared},
			disabled: want{binding: HTTPPostBinding, location: shared},
		},
		{
			name:      "ProtocolBinding HTTP-POST and the URL of an artifact endpoint",
			endpoints: both,
			mutate: func(r *AuthnRequest) {
				r.ProtocolBinding, r.AssertionConsumerServiceURL = HTTPPostBinding, artifact
			},
			enabled:  want{refused: true},
			disabled: want{refused: true},
		},
		{
			name:      "ProtocolBinding alone",
			endpoints: both,
			mutate: func(r *AuthnRequest) {
				r.ProtocolBinding, r.AssertionConsumerServiceURL = HTTPArtifactBinding, ""
			},
			enabled:  want{binding: HTTPArtifactBinding, location: artifact},
			disabled: want{binding: HTTPPostBinding, location: post, unsupported: true},
		},
		{
			name:      "ProtocolBinding and a URL that is not in the metadata",
			endpoints: both,
			mutate: func(r *AuthnRequest) {
				r.ProtocolBinding, r.AssertionConsumerServiceURL = HTTPArtifactBinding, unregistered
			},
			enabled:  want{refused: true},
			disabled: want{refused: true},
		},
		{
			name:      "index of an artifact endpoint",
			endpoints: both,
			mutate: func(r *AuthnRequest) {
				r.ProtocolBinding, r.AssertionConsumerServiceURL, r.AssertionConsumerServiceIndex = "", "", "2"
			},
			enabled:  want{binding: HTTPArtifactBinding, location: artifact},
			disabled: want{refused: true},
		},
		{
			name:      "URL of an artifact endpoint",
			endpoints: both,
			mutate: func(r *AuthnRequest) {
				r.ProtocolBinding, r.AssertionConsumerServiceURL = "", artifact
			},
			enabled:  want{binding: HTTPArtifactBinding, location: artifact},
			disabled: want{refused: true},
		},
		{
			name:      "URL with both bindings uses the first in the metadata",
			endpoints: both,
			mutate: func(r *AuthnRequest) {
				r.ProtocolBinding, r.AssertionConsumerServiceURL = "", shared
			},
			enabled:  want{binding: HTTPArtifactBinding, location: shared},
			disabled: want{binding: HTTPPostBinding, location: shared},
		},
		{
			name:      "no endpoint named and HTTP-POST first",
			endpoints: both,
			mutate: func(r *AuthnRequest) {
				r.ProtocolBinding, r.AssertionConsumerServiceURL = "", ""
			},
			enabled:  want{binding: HTTPPostBinding, location: post},
			disabled: want{binding: HTTPPostBinding, location: post},
		},
		{
			name: "no endpoint named and an artifact endpoint is the default",
			endpoints: []IndexedEndpoint{
				{Binding: HTTPPostBinding, Location: post, Index: 1, IsDefault: &notDefault},
				{Binding: HTTPArtifactBinding, Location: artifact, Index: 2, IsDefault: &isDefault},
			},
			mutate: func(r *AuthnRequest) {
				r.ProtocolBinding, r.AssertionConsumerServiceURL = "", ""
			},
			enabled:  want{binding: HTTPArtifactBinding, location: artifact},
			disabled: want{binding: HTTPPostBinding, location: post},
		},
		{
			name:      "only an artifact endpoint",
			endpoints: []IndexedEndpoint{{Binding: HTTPArtifactBinding, Location: artifact, Index: 1}},
			mutate: func(r *AuthnRequest) {
				r.ProtocolBinding, r.AssertionConsumerServiceURL = "", ""
			},
			enabled:  want{binding: HTTPArtifactBinding, location: artifact},
			disabled: want{refused: true},
		},
		{
			name: "an insecure artifact endpoint that is named",
			endpoints: []IndexedEndpoint{
				{Binding: HTTPPostBinding, Location: post, Index: 1},
				{Binding: HTTPArtifactBinding, Location: insecure, Index: 2},
			},
			mutate: func(r *AuthnRequest) {
				r.ProtocolBinding, r.AssertionConsumerServiceURL = HTTPArtifactBinding, insecure
			},
			enabled:  want{refused: true},
			disabled: want{binding: HTTPPostBinding, location: post, unsupported: true},
		},
		{
			name: "an insecure artifact endpoint that is the default",
			endpoints: []IndexedEndpoint{
				{Binding: HTTPArtifactBinding, Location: insecure, Index: 1, IsDefault: &isDefault},
				{Binding: HTTPArtifactBinding, Location: artifact, Index: 2},
			},
			mutate: func(r *AuthnRequest) {
				r.ProtocolBinding, r.AssertionConsumerServiceURL = HTTPArtifactBinding, ""
			},
			enabled:  want{binding: HTTPArtifactBinding, location: artifact},
			disabled: want{refused: true},
		},
	} {
		for _, enabled := range []bool{true, false} {
			name, expected := tc.name+"/enabled", tc.enabled
			if !enabled {
				name, expected = tc.name+"/disabled", tc.disabled
			}

			t.Run(name, func(t *testing.T) {
				test, _ := artifactTestIDP(t)
				artifactACSMetadata(test, tc.endpoints...)

				if !enabled {
					test.IDP.ArtifactResolutionURL = url.URL{}
				}

				body := signedPostBody(t, &test.SP, tc.mutate)

				req, err := NewIdpAuthnRequest(&test.IDP, replayPostRequest(body, nil))
				assert.NilError(t, err)

				err = req.Validate()

				switch {
				case expected.refused:
					assert.Assert(t, err != nil)
					assert.Check(t, req.ACSEndpoint == nil)

					_, ok := RequestStatus(err)
					assert.Check(t, !ok, "a request with no endpoint can't be answered with a status")

					return
				case expected.unsupported:
					status, ok := RequestStatus(err)
					assert.Assert(t, ok, "error: %v", err)
					assert.Check(t, is.Equal(status.StatusCode.Value, StatusResponder))
					assert.Check(t, is.Equal(status.StatusCode.StatusCode.Value, StatusUnsupportedBinding))
				default:
					assert.NilError(t, err)
				}

				assert.Assert(t, req.ACSEndpoint != nil)
				assert.Check(t, is.Equal(req.ACSEndpoint.Binding, expected.binding))
				assert.Check(t, is.Equal(req.ACSEndpoint.Location, expected.location))
			})
		}
	}
}

func TestServeSSODeliversResponseByArtifactRedirect(t *testing.T) {
	test, _ := artifactTestIDP(t)
	test.IDP.ArtifactRedirectEncoding = true
	artifactACSMetadata(test,
		IndexedEndpoint{Binding: HTTPPostBinding, Location: "https://sp.example.com/saml2/acs", Index: 1},
		IndexedEndpoint{Binding: HTTPArtifactBinding, Location: "https://sp.example.com/saml2/acs?via=artifact", Index: 2},
	)

	store := NewMemoryArtifactStore(0)
	test.IDP.ArtifactStore = store

	w, id := artifactSSO(t, test, &test.SP, func(request *AuthnRequest) {
		request.AssertionConsumerServiceURL = "https://sp.example.com/saml2/acs?via=artifact"
	})

	location, value := redirectedArtifact(t, w)

	// SAMLBind §3.6.3.2: the artifact and the RelayState are added to the query of the endpoint, and nothing of
	// the response is.
	assert.Check(t, is.Equal(location.Scheme+"://"+location.Host+location.Path, "https://sp.example.com/saml2/acs"))
	assert.Check(t, is.DeepEqual(location.Query(), url.Values{
		"via":        {"artifact"},
		"SAMLart":    {value},
		"RelayState": {"relay state&"},
	}))
	assert.Check(t, !strings.Contains(w.Body.String(), "SAMLResponse"))

	artifact, err := ParseArtifact(value)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(artifact.EndpointIndex, uint16(0)))
	assert.Check(t, is.DeepEqual(artifact.SourceID, ArtifactSourceID("https://idp.example.com/saml/metadata")))

	// The response waits in the store for the service provider it is for, under a key that is not the artifact.
	assert.Check(t, is.Equal(store.Len(), 1))

	key := test.IDP.artifactKey(artifact)
	assert.Check(t, strings.HasPrefix(key, "artifact:"))
	assert.Check(t, is.Len(key, len("artifact:")+64))

	entry, err := store.GetArtifact(context.Background(), key)
	assert.NilError(t, err)
	assert.Assert(t, entry != nil)
	assert.Check(t, is.Equal(entry.ServiceProviderEntityID, "https://sp.example.com/saml2/metadata"))
	assert.Check(t, entry.Expires.Equal(TimeNow().Add(DefaultArtifactLifetime)))

	var response Response

	assert.NilError(t, xml.Unmarshal(entry.Message, &response))
	assert.Check(t, is.Equal(response.InResponseTo, id))
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	assert.Check(t, is.Equal(response.Destination, "https://sp.example.com/saml2/acs?via=artifact"))
	assert.Check(t, response.Signature != nil)
	assert.Check(t, response.Assertion != nil || response.EncryptedAssertion != nil)

	for name, values := range store.entries {
		assert.Check(t, !strings.Contains(name, value))
		assert.Check(t, !bytes.Contains(values.Message, []byte(value)))
	}
}

func TestServeSSOArtifactsAreUnique(t *testing.T) {
	test, _ := artifactTestIDP(t)

	seen := map[string]bool{}

	for range 8 {
		artifact, _ := issueTestArtifact(t, test, &test.SP)
		assert.Check(t, !seen[artifact])

		seen[artifact] = true
	}
}

func TestServeSSODeliversResponseByArtifactForm(t *testing.T) {
	test, _ := artifactTestIDP(t)
	test.IDP.ArtifactLifetime = 10 * time.Second

	store := NewMemoryArtifactStore(0)
	test.IDP.ArtifactStore = store

	w, _ := artifactSSO(t, test, &test.SP, nil)

	assert.Assert(t, is.Equal(w.Code, http.StatusOK))
	assert.Check(t, is.Equal(w.Header().Get("Cache-Control"), "no-cache, no-store"))
	assert.Check(t, is.Equal(w.Header().Get("Pragma"), "no-cache"))

	// SAMLBind §3.6.3.3: a form posted to the endpoint, with the artifact and the RelayState in hidden controls,
	// escaped. It is the default, as it keeps the artifact out of the URL: nothing is redirected.
	assert.Check(t, is.Equal(w.Header().Get("Location"), ""))

	body := w.Body.String()
	assert.Check(t, is.Contains(body, `<form method="post" action="https://sp.example.com/saml2/acs"`))
	assert.Check(t, is.Contains(body, `<input type="hidden" name="RelayState" value="relay state&amp;" />`))
	assert.Check(t, !strings.Contains(body, "SAMLResponse"))

	const marker = `<input type="hidden" name="SAMLart" value="`

	start := strings.Index(body, marker)
	assert.Assert(t, start >= 0)

	value, _, _ := strings.Cut(body[start+len(marker):], `"`)

	artifact, err := ParseArtifact(html.UnescapeString(value))
	assert.NilError(t, err)

	entry, err := store.GetArtifact(context.Background(), test.IDP.artifactKey(artifact))
	assert.NilError(t, err)
	assert.Assert(t, entry != nil)
	assert.Check(t, entry.Expires.Equal(TimeNow().Add(10*time.Second)))
}

func TestServeSSODeliversErrorResponseByArtifact(t *testing.T) {
	test, _ := artifactTestIDP(t)
	test.IDP.AssertionMaker = assertionMakerFunc(func(*IdpAuthnRequest, *Session) error { return errors.New("boom") })

	artifact, id := issueTestArtifact(t, test, &test.SP)

	r, resolveID := artifactResolvePost(t, &test.SP, artifact, nil)

	response, message := artifactResponse(t, serveArtifactResolution(test, r))
	assert.Check(t, is.Equal(response.InResponseTo, resolveID))
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	assert.Assert(t, message != nil)
	assert.Assert(t, response.Response != nil)
	assert.Check(t, is.Equal(response.Response.InResponseTo, id))
	assert.Check(t, is.Equal(response.Response.Status.StatusCode.Value, StatusResponder))
	assert.Check(t, response.Response.Assertion == nil && response.Response.EncryptedAssertion == nil)
}

// failingArtifactStore is an ArtifactStore whose operations fail with the errors that are set, and otherwise
// those of a MemoryArtifactStore.
type failingArtifactStore struct {
	*MemoryArtifactStore
	saveErr, getErr, deleteErr error
	deleted                    []string
}

func (s *failingArtifactStore) SaveArtifact(ctx context.Context, key string, entry ArtifactEntry) error {
	if s.saveErr != nil {
		return s.saveErr
	}

	return s.MemoryArtifactStore.SaveArtifact(ctx, key, entry)
}

func (s *failingArtifactStore) GetArtifact(ctx context.Context, key string) (*ArtifactEntry, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}

	return s.MemoryArtifactStore.GetArtifact(ctx, key)
}

func (s *failingArtifactStore) DeleteArtifact(ctx context.Context, key string) error {
	s.deleted = append(s.deleted, key)

	if s.deleteErr != nil {
		return s.deleteErr
	}

	return s.MemoryArtifactStore.DeleteArtifact(ctx, key)
}

func TestServeSSOArtifactStoreFailure(t *testing.T) {
	test, logs := artifactTestIDP(t)
	test.IDP.ArtifactStore = &failingArtifactStore{MemoryArtifactStore: NewMemoryArtifactStore(0), saveErr: errors.New("store down")}

	// The error response can't be delivered by artifact either, so nothing is sent to the service provider.
	w, _ := artifactSSO(t, test, &test.SP, nil)
	assert.Check(t, is.Equal(w.Code, http.StatusInternalServerError))
	assert.Check(t, is.Equal(w.Header().Get("Location"), ""))
	assert.Check(t, !strings.Contains(w.Body.String(), "store down"))
	assert.Check(t, is.Contains(logs.String(), "store down"))
}

func TestWriteResponseDeletesArtifactThatIsNotSent(t *testing.T) {
	f := newPropagationFixture(t)
	f.test.IDP.ArtifactResolutionURL = mustParseURL(artifactTestURL)
	f.test.IDP.Logger = log.New(io.Discard, "", 0)

	store := &failingArtifactStore{MemoryArtifactStore: NewMemoryArtifactStore(0)}
	f.test.IDP.ArtifactStore = store
	f.provider.closed = map[string]bool{f.session.ID: true}

	body := signedPostBody(t, f.a, func(request *AuthnRequest) { request.ProtocolBinding = HTTPArtifactBinding })

	req, err := NewIdpAuthnRequest(&f.test.IDP, replayPostRequest(body, nil))
	assert.NilError(t, err)
	assert.NilError(t, req.Validate())

	req.Session = f.session
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, f.session))

	w := httptest.NewRecorder()

	// The participant can't be recorded, as when a logout of the session has begun, so no artifact is sent,
	// and the response it stands for doesn't stay behind.
	err = req.WriteResponse(w)
	assert.Check(t, errors.Is(err, ErrResponseNotBuilt))
	assert.Check(t, errors.Is(err, ErrSessionParticipantsClosed))
	assert.Check(t, is.Equal(w.Header().Get("Location"), ""))
	assert.Check(t, !strings.Contains(w.Body.String(), "SAMLart"))
	assert.Check(t, is.Len(store.deleted, 1))
	assert.Check(t, is.Equal(store.Len(), 0))
}

func TestPostBindingRefusesArtifactEndpoint(t *testing.T) {
	test, _ := artifactTestIDP(t)

	body := signedPostBody(t, &test.SP, func(request *AuthnRequest) { request.ProtocolBinding = HTTPArtifactBinding })

	req, err := NewIdpAuthnRequest(&test.IDP, replayPostRequest(body, nil))
	assert.NilError(t, err)
	assert.NilError(t, req.Validate())
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00f00", UserName: "alice", NameID: "alice"}))

	_, err = req.PostBinding()
	assert.Check(t, is.ErrorContains(err, "unsupported binding"))

	// And the artifact binding refuses any other endpoint, or to work without a resolution service.
	delivery, err := req.ArtifactBinding()
	assert.NilError(t, err)
	assert.Check(t, is.Equal(delivery.URL, "https://sp.example.com/saml2/acs"))

	test.IDP.ArtifactResolutionURL = url.URL{}
	_, err = req.ArtifactBinding()
	assert.Check(t, err != nil)

	test.IDP.ArtifactResolutionURL = mustParseURL(artifactTestURL)
	req.ACSEndpoint = &IndexedEndpoint{Binding: HTTPPostBinding, Location: "https://sp.example.com/saml2/acs"}
	_, err = req.ArtifactBinding()
	assert.Check(t, err != nil)

	req.ACSEndpoint = &IndexedEndpoint{Binding: HTTPArtifactBinding, Location: "http://sp.example.com/saml2/acs"}
	_, err = req.ArtifactBinding()
	assert.Check(t, errors.Is(err, ErrInsecureEndpoint))
}

func TestServeIDPInitiatedDeliversResponseByArtifact(t *testing.T) {
	test, _ := artifactTestIDP(t)
	artifactACSMetadata(test, IndexedEndpoint{Binding: HTTPArtifactBinding, Location: "https://sp.example.com/saml2/acs", Index: 1})

	w := httptest.NewRecorder()
	test.IDP.ServeIDPInitiated(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/services/sp", nil),
		test.SP.MetadataURL.String(), "ThisIsTheRelayState")

	form := postedArtifact(t, w)
	assert.Check(t, is.Equal(form.Get("RelayState"), "ThisIsTheRelayState"))

	r, id := artifactResolvePost(t, &test.SP, form.Get("SAMLart"), nil)
	assertResolvedArtifactResponse(t, serveArtifactResolution(test, r), id, "")
}

func TestServeArtifactResolution(t *testing.T) {
	test, logs := artifactTestIDP(t)

	artifact, authnRequestID := issueTestArtifact(t, test, &test.SP)

	r, id := artifactResolvePost(t, &test.SP, artifact, nil)
	message := assertResolvedArtifactResponse(t, serveArtifactResolution(test, r), id, authnRequestID)

	// The message is the signed Response that the POST binding would have delivered, unchanged.
	_, err := verifyEnvelopedSignature(message, []*x509.Certificate{mustParseCertificate(golden.Get(t, "idp_cert.pem"))}, anySignaturePolicy)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(message.SelectAttrValue("Destination", ""), "https://sp.example.com/saml2/acs"))

	// It is deleted once it is resolved.
	assert.Check(t, is.Equal(test.IDP.artifactStore().(*MemoryArtifactStore).Len(), 0))
	assert.Check(t, is.Equal(logs.String(), ""))
}

func TestServeArtifactResolutionAcceptsDestination(t *testing.T) {
	test, _ := artifactTestIDP(t)

	artifact, authnRequestID := issueTestArtifact(t, test, &test.SP)

	r, id := artifactResolvePost(t, &test.SP, artifact, func(request *ArtifactResolve) { request.Destination = artifactTestURL })
	assertResolvedArtifactResponse(t, serveArtifactResolution(test, r), id, authnRequestID)
}

func TestServeArtifactResolutionResolvesOnce(t *testing.T) {
	test, logs := artifactTestIDP(t)

	artifact, authnRequestID := issueTestArtifact(t, test, &test.SP)

	r, id := artifactResolvePost(t, &test.SP, artifact, nil)
	assertResolvedArtifactResponse(t, serveArtifactResolution(test, r), id, authnRequestID)

	// SAMLCore §3.5.3: any later request with the same artifact, by any requester, gets an empty response.
	b := soapLogoutServiceProviderB(t, test)

	for _, sp := range []*ServiceProvider{&test.SP, b, &test.SP} {
		r, id = artifactResolvePost(t, sp, artifact, nil)
		assertEmptyArtifactResponse(t, serveArtifactResolution(test, r), id)
	}

	assert.Check(t, is.Contains(logs.String(), "artifact not resolved: https://sp.example.com/saml2/metadata sent an artifact that is unknown, expired or already resolved"))
}

func TestServeArtifactResolutionSingleUseSurvivesTheMessageStore(t *testing.T) {
	test, _ := artifactTestIDP(t)

	// A store that fails to delete, as a shared one might: the ReplayStore still makes the artifact single use.
	store := &failingArtifactStore{MemoryArtifactStore: NewMemoryArtifactStore(0), deleteErr: errors.New("store down")}
	test.IDP.ArtifactStore = store

	replay := newRecordingReplayStore()
	test.IDP.ReplayStore = replay

	artifact, authnRequestID := issueTestArtifact(t, test, &test.SP)
	before := replay.calls()

	r, id := artifactResolvePost(t, &test.SP, artifact, nil)
	assertResolvedArtifactResponse(t, serveArtifactResolution(test, r), id, authnRequestID)
	assert.Check(t, is.Equal(store.Len(), 1))

	// The artifact is recorded under the key of its message, until it expires and the clocks may differ.
	parsed, err := ParseArtifact(artifact)
	assert.NilError(t, err)
	assert.Assert(t, is.Equal(replay.calls(), before+1))
	assert.Check(t, is.Equal(replay.keys[before], test.IDP.artifactKey(parsed)))
	assert.Check(t, replay.expiries[before].Equal(TimeNow().Add(DefaultArtifactLifetime+MaxClockSkew)))

	// Another instance, which shares both stores.
	other := test.IDP

	r, id = artifactResolvePost(t, &test.SP, artifact, nil)
	w := httptest.NewRecorder()
	other.ServeArtifactResolution(w, r)
	assertEmptyArtifactResponse(t, w, id)
}

func TestServeArtifactResolutionConcurrentResolvesGiveOneMessage(t *testing.T) {
	test, _ := artifactTestIDP(t)

	artifact, _ := issueTestArtifact(t, test, &test.SP)

	const workers = 16

	requests := make([]*http.Request, workers)
	recorders := make([]*httptest.ResponseRecorder, workers)

	for i := range requests {
		requests[i], _ = artifactResolvePost(t, &test.SP, artifact, nil)
	}

	var wg sync.WaitGroup

	for i := range requests {
		wg.Add(1)

		go func() {
			defer wg.Done()

			recorders[i] = serveArtifactResolution(test, requests[i])
		}()
	}

	wg.Wait()

	resolved := 0

	for _, w := range recorders {
		response, message := artifactResponse(t, w)
		assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))

		if message != nil {
			resolved++
		}
	}

	assert.Check(t, is.Equal(resolved, 1))
}

func TestServeArtifactResolutionRefusesAnotherServiceProvider(t *testing.T) {
	test, logs := artifactTestIDP(t)
	b := soapLogoutServiceProviderB(t, test)

	artifact, _ := issueTestArtifact(t, test, &test.SP)

	// SAMLProf §4.1.4.4, SAMLSec §6.5.3: B is registered and its signature is valid, but the response was not
	// issued to it.
	r, id := artifactResolvePost(t, b, artifact, nil)
	assertEmptyArtifactResponse(t, serveArtifactResolution(test, r), id)
	assert.Check(t, is.Contains(logs.String(),
		"https://sp-b.example.com/saml2/metadata sent an artifact that was issued for https://sp.example.com/saml2/metadata"))

	// An artifact that another party holds is no longer safe to resolve for anyone.
	r, id = artifactResolvePost(t, &test.SP, artifact, nil)
	assertEmptyArtifactResponse(t, serveArtifactResolution(test, r), id)
	assert.Check(t, is.Equal(test.IDP.artifactStore().(*MemoryArtifactStore).Len(), 0))

	// B resolves the artifacts of its own responses.
	artifact, authnRequestID := issueTestArtifact(t, test, b)
	r, id = artifactResolvePost(t, b, artifact, nil)
	assertResolvedArtifactResponse(t, serveArtifactResolution(test, r), id, authnRequestID)
}

func TestServeArtifactResolutionExpiredArtifact(t *testing.T) {
	for name, tc := range map[string]struct {
		store func() ArtifactStore
	}{
		"store forgets": {store: func() ArtifactStore { return NewMemoryArtifactStore(0) }},
		// A store may return an entry that has expired: the identity provider checks.
		"store keeps": {store: func() ArtifactStore { return &keepingArtifactStore{entries: map[string]ArtifactEntry{}} }},
	} {
		t.Run(name, func(t *testing.T) {
			test, _ := artifactTestIDP(t)
			test.IDP.ArtifactStore = tc.store()

			advance := replayTestClock(t)

			first, authnRequestID := issueTestArtifact(t, test, &test.SP)
			second, _ := issueTestArtifact(t, test, &test.SP)

			advance(DefaultArtifactLifetime - time.Second)

			r, id := artifactResolvePost(t, &test.SP, first, nil)
			assertResolvedArtifactResponse(t, serveArtifactResolution(test, r), id, authnRequestID)

			advance(time.Second)

			r, id = artifactResolvePost(t, &test.SP, second, nil)
			assertEmptyArtifactResponse(t, serveArtifactResolution(test, r), id)
		})
	}
}

// keepingArtifactStore is an ArtifactStore which never forgets an entry by itself.
type keepingArtifactStore struct {
	mu      sync.Mutex
	entries map[string]ArtifactEntry
}

func (s *keepingArtifactStore) SaveArtifact(_ context.Context, key string, entry ArtifactEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[key] = entry

	return nil
}

func (s *keepingArtifactStore) GetArtifact(_ context.Context, key string) (*ArtifactEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, ok := s.entries[key]; ok {
		return &entry, nil
	}

	return nil, nil
}

func (s *keepingArtifactStore) DeleteArtifact(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, key)

	return nil
}

func TestServeArtifactResolutionEmptyResponses(t *testing.T) {
	type fixture struct {
		test     *IdentityProviderTest
		artifact string
	}

	otherIssuer := Artifact{SourceID: ArtifactSourceID("https://other-idp.example.com/metadata")}
	unknown := Artifact{SourceID: ArtifactSourceID("https://idp.example.com/saml/metadata"), MessageHandle: [20]byte{1, 2, 3}}

	for name, tc := range map[string]struct {
		// request returns the request to send for the artifact that was issued.
		request func(t *testing.T, f *fixture) (*http.Request, string)
		// usable reports whether the artifact can still be resolved afterwards.
		usable bool
		logged string
	}{
		"unknown artifact": {
			request: func(t *testing.T, f *fixture) (*http.Request, string) {
				return artifactResolvePost(t, &f.test.SP, unknown.String(), nil)
			},
			usable: true,
			logged: "unknown, expired or already resolved",
		},
		"artifact of another issuer": {
			request: func(t *testing.T, f *fixture) (*http.Request, string) {
				return artifactResolvePost(t, &f.test.SP, otherIssuer.String(), nil)
			},
			usable: true,
			logged: "this identity provider did not issue",
		},
		"artifact with another endpoint index": {
			request: func(t *testing.T, f *fixture) (*http.Request, string) {
				artifact, err := ParseArtifact(f.artifact)
				assert.NilError(t, err)

				artifact.EndpointIndex = 1

				return artifactResolvePost(t, &f.test.SP, artifact.String(), nil)
			},
			usable: true,
			logged: "this identity provider did not issue",
		},
		"malformed artifact": {
			request: func(t *testing.T, f *fixture) (*http.Request, string) {
				return artifactResolvePost(t, &f.test.SP, "AAQAAA==", nil)
			},
			usable: true,
			logged: "malformed artifact",
		},
		"no artifact": {
			request: func(t *testing.T, f *fixture) (*http.Request, string) {
				return artifactResolvePost(t, &f.test.SP, "", nil)
			},
			usable: true,
			logged: "malformed artifact",
		},
		// SAMLBind §3.6.5.2 and SAMLCore §3.5.3: the requester must authenticate itself as the recipient.
		"unsigned": {
			request: func(t *testing.T, f *fixture) (*http.Request, string) {
				unsigned := f.test.SP
				unsigned.SignatureMethod = ""

				return artifactResolvePost(t, &unsigned, f.artifact, nil)
			},
			usable: true,
			logged: "the requester is not authenticated: the message is not signed",
		},
		"signed with another key": {
			request: func(t *testing.T, f *fixture) (*http.Request, string) {
				forger := f.test.SP
				forger.Key, forger.Certificate = propagationServiceProviderKey(t)

				return artifactResolvePost(t, &forger, f.artifact, nil)
			},
			usable: true,
			logged: "the requester is not authenticated: invalid message signature",
		},
		"changed after it was signed": {
			request: func(t *testing.T, f *fixture) (*http.Request, string) {
				request, err := f.test.SP.MakeArtifactResolveRequest(unknown.String())
				assert.NilError(t, err)

				el := request.Element()
				el.FindElement("./Artifact").SetText(f.artifact)

				return artifactSOAPPost(soapLogoutEnvelope(t, el)), request.ID
			},
			usable: true,
			logged: "the requester is not authenticated: invalid message signature",
		},
		"unknown issuer": {
			request: func(t *testing.T, f *fixture) (*http.Request, string) {
				stranger := f.test.SP
				stranger.MetadataURL = mustParseURL("https://stranger.example.com/metadata")

				return artifactResolvePost(t, &stranger, f.artifact, nil)
			},
			usable: true,
			logged: "the requester is not authenticated: the service provider is unknown",
		},
		"expired request": {
			request: func(t *testing.T, f *fixture) (*http.Request, string) {
				return artifactResolvePost(t, &f.test.SP, f.artifact, func(request *ArtifactResolve) {
					request.IssueInstant = TimeNow().Add(-MaxIssueDelay - MaxClockSkew)
				})
			},
			usable: true,
			logged: "expired at",
		},
		"request from the future": {
			request: func(t *testing.T, f *fixture) (*http.Request, string) {
				return artifactResolvePost(t, &f.test.SP, f.artifact, func(request *ArtifactResolve) {
					request.IssueInstant = TimeNow().Add(MaxClockSkew + time.Second)
				})
			},
			usable: true,
			logged: "issued in the future",
		},
		"another destination": {
			request: func(t *testing.T, f *fixture) (*http.Request, string) {
				return artifactResolvePost(t, &f.test.SP, f.artifact, func(request *ArtifactResolve) {
					request.Destination = "https://idp.example.com/saml/slo/soap"
				})
			},
			usable: true,
			logged: "has the destination",
		},
	} {
		t.Run(name, func(t *testing.T) {
			test, logs := artifactTestIDP(t)

			replay := newRecordingReplayStore()
			test.IDP.ReplayStore = replay

			artifact, authnRequestID := issueTestArtifact(t, test, &test.SP)
			recorded := replay.calls()

			r, id := tc.request(t, &fixture{test: test, artifact: artifact})

			// SAMLBind §3.6.6: a Success status, even though the message is not returned.
			assertEmptyArtifactResponse(t, serveArtifactResolution(test, r), id)
			assert.Check(t, is.Contains(logs.String(), tc.logged))

			// Nothing is recorded for a request that is refused, so only the holder of a real artifact that
			// is authenticated can add to the replay store.
			assert.Check(t, is.Equal(replay.calls(), recorded))

			r, id = artifactResolvePost(t, &test.SP, artifact, nil)

			if tc.usable {
				assertResolvedArtifactResponse(t, serveArtifactResolution(test, r), id, authnRequestID)
			} else {
				assertEmptyArtifactResponse(t, serveArtifactResolution(test, r), id)
			}
		})
	}
}

func TestServeArtifactResolutionErrorStatuses(t *testing.T) {
	t.Run("not an ArtifactResolve", func(t *testing.T) {
		test, _ := artifactTestIDP(t)

		el, id := soapLogoutRequestElement(t, &test.SP, nil)

		w := serveArtifactResolution(test, artifactSOAPPost(soapLogoutEnvelope(t, el)))
		assertArtifactResponseStatus(t, w, id, StatusRequester, StatusRequestUnsupported)
	})

	for _, tc := range []struct {
		version, second string
	}{
		{"3.0", StatusRequestVersionTooHigh},
		{"1.1", StatusRequestVersionTooLow},
		{"2.1", ""},
	} {
		t.Run("version "+tc.version, func(t *testing.T) {
			test, _ := artifactTestIDP(t)
			artifact, authnRequestID := issueTestArtifact(t, test, &test.SP)

			r, id := artifactResolvePost(t, &test.SP, artifact, func(request *ArtifactResolve) { request.Version = tc.version })
			assertArtifactResponseStatus(t, serveArtifactResolution(test, r), id, StatusVersionMismatch, tc.second)

			r, id = artifactResolvePost(t, &test.SP, artifact, nil)
			assertResolvedArtifactResponse(t, serveArtifactResolution(test, r), id, authnRequestID)
		})
	}

	t.Run("no issuer", func(t *testing.T) {
		test, logs := artifactTestIDP(t)
		artifact, _ := issueTestArtifact(t, test, &test.SP)

		r, id := artifactResolvePost(t, &test.SP, artifact, func(request *ArtifactResolve) { request.Issuer = nil })
		assertArtifactResponseStatus(t, serveArtifactResolution(test, r), id, StatusRequester, "")

		// Nothing of the request is logged before its sender is verified.
		assert.Check(t, !strings.Contains(logs.String(), id))
		assert.Check(t, !strings.Contains(logs.String(), artifact))
	})

	t.Run("invalid ID", func(t *testing.T) {
		test, logs := artifactTestIDP(t)
		artifact, _ := issueTestArtifact(t, test, &test.SP)

		r, _ := artifactResolvePost(t, &test.SP, artifact, func(request *ArtifactResolve) { request.ID = "an id" })

		// The ID can't be echoed.
		assertArtifactResponseStatus(t, serveArtifactResolution(test, r), "", StatusRequester, "")
		assert.Check(t, !strings.Contains(logs.String(), "an id"))
	})

	t.Run("too large", func(t *testing.T) {
		test, _ := artifactTestIDP(t)

		r, id := artifactResolvePost(t, &test.SP, strings.Repeat("A", maxAuthnRequestSize), nil)
		assertArtifactResponseStatus(t, serveArtifactResolution(test, r), id, StatusRequester, "")
	})

	t.Run("service provider lookup fails", func(t *testing.T) {
		test, logs := artifactTestIDP(t)
		artifact, _ := issueTestArtifact(t, test, &test.SP)

		test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
			GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) {
				return nil, errors.New("database down")
			},
		}

		r, id := artifactResolvePost(t, &test.SP, artifact, nil)
		w := serveArtifactResolution(test, r)
		assertArtifactResponseStatus(t, w, id, StatusResponder, "")

		// SAMLCore §3.2.2.4 lets a status carry a message, but an internal error is never put in one.
		assert.Check(t, !strings.Contains(w.Body.String(), "database down"))
		assert.Check(t, is.Contains(logs.String(), "database down"))
	})

	t.Run("artifact store fails", func(t *testing.T) {
		test, _ := artifactTestIDP(t)

		store := &failingArtifactStore{MemoryArtifactStore: NewMemoryArtifactStore(0)}
		test.IDP.ArtifactStore = store

		artifact, authnRequestID := issueTestArtifact(t, test, &test.SP)

		store.getErr = errors.New("store down")

		r, id := artifactResolvePost(t, &test.SP, artifact, nil)
		w := serveArtifactResolution(test, r)
		assertArtifactResponseStatus(t, w, id, StatusResponder, "")
		assert.Check(t, !strings.Contains(w.Body.String(), "store down"))

		// The artifact was not used up.
		store.getErr = nil

		r, id = artifactResolvePost(t, &test.SP, artifact, nil)
		assertResolvedArtifactResponse(t, serveArtifactResolution(test, r), id, authnRequestID)
	})

	t.Run("replay store fails", func(t *testing.T) {
		test, _ := artifactTestIDP(t)

		replay := newRecordingReplayStore()
		test.IDP.ReplayStore = replay

		artifact, _ := issueTestArtifact(t, test, &test.SP)

		replay.err = errors.New("replay store down")

		// Without the store the artifact can't be known to be unused, so the message is not given out.
		r, id := artifactResolvePost(t, &test.SP, artifact, nil)
		w := serveArtifactResolution(test, r)
		assertArtifactResponseStatus(t, w, id, StatusResponder, "")
		assert.Check(t, !strings.Contains(w.Body.String(), "replay store down"))
	})

	t.Run("stored message is not XML", func(t *testing.T) {
		test, _ := artifactTestIDP(t)

		artifact := Artifact{SourceID: ArtifactSourceID(test.IDP.MetadataURL.String()), MessageHandle: [20]byte{9}}

		assert.NilError(t, test.IDP.artifactStore().SaveArtifact(context.Background(), test.IDP.artifactKey(artifact), ArtifactEntry{
			ServiceProviderEntityID: test.SP.MetadataURL.String(),
			Message:                 []byte("not xml <"),
			Expires:                 TimeNow().Add(time.Minute),
		}))

		r, id := artifactResolvePost(t, &test.SP, artifact.String(), nil)
		assertArtifactResponseStatus(t, serveArtifactResolution(test, r), id, StatusResponder, "")
	})
}

func TestServeArtifactResolutionFaults(t *testing.T) {
	test, _ := artifactTestIDP(t)

	// SAMLBind §3.2.3.3: a problem with the SOAP message itself is a fault.
	r := artifactSOAPPost([]byte("<not-soap/>"))
	w := serveArtifactResolution(test, r)
	assert.Check(t, is.Equal(soapFaultCode(t, w), "soapenv:Client"))

	r, _ = artifactResolvePost(t, &test.SP, Artifact{}.String(), nil)
	r.Header.Set("Content-Type", "application/json")
	assert.Check(t, is.Equal(soapFaultCode(t, serveArtifactResolution(test, r)), "soapenv:Client"))

	r = httptest.NewRequest(http.MethodGet, artifactTestURL, nil)
	w = serveArtifactResolution(test, r)
	assert.Check(t, is.Equal(w.Code, http.StatusMethodNotAllowed))
	assert.Check(t, is.Equal(w.Header().Get("Allow"), http.MethodPost))

	// The response can't be signed.
	test.IDP.Key = nil

	r, _ = artifactResolvePost(t, &test.SP, Artifact{}.String(), nil)
	assert.Check(t, is.Equal(soapFaultCode(t, serveArtifactResolution(test, r)), "soapenv:Server"))
}

// artifactEndToEnd runs Web Browser SSO between the service provider and the identity provider of this package
// with the response delivered by artifact, and returns the assertion the service provider accepts.
func artifactEndToEnd(t *testing.T, test *IdentityProviderTest, logs *bytes.Buffer) {
	t.Helper()

	// The service provider resolves the artifact at the identity provider over HTTP.
	server := httptest.NewServer(test.IDP.Handler())
	t.Cleanup(server.Close)

	test.IDP.ArtifactResolutionURL = mustParseURL(server.URL + "/saml/artifact")
	server.Config.Handler = test.IDP.Handler()
	test.SP.IDPMetadata = test.IDP.Metadata()

	assert.Equal(t, test.SP.GetArtifactBindingLocation(SOAPBinding), server.URL+"/saml/artifact")

	// The service provider asks for the response at its artifact endpoint.
	request, err := test.SP.MakeAuthenticationRequest(test.SP.GetSSOBindingLocation(HTTPRedirectBinding), HTTPRedirectBinding, HTTPArtifactBinding)
	assert.NilError(t, err)

	redirect, err := request.Redirect("relay-state", &test.SP)
	assert.NilError(t, err)

	// The browser takes the request to the identity provider, which answers with an artifact.
	w := serveSSO(test, httptest.NewRequest(http.MethodGet, redirect.String(), nil))

	var acs *http.Request

	if test.IDP.ArtifactRedirectEncoding {
		location, _ := redirectedArtifact(t, w)
		acs = httptest.NewRequest(http.MethodGet, location.String(), nil)
	} else {
		acs = httptest.NewRequest(http.MethodPost, test.SP.AcsURL.String(), strings.NewReader(postedArtifact(t, w).Encode()))
		acs.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// The browser takes the artifact to the service provider, which resolves it and accepts the assertion.
	assert.NilError(t, acs.ParseForm())
	assert.Check(t, is.Equal(acs.Form.Get("RelayState"), "relay-state"))

	assertion, err := test.SP.ParseResponse(acs, []string{request.ID})
	if err != nil {
		var invalid *InvalidResponseError
		if errors.As(err, &invalid) {
			t.Fatalf("the service provider refused the response: %v\nidentity provider log: %s", invalid.PrivateErr, logs)
		}
	}

	assert.NilError(t, err)
	assert.Assert(t, assertion.Subject != nil && assertion.Subject.NameID != nil)
	assert.Check(t, is.Equal(assertion.Issuer.Value, "https://idp.example.com/saml/metadata"))

	// SAMLProf §4.1.4.2: the bearer confirmation is for the endpoint that the artifact was delivered to.
	assert.Assert(t, is.Len(assertion.Subject.SubjectConfirmations, 1))
	assert.Check(t, is.Equal(assertion.Subject.SubjectConfirmations[0].Method, bearerSubjectConfirmationMethod))
	assert.Check(t, is.Equal(assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.Recipient, test.SP.AcsURL.String()))
	assert.Check(t, is.Equal(assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo, request.ID))

	// The artifact is used up: presenting it to the service provider again resolves to nothing.
	replayed := httptest.NewRequest(http.MethodGet, test.SP.AcsURL.String()+"?"+url.Values{"SAMLart": {acs.Form.Get("SAMLart")}}.Encode(), nil)
	assert.NilError(t, replayed.ParseForm())

	_, err = test.SP.ParseResponse(replayed, []string{request.ID})
	assert.Check(t, err != nil)
	assert.Check(t, is.Contains(logs.String(), "unknown, expired or already resolved"))
}

func TestArtifactEndToEnd(t *testing.T) {
	t.Run("form, encrypted assertion", func(t *testing.T) {
		test, logs := artifactTestIDP(t)

		artifactEndToEnd(t, test, logs)
	})

	t.Run("redirect, encrypted assertion", func(t *testing.T) {
		test, logs := artifactTestIDP(t)
		test.IDP.ArtifactRedirectEncoding = true

		artifactEndToEnd(t, test, logs)
	})

	t.Run("form, signed assertion", func(t *testing.T) {
		test, logs := artifactTestIDP(t)

		sp := &test.SP

		// A service provider that publishes no encryption key gets the assertion signed and in the clear.
		test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
			GetServiceProviderFunc: func(_ *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
				if serviceProviderID != sp.MetadataURL.String() {
					return nil, os.ErrNotExist
				}

				metadata := sp.Metadata()

				descriptor := &metadata.SPSSODescriptors[0]
				descriptor.KeyDescriptors = slices.DeleteFunc(descriptor.KeyDescriptors, func(key KeyDescriptor) bool {
					return key.Use != "signing"
				})
				assert.Check(t, is.Len(descriptor.KeyDescriptors, 1))

				return metadata, nil
			},
		}

		artifactEndToEnd(t, test, logs)
	})
}
