package saml

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/golden"
)

const (
	manageNameIDTestURL     = "https://idp.example.com/saml/mni"
	soapManageNameIDTestURL = "https://idp.example.com/saml/mni/soap"
	manageNameIDTestSPURL   = "https://sp.example.com/saml2/mni"
)

// managedNameID is one call to a nameIDManagementProvider.
type managedNameID struct {
	Request      *IdpManageNameIDRequest
	NameID       NameID
	SPProvidedID string
	Terminate    bool
}

// nameIDManagementProvider is a NameIDProvider which manages the identifiers whose values it is given, and
// records what it is asked.
type nameIDManagementProvider struct {
	DefaultNameIDProvider
	known []string
	calls []managedNameID
	err   error

	// aliases are the SPProvidedIDs that were set, by aliasKey.
	aliases map[string]string

	// lookups are the identifiers that SPProvidedID was asked about, and lookupErr is what it returns, if set.
	lookups   []NameID
	lookupErr error
}

// aliasKey is the key of the alias that the service provider has for the identifier with the value.
func aliasKey(serviceProviderEntityID, value string) string {
	return serviceProviderEntityID + " " + value
}

func (p *nameIDManagementProvider) manage(req *IdpManageNameIDRequest, call managedNameID) error {
	call.Request, call.NameID = req, *req.Request.NameID
	p.calls = append(p.calls, call)

	if !slices.Contains(p.known, req.Request.NameID.Value) {
		return fmt.Errorf("%w: %s", ErrUnknownPrincipal, req.Request.NameID.Value)
	}

	if p.err != nil {
		return p.err
	}

	if p.aliases == nil {
		p.aliases = map[string]string{}
	}

	key := aliasKey(req.ServiceProviderMetadata.EntityID, req.Request.NameID.Value)

	if call.Terminate {
		delete(p.aliases, key)
	} else {
		p.aliases[key] = call.SPProvidedID
	}

	return nil
}

func (p *nameIDManagementProvider) SPProvidedID(_ *http.Request, serviceProviderEntityID string, nameID *NameID) (string, error) {
	p.lookups = append(p.lookups, *nameID)

	if p.lookupErr != nil {
		return "", p.lookupErr
	}

	return p.aliases[aliasKey(serviceProviderEntityID, nameID.Value)], nil
}

func (p *nameIDManagementProvider) SetSPProvidedID(_ *http.Request, req *IdpManageNameIDRequest, spProvidedID string) error {
	return p.manage(req, managedNameID{SPProvidedID: spProvidedID})
}

func (p *nameIDManagementProvider) TerminateNameID(_ *http.Request, req *IdpManageNameIDRequest) error {
	return p.manage(req, managedNameID{Terminate: true})
}

// nameIDTestServiceProviders makes the identity provider of test know each of sps, with the metadata that
// each has when it is asked for after edit, if any, has changed it.
func nameIDTestServiceProviders(test *IdentityProviderTest, edit func(*EntityDescriptor), sps ...*ServiceProvider) {
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			for _, sp := range sps {
				if serviceProviderID != sp.MetadataURL.String() {
					continue
				}

				metadata := sp.Metadata()
				if edit != nil {
					edit(metadata)
				}

				return metadata, nil
			}

			return nil, os.ErrNotExist
		},
	}
}

// manageNameIDTestIDP returns an identity provider with the name identifier management services, whose
// NameIDProvider manages the identifier p-alice, and a service provider which signs its requests and has a
// ManageNameIDService on each of bindings, or on HTTP-Redirect and HTTP-POST when none are given.
func manageNameIDTestIDP(t *testing.T, bindings ...string) (*IdentityProviderTest, *nameIDManagementProvider) {
	t.Helper()

	if len(bindings) == 0 {
		bindings = []string{HTTPRedirectBinding, HTTPPostBinding}
	}

	test := signatureTestIDP(t)
	test.IDP.Observer = logObserver(io.Discard)
	test.IDP.ManageNameIDURL = mustParseURL(manageNameIDTestURL)
	test.IDP.SOAPManageNameIDURL = mustParseURL(soapManageNameIDTestURL)

	provider := &nameIDManagementProvider{known: []string{"p-alice"}}
	test.IDP.NameIDProvider = provider
	test.SP.IDPMetadata = test.IDP.Metadata()

	nameIDTestServiceProviders(test, func(metadata *EntityDescriptor) {
		for _, binding := range bindings {
			metadata.SPSSODescriptors[0].ManageNameIDServices = append(metadata.SPSSODescriptors[0].ManageNameIDServices,
				Endpoint{Binding: binding, Location: manageNameIDTestSPURL})
		}
	}, &test.SP)

	return test, provider
}

// manageNameIDOptions change the ManageNameIDRequest that a test sends.
type manageNameIDOptions struct {
	// mutate changes the request before it is serialized.
	mutate func(*ManageNameIDRequest)

	// mutateEl changes the element of the request before it is signed.
	mutateEl func(*etree.Element)

	// signer signs the request in place of the service provider that issues it.
	signer *ServiceProvider

	// unsigned leaves the request unsigned.
	unsigned bool
}

// testNameID is the identifier that the tests name the principal with.
func testNameID(test *IdentityProviderTest, sp *ServiceProvider) *NameID {
	return &NameID{
		Format:          string(PersistentNameIDFormat),
		NameQualifier:   test.IDP.MetadataURL.String(),
		SPNameQualifier: sp.MetadataURL.String(),
		Value:           "p-alice",
	}
}

// manageNameIDRequestElement returns the element of a ManageNameIDRequest of the service provider for destination,
// which sets the SPProvidedID sp-alias unless the options change it, and its ID. It is not signed.
func manageNameIDRequestElement(test *IdentityProviderTest, destination string, opts manageNameIDOptions) (*etree.Element, string) {
	request := &ManageNameIDRequest{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		Version:      "2.0",
		IssueInstant: TimeNow(),
		Destination:  destination,
		Issuer:       &Issuer{Format: string(EntityNameIDFormat), Value: test.SP.MetadataURL.String()},
		NameID:       testNameID(test, &test.SP),
		NewID:        "sp-alias",
	}

	if opts.mutate != nil {
		opts.mutate(request)
	}

	el := request.Element()

	if opts.mutateEl != nil {
		opts.mutateEl(el)
	}

	return el, request.ID
}

// testSigner returns the service provider that signs a request, or nil for one that is not signed.
func testSigner(sp *ServiceProvider, signer *ServiceProvider, unsigned bool) *ServiceProvider {
	switch {
	case unsigned:
		return nil
	case signer != nil:
		return signer
	default:
		return sp
	}
}

// signTestElement returns el with an enveloped signature of signer, or el itself if signer is nil.
func signTestElement(t *testing.T, signer *ServiceProvider, el *etree.Element) *etree.Element {
	t.Helper()

	if signer == nil {
		return el
	}

	signingContext, err := GetSigningContext(signer)
	require.NoError(t, err)

	signed, err := signingContext.SignEnveloped(el)
	require.NoError(t, err)

	return signed
}

// nameIDTestSOAPPost returns a SOAP POST of the envelope that carries el to target.
func nameIDTestSOAPPost(t *testing.T, target string, el *etree.Element) *http.Request {
	t.Helper()

	r := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(soapLogoutEnvelope(t, el)))
	r.Header.Set("Content-Type", "text/xml")

	return r
}

// nameIDTestSOAPMessage returns the message of a 200 SOAP response, which must be the protocol element named
// tag, and the content of it that the signature of the identity provider covers.
func nameIDTestSOAPMessage(t *testing.T, w *httptest.ResponseRecorder, tag string) *etree.Element {
	t.Helper()

	require.Equal(t, w.Code, http.StatusOK, "body: %s", w.Body.String())

	envelope := soapTestParseResponse(t, w)

	body := envelope.FindElement("./Body")
	require.NotNil(t, body)
	require.Len(t, body.ChildElements(), 1)

	message := detachSOAPBodyChild(body.ChildElements()[0])
	require.Equal(t, message.Tag, tag)
	require.Equal(t, message.NamespaceURI(), samlProtocolNS)

	verified, err := verifyEnvelopedSignature(message, certificateVerificationKeys([]*x509.Certificate{mustParseCertificate(golden.Get(t, "idp_cert.pem"))}), anySignaturePolicy)
	require.NoError(t, err)

	return verified
}

// manageNameIDResult is the answer of the identity provider to a ManageNameIDRequest.
type manageNameIDResult struct {
	// Code is the HTTP status.
	Code int

	// Response is the verified ManageNameIDResponse, or nil if the identity provider sent none.
	Response *ManageNameIDResponse

	// Destination is where the browser was sent with the response, on the front channel.
	Destination string

	// Binding is the binding the response was sent on.
	Binding string

	// RelayState is the RelayState sent with the response, on the front channel.
	RelayState string

	// RequestID is the ID of the request.
	RequestID string
}

// frontChannelManageNameIDResult reads the answer of ServeManageNameID in w.
func frontChannelManageNameIDResult(t *testing.T, w *httptest.ResponseRecorder, requestID string) manageNameIDResult {
	t.Helper()

	result := manageNameIDResult{Code: w.Code, RequestID: requestID}
	certificates := []*x509.Certificate{mustParseCertificate(golden.Get(t, "idp_cert.pem"))}

	switch w.Code {
	case http.StatusFound:
		location, err := url.Parse(w.Header().Get("Location"))
		require.NoError(t, err)

		// SAMLProfiles §4.5.3.2: the response MUST be signed, which on this binding is in the query.
		require.NoError(t, verifyRedirectSignature(location.RawQuery, "SAMLResponse", certificateVerificationKeys(certificates), anySignaturePolicy))

		compressed, err := base64.StdEncoding.DecodeString(location.Query().Get("SAMLResponse"))
		require.NoError(t, err)
		buf, err := io.ReadAll(flate.NewReader(bytes.NewReader(compressed)))
		require.NoError(t, err)

		doc := etree.NewDocument()
		require.NoError(t, doc.ReadFromBytes(buf))

		result.Response = &ManageNameIDResponse{}
		require.NoError(t, unmarshalElement(doc.Root(), result.Response))

		result.Binding, result.RelayState = HTTPRedirectBinding, location.Query().Get("RelayState")
		location.RawQuery = ""
		result.Destination = location.String()
	case http.StatusOK:
		body := w.Body.String()
		field := func(name string) string {
			marker := `name="` + name + `" value="`
			start := strings.Index(body, marker)
			require.True(t, start >= 0, "no %s in %q", name, body)
			value, _, _ := strings.Cut(body[start+len(marker):], `"`)

			return html.UnescapeString(value)
		}

		buf, err := base64.StdEncoding.DecodeString(field("SAMLResponse"))
		require.NoError(t, err)

		doc := etree.NewDocument()
		require.NoError(t, doc.ReadFromBytes(buf))

		verified, err := verifyEnvelopedSignature(doc.Root(), certificateVerificationKeys(certificates), anySignaturePolicy)
		require.NoError(t, err)

		result.Response = &ManageNameIDResponse{}
		require.NoError(t, unmarshalElement(verified, result.Response))

		marker := `action="`
		start := strings.Index(body, marker)
		require.True(t, start >= 0)
		action, _, _ := strings.Cut(body[start+len(marker):], `"`)

		result.Binding, result.RelayState, result.Destination = HTTPPostBinding, field("RelayState"), html.UnescapeString(action)
	}

	return result
}

// manageNameIDBindings are the ways a service provider sends a ManageNameIDRequest to the identity provider.
var manageNameIDBindings = map[string]func(t *testing.T, test *IdentityProviderTest, opts manageNameIDOptions) manageNameIDResult{
	"redirect": func(t *testing.T, test *IdentityProviderTest, opts manageNameIDOptions) manageNameIDResult {
		t.Helper()

		el, id := manageNameIDRequestElement(test, manageNameIDTestURL, opts)
		u, err := redirectURL(manageNameIDTestURL, "SAMLRequest", el, "relay", testSigner(&test.SP, opts.signer, opts.unsigned))
		require.NoError(t, err)

		w := httptest.NewRecorder()
		test.IDP.ServeManageNameID(w, httptest.NewRequest(http.MethodGet, u.String(), nil))

		return frontChannelManageNameIDResult(t, w, id)
	},
	"post": func(t *testing.T, test *IdentityProviderTest, opts manageNameIDOptions) manageNameIDResult {
		t.Helper()

		el, id := manageNameIDRequestElement(test, manageNameIDTestURL, opts)

		doc := etree.NewDocument()
		doc.SetRoot(signTestElement(t, testSigner(&test.SP, opts.signer, opts.unsigned), el))
		body, err := doc.WriteToBytes()
		require.NoError(t, err)

		form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}, "RelayState": {"relay"}}
		r := httptest.NewRequest(http.MethodPost, manageNameIDTestURL, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()
		test.IDP.ServeManageNameID(w, r)

		return frontChannelManageNameIDResult(t, w, id)
	},
	"soap": func(t *testing.T, test *IdentityProviderTest, opts manageNameIDOptions) manageNameIDResult {
		t.Helper()

		el, id := manageNameIDRequestElement(test, soapManageNameIDTestURL, opts)
		el = signTestElement(t, testSigner(&test.SP, opts.signer, opts.unsigned), el)

		w := httptest.NewRecorder()
		test.IDP.ServeSOAPManageNameID(w, nameIDTestSOAPPost(t, soapManageNameIDTestURL, el))

		result := manageNameIDResult{Code: w.Code, RequestID: id, Binding: SOAPBinding}

		if w.Code == http.StatusOK {
			result.Response = &ManageNameIDResponse{}
			require.NoError(t, unmarshalElement(nameIDTestSOAPMessage(t, w, "ManageNameIDResponse"), result.Response))
		}

		return result
	},
}

// checkStatus checks that status has the top-level code top, and the second-level code second or none if it is
// empty, and no message, which must never be sent.
func checkStatus(t *testing.T, status Status, top, second string) {
	t.Helper()

	assert.Equal(t, status.StatusCode.Value, top)

	if second == "" {
		assert.Nil(t, status.StatusCode.StatusCode)
	} else if assert.True(t, status.StatusCode.StatusCode != nil, "no second-level status") {
		assert.Equal(t, status.StatusCode.StatusCode.Value, second)
	}

	assert.True(t, statusSaysNothingOfTheRequest(status))
	assert.Nil(t, status.StatusDetail)
}

// idpEncrypter returns the encrypter of the service provider to the identity provider, negotiated from its
// metadata.
func idpEncrypter(t *testing.T, test *IdentityProviderTest) *elementEncrypter {
	t.Helper()

	encrypter, err := test.SP.idpElementEncrypter()
	require.NoError(t, err)

	return encrypter
}

// otherKeyEncrypter returns an encrypter to a key that the identity provider doesn't hold.
func otherKeyEncrypter(t *testing.T, test *IdentityProviderTest) *elementEncrypter {
	t.Helper()

	encrypter := *idpEncrypter(t, test)
	_, encrypter.certificate = propagationServiceProviderKey(t)

	return &encrypter
}

func TestManageNameIDNewID(t *testing.T) {
	for name, send := range manageNameIDBindings {
		t.Run(name, func(t *testing.T) {
			test, provider := manageNameIDTestIDP(t)

			result := send(t, test, manageNameIDOptions{})
			require.True(t, result.Response != nil, "HTTP status %d", result.Code)
			checkStatus(t, result.Response.Status, StatusSuccess, "")

			// SAMLCore §3.2.2, SAMLProfiles §4.5.4.2.
			assert.Equal(t, result.Response.InResponseTo, result.RequestID)
			assert.Equal(t, result.Response.Version, "2.0")
			require.NotNil(t, result.Response.Issuer)
			assert.Equal(t, result.Response.Issuer.Value, test.IDP.MetadataURL.String())
			assert.Equal(t, result.Response.Issuer.Format, string(EntityNameIDFormat))

			if result.Binding == SOAPBinding {
				assert.Equal(t, result.Response.Destination, "")
			} else {
				assert.Equal(t, result.Response.Destination, manageNameIDTestSPURL)
				assert.Equal(t, result.Destination, manageNameIDTestSPURL)
				assert.Equal(t, result.RelayState, "relay")
			}

			// SAMLCore §3.6.3: the NewID is the SPProvidedID from now on.
			require.Len(t, provider.calls, 1)
			assert.Equal(t, provider.calls[0].SPProvidedID, "sp-alias")
			assert.False(t, provider.calls[0].Terminate)
			assert.Equal(t, provider.calls[0].NameID, *testNameID(test, &test.SP))
			assert.Equal(t, provider.calls[0].Request.ServiceProviderMetadata.EntityID, test.SP.MetadataURL.String())
			assert.False(t, provider.calls[0].Request.NameIDEncrypted)
			assert.False(t, provider.calls[0].Request.NewIDEncrypted)
			assert.False(t, provider.calls[0].Request.Unidentified)
		})
	}
}

func TestManageNameIDTerminate(t *testing.T) {
	for name, send := range manageNameIDBindings {
		t.Run(name, func(t *testing.T) {
			test, provider := manageNameIDTestIDP(t)

			result := send(t, test, manageNameIDOptions{mutate: func(request *ManageNameIDRequest) {
				request.NewID, request.Terminate = "", true
			}})
			require.True(t, result.Response != nil, "HTTP status %d", result.Code)
			checkStatus(t, result.Response.Status, StatusSuccess, "")

			require.Len(t, provider.calls, 1)
			assert.True(t, provider.calls[0].Terminate)
			assert.Equal(t, provider.calls[0].SPProvidedID, "")
			assert.Equal(t, provider.calls[0].NameID.Value, "p-alice")
		})
	}
}

// SAMLCore §3.6.1 and §3.6.3: either, or both, of the identifier and the new identifier may be encrypted.
func TestManageNameIDEncrypted(t *testing.T) {
	for name, send := range manageNameIDBindings {
		t.Run(name, func(t *testing.T) {
			test, provider := manageNameIDTestIDP(t)

			result := send(t, test, manageNameIDOptions{
				mutate: func(request *ManageNameIDRequest) {
					encrypter := idpEncrypter(t, test)

					var err error

					request.EncryptedID, err = encrypter.encryptNameID(request.NameID)
					require.NoError(t, err)
					request.NewEncryptedID, err = encrypter.encryptNewID("sp-secret-alias")
					require.NoError(t, err)
				},
				mutateEl: func(el *etree.Element) {
					// Neither identifier is in the message in plaintext.
					text := elementToString(el)
					assert.False(t, strings.Contains(text, "p-alice"))
					assert.False(t, strings.Contains(text, "alias"))
					assert.NotNil(t, el.FindElement("./EncryptedID"))
					assert.NotNil(t, el.FindElement("./NewEncryptedID"))
					assert.Nil(t, el.FindElement("./NameID"))
					assert.Nil(t, el.FindElement("./NewID"))
				},
			})
			require.True(t, result.Response != nil, "HTTP status %d", result.Code)
			checkStatus(t, result.Response.Status, StatusSuccess, "")

			require.Len(t, provider.calls, 1)
			assert.Equal(t, provider.calls[0].SPProvidedID, "sp-secret-alias")
			assert.Equal(t, provider.calls[0].NameID, *testNameID(test, &test.SP))
			assert.True(t, provider.calls[0].Request.NameIDEncrypted)
			assert.True(t, provider.calls[0].Request.NewIDEncrypted)
			assert.False(t, provider.calls[0].Request.Unidentified)
		})
	}
}

// A NewEncryptedID that can't be used is refused whatever is wrong with it, and nothing is changed.
func TestManageNameIDNewEncryptedIDRefused(t *testing.T) {
	for name, encrypt := range map[string]func(t *testing.T, test *IdentityProviderTest) *etree.Element{
		"encrypted to another key": func(t *testing.T, test *IdentityProviderTest) *etree.Element {
			el, err := otherKeyEncrypter(t, test).encryptNewID("sp-alias")
			require.NoError(t, err)

			return el
		},
		"tampered ciphertext": func(t *testing.T, test *IdentityProviderTest) *etree.Element {
			el, err := idpEncrypter(t, test).encryptNewID("sp-alias")
			require.NoError(t, err)

			value := el.FindElement("./EncryptedData/CipherData/CipherValue")
			buf, err := base64.StdEncoding.DecodeString(value.Text())
			require.NoError(t, err)

			buf[len(buf)-1] ^= 0x01
			value.SetText(base64.StdEncoding.EncodeToString(buf))

			return el
		},
		// Errata E93: a cipher in CBC mode doesn't protect its integrity, and the answer would tell whether an
		// altered ciphertext decrypted.
		"cbc": func(t *testing.T, test *IdentityProviderTest) *etree.Element {
			encrypter := &elementEncrypter{certificate: test.Certificate, encrypter: testElementEncrypter(t, method(aes128CBC)).encrypter}

			el, err := encrypter.encryptNewID("sp-alias")
			require.NoError(t, err)

			return el
		},
		"holds a NameID": func(t *testing.T, test *IdentityProviderTest) *etree.Element {
			el, err := idpEncrypter(t, test).encryptNameID(testNameID(test, &test.SP))
			require.NoError(t, err)

			el.Tag, el.Space = "NewEncryptedID", "samlp"

			return el
		},
		"holds an empty NewID": func(t *testing.T, test *IdentityProviderTest) *etree.Element {
			el, err := idpEncrypter(t, test).encryptNewID("")
			require.NoError(t, err)

			return el
		},
	} {
		for binding, send := range manageNameIDBindings {
			t.Run(name+"/"+binding, func(t *testing.T) {
				test, provider := manageNameIDTestIDP(t)

				result := send(t, test, manageNameIDOptions{mutate: func(request *ManageNameIDRequest) {
					request.NewEncryptedID = encrypt(t, test)
				}})
				require.True(t, result.Response != nil, "HTTP status %d", result.Code)
				checkStatus(t, result.Response.Status, StatusRequester, StatusRequestDenied)
				assert.Len(t, provider.calls, 0)
			})
		}
	}
}

// An identifier that the requester doesn't share with the identity provider is answered as an unknown principal
// is, whatever the reason: SAMLCore §3.6.3 requires an error status, and an EncryptedID that can't be decrypted
// must not be told apart (errata E93).
func TestManageNameIDUnknownPrincipal(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(t *testing.T, test *IdentityProviderTest, request *ManageNameIDRequest)

		// calls is how often the provider is asked, which it never is for a request that names nobody.
		calls int
	}{
		"unknown to the provider": {
			mutate: func(_ *testing.T, _ *IdentityProviderTest, request *ManageNameIDRequest) {
				request.NameID.Value = "p-mallory"
			},
			calls: 1,
		},
		"unknown to the provider and encrypted": {
			mutate: func(t *testing.T, test *IdentityProviderTest, request *ManageNameIDRequest) {
				request.NameID.Value = "p-mallory"

				var err error

				request.EncryptedID, err = idpEncrypter(t, test).encryptNameID(request.NameID)
				require.NoError(t, err)
			},
			calls: 1,
		},
		"encrypted to another key": {
			mutate: func(t *testing.T, test *IdentityProviderTest, request *ManageNameIDRequest) {
				var err error

				request.EncryptedID, err = otherKeyEncrypter(t, test).encryptNameID(request.NameID)
				require.NoError(t, err)
			},
		},
		"tampered ciphertext": {
			mutate: func(t *testing.T, test *IdentityProviderTest, request *ManageNameIDRequest) {
				var err error

				request.EncryptedID, err = idpEncrypter(t, test).encryptNameID(request.NameID)
				require.NoError(t, err)

				value := request.EncryptedID.FindElement("./EncryptedData/CipherData/CipherValue")
				buf, err := base64.StdEncoding.DecodeString(value.Text())
				require.NoError(t, err)

				buf[len(buf)-1] ^= 0x01
				value.SetText(base64.StdEncoding.EncodeToString(buf))
			},
		},
		// The identifier of another service provider, which this one saw as a ciphertext and sent as its own.
		"encrypted identifier of another service provider": {
			mutate: func(t *testing.T, test *IdentityProviderTest, request *ManageNameIDRequest) {
				request.NameID.SPNameQualifier = "https://sp-b.example.com/saml2/metadata"

				var err error

				request.EncryptedID, err = idpEncrypter(t, test).encryptNameID(request.NameID)
				require.NoError(t, err)
			},
		},
		"identifier of another service provider": {
			mutate: func(_ *testing.T, _ *IdentityProviderTest, request *ManageNameIDRequest) {
				request.NameID.SPNameQualifier = "https://sp-b.example.com/saml2/metadata"
			},
		},
		"identifier of another identity provider": {
			mutate: func(_ *testing.T, _ *IdentityProviderTest, request *ManageNameIDRequest) {
				request.NameID.NameQualifier = "https://other-idp.example.com/metadata"
			},
		},
		// Errata E12: the protocol MUST NOT be used with the transient format.
		"transient": {
			mutate: func(_ *testing.T, _ *IdentityProviderTest, request *ManageNameIDRequest) {
				request.NameID.Format = string(TransientNameIDFormat)
			},
		},
		"encrypted transient": {
			mutate: func(t *testing.T, test *IdentityProviderTest, request *ManageNameIDRequest) {
				request.NameID.Format = string(TransientNameIDFormat)

				var err error

				request.EncryptedID, err = idpEncrypter(t, test).encryptNameID(request.NameID)
				require.NoError(t, err)
			},
		},
	} {
		for binding, send := range manageNameIDBindings {
			t.Run(name+"/"+binding, func(t *testing.T) {
				test, provider := manageNameIDTestIDP(t)

				result := send(t, test, manageNameIDOptions{mutate: func(request *ManageNameIDRequest) {
					tc.mutate(t, test, request)
				}})
				require.True(t, result.Response != nil, "HTTP status %d", result.Code)
				checkStatus(t, result.Response.Status, StatusRequester, StatusUnknownPrincipal)

				require.Len(t, provider.calls, tc.calls)
				assert.Len(t, provider.lookups, 0)

				for _, call := range provider.calls {
					assert.False(t, call.Request.Unidentified)
					assert.Equal(t, call.NameID.Value, "p-mallory")
				}
			})
		}
	}
}

// The methods of the provider change what is stored, so they are never given the stand-in of a request that names
// nobody, whether it is a NewID, a NewEncryptedID or a Terminate, and whatever the provider would answer.
func TestManageNameIDUnidentifiedNeverReachesProvider(t *testing.T) {
	unidentified := func(t *testing.T, test *IdentityProviderTest, request *ManageNameIDRequest) {
		var err error

		request.EncryptedID, err = otherKeyEncrypter(t, test).encryptNameID(request.NameID)
		require.NoError(t, err)
	}

	for name, mutate := range map[string]func(*ManageNameIDRequest){
		"NewID":     func(*ManageNameIDRequest) {},
		"Terminate": func(request *ManageNameIDRequest) { request.NewID, request.Terminate = "", true },
	} {
		for binding, send := range manageNameIDBindings {
			t.Run(name+"/"+binding, func(t *testing.T) {
				test, provider := manageNameIDTestIDP(t)

				result := send(t, test, manageNameIDOptions{mutate: func(request *ManageNameIDRequest) {
					mutate(request)
					unidentified(t, test, request)
				}})
				require.True(t, result.Response != nil, "HTTP status %d", result.Code)
				checkStatus(t, result.Response.Status, StatusRequester, StatusUnknownPrincipal)

				assert.Len(t, provider.calls, 0)
				assert.Len(t, provider.lookups, 0)
				assert.Len(t, provider.aliases, 0)
			})
		}
	}

	// A provider which would recognize the stand-in is not asked either.
	test, provider := manageNameIDTestIDP(t)
	provider.known = append(provider.known, "stand-in")

	for _, terminate := range []bool{false, true} {
		req := &IdpManageNameIDRequest{
			IDP:                     &test.IDP,
			Request:                 ManageNameIDRequest{NameID: &NameID{Value: "stand-in"}, NewID: "sp-alias", Terminate: terminate},
			ServiceProviderMetadata: test.SP.Metadata(),
			Unidentified:            true,
			NameIDEncrypted:         true,
		}

		err := test.IDP.manageNameID(httptest.NewRequest(http.MethodPost, "/", nil), req)
		assert.True(t, errors.Is(err, ErrUnknownPrincipal), "%v", err)
		checkStatus(t, test.IDP.ErrorStatus(err), StatusRequester, StatusUnknownPrincipal)
	}

	assert.Len(t, provider.calls, 0)
}

// An affiliation that the service provider is a member of may qualify the identifier (SAMLCore §3.6.3).
func TestManageNameIDAffiliation(t *testing.T) {
	const affiliation = "https://affiliation.example.com/metadata"

	test, provider := manageNameIDTestIDP(t)
	known := test.IDP.ServiceProviderProvider

	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(r *http.Request, id string) (*EntityDescriptor, error) {
			if id == affiliation {
				return &EntityDescriptor{EntityID: affiliation, AffiliationDescriptor: &AffiliationDescriptor{
					AffiliationOwnerID: "https://owner.example.com",
					AffiliateMembers:   []string{test.SP.MetadataURL.String()},
				}}, nil
			}

			return known.GetServiceProvider(r, id)
		},
	}

	result := manageNameIDBindings["soap"](t, test, manageNameIDOptions{mutate: func(request *ManageNameIDRequest) {
		request.NameID.SPNameQualifier = affiliation
	}})
	require.NotNil(t, result.Response)
	checkStatus(t, result.Response.Status, StatusSuccess, "")
	require.Len(t, provider.calls, 1)
	assert.Equal(t, provider.calls[0].NameID.SPNameQualifier, affiliation)
}

// Without a NameIDManagementProvider the protocol is not supported, and not advertised.
func TestManageNameIDWithoutProvider(t *testing.T) {
	for name, send := range manageNameIDBindings {
		t.Run(name, func(t *testing.T) {
			test, _ := manageNameIDTestIDP(t)
			test.IDP.NameIDProvider = nil

			result := send(t, test, manageNameIDOptions{})
			require.True(t, result.Response != nil, "HTTP status %d", result.Code)
			checkStatus(t, result.Response.Status, StatusResponder, StatusRequestUnsupported)

			assert.Len(t, test.IDP.Metadata().IDPSSODescriptors[0].ManageNameIDServices, 0)
		})
	}
}

func TestManageNameIDProviderFailure(t *testing.T) {
	for name, send := range manageNameIDBindings {
		t.Run(name, func(t *testing.T) {
			test, provider := manageNameIDTestIDP(t)
			provider.err = errors.New("the database is down: secret detail")

			result := send(t, test, manageNameIDOptions{})
			require.True(t, result.Response != nil, "HTTP status %d", result.Code)
			checkStatus(t, result.Response.Status, StatusResponder, "")
		})
	}
}

// A request whose requester isn't verified changes nothing. On the front channel it is not answered with a
// SAML response at all, and on SOAP, where the answer goes back to the caller, with RequestDenied.
func TestManageNameIDRejectsUnauthenticatedRequests(t *testing.T) {
	otherSigner := func(t *testing.T, test *IdentityProviderTest) *ServiceProvider {
		t.Helper()

		other := test.SP
		other.Key, other.Certificate = propagationServiceProviderKey(t)

		return &other
	}

	for name, options := range map[string]func(t *testing.T, test *IdentityProviderTest) manageNameIDOptions{
		"unsigned": func(*testing.T, *IdentityProviderTest) manageNameIDOptions {
			return manageNameIDOptions{unsigned: true}
		},
		"signed with another key": func(t *testing.T, test *IdentityProviderTest) manageNameIDOptions {
			return manageNameIDOptions{signer: otherSigner(t, test)}
		},
		"unknown service provider": func(*testing.T, *IdentityProviderTest) manageNameIDOptions {
			return manageNameIDOptions{mutate: func(request *ManageNameIDRequest) {
				request.Issuer.Value = "https://unknown.example.com/metadata"
			}}
		},
		"no issuer": func(*testing.T, *IdentityProviderTest) manageNameIDOptions {
			return manageNameIDOptions{mutate: func(request *ManageNameIDRequest) { request.Issuer = nil }}
		},
		// SAMLProfiles §4.5.4.1.
		"issuer of another format": func(*testing.T, *IdentityProviderTest) manageNameIDOptions {
			return manageNameIDOptions{mutate: func(request *ManageNameIDRequest) {
				request.Issuer.Format = string(PersistentNameIDFormat)
			}}
		},
		"invalid ID": func(*testing.T, *IdentityProviderTest) manageNameIDOptions {
			return manageNameIDOptions{mutate: func(request *ManageNameIDRequest) { request.ID = "an id" }}
		},
	} {
		for binding, send := range manageNameIDBindings {
			t.Run(name+"/"+binding, func(t *testing.T) {
				test, provider := manageNameIDTestIDP(t)

				result := send(t, test, options(t, test))
				assert.Len(t, provider.calls, 0)

				if binding != "soap" {
					assert.Equal(t, result.Code, http.StatusBadRequest)
					assert.Nil(t, result.Response)

					return
				}

				require.True(t, result.Response != nil, "HTTP status %d", result.Code)
				checkStatus(t, result.Response.Status, StatusRequester, StatusRequestDenied)
			})
		}
	}
}

// A request that was altered after it was signed is refused.
func TestManageNameIDRejectsAlteredRequest(t *testing.T) {
	test, provider := manageNameIDTestIDP(t)

	el, _ := manageNameIDRequestElement(test, soapManageNameIDTestURL, manageNameIDOptions{})
	el = signTestElement(t, &test.SP, el)
	el.FindElement("./NewID").SetText("attacker-alias")

	w := httptest.NewRecorder()
	test.IDP.ServeSOAPManageNameID(w, nameIDTestSOAPPost(t, soapManageNameIDTestURL, el))

	response := &ManageNameIDResponse{}
	require.NoError(t, unmarshalElement(nameIDTestSOAPMessage(t, w, "ManageNameIDResponse"), response))
	checkStatus(t, response.Status, StatusRequester, StatusRequestDenied)
	assert.Len(t, provider.calls, 0)
}

// The requester of a valid request is answered with an error status for what is wrong with the request.
func TestManageNameIDRequestStatus(t *testing.T) {
	for name, tc := range map[string]struct {
		options     manageNameIDOptions
		top, second string
	}{
		"wrong destination": {
			options: manageNameIDOptions{mutate: func(request *ManageNameIDRequest) {
				request.Destination = "https://idp.example.com/saml/other"
			}},
			top: StatusRequester, second: StatusRequestDenied,
		},
		"version too high": {
			options: manageNameIDOptions{mutate: func(request *ManageNameIDRequest) { request.Version = "3.0" }},
			top:     StatusVersionMismatch, second: StatusRequestVersionTooHigh,
		},
		"expired": {
			options: manageNameIDOptions{mutate: func(request *ManageNameIDRequest) {
				request.IssueInstant = TimeNow().Add(-MaxIssueDelay - MaxClockSkew)
			}},
			top: StatusRequester, second: StatusRequestDenied,
		},
		"issued in the future": {
			options: manageNameIDOptions{mutate: func(request *ManageNameIDRequest) {
				request.IssueInstant = TimeNow().Add(MaxClockSkew + time.Minute)
			}},
			top: StatusRequester, second: StatusRequestDenied,
		},
		"empty NewID": {
			options: manageNameIDOptions{mutate: func(request *ManageNameIDRequest) { request.NewID = "" }},
			top:     StatusRequester, second: StatusRequestDenied,
		},
		"NewID too long": {
			options: manageNameIDOptions{mutate: func(request *ManageNameIDRequest) {
				request.NewID = strings.Repeat("a", maxSPProvidedIDLength+1)
			}},
			top: StatusRequester, second: StatusRequestDenied,
		},
		"NewID and Terminate": {
			options: manageNameIDOptions{mutateEl: func(el *etree.Element) { el.CreateElement("samlp:Terminate") }},
			top:     StatusRequester, second: StatusRequestDenied,
		},
		"two NewIDs": {
			options: manageNameIDOptions{mutateEl: func(el *etree.Element) { el.CreateElement("samlp:NewID").SetText("other") }},
			top:     StatusRequester, second: StatusRequestDenied,
		},
		"no NewID, NewEncryptedID or Terminate": {
			options: manageNameIDOptions{mutateEl: func(el *etree.Element) { el.RemoveChild(el.FindElement("./NewID")) }},
			top:     StatusRequester, second: StatusRequestDenied,
		},
		"no identifier": {
			options: manageNameIDOptions{mutate: func(request *ManageNameIDRequest) { request.NameID = nil }},
			top:     StatusRequester, second: StatusRequestDenied,
		},
		"NameID with no value": {
			options: manageNameIDOptions{mutate: func(request *ManageNameIDRequest) { request.NameID.Value = "" }},
			top:     StatusRequester, second: StatusRequestDenied,
		},
		"two identifiers": {
			options: manageNameIDOptions{mutateEl: func(el *etree.Element) {
				second := el.FindElement("./NameID").Copy()
				second.SetText("p-bob")
				el.InsertChildAt(el.FindElement("./NewID").Index(), second)
			}},
			top: StatusRequester, second: StatusRequestDenied,
		},
	} {
		for binding, send := range manageNameIDBindings {
			t.Run(name+"/"+binding, func(t *testing.T) {
				test, provider := manageNameIDTestIDP(t)

				result := send(t, test, tc.options)
				require.True(t, result.Response != nil, "HTTP status %d", result.Code)
				checkStatus(t, result.Response.Status, tc.top, tc.second)
				assert.Len(t, provider.calls, 0)
			})
		}
	}
}

// SAMLBind §3.4.5.2 and §3.5.5.2 require the Destination of a signed message on the front channel; SAMLBind §3.2
// doesn't on SOAP.
func TestManageNameIDWithoutDestination(t *testing.T) {
	for binding, send := range manageNameIDBindings {
		t.Run(binding, func(t *testing.T) {
			test, provider := manageNameIDTestIDP(t)

			result := send(t, test, manageNameIDOptions{mutate: func(request *ManageNameIDRequest) { request.Destination = "" }})

			if binding != "soap" {
				assert.Equal(t, result.Code, http.StatusBadRequest)
				assert.Len(t, provider.calls, 0)

				return
			}

			require.True(t, result.Response != nil, "HTTP status %d", result.Code)
			checkStatus(t, result.Response.Status, StatusSuccess, "")
		})
	}
}

// The response on the front channel only goes to a ManageNameIDService of the metadata that is secure.
func TestManageNameIDResponseEndpoint(t *testing.T) {
	t.Run("another binding than the request", func(t *testing.T) {
		test, _ := manageNameIDTestIDP(t, HTTPRedirectBinding)

		result := manageNameIDBindings["post"](t, test, manageNameIDOptions{})
		require.True(t, result.Response != nil, "HTTP status %d", result.Code)
		assert.Equal(t, result.Binding, HTTPRedirectBinding)
		assert.Equal(t, result.Destination, manageNameIDTestSPURL)
	})

	t.Run("response location", func(t *testing.T) {
		test, _ := manageNameIDTestIDP(t)
		nameIDTestServiceProviders(test, func(metadata *EntityDescriptor) {
			metadata.SPSSODescriptors[0].ManageNameIDServices = []Endpoint{
				{Binding: HTTPPostBinding, Location: manageNameIDTestSPURL, ResponseLocation: manageNameIDTestSPURL + "/response"},
			}
		}, &test.SP)

		result := manageNameIDBindings["post"](t, test, manageNameIDOptions{})
		require.True(t, result.Response != nil, "HTTP status %d", result.Code)
		assert.Equal(t, result.Destination, manageNameIDTestSPURL+"/response")
		assert.Equal(t, result.Response.Destination, manageNameIDTestSPURL+"/response")
	})

	for name, endpoints := range map[string][]Endpoint{
		"none":               nil,
		"only SOAP":          {{Binding: SOAPBinding, Location: manageNameIDTestSPURL}},
		"insecure":           {{Binding: HTTPPostBinding, Location: "http://sp.example.com/saml2/mni"}},
		"insecure responses": {{Binding: HTTPPostBinding, Location: manageNameIDTestSPURL, ResponseLocation: "http://sp.example.com/saml2/mni"}},
	} {
		t.Run(name, func(t *testing.T) {
			test, provider := manageNameIDTestIDP(t)
			nameIDTestServiceProviders(test, func(metadata *EntityDescriptor) {
				metadata.SPSSODescriptors[0].ManageNameIDServices = endpoints
			}, &test.SP)

			result := manageNameIDBindings["post"](t, test, manageNameIDOptions{})
			assert.Equal(t, result.Code, http.StatusBadRequest)
			assert.Len(t, provider.calls, 0)
		})
	}
}

func TestServeSOAPManageNameIDEnvelope(t *testing.T) {
	test, provider := manageNameIDTestIDP(t)

	t.Run("not a POST", func(t *testing.T) {
		w := httptest.NewRecorder()
		test.IDP.ServeSOAPManageNameID(w, httptest.NewRequest(http.MethodGet, soapManageNameIDTestURL, nil))
		assert.Equal(t, w.Code, http.StatusMethodNotAllowed)
	})

	t.Run("not an envelope", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, soapManageNameIDTestURL, strings.NewReader("<a/>"))
		r.Header.Set("Content-Type", "text/xml")

		w := httptest.NewRecorder()
		test.IDP.ServeSOAPManageNameID(w, r)
		assert.Equal(t, soapFaultCode(t, w), "soapenv:Client")
	})

	t.Run("another message", func(t *testing.T) {
		el, id := soapLogoutRequestElement(t, &test.SP, nil)

		w := httptest.NewRecorder()
		test.IDP.ServeSOAPManageNameID(w, nameIDTestSOAPPost(t, soapManageNameIDTestURL, el))

		response := &ManageNameIDResponse{}
		require.NoError(t, unmarshalElement(nameIDTestSOAPMessage(t, w, "ManageNameIDResponse"), response))
		checkStatus(t, response.Status, StatusRequester, StatusRequestUnsupported)
		assert.Equal(t, response.InResponseTo, id)
	})

	assert.Len(t, provider.calls, 0)
}

// The identity provider sends no ManageNameIDRequest on the front channel, so it accepts no response there.
func TestServeManageNameIDRefusesResponse(t *testing.T) {
	test, provider := manageNameIDTestIDP(t)

	form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte("<a/>"))}}
	r := httptest.NewRequest(http.MethodPost, manageNameIDTestURL, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	test.IDP.ServeManageNameID(w, r)
	assert.Equal(t, w.Code, http.StatusBadRequest)

	w = httptest.NewRecorder()
	test.IDP.ServeManageNameID(w, httptest.NewRequest(http.MethodPut, manageNameIDTestURL, nil))
	assert.Equal(t, w.Code, http.StatusBadRequest)
	assert.Len(t, provider.calls, 0)
}

func TestNameIDServiceMetadata(t *testing.T) {
	test, _ := manageNameIDTestIDP(t)

	descriptor := test.IDP.Metadata().IDPSSODescriptors[0]

	// SAMLMeta §2.4.2.
	assert.Equal(t, descriptor.ManageNameIDServices, []Endpoint{
		{Binding: HTTPRedirectBinding, Location: manageNameIDTestURL},
		{Binding: HTTPPostBinding, Location: manageNameIDTestURL},
		{Binding: SOAPBinding, Location: soapManageNameIDTestURL},
	})
	assert.Len(t, descriptor.NameIDMappingServices, 0)

	test.IDP.SOAPManageNameIDURL = url.URL{}
	assert.Len(t, test.IDP.Metadata().IDPSSODescriptors[0].ManageNameIDServices, 2)

	test.IDP.ManageNameIDURL = url.URL{}
	assert.Len(t, test.IDP.Metadata().IDPSSODescriptors[0].ManageNameIDServices, 0)
}

func TestHandlerServesNameIDServices(t *testing.T) {
	test, provider := manageNameIDTestIDP(t)
	test.IDP.SOAPManageNameIDURL = mustParseURL(manageNameIDTestURL)

	handler := test.IDP.Handler()

	// A SOAP request and a front-channel request to the same path.
	el, _ := manageNameIDRequestElement(test, manageNameIDTestURL, manageNameIDOptions{})

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, nameIDTestSOAPPost(t, manageNameIDTestURL, signTestElement(t, &test.SP, el)))
	nameIDTestSOAPMessage(t, w, "ManageNameIDResponse")
	assert.Len(t, provider.calls, 1)

	el, id := manageNameIDRequestElement(test, manageNameIDTestURL, manageNameIDOptions{})
	u, err := redirectURL(manageNameIDTestURL, "SAMLRequest", el, "relay", &test.SP)
	require.NoError(t, err)

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, u.String(), nil))

	result := frontChannelManageNameIDResult(t, w, id)
	require.True(t, result.Response != nil, "HTTP status %d", w.Code)
	checkStatus(t, result.Response.Status, StatusSuccess, "")
	assert.Len(t, provider.calls, 2)

	// Services that share a path never make Handler panic. Two front-channel services can't be told apart, so
	// the first of them, which is the logout service, gets the requests of the browser, and the SOAP service
	// still gets its own.
	test.IDP.LogoutURL = mustParseURL(manageNameIDTestURL)

	handler = test.IDP.Handler()

	el, _ = manageNameIDRequestElement(test, manageNameIDTestURL, manageNameIDOptions{})

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, nameIDTestSOAPPost(t, manageNameIDTestURL, signTestElement(t, &test.SP, el)))
	nameIDTestSOAPMessage(t, w, "ManageNameIDResponse")
	assert.Len(t, provider.calls, 3)
}

// Several services on the SOAP binding at one path: Handler sends each request to the service of its message.
func TestHandlerServesNameIDServicesAtOneSOAPPath(t *testing.T) {
	f := newNameIDMappingFixture(t)

	idp := &f.test.IDP
	idp.SOAPLogoutURL = idp.NameIDMappingURL
	idp.SOAPManageNameIDURL = idp.NameIDMappingURL
	idp.ManageNameIDURL = idp.NameIDMappingURL

	handler := idp.Handler()
	target := f.b.MetadataURL.String()

	mapping := &NameIDMappingRequest{
		ID:           "id-mapping-request",
		Version:      "2.0",
		IssueInstant: TimeNow(),
		Destination:  nameIDMappingTestURL,
		Issuer:       &Issuer{Format: string(EntityNameIDFormat), Value: f.a.MetadataURL.String()},
		NameID:       testNameID(f.test, f.a),
		NameIDPolicy: &NameIDPolicy{SPNameQualifier: &target},
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, nameIDTestSOAPPost(t, nameIDMappingTestURL, signTestElement(t, f.a, mapping.Element())))

	response := &NameIDMappingResponse{}
	require.NoError(t, unmarshalElement(nameIDTestSOAPMessage(t, w, "NameIDMappingResponse"), response))
	checkStatus(t, response.Status, StatusSuccess, "")
	assert.Equal(t, response.InResponseTo, mapping.ID)
	assert.Len(t, f.provider.calls, 1)

	// The provider of this fixture doesn't manage identifiers, which the management service answers.
	el, id := manageNameIDRequestElement(f.test, nameIDMappingTestURL, manageNameIDOptions{})

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, nameIDTestSOAPPost(t, nameIDMappingTestURL, signTestElement(t, f.a, el)))

	managed := &ManageNameIDResponse{}
	require.NoError(t, unmarshalElement(nameIDTestSOAPMessage(t, w, "ManageNameIDResponse"), managed))
	checkStatus(t, managed.Status, StatusResponder, StatusRequestUnsupported)
	assert.Equal(t, managed.InResponseTo, id)

	logout, _ := soapLogoutRequestElement(t, f.a, nil)

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, nameIDTestSOAPPost(t, nameIDMappingTestURL, logout))
	nameIDTestSOAPMessage(t, w, "LogoutResponse")

	// A request of the browser goes to the front-channel service, which refuses this one as it holds no request.
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, nameIDMappingTestURL, nil))
	assert.Equal(t, w.Code, http.StatusBadRequest)
}

// SAMLSec §6.1.2: a request is acted on once. A request that changed an identifier and is presented again after a
// later change would otherwise undo that change.
func TestManageNameIDRefusesReplay(t *testing.T) {
	newID := func(value string) manageNameIDOptions {
		return manageNameIDOptions{mutate: func(request *ManageNameIDRequest) { request.NewID = value }}
	}

	t.Run("soap", func(t *testing.T) {
		test, provider := manageNameIDTestIDP(t)

		store := newRecordingReplayStore()
		test.IDP.ReplayStore = store

		serve := func(el *etree.Element) *ManageNameIDResponse {
			w := httptest.NewRecorder()
			test.IDP.ServeSOAPManageNameID(w, nameIDTestSOAPPost(t, soapManageNameIDTestURL, el))

			response := &ManageNameIDResponse{}
			require.NoError(t, unmarshalElement(nameIDTestSOAPMessage(t, w, "ManageNameIDResponse"), response))

			return response
		}

		older, olderID := manageNameIDRequestElement(test, soapManageNameIDTestURL, newID("alias-one"))
		unsigned := older.Copy()
		older = signTestElement(t, &test.SP, older)

		// A request that isn't verified is not recorded, so nobody else can use up the ID.
		checkStatus(t, serve(unsigned).Status, StatusRequester, StatusRequestDenied)
		assert.Equal(t, store.calls(), 0)

		checkStatus(t, serve(older.Copy()).Status, StatusSuccess, "")
		require.Equal(t, store.calls(), 1)
		assert.True(t, strings.HasPrefix(store.keys[0], replayKindManageNameIDRequest+":"))
		assert.True(t, store.expiries[0].Equal(TimeNow().Add(MaxIssueDelay+2*MaxClockSkew)))

		newer, _ := manageNameIDRequestElement(test, soapManageNameIDTestURL, newID("alias-two"))
		checkStatus(t, serve(signTestElement(t, &test.SP, newer)).Status, StatusSuccess, "")
		require.Len(t, provider.calls, 2)

		// The older request again doesn't bring its identifier back.
		response := serve(older.Copy())
		checkStatus(t, response.Status, StatusRequester, StatusRequestDenied)
		assert.Equal(t, response.InResponseTo, olderID)
		require.Len(t, provider.calls, 2)
		assert.Equal(t, provider.calls[1].SPProvidedID, "alias-two")

		// If the store fails nothing is known about a request, and it is refused.
		store.err = errors.New("store down")

		another, _ := manageNameIDRequestElement(test, soapManageNameIDTestURL, newID("alias-three"))
		checkStatus(t, serve(signTestElement(t, &test.SP, another)).Status, StatusResponder, "")
		assert.Len(t, provider.calls, 2)
	})

	t.Run("redirect", func(t *testing.T) {
		test, provider := manageNameIDTestIDP(t)

		serve := func(u *url.URL, id string) manageNameIDResult {
			w := httptest.NewRecorder()
			test.IDP.ServeManageNameID(w, httptest.NewRequest(http.MethodGet, u.String(), nil))

			result := frontChannelManageNameIDResult(t, w, id)
			require.True(t, result.Response != nil, "HTTP status %d", w.Code)

			return result
		}

		el, olderID := manageNameIDRequestElement(test, manageNameIDTestURL, newID("alias-one"))
		older, err := redirectURL(manageNameIDTestURL, "SAMLRequest", el, "relay", &test.SP)
		require.NoError(t, err)

		checkStatus(t, serve(older, olderID).Response.Status, StatusSuccess, "")

		el, newerID := manageNameIDRequestElement(test, manageNameIDTestURL, newID("alias-two"))
		newer, err := redirectURL(manageNameIDTestURL, "SAMLRequest", el, "relay", &test.SP)
		require.NoError(t, err)

		checkStatus(t, serve(newer, newerID).Response.Status, StatusSuccess, "")

		checkStatus(t, serve(older, olderID).Response.Status, StatusRequester, StatusRequestDenied)
		require.Len(t, provider.calls, 2)
		assert.Equal(t, provider.calls[1].SPProvidedID, "alias-two")
	})
}

// smuggledIssueInstant serializes the signed element el, whose IssueInstant is too old, with a namespace
// declaration that [encoding/xml] reads as a current IssueInstant attribute and that the signature doesn't cover.
func smuggledIssueInstant(t *testing.T, el *etree.Element) []byte {
	t.Helper()

	doc := etree.NewDocument()
	doc.SetRoot(el)

	body, err := doc.WriteToBytes()
	require.NoError(t, err)

	// encoding/xml keeps the last of the two, so the declaration goes at the end of the start tag.
	end := bytes.IndexByte(body, '>')
	now := TimeNow().UTC().Format(timeFormat)

	return append(append(append([]byte{}, body[:end]...), []byte(` xmlns:IssueInstant="`+now+`"`)...), body[end:]...)
}

// nameIDTestSOAPPostBytes returns a SOAP POST to target of an envelope that carries the serialized message.
func nameIDTestSOAPPostBytes(target string, message []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(soapTestEnvelope("", string(message))))
	r.Header.Set("Content-Type", "text/xml")

	return r
}

// Only the content that the signature covers is acted on, not what the message says outside of it.
func TestManageNameIDUsesSignedContent(t *testing.T) {
	old := manageNameIDOptions{mutate: func(request *ManageNameIDRequest) {
		request.IssueInstant = request.IssueInstant.Add(-time.Hour)
	}}

	t.Run("post", func(t *testing.T) {
		test, provider := manageNameIDTestIDP(t)

		el, id := manageNameIDRequestElement(test, manageNameIDTestURL, old)
		body := smuggledIssueInstant(t, signTestElement(t, &test.SP, el))

		form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}}
		r := httptest.NewRequest(http.MethodPost, manageNameIDTestURL, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()
		test.IDP.ServeManageNameID(w, r)

		result := frontChannelManageNameIDResult(t, w, id)
		require.True(t, result.Response != nil, "HTTP status %d", w.Code)
		checkStatus(t, result.Response.Status, StatusRequester, StatusRequestDenied)
		assert.Len(t, provider.calls, 0)
	})

	t.Run("soap", func(t *testing.T) {
		test, provider := manageNameIDTestIDP(t)

		el, _ := manageNameIDRequestElement(test, soapManageNameIDTestURL, old)
		body := smuggledIssueInstant(t, signTestElement(t, &test.SP, el))

		w := httptest.NewRecorder()
		test.IDP.ServeSOAPManageNameID(w, nameIDTestSOAPPostBytes(soapManageNameIDTestURL, body))

		response := &ManageNameIDResponse{}
		require.NoError(t, unmarshalElement(nameIDTestSOAPMessage(t, w, "ManageNameIDResponse"), response))
		checkStatus(t, response.Status, StatusRequester, StatusRequestDenied)
		assert.Len(t, provider.calls, 0)
	})
}
