package saml

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

const nameIDMappingTestURL = "https://idp.example.com/saml/nim"

// nameIDMappingProvider is a NameIDProvider which maps the identifiers it is given, and records the requests it
// is asked about.
type nameIDMappingProvider struct {
	DefaultNameIDProvider

	// mapped is the NameID of each principal for each target, by the value of the identifier of the request
	// and the entity ID of the target.
	mapped map[string]map[string]NameID
	calls  []IdpNameIDMappingRequest
	err    error
}

func (p *nameIDMappingProvider) MapNameID(_ *http.Request, req *IdpNameIDMappingRequest) (*NameID, error) {
	p.calls = append(p.calls, *req)

	if p.err != nil {
		return nil, p.err
	}

	targets, ok := p.mapped[req.Request.NameID.Value]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownPrincipal, req.Request.NameID.Value)
	}

	nameID, ok := targets[req.TargetMetadata.EntityID]
	if !ok {
		return nil, fmt.Errorf("%w: no identifier for the target", ErrInvalidNameIDPolicy)
	}

	return &nameID, nil
}

// nameIDMappingFixture is an identity provider with a name identifier mapping service, the requester A, which
// may map to the service provider B, and C, which nobody may map to.
type nameIDMappingFixture struct {
	test     *IdentityProviderTest
	provider *nameIDMappingProvider
	a, b, c  *ServiceProvider
}

func newNameIDMappingFixture(t *testing.T) *nameIDMappingFixture {
	t.Helper()

	test := signatureTestIDP(t)
	test.IDP.Observer = logObserver(io.Discard)
	test.IDP.NameIDMappingURL = mustParseURL(nameIDMappingTestURL)

	f := &nameIDMappingFixture{test: test, a: &test.SP}

	other := func(name string) *ServiceProvider {
		sp := test.SP
		sp.MetadataURL = mustParseURL("https://" + name + ".example.com/saml2/metadata")
		sp.AcsURL = mustParseURL("https://" + name + ".example.com/saml2/acs")
		sp.Key, sp.Certificate = propagationServiceProviderKey(t)

		return &sp
	}

	f.b, f.c = other("sp-b"), other("sp-c")

	f.provider = &nameIDMappingProvider{mapped: map[string]map[string]NameID{
		"p-alice": {
			f.a.MetadataURL.String(): {Format: string(EmailAddressNameIDFormat), Value: "alice@example.com"},
			f.b.MetadataURL.String(): {Format: string(PersistentNameIDFormat), Value: "b-alice", SPProvidedID: "b-alias"},
			f.c.MetadataURL.String(): {Format: string(PersistentNameIDFormat), Value: "c-alice"},
		},
	}}
	test.IDP.NameIDProvider = f.provider
	test.IDP.NameIDMappingPolicy = DefaultNameIDMappingPolicy{Targets: map[string][]string{
		f.a.MetadataURL.String(): {f.b.MetadataURL.String()},
	}}

	for _, sp := range []*ServiceProvider{f.a, f.b, f.c} {
		sp.IDPMetadata = test.IDP.Metadata()
	}

	nameIDTestServiceProviders(test, nil, f.a, f.b, f.c)

	return f
}

// nameIDMappingOptions change the NameIDMappingRequest that a test sends.
type nameIDMappingOptions struct {
	// mutate changes the request before it is serialized.
	mutate func(*NameIDMappingRequest)

	// mutateEl changes the element of the request before it is signed.
	mutateEl func(*etree.Element)

	// signer signs the request in place of A.
	signer *ServiceProvider

	// unsigned leaves the request unsigned.
	unsigned bool
}

// nameIDMappingResult is the answer of the identity provider to a NameIDMappingRequest.
type nameIDMappingResult struct {
	// Response is the response, from the content that the signature of the identity provider covers.
	Response *NameIDMappingResponse

	// Element is that content.
	Element *etree.Element

	// RequestID is the ID of the request.
	RequestID string
}

// send sends the NameIDMappingRequest of A for the identifier that p-alice has at B, as the options change it.
func (f *nameIDMappingFixture) send(t *testing.T, opts nameIDMappingOptions) nameIDMappingResult {
	t.Helper()

	target := f.b.MetadataURL.String()

	request := &NameIDMappingRequest{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		Version:      "2.0",
		IssueInstant: TimeNow(),
		Destination:  nameIDMappingTestURL,
		Issuer:       &Issuer{Format: string(EntityNameIDFormat), Value: f.a.MetadataURL.String()},
		NameID:       testNameID(f.test, f.a),
		NameIDPolicy: &NameIDPolicy{SPNameQualifier: &target},
	}

	if opts.mutate != nil {
		opts.mutate(request)
	}

	el := request.Element()

	if opts.mutateEl != nil {
		opts.mutateEl(el)
	}

	el = signTestElement(t, testSigner(f.a, opts.signer, opts.unsigned), el)

	w := httptest.NewRecorder()
	f.test.IDP.ServeNameIDMapping(w, nameIDTestSOAPPost(t, nameIDMappingTestURL, el))

	result := nameIDMappingResult{RequestID: request.ID, Response: &NameIDMappingResponse{}}

	// SAMLProfiles §7.3.2: the response is signed.
	result.Element = nameIDTestSOAPMessage(t, w, "NameIDMappingResponse")
	assert.NilError(t, unmarshalElement(result.Element, result.Response))

	// SAMLProfiles §7.4.2.
	assert.Check(t, is.Equal(result.Response.Version, "2.0"))
	assert.Assert(t, result.Response.Issuer != nil)
	assert.Check(t, is.Equal(result.Response.Issuer.Value, f.test.IDP.MetadataURL.String()))
	assert.Check(t, is.Equal(result.Response.Issuer.Format, string(EntityNameIDFormat)))
	assert.Check(t, is.Equal(result.Response.Destination, ""))

	return result
}

// checkNoIdentifier checks that the response has the error status and holds no identifier, but the empty NameID
// that the schema of SAMLCore §3.8.2 requires in its place.
func (result nameIDMappingResult) checkNoIdentifier(t *testing.T, top, second string) {
	t.Helper()

	checkStatus(t, result.Response.Status, top, second)

	assert.Check(t, result.Element.FindElement("./EncryptedID") == nil)

	nameIDs := result.Element.FindElements("./NameID")
	if assert.Check(t, is.Len(nameIDs, 1)) {
		assert.Check(t, is.Equal(nameIDs[0].Text(), ""))

		// The verified content declares its namespaces on each element; a NameID has no other attribute.
		for _, attr := range nameIDs[0].Attr {
			assert.Check(t, attr.Space == "xmlns" || attr.Key == "xmlns", "attribute %s", attr.Key)
		}
	}

	assert.Check(t, !strings.Contains(elementToString(result.Element), "alice"))
}

// SAMLCore §3.8 and SAMLProfiles §7.4.2, §7.5: the mapped identifier is encrypted to the service provider that it
// is for, which the requester is not.
func TestNameIDMappingAllowed(t *testing.T) {
	f := newNameIDMappingFixture(t)

	result := f.send(t, nameIDMappingOptions{})
	checkStatus(t, result.Response.Status, StatusSuccess, "")
	assert.Check(t, is.Equal(result.Response.InResponseTo, result.RequestID))

	// SAMLCore §3.8.2: the status and then the identifier, which is only there as a ciphertext.
	assert.Check(t, is.DeepEqual(childTags(result.Element), []string{"Issuer", "Status", "EncryptedID"}))
	assert.Check(t, !strings.Contains(elementToString(result.Element), "alice"))
	assert.Check(t, !strings.Contains(elementToString(result.Element), "b-alias"))

	encryptedID := result.Element.FindElement("./EncryptedID")
	assert.Check(t, is.Equal(encryptedID.NamespaceURI(), samlAssertionNamespace))

	// SAMLCore §2.2.4: the key names the entity it was encrypted for.
	encryptedKey := encryptedID.FindElement("./EncryptedData/KeyInfo/EncryptedKey")
	assert.Assert(t, encryptedKey != nil)
	assert.Check(t, is.Equal(encryptedKey.SelectAttrValue("Recipient", ""), f.b.MetadataURL.String()))

	// The target decrypts it with the code of the library's own service provider.
	nameID, err := f.b.DecryptNameID(reparse(t, encryptedID))
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(*nameID, NameID{
		Format:          string(PersistentNameIDFormat),
		NameQualifier:   f.test.IDP.MetadataURL.String(),
		SPNameQualifier: f.b.MetadataURL.String(),
		SPProvidedID:    "b-alias",
		Value:           "b-alice",
	}))

	// The requester can't.
	_, err = f.a.DecryptNameID(reparse(t, encryptedID))
	assert.Check(t, err != nil)

	assert.Assert(t, is.Len(f.provider.calls, 1))

	call := f.provider.calls[0]
	assert.Check(t, is.Equal(call.ServiceProviderMetadata.EntityID, f.a.MetadataURL.String()))
	assert.Check(t, is.Equal(call.TargetMetadata.EntityID, f.b.MetadataURL.String()))
	assert.Check(t, is.DeepEqual(*call.Request.NameID, *testNameID(f.test, f.a)))
	assert.Check(t, is.Equal(call.Format, ""))
	assert.Check(t, !call.AllowCreate)
	assert.Check(t, !call.NameIDEncrypted)
	assert.Check(t, !call.Unidentified)
}

// The NameIDPolicy states the format, and whether an identifier may be created (SAMLCore §3.4.1.1).
func TestNameIDMappingPolicyAttributes(t *testing.T) {
	for name, tc := range map[string]struct {
		format string
		want   string
	}{
		"persistent":  {string(PersistentNameIDFormat), string(PersistentNameIDFormat)},
		"unspecified": {string(UnspecifiedNameIDFormat), ""},
		// The encrypted format asks for an EncryptedID, which every response holds, of any format.
		"encrypted": {string(EncryptedNameIDFormat), ""},
	} {
		t.Run(name, func(t *testing.T) {
			f := newNameIDMappingFixture(t)

			result := f.send(t, nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) {
				allowCreate := true
				request.NameIDPolicy.Format, request.NameIDPolicy.AllowCreate = &tc.format, &allowCreate
			}})
			checkStatus(t, result.Response.Status, StatusSuccess, "")

			assert.Assert(t, is.Len(f.provider.calls, 1))
			assert.Check(t, is.Equal(f.provider.calls[0].Format, tc.want))
			assert.Check(t, f.provider.calls[0].AllowCreate)
		})
	}
}

// A requester that names no SPNameQualifier asks for its own identifier in another format, which the policy must
// allow like any other, and which is encrypted to the requester.
func TestNameIDMappingToRequester(t *testing.T) {
	f := newNameIDMappingFixture(t)

	self := func(request *NameIDMappingRequest) {
		format := string(EmailAddressNameIDFormat)
		request.NameIDPolicy = &NameIDPolicy{Format: &format}
	}

	f.send(t, nameIDMappingOptions{mutate: self}).checkNoIdentifier(t, StatusRequester, StatusInvalidNameIDPolicy)
	assert.Check(t, is.Len(f.provider.calls, 0))

	f.test.IDP.NameIDMappingPolicy = DefaultNameIDMappingPolicy{Targets: map[string][]string{
		f.a.MetadataURL.String(): {f.a.MetadataURL.String()},
	}}

	result := f.send(t, nameIDMappingOptions{mutate: self})
	checkStatus(t, result.Response.Status, StatusSuccess, "")

	nameID, err := f.a.DecryptNameID(reparse(t, result.Element.FindElement("./EncryptedID")))
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(*nameID, NameID{
		Format:          string(EmailAddressNameIDFormat),
		NameQualifier:   f.test.IDP.MetadataURL.String(),
		SPNameQualifier: f.a.MetadataURL.String(),
		Value:           "alice@example.com",
	}))
}

// The principal may be identified with an EncryptedID (SAMLCore §3.8.1).
func TestNameIDMappingWithEncryptedID(t *testing.T) {
	f := newNameIDMappingFixture(t)

	result := f.send(t, nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) {
		var err error

		request.EncryptedID, err = idpEncrypter(t, f.test).encryptNameID(request.NameID)
		assert.NilError(t, err)
	}})
	checkStatus(t, result.Response.Status, StatusSuccess, "")

	nameID, err := f.b.DecryptNameID(reparse(t, result.Element.FindElement("./EncryptedID")))
	assert.NilError(t, err)
	assert.Check(t, is.Equal(nameID.Value, "b-alice"))

	assert.Assert(t, is.Len(f.provider.calls, 1))
	assert.Check(t, f.provider.calls[0].NameIDEncrypted)
	assert.Check(t, is.DeepEqual(*f.provider.calls[0].Request.NameID, *testNameID(f.test, f.a)))
}

// Nothing is mapped that the policy doesn't allow, and the answer doesn't tell why: whether the target exists,
// has a key, or is only not allowed (SAMLCore §3.8.3).
func TestNameIDMappingDenied(t *testing.T) {
	target := func(entityID string) func(*NameIDMappingRequest) {
		return func(request *NameIDMappingRequest) { request.NameIDPolicy.SPNameQualifier = &entityID }
	}

	for name, tc := range map[string]struct {
		configure func(f *nameIDMappingFixture)
		mutate    func(f *nameIDMappingFixture) func(*NameIDMappingRequest)
	}{
		"no policy": {
			configure: func(f *nameIDMappingFixture) { f.test.IDP.NameIDMappingPolicy = nil },
		},
		"empty policy": {
			configure: func(f *nameIDMappingFixture) { f.test.IDP.NameIDMappingPolicy = DefaultNameIDMappingPolicy{} },
		},
		"another target": {
			mutate: func(f *nameIDMappingFixture) func(*NameIDMappingRequest) { return target(f.c.MetadataURL.String()) },
		},
		"another requester": {
			configure: func(f *nameIDMappingFixture) {
				f.test.IDP.NameIDMappingPolicy = DefaultNameIDMappingPolicy{Targets: map[string][]string{
					f.c.MetadataURL.String(): {f.b.MetadataURL.String()},
				}}
			},
		},
		"unknown target": {
			mutate: func(*nameIDMappingFixture) func(*NameIDMappingRequest) {
				return target("https://unknown.example.com/metadata")
			},
		},
		"allowed target without an encryption key": {
			configure: func(f *nameIDMappingFixture) {
				nameIDTestServiceProviders(f.test, func(metadata *EntityDescriptor) {
					if metadata.EntityID != f.b.MetadataURL.String() {
						return
					}

					descriptor := &metadata.SPSSODescriptors[0]
					descriptor.KeyDescriptors = descriptor.KeyDescriptors[1:]
				}, f.a, f.b, f.c)
			},
		},
		"allowed target whose encryption key is refused": {
			configure: func(f *nameIDMappingFixture) {
				f.test.IDP.EncryptionCertificateEnforcer = DefaultEncryptionCertificateEnforcer{MinimumRSAKeySize: 4096}
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newNameIDMappingFixture(t)

			if tc.configure != nil {
				tc.configure(f)
			}

			opts := nameIDMappingOptions{}
			if tc.mutate != nil {
				opts.mutate = tc.mutate(f)
			}

			f.send(t, opts).checkNoIdentifier(t, StatusRequester, StatusInvalidNameIDPolicy)

			// The principal is not even looked up.
			assert.Check(t, is.Len(f.provider.calls, 0))
		})
	}
}

// A custom policy is asked with the requester and the target.
type recordingMappingPolicy struct {
	requester, target string
	allow             bool
}

func (p *recordingMappingPolicy) AllowNameIDMapping(_ *http.Request, requester, target *EntityDescriptor) bool {
	p.requester, p.target = requester.EntityID, target.EntityID

	return p.allow
}

func TestNameIDMappingCustomPolicy(t *testing.T) {
	f := newNameIDMappingFixture(t)

	policy := &recordingMappingPolicy{}
	f.test.IDP.NameIDMappingPolicy = policy

	f.send(t, nameIDMappingOptions{}).checkNoIdentifier(t, StatusRequester, StatusInvalidNameIDPolicy)
	assert.Check(t, is.Equal(policy.requester, f.a.MetadataURL.String()))
	assert.Check(t, is.Equal(policy.target, f.b.MetadataURL.String()))

	policy.allow = true

	checkStatus(t, f.send(t, nameIDMappingOptions{}).Response.Status, StatusSuccess, "")
}

// An identifier that the requester doesn't share with the identity provider is answered as an unknown principal
// is, whatever the reason, so that an EncryptedID that can't be decrypted is not told apart (errata E93).
func TestNameIDMappingUnknownPrincipal(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate       func(t *testing.T, f *nameIDMappingFixture, request *NameIDMappingRequest)
		calls        int
		unidentified bool
	}{
		"unknown to the provider": {
			mutate: func(_ *testing.T, _ *nameIDMappingFixture, request *NameIDMappingRequest) {
				request.NameID.Value = "p-mallory"
			},
			calls: 1,
		},
		"encrypted to another key": {
			mutate: func(t *testing.T, f *nameIDMappingFixture, request *NameIDMappingRequest) {
				var err error

				request.EncryptedID, err = otherKeyEncrypter(t, f.test).encryptNameID(request.NameID)
				assert.NilError(t, err)
			},
			calls: 1, unidentified: true,
		},
		"encrypted identifier of another service provider": {
			mutate: func(t *testing.T, f *nameIDMappingFixture, request *NameIDMappingRequest) {
				request.NameID.SPNameQualifier = f.c.MetadataURL.String()

				var err error

				request.EncryptedID, err = idpEncrypter(t, f.test).encryptNameID(request.NameID)
				assert.NilError(t, err)
			},
			calls: 1, unidentified: true,
		},
		"identifier of another service provider": {
			mutate: func(_ *testing.T, f *nameIDMappingFixture, request *NameIDMappingRequest) {
				request.NameID.SPNameQualifier = f.c.MetadataURL.String()
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newNameIDMappingFixture(t)

			f.send(t, nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) {
				tc.mutate(t, f, request)
			}}).checkNoIdentifier(t, StatusRequester, StatusUnknownPrincipal)

			assert.Assert(t, is.Len(f.provider.calls, tc.calls))

			if tc.calls != 0 {
				assert.Check(t, is.Equal(f.provider.calls[0].Unidentified, tc.unidentified))
			}

			if tc.unidentified {
				assert.Check(t, f.provider.calls[0].Request.NameID.Value != "p-alice")
			}
		})
	}
}

// What a provider answers for a request that names nobody is ignored: nothing is mapped.
func TestNameIDMappingUnidentifiedIsNeverMapped(t *testing.T) {
	f := newNameIDMappingFixture(t)
	f.provider.mapped = nil
	f.provider.err = nil

	always := &alwaysMappingProvider{}
	f.test.IDP.NameIDProvider = always

	f.send(t, nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) {
		var err error

		request.EncryptedID, err = otherKeyEncrypter(t, f.test).encryptNameID(request.NameID)
		assert.NilError(t, err)
	}}).checkNoIdentifier(t, StatusRequester, StatusUnknownPrincipal)
	assert.Check(t, is.Equal(always.calls, 1))
}

// alwaysMappingProvider maps every identifier, even one that names nobody.
type alwaysMappingProvider struct {
	DefaultNameIDProvider
	calls  int
	nameID NameID
}

func (p *alwaysMappingProvider) MapNameID(*http.Request, *IdpNameIDMappingRequest) (*NameID, error) {
	p.calls++

	if p.nameID.Value == "" {
		return &NameID{Format: string(PersistentNameIDFormat), Value: "b-alice"}, nil
	}

	nameID := p.nameID

	return &nameID, nil
}

// Transient identifiers can be mapped from, unlike in the Name Identifier Management protocol.
func TestNameIDMappingFromTransient(t *testing.T) {
	f := newNameIDMappingFixture(t)
	f.provider.mapped["t-1234"] = f.provider.mapped["p-alice"]

	result := f.send(t, nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) {
		request.NameID.Format, request.NameID.Value = string(TransientNameIDFormat), "t-1234"
	}})
	checkStatus(t, result.Response.Status, StatusSuccess, "")
}

// Without a NameIDMappingProvider the protocol is not supported, and not advertised.
func TestNameIDMappingWithoutProvider(t *testing.T) {
	f := newNameIDMappingFixture(t)

	assert.Check(t, is.DeepEqual(f.test.IDP.Metadata().IDPSSODescriptors[0].NameIDMappingServices, []Endpoint{
		{Binding: SOAPBinding, Location: nameIDMappingTestURL},
	}))
	assert.Check(t, is.Len(f.test.IDP.Metadata().IDPSSODescriptors[0].ManageNameIDServices, 0))

	f.test.IDP.NameIDProvider = nil

	f.send(t, nameIDMappingOptions{}).checkNoIdentifier(t, StatusResponder, StatusRequestUnsupported)
	assert.Check(t, is.Len(f.test.IDP.Metadata().IDPSSODescriptors[0].NameIDMappingServices, 0))

	// A service that refuses everything is not advertised either.
	f.test.IDP.NameIDProvider = f.provider
	f.test.IDP.NameIDMappingPolicy = nil
	assert.Check(t, is.Len(f.test.IDP.Metadata().IDPSSODescriptors[0].NameIDMappingServices, 0))

	f.test.IDP.NameIDMappingPolicy = DefaultNameIDMappingPolicy{}
	f.test.IDP.NameIDMappingURL = mustParseURL("")
	assert.Check(t, is.Len(f.test.IDP.Metadata().IDPSSODescriptors[0].NameIDMappingServices, 0))
}

// What the provider returns is checked against what was requested and allowed.
func TestNameIDMappingProviderResult(t *testing.T) {
	for name, tc := range map[string]struct {
		err         error
		nameID      NameID
		format      string
		top, second string
	}{
		"failure":                  {err: errors.New("the database is down: secret detail"), top: StatusResponder},
		"cannot supply":            {err: fmt.Errorf("nothing to supply: %w", ErrInvalidNameIDPolicy), top: StatusRequester, second: StatusInvalidNameIDPolicy},
		"unknown principal":        {err: ErrUnknownPrincipal, top: StatusRequester, second: StatusUnknownPrincipal},
		"another format":           {nameID: NameID{Format: string(EmailAddressNameIDFormat), Value: "alice@example.com"}, format: string(PersistentNameIDFormat), top: StatusResponder},
		"the encrypted format":     {nameID: NameID{Format: string(EncryptedNameIDFormat), Value: "b-alice"}, top: StatusResponder},
		"another service provider": {nameID: NameID{Format: string(PersistentNameIDFormat), Value: "c-alice", SPNameQualifier: "https://sp-c.example.com/saml2/metadata"}, top: StatusResponder},
	} {
		t.Run(name, func(t *testing.T) {
			f := newNameIDMappingFixture(t)

			if tc.err != nil {
				f.provider.err = tc.err
			} else {
				f.test.IDP.NameIDProvider = &alwaysMappingProvider{nameID: tc.nameID}
			}

			f.send(t, nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) {
				if tc.format != "" {
					request.NameIDPolicy.Format = &tc.format
				}
			}}).checkNoIdentifier(t, tc.top, tc.second)
		})
	}

	t.Run("nil", func(t *testing.T) {
		f := newNameIDMappingFixture(t)
		f.test.IDP.NameIDProvider = nilMappingProvider{}

		f.send(t, nameIDMappingOptions{}).checkNoIdentifier(t, StatusRequester, StatusUnknownPrincipal)
	})
}

type nilMappingProvider struct{ DefaultNameIDProvider }

func (nilMappingProvider) MapNameID(*http.Request, *IdpNameIDMappingRequest) (*NameID, error) {
	return nil, nil
}

// A request whose requester isn't verified is answered with RequestDenied, and nothing is looked up
// (SAMLProfiles §7.3.1).
func TestNameIDMappingRejectsUnauthenticatedRequests(t *testing.T) {
	for name, options := range map[string]func(t *testing.T, f *nameIDMappingFixture) nameIDMappingOptions{
		"unsigned": func(*testing.T, *nameIDMappingFixture) nameIDMappingOptions {
			return nameIDMappingOptions{unsigned: true}
		},
		// B is a registered service provider, but not the issuer.
		"signed by another service provider": func(_ *testing.T, f *nameIDMappingFixture) nameIDMappingOptions {
			return nameIDMappingOptions{signer: f.b}
		},
		"unknown service provider": func(*testing.T, *nameIDMappingFixture) nameIDMappingOptions {
			return nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) {
				request.Issuer.Value = "https://unknown.example.com/metadata"
			}}
		},
		"no issuer": func(*testing.T, *nameIDMappingFixture) nameIDMappingOptions {
			return nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) { request.Issuer = nil }}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newNameIDMappingFixture(t)

			f.send(t, options(t, f)).checkNoIdentifier(t, StatusRequester, StatusRequestDenied)
			assert.Check(t, is.Len(f.provider.calls, 0))
		})
	}
}

func TestNameIDMappingRejectsAlteredRequest(t *testing.T) {
	f := newNameIDMappingFixture(t)

	// The policy would allow a mapping to C, which the signed request doesn't ask for.
	f.test.IDP.NameIDMappingPolicy = DefaultNameIDMappingPolicy{Targets: map[string][]string{
		f.a.MetadataURL.String(): {f.b.MetadataURL.String(), f.c.MetadataURL.String()},
	}}

	target := f.b.MetadataURL.String()
	request := &NameIDMappingRequest{
		ID:           "id-altered",
		Version:      "2.0",
		IssueInstant: TimeNow(),
		Issuer:       &Issuer{Value: f.a.MetadataURL.String()},
		NameID:       testNameID(f.test, f.a),
		NameIDPolicy: &NameIDPolicy{SPNameQualifier: &target},
	}

	el := signTestElement(t, f.a, request.Element())
	el.FindElement("./NameIDPolicy").CreateAttr("SPNameQualifier", f.c.MetadataURL.String())

	w := httptest.NewRecorder()
	f.test.IDP.ServeNameIDMapping(w, nameIDTestSOAPPost(t, nameIDMappingTestURL, el))

	response := &NameIDMappingResponse{}
	assert.NilError(t, unmarshalElement(nameIDTestSOAPMessage(t, w, "NameIDMappingResponse"), response))
	checkStatus(t, response.Status, StatusRequester, StatusRequestDenied)
	assert.Check(t, is.Len(f.provider.calls, 0))
}

func TestNameIDMappingRequestStatus(t *testing.T) {
	for name, tc := range map[string]struct {
		options     nameIDMappingOptions
		top, second string
	}{
		"wrong destination": {
			options: nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) {
				request.Destination = soapManageNameIDTestURL
			}},
			top: StatusRequester, second: StatusRequestDenied,
		},
		"version too low": {
			options: nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) { request.Version = "1.1" }},
			top:     StatusVersionMismatch, second: StatusRequestVersionTooLow,
		},
		"expired": {
			options: nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) {
				request.IssueInstant = TimeNow().Add(-MaxIssueDelay - MaxClockSkew)
			}},
			top: StatusRequester, second: StatusRequestDenied,
		},
		"no NameIDPolicy": {
			options: nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) { request.NameIDPolicy = nil }},
			top:     StatusRequester, second: StatusRequestDenied,
		},
		"no identifier": {
			options: nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) { request.NameID = nil }},
			top:     StatusRequester, second: StatusRequestDenied,
		},
		"BaseID": {
			options: nameIDMappingOptions{
				mutate: func(request *NameIDMappingRequest) { request.NameID = nil },
				mutateEl: func(el *etree.Element) {
					el.InsertChildAt(el.FindElement("./NameIDPolicy").Index(), etree.NewElement("saml:BaseID"))
				},
			},
			top: StatusRequester, second: StatusRequestUnsupported,
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newNameIDMappingFixture(t)

			f.send(t, tc.options).checkNoIdentifier(t, tc.top, tc.second)
			assert.Check(t, is.Len(f.provider.calls, 0))
		})
	}
}

// SAMLBind §3.2 doesn't require a Destination on SOAP.
func TestNameIDMappingWithoutDestination(t *testing.T) {
	f := newNameIDMappingFixture(t)

	result := f.send(t, nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) { request.Destination = "" }})
	checkStatus(t, result.Response.Status, StatusSuccess, "")
}

func TestServeNameIDMappingEnvelope(t *testing.T) {
	f := newNameIDMappingFixture(t)

	t.Run("not a POST", func(t *testing.T) {
		w := httptest.NewRecorder()
		f.test.IDP.ServeNameIDMapping(w, httptest.NewRequest(http.MethodGet, nameIDMappingTestURL, nil))
		assert.Check(t, is.Equal(w.Code, http.StatusMethodNotAllowed))
	})

	t.Run("not an envelope", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, nameIDMappingTestURL, strings.NewReader("<a/>"))
		r.Header.Set("Content-Type", "text/xml")

		w := httptest.NewRecorder()
		f.test.IDP.ServeNameIDMapping(w, r)
		assert.Check(t, is.Equal(soapFaultCode(t, w), "soapenv:Client"))
	})

	t.Run("another message", func(t *testing.T) {
		el, _ := manageNameIDRequestElement(f.test, nameIDMappingTestURL, manageNameIDOptions{})

		w := httptest.NewRecorder()
		f.test.IDP.ServeNameIDMapping(w, nameIDTestSOAPPost(t, nameIDMappingTestURL, signTestElement(t, f.a, el)))

		response := &NameIDMappingResponse{}
		assert.NilError(t, unmarshalElement(nameIDTestSOAPMessage(t, w, "NameIDMappingResponse"), response))
		checkStatus(t, response.Status, StatusRequester, StatusRequestUnsupported)
	})

	t.Run("handler", func(t *testing.T) {
		w := httptest.NewRecorder()
		f.test.IDP.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, nameIDMappingTestURL, nil))
		assert.Check(t, is.Equal(w.Code, http.StatusMethodNotAllowed))
	})

	assert.Check(t, is.Len(f.provider.calls, 0))
}

// Only the content that the signature covers is acted on, not what the message says outside of it.
func TestNameIDMappingUsesSignedContent(t *testing.T) {
	f := newNameIDMappingFixture(t)

	target := f.b.MetadataURL.String()
	request := &NameIDMappingRequest{
		ID:           "id-old",
		Version:      "2.0",
		IssueInstant: TimeNow().Add(-time.Hour),
		Issuer:       &Issuer{Value: f.a.MetadataURL.String()},
		NameID:       testNameID(f.test, f.a),
		NameIDPolicy: &NameIDPolicy{SPNameQualifier: &target},
	}

	body := smuggledIssueInstant(t, signTestElement(t, f.a, request.Element()))

	w := httptest.NewRecorder()
	f.test.IDP.ServeNameIDMapping(w, nameIDTestSOAPPostBytes(nameIDMappingTestURL, body))

	response := &NameIDMappingResponse{}
	assert.NilError(t, unmarshalElement(nameIDTestSOAPMessage(t, w, "NameIDMappingResponse"), response))
	checkStatus(t, response.Status, StatusRequester, StatusRequestDenied)
	assert.Check(t, is.Len(f.provider.calls, 0))
}

// SAMLSec §6.1.2: a request is answered once.
func TestNameIDMappingRefusesReplay(t *testing.T) {
	f := newNameIDMappingFixture(t)

	store := newRecordingReplayStore()
	f.test.IDP.ReplayStore = store

	target := f.b.MetadataURL.String()

	request := &NameIDMappingRequest{
		ID:           "id-mapping-request",
		Version:      "2.0",
		IssueInstant: TimeNow(),
		Destination:  nameIDMappingTestURL,
		Issuer:       &Issuer{Format: string(EntityNameIDFormat), Value: f.a.MetadataURL.String()},
		NameID:       testNameID(f.test, f.a),
		NameIDPolicy: &NameIDPolicy{SPNameQualifier: &target},
	}

	serve := func(el *etree.Element) nameIDMappingResult {
		w := httptest.NewRecorder()
		f.test.IDP.ServeNameIDMapping(w, nameIDTestSOAPPost(t, nameIDMappingTestURL, el))

		result := nameIDMappingResult{RequestID: request.ID, Response: &NameIDMappingResponse{}}
		result.Element = nameIDTestSOAPMessage(t, w, "NameIDMappingResponse")
		assert.NilError(t, unmarshalElement(result.Element, result.Response))

		return result
	}

	signed := signTestElement(t, f.a, request.Element())

	// A request that isn't verified is not recorded.
	serve(request.Element()).checkNoIdentifier(t, StatusRequester, StatusRequestDenied)
	assert.Check(t, is.Equal(store.calls(), 0))

	result := serve(signed.Copy())
	checkStatus(t, result.Response.Status, StatusSuccess, "")
	assert.Check(t, result.Element.FindElement("./EncryptedID") != nil)
	assert.Assert(t, is.Equal(store.calls(), 1))
	assert.Check(t, strings.HasPrefix(store.keys[0], replayKindNameIDMappingRequest+":"))
	assert.Check(t, is.Len(f.provider.calls, 1))

	// The same request again gets no identifier, and the provider is not asked.
	result = serve(signed.Copy())
	result.checkNoIdentifier(t, StatusRequester, StatusRequestDenied)
	assert.Check(t, is.Equal(result.Response.InResponseTo, request.ID))
	assert.Check(t, is.Len(f.provider.calls, 1))

	// If the store fails nothing is known about a request, and it is refused.
	store.err = errors.New("store down")
	request.ID = "id-another-request"

	serve(signTestElement(t, f.a, request.Element())).checkNoIdentifier(t, StatusResponder, "")
	assert.Check(t, is.Len(f.provider.calls, 1))
}
