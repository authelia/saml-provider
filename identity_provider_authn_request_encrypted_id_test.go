package saml

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml/internal/dsig"
)

// encryptedSubjectFixture is an identity provider with a session for alice, and a service provider which signs
// its requests and has an encryption key.
type encryptedSubjectFixture struct {
	test *IdentityProviderTest

	// requests are the requests that the SessionProvider was asked for a session for.
	requests []*IdpAuthnRequest

	// metadata changes the metadata of the service provider, if it is not nil.
	metadata func(*EntityDescriptor)
}

func newEncryptedSubjectFixture(t *testing.T) *encryptedSubjectFixture {
	t.Helper()

	f := &encryptedSubjectFixture{test: signatureTestIDP(t)}

	f.test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(_ http.ResponseWriter, _ *http.Request, req *IdpAuthnRequest) *Session {
			f.requests = append(f.requests, req)

			return subjectSession()
		},
	}
	f.test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			if serviceProviderID != f.test.SP.MetadataURL.String() {
				return nil, os.ErrNotExist
			}

			metadata := f.test.SP.Metadata()
			if f.metadata != nil {
				f.metadata(metadata)
			}

			return metadata, nil
		},
	}

	return f
}

// alice is the NameID that the assertion for the session of the fixture has when the format is left open.
func (f *encryptedSubjectFixture) alice() *NameID {
	return &NameID{Format: string(EmailAddressNameIDFormat), Value: "alice"}
}

// requestElement returns the element of an unsigned request of the service provider on binding, with no
// NameIDPolicy and with a Subject that has the identifiers.
func (f *encryptedSubjectFixture) requestElement(t *testing.T, binding string, identifiers ...*etree.Element) *etree.Element {
	t.Helper()

	unsigned := f.test.SP
	unsigned.SignatureMethod = ""

	request, err := unsigned.MakeAuthenticationRequest(signatureTestSSOURL, binding, HTTPPostBinding)
	assert.NilError(t, err)

	request.NameIDPolicy = nil
	request.Subject = &Subject{}

	el := request.Element()

	subject := el.FindElement("./Subject")
	assert.Assert(t, subject != nil)

	for _, identifier := range identifiers {
		subject.AddChild(identifier)
	}

	return el
}

// encrypted returns an EncryptedID of nameID to the identity provider.
func (f *encryptedSubjectFixture) encrypted(t *testing.T, nameID *NameID) *etree.Element {
	t.Helper()

	encryptedID, err := idpEncrypter(t, f.test).encryptNameID(nameID)
	assert.NilError(t, err)

	return encryptedID
}

// allowUnsigned makes the metadata of the service provider not declare that its requests are signed, after the
// change that the fixture already makes to it.
func (f *encryptedSubjectFixture) allowUnsigned() {
	edit := f.metadata

	f.metadata = func(metadata *EntityDescriptor) {
		if edit != nil {
			edit(metadata)
		}

		metadata.SPSSODescriptors[0].AuthnRequestsSigned = nil
	}
}

// post serves the request element on the HTTP-POST binding, with an enveloped signature if signed.
func (f *encryptedSubjectFixture) post(t *testing.T, el *etree.Element, signed bool) *httptest.ResponseRecorder {
	t.Helper()

	if signed {
		signingContext, err := GetSigningContext(&f.test.SP)
		assert.NilError(t, err)

		el, err = signingContext.SignEnveloped(el)
		assert.NilError(t, err)
	}

	doc := etree.NewDocument()
	doc.SetRoot(el)

	body, err := doc.WriteToBytes()
	assert.NilError(t, err)

	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}}
	r := httptest.NewRequest(http.MethodPost, signatureTestSSOURL, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	f.test.IDP.ServeSSO(w, r)

	return w
}

// redirect serves the request element on the HTTP-Redirect binding, with a signature in the query if signed.
func (f *encryptedSubjectFixture) redirect(t *testing.T, el *etree.Element, signed bool) *httptest.ResponseRecorder {
	t.Helper()

	sp := f.test.SP
	if !signed {
		sp.SignatureMethod = ""
	}

	u, err := redirectURL(signatureTestSSOURL, "SAMLRequest", el, "relay", &sp)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(u.Query().Has("Signature"), signed))

	w := httptest.NewRecorder()
	f.test.IDP.ServeSSO(w, httptest.NewRequest(http.MethodGet, u.String(), nil))

	return w
}

// encryptedSubjectBindings are the browser bindings of a signed request.
var encryptedSubjectBindings = []struct {
	name  string
	serve func(*encryptedSubjectFixture, *testing.T, *etree.Element, bool) *httptest.ResponseRecorder
}{
	{HTTPPostBinding, (*encryptedSubjectFixture).post},
	{HTTPRedirectBinding, (*encryptedSubjectFixture).redirect},
}

// unidentified returns the debug messages of the EventPrincipalUnidentified events.
func (f *encryptedSubjectFixture) unidentified() []string {
	events := eventsOfKind(f.test.Events, EventPrincipalUnidentified)
	reasons := make([]string, 0, len(events))

	for _, event := range events {
		reasons = append(reasons, event.Err.Debug())
	}

	return reasons
}

func assertSubjectStatus(t *testing.T, w *httptest.ResponseRecorder, top, second string) {
	t.Helper()

	response := subjectResponse(t, w)
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, top))
	assert.Assert(t, response.Status.StatusCode.StatusCode != nil)
	assert.Check(t, is.Equal(response.Status.StatusCode.StatusCode.Value, second))
	assert.Check(t, response.Assertion == nil)
	assert.Check(t, response.EncryptedAssertion == nil)
}

// sentAssertionEl returns the assertion that req was answered with, as the service provider decrypts it.
func sentAssertionEl(t *testing.T, test *IdentityProviderTest, req *IdpAuthnRequest) *etree.Element {
	t.Helper()

	assert.Assert(t, req.AssertionEl != nil)
	assert.Assert(t, is.Equal(req.AssertionEl.Tag, "EncryptedAssertion"))

	assertionEl, err := test.SP.decryptElement(req.AssertionEl)
	assert.NilError(t, err)

	return assertionEl
}

// assertEncryptedIDIssued checks that req was answered with an assertion whose Subject is an EncryptedID that the
// service provider decrypts to the NameID of the session.
func assertEncryptedIDIssued(t *testing.T, test *IdentityProviderTest, req *IdpAuthnRequest) {
	t.Helper()

	assertionEl := sentAssertionEl(t, test, req)

	subjectEl := assertionEl.FindElement("./Subject")
	assert.Assert(t, subjectEl != nil)
	assert.Check(t, subjectEl.FindElement("./NameID") == nil)
	assert.Check(t, !strings.Contains(elementToString(assertionEl), "alice"))

	encryptedID := subjectEl.FindElement("./EncryptedID")
	assert.Assert(t, encryptedID != nil)

	decrypted, err := test.SP.DecryptNameID(encryptedID)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(decrypted.Value, "alice"))
	assert.Check(t, is.Equal(decrypted.Format, string(EmailAddressNameIDFormat)))
}

// A signed request may name the principal with an EncryptedID (SAMLCore §3.4.1, §2.2.4), and the assertion then
// carries the identifier as an EncryptedID to the service provider.
func TestServeSSOEncryptedSubject(t *testing.T) {
	for _, binding := range encryptedSubjectBindings {
		t.Run(binding.name, func(t *testing.T) {
			f := newEncryptedSubjectFixture(t)

			el := f.requestElement(t, binding.name, f.encrypted(t, f.alice()))
			assert.Check(t, !strings.Contains(elementToString(el), "alice"))

			var enforced []NameID

			f.test.IDP.SubjectEnforcer = subjectEnforcerFunc(func(req *IdpAuthnRequest, session *Session) error {
				enforced = append(enforced, *req.Request.Subject.NameID)

				return DefaultSubjectEnforcer{}.EnforceSubject(req, session)
			})

			w := binding.serve(f, t, el, true)
			assert.Check(t, is.Equal(subjectResponse(t, w).Status.StatusCode.Value, StatusSuccess))

			// The session provider and the enforcer are given the identifier that was encrypted.
			assert.Assert(t, is.Len(f.requests, 1))

			req := f.requests[0]
			assert.Check(t, req.SubjectEncrypted)
			assert.Assert(t, req.Request.Subject.NameID != nil)
			assert.Check(t, is.DeepEqual(*req.Request.Subject.NameID, *f.alice()))
			assert.Check(t, is.DeepEqual(enforced, []NameID{*f.alice()}))

			assertEncryptedIDIssued(t, f.test, req)
			assert.Check(t, is.Len(f.unidentified(), 0))
		})
	}
}

// The default enforcer compares the assertion with the identifier that was encrypted, so an EncryptedID of another
// principal is refused as a NameID of one is.
func TestServeSSOEncryptedSubjectOfOtherPrincipal(t *testing.T) {
	for _, binding := range encryptedSubjectBindings {
		t.Run(binding.name, func(t *testing.T) {
			f := newEncryptedSubjectFixture(t)

			bob := f.alice()
			bob.Value = "bob"

			w := binding.serve(f, t, f.requestElement(t, binding.name, f.encrypted(t, bob)), true)
			assertAuthnFailed(t, subjectResponse(t, w))
			assert.Check(t, is.Len(f.unidentified(), 0))
		})
	}
}

// A request with a NameID is not one with an encrypted Subject, and its assertion has a NameID.
func TestServeSSOPlainSubjectIsNotEncrypted(t *testing.T) {
	f := newEncryptedSubjectFixture(t)

	w := f.post(t, f.requestElement(t, HTTPPostBinding, f.alice().Element()), true)
	assert.Check(t, is.Equal(subjectResponse(t, w).Status.StatusCode.Value, StatusSuccess))

	assert.Assert(t, is.Len(f.requests, 1))
	assert.Check(t, !f.requests[0].SubjectEncrypted)

	assertionEl := sentAssertionEl(t, f.test, f.requests[0])
	assert.Check(t, assertionEl.FindElement("./Subject/NameID") != nil)
	assert.Check(t, assertionEl.FindElement("./Subject/EncryptedID") == nil)
}

// Nothing is decrypted for a request that is not signed, as the service provider is not known to have sent the
// ciphertext (SAMLCore §6.2, errata E93). It is refused whether or not the EncryptedID could be decrypted.
func TestServeSSOUnsignedEncryptedSubjectIsUnsupported(t *testing.T) {
	for _, binding := range encryptedSubjectBindings {
		for name, encrypter := range map[string]func(*testing.T, *IdentityProviderTest) *elementEncrypter{
			"valid":       idpEncrypter,
			"another key": otherKeyEncrypter,
		} {
			t.Run(binding.name+"/"+name, func(t *testing.T) {
				f := newEncryptedSubjectFixture(t)
				f.allowUnsigned()

				encryptedID, err := encrypter(t, f.test).encryptNameID(f.alice())
				assert.NilError(t, err)

				w := binding.serve(f, t, f.requestElement(t, binding.name, encryptedID), false)
				assertSubjectStatus(t, w, StatusRequester, StatusRequestUnsupported)

				// It is refused before there is a session, and nothing was decrypted that could be reported.
				assert.Check(t, is.Len(f.requests, 0))
				assert.Check(t, is.Len(f.unidentified(), 0))
			})
		}
	}
}

// An EncryptedID can't be answered to a service provider with no encryption key without sending the identifier in
// plaintext, so it is refused before it is decrypted.
func TestServeSSOEncryptedSubjectWithoutEncryptionKey(t *testing.T) {
	for _, binding := range encryptedSubjectBindings {
		t.Run(binding.name, func(t *testing.T) {
			f := newEncryptedSubjectFixture(t)
			f.metadata = withoutEncryptionKey(nil)

			// One that can't be decrypted is refused in the same way, which shows that it isn't tried.
			encryptedID, err := otherKeyEncrypter(t, f.test).encryptNameID(f.alice())
			assert.NilError(t, err)

			for _, identifier := range []*etree.Element{f.encrypted(t, f.alice()), encryptedID} {
				w := binding.serve(f, t, f.requestElement(t, binding.name, identifier), true)
				assertSubjectStatus(t, w, StatusRequester, StatusRequestUnsupported)
			}

			assert.Check(t, is.Len(f.requests, 0))
			assert.Check(t, is.Len(f.unidentified(), 0))
		})
	}
}

// An EncryptedID that names nobody the service provider shares an identifier with is answered as a Subject that
// names another principal, whatever is wrong with it, so that the answer says nothing of what it held (errata
// E93). The reason only goes to the Observer.
func TestServeSSOUnidentifiedEncryptedSubject(t *testing.T) {
	const other = "https://other.example.com/metadata"

	cases := []struct {
		name    string
		encrypt func(*encryptedSubjectFixture, *testing.T) *etree.Element
		reason  string
	}{
		{
			name: "encrypted to another key",
			encrypt: func(f *encryptedSubjectFixture, t *testing.T) *etree.Element {
				encryptedID, err := otherKeyEncrypter(t, f.test).encryptNameID(f.alice())
				assert.NilError(t, err)

				return encryptedID
			},
			reason: "cannot decrypt the EncryptedID",
		},
		{
			name: "SPNameQualifier of another service provider",
			encrypt: func(f *encryptedSubjectFixture, t *testing.T) *etree.Element {
				nameID := f.alice()
				nameID.SPNameQualifier = other

				return f.encrypted(t, nameID)
			},
			reason: "SPNameQualifier of another service provider",
		},
		{
			name: "NameQualifier of another identity provider",
			encrypt: func(f *encryptedSubjectFixture, t *testing.T) *etree.Element {
				return f.encrypted(t, &NameID{Format: string(PersistentNameIDFormat), NameQualifier: other, Value: "alice"})
			},
			reason: "NameQualifier of another identity provider",
		},
		{
			name: "encrypted format",
			encrypt: func(f *encryptedSubjectFixture, t *testing.T) *etree.Element {
				return f.encrypted(t, &NameID{Format: string(EncryptedNameIDFormat), Value: "alice"})
			},
			reason: "encrypted format",
		},
	}

	for _, binding := range encryptedSubjectBindings {
		// What a signed request that names another principal with a NameID is answered with.
		baseline := newEncryptedSubjectFixture(t)
		mismatch := subjectResponse(t, binding.serve(baseline, t,
			baseline.requestElement(t, binding.name, (&NameID{Value: "bob"}).Element()), true))
		assertAuthnFailed(t, mismatch)
		assert.Assert(t, is.Len(baseline.requests, 1))

		for _, tc := range cases {
			t.Run(binding.name+"/"+tc.name, func(t *testing.T) {
				f := newEncryptedSubjectFixture(t)

				// An enforcer that accepts anything is not asked, so it can't accept a principal that
				// is not identified.
				enforced := 0
				f.test.IDP.SubjectEnforcer = subjectEnforcerFunc(func(*IdpAuthnRequest, *Session) error {
					enforced++

					return nil
				})

				w := binding.serve(f, t, f.requestElement(t, binding.name, tc.encrypt(f, t)), true)

				response := subjectResponse(t, w)
				assertAuthnFailed(t, response)
				assert.Check(t, is.DeepEqual(response.Status, mismatch.Status))
				assert.Check(t, statusSaysNothingOfTheRequest(response.Status))
				assert.Check(t, is.Equal(enforced, 0))

				// As for the mismatch, it fails once there is a session, and not before.
				assert.Assert(t, is.Len(f.requests, 1))
				assert.Check(t, f.requests[0].SubjectEncrypted)
				assert.Check(t, f.requests[0].Request.Subject.NameID == nil)

				reasons := f.unidentified()
				assert.Assert(t, is.Len(reasons, 1))
				assert.Check(t, is.Contains(reasons[0], tc.reason))

				var log strings.Builder

				for _, event := range f.test.Events.Events() {
					log.WriteString(event.String() + "\n")
				}

				assert.Check(t, is.Contains(log.String(), string(EventPrincipalUnidentified)))
			})
		}
	}
}

// SAMLCore §3.4.1 and §2.4.1.1: a Subject has one identifier. This doesn't depend on a signature, and comes before
// anything is decrypted.
func TestServeSSOSubjectIdentifierRules(t *testing.T) {
	baseID := func() *etree.Element {
		el := etree.NewElement("saml:BaseID")
		el.CreateAttr("NameQualifier", "https://idp.example.com/saml/metadata")

		return el
	}

	for _, binding := range encryptedSubjectBindings {
		for _, signed := range []bool{false, true} {
			name := binding.name + "/unsigned"
			if signed {
				name = binding.name + "/signed"
			}

			t.Run(name, func(t *testing.T) {
				f := newEncryptedSubjectFixture(t)
				if !signed {
					f.allowUnsigned()
				}

				for _, tc := range []struct {
					name        string
					identifiers []*etree.Element
					second      string
				}{
					{"EncryptedID beside NameID", []*etree.Element{f.alice().Element(), f.encrypted(t, f.alice())}, StatusRequestDenied},
					{"two EncryptedIDs", []*etree.Element{f.encrypted(t, f.alice()), f.encrypted(t, f.alice())}, StatusRequestDenied},
					{"two NameIDs", []*etree.Element{f.alice().Element(), f.alice().Element()}, StatusRequestDenied},
					{"BaseID beside NameID", []*etree.Element{baseID(), f.alice().Element()}, StatusRequestDenied},
					{"BaseID", []*etree.Element{baseID()}, StatusRequestUnsupported},
				} {
					w := binding.serve(f, t, f.requestElement(t, binding.name, tc.identifiers...), signed)
					assertSubjectStatus(t, w, StatusRequester, tc.second)
				}

				assert.Check(t, is.Len(f.requests, 0))
				assert.Check(t, is.Len(f.unidentified(), 0))
			})
		}
	}
}

// An EncryptedID that an enveloped signature doesn't cover is not the one that is decrypted: the Subject is read
// from the content that was verified.
func TestServeSSOEncryptedSubjectMustBeSigned(t *testing.T) {
	f := newEncryptedSubjectFixture(t)

	signingContext, err := GetSigningContext(&f.test.SP)
	assert.NilError(t, err)

	signed, err := signingContext.SignEnveloped(f.requestElement(t, HTTPPostBinding, f.alice().Element()))
	assert.NilError(t, err)

	// The NameID that was signed is replaced after the fact.
	subject := signed.FindElement("./Subject")
	subject.RemoveChild(subject.FindElement("./NameID"))
	subject.AddChild(f.encrypted(t, f.alice()))

	doc := etree.NewDocument()
	doc.SetRoot(signed)

	body, err := doc.WriteToBytes()
	assert.NilError(t, err)

	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}}
	r := httptest.NewRequest(http.MethodPost, signatureTestSSOURL, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	f.test.IDP.ServeSSO(w, r)

	assert.Check(t, is.Equal(w.Code, http.StatusBadRequest), "the signature doesn't verify")
	assert.Check(t, is.Len(f.requests, 0))
	assert.Check(t, is.Len(f.unidentified(), 0))
}

// A request of the Enhanced Client or Proxy profile is verified by its enveloped signature like one on HTTP-POST.
func TestServeECPEncryptedSubject(t *testing.T) {
	setup := func(t *testing.T, signed, encryptionKey bool) (*IdentityProviderTest, *ecpSessionProvider, func(*AuthnRequest)) {
		t.Helper()

		test, provider := ecpTestIDP(t, nil)
		test.IDP.Observer = test.Events
		provider.session.NameIDFormat = string(EmailAddressNameIDFormat)

		if signed {
			test.SP.SignatureMethod = dsig.RSASHA256SignatureMethod
		}

		if encryptionKey {
			test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
				GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) {
					metadata := test.SP.Metadata()
					descriptor := &metadata.SPSSODescriptors[0]
					descriptor.AssertionConsumerServices = append(descriptor.AssertionConsumerServices,
						IndexedEndpoint{Binding: PAOSBinding, Location: ecpTestPAOSURL, Index: 3})

					return metadata, nil
				},
			}
		}

		encryptedID, err := idpEncrypter(t, test).encryptNameID(&NameID{Format: string(EmailAddressNameIDFormat), Value: "alice"})
		assert.NilError(t, err)

		return test, provider, func(request *AuthnRequest) {
			request.NameIDPolicy = nil
			request.Subject = &Subject{EncryptedID: encryptedID}
		}
	}

	t.Run("signed", func(t *testing.T) {
		test, provider, mutate := setup(t, true, true)

		w, _ := serveECP(t, test, mutate)
		response := parseECPResponse(t, w)
		assert.Check(t, is.Equal(response.Response.Status.StatusCode.Value, StatusSuccess))

		assert.Assert(t, is.Len(provider.requests, 1))
		assert.Check(t, provider.requests[0].SubjectEncrypted)
		assert.Check(t, is.Equal(provider.requests[0].Request.Subject.NameID.Value, "alice"))
		assertEncryptedIDIssued(t, test, provider.requests[0])
	})

	t.Run("unsigned", func(t *testing.T) {
		test, provider, mutate := setup(t, false, true)

		w, id := serveECP(t, test, mutate)
		assertECPStatus(t, w, id, StatusRequester, StatusRequestUnsupported)
		assert.Check(t, is.Len(provider.requests, 0))
		assert.Check(t, is.Len(eventsOfKind(test.Events, EventPrincipalUnidentified), 0))
	})

	t.Run("no encryption key", func(t *testing.T) {
		test, provider, mutate := setup(t, true, false)

		w, id := serveECP(t, test, mutate)
		assertECPStatus(t, w, id, StatusRequester, StatusRequestUnsupported)
		assert.Check(t, is.Len(provider.requests, 0))
		assert.Check(t, is.Len(eventsOfKind(test.Events, EventPrincipalUnidentified), 0))
	})
}

// The login form re-presents the request, which is validated again, and the EncryptedID is decrypted each time.
func TestEncryptedSubjectSurvivesResume(t *testing.T) {
	f := newEncryptedSubjectFixture(t)

	u, err := redirectURL(signatureTestSSOURL, "SAMLRequest",
		f.requestElement(t, HTTPRedirectBinding, f.encrypted(t, f.alice())), "relay", &f.test.SP)
	assert.NilError(t, err)

	first, err := NewIdpAuthnRequest(&f.test.IDP, httptest.NewRequest(http.MethodGet, u.String(), nil))
	assert.NilError(t, err)
	assert.NilError(t, first.Validate())
	assert.Check(t, first.SubjectEncrypted)

	r := httptest.NewRequest(http.MethodPost, signatureTestSSOURL, strings.NewReader(first.ResumeFormValues().Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	f.test.IDP.ServeSSO(w, r)

	assert.Check(t, is.Equal(subjectResponse(t, w).Status.StatusCode.Value, StatusSuccess))
	assert.Assert(t, is.Len(f.requests, 1))
	assert.Check(t, is.DeepEqual(*f.requests[0].Request.Subject.NameID, *f.alice()))
	assertEncryptedIDIssued(t, f.test, f.requests[0])
}
