package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// encryptedLogoutBindings are the ways a service provider sends a LogoutRequest to the identity provider. Each
// returns the status of the LogoutResponse.
var encryptedLogoutBindings = map[string]func(t *testing.T, test *IdentityProviderTest, mutate func(*LogoutRequest)) Status{
	"redirect": func(t *testing.T, test *IdentityProviderTest, mutate func(*LogoutRequest)) Status {
		r, _ := redirectLogoutRequest(t, &test.SP, mutate)
		_, response := redirectedLogoutResponse(t, serveSLO(test, r))

		return response.Status
	},
	"post": func(t *testing.T, test *IdentityProviderTest, mutate func(*LogoutRequest)) Status {
		r, _ := postLogoutRequest(t, &test.SP, mutate)
		_, _, response := postedLogoutResponse(t, serveSLO(test, r))

		return response.Status
	},
	"soap": func(t *testing.T, test *IdentityProviderTest, mutate func(*LogoutRequest)) Status {
		r, _ := soapLogoutRequest(t, &test.SP, mutate)

		return soapLogoutResponse(t, serveSOAPLogout(test, r)).Status
	},
}

// encryptedLogoutIDP returns an identity provider with front-channel and SOAP logout, and a service provider which
// identifies the principal of its LogoutRequests with an EncryptedID.
func encryptedLogoutIDP(t *testing.T) (*IdentityProviderTest, *logoutSessionProvider) {
	t.Helper()

	test, provider := soapLogoutTestIDP(t)
	test.SP.EncryptNameID = true

	return test, provider
}

// flipCipherValue changes one bit of the ciphertext of the EncryptedID of a request.
func flipCipherValue(t *testing.T) func(*LogoutRequest) {
	t.Helper()

	return func(request *LogoutRequest) {
		value := request.EncryptedID.FindElement("./EncryptedData/CipherData/CipherValue")
		assert.Assert(t, value != nil)

		buf, err := base64.StdEncoding.DecodeString(value.Text())
		assert.NilError(t, err)

		buf[len(buf)-1] ^= 0x01
		value.SetText(base64.StdEncoding.EncodeToString(buf))
	}
}

func TestServeLogoutRequestWithEncryptedID(t *testing.T) {
	for name, send := range encryptedLogoutBindings {
		t.Run(name, func(t *testing.T) {
			test, provider := encryptedLogoutIDP(t)

			status := send(t, test, func(request *LogoutRequest) {
				// SAMLCore §3.7.1: the EncryptedID is in the place of the NameID.
				assert.Check(t, request.NameID == nil)
				assert.Check(t, request.EncryptedID != nil)
				assert.Check(t, !strings.Contains(elementToString(request.Element()), "alice"))
			})
			assert.Check(t, is.Equal(StatusSuccess, status.StatusCode.Value))
			assert.Check(t, status.StatusCode.StatusCode == nil)

			assert.Assert(t, is.Len(provider.lookups, 1))

			request := provider.lookups[0]
			assert.Check(t, request.NameIDEncrypted)
			assert.Check(t, !request.Unidentified)
			assert.Assert(t, request.Request.NameID != nil)
			assert.Check(t, is.DeepEqual(NameID{
				Format:          string(TransientNameIDFormat),
				NameQualifier:   test.IDP.Metadata().EntityID,
				SPNameQualifier: test.SP.MetadataURL.String(),
				Value:           "alice",
			}, *request.Request.NameID))
			assert.Check(t, is.Len(provider.terminated, 1))
		})
	}
}

// The decrypted NameID is matched like one that was sent in plaintext (SAMLProfiles §4.4.4.1).
func TestLogoutRequestWithEncryptedIDMatchesSession(t *testing.T) {
	test, provider := encryptedLogoutIDP(t)
	session := &Session{ID: "session-one", NameID: "alice", NameIDFormat: string(TransientNameIDFormat), Index: "index-one"}

	encryptedLogoutBindings["post"](t, test, nil)
	assert.Assert(t, is.Len(provider.lookups, 1))

	assert.NilError(t, provider.lookups[0].MatchesSession(provider.lookups[0].HTTPRequest, session))

	other := *session
	other.NameID = "bob"
	assert.Check(t, is.ErrorContains(provider.lookups[0].MatchesSession(provider.lookups[0].HTTPRequest, &other), "the NameID value is not that of the session"))
}

// An EncryptedID that can't be decrypted must be answered exactly as a NameID which names no session is, so that
// the requester learns nothing about a ciphertext from how the identity provider answers (errata E93).
func TestServeLogoutRequestWithUndecryptableEncryptedID(t *testing.T) {
	// cbc returns a mutation which replaces the EncryptedID with one that is encrypted with AES-128-CBC.
	cbc := func(t *testing.T, test *IdentityProviderTest) func(*LogoutRequest) {
		t.Helper()

		return func(request *LogoutRequest) {
			encrypter := &elementEncrypter{certificate: test.Certificate, encrypter: testElementEncrypter(t, method(aes128CBC)).encrypter}

			encryptedID, err := encrypter.encryptNameID(&NameID{Value: "alice"})
			assert.NilError(t, err)

			request.EncryptedID = encryptedID
		}
	}

	for name, tc := range map[string]struct {
		configure func(*IdentityProviderTest)
		mutate    func(*testing.T, *IdentityProviderTest) func(*LogoutRequest)
	}{
		"tampered ciphertext": {
			mutate: func(t *testing.T, _ *IdentityProviderTest) func(*LogoutRequest) { return flipCipherValue(t) },
		},
		"encrypted to another key": {
			mutate: func(t *testing.T, _ *IdentityProviderTest) func(*LogoutRequest) {
				return func(request *LogoutRequest) {
					encryptedID, err := testElementEncrypter(t, method(aes128GCM)).encryptNameID(&NameID{Value: "alice"})
					assert.NilError(t, err)

					request.EncryptedID = encryptedID
				}
			},
		},
		"algorithm the identity provider does not allow": {
			configure: func(test *IdentityProviderTest) { test.IDP.ContentEncryptionMethods = []string{aes128GCM} },
			mutate:    cbc,
		},
		"identity provider with only a signer": {
			configure: func(test *IdentityProviderTest) { test.IDP.Signer, test.IDP.Key = test.Key.(crypto.Signer), nil },
		},
		"not a name id": {
			mutate: func(t *testing.T, test *IdentityProviderTest) func(*LogoutRequest) {
				return func(request *LogoutRequest) {
					encrypter := &elementEncrypter{certificate: test.Certificate, encrypter: testElementEncrypter(t).encrypter}

					encryptedID, err := encrypter.encrypt("EncryptedID", (&Issuer{Value: "alice"}).Element())
					assert.NilError(t, err)

					request.EncryptedID = encryptedID
				}
			},
		},
	} {
		for binding, send := range encryptedLogoutBindings {
			t.Run(name+"/"+binding, func(t *testing.T) {
				// The answer to a NameID in plaintext which names no session.
				unknownTest, unknownProvider := soapLogoutTestIDP(t)
				unknownProvider.sessions = nil
				unknown := send(t, unknownTest, nil)

				test, provider := encryptedLogoutIDP(t)
				if tc.configure != nil {
					tc.configure(test)
				}

				var mutate func(*LogoutRequest)
				if tc.mutate != nil {
					mutate = tc.mutate(t, test)
				}

				status := send(t, test, mutate)
				assert.Check(t, is.DeepEqual(unknown, status))
				assert.Check(t, status.StatusMessage == nil)
				assert.Check(t, status.StatusDetail == nil)

				// The provider is asked, as it is for a NameID which names nobody, with an identifier that isn't
				// alice's. The session that it returns for any request is left alone.
				assert.Check(t, is.Len(unknownProvider.lookups, 1))
				assert.Assert(t, is.Len(provider.lookups, 1))
				assert.Check(t, provider.lookups[0].Unidentified)
				assert.Assert(t, provider.lookups[0].Request.NameID != nil)
				assert.Check(t, len(provider.lookups[0].Request.NameID.Value) >= 43)
				assert.Check(t, is.Len(provider.terminated, 0))
			})
		}
	}

	// The algorithm is what the policy refused: the same EncryptedID is accepted when CBC is allowed.
	t.Run("cbc is accepted by default", func(t *testing.T) {
		test, provider := encryptedLogoutIDP(t)

		encryptedLogoutBindings["post"](t, test, cbc(t, test))
		assert.Assert(t, is.Len(provider.lookups, 1))
		assert.Check(t, is.Equal("alice", provider.lookups[0].Request.NameID.Value))
	})
}

func TestUnidentifiedLogoutRequestMatchesNoSession(t *testing.T) {
	test, _ := encryptedLogoutIDP(t)

	r, _ := postLogoutRequest(t, &test.SP, flipCipherValue(t))
	req, err := NewIdpLogoutRequest(&test.IDP, r)
	assert.NilError(t, err)
	assert.NilError(t, req.Validate())

	assert.Check(t, req.Unidentified)
	assert.Check(t, req.NameIDEncrypted)

	// The NameID is a stand-in, so that a provider which reads it finds nobody.
	assert.Assert(t, req.Request.NameID != nil)
	assert.Check(t, req.Request.NameID.Value != "alice")

	// The request is validated again, which only an identity provider that has not seen it does.
	test.IDP.ReplayStore = NewMemoryReplayStore(0)

	other, err := NewIdpLogoutRequest(&test.IDP, r)
	assert.NilError(t, err)
	assert.NilError(t, other.Validate())
	assert.Check(t, other.Request.NameID.Value != req.Request.NameID.Value)

	// Not even the session of its stand-in, when only values are compared.
	test.IDP.LogoutNameIDValueOnly = true
	err = req.MatchesSession(r, &Session{ID: "s", NameID: req.Request.NameID.Value, NameIDFormat: string(TransientNameIDFormat)})
	assert.Check(t, is.ErrorContains(err, "the EncryptedID of the request could not be decrypted"))
}

// SAMLCore §3.7.1 has a choice of one identifier.
func TestLogoutRequestWithNameIDAndEncryptedIDIsInvalid(t *testing.T) {
	test, _ := encryptedLogoutIDP(t)

	request, err := test.SP.MakeLogoutRequest(logoutTestSLOURL, "alice")
	assert.NilError(t, err)

	el := request.Element()
	el.InsertChildAt(el.FindElement("./EncryptedID").Index(), (&NameID{Value: "bob"}).Element())

	req := &IdpLogoutRequest{IDP: &test.IDP, verifiedEl: reparse(t, el)}
	assert.NilError(t, unmarshalElement(req.verifiedEl, &req.Request))
	assert.Check(t, is.ErrorContains(req.identifyPrincipal(), "request has both a NameID and an EncryptedID"))
	assert.Check(t, is.Equal("bob", req.Request.NameID.Value))

	// Neither is as invalid as it was.
	req = &IdpLogoutRequest{IDP: &test.IDP, verifiedEl: etree.NewElement("LogoutRequest")}
	assert.Check(t, is.ErrorContains(req.identifyPrincipal(), "request has no NameID"))
}

// sentLogoutRequestElement returns the LogoutRequest that the identity provider sent to sp at location, as
// sentLogoutRequest returns it, after verifying the signature of the identity provider.
func sentLogoutRequestElement(t *testing.T, sp *ServiceProvider, location *url.URL) *etree.Element {
	t.Helper()

	certificates, err := sp.getIDPSigningCerts()
	assert.NilError(t, err)

	encoded, err := base64.StdEncoding.DecodeString(location.Query().Get("SAMLRequest"))
	assert.NilError(t, err)

	doc := etree.NewDocument()

	if location.Query().Has("SigAlg") {
		assert.NilError(t, verifyRedirectSignature(location.RawQuery, "SAMLRequest", certificates))

		buf, err := io.ReadAll(flate.NewReader(bytes.NewReader(encoded)))
		assert.NilError(t, err)
		assert.NilError(t, doc.ReadFromBytes(buf))

		return doc.Root()
	}

	assert.NilError(t, doc.ReadFromBytes(encoded))

	verified, err := verifyEnvelopedSignature(doc.Root(), certificates)
	assert.NilError(t, err)

	return verified
}

// checkEncryptedLogoutRequest checks that the LogoutRequest el identifies alice to sp with an EncryptedID only.
func checkEncryptedLogoutRequest(t *testing.T, test *IdentityProviderTest, sp *ServiceProvider, el *etree.Element) {
	t.Helper()

	assert.Check(t, el.FindElement("./NameID") == nil)
	assert.Check(t, !strings.Contains(elementToString(el), "alice"))

	encryptedID, err := findOneChild(el, samlAssertionNamespace, "EncryptedID")
	assert.NilError(t, err)
	assert.Check(t, is.Equal(sp.MetadataURL.String(), encryptedID.FindElement("./EncryptedData/KeyInfo/EncryptedKey").SelectAttrValue("Recipient", "")))
	assert.Check(t, is.Equal(aes128GCM, encryptedID.FindElement("./EncryptedData/EncryptionMethod").SelectAttrValue("Algorithm", "")))

	// SAMLCore §3.7.1: the identifier precedes the SessionIndex.
	sessionIndex := el.FindElement("./SessionIndex")
	assert.Assert(t, sessionIndex != nil)
	assert.Check(t, encryptedID.Index() < sessionIndex.Index())

	nameID, err := sp.DecryptNameID(encryptedID)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(NameID{
		Format:          string(PersistentNameIDFormat),
		Value:           "alice",
		NameQualifier:   test.IDP.Metadata().EntityID,
		SPNameQualifier: sp.MetadataURL.String(),
	}, *nameID))
}

// encryptParticipants marks the participants of the session of f as having been asserted an EncryptedID.
func (f *propagationFixture) encryptParticipants(entityIDs ...string) {
	participants := f.provider.participants[f.session.ID]

	for i := range participants {
		for _, entityID := range entityIDs {
			if participants[i].ServiceProviderEntityID == entityID {
				participants[i].NameIDEncrypted = true
			}
		}
	}
}

func TestLogoutRequestToParticipantWithEncryptedID(t *testing.T) {
	for _, binding := range []string{HTTPRedirectBinding, HTTPPostBinding} {
		t.Run(binding, func(t *testing.T) {
			f := newPropagationFixture(t)
			f.a.LogoutBindings = []string{binding}
			f.encryptParticipants(f.a.MetadataURL.String())

			location := sentLogoutRequest(t, f.startLogout(t))
			checkEncryptedLogoutRequest(t, f.test, f.a, sentLogoutRequestElement(t, f.a, location))
		})
	}

	t.Run(SOAPBinding, func(t *testing.T) {
		f, _, recorder := newSOAPLogoutFixture(t, nil)
		f.encryptParticipants(f.b.MetadataURL.String())

		state := f.sendToB(t)
		assert.Check(t, is.Equal(LogoutOutcomeSuccess, state.Participants[0].Outcome), state.Participants[0].Reason)
		assert.Check(t, state.Participants[0].NameIDEncrypted)

		received := recorder.Received()
		assert.Assert(t, is.Len(received, 1))
		assert.Check(t, received[0].Request.NameID == nil)
		checkEncryptedLogoutRequest(t, f.test, f.b, received[0].Element)
	})
}

// A participant that was asserted its NameID in plaintext is still sent it in plaintext.
func TestLogoutRequestToParticipantWithoutEncryptedID(t *testing.T) {
	f := newPropagationFixture(t)
	f.encryptParticipants(f.b.MetadataURL.String())

	el := sentLogoutRequestElement(t, f.a, sentLogoutRequest(t, f.startLogout(t)))
	assert.Check(t, el.FindElement("./EncryptedID") == nil)
	assert.Check(t, is.Equal("alice", el.FindElement("./NameID").Text()))
}

// The NameID that was kept from intermediaries at login is not shown to them at logout: a participant which can
// no longer be encrypted to is skipped, and the logout is partial.
func TestLogoutRequestToParticipantWithoutEncryptionKeyIsSkipped(t *testing.T) {
	t.Run("front channel", func(t *testing.T) {
		f := newPropagationFixture(t)
		f.encryptParticipants(f.a.MetadataURL.String())

		// The metadata of A now has a key for signing only.
		metadata := f.a.Metadata()
		for i := range metadata.SPSSODescriptors[0].KeyDescriptors {
			metadata.SPSSODescriptors[0].KeyDescriptors[i].Use = "signing"
		}

		inner := f.test.IDP.ServiceProviderProvider
		f.test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
			GetServiceProviderFunc: func(r *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
				if serviceProviderID == metadata.EntityID {
					return metadata, nil
				}

				return inner.GetServiceProvider(r, serviceProviderID)
			},
		}

		// The first request goes to B, as none was sent to A.
		location := sentLogoutRequest(t, f.startLogout(t))
		assert.Check(t, is.Equal(f.b.SloURL.Host, location.Host))

		state, err := f.provider.LoadLogoutState(httptest.NewRequest(http.MethodGet, "/", nil), location.Query().Get("RelayState"))
		assert.NilError(t, err)
		assert.Check(t, is.Equal(LogoutOutcomeSkipped, state.Participants[0].Outcome))
		assert.Check(t, is.Contains(state.Participants[0].Reason, "cannot encrypt the NameID of the logout request"))
	})

	t.Run("soap", func(t *testing.T) {
		f, _, recorder := newSOAPLogoutFixture(t, nil)
		f.encryptParticipants(f.b.MetadataURL.String())
		f.b.Certificate = nil

		state := f.sendToB(t)
		assert.Check(t, is.Equal(LogoutOutcomeSkipped, state.Participants[0].Outcome))
		assert.Check(t, is.Contains(state.Participants[0].Reason, "has no encryption key"))
		assert.Check(t, is.Len(recorder.Received(), 0))
		assert.Check(t, state.result().Partial())
	})
}

func TestNewLogoutStateKeepsNameIDEncrypted(t *testing.T) {
	nameID := NameID{Format: string(PersistentNameIDFormat), Value: "alice"}
	now := time.Unix(1000, 0)

	state := newLogoutState(&IdentityProvider{}, []SessionParticipant{
		{ServiceProviderEntityID: "https://a.example.com", NameID: nameID, SessionIndex: "1", IssueInstant: now},
		{ServiceProviderEntityID: "https://a.example.com", NameID: nameID, SessionIndex: "2", IssueInstant: now.Add(time.Second), NameIDEncrypted: true},
		{ServiceProviderEntityID: "https://b.example.com", NameID: nameID, SessionIndex: "1", IssueInstant: now.Add(2 * time.Second)},
	}, "")

	assert.Assert(t, is.Len(state.Participants, 2))

	// One request names the principal to A, and it must not show what any assertion to A hid.
	assert.Check(t, state.Participants[0].NameIDEncrypted)
	assert.Check(t, !state.Participants[1].NameIDEncrypted)
}
