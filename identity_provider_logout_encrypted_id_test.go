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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		require.NotNil(t, value)

		buf, err := base64.StdEncoding.DecodeString(value.Text())
		require.NoError(t, err)

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
				assert.Nil(t, request.NameID)
				assert.NotNil(t, request.EncryptedID)
				assert.False(t, strings.Contains(elementToString(request.Element()), "alice"))
			})
			assert.Equal(t, StatusSuccess, status.StatusCode.Value)
			assert.Nil(t, status.StatusCode.StatusCode)

			require.Len(t, provider.lookups, 1)

			request := provider.lookups[0]
			assert.True(t, request.NameIDEncrypted)
			assert.False(t, request.Unidentified)
			require.NotNil(t, request.Request.NameID)
			assert.Equal(t, NameID{
				Format:          string(TransientNameIDFormat),
				NameQualifier:   test.IDP.Metadata().EntityID,
				SPNameQualifier: test.SP.MetadataURL.String(),
				Value:           "alice",
			}, *request.Request.NameID)
			assert.Len(t, provider.terminated, 1)
		})
	}
}

// The decrypted NameID is matched like one that was sent in plaintext (SAMLProfiles §4.4.4.1).
func TestLogoutRequestWithEncryptedIDMatchesSession(t *testing.T) {
	test, provider := encryptedLogoutIDP(t)
	session := &Session{ID: "session-one", NameID: "alice", NameIDFormat: string(TransientNameIDFormat), Index: "index-one"}

	encryptedLogoutBindings["post"](t, test, nil)
	require.Len(t, provider.lookups, 1)

	require.NoError(t, provider.lookups[0].MatchesSession(provider.lookups[0].HTTPRequest, session))

	other := *session
	other.NameID = "bob"
	assert.ErrorContains(t, provider.lookups[0].MatchesSession(provider.lookups[0].HTTPRequest, &other), "the NameID value is not that of the session")
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
			require.NoError(t, err)

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
					require.NoError(t, err)

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
					require.NoError(t, err)

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
				assert.Equal(t, unknown, status)
				assert.True(t, statusSaysNothingOfTheRequest(status))
				assert.Nil(t, status.StatusDetail)

				// The provider is asked, as it is for a NameID which names nobody, with an identifier that isn't
				// alice's. The session that it returns for any request is left alone.
				assert.Len(t, unknownProvider.lookups, 1)
				require.Len(t, provider.lookups, 1)
				assert.True(t, provider.lookups[0].Unidentified)
				require.NotNil(t, provider.lookups[0].Request.NameID)
				assert.True(t, len(provider.lookups[0].Request.NameID.Value) >= 43)
				assert.Len(t, provider.terminated, 0)
			})
		}
	}

	// The algorithm is what the policy refused: the same EncryptedID is accepted when CBC is allowed.
	t.Run("cbc is accepted by default", func(t *testing.T) {
		test, provider := encryptedLogoutIDP(t)

		encryptedLogoutBindings["post"](t, test, cbc(t, test))
		require.Len(t, provider.lookups, 1)
		assert.Equal(t, "alice", provider.lookups[0].Request.NameID.Value)
	})
}

func TestUnidentifiedLogoutRequestMatchesNoSession(t *testing.T) {
	test, _ := encryptedLogoutIDP(t)

	r, _ := postLogoutRequest(t, &test.SP, flipCipherValue(t))
	req, err := NewIdpLogoutRequest(&test.IDP, r)
	require.NoError(t, err)
	require.NoError(t, req.Validate())

	assert.True(t, req.Unidentified)
	assert.True(t, req.NameIDEncrypted)

	// The NameID is a stand-in, so that a provider which reads it finds nobody.
	require.NotNil(t, req.Request.NameID)
	assert.True(t, req.Request.NameID.Value != "alice")

	// The request is validated again, which only an identity provider that has not seen it does.
	test.IDP.ReplayStore = NewMemoryReplayStore(0)

	other, err := NewIdpLogoutRequest(&test.IDP, r)
	require.NoError(t, err)
	require.NoError(t, other.Validate())
	assert.True(t, other.Request.NameID.Value != req.Request.NameID.Value)

	// Not even the session of its stand-in, when only values are compared.
	test.IDP.LogoutNameIDValueOnly = true
	err = req.MatchesSession(r, &Session{ID: "s", NameID: req.Request.NameID.Value, NameIDFormat: string(TransientNameIDFormat)})
	assert.ErrorContains(t, err, "the EncryptedID of the request could not be decrypted")
}

// SAMLCore §3.7.1 has a choice of one identifier.
func TestLogoutRequestWithNameIDAndEncryptedIDIsInvalid(t *testing.T) {
	test, _ := encryptedLogoutIDP(t)

	request, err := test.SP.MakeLogoutRequest(logoutTestSLOURL, "alice")
	require.NoError(t, err)

	el := request.Element()
	el.InsertChildAt(el.FindElement("./EncryptedID").Index(), (&NameID{Value: "bob"}).Element())

	req := &IdpLogoutRequest{IDP: &test.IDP, verifiedEl: reparse(t, el)}
	require.NoError(t, unmarshalElement(req.verifiedEl, &req.Request))
	assert.ErrorContains(t, req.identifyPrincipal(), "request has both a NameID and an EncryptedID")
	assert.Equal(t, "bob", req.Request.NameID.Value)

	// Neither is as invalid as it was.
	req = &IdpLogoutRequest{IDP: &test.IDP, verifiedEl: etree.NewElement("LogoutRequest")}
	assert.ErrorContains(t, req.identifyPrincipal(), "request has no NameID")
}

// sentLogoutRequestElement returns the LogoutRequest that the identity provider sent to sp at location, as
// sentLogoutRequest returns it, after verifying the signature of the identity provider.
func sentLogoutRequestElement(t *testing.T, sp *ServiceProvider, location *url.URL) *etree.Element {
	t.Helper()

	certificates, err := sp.getIDPSigningCerts()
	require.NoError(t, err)

	encoded, err := base64.StdEncoding.DecodeString(location.Query().Get("SAMLRequest"))
	require.NoError(t, err)

	doc := etree.NewDocument()

	if location.Query().Has("SigAlg") {
		require.NoError(t, verifyRedirectSignature(location.RawQuery, "SAMLRequest", certificates, anySignaturePolicy))

		buf, err := io.ReadAll(flate.NewReader(bytes.NewReader(encoded)))
		require.NoError(t, err)
		require.NoError(t, doc.ReadFromBytes(buf))

		return doc.Root()
	}

	require.NoError(t, doc.ReadFromBytes(encoded))

	verified, err := verifyEnvelopedSignature(doc.Root(), certificates, anySignaturePolicy)
	require.NoError(t, err)

	return verified
}

// checkEncryptedLogoutRequest checks that the LogoutRequest el identifies alice to sp with an EncryptedID only.
func checkEncryptedLogoutRequest(t *testing.T, test *IdentityProviderTest, sp *ServiceProvider, el *etree.Element) {
	t.Helper()

	assert.Nil(t, el.FindElement("./NameID"))
	assert.False(t, strings.Contains(elementToString(el), "alice"))

	encryptedID, err := findOneChild(el, samlAssertionNamespace, "EncryptedID")
	require.NoError(t, err)
	assert.Equal(t, sp.MetadataURL.String(), encryptedID.FindElement("./EncryptedData/KeyInfo/EncryptedKey").SelectAttrValue("Recipient", ""))
	assert.Equal(t, aes128GCM, encryptedID.FindElement("./EncryptedData/EncryptionMethod").SelectAttrValue("Algorithm", ""))

	// SAMLCore §3.7.1: the identifier precedes the SessionIndex.
	sessionIndex := el.FindElement("./SessionIndex")
	require.NotNil(t, sessionIndex)
	assert.True(t, encryptedID.Index() < sessionIndex.Index())

	nameID, err := sp.DecryptNameID(encryptedID)
	require.NoError(t, err)
	assert.Equal(t, NameID{
		Format:          string(PersistentNameIDFormat),
		Value:           "alice",
		NameQualifier:   test.IDP.Metadata().EntityID,
		SPNameQualifier: sp.MetadataURL.String(),
	}, *nameID)
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
		assert.Equal(t, LogoutOutcomeSuccess, state.Participants[0].Outcome, state.Participants[0].Reason)
		assert.True(t, state.Participants[0].NameIDEncrypted)

		received := recorder.Received()
		require.Len(t, received, 1)
		assert.Nil(t, received[0].Request.NameID)
		checkEncryptedLogoutRequest(t, f.test, f.b, received[0].Element)
	})
}

// A participant that was asserted its NameID in plaintext is still sent it in plaintext.
func TestLogoutRequestToParticipantWithoutEncryptedID(t *testing.T) {
	f := newPropagationFixture(t)
	f.encryptParticipants(f.b.MetadataURL.String())

	el := sentLogoutRequestElement(t, f.a, sentLogoutRequest(t, f.startLogout(t)))
	assert.Nil(t, el.FindElement("./EncryptedID"))
	assert.Equal(t, "alice", el.FindElement("./NameID").Text())
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
		assert.Equal(t, f.b.SloURL.Host, location.Host)

		state, err := f.provider.LoadLogoutState(httptest.NewRequest(http.MethodGet, "/", nil), location.Query().Get("RelayState"))
		require.NoError(t, err)
		assert.Equal(t, LogoutOutcomeSkipped, state.Participants[0].Outcome)
		assert.Contains(t, state.Participants[0].Reason, "cannot encrypt the NameID of the logout request")
	})

	t.Run("soap", func(t *testing.T) {
		f, _, recorder := newSOAPLogoutFixture(t, nil)
		f.encryptParticipants(f.b.MetadataURL.String())
		f.b.Certificate = nil

		state := f.sendToB(t)
		assert.Equal(t, LogoutOutcomeSkipped, state.Participants[0].Outcome)
		assert.Contains(t, state.Participants[0].Reason, "has no encryption key")
		assert.Len(t, recorder.Received(), 0)
		assert.True(t, state.result().Partial())
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

	require.Len(t, state.Participants, 2)

	// One request names the principal to A, and it must not show what any assertion to A hid.
	assert.True(t, state.Participants[0].NameIDEncrypted)
	assert.False(t, state.Participants[1].NameIDEncrypted)
}
