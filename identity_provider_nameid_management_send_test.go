package saml

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// manageNameIDSP is a service provider with a ManageNameIDService on the SOAP binding, at an httptest server.
type manageNameIDSP struct {
	mu sync.Mutex

	// requests are the verified requests that the service provider received, and elements the content of
	// each that the signature of the identity provider covers.
	requests []*ManageNameIDRequest
	elements []*etree.Element

	// nameIDs and newIDs are the identifiers of each request, decrypted if they were encrypted.
	nameIDs []*NameID
	newIDs  []string

	// respond changes the unsigned Success response to a request before it is signed and sent, or writes its
	// own answer to w and returns false.
	respond func(w http.ResponseWriter, response *ManageNameIDResponse) bool

	// unsigned leaves the response unsigned.
	unsigned bool
}

// serve makes the ManageNameIDService of the service provider of test the server, which is closed when the test
// ends, and has the identity provider trust its certificate.
func (m *manageNameIDSP) serve(t *testing.T, test *IdentityProviderTest, server *httptest.Server) {
	t.Helper()

	sp := &test.SP

	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, err := m.read(sp, r)
		if err != nil {
			t.Errorf("the service provider could not read the request: %v", err)
			writeSOAPFault(w, &soapFault{Code: "Client", String: soapFaultStringEnvelope})

			return
		}

		response := &ManageNameIDResponse{
			ID:           "id-response",
			InResponseTo: request.ID,
			Version:      "2.0",
			IssueInstant: TimeNow(),
			Issuer:       &Issuer{Format: string(EntityNameIDFormat), Value: sp.MetadataURL.String()},
			Status:       Status{StatusCode: StatusCode{Value: StatusSuccess}},
		}

		if m.respond != nil && !m.respond(w, response) {
			return
		}

		el := response.Element()
		if !m.unsigned {
			el = signTestElement(t, sp, el)
		}

		if err = writeSOAPResponse(w, nil, el); err != nil {
			t.Errorf("the service provider could not write the response: %v", err)
		}
	})

	if server.TLS == nil && server.URL == "" {
		server.StartTLS()
	}

	t.Cleanup(server.Close)

	test.IDP.HTTPClient = server.Client()

	nameIDTestServiceProviders(test, func(metadata *EntityDescriptor) {
		metadata.SPSSODescriptors[0].ManageNameIDServices = []Endpoint{
			{Binding: HTTPRedirectBinding, Location: manageNameIDTestSPURL},
			{Binding: SOAPBinding, Location: server.URL + "/saml2/mni"},
		}
	}, sp)
}

// read reads the ManageNameIDRequest of r as sp, verifying that the identity provider signed it, and decrypts
// its identifiers.
func (m *manageNameIDSP) read(sp *ServiceProvider, r *http.Request) (*ManageNameIDRequest, error) {
	if r.Method != http.MethodPost || r.URL.Path != "/saml2/mni" {
		return nil, errors.New("not a POST to the service")
	}

	message, fault := readSOAPRequest(r)
	if fault != nil {
		return nil, errors.New(fault.String)
	}

	certificates, err := sp.getIDPSigningCerts()
	if err != nil {
		return nil, err
	}

	verified, err := verifyEnvelopedSignature(message.Message, certificates, anySignaturePolicy)
	if err != nil {
		return nil, err
	}

	request := &ManageNameIDRequest{}
	if err = unmarshalElement(verified, request); err != nil {
		return nil, err
	}

	nameID, newID := request.NameID, request.NewID

	if encryptedID := verified.FindElement("./EncryptedID"); encryptedID != nil {
		if nameID, err = sp.DecryptNameID(encryptedID); err != nil {
			return nil, err
		}
	}

	if newEncryptedID := verified.FindElement("./NewEncryptedID"); newEncryptedID != nil {
		el, err := sp.elementDecrypter().decrypt(newEncryptedID)
		if err != nil {
			return nil, err
		}

		if el.Tag != "NewID" || el.NamespaceURI() != samlProtocolNS {
			return nil, errors.New("the NewEncryptedID does not hold a NewID")
		}

		newID = el.Text()
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.requests, m.elements = append(m.requests, request), append(m.elements, verified)
	m.nameIDs, m.newIDs = append(m.nameIDs, nameID), append(m.newIDs, newID)

	return request, nil
}

// sendManageNameIDFixture returns an identity provider and a service provider with a SOAP ManageNameIDService.
func sendManageNameIDFixture(t *testing.T) (*IdentityProviderTest, *manageNameIDSP, *httptest.Server) {
	t.Helper()

	test, _ := manageNameIDTestIDP(t)
	sp := &manageNameIDSP{}

	server := httptest.NewUnstartedServer(nil)
	sp.serve(t, test, server)

	return test, sp, server
}

func sendManageNameID(test *IdentityProviderTest, change NameIDChange) error {
	return test.IDP.SendManageNameIDRequest(httptest.NewRequest(http.MethodPost, "/admin", nil), test.SP.MetadataURL.String(), change)
}

func TestSendManageNameIDRequestNewID(t *testing.T) {
	test, sp, server := sendManageNameIDFixture(t)

	assert.NilError(t, sendManageNameID(test, NameIDChange{NameID: *testNameID(test, &test.SP), NewID: "p-alice-2"}))

	assert.Assert(t, is.Len(sp.requests, 1))

	request := sp.requests[0]

	// SAMLProfiles §4.5.4.1.
	assert.Check(t, is.Equal(request.Issuer.Value, test.IDP.MetadataURL.String()))
	assert.Check(t, is.Equal(request.Issuer.Format, string(EntityNameIDFormat)))
	assert.Check(t, is.Equal(request.Version, "2.0"))
	assert.Check(t, is.Equal(request.Destination, server.URL+"/saml2/mni"))
	assert.Check(t, is.DeepEqual(*request.NameID, *testNameID(test, &test.SP)))
	assert.Check(t, is.Equal(request.NewID, "p-alice-2"))
	assert.Check(t, !request.Terminate)

	// SAMLCore §3.6.1: the identifier, and then one of the three.
	assert.Check(t, is.DeepEqual(childTags(sp.elements[0]), []string{"Issuer", "NameID", "NewID"}))
}

func TestSendManageNameIDRequestTerminate(t *testing.T) {
	test, sp, _ := sendManageNameIDFixture(t)

	assert.NilError(t, sendManageNameID(test, NameIDChange{NameID: *testNameID(test, &test.SP), Terminate: true}))

	assert.Assert(t, is.Len(sp.requests, 1))
	assert.Check(t, sp.requests[0].Terminate)
	assert.Check(t, sp.elements[0].FindElement("./Terminate") != nil)
	assert.Check(t, sp.elements[0].FindElement("./NewID") == nil)
}

// SAMLProfiles §4.5.5: the identifiers are encrypted to the key of the service provider, which decrypts them.
func TestSendManageNameIDRequestEncrypted(t *testing.T) {
	test, sp, _ := sendManageNameIDFixture(t)

	assert.NilError(t, sendManageNameID(test, NameIDChange{NameID: *testNameID(test, &test.SP), NewID: "p-alice-2", Encrypt: true}))

	assert.Assert(t, is.Len(sp.requests, 1))

	text := elementToString(sp.elements[0])
	assert.Check(t, !strings.Contains(text, "p-alice"))
	assert.Check(t, sp.elements[0].FindElement("./NameID") == nil)
	assert.Check(t, sp.elements[0].FindElement("./NewID") == nil)

	newEncryptedID := sp.elements[0].FindElement("./NewEncryptedID")
	assert.Assert(t, newEncryptedID != nil)
	assert.Check(t, is.Equal(newEncryptedID.NamespaceURI(), samlProtocolNS))

	assert.Check(t, is.DeepEqual(*sp.nameIDs[0], *testNameID(test, &test.SP)))
	assert.Check(t, is.Equal(sp.newIDs[0], "p-alice-2"))

	// A Terminate has no new identifier to encrypt.
	assert.NilError(t, sendManageNameID(test, NameIDChange{NameID: *testNameID(test, &test.SP), Terminate: true, Encrypt: true}))
	assert.Check(t, sp.elements[1].FindElement("./EncryptedID") != nil)
	assert.Check(t, sp.elements[1].FindElement("./Terminate") != nil)
}

// An identifier that must be encrypted and can't be is not sent.
func TestSendManageNameIDRequestCannotEncrypt(t *testing.T) {
	test, sp, _ := sendManageNameIDFixture(t)
	test.IDP.EncryptionKeyEnforcer = nil

	err := sendManageNameID(test, NameIDChange{NameID: *testNameID(test, &test.SP), NewID: "p-alice-2", Encrypt: true})
	assert.Check(t, is.ErrorContains(err, "cannot encrypt the name identifier management request"))
	assert.Check(t, is.Len(sp.requests, 0))
}

func TestSendManageNameIDRequestInvalidChange(t *testing.T) {
	test, sp, _ := sendManageNameIDFixture(t)
	nameID := *testNameID(test, &test.SP)

	transient := nameID
	transient.Format = string(TransientNameIDFormat)

	for name, tc := range map[string]struct {
		change NameIDChange
		err    string
	}{
		"no value":        {NameIDChange{NewID: "x"}, "no value"},
		"neither":         {NameIDChange{NameID: nameID}, "exactly one"},
		"both":            {NameIDChange{NameID: nameID, NewID: "x", Terminate: true}, "exactly one"},
		"transient (E12)": {NameIDChange{NameID: transient, Terminate: true}, "transient"},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Check(t, is.ErrorContains(sendManageNameID(test, tc.change), tc.err))
		})
	}

	assert.Check(t, is.ErrorContains(
		test.IDP.SendManageNameIDRequest(httptest.NewRequest(http.MethodPost, "/admin", nil), "https://unknown.example.com", NameIDChange{NameID: nameID, Terminate: true}),
		"cannot find service provider"))
	assert.Check(t, is.Len(sp.requests, 0))
}

func TestSendManageNameIDRequestStatus(t *testing.T) {
	test, sp, _ := sendManageNameIDFixture(t)
	sp.respond = func(_ http.ResponseWriter, response *ManageNameIDResponse) bool {
		response.Status = Status{
			StatusCode:    StatusCode{Value: StatusRequester, StatusCode: &StatusCode{Value: StatusUnknownPrincipal}},
			StatusMessage: &StatusMessage{Value: "who is this\nFAKE LOG LINE"},
		}

		return true
	}

	err := sendManageNameID(test, NameIDChange{NameID: *testNameID(test, &test.SP), Terminate: true})

	var statusErr *StatusError

	assert.Assert(t, errors.As(err, &statusErr), "%v", err)
	assert.Check(t, errors.Is(err, ErrReceivedStatus))
	assert.Check(t, is.Equal(statusErr.TopLevelField, StatusRequester))
	assert.Check(t, is.Equal(statusErr.SecondLevelField, StatusUnknownPrincipal))

	// What the service provider said is text of another party, so it is only in the debug message.
	assert.Check(t, is.Equal(statusErr.StatusMessageField, ErrReceivedStatus.StatusMessageField))
	assert.Check(t, is.Len(statusErr.StatusDetailField, 0))
	assert.Check(t, is.Contains(statusErr.Debug(), "who is this\nFAKE LOG LINE"))
	assert.Check(t, !strings.ContainsAny(fmt.Sprintf("%+v", err), "\n"))
}

// The response is only believed if it is an answer of the service provider to the request.
func TestSendManageNameIDRequestInvalidResponse(t *testing.T) {
	for name, tc := range map[string]struct {
		respond func(w http.ResponseWriter, response *ManageNameIDResponse) bool
		err     string
	}{
		"for another request": {
			respond: func(_ http.ResponseWriter, response *ManageNameIDResponse) bool {
				response.InResponseTo = "id-other"

				return true
			},
			err: "not to the request",
		},
		"no InResponseTo": {
			respond: func(_ http.ResponseWriter, response *ManageNameIDResponse) bool {
				response.InResponseTo = ""

				return true
			},
			err: "not to the request",
		},
		"from another issuer": {
			respond: func(_ http.ResponseWriter, response *ManageNameIDResponse) bool {
				response.Issuer.Value = "https://other.example.com"

				return true
			},
			err: "not from the service provider",
		},
		"another version": {
			respond: func(_ http.ResponseWriter, response *ManageNameIDResponse) bool {
				response.Version = "1.1"

				return true
			},
			err: "version",
		},
		"expired": {
			respond: func(_ http.ResponseWriter, response *ManageNameIDResponse) bool {
				response.IssueInstant = TimeNow().Add(-MaxIssueDelay - MaxClockSkew)

				return true
			},
			err: "expired",
		},
		"fault": {
			respond: func(w http.ResponseWriter, _ *ManageNameIDResponse) bool {
				writeSOAPFault(w, &soapFault{Code: "Server", String: soapFaultStringProcessing})

				return false
			},
			err: "HTTP status 500",
		},
		"redirect": {
			respond: func(w http.ResponseWriter, _ *ManageNameIDResponse) bool {
				w.Header().Set("Location", "https://elsewhere.example.com/")
				w.WriteHeader(http.StatusFound)

				return false
			},
			err: "HTTP status 302",
		},
		"another message": {
			respond: func(w http.ResponseWriter, _ *ManageNameIDResponse) bool {
				_ = writeSOAPResponse(w, nil, (&LogoutResponse{ID: "id-x", Version: "2.0", IssueInstant: TimeNow()}).Element())

				return false
			},
			err: "invalid name identifier management response",
		},
	} {
		t.Run(name, func(t *testing.T) {
			test, sp, _ := sendManageNameIDFixture(t)
			sp.respond = tc.respond

			err := sendManageNameID(test, NameIDChange{NameID: *testNameID(test, &test.SP), Terminate: true})
			assert.Check(t, is.ErrorContains(err, tc.err))

			assert.Check(t, !errors.Is(err, ErrReceivedStatus))
		})
	}
}

// A response signed with a key that is not the service provider's is refused, even over TLS.
func TestSendManageNameIDRequestBadlySignedResponse(t *testing.T) {
	test, sp, _ := sendManageNameIDFixture(t)

	other := test.SP
	other.Key, other.Certificate = propagationServiceProviderKey(t)

	sp.respond = func(w http.ResponseWriter, response *ManageNameIDResponse) bool {
		_ = writeSOAPResponse(w, nil, signTestElement(t, &other, response.Element()))

		return false
	}

	err := sendManageNameID(test, NameIDChange{NameID: *testNameID(test, &test.SP), Terminate: true})
	assert.Check(t, is.ErrorContains(err, "invalid response signature"))
}

// SAMLProfiles §4.5.3.2: the responder authenticates itself by signing the response or by the binding, which is
// TLS on the connection that the identity provider opened.
func TestSendManageNameIDRequestUnsignedResponse(t *testing.T) {
	t.Run("over TLS", func(t *testing.T) {
		test, sp, _ := sendManageNameIDFixture(t)
		sp.unsigned = true

		assert.NilError(t, sendManageNameID(test, NameIDChange{NameID: *testNameID(test, &test.SP), Terminate: true}))
	})

	t.Run("over http", func(t *testing.T) {
		test, _ := manageNameIDTestIDP(t)
		test.IDP.AllowInsecureServiceProviderEndpoints = true

		sp := &manageNameIDSP{unsigned: true}
		server := httptest.NewUnstartedServer(nil)
		server.Start()
		sp.serve(t, test, server)

		err := sendManageNameID(test, NameIDChange{NameID: *testNameID(test, &test.SP), Terminate: true})
		assert.Check(t, is.ErrorContains(err, "response is not signed"))

		sp.unsigned = false

		assert.NilError(t, sendManageNameID(test, NameIDChange{NameID: *testNameID(test, &test.SP), Terminate: true}))
	})
}

// The request is only sent to a SOAP ManageNameIDService that passes the check of back-channel endpoints.
func TestSendManageNameIDRequestEndpoint(t *testing.T) {
	t.Run("plain http", func(t *testing.T) {
		test, _ := manageNameIDTestIDP(t)

		sp := &manageNameIDSP{}
		server := httptest.NewUnstartedServer(nil)
		server.Start()
		sp.serve(t, test, server)

		err := sendManageNameID(test, NameIDChange{NameID: *testNameID(test, &test.SP), Terminate: true})
		assert.Check(t, errors.Is(err, ErrInsecureEndpoint), "%v", err)
		assert.Check(t, is.Len(sp.requests, 0))
	})

	t.Run("no SOAP service", func(t *testing.T) {
		test, _ := manageNameIDTestIDP(t)

		err := sendManageNameID(test, NameIDChange{NameID: *testNameID(test, &test.SP), Terminate: true})
		assert.Check(t, is.ErrorContains(err, "no name identifier management service on the SOAP binding"))
	})
}

// Only the content of the response that the signature covers is believed.
func TestSendManageNameIDRequestUsesSignedResponse(t *testing.T) {
	test, sp, _ := sendManageNameIDFixture(t)

	sp.respond = func(w http.ResponseWriter, response *ManageNameIDResponse) bool {
		// The signed response is to another request. A namespace declaration, which the signature doesn't
		// cover, reads to [encoding/xml] as the InResponseTo of this one.
		id := response.InResponseTo
		response.InResponseTo = "id-other"

		doc := etree.NewDocument()
		doc.SetRoot(signTestElement(t, &test.SP, response.Element()))

		body, err := doc.WriteToBytes()
		assert.NilError(t, err)

		end := strings.IndexByte(string(body), '>')
		smuggled := string(body[:end]) + ` xmlns:InResponseTo="` + id + `"` + string(body[end:])

		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(soapTestEnvelope("", smuggled)))

		return false
	}

	err := sendManageNameID(test, NameIDChange{NameID: *testNameID(test, &test.SP), Terminate: true})
	assert.Check(t, is.ErrorContains(err, "not to the request"))
}
