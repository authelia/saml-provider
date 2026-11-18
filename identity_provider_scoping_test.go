package saml

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

const (
	scopingOtherIDP = "https://other-idp.example.com/metadata"
	scopingBehindSP = "https://behind-the-proxy.example.com/metadata"
)

// scopingBindings are the bindings that a request reaches the identity provider on.
var scopingBindings = []string{HTTPPostBinding, HTTPRedirectBinding}

// scopingRequest returns the HTTP request that carries a signed AuthnRequest of the service provider of test
// with that Scoping on the binding, and the ID of the AuthnRequest.
func scopingRequest(t *testing.T, test *IdentityProviderTest, binding string, scoping *Scoping) (*http.Request, string) {
	t.Helper()

	sp := test.SP
	sp.Scoping = scoping

	if binding == HTTPPostBinding {
		body := signedPostBody(t, &sp, nil)

		return replayPostRequest(body, nil), authnRequestID(t, body)
	}

	request, err := sp.MakeAuthenticationRequest(signatureTestSSOURL, HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)

	u, err := request.Redirect("relay", &sp)
	assert.NilError(t, err)
	assert.Assert(t, u.Query().Get("Signature") != "")

	return httptest.NewRequest(http.MethodGet, u.String(), nil), request.ID
}

// scopingSSO sends the request to the identity provider, and returns the assertion of the Response once the
// service provider has accepted it.
func scopingSSO(t *testing.T, test *IdentityProviderTest, binding string, scoping *Scoping) *Assertion {
	t.Helper()

	r, id := scopingRequest(t, test, binding, scoping)

	w := serveSSO(test, r)
	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())

	doc, response := postedResponse(t, w.Body.String())
	assert.Assert(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))

	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)

	return issuanceAccept(t, &test.SP, buf, []string{id})
}

func scopingEverything(test *IdentityProviderTest) *Scoping {
	return &Scoping{
		ProxyCount: scopingInt(2),
		IDPList: &IDPList{
			IDPEntries: []IDPEntry{
				{ProviderID: test.IDP.entityID(), Name: "This one", Loc: signatureTestSSOURL},
				{ProviderID: scopingOtherIDP},
			},
			GetComplete: "https://sp.example.com/idplist",
		},
		RequesterIDs: []string{scopingBehindSP, "https://second.example.com/metadata"},
	}
}

func TestServeSSOExposesScoping(t *testing.T) {
	for _, binding := range scopingBindings {
		t.Run(binding, func(t *testing.T) {
			test := issuanceTestIDP(t)
			sent := scopingEverything(test)

			var toSessionProvider, toIssuancePolicy *Scoping

			test.IDP.SessionProvider = &mockSessionProvider{
				GetSessionFunc: func(_ http.ResponseWriter, _ *http.Request, req *IdpAuthnRequest) *Session {
					toSessionProvider = req.Request.Scoping

					return &Session{ID: "f00f00", UserName: "alice", NameID: "alice"}
				},
			}
			test.IDP.IssuancePolicy = issuancePolicyFunc(func(req IssuanceRequest) (Issuance, error) {
				if req.AuthnRequest != nil {
					toIssuancePolicy = req.AuthnRequest.Request.Scoping
				}

				return req.Defaults, nil
			})

			scopingSSO(t, test, binding, sent)

			assert.Check(t, is.DeepEqual(toSessionProvider, sent))
			assert.Check(t, is.DeepEqual(toIssuancePolicy, sent))
			assert.Check(t, toSessionProvider.IDPList.Contains(test.IDP.entityID()))
		})
	}
}

func TestServeSSOWithoutScoping(t *testing.T) {
	test := issuanceTestIDP(t)

	called := false

	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(_ http.ResponseWriter, _ *http.Request, req *IdpAuthnRequest) *Session {
			called = true

			assert.Check(t, req.Request.Scoping == nil)

			return &Session{ID: "f00f00", UserName: "alice", NameID: "alice"}
		},
	}

	assertion := scopingSSO(t, test, HTTPPostBinding, nil)
	assert.Check(t, called)
	assert.Check(t, assertion.Conditions.ProxyRestriction == nil)
}

// TestServeSSOAuthenticatesWhateverTheScoping checks that an identity provider which authenticates the principal
// itself answers a request whatever its Scoping says, and that the Scoping puts no ProxyRestriction in the
// assertion: a proxy that sends ProxyCount="0", so that the request goes no further, must still be allowed to issue
// its own assertion on the basis of the one it gets.
func TestServeSSOAuthenticatesWhateverTheScoping(t *testing.T) {
	testCases := []struct {
		name    string
		scoping func(test *IdentityProviderTest) *Scoping
	}{
		{"ProxyCount 0", func(*IdentityProviderTest) *Scoping { return &Scoping{ProxyCount: scopingInt(0)} }},
		{"ProxyCount 3", func(*IdentityProviderTest) *Scoping { return &Scoping{ProxyCount: scopingInt(3)} }},
		{"IDPList with the identity provider", func(test *IdentityProviderTest) *Scoping {
			return &Scoping{IDPList: &IDPList{IDPEntries: []IDPEntry{{ProviderID: scopingOtherIDP}, {ProviderID: test.IDP.entityID()}}}}
		}},
		{"IDPList without the identity provider", func(*IdentityProviderTest) *Scoping {
			return &Scoping{IDPList: &IDPList{IDPEntries: []IDPEntry{{ProviderID: scopingOtherIDP}}}}
		}},
		{"incomplete IDPList without the identity provider", func(*IdentityProviderTest) *Scoping {
			return &Scoping{IDPList: &IDPList{IDPEntries: []IDPEntry{{ProviderID: scopingOtherIDP}}, GetComplete: "http://127.0.0.1:1/idplist"}}
		}},
		{"RequesterID", func(*IdentityProviderTest) *Scoping {
			return &Scoping{ProxyCount: scopingInt(0), RequesterIDs: []string{scopingBehindSP}}
		}},
	}

	for _, tc := range testCases {
		for _, binding := range scopingBindings {
			t.Run(tc.name+"/"+binding, func(t *testing.T) {
				test := issuanceTestIDP(t)

				assertion := scopingSSO(t, test, binding, tc.scoping(test))
				assert.Check(t, is.Equal(assertion.Issuer.Value, test.IDP.entityID()))
				assert.Check(t, assertion.Conditions.ProxyRestriction == nil)
			})
		}
	}
}

func TestValidateVerifiesSignatureOverScoping(t *testing.T) {
	test := signatureTestIDP(t)

	body := signedPostBody(t, &test.SP, func(request *AuthnRequest) {
		request.Scoping = &Scoping{ProxyCount: scopingInt(0), RequesterIDs: []string{scopingBehindSP}}
	})
	assert.NilError(t, validatePost(t, test, body))

	for _, altered := range [][2]string{
		{`ProxyCount="0"`, `ProxyCount="5"`},
		{scopingBehindSP, "https://someone-else.example.com/metadata"},
	} {
		assert.Assert(t, bytes.Contains(body, []byte(altered[0])))

		err := validatePost(t, test, bytes.Replace(body, []byte(altered[0]), []byte(altered[1]), 1))
		assert.Check(t, is.ErrorContains(err, "signature"), "%s", altered[1])
	}
}

// TestSessionProviderRefusesIDPList is how an application refuses a request whose IDPList doesn't name the
// identity provider, which the identity provider doesn't do itself.
func TestSessionProviderRefusesIDPList(t *testing.T) {
	test := issuanceTestIDP(t)

	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, _ *http.Request, req *IdpAuthnRequest) *Session {
			scoping := req.Request.Scoping
			if scoping != nil && scoping.IDPList != nil && scoping.IDPList.GetComplete == "" && !scoping.IDPList.Contains(req.IDP.entityID()) {
				assert.Check(t, req.WriteErrorResponse(w, ErrNoSupportedIDP))

				return nil
			}

			return &Session{ID: "f00f00", UserName: "alice", NameID: "alice"}
		},
	}

	r, id := scopingRequest(t, test, HTTPPostBinding, &Scoping{IDPList: &IDPList{IDPEntries: []IDPEntry{{ProviderID: scopingOtherIDP}}}})
	assertRequestStatus(t, serveSSO(test, r), id, StatusResponder, StatusNoSupportedIDP)

	scopingSSO(t, test, HTTPPostBinding, &Scoping{IDPList: &IDPList{IDPEntries: []IDPEntry{{ProviderID: test.IDP.entityID()}}}})
}

func TestIssuanceProxyRestriction(t *testing.T) {
	testCases := []struct {
		name        string
		restriction ProxyRestriction
	}{
		{"must not be proxied", ProxyRestriction{Count: scopingInt(0)}},
		{"one hop to named audiences", ProxyRestriction{Count: scopingInt(1), Audiences: []Audience{{Value: scopingBehindSP}, {Value: "https://second.example.com/metadata"}}}},
		{"named audiences", ProxyRestriction{Audiences: []Audience{{Value: scopingBehindSP}}}},
	}

	for _, tc := range testCases {
		for _, binding := range scopingBindings {
			t.Run(tc.name+"/"+binding, func(t *testing.T) {
				test := issuanceTestIDP(t)
				configured := tc.restriction

				issuanceFor(test, ServiceProviderIssuance{ProxyRestriction: &configured})

				// The ProxyCount of the request has no part in it.
				assertion := scopingSSO(t, test, binding, &Scoping{ProxyCount: scopingInt(7)})
				assert.Assert(t, assertion.Conditions.ProxyRestriction != nil)
				assert.Check(t, is.DeepEqual(*assertion.Conditions.ProxyRestriction, tc.restriction))
			})
		}
	}
}

func TestIssuanceProxyRestrictionIsForOneServiceProvider(t *testing.T) {
	test := issuanceTestIDP(t)

	test.IDP.IssuancePolicy = DefaultIssuancePolicy{ServiceProviders: map[string]ServiceProviderIssuance{
		"https://another.example.com/metadata": {ProxyRestriction: &ProxyRestriction{Count: scopingInt(0)}},
	}}

	assert.Check(t, scopingSSO(t, test, HTTPPostBinding, nil).Conditions.ProxyRestriction == nil)
}

func TestIssuanceProxyRestrictionIsCopied(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	configured := &ProxyRestriction{Count: scopingInt(1), Audiences: []Audience{{Value: scopingBehindSP}}}

	issuanceFor(test, ServiceProviderIssuance{ProxyRestriction: configured})

	req := issuanceAssertion(t, test, &Session{ID: "f00f00", NameID: "alice"})

	issued := req.Assertion.Conditions.ProxyRestriction
	assert.Assert(t, issued != nil)
	assert.Check(t, is.DeepEqual(issued, configured))

	*issued.Count = 9
	issued.Audiences[0].Value = "https://changed.example.com/"

	assert.Check(t, is.DeepEqual(configured, &ProxyRestriction{Count: scopingInt(1), Audiences: []Audience{{Value: scopingBehindSP}}}))
}

func TestIssuanceRefusesProxyRestrictionThatCannotBeStated(t *testing.T) {
	testCases := []struct {
		name        string
		restriction ProxyRestriction
		err         string
	}{
		{"negative count", ProxyRestriction{Count: scopingInt(-1)}, "ProxyRestriction Count must not be negative"},
		{"empty audience", ProxyRestriction{Audiences: []Audience{{Value: scopingBehindSP}, {}}}, "a ProxyRestriction Audience is empty"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			test := issuanceTestIDP(t)

			issuanceFor(test, ServiceProviderIssuance{ProxyRestriction: &tc.restriction})

			logs := &bytes.Buffer{}
			test.IDP.Observer = logObserver(logs)

			// Nothing is sent, as for every decision that can't be carried out.
			r, _ := scopingRequest(t, test, HTTPPostBinding, nil)

			w := serveSSO(test, r)
			assert.Check(t, is.Equal(w.Code, http.StatusInternalServerError))
			assert.Check(t, !strings.Contains(w.Body.String(), "SAMLResponse"))
			assert.Check(t, is.Contains(logs.String(), "IssuancePolicy: "+tc.err))
		})
	}
}

func TestIssuanceProxyRestrictionOnQueryAssertion(t *testing.T) {
	e := newQueryE2E(t)
	f, sp := e.f, &e.f.test.SP

	restriction := ProxyRestriction{Count: scopingInt(0)}

	issuanceFor(f.test, ServiceProviderIssuance{ProxyRestriction: &restriction})

	issued := e.sso(t)
	assert.Assert(t, issued.Conditions.ProxyRestriction != nil)
	assert.Check(t, is.DeepEqual(*issued.Conditions.ProxyRestriction, restriction))

	query := f.attributeQuery()
	query.Destination, query.Subject = e.attributeService, &Subject{NameID: issued.Subject.NameID}

	response := e.post(t, sp, e.attributeService, query.Element())
	assertQueryStatus(t, response, StatusSuccess, "")
	assert.Assert(t, is.Len(response.Assertions, 1))
	assert.Assert(t, response.Assertions[0].Conditions.ProxyRestriction != nil)
	assert.Check(t, is.DeepEqual(*response.Assertions[0].Conditions.ProxyRestriction, restriction))
}

func TestServeSSORefusesMalformedScoping(t *testing.T) {
	for _, scoping := range []string{
		`<Scoping ProxyCount="-1"/>`,
		`<Scoping ProxyCount="many"/>`,
		`<Scoping><IDPList/></Scoping>`,
		`<Scoping><IDPList><IDPEntry/></IDPList></Scoping>`,
		`<Scoping><IDPList><IDPEntry ProviderID="https://a.example.com/"/></IDPList><IDPList><IDPEntry ProviderID="https://b.example.com/"/></IDPList></Scoping>`,
		`<Scoping><RequesterID></RequesterID></Scoping>`,
	} {
		t.Run(scoping, func(t *testing.T) {
			test := hardeningIDPWithSessionCheck(t)

			w := serveSSO(test, replayPostRequest(hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer+scoping), nil))
			assert.Check(t, is.Equal(w.Code, http.StatusBadRequest))
			assert.Check(t, !strings.Contains(w.Body.String(), "SAMLResponse"))
		})
	}

	// The same request without what is malformed is valid.
	test := NewIdentityProviderTest(t, applyKey)

	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer+`<Scoping ProxyCount="1"><RequesterID>`+scopingBehindSP+`</RequesterID></Scoping>`))
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(req.Request.Scoping, &Scoping{ProxyCount: scopingInt(1), RequesterIDs: []string{scopingBehindSP}}))
}

// TestScopingIsBoundedByRequestSize pins what the design relies on in place of a limit on the number of
// RequesterID and IDPEntry elements: a request of the largest size that is read holds a few hundred of the
// smallest of either, which take about as much memory as the request itself.
func TestScopingIsBoundedByRequestSize(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)

	fill := func(open, element, closing string) []byte {
		empty := hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer+open+closing)
		count := (maxAuthnRequestSize - len(empty)) / len(element)

		return hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer+open+strings.Repeat(element, count)+closing)
	}

	req, err := hardeningValidate(test, fill(`<Scoping>`, `<RequesterID>a</RequesterID>`, `</Scoping>`))
	assert.NilError(t, err)
	assert.Check(t, len(req.Request.Scoping.RequesterIDs) > 500)
	assert.Check(t, len(req.Request.Scoping.RequesterIDs) < 600)

	req, err = hardeningValidate(test, fill(`<Scoping><IDPList>`, `<IDPEntry ProviderID="a"/>`, `</IDPList></Scoping>`))
	assert.NilError(t, err)
	assert.Check(t, len(req.Request.Scoping.IDPList.IDPEntries) > 500)
	assert.Check(t, len(req.Request.Scoping.IDPList.IDPEntries) < 640)

	oversized := hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer+`<Scoping>`+strings.Repeat(`<RequesterID>a</RequesterID>`, 600)+`</Scoping>`)

	_, err = hardeningValidate(test, oversized)
	assert.Check(t, is.Contains(errorText(err), "exceeds"))
}

func TestServiceProviderSendsScoping(t *testing.T) {
	test := signatureTestIDP(t)
	sp := test.SP

	request, err := sp.MakeAuthenticationRequest(signatureTestSSOURL, HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	assert.Check(t, request.Scoping == nil)

	sp.Scoping = &Scoping{ProxyCount: scopingInt(1), IDPList: &IDPList{IDPEntries: []IDPEntry{{ProviderID: test.IDP.entityID()}}}}

	request, err = sp.MakeAuthenticationRequest(signatureTestSSOURL, HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(request.Scoping, sp.Scoping))
	assert.Assert(t, request.Signature != nil)

	// The signature that MakeAuthenticationRequest made covers the Scoping.
	body := []byte(scopingXML(t, request.Element()))
	assert.Assert(t, bytes.Contains(body, []byte(`<samlp:Scoping ProxyCount="1">`)))
	assert.NilError(t, validatePost(t, test, body))

	err = validatePost(t, test, bytes.Replace(body, []byte(`ProxyCount="1"`), []byte(`ProxyCount="2"`), 1))
	assert.Check(t, is.ErrorContains(err, "signature"))
}
