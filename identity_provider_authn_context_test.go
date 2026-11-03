package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

const (
	weakClass      = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
	transportClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	strongClass    = "https://refeds.org/profile/mfa"
	unrankedClass  = "urn:example:unranked"
)

type authnContextEnforcerFunc func(*IdpAuthnRequest, *Session) error

func (f authnContextEnforcerFunc) EnforceAuthnContext(req *IdpAuthnRequest, session *Session) error {
	return f(req, session)
}

// serveSSOWithAuthnContext posts a request with the given requested context, and returns the
// response sent to the service provider.
func serveSSOWithAuthnContext(t *testing.T, test *IdentityProviderTest, requested *RequestedAuthnContext) Response {
	t.Helper()
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
			return &Session{ID: "s", NameID: "alice"}
		},
	}

	request, err := test.SP.MakeAuthenticationRequest("https://idp.example.com/saml/sso", HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	request.RequestedAuthnContext = requested
	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	body, err := doc.WriteToBytes()
	assert.NilError(t, err)

	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}}
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/saml/sso", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, r)
	assert.Check(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())

	_, response := postedResponse(t, w.Body.String())
	return response
}

func assertNoAuthnContext(t *testing.T, response Response) {
	t.Helper()
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusResponder))
	assert.Assert(t, response.Status.StatusCode.StatusCode != nil)
	assert.Check(t, is.Equal(response.Status.StatusCode.StatusCode.Value, StatusNoAuthnContext))
	assert.Check(t, response.Assertion == nil)
	assert.Check(t, response.EncryptedAssertion == nil)
}

// The default assertion is PasswordProtectedTransport, and with no ranking configured only that
// class can satisfy a request.
func TestServeSSOAcceptsSatisfiableAuthnContext(t *testing.T) {
	for name, requested := range map[string]*RequestedAuthnContext{
		"none":               nil,
		"no comparison":      {AuthnContextClassRefs: []string{transportClass}},
		"exact":              {Comparison: AuthnContextComparisonExact, AuthnContextClassRefs: []string{transportClass}},
		"exact second class": {Comparison: AuthnContextComparisonExact, AuthnContextClassRefs: []string{strongClass, transportClass}},
		"minimum":            {Comparison: AuthnContextComparisonMinimum, AuthnContextClassRefs: []string{transportClass}},
		"maximum":            {Comparison: AuthnContextComparisonMaximum, AuthnContextClassRefs: []string{transportClass}},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			response := serveSSOWithAuthnContext(t, test, requested)
			assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
		})
	}
}

func TestServeSSORejectsUnsatisfiableAuthnContext(t *testing.T) {
	for name, requested := range map[string]*RequestedAuthnContext{
		"exact other class":     {AuthnContextClassRefs: []string{strongClass}},
		"exact none of several": {AuthnContextClassRefs: []string{strongClass, weakClass}},
		"minimum unranked":      {Comparison: AuthnContextComparisonMinimum, AuthnContextClassRefs: []string{weakClass}},
		"better than itself":    {Comparison: AuthnContextComparisonBetter, AuthnContextClassRefs: []string{transportClass}},
		"declaration":           {AuthnContextDeclRefs: []string{"urn:example:declaration"}},
		"declaration and class": {AuthnContextClassRefs: []string{transportClass}, AuthnContextDeclRefs: []string{"urn:example:declaration"}},
		"unknown comparison":    {Comparison: "most", AuthnContextClassRefs: []string{transportClass}},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			assertNoAuthnContext(t, serveSSOWithAuthnContext(t, test, requested))
		})
	}
}

func TestServeSSOUsesConfiguredAuthnContextEnforcer(t *testing.T) {
	t.Run("accepts what the default would not", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.AuthnContextEnforcer = authnContextEnforcerFunc(func(*IdpAuthnRequest, *Session) error { return nil })
		response := serveSSOWithAuthnContext(t, test, &RequestedAuthnContext{AuthnContextClassRefs: []string{strongClass}})
		assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	})

	t.Run("refuses with the request and session", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		var classes []string
		var nameID string
		test.IDP.AuthnContextEnforcer = authnContextEnforcerFunc(func(req *IdpAuthnRequest, session *Session) error {
			classes = req.Request.RequestedAuthnContext.AuthnContextClassRefs
			nameID = session.NameID
			return errors.New("alice has not used a second factor")
		})
		response := serveSSOWithAuthnContext(t, test, &RequestedAuthnContext{AuthnContextClassRefs: []string{transportClass, strongClass}})
		assertNoAuthnContext(t, response)
		assert.Check(t, is.DeepEqual(classes, []string{transportClass, strongClass}))
		assert.Check(t, is.Equal(nameID, "alice"))
		assert.Check(t, response.Status.StatusMessage == nil)
	})

	t.Run("not called without a requested context", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.AuthnContextEnforcer = authnContextEnforcerFunc(func(*IdpAuthnRequest, *Session) error {
			t.Error("the enforcer must not run")
			return nil
		})
		response := serveSSOWithAuthnContext(t, test, nil)
		assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	})
}

// An IdP-initiated response isn't answering a request, so there is no context to enforce.
func TestServeIDPInitiatedSkipsAuthnContextEnforcer(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.AuthnContextEnforcer = authnContextEnforcerFunc(func(*IdpAuthnRequest, *Session) error {
		t.Error("the enforcer must not run")
		return nil
	})
	w := httptest.NewRecorder()
	test.IDP.ServeIDPInitiated(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/sso", nil), test.SP.MetadataURL.String(), "")
	assert.Check(t, is.Equal(w.Code, http.StatusOK))
}

// enforceAssertedClasses runs the default enforcer against an assertion with one authentication
// statement per class.
func enforceAssertedClasses(enforcer DefaultAuthnContextEnforcer, requested *RequestedAuthnContext, asserted ...string) error {
	assertion := &Assertion{}
	for _, class := range asserted {
		assertion.AuthnStatements = append(assertion.AuthnStatements, AuthnStatement{
			AuthnContext: AuthnContext{AuthnContextClassRef: &AuthnContextClassRef{Value: class}},
		})
	}
	req := &IdpAuthnRequest{Request: AuthnRequest{RequestedAuthnContext: requested}, Assertion: assertion}
	return enforcer.EnforceAuthnContext(req, &Session{})
}

func TestDefaultAuthnContextEnforcerComparisons(t *testing.T) {
	ranked := DefaultAuthnContextEnforcer{Strength: map[string]int{
		weakClass:      1,
		transportClass: 2,
		strongClass:    3,
	}}

	request := func(comparison string, classes ...string) *RequestedAuthnContext {
		return &RequestedAuthnContext{Comparison: comparison, AuthnContextClassRefs: classes}
	}

	for name, tc := range map[string]struct {
		requested *RequestedAuthnContext
		asserted  []string
		ok        bool
	}{
		"exact match":                    {request("", weakClass), []string{weakClass}, true},
		"exact ignores strength":         {request(AuthnContextComparisonExact, weakClass), []string{strongClass}, false},
		"minimum equal":                  {request(AuthnContextComparisonMinimum, transportClass), []string{transportClass}, true},
		"minimum stronger":               {request(AuthnContextComparisonMinimum, transportClass), []string{strongClass}, true},
		"minimum weaker":                 {request(AuthnContextComparisonMinimum, transportClass), []string{weakClass}, false},
		"minimum of one listed":          {request(AuthnContextComparisonMinimum, strongClass, weakClass), []string{transportClass}, true},
		"minimum unranked request equal": {request(AuthnContextComparisonMinimum, unrankedClass), []string{unrankedClass}, true},
		"minimum unranked request":       {request(AuthnContextComparisonMinimum, unrankedClass), []string{strongClass}, false},
		"minimum unranked assertion":     {request(AuthnContextComparisonMinimum, weakClass), []string{unrankedClass}, false},
		"maximum equal":                  {request(AuthnContextComparisonMaximum, transportClass), []string{transportClass}, true},
		"maximum weaker":                 {request(AuthnContextComparisonMaximum, transportClass), []string{weakClass}, true},
		"maximum stronger":               {request(AuthnContextComparisonMaximum, transportClass), []string{strongClass}, false},
		"maximum of one listed":          {request(AuthnContextComparisonMaximum, weakClass, strongClass), []string{transportClass}, true},
		"better stronger":                {request(AuthnContextComparisonBetter, transportClass), []string{strongClass}, true},
		"better equal":                   {request(AuthnContextComparisonBetter, transportClass), []string{transportClass}, false},
		"better weaker":                  {request(AuthnContextComparisonBetter, transportClass), []string{weakClass}, false},
		"better than one listed":         {request(AuthnContextComparisonBetter, strongClass, weakClass), []string{transportClass}, true},
		"better unranked":                {request(AuthnContextComparisonBetter, unrankedClass), []string{unrankedClass}, false},
		"every statement must match":     {request("", weakClass), []string{weakClass, strongClass}, false},
		"no statement":                   {request("", weakClass), nil, false},
		"no class in request":            {request(""), []string{weakClass}, false},
	} {
		t.Run(name, func(t *testing.T) {
			err := enforceAssertedClasses(ranked, tc.requested, tc.asserted...)
			if tc.ok {
				assert.Check(t, err)
			} else {
				assert.Check(t, err != nil)
			}
		})
	}

	t.Run("statement without a class", func(t *testing.T) {
		req := &IdpAuthnRequest{
			Request:   AuthnRequest{RequestedAuthnContext: request("", weakClass)},
			Assertion: &Assertion{AuthnStatements: []AuthnStatement{{}}},
		}
		assert.Check(t, ranked.EnforceAuthnContext(req, &Session{}) != nil)
	})

	t.Run("no assertion", func(t *testing.T) {
		req := &IdpAuthnRequest{Request: AuthnRequest{RequestedAuthnContext: request("", weakClass)}}
		assert.Check(t, ranked.EnforceAuthnContext(req, &Session{}) != nil)
	})
}

// BUG-39: only the last class ref survived parsing.
func TestRequestedAuthnContextKeepsEveryReference(t *testing.T) {
	const input = `<samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Comparison="minimum">` +
		`<saml:AuthnContextClassRef>a</saml:AuthnContextClassRef><saml:AuthnContextClassRef>b</saml:AuthnContextClassRef>` +
		`</samlp:RequestedAuthnContext>`
	var actual RequestedAuthnContext
	assert.NilError(t, xml.Unmarshal([]byte(input), &actual))
	assert.Check(t, is.Equal(actual.Comparison, AuthnContextComparisonMinimum))
	assert.Check(t, is.DeepEqual(actual.AuthnContextClassRefs, []string{"a", "b"}))

	const declarations = `<samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<saml:AuthnContextDeclRef>c</saml:AuthnContextDeclRef><saml:AuthnContextDeclRef>d</saml:AuthnContextDeclRef>` +
		`</samlp:RequestedAuthnContext>`
	actual = RequestedAuthnContext{}
	assert.NilError(t, xml.Unmarshal([]byte(declarations), &actual))
	assert.Check(t, is.DeepEqual(actual.AuthnContextDeclRefs, []string{"c", "d"}))
	assert.Check(t, is.Len(actual.AuthnContextClassRefs, 0))
}

// SP-02: an unset Comparison was written as Comparison="".
func TestRequestedAuthnContextElement(t *testing.T) {
	for name, tc := range map[string]struct {
		requested RequestedAuthnContext
		expected  string
	}{
		"classes": {
			RequestedAuthnContext{Comparison: AuthnContextComparisonMinimum, AuthnContextClassRefs: []string{"a", "b"}},
			`<samlp:RequestedAuthnContext Comparison="minimum"><saml:AuthnContextClassRef>a</saml:AuthnContextClassRef><saml:AuthnContextClassRef>b</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>`,
		},
		"declarations without comparison": {
			RequestedAuthnContext{AuthnContextDeclRefs: []string{"c"}},
			`<samlp:RequestedAuthnContext><saml:AuthnContextDeclRef>c</saml:AuthnContextDeclRef></samlp:RequestedAuthnContext>`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			doc := etree.NewDocument()
			doc.SetRoot(tc.requested.Element())
			x, err := doc.WriteToBytes()
			assert.NilError(t, err)
			assert.Check(t, is.Equal(tc.expected, string(x)))
		})
	}
}
