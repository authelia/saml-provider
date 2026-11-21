package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	weakClass      = AuthnContextClassPassword
	transportClass = AuthnContextClassPasswordProtectedTransport
	strongClass    = "https://refeds.org/profile/mfa"
	unrankedClass  = "urn:example:unranked"

	testDeclRef       = "urn:example:declaration"
	otherDeclRef      = "urn:example:declaration:other"
	upstreamAuthority = "https://upstream.example.com/idp"
)

type authnContextEnforcerFunc func(*RequestedAuthnContext, *Session) error

func (f authnContextEnforcerFunc) SatisfiesAuthnContext(requested *RequestedAuthnContext, session *Session) error {
	return f(requested, session)
}

// serveSSOWithAuthnContext posts a request with the given requested context, and returns the
// response sent to the service provider.
func serveSSOWithAuthnContext(t *testing.T, test *IdentityProviderTest, requested *RequestedAuthnContext) Response {
	t.Helper()
	return serveSSOWithSession(t, test, &Session{ID: "s", NameID: "alice"}, requested)
}

// serveSSOWithSession is serveSSOWithAuthnContext for the given session.
func serveSSOWithSession(t *testing.T, test *IdentityProviderTest, session *Session, requested *RequestedAuthnContext) Response {
	t.Helper()

	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
			return session
		},
	}

	request, err := test.SP.MakeAuthenticationRequest("https://idp.example.com/saml/sso", HTTPPostBinding, HTTPPostBinding)
	require.NoError(t, err)

	request.RequestedAuthnContext = requested
	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	body, err := doc.WriteToBytes()
	require.NoError(t, err)

	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}}
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/saml/sso", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, r)
	assert.Equal(t, w.Code, http.StatusOK, "body: %s", w.Body.String())

	_, response := postedResponse(t, w.Body.String())

	return response
}

func assertNoAuthnContext(t *testing.T, response Response) {
	t.Helper()
	assert.Equal(t, response.Status.StatusCode.Value, StatusResponder)
	require.NotNil(t, response.Status.StatusCode.StatusCode)
	assert.Equal(t, response.Status.StatusCode.StatusCode.Value, StatusNoAuthnContext)
	assert.Nil(t, response.Assertion)
	assert.Nil(t, response.EncryptedAssertion)
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
			assert.Equal(t, response.Status.StatusCode.Value, StatusSuccess)
		})
	}
}

func TestServeSSORejectsUnsatisfiableAuthnContext(t *testing.T) {
	for name, requested := range map[string]*RequestedAuthnContext{
		"exact other class":     {AuthnContextClassRefs: []string{strongClass}},
		"exact none of several": {AuthnContextClassRefs: []string{strongClass, weakClass}},
		"minimum unranked":      {Comparison: AuthnContextComparisonMinimum, AuthnContextClassRefs: []string{weakClass}},
		"better than itself":    {Comparison: AuthnContextComparisonBetter, AuthnContextClassRefs: []string{transportClass}},
		"declaration":           {AuthnContextDeclRefs: []string{testDeclRef}},
		"declaration and class": {AuthnContextClassRefs: []string{transportClass}, AuthnContextDeclRefs: []string{testDeclRef}},
		"unknown comparison":    {Comparison: "most", AuthnContextClassRefs: []string{transportClass}},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			assertNoAuthnContext(t, serveSSOWithAuthnContext(t, test, requested))
		})
	}
}

// The assertion carries the class, declaration reference and authorities of the session, and
// PasswordProtectedTransport when the session sets neither a class nor a declaration reference, so a
// session provider can assert a stronger authentication truthfully.
func TestDefaultAssertionMakerUsesSessionAuthnContext(t *testing.T) {
	for name, tc := range map[string]struct {
		session  Session
		asserted AuthnContext
	}{
		"class only": {
			session:  Session{AuthnContextClassRef: strongClass},
			asserted: AuthnContext{AuthnContextClassRef: &AuthnContextClassRef{Value: strongClass}},
		},
		"nothing": {
			session:  Session{},
			asserted: AuthnContext{AuthnContextClassRef: &AuthnContextClassRef{Value: transportClass}},
		},
		"declaration only": {
			session:  Session{AuthnContextDeclRef: testDeclRef},
			asserted: AuthnContext{AuthnContextDeclRef: &AuthnContextDeclRef{Value: testDeclRef}},
		},
		"blank declaration only": {
			session:  Session{AuthnContextDeclRef: "  "},
			asserted: AuthnContext{AuthnContextClassRef: &AuthnContextClassRef{Value: transportClass}},
		},
		"class and declaration": {
			session: Session{AuthnContextClassRef: strongClass, AuthnContextDeclRef: testDeclRef},
			asserted: AuthnContext{
				AuthnContextClassRef: &AuthnContextClassRef{Value: strongClass},
				AuthnContextDeclRef:  &AuthnContextDeclRef{Value: testDeclRef},
			},
		},
		"authorities": {
			session: Session{AuthenticatingAuthorities: []string{upstreamAuthority, "", "  "}},
			asserted: AuthnContext{
				AuthnContextClassRef:      &AuthnContextClassRef{Value: transportClass},
				AuthenticatingAuthorities: []string{upstreamAuthority},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
			require.NoError(t, err)

			session := tc.session
			session.ID, session.NameID = "f00d", "alice"
			require.NoError(t, DefaultAssertionMaker{}.MakeAssertion(req, &session))
			require.Len(t, req.Assertion.AuthnStatements, 1)
			assert.Equal(t, tc.asserted, req.Assertion.AuthnStatements[0].AuthnContext)
		})
	}
}

func TestServeSSOMatchesRequestedDeclRef(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	session := &Session{ID: "s", NameID: "alice", AuthnContextDeclRef: testDeclRef}

	response := serveSSOWithSession(t, test, session, &RequestedAuthnContext{AuthnContextDeclRefs: []string{testDeclRef}})
	assert.Equal(t, response.Status.StatusCode.Value, StatusSuccess)

	response = serveSSOWithSession(t, test, session, &RequestedAuthnContext{AuthnContextDeclRefs: []string{otherDeclRef}})
	assertNoAuthnContext(t, response)
}

func TestServeSSOAcceptsSessionAuthnContext(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	session := &Session{ID: "s", NameID: "alice", AuthnContextClassRef: strongClass}
	response := serveSSOWithSession(t, test, session, &RequestedAuthnContext{AuthnContextClassRefs: []string{strongClass}})
	assert.Equal(t, response.Status.StatusCode.Value, StatusSuccess)

	response = serveSSOWithSession(t, test, session, &RequestedAuthnContext{AuthnContextClassRefs: []string{transportClass}})
	assertNoAuthnContext(t, response)
}

func TestServeSSOUsesConfiguredAuthnContextEnforcer(t *testing.T) {
	t.Run("accepts what the default would not", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.AuthnContextEnforcer = authnContextEnforcerFunc(func(*RequestedAuthnContext, *Session) error { return nil })
		response := serveSSOWithAuthnContext(t, test, &RequestedAuthnContext{AuthnContextClassRefs: []string{strongClass}})
		assert.Equal(t, response.Status.StatusCode.Value, StatusSuccess)
	})

	t.Run("refuses with the request and session", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)

		var (
			classes []string
			nameID  string
		)

		test.IDP.AuthnContextEnforcer = authnContextEnforcerFunc(func(requested *RequestedAuthnContext, session *Session) error {
			classes = requested.AuthnContextClassRefs
			nameID = session.NameID

			return errors.New("alice has not used a second factor")
		})
		response := serveSSOWithAuthnContext(t, test, &RequestedAuthnContext{AuthnContextClassRefs: []string{transportClass, strongClass}})
		assertNoAuthnContext(t, response)
		assert.Equal(t, classes, []string{transportClass, strongClass})
		assert.Equal(t, nameID, "alice")
		assert.True(t, statusSaysNothingOfTheRequest(response.Status))
	})

	t.Run("not called without a requested context", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.AuthnContextEnforcer = authnContextEnforcerFunc(func(*RequestedAuthnContext, *Session) error {
			t.Error("the enforcer must not run")
			return nil
		})
		response := serveSSOWithAuthnContext(t, test, nil)
		assert.Equal(t, response.Status.StatusCode.Value, StatusSuccess)
	})
}

// An IdP-initiated response isn't answering a request, so there is no context to enforce.
func TestServeIDPInitiatedSkipsAuthnContextEnforcer(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.AuthnContextEnforcer = authnContextEnforcerFunc(func(*RequestedAuthnContext, *Session) error {
		t.Error("the enforcer must not run")
		return nil
	})
	w := httptest.NewRecorder()
	test.IDP.ServeIDPInitiated(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/sso", nil), test.SP.MetadataURL.String(), "")
	assert.Equal(t, w.Code, http.StatusOK)
}

// enforceAssertedClasses runs the default enforcer against an assertion with one authentication
// statement per class, as ServeSSO does.
func enforceAssertedClasses(enforcer DefaultAuthnContextEnforcer, requested *RequestedAuthnContext, asserted ...string) error {
	assertion := &Assertion{}
	for _, class := range asserted {
		assertion.AuthnStatements = append(assertion.AuthnStatements, AuthnStatement{
			AuthnContext: AuthnContext{AuthnContextClassRef: &AuthnContextClassRef{Value: class}},
		})
	}

	idp := &IdentityProvider{AuthnContextEnforcer: enforcer}

	return idp.satisfiesAuthnContext(requested, assertion, &Session{})
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
				assert.NoError(t, err)
			} else {
				assert.NotNil(t, err)
			}
		})
	}

	idp := &IdentityProvider{AuthnContextEnforcer: ranked}

	t.Run("statement without a class", func(t *testing.T) {
		assertion := &Assertion{AuthnStatements: []AuthnStatement{{}}}
		assert.True(t, idp.satisfiesAuthnContext(request("", weakClass), assertion, &Session{}) != nil)
	})

	t.Run("no assertion", func(t *testing.T) {
		assert.True(t, idp.satisfiesAuthnContext(request("", weakClass), nil, &Session{}) != nil)
	})

	t.Run("the class of the session", func(t *testing.T) {
		assert.NoError(t, ranked.SatisfiesAuthnContext(request("", strongClass), &Session{AuthnContextClassRef: strongClass}))
		assert.True(t, ranked.SatisfiesAuthnContext(request("", strongClass), &Session{AuthnContextClassRef: weakClass}) != nil)
		assert.NoError(t, ranked.SatisfiesAuthnContext(request(AuthnContextComparisonMinimum, weakClass), &Session{AuthnContextClassRef: strongClass}))
	})

	t.Run("a session without a class is PasswordProtectedTransport", func(t *testing.T) {
		assert.NoError(t, ranked.SatisfiesAuthnContext(request("", transportClass), &Session{}))
		assert.True(t, ranked.SatisfiesAuthnContext(request("", strongClass), &Session{}) != nil)
	})
}

// SAMLCore §3.3.2.2.1 allows a set of class references or a set of declaration references, with the
// same comparison rules, so a requested declaration reference is matched against the declaration
// reference of the session, and never against its class.
func TestDefaultAuthnContextEnforcerDeclRefs(t *testing.T) {
	enforcer := DefaultAuthnContextEnforcer{Strength: map[string]int{testDeclRef: 1, otherDeclRef: 2}}

	declRefs := func(comparison string, refs ...string) *RequestedAuthnContext {
		return &RequestedAuthnContext{Comparison: comparison, AuthnContextDeclRefs: refs}
	}

	for name, tc := range map[string]struct {
		requested *RequestedAuthnContext
		session   Session
		ok        bool
	}{
		"exact":                         {declRefs("", testDeclRef), Session{AuthnContextDeclRef: testDeclRef}, true},
		"any one listed":                {declRefs("", otherDeclRef, testDeclRef), Session{AuthnContextDeclRef: testDeclRef}, true},
		"another declaration":           {declRefs(AuthnContextComparisonExact, otherDeclRef), Session{AuthnContextDeclRef: testDeclRef}, false},
		"session without a declaration": {declRefs("", testDeclRef), Session{AuthnContextClassRef: strongClass}, false},
		"kinds do not cross":            {declRefs("", strongClass), Session{AuthnContextClassRef: strongClass}, false},
		"minimum":                       {declRefs(AuthnContextComparisonMinimum, testDeclRef), Session{AuthnContextDeclRef: otherDeclRef}, true},
		"better, equal":                 {declRefs(AuthnContextComparisonBetter, testDeclRef), Session{AuthnContextDeclRef: testDeclRef}, false},
		"empty declaration requested":   {declRefs("", ""), Session{AuthnContextClassRef: strongClass}, false},
		"class requested of a declaration-only session": {
			&RequestedAuthnContext{AuthnContextClassRefs: []string{transportClass}},
			Session{AuthnContextDeclRef: testDeclRef},
			false,
		},
		"class requested of a session with both": {
			&RequestedAuthnContext{AuthnContextClassRefs: []string{strongClass}},
			Session{AuthnContextClassRef: strongClass, AuthnContextDeclRef: testDeclRef},
			true,
		},
		"both kinds requested": {
			&RequestedAuthnContext{AuthnContextClassRefs: []string{strongClass}, AuthnContextDeclRefs: []string{testDeclRef}},
			Session{AuthnContextClassRef: strongClass, AuthnContextDeclRef: testDeclRef},
			false,
		},
		"empty class requested": {
			&RequestedAuthnContext{AuthnContextClassRefs: []string{""}},
			Session{AuthnContextDeclRef: testDeclRef},
			false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := enforcer.SatisfiesAuthnContext(tc.requested, &tc.session)
			if tc.ok {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// The enforcer judges what each statement asserts, not what the session holds, so a custom
// AssertionMaker is held to its statements.
func TestSatisfiesAuthnContextJudgesTheStatement(t *testing.T) {
	idp := &IdentityProvider{}

	withStatement := func(context AuthnContext) *Assertion {
		return &Assertion{AuthnStatements: []AuthnStatement{{AuthnContext: context}}}
	}

	declOnly := withStatement(AuthnContext{AuthnContextDeclRef: &AuthnContextDeclRef{Value: testDeclRef}})

	t.Run("declaration asserted", func(t *testing.T) {
		assert.NoError(t, idp.satisfiesAuthnContext(&RequestedAuthnContext{AuthnContextDeclRefs: []string{testDeclRef}}, declOnly, &Session{}))
	})

	t.Run("class of the session but not of the statement", func(t *testing.T) {
		requested := &RequestedAuthnContext{AuthnContextClassRefs: []string{strongClass}}
		assert.Error(t, idp.satisfiesAuthnContext(requested, declOnly, &Session{AuthnContextClassRef: strongClass}))
	})

	t.Run("declaration of the session but not of the statement", func(t *testing.T) {
		assertion := withStatement(AuthnContext{AuthnContextClassRef: &AuthnContextClassRef{Value: weakClass}})
		requested := &RequestedAuthnContext{AuthnContextDeclRefs: []string{testDeclRef}}
		assert.Error(t, idp.satisfiesAuthnContext(requested, assertion, &Session{AuthnContextDeclRef: testDeclRef}))
	})

	t.Run("statement with neither", func(t *testing.T) {
		err := idp.satisfiesAuthnContext(&RequestedAuthnContext{AuthnContextClassRefs: []string{weakClass}}, withStatement(AuthnContext{}), &Session{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "neither")
	})

	t.Run("empty references are absent", func(t *testing.T) {
		requested := &RequestedAuthnContext{AuthnContextClassRefs: []string{transportClass}}

		for name, authn := range map[string]AuthnContext{
			"declaration": {AuthnContextDeclRef: &AuthnContextDeclRef{Value: ""}},
			"class":       {AuthnContextClassRef: &AuthnContextClassRef{Value: ""}},
			"blank class": {AuthnContextClassRef: &AuthnContextClassRef{Value: "  "}},
		} {
			t.Run(name, func(t *testing.T) {
				err := idp.satisfiesAuthnContext(requested, withStatement(authn), &Session{})
				require.Error(t, err)
				assert.Contains(t, err.Error(), "neither")
			})
		}
	})

	t.Run("the enforcer sees the statement", func(t *testing.T) {
		var seen Session

		recorder := &IdentityProvider{AuthnContextEnforcer: authnContextEnforcerFunc(func(_ *RequestedAuthnContext, session *Session) error {
			seen = *session

			return nil
		})}

		session := &Session{
			NameID:                    "alice",
			AuthnContextClassRef:      weakClass,
			AuthnContextDeclRef:       otherDeclRef,
			AuthenticatingAuthorities: []string{"https://other.example.com/idp"},
		}
		original := *session
		original.AuthenticatingAuthorities = slices.Clone(session.AuthenticatingAuthorities)

		assertion := withStatement(AuthnContext{
			AuthnContextClassRef:      &AuthnContextClassRef{Value: strongClass},
			AuthnContextDeclRef:       &AuthnContextDeclRef{Value: testDeclRef},
			AuthenticatingAuthorities: []string{upstreamAuthority},
		})
		require.NoError(t, recorder.satisfiesAuthnContext(&RequestedAuthnContext{AuthnContextClassRefs: []string{strongClass}}, assertion, session))
		assert.Equal(t, seen.NameID, "alice")
		assert.Equal(t, seen.AuthnContextClassRef, strongClass)
		assert.Equal(t, seen.AuthnContextDeclRef, testDeclRef)
		assert.Equal(t, seen.AuthenticatingAuthorities, []string{upstreamAuthority})
		assert.Equal(t, original, *session, "the session is not changed")

		require.NoError(t, recorder.satisfiesAuthnContext(&RequestedAuthnContext{AuthnContextDeclRefs: []string{testDeclRef}}, declOnly, session))
		assert.Equal(t, seen.AuthnContextClassRef, "")
		assert.Equal(t, seen.AuthnContextDeclRef, testDeclRef)
		assert.Nil(t, seen.AuthenticatingAuthorities)
	})
}

// A custom AssertionMaker is held to the class it asserts, not the class of the session.
func TestServeSSOEnforcesTheAssertedAuthnContext(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.AssertionMaker = assertionMakerFunc(func(req *IdpAuthnRequest, session *Session) error {
		if err := (DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
			return err
		}

		req.Assertion.AuthnStatements[0].AuthnContext.AuthnContextClassRef.Value = weakClass

		return nil
	})

	session := &Session{ID: "s", NameID: "alice", AuthnContextClassRef: strongClass}

	response := serveSSOWithSession(t, test, session, &RequestedAuthnContext{AuthnContextClassRefs: []string{strongClass}})
	assertNoAuthnContext(t, response)

	response = serveSSOWithSession(t, test, session, &RequestedAuthnContext{AuthnContextClassRefs: []string{weakClass}})
	assert.Equal(t, response.Status.StatusCode.Value, StatusSuccess)
	assert.Equal(t, session.AuthnContextClassRef, strongClass, "the session is not changed")
}

// BUG-39: only the last class ref survived parsing.
func TestRequestedAuthnContextKeepsEveryReference(t *testing.T) {
	const input = `<samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Comparison="minimum">` +
		`<saml:AuthnContextClassRef>a</saml:AuthnContextClassRef><saml:AuthnContextClassRef>b</saml:AuthnContextClassRef>` +
		`</samlp:RequestedAuthnContext>`

	var actual RequestedAuthnContext
	require.NoError(t, xml.Unmarshal([]byte(input), &actual))
	assert.Equal(t, actual.Comparison, AuthnContextComparisonMinimum)
	assert.Equal(t, actual.AuthnContextClassRefs, []string{"a", "b"})

	const declarations = `<samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<saml:AuthnContextDeclRef>c</saml:AuthnContextDeclRef><saml:AuthnContextDeclRef>d</saml:AuthnContextDeclRef>` +
		`</samlp:RequestedAuthnContext>`

	actual = RequestedAuthnContext{}
	require.NoError(t, xml.Unmarshal([]byte(declarations), &actual))
	assert.Equal(t, actual.AuthnContextDeclRefs, []string{"c", "d"})
	assert.Len(t, actual.AuthnContextClassRefs, 0)
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
			require.NoError(t, err)
			assert.Equal(t, tc.expected, string(x))
		})
	}
}
