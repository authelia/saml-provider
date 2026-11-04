package saml

import (
	"encoding/base64"
	"errors"
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

const holderOfKeyMethod = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"

type subjectEnforcerFunc func(*IdpAuthnRequest, *Session) error

func (f subjectEnforcerFunc) EnforceSubject(req *IdpAuthnRequest, session *Session) error {
	return f(req, session)
}

// serveSSOWithSubject posts a request naming subject, and returns the HTTP response.
func serveSSOWithSubject(t *testing.T, test *IdentityProviderTest, session *Session, subject *Subject) *httptest.ResponseRecorder {
	t.Helper()
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session { return session },
	}

	request, err := test.SP.MakeAuthenticationRequest("https://idp.example.com/saml/sso", HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	request.Subject = subject
	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	body, err := doc.WriteToBytes()
	assert.NilError(t, err)

	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}}
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/saml/sso", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, r)
	return w
}

func subjectResponse(t *testing.T, w *httptest.ResponseRecorder) Response {
	t.Helper()
	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())
	_, response := postedResponse(t, w.Body.String())
	return response
}

func assertAuthnFailed(t *testing.T, response Response) {
	t.Helper()
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusResponder))
	assert.Assert(t, response.Status.StatusCode.StatusCode != nil)
	assert.Check(t, is.Equal(response.Status.StatusCode.StatusCode.Value, StatusAuthnFailed))
	assert.Check(t, response.Assertion == nil)
	assert.Check(t, response.EncryptedAssertion == nil)
}

type assertionMakerFunc func(*IdpAuthnRequest, *Session) error

func (f assertionMakerFunc) MakeAssertion(req *IdpAuthnRequest, session *Session) error {
	return f(req, session)
}

func bearer() []SubjectConfirmation {
	return []SubjectConfirmation{{Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer"}}
}

// The assertion must strongly match the subject of the request, SAMLCore §3.4.1 and §3.3.4. A
// qualifier or format the request leaves out isn't compared.
func TestServeSSOAcceptsMatchingSubject(t *testing.T) {
	transient := "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	for name, subject := range map[string]*Subject{
		"value":                  {NameID: &NameID{Value: "alice"}},
		"format":                 {NameID: &NameID{Format: transient, Value: "alice"}},
		"unspecified format":     {NameID: &NameID{Format: string(UnspecifiedNameIDFormat), Value: "alice"}},
		"unspecified format 2.0": {NameID: &NameID{Format: unspecifiedNameIDFormat20, Value: "alice"}},
		"qualifiers": {NameID: &NameID{
			NameQualifier:   "https://idp.example.com/saml/metadata",
			SPNameQualifier: "https://sp.example.com/saml2/metadata",
			Value:           "alice",
		}},
		"bearer confirmation": {NameID: &NameID{Value: "alice"}, SubjectConfirmations: bearer()},
		"one of the confirmations": {NameID: &NameID{Value: "alice"}, SubjectConfirmations: append(
			[]SubjectConfirmation{{Method: holderOfKeyMethod}}, bearer()...)},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			w := serveSSOWithSubject(t, test, &Session{ID: "s", NameID: "alice"}, subject)
			assert.Check(t, is.Equal(subjectResponse(t, w).Status.StatusCode.Value, StatusSuccess))
		})
	}
}

// An assertion for another principal than the one the request names is refused, rather than sent
// for whoever is logged in.
func TestServeSSORejectsOtherSubject(t *testing.T) {
	for name, subject := range map[string]*Subject{
		"other value":          {NameID: &NameID{Value: "bob"}},
		"other format":         {NameID: &NameID{Format: string(EmailAddressNameIDFormat), Value: "alice"}},
		"other name qualifier": {NameID: &NameID{NameQualifier: "https://other.example.com", Value: "alice"}},
		"other sp qualifier":   {NameID: &NameID{SPNameQualifier: "https://other.example.com", Value: "alice"}},
		"sp provided id":       {NameID: &NameID{SPProvidedID: "a1", Value: "alice"}},
		"no identifier":        {SubjectConfirmations: bearer()},
		"empty value":          {NameID: &NameID{}},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			w := serveSSOWithSubject(t, test, &Session{ID: "s", NameID: "alice"}, subject)
			assertAuthnFailed(t, subjectResponse(t, w))
		})
	}
}

// The assertion must be confirmable in the manner of one of the requested confirmations, SAMLCore
// §3.3.4. Only bearer confirmations are made, and only their data can be compared.
func TestServeSSOMatchesSubjectConfirmation(t *testing.T) {
	data := func(d SubjectConfirmationData) func() []SubjectConfirmation {
		return func() []SubjectConfirmation {
			return []SubjectConfirmation{{Method: bearerSubjectConfirmationMethod, SubjectConfirmationData: &d}}
		}
	}
	// The times are made once the test has installed its clock.
	at := func(offset time.Duration, set func(*SubjectConfirmationData, time.Time)) func() []SubjectConfirmation {
		return func() []SubjectConfirmation {
			var d SubjectConfirmationData
			set(&d, TimeNow().Add(offset))
			return data(d)()
		}
	}
	notOnOrAfter := func(d *SubjectConfirmationData, t time.Time) { d.NotOnOrAfter = t }
	notBefore := func(d *SubjectConfirmationData, t time.Time) { d.NotBefore = t }
	for name, tc := range map[string]struct {
		confirmations func() []SubjectConfirmation
		success       bool
	}{
		"recipient":             {data(SubjectConfirmationData{Recipient: "https://sp.example.com/saml2/acs"}), true},
		"later not on or after": {at(time.Hour, notOnOrAfter), true},
		"holder of key":         {func() []SubjectConfirmation { return []SubjectConfirmation{{Method: holderOfKeyMethod}} }, false},
		"sender vouches": {func() []SubjectConfirmation {
			return []SubjectConfirmation{{Method: "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches"}}
		}, false},
		"other recipient":         {data(SubjectConfirmationData{Recipient: "https://other.example.com/acs"}), false},
		"other address":           {data(SubjectConfirmationData{Address: "192.0.2.99"}), false},
		"other request":           {data(SubjectConfirmationData{InResponseTo: "id-other"}), false},
		"earlier not on or after": {at(time.Second, notOnOrAfter), false},
		"not before":              {at(0, notBefore), false},
		"confirmation name id": {func() []SubjectConfirmation {
			return []SubjectConfirmation{{Method: bearerSubjectConfirmationMethod, NameID: &NameID{Value: "alice"}}}
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			w := serveSSOWithSubject(t, test, &Session{ID: "s", NameID: "alice"},
				&Subject{NameID: &NameID{Value: "alice"}, SubjectConfirmations: tc.confirmations()})
			response := subjectResponse(t, w)
			if tc.success {
				assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
			} else {
				assertAuthnFailed(t, response)
			}
		})
	}
}

// A custom AssertionMaker can make another kind of confirmation, which the default can't compare even
// when the request asks for it, so it needs a SubjectEnforcer which can.
func TestServeSSOMatchesConfirmationOfCustomAssertion(t *testing.T) {
	for name, requested := range map[string][]SubjectConfirmation{
		"bearer":        bearer(),
		"holder of key": {{Method: holderOfKeyMethod}},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			test.IDP.AssertionMaker = assertionMakerFunc(func(req *IdpAuthnRequest, session *Session) error {
				if err := (DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
					return err
				}
				req.Assertion.Subject.SubjectConfirmations = []SubjectConfirmation{{Method: holderOfKeyMethod}}
				return nil
			})
			subject := &Subject{NameID: &NameID{Value: "alice"}, SubjectConfirmations: requested}
			w := serveSSOWithSubject(t, test, &Session{ID: "s", NameID: "alice"}, subject)
			assertAuthnFailed(t, subjectResponse(t, w))
		})
	}
}

// The asserted validity period must lie within the requested one, and the asserted data must exist
// for the requested data to be met.
func TestSatisfiesConfirmationDataPeriod(t *testing.T) {
	now := TimeNow()
	for name, tc := range map[string]struct {
		requested SubjectConfirmationData
		asserted  *SubjectConfirmationData
		satisfied bool
	}{
		"no asserted data":            {SubjectConfirmationData{Recipient: "r"}, nil, false},
		"same not before":             {SubjectConfirmationData{NotBefore: now}, &SubjectConfirmationData{NotBefore: now}, true},
		"later not before":            {SubjectConfirmationData{NotBefore: now}, &SubjectConfirmationData{NotBefore: now.Add(time.Second)}, true},
		"earlier not before":          {SubjectConfirmationData{NotBefore: now}, &SubjectConfirmationData{NotBefore: now.Add(-time.Second)}, false},
		"no asserted not before":      {SubjectConfirmationData{NotBefore: now}, &SubjectConfirmationData{}, false},
		"same not on or after":        {SubjectConfirmationData{NotOnOrAfter: now}, &SubjectConfirmationData{NotOnOrAfter: now}, true},
		"no asserted not on or after": {SubjectConfirmationData{NotOnOrAfter: now}, &SubjectConfirmationData{}, false},
		"same address":                {SubjectConfirmationData{Address: "192.0.2.1"}, &SubjectConfirmationData{Address: "192.0.2.1"}, true},
		"address in other notation":   {SubjectConfirmationData{Address: "2001:DB8:0::1"}, &SubjectConfirmationData{Address: "2001:db8::1"}, true},
		"other address":               {SubjectConfirmationData{Address: "2001:db8::1"}, &SubjectConfirmationData{Address: "2001:db8::2"}, false},
		"invalid requested address":   {SubjectConfirmationData{Address: "192.0.2.1:443"}, &SubjectConfirmationData{Address: "192.0.2.1"}, false},
		"no asserted address":         {SubjectConfirmationData{Address: "192.0.2.1"}, &SubjectConfirmationData{}, false},
	} {
		t.Run(name, func(t *testing.T) {
			requested := tc.requested
			assert.Check(t, is.Equal(satisfiesConfirmationData(&requested, tc.asserted), tc.satisfied))
		})
	}
}

func TestServeSSOUsesConfiguredSubjectEnforcer(t *testing.T) {
	t.Run("accepts what the default would not", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.SubjectEnforcer = subjectEnforcerFunc(func(*IdpAuthnRequest, *Session) error { return nil })
		w := serveSSOWithSubject(t, test, &Session{ID: "s", NameID: "alice"},
			&Subject{NameID: &NameID{Format: string(EmailAddressNameIDFormat), Value: "alice@example.com"}})
		assert.Check(t, is.Equal(subjectResponse(t, w).Status.StatusCode.Value, StatusSuccess))
	})

	t.Run("refuses", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		var seen *Session
		test.IDP.SubjectEnforcer = subjectEnforcerFunc(func(_ *IdpAuthnRequest, session *Session) error {
			seen = session
			return errors.New("not the same principal")
		})
		session := &Session{ID: "s", NameID: "alice"}
		w := serveSSOWithSubject(t, test, session, &Subject{NameID: &NameID{Value: "alice"}})
		response := subjectResponse(t, w)
		assertAuthnFailed(t, response)
		assert.Check(t, response.Status.StatusMessage == nil)
		assert.Check(t, seen == session)
	})

	t.Run("not used without a subject", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.SubjectEnforcer = subjectEnforcerFunc(func(*IdpAuthnRequest, *Session) error {
			return errors.New("called")
		})
		w := serveSSOWithSubject(t, test, &Session{ID: "s", NameID: "alice"}, nil)
		assert.Check(t, is.Equal(subjectResponse(t, w).Status.StatusCode.Value, StatusSuccess))
	})
}

// An empty identifier names no principal, even if the session has none either.
func TestServeSSORejectsEmptySubject(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	w := serveSSOWithSubject(t, test, &Session{ID: "s"}, &Subject{NameID: &NameID{}})
	assertAuthnFailed(t, subjectResponse(t, w))
}
