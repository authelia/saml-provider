package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

const hardeningIssuer = `<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com/saml2/metadata</Issuer>`

// hardeningRequest returns an otherwise valid AuthnRequest with the given ID attribute, issue
// instant and body.
func hardeningRequest(idAttr string, issueInstant time.Time, body string) []byte {
	return []byte(`<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`AssertionConsumerServiceURL="https://sp.example.com/saml2/acs" ` +
		`Destination="https://idp.example.com/saml/sso" ` + idAttr + ` ` +
		`IssueInstant="` + issueInstant.UTC().Format(time.RFC3339) + `" Version="2.0">` + body + `</AuthnRequest>`)
}

func hardeningValidate(test *IdentityProviderTest, buf []byte) (*IdpAuthnRequest, error) {
	req := &IdpAuthnRequest{Now: TimeNow(), IDP: &test.IDP, RequestBuffer: buf}
	req.HTTPRequest, _ = http.NewRequest("POST", "https://idp.example.com/saml/sso", nil)
	return req, req.Validate()
}

// hardeningIDPWithSessionCheck fails the test if a request reaches the session provider.
func hardeningIDPWithSessionCheck(t *testing.T) *IdentityProviderTest {
	t.Helper()
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
			t.Error("request must be rejected before the session is looked up")
			return nil
		},
	}
	return test
}

func hardeningDeflate(t *testing.T, data []byte) string {
	t.Helper()
	var compressed bytes.Buffer
	w, err := flate.NewWriter(&compressed, flate.BestCompression)
	assert.NilError(t, err)
	_, err = w.Write(data)
	assert.NilError(t, err)
	assert.NilError(t, w.Close())
	return base64.StdEncoding.EncodeToString(compressed.Bytes())
}

func TestIDPValidateRequestSizeLimit(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	valid := hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer)

	pad := func(size int) []byte {
		return append(bytes.Clone(valid), bytes.Repeat([]byte(" "), size-len(valid))...)
	}

	_, err := hardeningValidate(test, pad(maxAuthnRequestSize))
	assert.Check(t, err)

	_, err = hardeningValidate(test, pad(maxAuthnRequestSize+1))
	assert.Check(t, is.ErrorContains(err, "exceeds"))
}

func TestIDPServeSSORejectsOversizedRequestsBeforeParsing(t *testing.T) {
	// Valid in every respect except its size, so only the size limit can reject it.
	oversized := append(hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer), bytes.Repeat([]byte(" "), maxAuthnRequestSize)...)

	t.Run("redirect", func(t *testing.T) {
		test := hardeningIDPWithSessionCheck(t)
		r := httptest.NewRequest("GET", "https://idp.example.com/saml/sso?"+url.Values{
			"SAMLRequest": {hardeningDeflate(t, oversized)},
		}.Encode(), nil)
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, r)
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	})

	t.Run("post", func(t *testing.T) {
		test := hardeningIDPWithSessionCheck(t)
		r := httptest.NewRequest("POST", "https://idp.example.com/saml/sso", strings.NewReader(url.Values{
			"SAMLRequest": {base64.StdEncoding.EncodeToString(oversized)},
		}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, r)
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	})
}

func TestIDPServeSSORejectsMissingIssuer(t *testing.T) {
	for name, body := range map[string]string{
		"absent": "",
		"empty":  `<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion"></Issuer>`,
	} {
		t.Run(name, func(t *testing.T) {
			test := hardeningIDPWithSessionCheck(t)
			r := httptest.NewRequest("GET", "https://idp.example.com/saml/sso?"+url.Values{
				"SAMLRequest": {hardeningDeflate(t, hardeningRequest(`ID="id-1"`, TimeNow(), body))},
			}.Encode(), nil)
			w := httptest.NewRecorder()
			test.IDP.ServeSSO(w, r)
			assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
		})
	}
}

func TestIDPValidateIssueInstantBounds(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	for _, tc := range []struct {
		name   string
		offset time.Duration
		errMsg string
	}{
		{name: "now", offset: 0},
		{name: "at the skew limit", offset: MaxClockSkew},
		{name: "beyond the skew limit", offset: MaxClockSkew + time.Second, errMsg: "in the future"},
		{name: "far future", offset: 24 * 365 * 20 * time.Hour, errMsg: "in the future"},
		{name: "at the age limit", offset: -MaxIssueDelay},
		{name: "beyond the age limit", offset: -MaxIssueDelay - time.Second, errMsg: "expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow().Add(tc.offset), hardeningIssuer))
			if tc.errMsg == "" {
				assert.Check(t, err)
				return
			}
			assert.Check(t, is.ErrorContains(err, tc.errMsg))
		})
	}
}

func TestIDPAssertionConditionsUseIDPClock(t *testing.T) {
	for name, offset := range map[string]time.Duration{
		"request is old":             -85 * time.Second,
		"request is current":         0,
		"sp clock is slightly ahead": 2 * time.Minute,
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow().Add(offset), hardeningIssuer))
			assert.NilError(t, err)
			assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice"}))

			assert.Check(t, req.Assertion.Conditions.NotBefore.Equal(TimeNow().Add(-MaxClockSkew)),
				"NotBefore=%s", req.Assertion.Conditions.NotBefore)
			assert.Check(t, req.Assertion.Conditions.NotOnOrAfter.Equal(TimeNow().Add(MaxIssueDelay)),
				"NotOnOrAfter=%s", req.Assertion.Conditions.NotOnOrAfter)
		})
	}
}

func TestIDPValidateRequestID(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	for name, tc := range map[string]struct {
		attr  string
		valid bool
	}{
		"missing":        {attr: ``},
		"empty":          {attr: `ID=""`},
		"space":          {attr: `ID="a b"`},
		"line feed":      {attr: "ID=\"a\nb\""},
		"tab":            {attr: "ID=\"a\tb\""},
		"markup":         {attr: `ID="a&lt;b"`},
		"quote":          {attr: `ID="a&quot;b"`},
		"colon":          {attr: `ID="a:b"`},
		"underscore":     {attr: `ID="_abc"`, valid: true},
		"id prefix":      {attr: `ID="id-00020406.08_0a"`, valid: true},
		"leading digit":  {attr: `ID="0f8fad5b-d9cb-469f-a165-70867728950e"`, valid: true},
		"unicode letter": {attr: `ID="idé"`},
		"no-break space": {attr: "ID=\"a\u00a0b\""},
		"zero width":     {attr: "ID=\"a\u200bb\""},
		"at the limit":   {attr: `ID="` + strings.Repeat("a", maxAuthnRequestIDLength) + `"`, valid: true},
		"over the limit": {attr: `ID="` + strings.Repeat("a", maxAuthnRequestIDLength+1) + `"`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := hardeningValidate(test, hardeningRequest(tc.attr, TimeNow(), hardeningIssuer))
			if tc.valid {
				assert.Check(t, err)
				return
			}
			assert.Check(t, is.ErrorContains(err, "request ID"))
		})
	}
}

func TestIDPValidateErrorOmitsRequestID(t *testing.T) {
	// The error is logged without authentication, so it must not grow with the request.
	test := NewIdentityProviderTest(t, applyKey)
	_, err := hardeningValidate(test, hardeningRequest(`ID="`+strings.Repeat("x y", 1000)+`"`, TimeNow(), hardeningIssuer))
	assert.Check(t, is.ErrorContains(err, "request ID"))
	assert.Check(t, !strings.Contains(err.Error(), "x y"), err.Error())
}

func TestIDPGetSPEncryptionCert(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	certData := base64.StdEncoding.EncodeToString(test.SPCertificate.Raw)

	withCert := func(use string) KeyDescriptor {
		return KeyDescriptor{Use: use, KeyInfo: KeyInfo{X509Data: X509Data{X509Certificates: []X509Certificate{{Data: certData}}}}}
	}
	emptyThenCert := func(use string) KeyDescriptor {
		return KeyDescriptor{Use: use, KeyInfo: KeyInfo{X509Data: X509Data{X509Certificates: []X509Certificate{{}, {Data: certData}}}}}
	}
	noCerts := KeyDescriptor{Use: "encryption"}
	emptyCert := KeyDescriptor{Use: "encryption", KeyInfo: KeyInfo{X509Data: X509Data{X509Certificates: []X509Certificate{{}}}}}

	for _, tc := range []struct {
		name        string
		descriptors []KeyDescriptor
		found       bool
		notExist    bool
	}{
		{name: "no descriptors", notExist: true},
		{name: "signing only", descriptors: []KeyDescriptor{withCert("signing")}, notExist: true},
		{name: "encryption", descriptors: []KeyDescriptor{withCert("encryption")}, found: true},
		{name: "unspecified use", descriptors: []KeyDescriptor{withCert("")}, found: true},
		{name: "encryption without certificates", descriptors: []KeyDescriptor{noCerts}},
		{name: "encryption with an empty certificate", descriptors: []KeyDescriptor{emptyCert}},
		{name: "unusable encryption then usable", descriptors: []KeyDescriptor{noCerts, withCert("encryption")}, found: true},
		{name: "unusable encryption then unspecified", descriptors: []KeyDescriptor{noCerts, withCert("")}, found: true},
		{name: "unusable encryption and signing", descriptors: []KeyDescriptor{noCerts, withCert("signing")}},
		{name: "empty then usable certificate in an encryption descriptor", descriptors: []KeyDescriptor{emptyThenCert("encryption")}, found: true},
		{name: "empty then usable certificate with unspecified use", descriptors: []KeyDescriptor{emptyThenCert("")}, found: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &IdpAuthnRequest{IDP: &test.IDP, Now: TimeNow(), SPSSODescriptor: &SPSSODescriptor{SSODescriptor: SSODescriptor{RoleDescriptor: RoleDescriptor{KeyDescriptors: tc.descriptors}}}}
			cert, err := req.getSPEncryptionCert()
			switch {
			case tc.found:
				assert.Check(t, err)
				assert.Check(t, cert != nil)
			case tc.notExist:
				assert.Check(t, is.Equal(os.ErrNotExist, err))
			default:
				// Fail closed: this must not be os.ErrNotExist, which would send the assertion
				// in plaintext to an SP that asked for encryption.
				assert.Check(t, err != nil && err != os.ErrNotExist, fmt.Sprintf("err=%v", err))
			}
		})
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestNewIdpAuthnRequestLimitsPostBody(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	samlRequest := base64.StdEncoding.EncodeToString(hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))

	post := func(body io.Reader) *http.Request {
		r := httptest.NewRequest("POST", "https://idp.example.com/saml/sso", body)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	form := func(size int) string {
		prefix := "SAMLRequest=" + url.QueryEscape(samlRequest) + "&RelayState="
		return prefix + strings.Repeat("a", size-len(prefix))
	}

	t.Run("at the limit", func(t *testing.T) {
		req, err := NewIdpAuthnRequest(&test.IDP, post(strings.NewReader(form(maxAuthnRequestBodySize))))
		assert.NilError(t, err)
		assert.Check(t, is.Equal(samlRequest, base64.StdEncoding.EncodeToString(req.RequestBuffer)))
	})

	t.Run("over the limit stops reading", func(t *testing.T) {
		body := &countingReader{r: strings.NewReader(form(10 * maxAuthnRequestBodySize))}
		_, err := NewIdpAuthnRequest(&test.IDP, post(body))
		assert.Check(t, err != nil)
		assert.Check(t, body.n <= maxAuthnRequestBodySize+1, "read %d bytes", body.n)
	})

	t.Run("largest request with every base64 character escaped fits", func(t *testing.T) {
		encoded := strings.Repeat("%2B", base64.StdEncoding.EncodedLen(maxAuthnRequestSize))
		_, err := NewIdpAuthnRequest(&test.IDP, post(strings.NewReader("SAMLRequest="+encoded)))
		assert.Check(t, err == nil || !strings.Contains(err.Error(), "too large"), "err=%v", err)
	})

	t.Run("no body", func(t *testing.T) {
		r, err := http.NewRequest("POST", "https://idp.example.com/saml/sso", nil)
		assert.NilError(t, err)
		_, err = NewIdpAuthnRequest(&test.IDP, r)
		assert.Check(t, is.Error(err, "missing form body"))
	})
}

func TestIDPMaxAuthnRequestAge(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	old := hardeningRequest(`ID="id-1"`, TimeNow().Add(-4*time.Minute), hardeningIssuer)

	_, err := hardeningValidate(test, old)
	assert.Check(t, is.ErrorContains(err, "expired"), "the default age limit is MaxIssueDelay")

	test.IDP.MaxAuthnRequestAge = 5 * time.Minute
	req, err := hardeningValidate(test, old)
	assert.NilError(t, err)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "alice"}))
	assert.Check(t, req.Assertion.Conditions.NotOnOrAfter.Equal(TimeNow().Add(MaxIssueDelay)),
		"an old request must not shorten the assertion lifetime")

	test.IDP.MaxAuthnRequestAge = 3 * time.Minute
	_, err = hardeningValidate(test, old)
	assert.Check(t, is.ErrorContains(err, "expired"))
}
