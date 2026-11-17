package samlsp

import (
	"net/url"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml"
)

func TestNewCanAcceptCookieName(t *testing.T) {
	testCases := []struct {
		testName   string
		cookieName string
		expected   string
	}{
		{"Works with alt name", "altCookie", "altCookie"},
		{"Works with default", "", "token"},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			opts := Options{
				CookieName: tc.cookieName,
			}
			sp, err := New(opts)
			assert.Assert(t, err)

			cookieProvider := sp.Session.(CookieSessionProvider)
			assert.Equal(t, tc.expected, cookieProvider.Name)
		})
	}
}

func TestDefaultServiceProviderRequestsEncryptedNameID(t *testing.T) {
	sp := DefaultServiceProvider(Options{URL: url.URL{Scheme: "https", Host: "sp.example.com"}, EncryptNameID: true})
	assert.Check(t, sp.EncryptNameID)

	request, err := sp.MakeAuthenticationRequest("https://idp.example.com/sso", saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(string(saml.EncryptedNameIDFormat), *request.NameIDPolicy.Format))

	sp = DefaultServiceProvider(Options{URL: url.URL{Scheme: "https", Host: "sp.example.com"}})
	assert.Check(t, !sp.EncryptNameID)
}
