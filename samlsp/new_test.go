package samlsp

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
			require.NoError(t, err)

			cookieProvider := sp.Session.(CookieSessionProvider)
			require.Equal(t, tc.expected, cookieProvider.Name)
		})
	}
}

func TestDefaultServiceProviderRequestsEncryptedNameID(t *testing.T) {
	sp := DefaultServiceProvider(Options{URL: url.URL{Scheme: "https", Host: "sp.example.com"}, EncryptNameID: true})
	assert.True(t, sp.EncryptNameID)

	request, err := sp.MakeAuthenticationRequest("https://idp.example.com/sso", saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	require.NoError(t, err)
	assert.Equal(t, string(saml.EncryptedNameIDFormat), *request.NameIDPolicy.Format)

	sp = DefaultServiceProvider(Options{URL: url.URL{Scheme: "https", Host: "sp.example.com"}})
	assert.False(t, sp.EncryptNameID)
}
