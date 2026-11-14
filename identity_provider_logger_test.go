package saml

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// TestIDPNilLoggerDoesNotPanic checks that an identity provider embedded without a Logger falls back
// to the default logger rather than panicking when it has to log a failure.
func TestIDPNilLoggerDoesNotPanic(t *testing.T) {
	t.Run("ServeSSO", func(t *testing.T) {
		test := NewIdentityProviderTest(t)
		test.IDP.Logger = nil
		r := httptest.NewRequest("GET", "https://idp.example.com/saml/sso?SAMLRequest=%21", nil)
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, r)
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	})

	t.Run("ServeIDPInitiated", func(t *testing.T) {
		test := NewIdentityProviderTest(t)
		test.IDP.Logger = nil
		test.IDP.SessionProvider = &mockSessionProvider{
			GetSessionFunc: func(_ http.ResponseWriter, _ *http.Request, _ *IdpAuthnRequest) *Session {
				return &Session{ID: "session-id", NameID: "alice"}
			},
		}
		r := httptest.NewRequest("GET", "https://idp.example.com/saml/idp-initiated", nil)
		w := httptest.NewRecorder()
		test.IDP.ServeIDPInitiated(w, r, "https://unknown.example.com/metadata", "")
		assert.Check(t, is.Equal(http.StatusNotFound, w.Code))
	})

	t.Run("ServeSLO", func(t *testing.T) {
		test := NewIdentityProviderTest(t)
		test.IDP.Logger = nil
		r := httptest.NewRequest("GET", "https://idp.example.com/saml/slo?"+url.Values{
			"SAMLRequest": {"!"},
		}.Encode(), nil)
		w := httptest.NewRecorder()
		test.IDP.ServeSLO(w, r)
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	})
}
