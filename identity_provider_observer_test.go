package saml

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// captureDefaultLog makes [slog.Default] write to the buffer that it returns, until the test ends.
func captureDefaultLog(t *testing.T) *bytes.Buffer {
	t.Helper()

	var logged bytes.Buffer

	previous := slog.Default()

	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	return &logged
}

// TestIDPNilObserverLogs checks that an identity provider embedded without an Observer reports to the default
// logger, so that a failure is never silent, rather than panicking.
func TestIDPNilObserverLogs(t *testing.T) {
	t.Run("ServeSSO", func(t *testing.T) {
		test := NewIdentityProviderTest(t)
		test.IDP.Observer = nil
		r := httptest.NewRequest("GET", "https://idp.example.com/saml/sso?SAMLRequest=%21", nil)
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, r)
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	})

	t.Run("ServeIDPInitiated", func(t *testing.T) {
		test := NewIdentityProviderTest(t)
		test.IDP.Observer = nil
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

	t.Run("unknown AttributeConsumingServiceIndex", func(t *testing.T) {
		logged := captureDefaultLog(t)

		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.Observer = nil
		req := attributeReleaseRequest(t, test, "3")
		assert.Check(t, is.Len(releasedAttributes(t, req, attributeReleaseSession()), 0))
		assert.Check(t, is.Contains(logged.String(), "releasing no attributes"))
	})

	t.Run("ServeSLO", func(t *testing.T) {
		test := NewIdentityProviderTest(t)
		test.IDP.Observer = nil
		r := httptest.NewRequest("GET", "https://idp.example.com/saml/slo?"+url.Values{
			"SAMLRequest": {"!"},
		}.Encode(), nil)
		w := httptest.NewRecorder()
		test.IDP.ServeSLO(w, r)
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	})
}
