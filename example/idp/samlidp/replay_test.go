package samlidp

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml"
)

// The login form posts the AuthnRequest back, once for each attempt, which is not a replay. Once the request is
// answered, presenting it again is one, whether with the credentials or with the session cookie.
func TestLoginFormRepresentsRequestAndReplayIsRefused(t *testing.T) {
	test := NewServerTest(t)
	hardeningAddUser(t, test)

	form := hardeningStartSSO(t, test)

	for range 2 {
		w := hardeningSubmitLogin(t, test, form, "wrong")
		require.Equal(t, w.Code, http.StatusOK)

		form = w.Body.String()
		assert.Equal(t, hardeningFormAction(t, form), "https://idp.example.com/sso")
	}

	answered := hardeningSubmitLogin(t, test, form, "hunter2")
	hardeningAssertSAMLResponse(t, answered, "frob")
	require.Len(t, answered.Result().Cookies(), 1)

	assertDenied := func(w *httptest.ResponseRecorder) {
		t.Helper()

		require.Equal(t, w.Code, http.StatusOK)

		body := w.Body.String()
		assert.Equal(t, hardeningFormAction(t, body), "https://sp.example.com/saml2/acs")

		response, err := base64.StdEncoding.DecodeString(hardeningHidden(t, body, "SAMLResponse"))
		require.NoError(t, err)
		assert.Contains(t, string(response), saml.StatusRequester)
		assert.Contains(t, string(response), saml.StatusRequestDenied)
		assert.False(t, strings.Contains(string(response), "Assertion"), string(response))
	}

	assertDenied(hardeningSubmitLogin(t, test, form, "hunter2"))

	values := url.Values{"SAMLRequest": {hardeningHidden(t, form, "SAMLRequest")}, "RelayState": {"frob"}}
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/sso", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(answered.Result().Cookies()[0])

	w := httptest.NewRecorder()
	test.Server.ServeHTTP(w, r)
	assertDenied(w)
}
