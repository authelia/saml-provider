package saml

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The page which posts the response carries the assertion, so a browser or proxy must not keep it.
// SAMLBind §3.5.5.1.
func TestWriteResponseIsNotCached(t *testing.T) {
	for name, write := range map[string]func(*IdpAuthnRequest, http.ResponseWriter) error{
		"assertion": func(req *IdpAuthnRequest, w http.ResponseWriter) error {
			if err := (DefaultAssertionMaker{}).MakeAssertion(req, &Session{ID: "f00d", NameID: "alice"}); err != nil {
				return err
			}

			return req.WriteResponse(w)
		},
		"error status": func(req *IdpAuthnRequest, w http.ResponseWriter) error {
			return req.WriteErrorResponse(w, ErrNoAuthnContext)
		},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
			require.NoError(t, err)

			w := httptest.NewRecorder()
			require.NoError(t, write(req, w))
			assert.Equal(t, w.Header().Get("Cache-Control"), "no-cache, no-store")
			assert.Equal(t, w.Header().Get("Pragma"), "no-cache")
		})
	}
}
