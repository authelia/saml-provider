package saml

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
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
			return req.WriteErrorResponse(w, StatusResponder, StatusNoAuthnContext, "")
		},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
			assert.NilError(t, err)

			w := httptest.NewRecorder()
			assert.NilError(t, write(req, w))
			assert.Check(t, is.Equal(w.Header().Get("Cache-Control"), "no-cache, no-store"))
			assert.Check(t, is.Equal(w.Header().Get("Pragma"), "no-cache"))
		})
	}
}
