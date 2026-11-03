package samlidp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// oversizedBody is valid JSON and XML up to the limit, so only the size can refuse it.
func oversizedBody(prefix, suffix string) io.Reader {
	return io.MultiReader(strings.NewReader(prefix), strings.NewReader(strings.Repeat("a", maxAdminBodySize)), strings.NewReader(suffix))
}

// paddedBody is a small JSON object followed by whitespace that takes it over the limit.
func paddedBody(object string) io.Reader {
	return io.MultiReader(strings.NewReader(object), strings.NewReader(strings.Repeat(" ", maxAdminBodySize)))
}

// A request body to an admin route is read whole, so its size is limited.
func TestAdminBodiesAreLimited(t *testing.T) {
	for path, body := range map[string]func() io.Reader{
		"/users/big":           func() io.Reader { return oversizedBody(`{"given_name":"`, `"}`) },
		"/users/paddedbig":     func() io.Reader { return paddedBody(`{"given_name":"x"}`) },
		"/shortcuts/big":       func() io.Reader { return oversizedBody(`{"service_provider":"`, `"}`) },
		"/shortcuts/paddedbig": func() io.Reader { return paddedBody(`{"service_provider":"x"}`) },
		"/services/big": func() io.Reader {
			return oversizedBody(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://big.example.com/`, `"/>`)
		},
	} {
		t.Run(path, func(t *testing.T) {
			test := NewServerTest(t)
			w := httptest.NewRecorder()
			test.Server.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "https://idp.example.com"+path, body()))
			assert.Check(t, is.Equal(w.Code, http.StatusRequestEntityTooLarge))

			keys, err := test.Store.List(strings.TrimSuffix(strings.TrimSuffix(path, "big"), "padded"))
			assert.NilError(t, err)
			assert.Check(t, is.Len(keys, 0))
		})
	}
}
