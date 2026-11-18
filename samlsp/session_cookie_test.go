package samlsp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml"
)

func TestCookieSameSite(t *testing.T) {
	t.Parallel()

	csp := CookieSessionProvider{
		Name:   "token",
		Domain: "localhost",
		Codec: DefaultSessionCodec(Options{
			Key: NewMiddlewareTest(t).JWTKey,
		}),
	}

	getSessionCookie := func(tb testing.TB) *http.Cookie {
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		err := csp.CreateSession(resp, req, &saml.Assertion{})
		assert.NoError(tb, err)

		result := resp.Result()
		cookies := result.Cookies()
		assert.Len(tb, cookies, 1, "Expected to have a cookie set")
		assert.NoError(tb, result.Body.Close())

		return cookies[0]
	}

	t.Run("no same site", func(t *testing.T) {
		cookie := getSessionCookie(t)
		assert.Equal(t, http.SameSite(0), cookie.SameSite)
	})

	t.Run("with same site", func(t *testing.T) {
		csp.SameSite = http.SameSiteStrictMode
		cookie := getSessionCookie(t)
		assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
	})
}

func TestCookieSessionProviderDeleteSession(t *testing.T) {
	csp := CookieSessionProvider{
		Name:   "token",
		Domain: "localhost:8080",
		Codec: DefaultSessionCodec(Options{
			Key: NewMiddlewareTest(t).JWTKey,
		}),
	}

	t.Run("expires the cookie", func(t *testing.T) {
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Cookie", "token=session")

		require.NoError(t, csp.DeleteSession(resp, req))

		result := resp.Result()
		assert.NoError(t, result.Body.Close())
		cookies := result.Cookies()
		require.Len(t, cookies, 1)
		assert.Equal(t, "token", cookies[0].Name)
		assert.Equal(t, "", cookies[0].Value)
		assert.Equal(t, "localhost", cookies[0].Domain)
		assert.Equal(t, "/", cookies[0].Path)
		assert.True(t, cookies[0].Expires.Before(saml.TimeNow()))
	})

	t.Run("no cookie", func(t *testing.T) {
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		require.NoError(t, csp.DeleteSession(resp, req))
		assert.Len(t, resp.Result().Cookies(), 0)
	})
}
