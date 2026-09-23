package samlidp

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestSessionsCrud(t *testing.T) {
	test := NewServerTest(t)
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/sessions/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("{\"sessions\":[]}\n",
		w.Body.String()))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("PUT", "https://idp.example.com/users/alice",
		strings.NewReader(`{"name": "alice", "password": "hunter2"}`+"\n"))
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("POST", "https://idp.example.com/login",
		strings.NewReader("user=alice&password=hunter2"))
	r.Header.Set("Content-type", "application/x-www-form-urlencoded")
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("session=AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD4=; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=None",
		w.Header().Get("Set-Cookie")))
	assert.Check(t, is.Equal("{\"ID\":\"AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD4=\",\"CreateTime\":\"2015-12-01T01:57:09Z\",\"ExpireTime\":\"2015-12-01T02:57:09Z\",\"Index\":\"40424446484a4c4e50525456585a5c5e60626466686a6c6e70727476787a7c7e\",\"NameID\":\"\",\"NameIDFormat\":\"\",\"SubjectID\":\"\",\"Groups\":null,\"UserName\":\"alice\",\"UserEmail\":\"\",\"UserCommonName\":\"\",\"UserSurname\":\"\",\"UserGivenName\":\"\",\"UserScopedAffiliation\":\"\",\"CustomAttributes\":null}\n",
		w.Body.String()))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/login", nil)
	r.Header.Set("Cookie", "session=AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD4=")
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("{\"ID\":\"AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD4=\",\"CreateTime\":\"2015-12-01T01:57:09Z\",\"ExpireTime\":\"2015-12-01T02:57:09Z\",\"Index\":\"40424446484a4c4e50525456585a5c5e60626466686a6c6e70727476787a7c7e\",\"NameID\":\"\",\"NameIDFormat\":\"\",\"SubjectID\":\"\",\"Groups\":null,\"UserName\":\"alice\",\"UserEmail\":\"\",\"UserCommonName\":\"\",\"UserSurname\":\"\",\"UserGivenName\":\"\",\"UserScopedAffiliation\":\"\",\"CustomAttributes\":null}\n",
		w.Body.String()))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/sessions/AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD4=", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("{\"ID\":\"AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD4=\",\"CreateTime\":\"2015-12-01T01:57:09Z\",\"ExpireTime\":\"2015-12-01T02:57:09Z\",\"Index\":\"40424446484a4c4e50525456585a5c5e60626466686a6c6e70727476787a7c7e\",\"NameID\":\"\",\"NameIDFormat\":\"\",\"SubjectID\":\"\",\"Groups\":null,\"UserName\":\"alice\",\"UserEmail\":\"\",\"UserCommonName\":\"\",\"UserSurname\":\"\",\"UserGivenName\":\"\",\"UserScopedAffiliation\":\"\",\"CustomAttributes\":null}\n",
		w.Body.String()))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("DELETE", "https://idp.example.com/sessions/AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD4=", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/sessions/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("{\"sessions\":[]}\n",
		w.Body.String()))

	// user doesn't exists case
	w = httptest.NewRecorder()
	r, _ = http.NewRequest("POST", "https://idp.example.com/login",
		strings.NewReader("user=unknown&password=dummypassword"))
	r.Header.Set("Content-type", "application/x-www-form-urlencoded")
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("text/html; charset=utf-8",
		w.Header().Get("Content-type")))
	assert.Check(t, is.Equal(`<html><p>Invalid username or password</p><form method="post" action="https://idp.example.com/login"><input type="text" name="user" placeholder="user" value="" /><input type="password" name="password" placeholder="password" value="" /><input type="hidden" name="SAMLRequest" value="" /><input type="hidden" name="RelayState" value="" /><input type="submit" value="Log In" /></form></html>`,
		w.Body.String()))

	// invalid username/password exists case
	w = httptest.NewRecorder()
	r, _ = http.NewRequest("POST", "https://idp.example.com/login",
		strings.NewReader("user=alice&password=dummypassword"))
	r.Header.Set("Content-type", "application/x-www-form-urlencoded")
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("text/html; charset=utf-8",
		w.Header().Get("Content-type")))
	assert.Check(t, is.Equal(`<html><p>Invalid username or password</p><form method="post" action="https://idp.example.com/login"><input type="text" name="user" placeholder="user" value="" /><input type="password" name="password" placeholder="password" value="" /><input type="hidden" name="SAMLRequest" value="" /><input type="hidden" name="RelayState" value="" /><input type="submit" value="Log In" /></form></html>`,
		w.Body.String()))
}

func TestLoginSessionCookie(t *testing.T) {
	testCases := []struct {
		name     string
		scheme   string
		tls      bool
		secure   bool
		sameSite http.SameSite
	}{
		{name: "https", scheme: "https", secure: true, sameSite: http.SameSiteNoneMode},
		{name: "http", scheme: "http", secure: false, sameSite: http.SameSiteLaxMode},
		{name: "http with tls", scheme: "http", tls: true, secure: true, sameSite: http.SameSiteNoneMode},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			test := NewServerTest(t)
			test.Server.IDP.SSOURL.Scheme = tc.scheme

			hashedPassword, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
			assert.NilError(t, err)
			assert.NilError(t, test.Server.Store.Put("/users/alice", User{Name: "alice", HashedPassword: hashedPassword}))

			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("user=alice&password=hunter2"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}

			resp := httptest.NewRecorder()
			test.Server.ServeHTTP(resp, req)
			assert.Check(t, is.Equal(http.StatusOK, resp.Code))

			result := resp.Result()
			assert.Check(t, result.Body.Close())
			cookies := result.Cookies()
			assert.Assert(t, is.Len(cookies, 1))
			assert.Check(t, is.Equal("session", cookies[0].Name))
			assert.Check(t, is.Equal(tc.secure, cookies[0].Secure))
			assert.Check(t, is.Equal(tc.sameSite, cookies[0].SameSite))
		})
	}
}
