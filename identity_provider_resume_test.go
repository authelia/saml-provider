package saml

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResumeFormValues(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(_ http.ResponseWriter, _ *http.Request, _ *IdpAuthnRequest) *Session {
			return &Session{ID: "f00df00df00d", NameID: "alice", UserName: "alice"}
		},
	}

	requestURL, err := test.SP.MakeRedirectAuthenticationRequest("ThisIsTheRelayState")
	require.NoError(t, err)

	r, _ := http.NewRequest("GET", requestURL.String(), nil)
	req, err := NewIdpAuthnRequest(&test.IDP, r)
	require.NoError(t, err)

	req.RedirectQuery = ""

	values := req.ResumeFormValues()
	require.Equal(t, len(values), 2)
	assert.Equal(t, "ThisIsTheRelayState", values.Get("RelayState"))
	assert.True(t, values.Get("SAMLRequest") != "")

	post := func(v url.Values) *httptest.ResponseRecorder {
		pr, _ := http.NewRequest("POST", "https://idp.example.com/saml/sso", strings.NewReader(v.Encode()))
		pr.Header.Set("Content-type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, pr)

		return w
	}

	w := post(values)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "SAMLResponse")
	assert.Contains(t, w.Body.String(), "https://sp.example.com/saml2/acs")

	req.RedirectQuery = requestURL.RawQuery

	values = req.ResumeFormValues()
	require.Equal(t, len(values), 3)
	assert.Equal(t, requestURL.RawQuery, values.Get(RedirectQueryFormField))

	w = post(values)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "SAMLResponse")
}

func TestNewFakeClockAt(t *testing.T) {
	orig := Clock

	t.Cleanup(func() { Clock = orig })

	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	Clock = NewFakeClockAt(at)

	assert.True(t, Clock.Now().Equal(at))
}
