package saml

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/dsig"
)

const inResponseToError = "`InResponseTo` does not match"

// privateError returns the reason for a rejection, which an InvalidResponseError keeps private.
func privateError(err error) error {
	if invalid, ok := err.(*InvalidResponseError); ok {
		return invalid.PrivateErr
	}

	return err
}

func TestSPChecksInResponseToOfRedirectLogoutResponse(t *testing.T) {
	for _, tc := range []struct {
		name         string
		inResponseTo string
		possible     []string
		valid        bool
	}{
		{"matches", ` InResponseTo="id-request"`, []string{"id-request"}, true},
		{"matches one of many", ` InResponseTo="id-request"`, []string{"id-other", "id-request"}, true},
		{"another request", ` InResponseTo="id-other"`, []string{"id-request"}, false},
		{"none are pending", ` InResponseTo="id-request"`, nil, false},
		{"empty list", ` InResponseTo="id-request"`, []string{}, false},
		{"missing", ``, []string{"id-request"}, false},
		{"missing with nothing pending", ``, nil, false},
		{"empty", ` InResponseTo=""`, []string{""}, false},
		{"case differs", ` InResponseTo="ID-REQUEST"`, []string{"id-request"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLogoutResponseFixture(t)
			f.setMessageInResponseTo(t, f.sp.SloURL.String(), tc.inResponseTo)

			err := f.sp.ValidateLogoutResponseRedirect(&url.URL{RawQuery: f.signed(t, "")}, tc.possible)
			if tc.valid {
				assert.NoError(t, err)
				return
			}

			require.NotNil(t, err)
			assert.ErrorContains(t, privateError(err), inResponseToError)
		})
	}
}

// signedLogoutResponseForm returns a logout response from the identity provider with an embedded
// signature, encoded for the HTTP-POST binding.
func signedLogoutResponseForm(t *testing.T, f *logoutResponseFixture, inResponseTo string) string {
	t.Helper()

	idp := ServiceProvider{
		EntityID:        f.sp.IDPMetadata.EntityID,
		Key:             f.key,
		Certificate:     f.cert,
		IDPMetadata:     f.sp.IDPMetadata,
		SignatureMethod: dsig.RSASHA256SignatureMethod,
	}
	response, err := idp.MakeLogoutResponse(f.sp.SloURL.String(), inResponseTo)
	require.NoError(t, err)

	doc := etree.NewDocument()
	doc.SetRoot(response.Element())
	body, err := doc.WriteToBytes()
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(body)
}

func TestSPChecksInResponseToOfPostLogoutResponse(t *testing.T) {
	f := newLogoutResponseFixture(t)
	assert.NoError(t, f.sp.ValidateLogoutResponseForm(signedLogoutResponseForm(t, f, "id-request"), []string{"id-request"}))

	err := f.sp.ValidateLogoutResponseForm(signedLogoutResponseForm(t, f, "id-other"), []string{"id-request"})
	require.NotNil(t, err)
	assert.ErrorContains(t, privateError(err), inResponseToError)

	err = f.sp.ValidateLogoutResponseForm(signedLogoutResponseForm(t, f, ""), []string{"id-request"})
	require.NotNil(t, err)
	assert.ErrorContains(t, privateError(err), inResponseToError)
}

func TestValidateLogoutResponseRequestPassesPossibleRequestIDs(t *testing.T) {
	f := newLogoutResponseFixture(t)

	redirect, err := http.NewRequest(http.MethodGet, "https://sp.example.com/saml2/slo?"+f.signed(t, ""), nil)
	require.NoError(t, err)
	assert.NoError(t, f.sp.ValidateLogoutResponseRequest(redirect, []string{"id-request"}))
	assert.ErrorContains(t, privateError(f.sp.ValidateLogoutResponseRequest(redirect, []string{"id-other"})), inResponseToError)

	form := url.Values{"SAMLResponse": {signedLogoutResponseForm(t, f, "id-request")}}.Encode()
	newPost := func() *http.Request {
		post, err := http.NewRequest(http.MethodPost, "https://sp.example.com/saml2/slo", strings.NewReader(form))
		require.NoError(t, err)
		post.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		return post
	}
	assert.NoError(t, f.sp.ValidateLogoutResponseRequest(newPost(), []string{"id-request"}))
	assert.ErrorContains(t, privateError(f.sp.ValidateLogoutResponseRequest(newPost(), []string{"id-other"})), inResponseToError)
}

func TestLogoutRequestIDCanBeTrackedAcrossBindings(t *testing.T) {
	f := newLogoutResponseFixture(t)
	sp := f.sp
	sp.SignatureMethod = ""

	request, err := sp.MakeLogoutRequest("https://idp.example.com/slo", "alice")
	require.NoError(t, err)
	require.True(t, request.ID != "")
	_, err = request.Redirect("", &sp)
	require.NoError(t, err)

	f.setMessageInResponseTo(t, sp.SloURL.String(), ` InResponseTo="`+request.ID+`"`)
	assert.NoError(t, sp.ValidateLogoutResponseRedirect(&url.URL{RawQuery: f.signed(t, "")}, []string{request.ID}))
}

func TestLogoutResponseExpiryUsesTimeNow(t *testing.T) {
	f := newLogoutResponseFixture(t)
	query := f.signed(t, "")
	u := &url.URL{RawQuery: query}
	assert.NoError(t, f.sp.ValidateLogoutResponseRedirect(u, []string{"id-request"}))

	TimeNow = func() time.Time { return time.Now().Add(MaxIssueDelay + time.Hour) }
	err := f.sp.ValidateLogoutResponseRedirect(u, []string{"id-request"})
	require.NotNil(t, err)
	assert.ErrorContains(t, privateError(err), "expired")
}

func TestSPRejectsLogoutResponseWithoutIssuer(t *testing.T) {
	f := newLogoutResponseFixture(t)
	f.setMessageWithoutIssuer(t)
	err := f.sp.ValidateLogoutResponseRedirect(&url.URL{RawQuery: f.signed(t, "")}, []string{"id-request"})
	require.NotNil(t, err)
	assert.ErrorContains(t, privateError(err), "issuer")
}
