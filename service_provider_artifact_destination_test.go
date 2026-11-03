package saml

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// recordingTransport records the outbound request and fails it, so nothing leaves the test.
type recordingTransport struct {
	url  string
	body string
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.url = req.URL.String()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	r.body = string(body)
	return nil, errors.New("request recorded")
}

// The artifact comes from the client, but the request it causes must only ever go to the location in
// the metadata of the identity provider, with the artifact as text in the body.
func TestArtifactResolutionOnlyContactsLocationInMetadata(t *testing.T) {
	const location = "https://idp.example.com/saml/artifact"

	for _, artifact := range []string{
		"AAQAAMFbLinlXaCM+FIxiDwGOLAy2T71gbpO7ZhNzAgEANlB90ECfpNEVLg=",
		"http://169.254.169.254/latest/meta-data/",
		"https://attacker.example.com/",
		"</samlp:Artifact><samlp:Artifact>forged",
		"\"><x:y xmlns:x=\"urn:x\"/>",
	} {
		t.Run(artifact, func(t *testing.T) {
			test := NewServiceProviderTest(t)
			transport := &recordingTransport{}
			sp := ServiceProvider{
				Key:         test.Key,
				Certificate: test.Certificate,
				MetadataURL: mustParseURL("https://sp.example.com/saml2/metadata"),
				AcsURL:      mustParseURL("https://sp.example.com/saml2/acs"),
				IDPMetadata: &EntityDescriptor{},
				HTTPClient:  &http.Client{Transport: transport},
			}
			assert.NilError(t, xml.Unmarshal(test.IDPMetadata, sp.IDPMetadata))
			sp.IDPMetadata.IDPSSODescriptors[0].ArtifactResolutionServices = []Endpoint{
				{Binding: SOAPBinding, Location: location},
			}

			req, err := http.NewRequest(http.MethodPost, sp.AcsURL.String(), strings.NewReader(url.Values{"SAMLart": {artifact}}.Encode()))
			assert.NilError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			assert.NilError(t, req.ParseForm())

			_, err = sp.ParseResponse(req, nil)
			assert.Assert(t, err != nil)
			assert.Check(t, is.Equal(location, transport.url))

			doc := etree.NewDocument()
			assert.NilError(t, doc.ReadFromString(transport.body))
			artifacts := doc.FindElements("//Artifact")
			assert.Assert(t, is.Len(artifacts, 1))
			assert.Check(t, is.Equal(artifact, artifacts[0].Text()))
			assert.Check(t, is.Len(doc.FindElements("//y"), 0))
		})
	}
}

// A redirect would send the signed request somewhere other than the location in the metadata, so it
// is an error rather than being followed.
func TestArtifactResolutionDoesNotFollowRedirects(t *testing.T) {
	for _, status := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var hits atomic.Int32
			internal := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
			defer internal.Close()
			idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, internal.URL, status)
			}))
			defer idp.Close()

			for name, client := range map[string]*http.Client{
				"default client": nil,
				"custom client":  {CheckRedirect: func(*http.Request, []*http.Request) error { return nil }},
			} {
				t.Run(name, func(t *testing.T) {
					test := NewServiceProviderTest(t)
					sp := ServiceProvider{
						Key:         test.Key,
						Certificate: test.Certificate,
						MetadataURL: mustParseURL("https://sp.example.com/saml2/metadata"),
						AcsURL:      mustParseURL("https://sp.example.com/saml2/acs"),
						IDPMetadata: &EntityDescriptor{},
						HTTPClient:  client,
					}
					assert.NilError(t, xml.Unmarshal(test.IDPMetadata, sp.IDPMetadata))
					sp.IDPMetadata.IDPSSODescriptors[0].ArtifactResolutionServices = []Endpoint{{Binding: SOAPBinding, Location: idp.URL}}

					req, err := http.NewRequest(http.MethodPost, sp.AcsURL.String(), strings.NewReader(url.Values{"SAMLart": {"artifact"}}.Encode()))
					assert.NilError(t, err)
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					assert.NilError(t, req.ParseForm())

					_, err = sp.ParseResponse(req, nil)
					assert.Assert(t, err != nil)
					assert.Check(t, is.Equal(int32(0), hits.Load()))
					assert.Check(t, is.ErrorContains(err.(*InvalidResponseError).PrivateErr, "HTTP status"))
				})
			}
		})
	}

	t.Run("the client of the caller is not changed", func(t *testing.T) {
		client := &http.Client{}
		test := NewServiceProviderTest(t)
		sp := ServiceProvider{
			Key:         test.Key,
			Certificate: test.Certificate,
			MetadataURL: mustParseURL("https://sp.example.com/saml2/metadata"),
			AcsURL:      mustParseURL("https://sp.example.com/saml2/acs"),
			IDPMetadata: &EntityDescriptor{},
			HTTPClient:  client,
		}
		assert.NilError(t, xml.Unmarshal(test.IDPMetadata, sp.IDPMetadata))
		_, _ = sp.handleArtifactRequest(context.Background(), "artifact", nil)
		assert.Check(t, client.CheckRedirect == nil)
		assert.Check(t, http.DefaultClient.CheckRedirect == nil)
	})
}
