package saml

import (
	"bytes"
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
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			require.NoError(t, xml.Unmarshal(test.IDPMetadata, sp.IDPMetadata))
			sp.IDPMetadata.IDPSSODescriptors[0].ArtifactResolutionServices = []IndexedEndpoint{
				{Binding: SOAPBinding, Location: location},
			}

			req, err := http.NewRequest(http.MethodPost, sp.AcsURL.String(), strings.NewReader(url.Values{"SAMLart": {artifact}}.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			require.NoError(t, req.ParseForm())

			_, err = sp.ParseResponse(req, nil)
			require.NotNil(t, err)
			assert.Equal(t, location, transport.url)

			doc := etree.NewDocument()
			require.NoError(t, doc.ReadFromString(transport.body))
			artifacts := doc.FindElements("//Artifact")
			require.Len(t, artifacts, 1)
			assert.Equal(t, artifact, artifacts[0].Text())
			assert.Len(t, doc.FindElements("//y"), 0)
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
					require.NoError(t, xml.Unmarshal(test.IDPMetadata, sp.IDPMetadata))
					sp.IDPMetadata.IDPSSODescriptors[0].ArtifactResolutionServices = []IndexedEndpoint{{Binding: SOAPBinding, Location: idp.URL}}

					req, err := http.NewRequest(http.MethodPost, sp.AcsURL.String(), strings.NewReader(url.Values{"SAMLart": {"artifact"}}.Encode()))
					require.NoError(t, err)
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					require.NoError(t, req.ParseForm())

					_, err = sp.ParseResponse(req, nil)
					require.NotNil(t, err)
					assert.Equal(t, int32(0), hits.Load())
					assert.ErrorContains(t, err.(*InvalidResponseError).PrivateErr, "HTTP status")
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
		require.NoError(t, xml.Unmarshal(test.IDPMetadata, sp.IDPMetadata))
		_, _ = sp.handleArtifactRequest(context.Background(), "artifact", nil)

		assert.Nil(t, client.CheckRedirect)
		assert.Nil(t, http.DefaultClient.CheckRedirect)
	})
}

// artifactRequestTo returns a service provider which resolves artifacts at location, and a request
// containing an artifact.
func artifactRequestTo(t *testing.T, location string) (*ServiceProvider, *http.Request) {
	t.Helper()
	test := NewServiceProviderTest(t)
	sp := &ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://sp.example.com/saml2/metadata"),
		AcsURL:      mustParseURL("https://sp.example.com/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	require.NoError(t, xml.Unmarshal(test.IDPMetadata, sp.IDPMetadata))
	sp.IDPMetadata.IDPSSODescriptors[0].ArtifactResolutionServices = []IndexedEndpoint{{Binding: SOAPBinding, Location: location}}

	req, err := http.NewRequest(http.MethodPost, sp.AcsURL.String(), strings.NewReader(url.Values{"SAMLart": {"artifact"}}.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, req.ParseForm())

	return sp, req
}

func TestArtifactResolutionLimitsResponseSize(t *testing.T) {
	previous := maxArtifactResponseSize
	maxArtifactResponseSize = 1024

	t.Cleanup(func() { maxArtifactResponseSize = previous })

	for _, tc := range []struct {
		name    string
		size    int
		tooMuch bool
	}{
		{"at the limit", 1024, false},
		{"over the limit", 1025, true},
		{"far over the limit", 1 << 20, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(bytes.Repeat([]byte(" "), tc.size))
			}))
			defer idp.Close()

			sp, req := artifactRequestTo(t, idp.URL)
			_, err := sp.ParseResponse(req, nil)
			require.NotNil(t, err)

			reason := err.(*InvalidResponseError).PrivateErr
			if tc.tooMuch {
				assert.ErrorContains(t, reason, "too large")
			} else {
				assert.False(t, strings.Contains(reason.Error(), "too large"), reason.Error())
			}
		})
	}
}

func TestArtifactResolutionTimeout(t *testing.T) {
	previous := defaultArtifactResolutionTimeout
	defaultArtifactResolutionTimeout = 50 * time.Millisecond

	t.Cleanup(func() { defaultArtifactResolutionTimeout = previous })

	release := make(chan struct{})
	idp := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(idp.Close)
	t.Cleanup(func() { close(release) })

	t.Run("the default client has one", func(t *testing.T) {
		sp, req := artifactRequestTo(t, idp.URL)
		start := time.Now()
		_, err := sp.ParseResponse(req, nil)
		require.NotNil(t, err)
		assert.ErrorContains(t, err.(*InvalidResponseError).PrivateErr, "cannot resolve artifact")
		assert.True(t, time.Since(start) < 5*time.Second)
	})

	t.Run("the client of the caller decides", func(t *testing.T) {
		sp, req := artifactRequestTo(t, idp.URL)
		sp.HTTPClient = &http.Client{}

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		start := time.Now()
		_, err := sp.ParseResponse(req.WithContext(ctx), nil)
		require.NotNil(t, err)
		assert.True(t, time.Since(start) >= 400*time.Millisecond, "took %s", time.Since(start))
	})
}
