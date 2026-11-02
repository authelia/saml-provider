package saml

import (
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
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
