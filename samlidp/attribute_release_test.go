package samlidp

import (
	"net/url"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml"
)

type attributeReleasePolicyFunc func(*saml.IdpAuthnRequest, *saml.Session, []saml.Attribute) ([]saml.Attribute, error)

func (f attributeReleasePolicyFunc) ReleaseAttributes(req *saml.IdpAuthnRequest, session *saml.Session, candidates []saml.Attribute) ([]saml.Attribute, error) {
	return f(req, session, candidates)
}

func TestNewUsesAttributeReleasePolicy(t *testing.T) {
	test := NewServerTest(t)
	hardeningAddUser(t, test)

	var serviceProvider, user string
	server, err := New(Options{
		Certificate: test.Certificate,
		Key:         test.Key,
		Store:       &test.Store,
		URL:         url.URL{Scheme: "https", Host: "idp.example.com"},
		AttributeReleasePolicy: attributeReleasePolicyFunc(func(req *saml.IdpAuthnRequest, session *saml.Session, candidates []saml.Attribute) ([]saml.Attribute, error) {
			serviceProvider, user = req.ServiceProviderMetadata.EntityID, session.UserName
			return candidates, nil
		}),
	})
	assert.NilError(t, err)
	server.serviceProviders["https://sp.example.com/saml2/metadata"] = test.SP.Metadata()
	test.Server = server

	hardeningAssertSAMLResponse(t, hardeningSubmitLogin(t, test, hardeningStartSSO(t, test), "hunter2"), "frob")
	assert.Check(t, is.Equal(serviceProvider, "https://sp.example.com/saml2/metadata"))
	assert.Check(t, is.Equal(user, "alice"))
}
