package samlidp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml"
)

// A service provider that isn't registered comes from Options.ServiceProviderProvider, here a resolver that
// loads a file, and a registered service comes first.
func TestServiceProviderProviderIsAskedForUnregisteredServices(t *testing.T) {
	const (
		registered = "https://registered.example.com/metadata"
		federated  = "https://federated.example.com/metadata"
	)

	validUntil := ` validUntil="` + saml.TimeNow().Add(24*time.Hour).UTC().Format("2006-01-02T15:04:05Z") + `">`
	group := `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"` + validUntil +
		testServiceMetadata(registered, "federation") + testServiceMetadata(federated, "federation") + `</EntitiesDescriptor>`
	path := filepath.Join(t.TempDir(), "federation.xml")

	require.NoError(t, os.WriteFile(path, []byte(group), 0o600))

	resolver, err := saml.NewServiceProviderMetadataResolver(saml.ServiceProviderMetadataResolverOptions{
		Sources: []saml.MetadataSource{{File: path}},
	})
	require.NoError(t, err)
	require.NoError(t, resolver.Refresh(context.Background()))

	store := &MemoryStore{}

	metadata, err := saml.ParseServiceProviderMetadata([]byte(testServiceMetadata(registered, "sp")))
	require.NoError(t, err)
	require.NoError(t, store.Put("/services/sp", &Service{Metadata: *metadata}))

	server, err := New(Options{
		URL:                     url.URL{Scheme: "https", Host: "idp.example.com"},
		Store:                   store,
		ServiceProviderProvider: resolver,
	})
	require.NoError(t, err)

	r, _ := http.NewRequest(http.MethodGet, "https://idp.example.com/sso", nil)

	metadata, err = server.GetServiceProvider(r, federated)
	require.NoError(t, err)
	assert.Equal(t, "https://federation.example.net/acs", metadata.SPSSODescriptors[0].AssertionConsumerServices[0].Location)

	metadata, err = server.GetServiceProvider(r, registered)
	require.NoError(t, err)
	assert.Equal(t, "https://sp.example.net/acs", metadata.SPSSODescriptors[0].AssertionConsumerServices[0].Location)

	_, err = server.GetServiceProvider(r, "https://unknown.example.com/metadata")
	assert.True(t, errors.Is(err, os.ErrNotExist))
}
