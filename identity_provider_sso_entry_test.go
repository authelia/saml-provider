package saml

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wrappedNotExistProvider reports every service provider as unknown with an error that wraps os.ErrNotExist,
// as a provider that adds context to the error of its store does.
func wrappedNotExistProvider() *mockServiceProviderProvider {
	return &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			return nil, fmt.Errorf("cannot load service provider %s: %w", serviceProviderID, os.ErrNotExist)
		},
	}
}

func TestIDPInitiatedFindsServiceProviderBeforeSession(t *testing.T) {
	test := hardeningIDPWithSessionCheck(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/services/sp/whoami", nil)
	test.IDP.ServeIDPInitiated(w, r, "https://wrong.url/metadata", "ThisIsTheRelayState")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestIDPInitiatedWrappedNotExistIsUnknownServiceProvider(t *testing.T) {
	test := hardeningIDPWithSessionCheck(t)
	test.IDP.ServiceProviderProvider = wrappedNotExistProvider()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/services/sp/whoami", nil)
	test.IDP.ServeIDPInitiated(w, r, "https://sp.example.com/saml2/metadata", "ThisIsTheRelayState")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestIDPValidateWrappedNotExistIsUnknownServiceProvider(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.ServiceProviderProvider = wrappedNotExistProvider()

	_, err := interopValidate(test, "")

	assert.True(t, errors.Is(err, ErrUnknownServiceProvider), "%v", err)
}

func TestIDPSSORefusesOtherMethods(t *testing.T) {
	for _, method := range []string{http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			test := hardeningIDPWithSessionCheck(t)

			w := httptest.NewRecorder()
			test.IDP.ServeSSO(w, httptest.NewRequest(method, "https://idp.example.com/saml/sso", nil))

			require.Equal(t, http.StatusMethodNotAllowed, w.Code)
			assert.Equal(t, "GET, POST", w.Header().Get("Allow"))
		})
	}
}
