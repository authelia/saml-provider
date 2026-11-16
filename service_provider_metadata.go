package saml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"time"

	xrv "github.com/mattermost/xml-roundtrip-validator"
)

// CurrentMetadata returns metadata without the service provider descriptors whose validUntil is not
// after now, or nil if the metadata itself has expired or has no descriptor left, SAMLMeta §2.3.2 and
// §2.4.1. The zero time counts as no validUntil, as earlier versions of this package wrote it for a
// descriptor that had none.
func CurrentMetadata(metadata *EntityDescriptor, now time.Time) *EntityDescriptor {
	if metadata == nil {
		return nil
	}

	expired := func(validUntil time.Time) bool { return !validUntil.IsZero() && !now.Before(validUntil) }
	if expired(metadata.ValidUntil) {
		return nil
	}
	current := *metadata
	current.SPSSODescriptors = slices.DeleteFunc(slices.Clone(metadata.SPSSODescriptors), func(descriptor SPSSODescriptor) bool {
		return descriptor.ValidUntil != nil && expired(*descriptor.ValidUntil)
	})
	if len(current.SPSSODescriptors) == 0 {
		return nil
	}
	return &current
}

// serviceProvider returns the current metadata of the service provider from the ServiceProviderProvider,
// or os.ErrNotExist if it has expired, whatever the provider does about expiry.
func (idp *IdentityProvider) serviceProvider(r *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
	metadata, err := idp.ServiceProviderProvider.GetServiceProvider(r, serviceProviderID)
	if err != nil {
		return nil, err
	}
	current := CurrentMetadata(metadata, TimeNow())
	if current == nil {
		idp.logger().Printf("ERROR: the metadata of service provider %q has expired", serviceProviderID)
		return nil, os.ErrNotExist
	}
	return current, nil
}

// ParseServiceProviderMetadata parses the metadata of a service provider. If data is a group of
// entities, it returns the first entity that has a service provider descriptor, which is no longer
// valid after the group's validUntil, SAMLMeta §2.3.1.
func ParseServiceProviderMetadata(data []byte) (*EntityDescriptor, error) {
	if err := xrv.Validate(bytes.NewBuffer(data)); err != nil {
		return nil, err
	}

	metadata := &EntityDescriptor{}
	if err := xml.Unmarshal(data, &metadata); err != nil {
		if err.Error() != "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
			return nil, err
		}

		entities := &EntitiesDescriptor{}
		if err := xml.Unmarshal(data, &entities); err != nil {
			return nil, err
		}

		for _, e := range entities.EntityDescriptors {
			if len(e.SPSSODescriptors) > 0 {
				// The expiry of the group covers the entities it contains, SAMLMeta §2.3.1.
				if entities.ValidUntil != nil && !entities.ValidUntil.IsZero() && (e.ValidUntil.IsZero() || entities.ValidUntil.Before(e.ValidUntil)) {
					e.ValidUntil = *entities.ValidUntil
				}
				return &e, nil
			}
		}

		return nil, errors.New("metadata contained no service provider metadata")
	}

	return metadata, nil
}

// CheckServiceProviderMetadata returns an error if the metadata of a service provider can't be used
// to register it: a key descriptor has an unrecognized use, the metadata has expired at now, or the
// identity provider would refuse to send a response to every HTTP-POST assertion consumer service that
// has not expired, as the service could then never receive an assertion. See
// IdentityProvider.AllowInsecureServiceProviderEndpoints.
func (idp *IdentityProvider) CheckServiceProviderMetadata(metadata *EntityDescriptor, now time.Time) error {
	for _, descriptor := range metadata.SPSSODescriptors {
		for _, keyDescriptor := range descriptor.KeyDescriptors {
			switch keyDescriptor.Use {
			case "", "encryption", "signing":
			default:
				return fmt.Errorf("metadata has a key descriptor with an unrecognized use %q", keyDescriptor.Use)
			}
		}
	}

	if len(metadata.SPSSODescriptors) == 0 {
		return errors.New("metadata contained no service provider metadata")
	}

	// Only the descriptors that have not expired are served, so only their endpoints are checked.
	current := CurrentMetadata(metadata, now)
	if current == nil {
		return errors.New("the metadata has expired")
	}

	var refused error
	for _, descriptor := range current.SPSSODescriptors {
		for _, endpoint := range descriptor.AssertionConsumerServices {
			if endpoint.Binding != HTTPPostBinding {
				continue
			}
			if err := idp.CheckServiceProviderEndpoint(endpoint.Location); err != nil {
				refused = err
				continue
			}
			return nil
		}
	}
	return refused
}
