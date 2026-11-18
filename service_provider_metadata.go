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

// CurrentMetadata returns metadata without the service provider descriptors whose validUntil has
// passed, or nil if the metadata itself has expired or has no descriptor left, SAMLMeta §2.3.2 and
// §2.4.1. A validUntil has passed once it is MaxClockSkew before now, as the clock of whoever published
// the metadata may be behind (SAML2Int SDP-G01). The zero time counts as no validUntil, as earlier
// versions of this package wrote it for a descriptor that had none.
func CurrentMetadata(metadata *EntityDescriptor, now time.Time) *EntityDescriptor {
	if metadata == nil {
		return nil
	}

	if expiredAt(metadata.ValidUntil, now) {
		return nil
	}

	current := *metadata

	current.SPSSODescriptors = slices.DeleteFunc(slices.Clone(metadata.SPSSODescriptors), func(descriptor SPSSODescriptor) bool {
		return descriptor.ValidUntil != nil && expiredAt(*descriptor.ValidUntil, now)
	})
	if len(current.SPSSODescriptors) == 0 {
		return nil
	}

	return &current
}

// serviceProvider returns the current metadata of the service provider from the ServiceProviderProvider,
// or [os.ErrNotExist] if it has expired, whatever the provider does about expiry.
func (idp *IdentityProvider) serviceProvider(r *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
	metadata, err := idp.ServiceProviderProvider.GetServiceProvider(r, serviceProviderID)
	if err != nil {
		return nil, err
	}

	current := CurrentMetadata(metadata, TimeNow())
	if current == nil {
		idp.observe(r, requestState{serviceProvider: serviceProviderID}.warning(EventMetadataExpired,
			ErrUnknownServiceProvider.WithDebugf("the metadata of service provider %q has expired", serviceProviderID)))

		return nil, os.ErrNotExist
	}

	return current, nil
}

// ParseServiceProviderMetadata parses the metadata of a service provider. If data is a group of
// entities, it returns the first entity that has a service provider descriptor, as
// ParseServiceProvidersMetadata does. Metadata from a source that doesn't authenticate it must be verified with
// a MetadataVerifier first, and the XML that it returns parsed.
func ParseServiceProviderMetadata(data []byte) (*EntityDescriptor, error) {
	entities, err := ParseServiceProvidersMetadata(data)
	if err != nil {
		return nil, err
	}

	return entities[0], nil
}

// ParseServiceProvidersMetadata parses metadata which is an EntityDescriptor, and returns it, or an
// EntitiesDescriptor, such as the aggregate of a federation, and returns each entity in it, or in a group within
// it, that has a service provider descriptor, the entities of a group before those of the groups within it. An entity in a group is no longer valid after the
// earliest validUntil of the groups around it, SAMLMeta §2.3.1. Metadata from a source that doesn't authenticate it
// must be verified with a MetadataVerifier first, and the XML that it returns parsed.
func ParseServiceProvidersMetadata(data []byte) ([]*EntityDescriptor, error) {
	if err := xrv.Validate(bytes.NewBuffer(data)); err != nil {
		return nil, err
	}

	var root struct {
		XMLName xml.Name
	}

	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	switch root.XMLName {
	case xml.Name{Space: metadataNamespace, Local: "EntityDescriptor"}:
		metadata := &EntityDescriptor{}
		if err := xml.Unmarshal(data, metadata); err != nil {
			return nil, err
		}

		return []*EntityDescriptor{metadata}, nil
	case xml.Name{Space: metadataNamespace, Local: "EntitiesDescriptor"}:
		group := &EntitiesDescriptor{}
		if err := xml.Unmarshal(data, group); err != nil {
			return nil, err
		}

		entities := serviceProvidersOf(group, time.Time{}, nil, nil)
		if len(entities) == 0 {
			return nil, errors.New("metadata contained no service provider metadata")
		}

		return entities, nil
	default:
		return nil, fmt.Errorf("expected element type <EntityDescriptor> or <EntitiesDescriptor> but have <%s>", root.XMLName.Local)
	}
}

// serviceProvidersOf appends to entities each entity of group and of the groups within it that has a service
// provider descriptor, with the earliest of its own validUntil, that of group and validUntil, the earliest of the
// groups around group. The zero time counts as no validUntil.
//
// Each entity also has the entity attributes of group and of the groups around group, which are inherited, after
// its own, those of the nearest group first: the attributes in the Extensions of an EntitiesDescriptor "are bound
// to each EntityDescriptor within" it (SAML V2.0 Metadata Extension for Entity Attributes §2.3). The Extensions of
// such an entity are a copy, so group is not changed.
func serviceProvidersOf(group *EntitiesDescriptor, validUntil time.Time, inherited []Attribute, entities []*EntityDescriptor) []*EntityDescriptor {
	if group.ValidUntil != nil {
		validUntil = earliestValidUntil(validUntil, *group.ValidUntil)
	}

	if group.Extensions != nil && group.Extensions.EntityAttributes != nil {
		// A new slice, as the groups within this one must not share what they append to it.
		inherited = slices.Concat(group.Extensions.EntityAttributes.Attributes, inherited)
	}

	for i := range group.EntityDescriptors {
		entity := group.EntityDescriptors[i]
		if len(entity.SPSSODescriptors) == 0 {
			continue
		}

		entity.ValidUntil = earliestValidUntil(entity.ValidUntil, validUntil)
		entity.Extensions = inheritEntityAttributes(entity.Extensions, inherited)
		entities = append(entities, &entity)
	}

	for i := range group.EntitiesDescriptors {
		entities = serviceProvidersOf(&group.EntitiesDescriptors[i], validUntil, inherited, entities)
	}

	return entities
}

// inheritEntityAttributes returns extensions, or a copy of them that also has the entity attributes inherited
// if there are any. Each attribute is a copy, so a change to one entity is not a change to another.
func inheritEntityAttributes(extensions *Extensions, inherited []Attribute) *Extensions {
	if len(inherited) == 0 {
		return extensions
	}

	result := &Extensions{}
	if extensions != nil {
		*result = *extensions
	}

	var attributes []Attribute
	if result.EntityAttributes != nil {
		attributes = slices.Clone(result.EntityAttributes.Attributes)
	}

	for _, attribute := range inherited {
		attributes = append(attributes, attribute.clone())
	}

	result.EntityAttributes = &EntityAttributes{Attributes: attributes}

	return result
}

// earliestValidUntil returns the earlier of a and b, where the zero time counts as no validUntil.
func earliestValidUntil(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}

	return a
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
