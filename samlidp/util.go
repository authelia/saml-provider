package samlidp

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"

	xrv "github.com/mattermost/xml-roundtrip-validator"

	"authelia.com/provider/saml"
)

func randomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := saml.RandReader.Read(rv); err != nil {
		panic(err)
	}
	return rv
}

func getSPMetadata(r io.Reader) (spMetadata *saml.EntityDescriptor, err error) {
	var data []byte
	if data, err = io.ReadAll(r); err != nil {
		return nil, err
	}

	spMetadata = &saml.EntityDescriptor{}
	if err := xrv.Validate(bytes.NewBuffer(data)); err != nil {
		return nil, err
	}

	if err := xml.Unmarshal(data, &spMetadata); err != nil {
		if err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
			entities := &saml.EntitiesDescriptor{}
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

			// there were no SPSSODescriptors in the response
			return nil, errors.New("metadata contained no service provider metadata")
		}

		return nil, err
	}

	return spMetadata, nil
}
