package samlsp

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	xrv "github.com/mattermost/xml-roundtrip-validator"

	"authelia.com/provider/saml/logger"

	"authelia.com/provider/saml"
)

// ParseMetadata parses arbitrary SAML IDP metadata.
//
// Note: this is needed because IDP metadata is sometimes wrapped in
// an <EntitiesDescriptor>, and sometimes the top level element is an
// <EntityDescriptor>.
func ParseMetadata(data []byte) (*saml.EntityDescriptor, error) {
	entity := &saml.EntityDescriptor{}

	if err := xrv.Validate(bytes.NewBuffer(data)); err != nil {
		return nil, err
	}

	err := xml.Unmarshal(data, entity)

	// this comparison is ugly, but it is how the error is generated in encoding/xml
	if err != nil && err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
		entities := &saml.EntitiesDescriptor{}
		if err := xml.Unmarshal(data, entities); err != nil {
			return nil, err
		}

		for i, e := range entities.EntityDescriptors {
			if len(e.IDPSSODescriptors) > 0 {
				return &entities.EntityDescriptors[i], nil
			}
		}
		return nil, errors.New("no entity found with IDPSSODescriptor")
	}
	if err != nil {
		return nil, err
	}
	return entity, nil
}

// These are variables so that they can be changed by tests.
var (
	// maxMetadataSize limits the size of fetched metadata, and allows for large federations.
	maxMetadataSize int64 = 256 * 1024 * 1024
	// defaultFetchMetadataTimeout is used if httpClient is nil.
	defaultFetchMetadataTimeout = 30 * time.Second
)

// FetchMetadata returns metadata from an IDP metadata URL.
//
// The metadata decides which keys are trusted, so the URL should be one the operator has chosen and
// should use TLS. Redirects are followed according to httpClient, including to other hosts, and its
// CheckRedirect can restrict them. If httpClient is nil then a client with a timeout of 30 seconds is
// used. Otherwise, httpClient or ctx should have a timeout, which http.DefaultClient does not.
func FetchMetadata(ctx context.Context, httpClient *http.Client, metadataURL url.URL) (*saml.EntityDescriptor, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultFetchMetadataTimeout}
	}

	req, err := http.NewRequest("GET", metadataURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.DefaultLogger.Printf("Error while closing response body during fetch metadata: %v", err)
		}
	}()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("failed to fetch metadata: unexpected status code %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxMetadataSize {
		return nil, fmt.Errorf("failed to fetch metadata: too large, the limit is %d bytes", maxMetadataSize)
	}

	return ParseMetadata(data)
}
