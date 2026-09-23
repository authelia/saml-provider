package samlidp

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"os"

	"authelia.com/provider/saml"
)

// Service represents a configured SP for whom this IDP provides authentication services.
type Service struct {
	// Name is the name of the service provider
	Name string

	// Metdata is the XML metadata of the service provider.
	Metadata saml.EntityDescriptor
}

// GetServiceProvider returns the Service Provider metadata for the
// service provider ID, which is typically the service provider's
// metadata URL. If an appropriate service provider cannot be found then
// the returned error must be os.ErrNotExist.
func (s *Server) GetServiceProvider(_ *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	s.idpConfigMu.RLock()
	defer s.idpConfigMu.RUnlock()
	rv, ok := s.serviceProviders[serviceProviderID]
	if !ok {
		return nil, os.ErrNotExist
	}
	return rv, nil
}

// HandleListServices handles the `GET /services/` request and responds with a JSON formatted list
// of service names.
func (s *Server) HandleListServices(w http.ResponseWriter, _ *http.Request) {
	services, err := s.Store.List("/services/")
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(struct {
		Services []string `json:"services"`
	}{Services: services})
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// HandleGetService handles the `GET /services/:id` request and responds with the service
// metadata in XML format.
func (s *Server) HandleGetService(w http.ResponseWriter, r *http.Request) {
	service := Service{}
	err := s.Store.Get(fmt.Sprintf("/services/%s", r.PathValue("id")), &service)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	err = xml.NewEncoder(w).Encode(service.Metadata)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// HandlePutService handles the `PUT /services/:id` request. It accepts the XML-formatted
// service metadata in the request body and stores it. The request is rejected if the
// entity ID in the metadata is already registered by another service.
func (s *Server) HandlePutService(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	service := Service{}

	metadata, err := getSPMetadata(r.Body)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	service.Metadata = *metadata

	s.idpConfigMu.Lock()
	defer s.idpConfigMu.Unlock()

	if _, ok := s.serviceProviders[service.Metadata.EntityID]; ok && s.serviceIDs[service.Metadata.EntityID] != id {
		s.logger.Printf("ERROR: entity ID %q is already registered by another service", service.Metadata.EntityID)
		http.Error(w, http.StatusText(http.StatusConflict), http.StatusConflict)
		return
	}

	previous := Service{}
	hasPrevious := s.Store.Get(fmt.Sprintf("/services/%s", id), &previous) == nil

	err = s.Store.Put(fmt.Sprintf("/services/%s", id), &service)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if hasPrevious {
		s.deregisterServiceProvider(id, previous.Metadata.EntityID)
	}
	s.serviceProviders[service.Metadata.EntityID] = &service.Metadata
	s.serviceIDs[service.Metadata.EntityID] = id

	w.WriteHeader(http.StatusNoContent)
}

// HandleDeleteService handles the `DELETE /services/:id` request.
func (s *Server) HandleDeleteService(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	s.idpConfigMu.Lock()
	defer s.idpConfigMu.Unlock()

	service := Service{}
	err := s.Store.Get(fmt.Sprintf("/services/%s", id), &service)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if err := s.Store.Delete(fmt.Sprintf("/services/%s", id)); err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	s.deregisterServiceProvider(id, service.Metadata.EntityID)

	w.WriteHeader(http.StatusNoContent)
}

// deregisterServiceProvider removes entityID from the identity provider only
// if it is registered by the service id. The caller must hold idpConfigMu.
func (s *Server) deregisterServiceProvider(id, entityID string) {
	if s.serviceIDs[entityID] != id {
		return
	}
	delete(s.serviceProviders, entityID)
	delete(s.serviceIDs, entityID)
}

// initializeServices reads all the stored services and initializes the underlying
// identity provider to accept them.
func (s *Server) initializeServices() error {
	serviceNames, err := s.Store.List("/services/")
	if err != nil {
		return err
	}
	for _, serviceName := range serviceNames {
		service := Service{}
		if err := s.Store.Get(fmt.Sprintf("/services/%s", serviceName), &service); err != nil {
			return err
		}

		s.idpConfigMu.Lock()
		if other, ok := s.serviceIDs[service.Metadata.EntityID]; ok {
			s.idpConfigMu.Unlock()
			return fmt.Errorf("services %q and %q both register entity ID %q", other, serviceName, service.Metadata.EntityID)
		}
		s.serviceProviders[service.Metadata.EntityID] = &service.Metadata
		s.serviceIDs[service.Metadata.EntityID] = serviceName
		s.idpConfigMu.Unlock()
	}
	return nil
}
