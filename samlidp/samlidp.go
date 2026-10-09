// Package samlidp a rudimentary SAML identity provider suitable for
// testing or as a starting point for a more complex service.
//
// The RESTful interfaces for managing services, users, sessions and shortcuts
// are served by Server.AdminHandler, which has no authentication of its own.
// Anyone who can reach it can create a user and sign in as them, or register
// a service provider. Only expose it behind authentication, or on a listener
// that untrusted clients cannot reach.
package samlidp

import (
	"crypto"
	"crypto/x509"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"authelia.com/provider/saml"
	"authelia.com/provider/saml/logger"
)

// Options represent the parameters to New() for creating a new IDP server
type Options struct {
	URL               url.URL
	Key               crypto.PrivateKey
	Signer            crypto.Signer
	Logger            logger.Interface
	Certificate       *x509.Certificate
	Store             Store
	LoginFormTemplate *template.Template
}

// Server represents an IDP server. The server provides the following URLs:
//
//	/metadata     - the SAML metadata
//	/sso          - the SAML endpoint to initiate an authentication flow
//	/login        - prompt for a username and password if no session established
//	/login/:shortcut - kick off an IDP-initiated authentication flow
//
// AdminHandler separately provides the following URLs, without authentication:
//
//	/services     - RESTful interface to Service objects
//	/users        - RESTful interface to User objects
//	/sessions     - RESTful interface to Session objects
//	/shortcuts    - RESTful interface to Shortcut objects
type Server struct {
	http.Handler
	AdminHandler      http.Handler
	idpConfigMu       sync.RWMutex // protects calls into the IDP
	logger            logger.Interface
	serviceProviders  map[string]*saml.EntityDescriptor
	IDP               saml.IdentityProvider // the underlying IDP
	Store             Store                 // the data store
	LoginFormTemplate *template.Template
}

// New returns a new Server
func New(opts Options) (*Server, error) {
	opts.URL.Path = strings.TrimSuffix(opts.URL.Path, "/")

	metadataURL := opts.URL
	metadataURL.Path += "/metadata"
	ssoURL := opts.URL
	ssoURL.Path += "/sso"
	loginURL := opts.URL
	loginURL.Path += "/login"
	logr := opts.Logger
	if logr == nil {
		logr = logger.DefaultLogger
	}

	s := &Server{
		serviceProviders: map[string]*saml.EntityDescriptor{},
		IDP: saml.IdentityProvider{
			Key:         opts.Key,
			Signer:      opts.Signer,
			Logger:      logr,
			Certificate: opts.Certificate,
			MetadataURL: metadataURL,
			SSOURL:      ssoURL,
			LoginURL:    loginURL,
		},
		logger:            logr,
		Store:             opts.Store,
		LoginFormTemplate: opts.LoginFormTemplate,
	}

	s.IDP.SessionProvider = s
	s.IDP.ServiceProviderProvider = s

	if err := s.initializeServices(); err != nil {
		return nil, err
	}
	s.InitializeHTTP()
	return s, nil
}

// InitializeHTTP sets up the HTTP handler and the admin HTTP handler for the
// server. (This function is called automatically for you by New, but you may
// need to call it yourself if you don't create the object using New.)
func (s *Server) InitializeHTTP() {
	mux := http.NewServeMux()
	s.Handler = mux

	mux.HandleFunc("GET /metadata", func(w http.ResponseWriter, r *http.Request) {
		s.idpConfigMu.RLock()
		defer s.idpConfigMu.RUnlock()
		s.IDP.ServeMetadata(w, r)
	})
	mux.HandleFunc("/sso", func(w http.ResponseWriter, r *http.Request) {
		s.IDP.ServeSSO(w, r)
	})

	mux.HandleFunc("/login", s.HandleLogin)
	mux.HandleFunc("/login/{shortcut}", s.HandleIDPInitiated)
	mux.HandleFunc("/login/{shortcut}/{suffix}", s.HandleIDPInitiated)

	admin := http.NewServeMux()
	s.AdminHandler = admin

	admin.HandleFunc("GET /services/", s.HandleListServices)
	admin.HandleFunc("GET /services/{id}", s.HandleGetService)
	admin.HandleFunc("PUT /services/{id}", s.HandlePutService)
	admin.HandleFunc("POST /services/{id}", s.HandlePutService)
	admin.HandleFunc("DELETE /services/{id}", s.HandleDeleteService)

	admin.HandleFunc("GET /users/", s.HandleListUsers)
	admin.HandleFunc("GET /users/{id}", s.HandleGetUser)
	admin.HandleFunc("PUT /users/{id}", s.HandlePutUser)
	admin.HandleFunc("DELETE /users/{id}", s.HandleDeleteUser)

	admin.HandleFunc("GET /sessions/", s.HandleListSessions)
	admin.HandleFunc("GET /sessions/{id}", s.HandleGetSession)
	admin.HandleFunc("DELETE /sessions/{id}", s.HandleDeleteSession)

	admin.HandleFunc("GET /shortcuts/", s.HandleListShortcuts)
	admin.HandleFunc("GET /shortcuts/{id}", s.HandleGetShortcut)
	admin.HandleFunc("PUT /shortcuts/{id}", s.HandlePutShortcut)
	admin.HandleFunc("DELETE /shortcuts/{id}", s.HandleDeleteShortcut)
}
