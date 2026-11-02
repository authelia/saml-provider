// Package samlidp a rudimentary SAML identity provider suitable for
// testing or as a starting point for a more complex service.
package samlidp

import (
	"crypto"
	"crypto/x509"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"authelia.com/provider/saml"
	"authelia.com/provider/saml/logger"
)

// Options represent the parameters to New() for creating a new IDP server
type Options struct {
	URL         url.URL
	Key         crypto.PrivateKey
	Signer      crypto.Signer
	Logger      logger.Interface
	Certificate *x509.Certificate
	Store       Store

	// LoginFormTemplate replaces the login form. It must post to {{.URL}} and include the
	// SAMLRequest and RelayState hidden fields, which resume the flow once the user has logged in.
	LoginFormTemplate *template.Template

	// AdminAuthorizer decides whether a request may use the /services, /users, /sessions and
	// /shortcuts interfaces. If it is nil, every such request is refused.
	AdminAuthorizer func(r *http.Request) bool
}

// Server represents an IDP server. The server provides the following URLs:
//
//	/metadata     - the SAML metadata
//	/sso          - the SAML endpoint to initiate an authentication flow
//	/login        - prompt for a username and password if no session established
//	/login/:shortcut - kick off an IDP-initiated authentication flow
//	/services     - RESTful interface to Service objects
//	/users        - RESTful interface to User objects
//	/sessions     - RESTful interface to Session objects
//	/shortcuts    - RESTful interface to Shortcut objects
//
// The RESTful interfaces can create users, read session identifiers and redirect assertions, so
// they respond with 403 Forbidden unless AdminAuthorizer approves the request.
type Server struct {
	http.Handler
	idpConfigMu       sync.RWMutex // protects calls into the IDP
	logger            logger.Interface
	serviceProviders  map[string]*saml.EntityDescriptor
	IDP               saml.IdentityProvider // the underlying IDP
	Store             Store                 // the data store
	LoginFormTemplate *template.Template
	AdminAuthorizer   func(r *http.Request) bool // approves requests to the RESTful interfaces
}

// maxLoginDuration is how long a user has to complete the login form. The form re-presents the
// original AuthnRequest, which must still be acceptable when the credentials arrive.
const maxLoginDuration = 5 * time.Minute

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

			MaxAuthnRequestAge: maxLoginDuration,
		},
		logger:            logr,
		Store:             opts.Store,
		LoginFormTemplate: opts.LoginFormTemplate,
		AdminAuthorizer:   opts.AdminAuthorizer,
	}

	s.IDP.SessionProvider = s
	s.IDP.ServiceProviderProvider = s

	if err := s.initializeServices(); err != nil {
		return nil, err
	}
	s.InitializeHTTP()
	return s, nil
}

// InitializeHTTP sets up the HTTP handler for the server. (This function
// is called automatically for you by New, but you may need to call it
// yourself if you don't create the object using New.)
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

	admin := func(pattern string, handler http.HandlerFunc) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if s.AdminAuthorizer == nil || !s.AdminAuthorizer(r) {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			handler(w, r)
		})
	}

	admin("GET /services/", s.HandleListServices)
	admin("GET /services/{id}", s.HandleGetService)
	admin("PUT /services/{id}", s.HandlePutService)
	admin("POST /services/{id}", s.HandlePutService)
	admin("DELETE /services/{id}", s.HandleDeleteService)

	admin("GET /users/", s.HandleListUsers)
	admin("GET /users/{id}", s.HandleGetUser)
	admin("PUT /users/{id}", s.HandlePutUser)
	admin("DELETE /users/{id}", s.HandleDeleteUser)

	admin("GET /sessions/", s.HandleListSessions)
	admin("GET /sessions/{id}", s.HandleGetSession)
	admin("DELETE /sessions/{id}", s.HandleDeleteSession)

	admin("GET /shortcuts/", s.HandleListShortcuts)
	admin("GET /shortcuts/{id}", s.HandleGetShortcut)
	admin("PUT /shortcuts/{id}", s.HandlePutShortcut)
	admin("DELETE /shortcuts/{id}", s.HandleDeleteShortcut)
}
