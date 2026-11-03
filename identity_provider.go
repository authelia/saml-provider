package saml

import (
	"bytes"
	"cmp"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"

	"authelia.com/provider/saml/internal/dsig"

	"authelia.com/provider/saml/logger"
	"authelia.com/provider/saml/xmlenc"
)

// maxAuthnRequestSize is the largest decoded AuthnRequest that the identity provider will process.
// Real requests are a few kilobytes, including any signature and certificate. Requests are parsed
// before any authentication, so this limit bounds the work an anonymous client can cause.
const maxAuthnRequestSize = 16 * 1024

// maxAuthnRequestBodySize is the largest HTTP POST body that the identity provider will read. It
// allows for a request of maxAuthnRequestSize whose base64 is entirely percent-encoded, with room
// for RelayState and any login form fields.
const maxAuthnRequestBodySize = 128 * 1024

// maxAuthnRequestIDLength is the longest AuthnRequest ID that the identity provider will accept.
const maxAuthnRequestIDLength = 256

// Session represents a user session. It is returned by the
// SessionProvider implementation's GetSession method. Fields here
// are used to set fields in the SAML assertion.
type Session struct {
	ID         string
	CreateTime time.Time
	ExpireTime time.Time
	Index      string

	NameID       string
	NameIDFormat string
	SubjectID    string

	Groups                 []string
	UserName               string
	UserEmail              string
	UserCommonName         string
	UserSurname            string
	UserGivenName          string
	UserScopedAffiliation  string
	EduPersonPrincipalName string `json:",omitempty"`

	CustomAttributes []Attribute

	// AuthnContextClassRef is the authentication context class of the session, such as
	// https://refeds.org/profile/mfa, which DefaultAssertionMaker asserts. If it is empty the
	// assertion states PasswordProtectedTransport.
	AuthnContextClassRef string `json:",omitempty"`
}

// defaultAuthnContextClassRef is the authentication context class asserted for a session that sets
// none.
const defaultAuthnContextClassRef = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

// SessionProvider is an interface used by IdentityProvider to determine the
// Session associated with a request. For an example implementation, see
// GetSession in the samlidp package.
type SessionProvider interface {
	// GetSession returns the remote user session associated with the http.Request.
	//
	// If (and only if) the request is not associated with a session then GetSession
	// must complete the HTTP request and return nil.
	GetSession(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session
}

// PassiveSessionProvider is an optional interface of a SessionProvider, which is required to serve
// a request with IsPassive set. Without it those requests receive a NoPassive status, because
// GetSession is allowed to interact with the user.
type PassiveSessionProvider interface {
	// GetPassiveSession returns the session of the remote user without any interaction, or nil if
	// that isn't possible. It has no http.ResponseWriter because it must not write a response. If
	// req.Request.ForceAuthn is also set, it must return nil unless it can authenticate the user
	// directly with no interaction.
	GetPassiveSession(r *http.Request, req *IdpAuthnRequest) *Session
}

// ForceAuthnSessionProvider is an optional interface of a SessionProvider, which is required to serve
// a request with ForceAuthn set. Without it those requests receive an AuthnFailed status, because
// GetSession is allowed to rely on an existing session.
type ForceAuthnSessionProvider interface {
	// GetForcedSession authenticates the remote user directly and returns the resulting session. It
	// must not rely on an existing session. Otherwise it follows the rules of GetSession: if it has
	// no session yet, it must complete the HTTP request and return nil. That includes when a login
	// form re-presents the request, which arrives here again.
	GetForcedSession(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session
}

// ServiceProviderProvider is an interface used by IdentityProvider to look up
// service provider metadata for a request.
type ServiceProviderProvider interface {
	// GetServiceProvider returns the Service Provider metadata for the
	// service provider ID, which is typically the service provider's
	// metadata URL. If an appropriate service provider cannot be found then
	// the returned error must be os.ErrNotExist.
	GetServiceProvider(r *http.Request, serviceProviderID string) (*EntityDescriptor, error)
}

// AssertionMaker is an interface used by IdentityProvider to construct the
// assertion for a request. The default implementation is DefaultAssertionMaker,
// which is used if not AssertionMaker is specified.
type AssertionMaker interface {
	// MakeAssertion constructs an assertion from session and the request and
	// assigns it to req.Assertion.
	MakeAssertion(req *IdpAuthnRequest, session *Session) error
}

// NameIDPolicyEnforcer is an interface used by IdentityProvider to decide whether an assertion
// satisfies the NameIDPolicy of its request, which allows the decision to differ for each service
// provider. The default implementation is DefaultNameIDPolicyEnforcer, which is used if no
// NameIDPolicyEnforcer is specified.
type NameIDPolicyEnforcer interface {
	// EnforceNameIDPolicy returns an error if req.Assertion doesn't satisfy req.Request.NameIDPolicy,
	// which is not nil. The service provider receives an InvalidNameIDPolicy status, not the error.
	//
	// This is where to check AllowCreate, which the default implementation can't: only the identity
	// provider knows whether an identifier has already been established for this principal.
	EnforceNameIDPolicy(req *IdpAuthnRequest, session *Session) error
}

// AuthnContextEnforcer is an interface used by IdentityProvider to decide whether an assertion
// satisfies the RequestedAuthnContext of its request. The default implementation is
// DefaultAuthnContextEnforcer, which is used if no AuthnContextEnforcer is specified.
type AuthnContextEnforcer interface {
	// EnforceAuthnContext returns an error if req.Assertion doesn't satisfy
	// req.Request.RequestedAuthnContext, which is not nil. The service provider receives a
	// NoAuthnContext status, not the error.
	EnforceAuthnContext(req *IdpAuthnRequest, session *Session) error
}

// DefaultAuthnContextEnforcer applies the comparison rules of SAMLCore §3.3.2.2.1 to the class
// reference of every AuthnStatement in the assertion.
type DefaultAuthnContextEnforcer struct {
	// Strength ranks authentication context classes, where a greater value is stronger. It is
	// needed for the minimum, maximum and better comparisons, as the specification leaves the
	// ordering to the identity provider. Classes may share a value. A class that isn't listed is
	// only equal to itself.
	Strength map[string]int
}

// EnforceAuthnContext implements AuthnContextEnforcer.
// Declaration references are always refused, because the assertions made here only state a class.
// With minimum and maximum the asserted class must be at least as strong as, or no stronger than,
// one of the requested classes, and with better it must be stronger than one of them.
func (e DefaultAuthnContextEnforcer) EnforceAuthnContext(req *IdpAuthnRequest, _ *Session) error {
	requested := req.Request.RequestedAuthnContext
	if len(requested.AuthnContextDeclRefs) != 0 {
		return fmt.Errorf("the request requires an AuthnContextDeclRef, which is not supported")
	}

	var satisfies func(asserted, class string) bool
	switch requested.Comparison {
	case "", AuthnContextComparisonExact:
		satisfies = func(asserted, class string) bool { return asserted == class }
	case AuthnContextComparisonMinimum:
		satisfies = func(asserted, class string) bool { return asserted == class || e.compare(asserted, class) > 0 }
	case AuthnContextComparisonMaximum:
		satisfies = func(asserted, class string) bool { return asserted == class || e.compare(asserted, class) < 0 }
	case AuthnContextComparisonBetter:
		satisfies = func(asserted, class string) bool { return e.compare(asserted, class) > 0 }
	default:
		return fmt.Errorf("unknown comparison %q", requested.Comparison)
	}

	if req.Assertion == nil || len(req.Assertion.AuthnStatements) == 0 {
		return fmt.Errorf("assertion has no AuthnStatement")
	}
	for _, statement := range req.Assertion.AuthnStatements {
		if statement.AuthnContext.AuthnContextClassRef == nil {
			return fmt.Errorf("an AuthnStatement has no AuthnContextClassRef")
		}
		asserted := statement.AuthnContext.AuthnContextClassRef.Value
		if !slices.ContainsFunc(requested.AuthnContextClassRefs, func(class string) bool { return satisfies(asserted, class) }) {
			return fmt.Errorf("the asserted class %q doesn't satisfy the %q comparison", asserted, requested.Comparison)
		}
	}
	return nil
}

// compare returns a positive number if a is stronger than b, a negative number if it is weaker, and
// zero if they are equal or either is not ranked.
func (e DefaultAuthnContextEnforcer) compare(a, b string) int {
	strengthA, okA := e.Strength[a]
	strengthB, okB := e.Strength[b]
	if !okA || !okB {
		return 0
	}
	return cmp.Compare(strengthA, strengthB)
}

// IdentityProvider implements the SAML Identity Provider role (IDP).
//
// An identity provider receives SAML assertion requests and responds
// with SAML Assertions.
//
// You must provide a keypair that is used to
// sign assertions.
//
// You must provide an implementation of ServiceProviderProvider which
// returns
//
// You must provide an implementation of the SessionProvider which
// handles the actual authentication (i.e. prompting for a username
// and password).
type IdentityProvider struct {
	Key           crypto.PrivateKey
	Signer        crypto.Signer
	Logger        logger.Interface
	Certificate   *x509.Certificate
	Intermediates []*x509.Certificate
	// MaxAuthnRequestAge is the oldest AuthnRequest that will be accepted, which must allow for a
	// SessionProvider that re-presents the request after a login form. Defaults to MaxIssueDelay.
	MaxAuthnRequestAge      time.Duration
	MetadataURL             url.URL
	SSOURL                  url.URL
	LoginURL                url.URL
	LogoutURL               url.URL
	ServiceProviderProvider ServiceProviderProvider
	SessionProvider         SessionProvider
	AssertionMaker          AssertionMaker
	SignatureMethod         string
	ValidDuration           *time.Duration
	ResponseFormTemplate    *template.Template

	// WantAuthnRequestsSigned requires every AuthnRequest to be signed, and is declared in the
	// metadata. A request is also required to be signed if the metadata of its service provider
	// sets AuthnRequestsSigned, and any signature that is present is always verified.
	WantAuthnRequestsSigned bool

	// NameIDPolicyEnforcer decides whether an assertion satisfies the NameIDPolicy of its request.
	// Defaults to DefaultNameIDPolicyEnforcer.
	NameIDPolicyEnforcer NameIDPolicyEnforcer

	// AuthnContextEnforcer decides whether an assertion satisfies the RequestedAuthnContext of its
	// request. Defaults to a DefaultAuthnContextEnforcer with no Strength, which only accepts a
	// class that the request lists, and never satisfies the better comparison.
	AuthnContextEnforcer AuthnContextEnforcer
}

// Metadata returns the metadata structure for this identity provider.
func (idp *IdentityProvider) Metadata() *EntityDescriptor {
	certStr := base64.StdEncoding.EncodeToString(idp.Certificate.Raw)

	var validDuration time.Duration
	if idp.ValidDuration != nil {
		validDuration = *idp.ValidDuration
	} else {
		validDuration = DefaultValidDuration
	}

	keyDescriptors := []KeyDescriptor{
		{
			Use: "signing",
			KeyInfo: KeyInfo{
				X509Data: X509Data{
					X509Certificates: []X509Certificate{
						{Data: certStr},
					},
				},
			},
		},
	}
	// Encryption requires RSA, so a certificate with any other type of key must not be advertised for it.
	if _, ok := idp.Certificate.PublicKey.(*rsa.PublicKey); ok {
		keyDescriptors = append(keyDescriptors, KeyDescriptor{
			Use: "encryption",
			KeyInfo: KeyInfo{
				X509Data: X509Data{
					X509Certificates: []X509Certificate{
						{Data: certStr},
					},
				},
			},
			EncryptionMethods: []EncryptionMethod{
				{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
				{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc"},
				{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},
				{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
			},
		})
	}

	ed := &EntityDescriptor{
		EntityID:      idp.MetadataURL.String(),
		ValidUntil:    TimeNow().Add(validDuration),
		CacheDuration: validDuration,
		IDPSSODescriptors: []IDPSSODescriptor{
			{
				SSODescriptor: SSODescriptor{
					RoleDescriptor: RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors:             keyDescriptors,
					},
					NameIDFormats: []NameIDFormat{NameIDFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient")},
				},
				SingleSignOnServices: []Endpoint{
					{
						Binding:  HTTPRedirectBinding,
						Location: idp.SSOURL.String(),
					},
					{
						Binding:  HTTPPostBinding,
						Location: idp.SSOURL.String(),
					},
				},
			},
		},
	}

	if idp.WantAuthnRequestsSigned {
		wantAuthnRequestsSigned := true
		ed.IDPSSODescriptors[0].WantAuthnRequestsSigned = &wantAuthnRequestsSigned
	}

	if idp.LogoutURL.String() != "" {
		ed.IDPSSODescriptors[0].SingleLogoutServices = []Endpoint{
			{
				Binding:  HTTPRedirectBinding,
				Location: idp.LogoutURL.String(),
			},
			{
				Binding:  HTTPPostBinding,
				Location: idp.LogoutURL.String(),
			},
		}
	}

	return ed
}

// Handler returns an http.Handler that serves the metadata and SSO URLs, and the logout URL if it
// is set.
func (idp *IdentityProvider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(idp.MetadataURL.Path, idp.ServeMetadata)
	mux.HandleFunc(idp.SSOURL.Path, idp.ServeSSO)
	if idp.LogoutURL.String() != "" {
		mux.HandleFunc(idp.LogoutURL.Path, idp.ServeSLO)
	}
	return mux
}

// ServeMetadata is an http.HandlerFunc that serves the IDP metadata
func (idp *IdentityProvider) ServeMetadata(w http.ResponseWriter, _ *http.Request) {
	buf, _ := xml.MarshalIndent(idp.Metadata(), "", "  ")
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	if _, err := w.Write(buf); err != nil {
		idp.Logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// ServeSSO handles SAML auth requests.
//
// When it gets a request for a user that does not have a valid session,
// then it prompts the user via XXX.
//
// If the session already exists, then it produces a SAML assertion and
// returns an HTTP response according to the specified binding. The
// only supported binding right now is the HTTP-POST binding which returns
// an HTML form in the appropriate format with Javascript to automatically
// submit that form the to service provider's Assertion Customer Service
// endpoint.
//
// If the SAML request is invalid or cannot be verified a simple StatusBadRequest
// response is sent.
//
// If the assertion cannot be created or returned, a StatusInternalServerError
// response is sent.
func (idp *IdentityProvider) ServeSSO(w http.ResponseWriter, r *http.Request) {
	req, err := NewIdpAuthnRequest(idp, r)
	if err != nil {
		idp.Logger.Printf("failed to parse request: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		idp.Logger.Printf("failed to validate request: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// TODO(ross): we must check that the request ID has not been previously
	//   issued.

	session := req.getSession(w, r)
	if session == nil {
		return
	}

	assertionMaker := idp.AssertionMaker
	if assertionMaker == nil {
		assertionMaker = DefaultAssertionMaker{}
	}
	if err := assertionMaker.MakeAssertion(req, session); err != nil {
		idp.Logger.Printf("failed to make assertion: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if req.Request.NameIDPolicy != nil {
		nameIDPolicyEnforcer := idp.NameIDPolicyEnforcer
		if nameIDPolicyEnforcer == nil {
			nameIDPolicyEnforcer = DefaultNameIDPolicyEnforcer{}
		}
		if err := nameIDPolicyEnforcer.EnforceNameIDPolicy(req, session); err != nil {
			idp.Logger.Printf("cannot satisfy name id policy: %s", err)
			if err := req.WriteErrorResponse(w, StatusRequester, StatusInvalidNameIDPolicy, ""); err != nil {
				idp.Logger.Printf("failed to write response: %s", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			return
		}
	}
	if req.Request.RequestedAuthnContext != nil {
		authnContextEnforcer := idp.AuthnContextEnforcer
		if authnContextEnforcer == nil {
			authnContextEnforcer = DefaultAuthnContextEnforcer{}
		}
		if err := authnContextEnforcer.EnforceAuthnContext(req, session); err != nil {
			idp.Logger.Printf("cannot satisfy requested authn context: %s", err)
			if err := req.WriteErrorResponse(w, StatusResponder, StatusNoAuthnContext, ""); err != nil {
				idp.Logger.Printf("failed to write response: %s", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			return
		}
	}
	if err := req.WriteResponse(w); err != nil {
		idp.Logger.Printf("failed to write response: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

// getSession returns the session for the request, following its IsPassive and ForceAuthn attributes.
// If it returns nil then the HTTP request has been completed. IsPassive comes first, as SAMLCore
// §3.4.1 requires that ForceAuthn doesn't cause any authentication that it would forbid.
func (req *IdpAuthnRequest) getSession(w http.ResponseWriter, r *http.Request) *Session {
	idp := req.IDP

	if req.Request.IsPassive != nil && *req.Request.IsPassive {
		var session *Session
		if provider, ok := idp.SessionProvider.(PassiveSessionProvider); ok {
			session = provider.GetPassiveSession(r, req)
		}
		if session == nil {
			req.writeErrorStatus(w, StatusNoPassive)
		}
		return session
	}

	if req.Request.ForceAuthn != nil && *req.Request.ForceAuthn {
		provider, ok := idp.SessionProvider.(ForceAuthnSessionProvider)
		if !ok {
			req.writeErrorStatus(w, StatusAuthnFailed)
			return nil
		}
		return provider.GetForcedSession(w, r, req)
	}

	return idp.SessionProvider.GetSession(w, r, req)
}

// writeErrorStatus completes the HTTP request with a Responder status and the given second-level status.
func (req *IdpAuthnRequest) writeErrorStatus(w http.ResponseWriter, secondLevelStatus string) {
	if err := req.WriteErrorResponse(w, StatusResponder, secondLevelStatus, ""); err != nil {
		req.IDP.Logger.Printf("failed to write response: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// ServeIDPInitiated handes an IDP-initiated authorization request. Requests of this
// type require us to know a registered service provider and (optionally) the RelayState
// that will be passed to the application.
func (idp *IdentityProvider) ServeIDPInitiated(w http.ResponseWriter, r *http.Request, serviceProviderID string, relayState string) {
	req := &IdpAuthnRequest{
		IDP:         idp,
		HTTPRequest: r,
		RelayState:  relayState,
		Now:         TimeNow(),
	}

	session := idp.SessionProvider.GetSession(w, r, req)
	if session == nil {
		// If GetSession returns nil, it must have written an HTTP response, per the interface
		// (this is probably because it drew a login form or something)
		return
	}

	var err error
	req.ServiceProviderMetadata, err = idp.ServiceProviderProvider.GetServiceProvider(r, serviceProviderID)
	if err == os.ErrNotExist {
		idp.Logger.Printf("cannot find service provider: %s", serviceProviderID)
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	} else if err != nil {
		idp.Logger.Printf("cannot find service provider %s: %v", serviceProviderID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// find an ACS endpoint that we can use
	if err := req.useDefaultACSEndpoint(); err != nil {
		idp.Logger.Printf("saml metadata does not contain an Assertion Customer Service url")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	assertionMaker := idp.AssertionMaker
	if assertionMaker == nil {
		assertionMaker = DefaultAssertionMaker{}
	}
	if err := assertionMaker.MakeAssertion(req, session); err != nil {
		idp.Logger.Printf("failed to make assertion: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if err := req.WriteResponse(w); err != nil {
		idp.Logger.Printf("failed to write response: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

// IdpAuthnRequest is used by IdentityProvider to handle a single authentication request.
type IdpAuthnRequest struct {
	IDP                     *IdentityProvider
	HTTPRequest             *http.Request
	RelayState              string
	RequestBuffer           []byte
	Request                 AuthnRequest
	ServiceProviderMetadata *EntityDescriptor
	SPSSODescriptor         *SPSSODescriptor
	ACSEndpoint             *IndexedEndpoint
	Assertion               *Assertion
	AssertionEl             *etree.Element
	ResponseEl              *etree.Element
	Now                     time.Time

	// RedirectQuery is the raw query string of a signed HTTP-Redirect request, which is what the
	// signature covers. A SessionProvider which shows a login form and re-presents the request as a
	// POST must send this value in the RedirectQueryFormField field, otherwise the signature is lost
	// and a service provider that requires one is refused.
	RedirectQuery string
}

// RedirectQueryFormField is the POST form field which re-presents a signed HTTP-Redirect request. See
// IdpAuthnRequest.RedirectQuery.
const RedirectQueryFormField = "SAMLRedirectQuery"

// NewIdpAuthnRequest returns a new IdpAuthnRequest for the given HTTP request to the authorization
// service.
func NewIdpAuthnRequest(idp *IdentityProvider, r *http.Request) (*IdpAuthnRequest, error) {
	req := &IdpAuthnRequest{
		IDP:         idp,
		HTTPRequest: r,
		Now:         TimeNow(),
	}

	switch r.Method {
	case "GET":
		if err := req.readRedirectQuery(r.URL.RawQuery); err != nil {
			return nil, err
		}
	case "POST":
		// Limit what ParseForm reads, which is otherwise up to 10MB before any size check applies.
		if r.Body != nil {
			r.Body = http.MaxBytesReader(nil, r.Body, maxAuthnRequestBodySize)
		}
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		// A signed HTTP-Redirect request that was re-presented by a login form. The signature covers
		// this query, so the unsigned SAMLRequest and RelayState fields are not used.
		if rawQuery := r.PostForm.Get(RedirectQueryFormField); rawQuery != "" {
			if err := req.readRedirectQuery(rawQuery); err != nil {
				return nil, err
			}
			return req, nil
		}
		var err error
		req.RequestBuffer, err = base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLRequest"))
		if err != nil {
			return nil, err
		}
		req.RelayState = r.PostForm.Get("RelayState")
	default:
		return nil, fmt.Errorf("method not allowed")
	}

	return req, nil
}

// readRedirectQuery reads the request from the query string of the HTTP-Redirect binding.
func (req *IdpAuthnRequest) readRedirectQuery(rawQuery string) error {
	buf, relayState, signedQuery, err := readRedirectRequest(rawQuery)
	if err != nil {
		return err
	}
	req.RequestBuffer, req.RelayState, req.RedirectQuery = buf, relayState, signedQuery
	return nil
}

// readRedirectRequest returns the decoded request and the RelayState from the query string of the
// HTTP-Redirect binding, and the query string itself if it carries a signature.
func readRedirectRequest(rawQuery string) (buf []byte, relayState, signedQuery string, err error) {
	// As with url.URL.Query, malformed pairs are dropped. Those can't affect a signed request, which
	// verifyRedirectSignature rejects if the query has a malformed key.
	values, _ := url.ParseQuery(rawQuery)

	compressedRequest, err := base64.StdEncoding.DecodeString(values.Get("SAMLRequest"))
	if err != nil {
		return nil, "", "", fmt.Errorf("cannot decode request: %s", err)
	}
	// Read one byte past the limit so that an oversized request can be told apart from one
	// that is exactly at the limit, without inflating any more of it.
	buf, err = io.ReadAll(io.LimitReader(newSaferFlateReader(bytes.NewReader(compressedRequest)), maxAuthnRequestSize+1))
	if err != nil {
		return nil, "", "", fmt.Errorf("cannot decompress request: %s", err)
	}
	if err := checkAuthnRequestSize(buf); err != nil {
		return nil, "", "", err
	}
	relayState = values.Get("RelayState")
	if values.Has("Signature") || values.Has("SigAlg") {
		signedQuery = rawQuery
	}
	return buf, relayState, signedQuery, nil
}

// Validate checks that the authentication request is valid and assigns
// the AuthnRequest and Metadata properties. Returns a non-nil error if the
// request is not valid.
func (req *IdpAuthnRequest) Validate() error {
	// This must come first: this code runs before any authentication, and the cost of the XML
	// parsing below is proportional to the size of the request.
	if err := checkAuthnRequestSize(req.RequestBuffer); err != nil {
		return err
	}

	if err := xrv.Validate(bytes.NewReader(req.RequestBuffer)); err != nil {
		return err
	}

	if err := xml.Unmarshal(req.RequestBuffer, &req.Request); err != nil {
		return err
	}

	if err := req.checkRequest(); err != nil {
		return err
	}

	// find the service provider
	serviceProviderID := req.Request.Issuer.Value
	serviceProvider, err := req.IDP.ServiceProviderProvider.GetServiceProvider(req.HTTPRequest, serviceProviderID)
	if err == os.ErrNotExist {
		return fmt.Errorf("cannot handle request from unknown service provider %s", serviceProviderID)
	} else if err != nil {
		return fmt.Errorf("cannot find service provider %s: %v", serviceProviderID, err)
	}
	req.ServiceProviderMetadata = serviceProvider

	if err := req.verifyAuthnRequestSignature(); err != nil {
		return err
	}

	// Check that the ACS URL matches an ACS endpoint in the SP metadata.
	if err := req.getACSEndpoint(); err != nil {
		return fmt.Errorf("cannot find assertion consumer service: %v", err)
	}

	return nil
}

// checkRequest makes the checks that depend only on the content of Request and the identity provider.
func (req *IdpAuthnRequest) checkRequest() error {
	// In http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf §3.4.5.2
	// we get a description of the Destination attribute:
	//
	//   If the message is signed, the Destination XML attribute in the root SAML
	//   element of the protocol message MUST contain the URL to which the sender
	//   has instructed the user agent to deliver the message. The recipient MUST
	//   then verify that the value matches the location at which the message has
	//   been received.
	//
	// We require the destination to be correct if it was provided, or if every request must be signed.
	// verifyAuthnRequestSignature requires it on any other request that is signed.
	if req.IDP.WantAuthnRequestsSigned || req.Request.Destination != "" {
		if req.Request.Destination != req.IDP.SSOURL.String() {
			return fmt.Errorf("expected destination to be %q, not %q", req.IDP.SSOURL.String(), req.Request.Destination)
		}
	}

	maxAge := req.IDP.MaxAuthnRequestAge
	if maxAge == 0 {
		maxAge = MaxIssueDelay
	}
	if req.Request.IssueInstant.Add(maxAge).Before(req.Now) {
		return fmt.Errorf("request expired at %s", req.Request.IssueInstant.Add(maxAge))
	}
	if req.Request.IssueInstant.After(req.Now.Add(MaxClockSkew)) {
		return fmt.Errorf("request issued in the future at %s", req.Request.IssueInstant)
	}
	if req.Request.Version != "2.0" {
		return fmt.Errorf("expected SAML request version 2.0 got %v", req.Request.Version)
	}
	if !isValidAuthnRequestID(req.Request.ID) {
		// The value is not included because this error is logged without authentication.
		return fmt.Errorf("invalid request ID")
	}
	if req.Request.Issuer == nil || req.Request.Issuer.Value == "" {
		return fmt.Errorf("request has no issuer")
	}
	return nil
}

// checkAuthnRequestSize returns an error if the decoded request is larger than maxAuthnRequestSize.
func checkAuthnRequestSize(buf []byte) error {
	if len(buf) > maxAuthnRequestSize {
		return fmt.Errorf("request exceeds the limit of %d bytes", maxAuthnRequestSize)
	}
	return nil
}

// isValidAuthnRequestID returns true if id is non-empty, no longer than maxAuthnRequestIDLength,
// and contains only ASCII letters, digits, '_', '-' and '.'. The value is copied into the signed
// response, where anything that an XML parser or Unicode normalization might alter could break the
// signature.
//
// Unlike xs:ID this does not restrict the first character, because some service providers send IDs
// which begin with a digit, such as a bare UUID.
func isValidAuthnRequestID(id string) bool {
	if id == "" || len(id) > maxAuthnRequestIDLength {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-', c == '.':
		default:
			return false
		}
	}
	return true
}

// getACSEndpoint finds the endpoint to deliver the response to. HTTP-POST is the only binding this
// identity provider can send a response with, so other endpoints are never selected.
func (req *IdpAuthnRequest) getACSEndpoint() error {
	index, location := req.Request.AssertionConsumerServiceIndex, req.Request.AssertionConsumerServiceURL

	if index != "" || location != "" {
		for _, match := range []func(endpoint IndexedEndpoint) bool{
			func(endpoint IndexedEndpoint) bool { return index != "" && strconv.Itoa(endpoint.Index) == index },
			func(endpoint IndexedEndpoint) bool { return location != "" && endpoint.Location == location },
		} {
			for _, spssoDescriptor := range req.ServiceProviderMetadata.SPSSODescriptors {
				for _, endpoint := range spssoDescriptor.AssertionConsumerServices {
					if endpoint.Binding == HTTPPostBinding && match(endpoint) {
						req.SPSSODescriptor, req.ACSEndpoint = &spssoDescriptor, &endpoint
						return nil
					}
				}
			}
		}
		return os.ErrNotExist
	}

	// Some service providers, like the Microsoft Azure AD service provider, issue
	// assertion requests that don't specify an ACS url at all.
	return req.useDefaultACSEndpoint()
}

// useDefaultACSEndpoint selects the default HTTP-POST endpoint as defined by SAMLMetadata §2.2.3: the
// first with isDefault set to true, otherwise the first without isDefault set to false, otherwise
// the first.
func (req *IdpAuthnRequest) useDefaultACSEndpoint() error {
	preference := func(endpoint IndexedEndpoint) int {
		switch {
		case endpoint.IsDefault == nil:
			return 2
		case *endpoint.IsDefault:
			return 3
		default:
			return 1
		}
	}

	best := 0
	for _, spssoDescriptor := range req.ServiceProviderMetadata.SPSSODescriptors {
		for _, endpoint := range spssoDescriptor.AssertionConsumerServices {
			if endpoint.Binding == HTTPPostBinding && preference(endpoint) > best {
				best = preference(endpoint)
				req.SPSSODescriptor, req.ACSEndpoint = &spssoDescriptor, &endpoint
			}
		}
	}
	if best == 0 {
		return os.ErrNotExist
	}
	return nil
}

// DefaultNameIDPolicyEnforcer applies the rules of SAMLCore §3.4.1.1, as changed by errata E15.
type DefaultNameIDPolicyEnforcer struct {
}

// EnforceNameIDPolicy implements NameIDPolicyEnforcer. Unless the policy leaves the format open, the
// NameID must have that format. The encrypted format is always refused, because the assertions made
// here don't contain an EncryptedID. If the policy has an SPNameQualifier, the NameID must also have
// that value.
func (DefaultNameIDPolicyEnforcer) EnforceNameIDPolicy(req *IdpAuthnRequest, _ *Session) error {
	policy := req.Request.NameIDPolicy
	if req.Assertion == nil || req.Assertion.Subject == nil || req.Assertion.Subject.NameID == nil {
		return fmt.Errorf("assertion has no NameID")
	}
	nameID := req.Assertion.Subject.NameID

	if policy.Format != nil {
		switch *policy.Format {
		case "", string(UnspecifiedNameIDFormat), unspecifiedNameIDFormat:
		case encryptedNameIDFormat:
			return fmt.Errorf("the request requires an EncryptedID, which is not supported")
		default:
			if nameID.Format != *policy.Format {
				return fmt.Errorf("the NameID format is %q and the request requires %q", nameID.Format, *policy.Format)
			}
		}
	}
	if policy.SPNameQualifier != nil && nameID.SPNameQualifier != *policy.SPNameQualifier {
		return fmt.Errorf("the NameID SPNameQualifier is %q and the request requires %q", nameID.SPNameQualifier, *policy.SPNameQualifier)
	}
	return nil
}

// unspecifiedNameIDFormat is the value that SAMLCore §3.4.1.1 gives for a format left open, which
// differs from the identifier that UnspecifiedNameIDFormat holds, as defined by SAMLCore §8.3.1.
const unspecifiedNameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"

// encryptedNameIDFormat is the format that requests an EncryptedID, from SAMLCore §3.4.1.1.
const encryptedNameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"

// DefaultAssertionMaker produces a SAML assertion for the
// given request and assigns it to req.Assertion.
type DefaultAssertionMaker struct {
}

// MakeAssertion implements AssertionMaker. It produces a SAML assertion from the
// given request and assigns it to req.Assertion.
func (DefaultAssertionMaker) MakeAssertion(req *IdpAuthnRequest, session *Session) error {
	attributes := []Attribute{}

	var attributeConsumingService *AttributeConsumingService
	for _, acs := range req.SPSSODescriptor.AttributeConsumingServices {
		if acs.IsDefault != nil && *acs.IsDefault {
			// explicitly copy loop iterator variables
			//
			// c.f. https://github.com/golang/go/wiki/CommonMistakes#using-reference-to-loop-iterator-variable
			//
			// (note that I'm pretty sure this isn't strictly necessary because we break out of the loop immediately,
			// but it certainly doesn't hurt anything and may prevent bugs in the future.)
			acs := acs

			attributeConsumingService = &acs
			break
		}
	}
	if attributeConsumingService == nil {
		for _, acs := range req.SPSSODescriptor.AttributeConsumingServices {
			// explicitly copy loop iterator variables
			//
			// c.f. https://github.com/golang/go/wiki/CommonMistakes#using-reference-to-loop-iterator-variable
			//
			// (note that I'm pretty sure this isn't strictly necessary because we break out of the loop immediately,
			// but it certainly doesn't hurt anything and may prevent bugs in the future.)
			acs := acs

			attributeConsumingService = &acs
			break
		}
	}
	if attributeConsumingService == nil {
		attributeConsumingService = &AttributeConsumingService{}
	}

	for _, requestedAttribute := range attributeConsumingService.RequestedAttributes {
		if requestedAttribute.NameFormat == "urn:oasis:names:tc:SAML:2.0:attrname-format:basic" || requestedAttribute.NameFormat == "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" {
			attrName := requestedAttribute.Name
			attrName = regexp.MustCompile("[^A-Za-z0-9]+").ReplaceAllString(attrName, "")
			switch attrName {
			case "email", "emailaddress":
				attributes = append(attributes, Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []AttributeValue{{
						Type:  "xs:string",
						Value: session.UserEmail,
					}},
				})
			case "name", "fullname", "cn", "commonname":
				attributes = append(attributes, Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []AttributeValue{{
						Type:  "xs:string",
						Value: session.UserCommonName,
					}},
				})
			case "givenname", "firstname":
				attributes = append(attributes, Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []AttributeValue{{
						Type:  "xs:string",
						Value: session.UserGivenName,
					}},
				})
			case "surname", "lastname", "familyname":
				attributes = append(attributes, Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []AttributeValue{{
						Type:  "xs:string",
						Value: session.UserSurname,
					}},
				})
			case "uid", "user", "userid":
				attributes = append(attributes, Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []AttributeValue{{
						Type:  "xs:string",
						Value: session.UserName,
					}},
				})
			}
		}
	}

	if session.UserName != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "uid",
			Name:         "urn:oid:0.9.2342.19200300.100.1.1",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserName,
			}},
		})
	}

	if session.UserEmail != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "mail",
			Name:         "urn:oid:0.9.2342.19200300.100.1.3",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserEmail,
			}},
		})
	}
	if session.EduPersonPrincipalName != "" || session.UserEmail != "" {
		value := session.EduPersonPrincipalName
		if value == "" {
			// We used to set eduPersonPrincipalName (urn:oid:1.3.6.1.4.1.5923.1.1.1.6)
			// to the value of session.UserEmail. It is more correct to set
			// mail (urn:oid:0.9.2342.19200300.100.1.3). To avoid breaking things,
			// we preserve the former behavior.
			value = session.UserEmail
		}

		attributes = append(attributes, Attribute{
			FriendlyName: "eduPersonPrincipalName",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: value,
			}},
		})
	}
	if session.UserSurname != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "sn",
			Name:         "urn:oid:2.5.4.4",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserSurname,
			}},
		})
	}
	if session.UserGivenName != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "givenName",
			Name:         "urn:oid:2.5.4.42",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserGivenName,
			}},
		})
	}

	if session.UserCommonName != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "cn",
			Name:         "urn:oid:2.5.4.3",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserCommonName,
			}},
		})
	}

	if session.UserScopedAffiliation != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "scopedAffiliation",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserScopedAffiliation,
			}},
		})
	}

	attributes = append(attributes, session.CustomAttributes...)

	if len(session.Groups) != 0 {
		groupMemberAttributeValues := []AttributeValue{}
		for _, group := range session.Groups {
			groupMemberAttributeValues = append(groupMemberAttributeValues, AttributeValue{
				Type:  "xs:string",
				Value: group,
			})
		}
		attributes = append(attributes, Attribute{
			FriendlyName: "eduPersonAffiliation",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values:       groupMemberAttributeValues,
		})
	}

	if session.SubjectID != "" {
		attributes = append(attributes, Attribute{
			Name:       "urn:oasis:names:tc:SAML:attribute:subject-id",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: session.SubjectID,
				},
			},
		})
	}

	// allow for some clock skew in the validity period. This uses our own clock, because the
	// request and therefore its IssueInstant are not authenticated.
	notBefore := req.Now.Add(-1 * MaxClockSkew)
	notOnOrAfterAfter := req.Now.Add(MaxIssueDelay)

	nameIDFormat := "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

	if session.NameIDFormat != "" {
		nameIDFormat = session.NameIDFormat
	}

	req.Assertion = &Assertion{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		IssueInstant: TimeNow(),
		Version:      "2.0",
		Issuer: Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  req.IDP.Metadata().EntityID,
		},
		Subject: &Subject{
			NameID: &NameID{
				Format:          nameIDFormat,
				NameQualifier:   req.IDP.Metadata().EntityID,
				SPNameQualifier: req.ServiceProviderMetadata.EntityID,
				Value:           session.NameID,
			},
			SubjectConfirmations: []SubjectConfirmation{
				{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &SubjectConfirmationData{
						Address:      req.HTTPRequest.RemoteAddr,
						InResponseTo: req.Request.ID,
						NotOnOrAfter: req.Now.Add(MaxIssueDelay),
						Recipient:    req.ACSEndpoint.Location,
					},
				},
			},
		},
		Conditions: &Conditions{
			NotBefore:    notBefore,
			NotOnOrAfter: notOnOrAfterAfter,
			AudienceRestrictions: []AudienceRestriction{
				{
					Audiences: []Audience{{Value: req.ServiceProviderMetadata.EntityID}},
				},
			},
		},
		AuthnStatements: []AuthnStatement{
			{
				AuthnInstant: session.CreateTime,
				SessionIndex: session.Index,
				SubjectLocality: &SubjectLocality{
					Address: req.HTTPRequest.RemoteAddr,
				},
				AuthnContext: AuthnContext{
					AuthnContextClassRef: &AuthnContextClassRef{
						Value: cmp.Or(session.AuthnContextClassRef, defaultAuthnContextClassRef),
					},
				},
			},
		},
	}

	// SAMLCore §2.7.3 requires an AttributeStatement to contain at least one attribute.
	if len(attributes) != 0 {
		req.Assertion.AttributeStatements = []AttributeStatement{{Attributes: attributes}}
	}

	return nil
}

// The Canonicalizer prefix list MUST be empty. Various implementations
// (maybe ours?) do not appear to support non-empty prefix lists in XML C14N.
const canonicalizerPrefixList = ""

// MakeAssertionEl sets `AssertionEl` to a signed, possibly encrypted, version of `Assertion`.
func (req *IdpAuthnRequest) MakeAssertionEl() error {
	signingContext, err := req.signingContext()
	if err != nil {
		return err
	}

	assertionEl := req.Assertion.Element()

	signedAssertionEl, err := signingContext.SignEnveloped(assertionEl)
	if err != nil {
		return err
	}

	sigEl := signedAssertionEl.Child[len(signedAssertionEl.Child)-1]
	req.Assertion.Signature = sigEl.(*etree.Element)
	signedAssertionEl = req.Assertion.Element()

	certBuf, err := req.getSPEncryptionCert()
	if err == os.ErrNotExist {
		req.AssertionEl = signedAssertionEl
		return nil
	} else if err != nil {
		return err
	}

	var signedAssertionBuf []byte
	{
		doc := etree.NewDocument()
		doc.SetRoot(signedAssertionEl)
		signedAssertionBuf, err = doc.WriteToBytes()
		if err != nil {
			return err
		}
	}

	encryptor := xmlenc.OAEP()
	encryptor.BlockCipher = req.contentEncryption()
	encryptor.DigestMethod = &xmlenc.SHA1
	encryptedDataEl, err := encryptor.Encrypt(certBuf, signedAssertionBuf, nil)
	if err != nil {
		return err
	}
	encryptedDataEl.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")

	encryptedAssertionEl := etree.NewElement("saml:EncryptedAssertion")
	encryptedAssertionEl.AddChild(encryptedDataEl)
	req.AssertionEl = encryptedAssertionEl

	return nil
}

// IdpAuthnRequestForm contans HTML form information to be submitted to the
// SAML HTTP POST binding ACS.
type IdpAuthnRequestForm struct {
	URL          string
	SAMLResponse string
	RelayState   string
}

// PostBinding creates the HTTP POST form information for this
// `IdpAuthnRequest`. If `Response` is not already set, it calls MakeResponse
// to produce it.
func (req *IdpAuthnRequest) PostBinding() (IdpAuthnRequestForm, error) {
	var form IdpAuthnRequestForm

	if req.ResponseEl == nil {
		if err := req.MakeResponse(); err != nil {
			return form, err
		}
	}

	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)
	responseBuf, err := doc.WriteToBytes()
	if err != nil {
		return form, err
	}

	if req.ACSEndpoint.Binding != HTTPPostBinding {
		return form, fmt.Errorf("%s: unsupported binding %s",
			req.ServiceProviderMetadata.EntityID,
			req.ACSEndpoint.Binding)
	}

	form.URL = req.ACSEndpoint.Location
	form.SAMLResponse = base64.StdEncoding.EncodeToString(responseBuf)
	form.RelayState = req.RelayState

	return form, nil
}

var defaultResponseFormTemplate = template.Must(template.New("saml-post-form").Parse(`<html>` +
	`<form method="post" action="{{.URL}}" id="SAMLResponseForm">` +
	`<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}" />` +
	`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
	`<input id="SAMLSubmitButton" type="submit" value="Continue" />` +
	`</form>` +
	`<script>document.getElementById('SAMLSubmitButton').style.visibility='hidden';</script>` +
	`<script>document.getElementById('SAMLResponseForm').submit();</script>` +
	`</html>`))

// WriteResponse writes the `Response` to the http.ResponseWriter. If
// `Response` is not already set, it calls MakeResponse to produce it.
func (req *IdpAuthnRequest) WriteResponse(w http.ResponseWriter) error {
	form, err := req.PostBinding()
	if err != nil {
		return err
	}

	tmpl := req.IDP.ResponseFormTemplate
	if tmpl == nil {
		tmpl = defaultResponseFormTemplate
	}

	buf := bytes.NewBuffer(nil)
	if err := tmpl.Execute(buf, form); err != nil {
		return err
	}
	if _, err := io.Copy(w, buf); err != nil {
		return err
	}
	return nil
}

// contentEncryptionMethods are the content encryption algorithms this identity provider can use.
var contentEncryptionMethods = []xmlenc.BlockCipher{
	xmlenc.AES128GCM,
	xmlenc.AES128CBC,
	xmlenc.AES192CBC,
	xmlenc.AES256CBC,
}

// contentEncryption returns the first algorithm the service provider advertises for its encryption
// key that we can use, as metadata lists them in order of preference. It returns AES-128-CBC if there
// is none, which is the only option known to work with service providers that advertise nothing.
func (req *IdpAuthnRequest) contentEncryption() xmlenc.BlockCipher {
	if keyDescriptor := req.spEncryptionKeyDescriptor(); keyDescriptor != nil {
		for _, method := range keyDescriptor.EncryptionMethods {
			for _, candidate := range contentEncryptionMethods {
				if candidate.Algorithm() == method.Algorithm {
					return candidate
				}
			}
		}
	}
	return xmlenc.AES128CBC
}

// spEncryptionKeyDescriptor returns the key descriptor of the certificate used to encrypt things to
// the SP. It is the first one labeled for encryption which has a certificate, or if there are none
// the first one with no use which has a certificate, or nil if no such key descriptor is found.
func (req *IdpAuthnRequest) spEncryptionKeyDescriptor() *KeyDescriptor {
	for _, use := range []string{"encryption", ""} {
		for i := range req.SPSSODescriptor.KeyDescriptors {
			keyDescriptor := &req.SPSSODescriptor.KeyDescriptors[i]
			if keyDescriptor.Use == use && firstCertificateData(*keyDescriptor) != "" {
				return keyDescriptor
			}
		}
	}
	return nil
}

// getSPEncryptionCert returns the certificate which we can use to encrypt things
// to the SP in PEM format, or nil if no such certificate is found.
func (req *IdpAuthnRequest) getSPEncryptionCert() (*x509.Certificate, error) {
	certStr := ""
	if keyDescriptor := req.spEncryptionKeyDescriptor(); keyDescriptor != nil {
		certStr = firstCertificateData(*keyDescriptor)
	}

	if certStr == "" {
		// os.ErrNotExist makes the caller send the assertion in plaintext, which is not acceptable
		// if the service provider asked for encryption with a key we are unable to use.
		if req.serviceProviderAcceptsEncryption() {
			return nil, fmt.Errorf("service provider metadata allows encryption but has no usable certificate in the selected descriptor")
		}
		return nil, os.ErrNotExist
	}

	// cleanup whitespace and re-encode a PEM
	certStr = regexp.MustCompile(`\s+`).ReplaceAllString(certStr, "")
	certBytes, err := base64.StdEncoding.DecodeString(certStr)
	if err != nil {
		return nil, fmt.Errorf("cannot decode certificate base64: %v", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse certificate: %v", err)
	}
	return cert, nil
}

// serviceProviderAcceptsEncryption returns true if any of the service provider's key descriptors
// might be used for encryption, which includes any with an unrecognized use. This includes its other SPSSODescriptors, because the descriptor in use is
// selected by the ACS in the unauthenticated request, which must not be able to avoid encryption.
func (req *IdpAuthnRequest) serviceProviderAcceptsEncryption() bool {
	descriptors := []SPSSODescriptor{*req.SPSSODescriptor}
	if req.ServiceProviderMetadata != nil {
		descriptors = append(descriptors, req.ServiceProviderMetadata.SPSSODescriptors...)
	}
	for _, descriptor := range descriptors {
		for _, keyDescriptor := range descriptor.KeyDescriptors {
			if keyDescriptor.Use != "signing" {
				return true
			}
		}
	}
	return false
}

// firstCertificateData returns the data of the first non-empty certificate in the key descriptor,
// or an empty string if there is none.
func firstCertificateData(keyDescriptor KeyDescriptor) string {
	for _, certificate := range keyDescriptor.KeyInfo.X509Data.X509Certificates {
		if certificate.Data != "" {
			return certificate.Data
		}
	}
	return ""
}

// unmarshalEtreeHack parses `el` and sets values in the structure `v`.
//
// This is a hack -- it first serializes the element, then uses xml.Unmarshal.
func unmarshalEtreeHack(el *etree.Element, v interface{}) error {
	doc := etree.NewDocument()
	doc.SetRoot(el)
	buf, err := doc.WriteToBytes()
	if err != nil {
		return err
	}
	return xml.Unmarshal(buf, v)
}

// MakeResponse creates and assigns a new SAML response in ResponseEl. `Assertion` must
// be non-nil. If MakeAssertionEl() has not been called, this function calls it for
// you.
func (req *IdpAuthnRequest) MakeResponse() error {
	if req.AssertionEl == nil {
		if err := req.MakeAssertionEl(); err != nil {
			return err
		}
	}

	responseEl, err := req.signResponse(req.newResponse(Status{StatusCode: StatusCode{Value: StatusSuccess}}), req.AssertionEl)
	if err != nil {
		return err
	}

	req.ResponseEl = responseEl
	return nil
}

// MakeErrorResponse creates and assigns a new signed SAML response in ResponseEl which reports a
// failure and carries no assertion, replacing any response made earlier. The topLevelStatus must be
// one of StatusRequester, StatusResponder or StatusVersionMismatch, as required by SAMLCore §3.2.2.2.
// The secondLevelStatus and message are optional, and message is sent to the service provider as is.
//
// It returns an error if ACSEndpoint is not set, because a response must only be sent to an endpoint
// that has been checked against the metadata of the service provider. Requests which fail before
// that point, such as any for which Validate returns an error, can't be answered with a SAML response.
func (req *IdpAuthnRequest) MakeErrorResponse(topLevelStatus, secondLevelStatus, message string) error {
	req.ResponseEl = nil

	if req.ACSEndpoint == nil {
		return fmt.Errorf("cannot make an error response without a validated assertion consumer service")
	}

	switch topLevelStatus {
	case StatusRequester, StatusResponder, StatusVersionMismatch:
	default:
		return fmt.Errorf("invalid top-level status %q for an error response", topLevelStatus)
	}

	status := Status{StatusCode: StatusCode{Value: topLevelStatus}}
	if secondLevelStatus != "" {
		status.StatusCode.StatusCode = &StatusCode{Value: secondLevelStatus}
	}
	if message != "" {
		status.StatusMessage = &StatusMessage{Value: message}
	}

	responseEl, err := req.signResponse(req.newResponse(status), nil)
	if err != nil {
		return err
	}

	req.ResponseEl = responseEl
	return nil
}

// WriteErrorResponse writes a signed SAML response which reports a failure to the assertion consumer
// service of the service provider. See MakeErrorResponse for the arguments and when it can be used.
// Nothing is written to w if it returns an error from MakeErrorResponse.
func (req *IdpAuthnRequest) WriteErrorResponse(w http.ResponseWriter, topLevelStatus, secondLevelStatus, message string) error {
	if err := req.MakeErrorResponse(topLevelStatus, secondLevelStatus, message); err != nil {
		return err
	}
	return req.WriteResponse(w)
}

// newResponse returns the Response for this request with the given status.
func (req *IdpAuthnRequest) newResponse(status Status) *Response {
	return &Response{
		Destination:  req.ACSEndpoint.Location,
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		InResponseTo: req.Request.ID,
		IssueInstant: req.Now,
		Version:      "2.0",
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  req.IDP.MetadataURL.String(),
		},
		Status: status,
	}
}

// signResponse returns the signed element for response, which contains assertionEl if it is not nil.
// The assertionEl is either an EncryptedAssertion or an already signed Assertion element.
func (req *IdpAuthnRequest) signResponse(response *Response, assertionEl *etree.Element) (*etree.Element, error) {
	responseEl := response.Element()
	if assertionEl != nil {
		responseEl.AddChild(assertionEl)
	}

	signingContext, err := req.signingContext()
	if err != nil {
		return nil, err
	}

	signedResponseEl, err := signingContext.SignEnveloped(responseEl)
	if err != nil {
		return nil, err
	}

	response.Signature = signedResponseEl.ChildElements()[len(signedResponseEl.ChildElements())-1]
	responseEl = response.Element()
	if assertionEl != nil {
		responseEl.AddChild(assertionEl)
	}

	return responseEl, nil
}

// signingContext will create a signing context for the request.
func (req *IdpAuthnRequest) signingContext() (*dsig.SigningContext, error) {
	return req.IDP.signingContext()
}

// signingContext returns a context which signs with the key of the identity provider.
func (idp *IdentityProvider) signingContext() (*dsig.SigningContext, error) {
	// Create a cert chain based off of the IDP cert and its intermediates.
	certificates := make([][]byte, 0, 1+len(idp.Intermediates))
	certificates = append(certificates, idp.Certificate.Raw)
	for _, cert := range idp.Intermediates {
		certificates = append(certificates, cert.Raw)
	}

	// If signer is set, use it instead of the private key.
	signer := idp.Signer
	if signer == nil {
		var ok bool
		if signer, ok = idp.Key.(crypto.Signer); !ok {
			return nil, fmt.Errorf("identity provider key of type %T does not implement crypto.Signer", idp.Key)
		}
	}

	signingContext, err := dsig.NewSigningContext(signer, certificates)
	if err != nil {
		return nil, err
	}

	// Default to RSA with SHA-256, or ECDSA with the hash matching the curve of the key.
	signatureMethod := idp.SignatureMethod
	if signatureMethod == "" {
		signatureMethod = dsig.RSASHA256SignatureMethod
		if public, ok := signer.Public().(*ecdsa.PublicKey); ok {
			signatureMethod = dsig.DefaultECDSASignatureMethod(public)
		}
	}

	signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(canonicalizerPrefixList)
	if err := signingContext.SetSignatureMethod(signatureMethod); err != nil {
		return nil, err
	}

	return signingContext, nil
}
