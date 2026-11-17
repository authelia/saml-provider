package saml

import (
	"bytes"
	"cmp"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"

	"authelia.com/provider/saml/internal/dsig"
	"authelia.com/provider/saml/logger"
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

	// ClientAddress is the IP address of the user, which assertions state. Set it when the identity
	// provider is behind a proxy, as the address of the HTTP request is then the proxy's. If it is
	// empty the address of the HTTP request is used. An address which isn't an IP address is left
	// out of the assertion.
	ClientAddress string `json:",omitempty"`
}

// defaultAuthnContextClassRef is the authentication context class asserted for a session that sets
// none.
const defaultAuthnContextClassRef = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

// SessionProvider is an interface used by IdentityProvider to determine the
// Session associated with a request. For an example implementation, see
// GetSession in the example/idp/samlidp package.
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
	//
	// IdentityProvider drops expired metadata and descriptors itself (see CurrentMetadata), so a provider
	// may return the stored metadata as is. ParseServiceProviderMetadata and
	// IdentityProvider.CheckServiceProviderMetadata are there for registering metadata.
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

// SubjectEnforcer is an interface used by IdentityProvider to decide whether an assertion is about
// the principal that its request names. The default implementation is DefaultSubjectEnforcer, which
// is used if no SubjectEnforcer is specified.
type SubjectEnforcer interface {
	// EnforceSubject returns an error if req.Assertion doesn't strongly match req.Request.Subject,
	// which is not nil, as SAMLCore §3.4.1 requires. The service provider receives an AuthnFailed
	// status, not the error.
	//
	// This is where to accept an identifier in another format which refers to the same principal,
	// which the default implementation can't recognise.
	EnforceSubject(req *IdpAuthnRequest, session *Session) error
}

// EncryptionCertificateEnforcer is an interface used by IdentityProvider to decide whether the
// certificate in the metadata of a service provider may be used to encrypt assertions to it, which
// allows the decision to differ for each service provider. The default implementation is
// DefaultEncryptionCertificateEnforcer, which is used if no EncryptionCertificateEnforcer is
// specified.
type EncryptionCertificateEnforcer interface {
	// EnforceEncryptionCertificate returns an error if cert, which was taken from the selected
	// SPSSODescriptor of req.ServiceProviderMetadata, must not be used to encrypt the assertion. The
	// login then fails without a response: the assertion is never sent in plaintext, and no other key
	// of the service provider is tried in its place.
	EnforceEncryptionCertificate(req *IdpAuthnRequest, cert *x509.Certificate) error
}

// AttributeReleasePolicy is an interface used by DefaultAssertionMaker to decide which attributes of
// the principal are stated to a service provider, which allows the decision to differ for each
// service provider. The default implementation is DefaultAttributeReleasePolicy, which is used if no
// AttributeReleasePolicy is specified.
type AttributeReleasePolicy interface {
	// ReleaseAttributes returns the attributes of candidates that the assertion for req states.
	// candidates holds every attribute that DefaultAssertionMaker can state about the principal of
	// session, and may be modified or returned. req.AttributeConsumingService returns the service
	// that describes the attributes the service provider wants, if any.
	//
	// If no attributes are returned the assertion has no AttributeStatement, because SAMLCore
	// §2.7.3 requires every AttributeStatement to hold at least one attribute. If an error is
	// returned no assertion is made, and the user agent receives an HTTP error rather than a SAML
	// response.
	ReleaseAttributes(req *IdpAuthnRequest, session *Session, candidates []Attribute) ([]Attribute, error)
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
//
// Logger receives the reasons that requests fail, and defaults to
// logger.DefaultLogger.
type IdentityProvider struct {
	Key           crypto.PrivateKey
	Signer        crypto.Signer
	Logger        logger.Interface
	Certificate   *x509.Certificate
	Intermediates []*x509.Certificate
	// MaxAuthnRequestAge is the oldest AuthnRequest that will be accepted, which must allow for a
	// SessionProvider that re-presents the request after a login form. Defaults to MaxIssueDelay. The ID
	// of a request that was answered stays in the ReplayStore for this long after its IssueInstant, and
	// MaxClockSkew longer.
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

	// LogoutRequestFormTemplate renders the HTTP-POST form of a LogoutRequest, with an IdpLogoutRequestForm.
	// Defaults to a form which posts SAMLRequest and RelayState.
	LogoutRequestFormTemplate *template.Template

	// SOAPLogoutURL is the single logout service on the SOAP binding, which ServeSOAPLogout handles. When it is set
	// and the SessionProvider implements LogoutSessionProvider, the metadata lists it. It may share its path
	// with LogoutURL, as Handler tells the two apart by the Content-Type.
	SOAPLogoutURL url.URL

	// HTTPClient sends back-channel messages, such as a LogoutRequest over SOAP. Defaults to a client with a
	// 10 second timeout. A client that is set is copied, and the copy never follows a redirect, whatever its
	// CheckRedirect, and has the 10 second timeout if its Timeout is 0; its Transport is kept.
	HTTPClient *http.Client

	// WantAuthnRequestsSigned requires every AuthnRequest to be signed, and is declared in the
	// metadata. A request is also required to be signed if the metadata of its service provider
	// sets AuthnRequestsSigned, and any signature that is present is always verified.
	WantAuthnRequestsSigned bool

	// NameIDPolicyEnforcer decides whether an assertion satisfies the NameIDPolicy of its request.
	// Defaults to DefaultNameIDPolicyEnforcer.
	NameIDPolicyEnforcer NameIDPolicyEnforcer

	// NameIDProvider issues the NameID of each assertion that DefaultAssertionMaker makes, and its
	// formats are advertised in the metadata. Defaults to DefaultNameIDProvider.
	NameIDProvider NameIDProvider

	// AuthnContextEnforcer decides whether an assertion satisfies the RequestedAuthnContext of its
	// request. Defaults to a DefaultAuthnContextEnforcer with no Strength, which only accepts a
	// class that the request lists, and never satisfies the better comparison.
	AuthnContextEnforcer AuthnContextEnforcer

	// SubjectEnforcer decides whether an assertion matches the Subject of its request. Defaults to
	// DefaultSubjectEnforcer.
	SubjectEnforcer SubjectEnforcer

	// EncryptionCertificateEnforcer decides whether the encryption certificate of a service provider
	// may be used. Defaults to a DefaultEncryptionCertificateEnforcer with no options set, which
	// refuses a certificate that is expired or not yet valid, has an RSA key shorter than 2048 bits,
	// or has a KeyUsage extension without keyEncipherment.
	EncryptionCertificateEnforcer EncryptionCertificateEnforcer

	// AttributeReleasePolicy decides which attributes DefaultAssertionMaker states to each service
	// provider. Defaults to DefaultAttributeReleasePolicy, which only releases the attributes that
	// the AttributeConsumingService of the request lists, and none if there is no such service. It
	// is not used by any other AssertionMaker.
	AttributeReleasePolicy AttributeReleasePolicy

	// AllowInsecureServiceProviderEndpoints allows responses to be sent to an endpoint of a service
	// provider whose URL is plain http, on a host which is not loopback. That is an
	// AssertionConsumerService, or the SingleLogoutService that a LogoutResponse is sent to. By
	// default such an endpoint is never selected, and a request which asks for one is refused.
	//
	// Enabling this is a risk. The assertions in a response are bearer tokens, so anyone who can
	// read one in transit can use it to log in as the user until it expires. SAMLSec §6.4.1 requires
	// confidentiality whenever a response passes between a site and the browser, SAMLProf §4.1.3.5
	// recommends TLS for the delivery of a Response to the service provider, and §4.4.3.4 does so
	// for a LogoutResponse. It is only meant for testing, or for a network where something other
	// than TLS provides that confidentiality.
	//
	// Loopback hosts, which are localhost, names ending in .localhost, 127.0.0.0/8 and ::1, are
	// always allowed over http, as the traffic never leaves the machine of the user and browsers
	// treat them as secure contexts. URLs which are not absolute http or https URLs with a host are
	// always refused. To decide for each service provider, leave this unset and have the
	// ServiceProviderProvider rewrite or remove the endpoints of the metadata it returns.
	AllowInsecureServiceProviderEndpoints bool

	// ContentEncryptionMethods lists the identifiers of the block ciphers the identity provider may encrypt an
	// assertion with. When the service provider lists content encryption algorithms for its key, the first of them
	// in its order of preference that is also listed here is used, and when it lists none the first one listed
	// here is used (Metadata Profile for Algorithm Support §2.5). The supported ciphers are AES-128-CBC,
	// AES-192-CBC, AES-256-CBC, AES-128-GCM, AES-192-GCM and AES-256-GCM, and empty means all of them in that
	// order, so that a service provider which lists none receives AES-128-CBC.
	ContentEncryptionMethods []string

	// KeyTransportMethods lists the identifiers of the key transport algorithms the identity provider may encrypt
	// the key of an assertion with, and is chosen from like ContentEncryptionMethods. The supported algorithms
	// are RSA-OAEP-MGF1P (XML Encryption §5.4.2) and the RSA-OAEP of XML Encryption 1.1 (§5.5.2), and empty
	// means both in that order, so that a service provider which lists none receives RSA-OAEP-MGF1P.
	KeyTransportMethods []string

	// KeyTransportDigestMethods lists the identifiers of the digests the identity provider may use for RSA-OAEP,
	// and for the MGF1 mask generation function of XML Encryption 1.1 RSA-OAEP. The first one is used when the
	// service provider lists no key transport algorithm. A key transport algorithm it lists without a digest or
	// mask generation function means the default of that algorithm, SHA-1 or MGF1 with SHA-1, and can't be used
	// unless SHA-1 is allowed. The supported digests are SHA-1, SHA-256 and SHA-512, and empty means all of them in
	// that order, so that a service provider which lists no key transport algorithm receives SHA-1. The legacy
	// identifiers of SHA-256 and SHA-512 are accepted, and the standard ones are written.
	KeyTransportDigestMethods []string

	// LogoutNameIDValueOnly makes IdpLogoutRequest.MatchesSession compare only the NameID value and the session
	// indexes of a LogoutRequest, as earlier versions did, for service providers that don't echo the Format and
	// qualifiers of the NameID they were given. The value is compared with Session.NameID when
	// Session.NameIDFormat is set, and with the NameID recorded in a SessionParticipant of the requesting service
	// provider. It is off by default, which compares the whole identifier (SAMLCore §3.7.3.2).
	LogoutNameIDValueOnly bool

	// LogoutStateLifetime is how long the state of a logout that is spread over several requests remains valid. It
	// defaults to 5 minutes.
	LogoutStateLifetime time.Duration

	// ReplayStore records the ID of every request the identity provider acts on until the request expires, so
	// that a request which is presented again is refused. Defaults to a MemoryReplayStore of
	// DefaultMemoryReplayStoreCapacity, which is private to this process: identity providers that run as
	// several instances must set a store that they share.
	ReplayStore ReplayStore

	// defaultReplayStore is the *MemoryReplayStore that replayStore makes when ReplayStore is not set. It is
	// only read and written with sync/atomic, and is not an atomic.Pointer so that an IdentityProvider may
	// still be copied: a copy shares the store if it was already made, and otherwise makes its own.
	defaultReplayStore unsafe.Pointer
}

// ErrInsecureEndpoint is returned when the endpoint that a response would be sent to is not secure.
// See IdentityProvider.AllowInsecureServiceProviderEndpoints.
var ErrInsecureEndpoint = errors.New("the endpoint is not https")

// CheckServiceProviderEndpoint returns an error that wraps ErrInsecureEndpoint if the identity
// provider would refuse to send a response to location, which must be an absolute https URL or an
// http URL on a loopback host, unless AllowInsecureServiceProviderEndpoints allows any http URL.
// A ServiceProviderProvider can use it to refuse unusable metadata when it is registered.
func (idp *IdentityProvider) CheckServiceProviderEndpoint(location string) error {
	if isSecureEndpointLocation(location) {
		return nil
	}

	if idp.AllowInsecureServiceProviderEndpoints && endpointScheme(location) == "http" {
		return nil
	}

	return fmt.Errorf("cannot send a response to %q: %w", location, ErrInsecureEndpoint)
}

// CheckServiceProviderBackChannelEndpoint returns an error that wraps ErrInsecureEndpoint if the
// identity provider would refuse to send a back-channel message, such as a LogoutRequest over SOAP,
// to location, which must pass CheckServiceProviderEndpoint and be an absolute https URL, unless
// AllowInsecureServiceProviderEndpoints allows any http URL. Unlike CheckServiceProviderEndpoint, an
// http URL on a loopback host is not exempt: that exemption is for messages the browser delivers,
// whereas a back-channel message is sent by the identity provider itself, and a loopback URL would
// reach services on its own host. A ServiceProviderProvider can use it to refuse unusable metadata
// when it is registered.
func (idp *IdentityProvider) CheckServiceProviderBackChannelEndpoint(location string) error {
	if err := idp.CheckServiceProviderEndpoint(location); err != nil {
		return err
	}

	if idp.AllowInsecureServiceProviderEndpoints || endpointScheme(location) == "https" {
		return nil
	}

	return fmt.Errorf("cannot send a back-channel message to %q: %w", location, ErrInsecureEndpoint)
}

// checkServiceProviderBindingEndpoint checks location with CheckServiceProviderBackChannelEndpoint if
// binding is a back-channel binding, which the identity provider sends itself, and otherwise with
// CheckServiceProviderEndpoint.
func (idp *IdentityProvider) checkServiceProviderBindingEndpoint(binding, location string) error {
	if binding == SOAPBinding {
		return idp.CheckServiceProviderBackChannelEndpoint(location)
	}

	return idp.CheckServiceProviderEndpoint(location)
}

// endpointScheme returns the lower case scheme of location if it is an absolute URL with a host, or
// otherwise the empty string. The scheme is case-insensitive, RFC 3986 §3.1.
func endpointScheme(location string) string {
	u, err := url.Parse(location)
	if err != nil || u.Opaque != "" || u.Hostname() == "" {
		return ""
	}

	return strings.ToLower(u.Scheme)
}

// isSecureEndpointLocation returns true if location is an absolute https URL, or an http URL whose
// host is loopback. Browsers treat both as secure contexts, W3C Secure Contexts §3.2, and so does
// this identity provider.
func isSecureEndpointLocation(location string) bool {
	switch endpointScheme(location) {
	case "https":
		return true
	case "http":
		u, _ := url.Parse(location)
		return isLoopbackHost(u.Hostname())
	default:
		return false
	}
}

// isLoopbackHost returns true if host is localhost or a name within it, RFC 6761 §6.3, or a loopback
// IP address, which includes an IPv4 loopback address mapped to IPv6.
func isLoopbackHost(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}

	addr, err := netip.ParseAddr(host)

	return err == nil && addr.Unmap().IsLoopback()
}

// maxAuthnRequestAge returns MaxAuthnRequestAge, or MaxIssueDelay if it is not set.
func (idp *IdentityProvider) maxAuthnRequestAge() time.Duration {
	if idp.MaxAuthnRequestAge == 0 {
		return MaxIssueDelay
	}

	return idp.MaxAuthnRequestAge
}

// logger returns the Logger of the identity provider, or logger.DefaultLogger if it has none, so an
// identity provider embedded without a Logger doesn't panic when it logs a failure.
func (idp *IdentityProvider) logger() logger.Interface {
	if idp.Logger == nil {
		return logger.DefaultLogger
	}

	return idp.Logger
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

	formats := idp.nameIDProvider().NameIDFormats()

	nameIDFormats := make([]NameIDFormat, 0, len(formats))
	for _, format := range formats {
		nameIDFormats = append(nameIDFormats, NameIDFormat(format))
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
					NameIDFormats: nameIDFormats,
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

	if _, ok := idp.SessionProvider.(LogoutSessionProvider); ok && idp.SOAPLogoutURL.String() != "" {
		ed.IDPSSODescriptors[0].SingleLogoutServices = append(ed.IDPSSODescriptors[0].SingleLogoutServices, Endpoint{
			Binding:  SOAPBinding,
			Location: idp.SOAPLogoutURL.String(),
		})
	}

	return ed
}

// Handler returns an [http.Handler] that serves the metadata and SSO URLs, and the logout URL and SOAP logout URL
// if they are set. A URL with an empty path is served at "/". When LogoutURL and SOAPLogoutURL share a path, a
// POST with a text/xml body there goes to ServeSOAPLogout and anything else to ServeSLO.
func (idp *IdentityProvider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(handlerPath(idp.MetadataURL), idp.ServeMetadata)
	mux.HandleFunc(handlerPath(idp.SSOURL), idp.ServeSSO)

	slo, soap := idp.LogoutURL.String() != "", idp.SOAPLogoutURL.String() != ""

	switch {
	case slo && soap && handlerPath(idp.LogoutURL) == handlerPath(idp.SOAPLogoutURL):
		mux.HandleFunc(handlerPath(idp.LogoutURL), func(w http.ResponseWriter, r *http.Request) {
			if isSOAPRequest(r) {
				idp.ServeSOAPLogout(w, r)

				return
			}

			idp.ServeSLO(w, r)
		})
	default:
		if slo {
			mux.HandleFunc(handlerPath(idp.LogoutURL), idp.ServeSLO)
		}

		if soap {
			mux.HandleFunc(handlerPath(idp.SOAPLogoutURL), idp.ServeSOAPLogout)
		}
	}

	return mux
}

// handlerPath returns the path of u to serve it at on a mux, which is "/" when the path is empty.
func handlerPath(u url.URL) string {
	if u.Path == "" {
		return "/"
	}

	return u.Path
}

// isSOAPRequest reports whether r is a POST with a text/xml body, which a SOAP 1.1 request is, and which no
// front-channel binding sends.
func isSOAPRequest(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}

	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))

	return err == nil && mediaType == "text/xml"
}

// ServeMetadata is an [http.HandlerFunc] that serves the IDP metadata.
func (idp *IdentityProvider) ServeMetadata(w http.ResponseWriter, _ *http.Request) {
	buf, _ := xml.MarshalIndent(idp.Metadata(), "", "  ")

	w.Header().Set("Content-Type", "application/samlmetadata+xml")

	if _, err := w.Write(buf); err != nil {
		idp.logger().Printf("ERROR: %s", err)
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
// response is sent. Once the ACS endpoint has been resolved from the metadata of the
// service provider, a request with an unsupported version, that is too old or new, or that
// has the wrong destination is answered with a SAML error status instead.
//
// A request is used up once it is answered for a session: its ID is recorded in the ReplayStore until
// the request expires, and the same request presented again is answered with Requester and
// RequestDenied, without an assertion (SAMLSec §6.1.2). A request that a login form re-presents before
// then is not a replay. If the store fails the request is answered with Responder.
//
// If the assertion cannot be created or encrypted, a Responder error status is sent, or
// Requester with InvalidNameIDPolicy if the failure is ErrInvalidNameIDPolicy. A failure after
// the body has started is only logged.
//
//nolint:gocyclo // Complexity is inherent to the specification being implemented.
func (idp *IdentityProvider) ServeSSO(w http.ResponseWriter, r *http.Request) {
	req, err := NewIdpAuthnRequest(idp, r)
	if err != nil {
		idp.logger().Printf("failed to parse request: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

		return
	}

	if err := req.Validate(); err != nil {
		idp.logger().Printf("failed to validate request: %s", err)

		if top, second, ok := requestStatus(err); ok {
			req.writeErrorStatus(w, top, second)

			return
		}

		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

		return
	}

	session := req.getSession(w, r)
	if session == nil {
		return
	}

	req.Session = session

	// The request is used up here, once it is about to be answered for a session, and not when it is
	// validated: a SessionProvider that shows a login form re-presents the same request (SAMLSec §6.1.2).
	if err := req.CheckReplay(); err != nil {
		idp.logger().Printf("refused request: %s", err)

		top, second, _ := requestStatus(err)
		req.writeErrorStatus(w, top, second)

		return
	}

	assertionMaker := idp.AssertionMaker
	if assertionMaker == nil {
		assertionMaker = DefaultAssertionMaker{}
	}

	if err := assertionMaker.MakeAssertion(req, session); err != nil {
		idp.logger().Printf("failed to make assertion: %s", err)

		top, second, ok := requestStatus(err)
		if !ok {
			top, second = StatusResponder, ""
		}

		req.writeErrorStatus(w, top, second)

		return
	}

	if req.Request.Subject != nil {
		subjectEnforcer := idp.SubjectEnforcer
		if subjectEnforcer == nil {
			subjectEnforcer = DefaultSubjectEnforcer{}
		}

		if err := subjectEnforcer.EnforceSubject(req, session); err != nil {
			idp.logger().Printf("cannot match the request subject: %s", err)

			req.writeErrorStatus(w, StatusResponder, StatusAuthnFailed)

			return
		}
	}

	if req.Request.NameIDPolicy != nil {
		nameIDPolicyEnforcer := idp.NameIDPolicyEnforcer
		if nameIDPolicyEnforcer == nil {
			nameIDPolicyEnforcer = DefaultNameIDPolicyEnforcer{}
		}

		if err := nameIDPolicyEnforcer.EnforceNameIDPolicy(req, session); err != nil {
			idp.logger().Printf("cannot satisfy name id policy: %s", err)

			req.writeErrorStatus(w, StatusRequester, StatusInvalidNameIDPolicy)

			return
		}
	}

	if req.Request.RequestedAuthnContext != nil {
		authnContextEnforcer := idp.AuthnContextEnforcer
		if authnContextEnforcer == nil {
			authnContextEnforcer = DefaultAuthnContextEnforcer{}
		}

		if err := authnContextEnforcer.EnforceAuthnContext(req, session); err != nil {
			idp.logger().Printf("cannot satisfy requested authn context: %s", err)

			req.writeErrorStatus(w, StatusResponder, StatusNoAuthnContext)

			return
		}
	}

	if err := req.WriteResponse(w); err != nil {
		idp.logger().Printf("failed to write response: %s", err)

		// Once the body has started there is nothing sensible left to send.
		if !errors.Is(err, ErrResponseNotBuilt) {
			return
		}

		req.writeErrorStatus(w, StatusResponder, "")
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
			req.writeErrorStatus(w, StatusResponder, StatusNoPassive)
		}

		return session
	}

	if req.Request.ForceAuthn != nil && *req.Request.ForceAuthn {
		provider, ok := idp.SessionProvider.(ForceAuthnSessionProvider)
		if !ok {
			req.writeErrorStatus(w, StatusResponder, StatusAuthnFailed)
			return nil
		}

		return provider.GetForcedSession(w, r, req)
	}

	return idp.SessionProvider.GetSession(w, r, req)
}

// writeErrorStatus completes the HTTP request with an error Response carrying the given top-level and
// second-level status, or an internal server error if that Response can't be written.
func (req *IdpAuthnRequest) writeErrorStatus(w http.ResponseWriter, topLevelStatus, secondLevelStatus string) {
	if err := req.WriteErrorResponse(w, topLevelStatus, secondLevelStatus, ""); err != nil {
		req.IDP.logger().Printf("failed to write response: %s", err)
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
		// (this is probably because it drew a login form or something).
		return
	}

	req.Session = session

	var err error

	req.ServiceProviderMetadata, err = idp.serviceProvider(r, serviceProviderID)
	if err == os.ErrNotExist {
		idp.logger().Printf("cannot find service provider: %s", serviceProviderID)
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)

		return
	} else if err != nil {
		idp.logger().Printf("cannot find service provider %s: %v", serviceProviderID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

	// Find an ACS endpoint that we can use. Insecure endpoints are skipped, and if there is no other
	// the request fails here, before any assertion is made.
	if err := req.useDefaultACSEndpoint(); err != nil {
		idp.logger().Printf("cannot find assertion consumer service for %s: %v", serviceProviderID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

	assertionMaker := idp.AssertionMaker
	if assertionMaker == nil {
		assertionMaker = DefaultAssertionMaker{}
	}

	if err := assertionMaker.MakeAssertion(req, session); err != nil {
		idp.logger().Printf("failed to make assertion: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

	if err := req.WriteResponse(w); err != nil {
		idp.logger().Printf("failed to write response: %s", err)
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

	// Session is the session the assertion is for. ServeSSO and ServeIDPInitiated set it once the
	// SessionProvider has returned it.
	Session *Session

	// responseParticipant is the participant that the assertion in ResponseEl makes of the service
	// provider, which PublishResponse records each time the response is sent.
	responseParticipant *SessionParticipant

	// RedirectQuery is the raw query string of a signed HTTP-Redirect request, which is what the
	// signature covers. A SessionProvider which shows a login form and re-presents the request as a
	// POST must send this value in the RedirectQueryFormField field, otherwise the signature is lost
	// and a service provider that requires one is refused.
	RedirectQuery string
}

// RedirectQueryFormField is the POST form field which re-presents a signed HTTP-Redirect request. See
// IdpAuthnRequest.RedirectQuery.
const RedirectQueryFormField = "SAMLRedirectQuery"

// ResumeFormValues returns the hidden form fields a SessionProvider which shows a login form must
// include so that posting the form back to the SSO endpoint resumes this request.
func (req *IdpAuthnRequest) ResumeFormValues() url.Values {
	values := url.Values{
		"SAMLRequest": {base64.StdEncoding.EncodeToString(req.RequestBuffer)},
		"RelayState":  {req.RelayState},
	}

	if req.RedirectQuery != "" {
		values.Set(RedirectQueryFormField, req.RedirectQuery)
	}

	return values
}

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
	return readRedirectMessage(rawQuery, "SAMLRequest")
}

// readRedirectMessage returns the decoded message of the parameter and the RelayState from the query string of the
// HTTP-Redirect binding, and the query string itself if it carries a signature.
func readRedirectMessage(rawQuery, parameter string) (buf []byte, relayState, signedQuery string, err error) {
	// As with url.URL.Query, malformed pairs are dropped. Those can't affect a signed request, which
	// verifyRedirectSignature rejects if the query has a malformed key.
	values, _ := url.ParseQuery(rawQuery)

	compressedRequest, err := base64.StdEncoding.DecodeString(values.Get(parameter))
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

	//nolint:gosec // The request is size limited and passed XML round trip validation above.
	if err := xml.Unmarshal(req.RequestBuffer, &req.Request); err != nil {
		return err
	}

	if err := req.checkTrust(); err != nil {
		return err
	}

	// find the service provider.
	serviceProviderID := req.Request.Issuer.Value

	serviceProvider, err := req.IDP.serviceProvider(req.HTTPRequest, serviceProviderID)
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
		return fmt.Errorf("cannot find assertion consumer service: %w", err)
	}

	return req.checkRequestStage()
}

// checkTrust makes the checks on the identity of the request that are needed before the service
// provider can be looked up. Nothing in the request is acted on before these pass, and no response is
// sent for a request that fails them.
func (req *IdpAuthnRequest) checkTrust() error {
	if !isValidAuthnRequestID(req.Request.ID) {
		// The value is not included because this error is logged without authentication.
		return fmt.Errorf("invalid request ID")
	}

	if req.Request.Issuer == nil || req.Request.Issuer.Value == "" {
		return fmt.Errorf("request has no issuer")
	}

	return nil
}

// checkRequestStage makes the checks on the content of the request that are reported to the service
// provider as a SAML status. It must only run once the ACS endpoint has been resolved from metadata,
// and on the content that the signature covers if the request is signed. The error is a *statusError.
func (req *IdpAuthnRequest) checkRequestStage() error {
	if statusErr := versionStatus(req.Request.Version); statusErr != nil {
		return statusErr
	}

	maxAge := req.IDP.maxAuthnRequestAge()

	if req.Request.IssueInstant.Add(maxAge).Before(req.Now) {
		return &statusError{StatusRequester, StatusRequestDenied,
			fmt.Errorf("request expired at %s", req.Request.IssueInstant.Add(maxAge))}
	}

	if req.Request.IssueInstant.After(req.Now.Add(MaxClockSkew)) {
		return &statusError{StatusRequester, StatusRequestDenied,
			fmt.Errorf("request issued in the future at %s", req.Request.IssueInstant)}
	}

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
			return &statusError{StatusRequester, StatusRequestDenied,
				fmt.Errorf("expected destination to be %q, not %q", req.IDP.SSOURL.String(), req.Request.Destination)}
		}
	}

	if !req.supportedProtocolBinding() {
		return &statusError{StatusResponder, StatusUnsupportedBinding,
			fmt.Errorf("the response can't be sent with the requested binding %q", req.Request.ProtocolBinding)}
	}

	return nil
}

// listsACSLocation reports whether the metadata of the service provider lists an AssertionConsumerService at
// location, with any binding.
func (req *IdpAuthnRequest) listsACSLocation(location string) bool {
	for _, spssoDescriptor := range req.ServiceProviderMetadata.SPSSODescriptors {
		for _, endpoint := range spssoDescriptor.AssertionConsumerServices {
			if endpoint.Location == location {
				return true
			}
		}
	}

	return false
}

// supportedProtocolBinding reports whether the response can be sent with the ProtocolBinding of the
// request (SAMLCore §3.4.1): HTTP-POST, the only binding this identity provider sends responses with, or
// none, which leaves the binding to the endpoint.
func (req *IdpAuthnRequest) supportedProtocolBinding() bool {
	return req.Request.ProtocolBinding == "" || req.Request.ProtocolBinding == HTTPPostBinding
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
//
// An endpoint that the request names, by index or URL, is refused if it is insecure, as described by
// IdentityProvider.AllowInsecureServiceProviderEndpoints, rather than replaced by another endpoint.
// The response, whether an assertion or an error status, would be sent to that endpoint, so the
// request can only fail with an HTTP error.
//
// AssertionConsumerServiceIndex is mutually exclusive with AssertionConsumerServiceURL and
// ProtocolBinding (SAMLCore §3.4.1), so a request with both is refused. A request whose ProtocolBinding
// is another binding than HTTP-POST gets the default endpoint, which only receives the UnsupportedBinding
// status that checkRequestStage reports, as long as any AssertionConsumerServiceURL it names is listed in
// the metadata with some binding.
func (req *IdpAuthnRequest) getACSEndpoint() error {
	index, location := req.Request.AssertionConsumerServiceIndex, req.Request.AssertionConsumerServiceURL

	if index != "" && (location != "" || req.Request.ProtocolBinding != "") {
		return errors.New("the request has an AssertionConsumerServiceIndex with an AssertionConsumerServiceURL or ProtocolBinding, which are mutually exclusive")
	}

	if !req.supportedProtocolBinding() {
		if location != "" && !req.listsACSLocation(location) {
			return os.ErrNotExist
		}

		return req.useDefaultACSEndpoint()
	}

	if index != "" || location != "" {
		return req.useRequestedACSEndpoint(index, location)
	}

	// Some service providers, like the Microsoft Azure AD service provider, issue
	// assertion requests that don't specify an ACS url at all.
	return req.useDefaultACSEndpoint()
}

// useRequestedACSEndpoint selects the HTTP-POST endpoint that the request names by index or location.
func (req *IdpAuthnRequest) useRequestedACSEndpoint(index, location string) error {
	for _, match := range []func(endpoint IndexedEndpoint) bool{
		func(endpoint IndexedEndpoint) bool { return index != "" && strconv.Itoa(endpoint.Index) == index },
		func(endpoint IndexedEndpoint) bool { return location != "" && endpoint.Location == location },
	} {
		for _, spssoDescriptor := range req.ServiceProviderMetadata.SPSSODescriptors {
			for _, endpoint := range spssoDescriptor.AssertionConsumerServices {
				if endpoint.Binding == HTTPPostBinding && match(endpoint) {
					if err := req.IDP.CheckServiceProviderEndpoint(endpoint.Location); err != nil {
						return err
					}

					req.SPSSODescriptor, req.ACSEndpoint = &spssoDescriptor, &endpoint

					return nil
				}
			}
		}
	}

	return os.ErrNotExist
}

// useDefaultACSEndpoint selects the default HTTP-POST endpoint as defined by SAMLMetadata §2.2.3: the
// first with isDefault set to true, otherwise the first without isDefault set to false, otherwise
// the first.
//
// Insecure endpoints, as described by IdentityProvider.AllowInsecureServiceProviderEndpoints, are
// left out of that sequence, as endpoints of a binding that this identity provider doesn't support
// are. So a service provider which lists an http endpoint as the default, alongside an https one,
// receives the response at the https endpoint. If every HTTP-POST endpoint is insecure it returns an
// error which wraps ErrInsecureEndpoint.
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

	var insecure error

	for _, spssoDescriptor := range req.ServiceProviderMetadata.SPSSODescriptors {
		for _, endpoint := range spssoDescriptor.AssertionConsumerServices {
			if endpoint.Binding != HTTPPostBinding || preference(endpoint) <= best {
				continue
			}

			if err := req.IDP.CheckServiceProviderEndpoint(endpoint.Location); err != nil {
				insecure = err
				continue
			}

			best = preference(endpoint)
			req.SPSSODescriptor, req.ACSEndpoint = &spssoDescriptor, &endpoint
		}
	}

	if best == 0 {
		if insecure != nil {
			return insecure
		}

		return os.ErrNotExist
	}

	return nil
}

// DefaultSubjectEnforcer applies the strong matching rule of SAMLCore §3.3.4 to the request Subject.
type DefaultSubjectEnforcer struct {
}

// EnforceSubject implements SubjectEnforcer. The request must name the principal with a NameID, which
// must have the value of the asserted NameID. Its format, unless left unspecified, and any qualifier
// or SPProvidedID it has must also be the same. If the request has SubjectConfirmation elements, the
// assertion must have a bearer confirmation which meets the conditions of one of them.
func (DefaultSubjectEnforcer) EnforceSubject(req *IdpAuthnRequest, _ *Session) error {
	requested := req.Request.Subject.NameID
	if requested == nil || requested.Value == "" {
		return fmt.Errorf("the request Subject has no NameID")
	}

	if req.Assertion == nil || req.Assertion.Subject == nil || req.Assertion.Subject.NameID == nil {
		return fmt.Errorf("assertion has no NameID")
	}

	asserted := req.Assertion.Subject.NameID

	if asserted.Value != requested.Value {
		return fmt.Errorf("the assertion is for another principal than the request names")
	}

	if !isUnspecifiedNameIDFormat(requested.Format) && asserted.Format != requested.Format {
		return fmt.Errorf("the NameID format is %q and the request names %q", asserted.Format, requested.Format)
	}

	for _, qualifier := range []struct{ name, requested, asserted string }{
		{"NameQualifier", requested.NameQualifier, asserted.NameQualifier},
		{"SPNameQualifier", requested.SPNameQualifier, asserted.SPNameQualifier},
		{"SPProvidedID", requested.SPProvidedID, asserted.SPProvidedID},
	} {
		if qualifier.requested != "" && qualifier.requested != qualifier.asserted {
			return fmt.Errorf("the NameID %s is %q and the request names %q", qualifier.name, qualifier.asserted, qualifier.requested)
		}
	}

	if !confirmsSubject(req.Request.Subject.SubjectConfirmations, req.Assertion.Subject.SubjectConfirmations) {
		return fmt.Errorf("the assertion can't be confirmed in a manner the request accepts")
	}

	return nil
}

// confirmsSubject reports whether the assertion can be confirmed in the manner of one of the
// SubjectConfirmation elements of the request, as SAMLCore §3.3.4 requires. A request with none
// accepts any. Only a bearer confirmation is matched, because the data of the other methods, such as
// the key of holder-of-key, isn't parsed and so can't be compared.
func confirmsSubject(requested []SubjectConfirmation, asserted []SubjectConfirmation) bool {
	if len(requested) == 0 {
		return true
	}

	return slices.ContainsFunc(requested, func(want SubjectConfirmation) bool {
		return want.Method == bearerSubjectConfirmationMethod && slices.ContainsFunc(asserted, func(have SubjectConfirmation) bool {
			return have.Method == want.Method && sameNameID(want.NameID, have.NameID) && satisfiesConfirmationData(want.SubjectConfirmationData, have.SubjectConfirmationData)
		})
	})
}

// sameNameID reports whether a NameID the request gives, if any, is identical to the asserted one.
func sameNameID(requested, asserted *NameID) bool {
	return requested == nil || (asserted != nil && *requested == *asserted)
}

// satisfiesConfirmationData reports whether the asserted confirmation data meets every condition the
// requested data gives: the same recipient, request and IP address, and a validity period within the
// requested one. Addresses are compared by value, as the asserted one is written in canonical form.
func satisfiesConfirmationData(requested, asserted *SubjectConfirmationData) bool {
	if requested == nil {
		return true
	}

	if asserted == nil {
		return false
	}

	for _, value := range [][2]string{
		{requested.Recipient, asserted.Recipient},
		{requested.InResponseTo, asserted.InResponseTo},
	} {
		if value[0] != "" && value[0] != value[1] {
			return false
		}
	}

	if requested.Address != "" && !sameAddress(requested.Address, asserted.Address) {
		return false
	}

	if !requested.NotBefore.IsZero() && asserted.NotBefore.Before(requested.NotBefore) {
		return false
	}

	if !requested.NotOnOrAfter.IsZero() && (asserted.NotOnOrAfter.IsZero() || asserted.NotOnOrAfter.After(requested.NotOnOrAfter)) {
		return false
	}

	return true
}

// sameAddress reports whether two IP addresses are equal, however each is written. It returns false if
// either isn't an IP address.
func sameAddress(a, b string) bool {
	x, err := netip.ParseAddr(a)
	if err != nil {
		return false
	}

	y, err := netip.ParseAddr(b)

	return err == nil && x == y
}

// bearerSubjectConfirmationMethod is the only confirmation method of the assertions made here.
const bearerSubjectConfirmationMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer" //nolint:gosec // A SAML method identifier, not a credential.

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
		switch {
		case isUnspecifiedNameIDFormat(*policy.Format):
		case *policy.Format == encryptedNameIDFormat:
			return fmt.Errorf("the request requires an EncryptedID, which is not supported")
		case nameID.Format != *policy.Format:
			return fmt.Errorf("the NameID format is %q and the request requires %q", nameID.Format, *policy.Format)
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
//
//nolint:gocyclo // Complexity is inherent to the specification being implemented.
func (DefaultAssertionMaker) MakeAssertion(req *IdpAuthnRequest, session *Session) error {
	attributes := requestedNameAttributes(req.AttributeConsumingService(), session)

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

	// The policy may change its candidates, so it gets copies of the custom attributes of the session.
	for _, attribute := range session.CustomAttributes {
		attributes = append(attributes, attribute.clone())
	}

	if len(session.Groups) != 0 {
		groupMemberAttributeValues := make([]AttributeValue, 0, len(session.Groups))
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

	policy := req.IDP.AttributeReleasePolicy
	if policy == nil {
		policy = DefaultAttributeReleasePolicy{}
	}

	attributes, err := policy.ReleaseAttributes(req, session, attributes)
	if err != nil {
		return fmt.Errorf("cannot release attributes: %w", err)
	}

	// allow for some clock skew in the validity period. This uses our own clock, because the
	// request and therefore its IssueInstant are not authenticated.
	notBefore := req.Now.Add(-1 * MaxClockSkew)
	notOnOrAfterAfter := req.Now.Add(MaxIssueDelay)

	// The ID is taken first so that a transient NameID doesn't change it.
	assertionID := fmt.Sprintf("id-%x", randomBytes(20))

	nameID, err := req.resolveNameID(session)
	if err != nil {
		return fmt.Errorf("cannot issue a NameID: %w", err)
	}

	address := clientAddress(req.HTTPRequest, session)

	req.Assertion = &Assertion{
		ID:           assertionID,
		IssueInstant: TimeNow(),
		Version:      "2.0",
		Issuer: Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  req.IDP.Metadata().EntityID,
		},
		Subject: &Subject{
			NameID: nameID,
			SubjectConfirmations: []SubjectConfirmation{
				{
					Method: bearerSubjectConfirmationMethod,
					SubjectConfirmationData: &SubjectConfirmationData{
						Address:      address,
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
					Address: address,
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

// requestedNameAttributes returns the attributes of the user which service requests under a name of
// its own choosing, such as "email", rather than under the name that DefaultAssertionMaker states
// them with. Such a name is only recognised when its NameFormat is basic or unspecified, which leave
// its interpretation to the identity provider (SAMLCore §8.2.1 and §8.2.3). It is compared without
// regard to case or punctuation, so "Email", "email_address" and "EmailAddress" are all the email
// address of the user. Each attribute has the FriendlyName, Name and NameFormat that service gives
// it, and is omitted if the session has no value for it.
func requestedNameAttributes(service *AttributeConsumingService, session *Session) []Attribute {
	attributes := []Attribute{}
	if service == nil {
		return attributes
	}

	for _, requested := range service.RequestedAttributes {
		switch requested.NameFormat {
		case "", basicAttrNameFormat, unspecifiedAttrNameFormat:
		default:
			continue
		}

		var value string

		switch strings.ToLower(nonAlphanumeric.ReplaceAllString(requested.Name, "")) {
		case "email", "emailaddress":
			value = session.UserEmail
		case "name", "fullname", "cn", "commonname":
			value = session.UserCommonName
		case "givenname", "firstname":
			value = session.UserGivenName
		case "surname", "lastname", "familyname":
			value = session.UserSurname
		case "uid", "user", "userid":
			value = session.UserName
		}

		if value == "" {
			continue
		}

		if slices.ContainsFunc(attributes, func(attribute Attribute) bool {
			return attribute.Name == requested.Name && attribute.NameFormat == requested.NameFormat
		}) {
			continue
		}

		attributes = append(attributes, Attribute{
			FriendlyName: requested.FriendlyName,
			Name:         requested.Name,
			NameFormat:   requested.NameFormat,
			Values:       []AttributeValue{{Type: "xs:string", Value: value}},
		})
	}

	return attributes
}

// nonAlphanumeric matches the characters which are ignored in a name recognised by
// requestedNameAttributes.
var nonAlphanumeric = regexp.MustCompile("[^A-Za-z0-9]+")

// basicAttrNameFormat and unspecifiedAttrNameFormat are the attribute name formats of SAMLCore §8.2.3
// and §8.2.1.
const (
	basicAttrNameFormat       = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
	unspecifiedAttrNameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
)

// AttributeConsumingService returns the AttributeConsumingService of req.SPSSODescriptor which
// describes the attributes the service provider wants, or nil if there is none. The result is a copy
// of the service in the metadata, but its RequestedAttributes are shared and must not be modified.
//
// If the request has an AttributeConsumingServiceIndex it names the service, as SAMLCore §3.4.1
// describes. An index that doesn't name one of the services selects none, rather than the default:
// the identity provider "MUST have a trusted means to map the index value", and the attributes of
// another service were not asked for. The request still succeeds, as attributes are optional.
//
// Otherwise the default service is selected by SAMLMeta §2.4.4, as changed by errata E87: the first
// with isDefault set to true, otherwise the first without isDefault set to false, otherwise the first.
func (req *IdpAuthnRequest) AttributeConsumingService() *AttributeConsumingService {
	if req.SPSSODescriptor == nil {
		return nil
	}

	services := req.SPSSODescriptor.AttributeConsumingServices

	if index := req.Request.AttributeConsumingServiceIndex; index != "" {
		// The index has the xs:unsignedShort type.
		n, err := strconv.ParseUint(index, 10, 16)
		if err != nil {
			return nil
		}

		for _, service := range services {
			if service.Index == int(n) {
				return &service
			}
		}

		return nil
	}

	preference := func(service AttributeConsumingService) int {
		switch {
		case service.IsDefault == nil:
			return 2
		case *service.IsDefault:
			return 3
		default:
			return 1
		}
	}

	var selected *AttributeConsumingService
	for _, service := range services {
		if selected == nil || preference(service) > preference(*selected) {
			selected = &service
		}
	}

	return selected
}

// DefaultAttributeReleasePolicy releases only the attributes that the service provider requests in
// the RequestedAttribute elements of its AttributeConsumingService, as selected by
// IdpAuthnRequest.AttributeConsumingService. If there is no such service, no attributes are released,
// and the assertion only identifies the principal by its NameID.
//
// A candidate is released if a RequestedAttribute has the same Name and a compatible NameFormat. The
// Name must be identical, as SAMLCore §1.3.1 requires an exact binary comparison. FriendlyName is never
// used, because SAMLCore §2.7.3.1 says it "MUST NOT be used as a basis for formally identifying SAML
// attributes". A missing NameFormat is urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified, as
// SAMLCore §2.7.3.1 and errata E89 say, and the unspecified format is compatible with any other,
// since it leaves the interpretation of the name to the implementation (SAMLCore §8.2.1).
//
// If the matching RequestedAttribute elements list values, only those values of the candidate are
// released, as SAMLMeta §2.4.4.2 says that only matching values are relevant to the service, and the
// candidate is withheld if it has none of them. Values are compared exactly, and a NameID value by its
// content and qualifiers.
type DefaultAttributeReleasePolicy struct {
}

// ReleaseAttributes implements AttributeReleasePolicy.
func (DefaultAttributeReleasePolicy) ReleaseAttributes(req *IdpAuthnRequest, _ *Session, candidates []Attribute) ([]Attribute, error) {
	service := req.AttributeConsumingService()
	if service == nil {
		// The index is not included because the request may not be authenticated.
		if req.Request.AttributeConsumingServiceIndex != "" && req.IDP != nil {
			req.IDP.logger().Printf("releasing no attributes: the AttributeConsumingServiceIndex of the request names no service")
		}

		return nil, nil
	}

	var released []Attribute

	for _, candidate := range candidates {
		if attribute, ok := releaseRequestedAttribute(service.RequestedAttributes, candidate); ok {
			released = append(released, attribute)
		}
	}

	return released, nil
}

// releaseRequestedAttribute returns the part of candidate which requested asks for, and false if it
// asks for none of it.
func releaseRequestedAttribute(requested []RequestedAttribute, candidate Attribute) (Attribute, bool) {
	matched, anyValue := false, false

	var values []AttributeValue

	for _, r := range requested {
		if r.Name != candidate.Name || !compatibleAttrNameFormats(r.NameFormat, candidate.NameFormat) {
			continue
		}

		matched = true

		if len(r.Values) == 0 {
			anyValue = true
		}

		values = append(values, r.Values...)
	}

	if !matched {
		return Attribute{}, false
	}

	if anyValue {
		return candidate, true
	}

	attribute := candidate

	attribute.Values = nil
	for _, value := range candidate.Values {
		if slices.ContainsFunc(values, value.equal) {
			attribute.Values = append(attribute.Values, value)
		}
	}

	return attribute, len(attribute.Values) != 0
}

// equal returns true if a and b are the same value. A NameID value is compared by its content and
// qualifiers, since the text of its AttributeValue is only the whitespace around the NameID.
func (a AttributeValue) equal(b AttributeValue) bool {
	if a.NameID != nil || b.NameID != nil {
		return a.NameID != nil && b.NameID != nil && *a.NameID == *b.NameID
	}

	return a.Value == b.Value
}

// clone returns a copy of a which shares none of its values.
func (a Attribute) clone() Attribute {
	a.Values = slices.Clone(a.Values)
	for i, value := range a.Values {
		if value.NameID != nil {
			nameID := *value.NameID
			a.Values[i].NameID = &nameID
		}
	}

	return a
}

// compatibleAttrNameFormats returns true if attributes with the NameFormats a and b can have the same
// name. A missing NameFormat is unspecified, which is compatible with any other.
func compatibleAttrNameFormats(a, b string) bool {
	if a == "" || a == unspecifiedAttrNameFormat || b == "" || b == unspecifiedAttrNameFormat {
		return true
	}

	return a == b
}

// clientAddress returns the IP address of the user for an assertion, which SAMLCore §2.4.1.2 and
// §2.7.2.1 require to have no port. It is the ClientAddress of the session, or else the host of the
// RemoteAddr of the HTTP request. It returns "" if that isn't an IP address.
func clientAddress(r *http.Request, session *Session) string {
	address := session.ClientAddress
	if address == "" {
		address = r.RemoteAddr
		if host, _, err := net.SplitHostPort(address); err == nil {
			address = host
		}
	}

	ip, err := netip.ParseAddr(address)
	if err != nil {
		return ""
	}

	return ip.WithZone("").String()
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

	encryptor, err := req.assertionEncrypter()
	if err != nil {
		return err
	}

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
//
// It returns an error which wraps ErrInsecureEndpoint, before any response is made, if ACSEndpoint is
// insecure, as described by IdentityProvider.AllowInsecureServiceProviderEndpoints. That only
// happens if ACSEndpoint was set other than by Validate or ServeIDPInitiated, which never select one.
func (req *IdpAuthnRequest) PostBinding() (IdpAuthnRequestForm, error) {
	var form IdpAuthnRequestForm

	if req.ACSEndpoint != nil {
		if err := req.IDP.CheckServiceProviderEndpoint(req.ACSEndpoint.Location); err != nil {
			req.ResponseEl, req.responseParticipant = nil, nil
			return form, err
		}
	}

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

var defaultLogoutRequestFormTemplate = template.Must(template.New("saml-logout-request-form").Parse(`<html>` +
	`<form method="post" action="{{.URL}}" id="SAMLRequestForm">` +
	`<input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}" />` +
	`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
	`<input id="SAMLSubmitButton" type="submit" value="Continue" />` +
	`</form>` +
	`<script>document.getElementById('SAMLSubmitButton').style.visibility='hidden';</script>` +
	`<script>document.getElementById('SAMLRequestForm').submit();</script>` +
	`</html>`))

// ErrResponseNotBuilt is wrapped by an error of IdpAuthnRequest.WriteResponse that happened before
// anything was written, so the request can still be answered, such as with WriteErrorResponse. Any other
// error of WriteResponse may have happened after the body started.
var ErrResponseNotBuilt = errors.New("the response could not be built")

// WriteResponse writes the `Response` to the [http.ResponseWriter]. If
// `Response` is not already set, it calls MakeResponse to produce it. The response is written by
// PublishResponse, so if it carries an assertion nothing is written once a logout of the session has
// begun.
func (req *IdpAuthnRequest) WriteResponse(w http.ResponseWriter) error {
	form, err := req.PostBinding()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrResponseNotBuilt, err)
	}

	tmpl := req.IDP.ResponseFormTemplate
	if tmpl == nil {
		tmpl = defaultResponseFormTemplate
	}

	buf := bytes.NewBuffer(nil)
	if err := tmpl.Execute(buf, form); err != nil {
		return fmt.Errorf("%w: %w", ErrResponseNotBuilt, err)
	}

	published := false

	err = req.PublishResponse(func() error {
		published = true

		setNoCacheHeaders(w)

		_, err := io.Copy(w, buf)

		return err
	})

	// The participant couldn't be recorded, so nothing was written.
	if err != nil && !published {
		return fmt.Errorf("%w: %w", ErrResponseNotBuilt, err)
	}

	return err
}

// setNoCacheHeaders stops a browser or proxy keeping a page which carries a SAML message, as
// SAMLBind §3.5.5.1 and §3.4.5.1 ask.
func setNoCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Pragma", "no-cache")
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

	// cleanup whitespace and re-encode a PEM.
	certStr = regexp.MustCompile(`\s+`).ReplaceAllString(certStr, "")

	certBytes, err := base64.StdEncoding.DecodeString(certStr)
	if err != nil {
		return nil, fmt.Errorf("cannot decode certificate base64: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse certificate: %v", err)
	}

	var enforcer EncryptionCertificateEnforcer = DefaultEncryptionCertificateEnforcer{}
	if req.IDP != nil && req.IDP.EncryptionCertificateEnforcer != nil {
		enforcer = req.IDP.EncryptionCertificateEnforcer
	}

	if err := enforcer.EnforceEncryptionCertificate(req, cert); err != nil {
		entityID := ""
		if req.ServiceProviderMetadata != nil {
			entityID = req.ServiceProviderMetadata.EntityID
		}

		return nil, fmt.Errorf("refusing the encryption certificate of service provider %q: %w", entityID, err)
	}

	return cert, nil
}

// oidExtensionKeyUsage is the identifier of the KeyUsage extension, from RFC 5280 §4.2.1.3.
var oidExtensionKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}

// hasKeyUsageExtension returns true if the certificate has a KeyUsage extension, which can't be told
// from a KeyUsage field with no bits set.
func hasKeyUsageExtension(cert *x509.Certificate) bool {
	return slices.ContainsFunc(cert.Extensions, func(ext pkix.Extension) bool { return ext.Id.Equal(oidExtensionKeyUsage) })
}

// DefaultMinimumRSAKeySize is the shortest RSA key, in bits, that DefaultEncryptionCertificateEnforcer
// accepts unless its MinimumRSAKeySize is set. It follows NIST SP 800-131A, which disallows RSA keys
// shorter than 2048 bits for key transport.
const DefaultMinimumRSAKeySize = 2048

// DefaultEncryptionCertificateEnforcer is the default EncryptionCertificateEnforcer. With no options
// set it refuses a certificate which is expired or not yet valid at the time of the request, allowing
// MaxClockSkew either way, whose RSA key is shorter than DefaultMinimumRSAKeySize, or which has a
// KeyUsage extension that doesn't assert keyEncipherment. A certificate without a KeyUsage extension
// is not restricted, as RFC 5280 §4.2.1.3 describes. A key that is not RSA is refused when the
// assertion is encrypted, whatever the enforcer decides, because only RSA key transport is supported.
//
// These checks are a local security policy, not a requirement of SAML. The SAML V2.0 Metadata
// Interoperability Profile (sstc-metadata-iop §2.5.1) treats the certificate in metadata as merely a
// matter of notational convenience to communicate a key, which may be expired, not yet valid or carry
// any usage flags, although it recommends that certificates be unexpired, and §2.6.1 forbids a
// consumer following that profile to apply criteria beyond the key itself. §2.6 does allow a consumer
// to constrain interoperability by the default policies it applies, and this is one. The options exist
// to interoperate with service providers which follow that profile: each relaxes one check only, so
// that allowing an expired certificate does not also allow a weak key.
type DefaultEncryptionCertificateEnforcer struct {
	// IgnoreValidityPeriod accepts a certificate which is expired or not yet valid, as the Metadata
	// Interoperability Profile expects. Such a certificate is common where metadata is managed by
	// key rather than by certificate.
	IgnoreValidityPeriod bool

	// IgnoreKeyUsage accepts a certificate whose KeyUsage extension doesn't assert keyEncipherment.
	IgnoreKeyUsage bool

	// MinimumRSAKeySize is the shortest RSA key accepted, in bits. Defaults to
	// DefaultMinimumRSAKeySize. It may be set lower to accept legacy keys, or higher to be stricter.
	MinimumRSAKeySize int
}

// EnforceEncryptionCertificate implements EncryptionCertificateEnforcer.
func (e DefaultEncryptionCertificateEnforcer) EnforceEncryptionCertificate(req *IdpAuthnRequest, cert *x509.Certificate) error {
	if !e.IgnoreValidityPeriod {
		if cert.NotBefore.After(req.Now.Add(MaxClockSkew)) {
			return fmt.Errorf("the certificate is not yet valid: it is valid from %s", cert.NotBefore.UTC().Format(time.RFC3339))
		}

		if cert.NotAfter.Before(req.Now.Add(-MaxClockSkew)) {
			return fmt.Errorf("the certificate expired at %s", cert.NotAfter.UTC().Format(time.RFC3339))
		}
	}

	if key, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		minimum := e.MinimumRSAKeySize
		if minimum <= 0 {
			minimum = DefaultMinimumRSAKeySize
		}

		if size := key.N.BitLen(); size < minimum {
			return fmt.Errorf("the RSA key is %d-bit, shorter than the minimum of %d bits", size, minimum)
		}
	}

	// RFC 5280 §4.2.1.3: when the extension is present, keyEncipherment is asserted when the key is
	// used to encrypt keys, which is how RSA is used to encrypt an assertion.
	if !e.IgnoreKeyUsage && hasKeyUsageExtension(cert) && cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		return fmt.Errorf("the certificate has a KeyUsage extension which does not assert keyEncipherment")
	}

	return nil
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
// This is a hack -- it first serializes the element, then uses [xml.Unmarshal].
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

	// The participant is recorded each time the response is sent, by PublishResponse, so that a response isn't sent
	// once a logout of the session has begun.
	participant, err := req.sessionParticipant()
	if err != nil {
		return err
	}

	req.ResponseEl, req.responseParticipant = responseEl, participant

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
	req.ResponseEl, req.responseParticipant = nil, nil

	if req.ACSEndpoint == nil {
		return fmt.Errorf("cannot make an error response without a validated assertion consumer service")
	}

	if err := req.IDP.CheckServiceProviderEndpoint(req.ACSEndpoint.Location); err != nil {
		return err
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
