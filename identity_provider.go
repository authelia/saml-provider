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
	"unicode"
	"unicode/utf8"
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

// ECPSessionProvider is an optional interface of a SessionProvider, which is required to serve the Enhanced Client
// or Proxy profile with ServeECP. That profile has no browser to show a login page to, and leaves how the client
// authenticates the principal to the identity provider (ECP v2.0 §2.3.5), so GetSession is never used for it.
type ECPSessionProvider interface {
	// GetECPSession authenticates the principal from r, which is the SOAP request of the client, and returns the
	// session, or completes the HTTP request and returns nil. The usual means is HTTP Basic credentials, for which
	// the response to a request without valid ones is a 401 with a WWW-Authenticate header, which the client
	// answers by sending the request again (ECP v2.0 §2.3.4). A session cookie that the client kept from an
	// earlier exchange may also be relied on, unless req.Request.ForceAuthn is true, when the principal must be
	// authenticated freshly from the credentials in r.
	//
	// To refuse the principal with a SAML status that the service provider receives, such as for a disabled
	// account, call req.WriteErrorResponse with StatusResponder and StatusAuthnFailed and return nil.
	//
	// It is called once req is valid, so req.ServiceProviderMetadata is the service provider that the assertion is
	// for. The client is not the service provider and r isn't authenticated by req, even when req is signed: the
	// credentials in r are the only evidence of who the principal is. The assertion is returned to the client in
	// the response to r, so credentials must only be accepted over a channel that protects them, such as TLS.
	// The body of r has been read.
	GetECPSession(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session
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

// AuthnContextEnforcer is an interface used by IdentityProvider to decide whether the authentication of
// a session satisfies a RequestedAuthnContext, for single sign-on and for an AuthnQuery alike. The
// default implementation is DefaultAuthnContextEnforcer, which is used if no AuthnContextEnforcer is
// specified.
type AuthnContextEnforcer interface {
	// SatisfiesAuthnContext returns an error if the authentication of session, whose class is
	// session.AuthnContextClassRef or PasswordProtectedTransport when that is empty, doesn't satisfy
	// requested, which is not nil.
	//
	// ServeSSO calls it once for each AuthnStatement of the assertion, with a copy of the session whose
	// AuthnContextClassRef is the class that the statement asserts, so that a custom AssertionMaker is
	// held to what it asserts. The service provider receives a NoAuthnContext status, not the error.
	// ServeAuthnQuery calls it for each session of the principal, and leaves out those that return an
	// error.
	SatisfiesAuthnContext(requested *RequestedAuthnContext, session *Session) error
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
	//
	// It is also asked before an assertion is encrypted in answer to a request of the assertion query
	// and request protocol. There is then no AuthnRequest, and req holds only the IDP, HTTPRequest,
	// ServiceProviderMetadata, SPSSODescriptor and Now. A refusal there is a Responder status.
	//
	// It is also asked before the NameID of a LogoutRequest is encrypted to a service provider that
	// was sent an EncryptedID. There is then no AuthnRequest, and req only has its IDP,
	// ServiceProviderMetadata, SPSSODescriptor and Now, and as HTTPRequest a request of the identity
	// provider's own making to its logout URL. A refusal skips that service provider.
	EnforceEncryptionCertificate(req *IdpAuthnRequest, cert *x509.Certificate) error
}

// ElementEncryptionPolicy is an interface used by IdentityProvider to decide which parts of an assertion are
// encrypted on their own, as an EncryptedID or an EncryptedAttribute, which allows the decision to differ for each
// service provider. The default implementation is DefaultElementEncryptionPolicy, which is used if no
// ElementEncryptionPolicy is specified.
//
// It applies to the assertion of any AssertionMaker, when MakeAssertionEl encrypts and signs it. The parts are
// encrypted to the key that the assertion is encrypted to, with the same algorithms, so if the service provider
// has no encryption key and a part must be encrypted, no assertion is sent. The whole assertion is still
// encrypted afterwards.
type ElementEncryptionPolicy interface {
	// EncryptNameID reports whether the NameID of req.Assertion is sent as an EncryptedID although the request
	// didn't ask for the encrypted format, which SAMLCore §3.4.1.1 allows the policies of an identity provider
	// to require. It isn't asked when the request did.
	EncryptNameID(req *IdpAuthnRequest) bool

	// EncryptAttribute reports whether attribute, which is one of req.Assertion, is sent as an
	// EncryptedAttribute (SAMLCore §2.7.3.2).
	EncryptAttribute(req *IdpAuthnRequest, attribute Attribute) bool
}

// DefaultElementEncryptionPolicy is the default ElementEncryptionPolicy. With no options set it encrypts no part
// of an assertion on its own, so an EncryptedID is only sent to a service provider that requests one.
type DefaultElementEncryptionPolicy struct {
	// NameIDServiceProviders lists the entity IDs of the service providers that are always sent an EncryptedID.
	NameIDServiceProviders []string

	// AttributeServiceProviders lists the entity IDs of the service providers that are sent every attribute as
	// an EncryptedAttribute.
	AttributeServiceProviders []string
}

// EncryptNameID implements ElementEncryptionPolicy.
func (p DefaultElementEncryptionPolicy) EncryptNameID(req *IdpAuthnRequest) bool {
	return req.ServiceProviderMetadata != nil && slices.Contains(p.NameIDServiceProviders, req.ServiceProviderMetadata.EntityID)
}

// EncryptAttribute implements ElementEncryptionPolicy.
func (p DefaultElementEncryptionPolicy) EncryptAttribute(req *IdpAuthnRequest, _ Attribute) bool {
	return req.ServiceProviderMetadata != nil && slices.Contains(p.AttributeServiceProviders, req.ServiceProviderMetadata.EntityID)
}

// AttributeReleaseRequest describes what an AttributeReleasePolicy is asked to release attributes for:
// an assertion of single sign-on, or the answer to an AttributeQuery.
type AttributeReleaseRequest struct {
	// HTTPRequest is the request being served. For an AttributeQuery it comes from the server of the
	// service provider, not the browser of the principal.
	HTTPRequest *http.Request

	// ServiceProviderMetadata is the metadata of the service provider that receives the attributes.
	ServiceProviderMetadata *EntityDescriptor

	// Ceiling is the AttributeConsumingService of the metadata of the service provider that describes
	// the attributes it wants, or nil if there is none. For single sign-on it is the service that
	// IdpAuthnRequest.AttributeConsumingService returns. For an AttributeQuery it is the default
	// service, which single sign-on uses for a request without an index, so that a query is never
	// answered with more than single sign-on would state.
	Ceiling *AttributeConsumingService

	// Requested lists the attributes that an AttributeQuery names (SAMLCore §3.3.2.3). It is empty for
	// single sign-on and for a query that names none, which asks for every attribute that policy
	// allows. The candidates have already been narrowed to these, and what the policy returns is
	// narrowed to them again.
	Requested []Attribute

	// AuthnRequest is the request, for single sign-on, and nil for an AttributeQuery.
	AuthnRequest *IdpAuthnRequest

	// Query is the query, for an AttributeQuery, and nil for single sign-on.
	Query *IdpQueryRequest
}

// AttributeReleasePolicy is an interface used by DefaultAssertionMaker and ServeAttributeQuery to decide
// which attributes of the principal are stated to a service provider, which allows the decision to
// differ for each service provider. The default implementation is DefaultAttributeReleasePolicy, which
// is used if no AttributeReleasePolicy is specified.
type AttributeReleasePolicy interface {
	// ReleaseAttributes returns the attributes of candidates that are stated to the service provider of
	// req. candidates holds every attribute that can be stated about the principal of session, and may
	// be modified or returned. req.Ceiling is the service that describes the attributes the service
	// provider wants, if any.
	//
	// If no attributes are returned the assertion has no AttributeStatement, because SAMLCore
	// §2.7.3 requires every AttributeStatement to hold at least one attribute, and an AttributeQuery is
	// answered with no assertion. If an error is returned no assertion is made, and the request
	// receives a Responder status.
	ReleaseAttributes(req AttributeReleaseRequest, session *Session, candidates []Attribute) ([]Attribute, error)
}

// DefaultAuthnContextEnforcer applies the comparison rules of SAMLCore §3.3.2.2.1 to the class
// reference of the authentication of a session.
type DefaultAuthnContextEnforcer struct {
	// Strength ranks authentication context classes, where a greater value is stronger. It is
	// needed for the minimum, maximum and better comparisons, as the specification leaves the
	// ordering to the identity provider. Classes may share a value. A class that isn't listed is
	// only equal to itself.
	Strength map[string]int
}

// SatisfiesAuthnContext implements AuthnContextEnforcer.
// Declaration references are always refused, because the assertions made here only state a class.
// With minimum and maximum the class of the session must be at least as strong as, or no stronger
// than, one of the requested classes, and with better it must be stronger than one of them.
func (e DefaultAuthnContextEnforcer) SatisfiesAuthnContext(requested *RequestedAuthnContext, session *Session) error {
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

	asserted := sessionAuthnContextClassRef(session)
	if !slices.ContainsFunc(requested.AuthnContextClassRefs, func(class string) bool { return satisfies(asserted, class) }) {
		return fmt.Errorf("the class %q doesn't satisfy the %q comparison", asserted, requested.Comparison)
	}

	return nil
}

// sessionAuthnContextClassRef returns the authentication context class of session, which is
// PasswordProtectedTransport when it sets none.
func sessionAuthnContextClassRef(session *Session) string {
	return cmp.Or(session.AuthnContextClassRef, defaultAuthnContextClassRef)
}

// satisfiesAuthnContext returns an error unless every AuthnStatement of assertion satisfies requested,
// by asking the AuthnContextEnforcer about a copy of session with the class that the statement asserts.
func (idp *IdentityProvider) satisfiesAuthnContext(requested *RequestedAuthnContext, assertion *Assertion, session *Session) error {
	if assertion == nil || len(assertion.AuthnStatements) == 0 {
		return fmt.Errorf("assertion has no AuthnStatement")
	}

	enforcer := idp.authnContextEnforcer()

	for _, statement := range assertion.AuthnStatements {
		if statement.AuthnContext.AuthnContextClassRef == nil {
			return fmt.Errorf("an AuthnStatement has no AuthnContextClassRef")
		}

		asserted := *session
		asserted.AuthnContextClassRef = statement.AuthnContext.AuthnContextClassRef.Value

		if err := enforcer.SatisfiesAuthnContext(requested, &asserted); err != nil {
			return err
		}
	}

	return nil
}

// authnContextEnforcer returns the AuthnContextEnforcer of idp, or DefaultAuthnContextEnforcer if there
// is none.
func (idp *IdentityProvider) authnContextEnforcer() AuthnContextEnforcer {
	if idp.AuthnContextEnforcer != nil {
		return idp.AuthnContextEnforcer
	}

	return DefaultAuthnContextEnforcer{}
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

	// RolloverCertificates are further signing certificates which the metadata publishes after Certificate, each in
	// its own KeyDescriptor, but which are never used to sign. They allow a signing key to be changed without
	// downtime: publish the next certificate here until every service provider has refreshed the metadata, then
	// make it Certificate and keep the previous one here until responses signed with it can no longer be in flight.
	// The Metadata Interoperability Profile §2.5 describes this:
	//
	//	Signing or transport authentication keys intended for future use MAY be included as a means
	//	of preparing for migration from an older to a newer key (i.e., key rollover). Once an
	//	allowable period of time has elapsed (with this period dependent on deployment-specific
	//	policies), the older key can be removed, completing the change. Expired keys (those not in
	//	use anymore by an entity, for reasons other than compromise) SHOULD be removed once the
	//	rollover process to a new key (or keys) has been completed.
	//
	// A compromised key MUST be removed at once instead. The certificates may have any key type that can sign, so
	// an RSA key can be replaced with an ECDSA key. They are only published for signing, never for encryption. A
	// certificate that is nil, equal to Certificate or repeated is left out. Intermediates are not published for
	// them, as they are only sent with a signature and the profile permits a single certificate in each
	// KeyDescriptor.
	RolloverCertificates []*x509.Certificate

	// MaxAuthnRequestAge is the oldest AuthnRequest that will be accepted, which must allow for a
	// SessionProvider that re-presents the request after a login form. Defaults to MaxIssueDelay. The ID
	// of a request that was answered stays in the ReplayStore for this long after its IssueInstant, and
	// MaxClockSkew longer.
	//
	// It is independent of AssertionLifetime: MaxAuthnRequestAge bounds the time from the issue of the request to
	// the response, and AssertionLifetime the time from the response to its delivery at the service provider. An
	// assertion always takes its validity from the clock of the identity provider when it is made, so an old
	// request does not shorten it.
	MaxAuthnRequestAge time.Duration

	// AssertionLifetime is how long after it is made that an assertion states it is valid, in both the
	// NotOnOrAfter of its Conditions and the NotOnOrAfter of its bearer SubjectConfirmationData. Defaults to
	// MaxIssueDelay, and must not be negative. NotBefore is MaxClockSkew before the assertion is made, to allow for
	// a service provider whose clock is behind.
	//
	// SAMLProf §4.1.4.2 requires the bearer SubjectConfirmationData to contain "a NotOnOrAfter attribute that limits
	// the window during which the assertion can be delivered", and SAMLSecurity §6.4.1 recommends that the
	// NotBefore and NotOnOrAfter of SSO assertions "SHOULD have the shortest possible validity period consistent
	// with successful communication of the assertion from Identity Provider to Service Provider site", which "is
	// typically on the order of a few minutes". Both are set from this one value because a Web SSO assertion is
	// only used when it is delivered, and SAMLProf §4.1.4.3 requires the service provider to check both. A service
	// provider may also refuse an assertion whose IssueInstant is older than its own limit, as this package's
	// ServiceProvider does with MaxIssueDelay, so a longer lifetime may not be honoured.
	//
	// It is only used by DefaultAssertionMaker, for the assertions of single sign-on. An assertion that answers an
	// AttributeQuery or AuthnQuery is not delivered by the browser, and is valid for MaxIssueDelay.
	AssertionLifetime time.Duration

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
	// with LogoutURL, as Handler tells the two apart by the Content-Type, and with the other services on the
	// SOAP binding, which Handler tells apart by the message in the envelope.
	SOAPLogoutURL url.URL

	// ECPURL is the single sign-on service on the SOAP binding, which ServeECP handles for the Enhanced Client or
	// Proxy profile. When it is set and the SessionProvider implements ECPSessionProvider, the metadata lists it.
	// It may share its path with SSOURL, as Handler tells the two apart by the Content-Type, and with the other
	// services on the SOAP binding, which Handler tells apart by the message in the envelope.
	ECPURL url.URL

	// ManageNameIDURL is the name identifier management service on the HTTP-Redirect and HTTP-POST bindings,
	// which ServeManageNameID handles. When it is set and the NameIDProvider implements
	// NameIDManagementProvider, the metadata lists it.
	ManageNameIDURL url.URL

	// SOAPManageNameIDURL is the name identifier management service on the SOAP binding, which
	// ServeSOAPManageNameID handles. When it is set and the NameIDProvider implements
	// NameIDManagementProvider, the metadata lists it. It may share its path with ManageNameIDURL, as Handler
	// tells the two apart by the Content-Type, and with the other services on the SOAP binding, which Handler
	// tells apart by the message in the envelope.
	SOAPManageNameIDURL url.URL

	// NameIDMappingURL is the name identifier mapping service, on the SOAP binding, which ServeNameIDMapping
	// handles. When it is set, the NameIDProvider implements NameIDMappingProvider and there is a
	// NameIDMappingPolicy, the metadata lists it. It may share its path with the other services on the SOAP
	// binding, which Handler tells apart by the message in the envelope.
	NameIDMappingURL url.URL

	// NameIDMappingPolicy decides which requester may obtain the identifiers that a principal has at which
	// service provider, with a NameIDMappingRequest. Without one every such request is refused.
	NameIDMappingPolicy NameIDMappingPolicy

	// HTTPClient sends back-channel messages, such as a LogoutRequest over SOAP. Defaults to a client with a
	// 10 second timeout. A client that is set is copied, and the copy never follows a redirect, whatever its
	// CheckRedirect, and has the 10 second timeout if its Timeout is 0; its Transport is kept.
	HTTPClient *http.Client

	// EntityID is the entity identifier of the identity provider, which is the entityID of its metadata, the Issuer
	// of every assertion, response, logout request and logout response, and the NameQualifier of every NameID that
	// it asserts. SAMLCore §8.3.6 requires it to be an absolute URI of no more than 1024 characters, and a message
	// is refused if it is not. Defaults to MetadataURL, which remains the URL at which the metadata is served
	// whatever the entity ID is.
	EntityID string

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

	// AttributeServiceURL is the attribute service on the SOAP binding, which ServeAttributeQuery handles.
	// When it is set and the SessionProvider implements QuerySessionProvider, the metadata has an
	// AttributeAuthorityDescriptor that lists it. Like AuthnQueryServiceURL and AssertionIDRequestServiceURL,
	// it may share its path with the other services on the SOAP binding, which Handler tells apart by the
	// message in the envelope.
	AttributeServiceURL url.URL

	// AuthnQueryServiceURL is the authentication query service on the SOAP binding, which ServeAuthnQuery
	// handles. When it is set and the SessionProvider implements QuerySessionProvider, the metadata has
	// an AuthnAuthorityDescriptor that lists it.
	AuthnQueryServiceURL url.URL

	// AssertionIDRequestServiceURL is the assertion ID request service on the SOAP binding, which
	// ServeAssertionIDRequest handles. When it and AssertionStore are set, the metadata lists it.
	AssertionIDRequestServiceURL url.URL

	// AssertionStore keeps every assertion that is issued, so that ServeAssertionIDRequest can return
	// it to the service provider it was issued to. Nothing is kept by default, and every
	// AssertionIDRequest is then refused.
	AssertionStore AssertionStore

	// AuthnContextEnforcer decides whether the authentication of a session satisfies a
	// RequestedAuthnContext. Defaults to a DefaultAuthnContextEnforcer with no Strength, which only
	// accepts a class that the request lists, and never satisfies the better comparison.
	AuthnContextEnforcer AuthnContextEnforcer

	// SubjectEnforcer decides whether an assertion matches the Subject of its request. Defaults to
	// DefaultSubjectEnforcer.
	SubjectEnforcer SubjectEnforcer

	// EncryptionCertificateEnforcer decides whether the encryption certificate of a service provider
	// may be used. Defaults to a DefaultEncryptionCertificateEnforcer with no options set, which
	// refuses a certificate that is expired or not yet valid, has an RSA key shorter than 2048 bits,
	// or has a KeyUsage extension without keyEncipherment.
	EncryptionCertificateEnforcer EncryptionCertificateEnforcer

	// AttributeReleasePolicy decides which attributes DefaultAssertionMaker and ServeAttributeQuery
	// state to each service provider. Defaults to DefaultAttributeReleasePolicy, which only releases
	// the attributes that the AttributeConsumingService of the request lists, and none if there is no
	// such service. It is not used by any other AssertionMaker.
	AttributeReleasePolicy AttributeReleasePolicy

	// ElementEncryptionPolicy decides which service providers are sent an EncryptedID that they didn't request,
	// and which attributes are sent as an EncryptedAttribute. Defaults to a DefaultElementEncryptionPolicy with
	// no options set, which encrypts neither. A request for the encrypted NameID format is always honoured.
	ElementEncryptionPolicy ElementEncryptionPolicy

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
	// assertion, a NameID or an attribute with, and those it accepts an EncryptedID to be encrypted with. When the service provider lists content encryption algorithms for its key, the first of them
	// in its order of preference that is also listed here is used, and when it lists none the first one listed
	// here is used (Metadata Profile for Algorithm Support §2.5). The supported ciphers are AES-128-CBC,
	// AES-192-CBC, AES-256-CBC, AES-128-GCM, AES-192-GCM and AES-256-GCM, and empty means all of them in that
	// order, so that a service provider which lists none receives AES-128-CBC. The metadata lists them for the
	// encryption key of the identity provider with GCM first, as CBC doesn't protect the integrity of what it
	// encrypts (errata E93). KeyTransportMethods and KeyTransportDigestMethods restrict what is accepted in the
	// same way.
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

	// ArtifactResolutionURL is the artifact resolution service on the SOAP binding, which
	// ServeArtifactResolution handles. It may share its path with the other services on the SOAP binding, which
	// Handler tells apart by the message in the envelope. Setting it enables the HTTP-Artifact
	// binding for responses: the metadata lists the service, an AssertionConsumerService with the
	// HTTP-Artifact binding may be selected, and a request may name that binding as its ProtocolBinding. The
	// response then waits in the ArtifactStore while the browser takes an artifact to the service provider,
	// which resolves it here. It must be served over TLS, as SAMLProf §4.1.4.4 requires the exchange to be
	// confidential.
	ArtifactResolutionURL url.URL

	// ArtifactStore keeps the responses that are delivered with the HTTP-Artifact binding until their
	// artifact is resolved. Defaults to a MemoryArtifactStore of DefaultMemoryArtifactStoreCapacity, which
	// is private to this process: identity providers that run as several instances must set a store that
	// they share, and a ReplayStore that they share, which is what makes an artifact single use.
	ArtifactStore ArtifactStore

	// ArtifactLifetime is how long an artifact can be resolved for after it is issued. Defaults to
	// DefaultArtifactLifetime.
	ArtifactLifetime time.Duration

	// ArtifactRedirectEncoding delivers an artifact in the query of a redirect to the assertion consumer
	// service (SAMLBind §3.6.3.2), instead of in a form that the browser posts to it (§3.6.3.3), which is the
	// default. An endpoint with the HTTP-Artifact binding must accept both. The form is the default because
	// it keeps the artifact out of the URL, and so out of the history of the browser, the logs of servers and
	// proxies, and the Referer header: an artifact is a bearer reference to the response until it is resolved.
	ArtifactRedirectEncoding bool

	// ArtifactFormTemplate renders the form, with an IdpAuthnRequestArtifact. Defaults to a form which
	// posts SAMLart and RelayState.
	ArtifactFormTemplate *template.Template

	// defaultArtifactStore is the *MemoryArtifactStore that artifactStore makes when ArtifactStore is not
	// set, kept like defaultReplayStore.
	defaultArtifactStore unsafe.Pointer
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

	keyDescriptors := []KeyDescriptor{signingKeyDescriptor(certStr)}

	// The Metadata Interoperability Profile §2.5.1 requires each key to be placed in its own KeyDescriptor, with a
	// single certificate.
	published := []*x509.Certificate{idp.Certificate}
	for _, cert := range idp.RolloverCertificates {
		if cert == nil || slices.ContainsFunc(published, cert.Equal) {
			continue
		}

		published = append(published, cert)
		keyDescriptors = append(keyDescriptors, signingKeyDescriptor(base64.StdEncoding.EncodeToString(cert.Raw)))
	}

	// The authorities that answer queries sign with the same key, so they publish every signing key and no
	// encryption key.
	signingKeyDescriptors := len(keyDescriptors)

	// Encryption requires RSA, so a certificate with any other type of key must not be advertised for it. What
	// is encrypted to the identity provider is the EncryptedID of a LogoutRequest (SAMLProfiles §4.4.5), which it
	// can only decrypt with a private key it holds, so a key that is only a Signer isn't advertised either.
	if methods := idp.encryptionMethods(); methods != nil {
		keyDescriptors = append(keyDescriptors, KeyDescriptor{
			Use: "encryption",
			KeyInfo: KeyInfo{
				X509Data: X509Data{
					X509Certificates: []X509Certificate{
						{Data: certStr},
					},
				},
			},
			EncryptionMethods: methods,
		})
	}

	formats := idp.nameIDProvider().NameIDFormats()

	nameIDFormats := make([]NameIDFormat, 0, len(formats))
	for _, format := range formats {
		nameIDFormats = append(nameIDFormats, NameIDFormat(format))
	}

	ed := &EntityDescriptor{
		EntityID:      idp.entityID(),
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

	// ECP v2.0 §2.3.10: the endpoint that a client relays requests to has the SOAP binding.
	if _, ok := idp.SessionProvider.(ECPSessionProvider); ok && idp.ECPURL.String() != "" {
		ed.IDPSSODescriptors[0].SingleSignOnServices = append(ed.IDPSSODescriptors[0].SingleSignOnServices, Endpoint{
			Binding:  SOAPBinding,
			Location: idp.ECPURL.String(),
		})
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

	// SAMLBind §3.6.7 as changed by errata E2: an entity that sends messages with the HTTP-Artifact binding
	// lists the indexed endpoints at which its artifacts are resolved. The index is the EndpointIndex of the
	// artifacts (SAMLProf §5.5).
	if idp.artifactEnabled() {
		ed.IDPSSODescriptors[0].ArtifactResolutionServices = []IndexedEndpoint{
			{
				Binding:  SOAPBinding,
				Location: idp.ArtifactResolutionURL.String(),
				Index:    artifactResolutionServiceIndex,
			},
		}
	}

	idp.addQueryMetadata(ed, keyDescriptors[:signingKeyDescriptors:signingKeyDescriptors], nameIDFormats)

	idp.nameIDServiceMetadata(&ed.IDPSSODescriptors[0])

	return ed
}

// signingKeyDescriptor returns a KeyDescriptor which publishes the base64 encoded certificate for signing.
func signingKeyDescriptor(cert string) KeyDescriptor {
	return KeyDescriptor{
		Use: "signing",
		KeyInfo: KeyInfo{
			X509Data: X509Data{
				X509Certificates: []X509Certificate{
					{Data: cert},
				},
			},
		},
	}
}

// nameIDServiceMetadata lists the name identifier management and mapping services in descriptor: each one
// whose URL is set and which the NameIDProvider can serve (SAMLMeta §2.4.2, §2.4.3). The mapping service is
// only listed with a NameIDMappingPolicy, as without one it refuses every request, and has no
// ResponseLocation, which SAMLMeta §2.4.3 requires to be omitted.
func (idp *IdentityProvider) nameIDServiceMetadata(descriptor *IDPSSODescriptor) {
	provider := idp.nameIDProvider()

	if _, ok := provider.(NameIDManagementProvider); ok {
		if location := idp.ManageNameIDURL.String(); location != "" {
			descriptor.ManageNameIDServices = append(descriptor.ManageNameIDServices,
				Endpoint{Binding: HTTPRedirectBinding, Location: location},
				Endpoint{Binding: HTTPPostBinding, Location: location})
		}

		if location := idp.SOAPManageNameIDURL.String(); location != "" {
			descriptor.ManageNameIDServices = append(descriptor.ManageNameIDServices,
				Endpoint{Binding: SOAPBinding, Location: location})
		}
	}

	if _, ok := provider.(NameIDMappingProvider); ok && idp.NameIDMappingPolicy != nil {
		if location := idp.NameIDMappingURL.String(); location != "" {
			descriptor.NameIDMappingServices = append(descriptor.NameIDMappingServices,
				Endpoint{Binding: SOAPBinding, Location: location})
		}
	}
}

// entityID returns the entity identifier of the identity provider, which is EntityID, or MetadataURL if that is
// empty.
func (idp *IdentityProvider) entityID() string {
	if idp.EntityID != "" {
		return idp.EntityID
	}

	return idp.MetadataURL.String()
}

// maxEntityIDLength is the longest entity identifier that SAMLCore §8.3.6 allows, in characters.
const maxEntityIDLength = 1024

// checkEntityID returns an error unless the entity identifier is an absolute URI, as SAMLCore §1.3.2 requires, of
// no more than 1024 characters, as SAMLCore §8.3.6 requires.
func (idp *IdentityProvider) checkEntityID() error {
	entityID := idp.entityID()
	if utf8.RuneCountInString(entityID) > maxEntityIDLength {
		return fmt.Errorf("the entity ID is longer than %d characters", maxEntityIDLength)
	}

	if strings.ContainsFunc(entityID, unicode.IsSpace) {
		return fmt.Errorf("the entity ID %q contains whitespace", entityID)
	}

	if u, err := url.Parse(entityID); err != nil || !u.IsAbs() {
		return fmt.Errorf("the entity ID %q is not an absolute URI", entityID)
	}

	return nil
}

// ServeMetadata is an [http.HandlerFunc] that serves the IDP metadata, signed by the key of the identity provider
// (see SignedMetadata). It responds with StatusInternalServerError if the entity ID is not valid.
func (idp *IdentityProvider) ServeMetadata(w http.ResponseWriter, _ *http.Request) {
	if err := idp.checkEntityID(); err != nil {
		idp.logger().Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

	buf, err := idp.SignedMetadata()
	if err != nil {
		idp.logger().Printf("ERROR: cannot sign the metadata: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

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
// returns an HTTP response according to the binding of the assertion
// consumer service. That is the HTTP-POST binding, which returns
// an HTML form in the appropriate format with Javascript to automatically
// submit that form the to service provider's Assertion Customer Service
// endpoint, or, if ArtifactResolutionURL is set, the HTTP-Artifact binding,
// which sends the browser there with an artifact that the service provider
// resolves with ServeArtifactResolution.
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

	req.respond(w, session)
}

// respond answers a valid request with an assertion about the principal of session, or with the error status of
// the request that the assertion can't satisfy. It is the same for every binding the request can arrive on; the
// binding decides how WriteResponse delivers the Response.
func (req *IdpAuthnRequest) respond(w http.ResponseWriter, session *Session) {
	idp := req.IDP

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
		if err := idp.satisfiesAuthnContext(req.Request.RequestedAuthnContext, req.Assertion, session); err != nil {
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
// second-level status. If that Response can't be written, it completes it with an internal server error, or with a
// Server fault on the SOAP binding. Nothing more is written if the body had already started.
func (req *IdpAuthnRequest) writeErrorStatus(w http.ResponseWriter, topLevelStatus, secondLevelStatus string) {
	err := req.MakeErrorResponse(topLevelStatus, secondLevelStatus, "")
	started := false

	if err == nil {
		if err = req.WriteResponse(w); err == nil {
			return
		}

		started = !errors.Is(err, ErrResponseNotBuilt)
	}

	req.IDP.logger().Printf("failed to write response: %s", err)

	switch {
	case req.binding != SOAPBinding:
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	case !started:
		writeSOAPFault(w, &soapFault{Code: "Server", String: soapFaultStringProcessing})
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

	// nameIDEncrypted is whether AssertionEl carries the NameID of the Subject as an EncryptedID.
	nameIDEncrypted bool

	// responseParticipant is the participant that the assertion in ResponseEl makes of the service
	// provider, which PublishResponse records each time the response is sent.
	responseParticipant *SessionParticipant

	// RedirectQuery is the raw query string of a signed HTTP-Redirect request, which is what the
	// signature covers. A SessionProvider which shows a login form and re-presents the request as a
	// POST must send this value in the RedirectQueryFormField field, otherwise the signature is lost
	// and a service provider that requires one is refused.
	RedirectQuery string

	// binding is SOAPBinding for a request of the Enhanced Client or Proxy profile, which ServeECP received in a
	// SOAP envelope and whose Response goes back on the same connection, for the PAOS endpoint of the service
	// provider. It is empty for a request on a browser binding, whose Response is for an HTTP-POST endpoint.
	binding string

	// requestAuthenticated is set by Validate if the request has a signature, which was verified.
	requestAuthenticated bool
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
	//
	// That section is of the browser bindings. A request of the Enhanced Client or Proxy profile is issued, and
	// signed, before the client chooses the identity provider to send it to (ECP v2.0 §2.3.2 and §2.3.3), so it
	// usually has no destination, and it is only checked when it was provided.
	destination, required := req.IDP.SSOURL.String(), req.IDP.WantAuthnRequestsSigned
	if req.binding == SOAPBinding {
		destination, required = req.IDP.ECPURL.String(), false
	}

	if required || req.Request.Destination != "" {
		if req.Request.Destination != destination {
			return &statusError{StatusRequester, StatusRequestDenied,
				fmt.Errorf("expected destination to be %q, not %q", destination, req.Request.Destination)}
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

// responseBindings returns the bindings of the AssertionConsumerService that the Response to the request can be
// for. A request on a browser binding is answered through the browser with HTTP-POST, or with HTTP-Artifact if the
// identity provider has an ArtifactResolutionURL at which the artifact can be resolved. A request of the Enhanced
// Client or Proxy profile is answered to the client, which delivers the Response with PAOS (SAMLProf §4.2.3.7, ECP
// v2.0 §2.3.10), and never with a browser binding.
func (req *IdpAuthnRequest) responseBindings() []string {
	switch {
	case req.binding == SOAPBinding:
		return []string{PAOSBinding}
	case req.IDP.artifactEnabled():
		return []string{HTTPPostBinding, HTTPArtifactBinding}
	default:
		return []string{HTTPPostBinding}
	}
}

// supportedProtocolBinding reports whether the response can be sent with the ProtocolBinding of the
// request (SAMLCore §3.4.1): one of the bindings this identity provider sends the response to it with, or
// none, which leaves the binding to the endpoint.
func (req *IdpAuthnRequest) supportedProtocolBinding() bool {
	return req.Request.ProtocolBinding == "" || slices.Contains(req.responseBindings(), req.Request.ProtocolBinding)
}

// acsBindings returns the bindings of the endpoints that the response to the request may be sent to: the
// ProtocolBinding of the request, which the identity provider must honour if it can (SAMLProf §4.1.3.5), or
// every binding it sends the response with if the request names none, or one that is not supported.
func (req *IdpAuthnRequest) acsBindings() []string {
	if req.Request.ProtocolBinding != "" && req.supportedProtocolBinding() {
		return []string{req.Request.ProtocolBinding}
	}

	return req.responseBindings()
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

// getACSEndpoint finds the endpoint to deliver the response to. HTTP-POST, and HTTP-Artifact when the
// identity provider has an ArtifactResolutionURL, are the only bindings it can send a response with, so
// other endpoints are never selected, and neither are those of another binding than a ProtocolBinding
// that the request names. For a request of the Enhanced Client or Proxy profile the only binding is PAOS
// instead, here and below (see responseBindings).
//
// An endpoint that the request names, by index or URL, is refused if it is insecure, as described by
// IdentityProvider.AllowInsecureServiceProviderEndpoints, rather than replaced by another endpoint.
// The response, whether an assertion or an error status, would be sent to that endpoint, so the
// request can only fail with an HTTP error.
//
// AssertionConsumerServiceIndex is mutually exclusive with AssertionConsumerServiceURL and
// ProtocolBinding (SAMLCore §3.4.1), so a request with both is refused. A request whose ProtocolBinding
// is a binding that is not supported gets the default endpoint, which only receives the UnsupportedBinding
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

// useRequestedACSEndpoint selects the endpoint that the request names by index or location, among those
// with one of acsBindings. Several endpoints may share a location with different bindings, in which case
// the first in the metadata is used.
func (req *IdpAuthnRequest) useRequestedACSEndpoint(index, location string) error {
	bindings := req.acsBindings()

	for _, match := range []func(endpoint IndexedEndpoint) bool{
		func(endpoint IndexedEndpoint) bool { return index != "" && strconv.Itoa(endpoint.Index) == index },
		func(endpoint IndexedEndpoint) bool { return location != "" && endpoint.Location == location },
	} {
		for _, spssoDescriptor := range req.ServiceProviderMetadata.SPSSODescriptors {
			for _, endpoint := range spssoDescriptor.AssertionConsumerServices {
				if slices.Contains(bindings, endpoint.Binding) && match(endpoint) {
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

// useDefaultACSEndpoint selects the default endpoint among those with one of acsBindings, as defined by
// SAMLMetadata §2.2.3: the first with isDefault set to true, otherwise the first without isDefault set to
// false, otherwise the first.
//
// Insecure endpoints, as described by IdentityProvider.AllowInsecureServiceProviderEndpoints, are
// left out of that sequence, as endpoints of a binding that this identity provider doesn't support
// are. So a service provider which lists an http endpoint as the default, alongside an https one,
// receives the response at the https endpoint. If every such endpoint is insecure it returns an
// error which wraps ErrInsecureEndpoint.
func (req *IdpAuthnRequest) useDefaultACSEndpoint() error {
	bindings := req.acsBindings()

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
			if !slices.Contains(bindings, endpoint.Binding) || preference(endpoint) <= best {
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
// NameID must have that format. The encrypted format is satisfied by a NameID of any format, which
// MakeAssertionEl sends as an EncryptedID, so it only requires that the service provider has a key to
// encrypt it to (SAMLCore §3.4.1.1, errata E6). If the policy has an SPNameQualifier, the NameID must
// also have that value.
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
			if req.SPSSODescriptor == nil || req.spEncryptionKeyDescriptor() == nil {
				return fmt.Errorf("the request requires an EncryptedID, and the service provider has no encryption key")
			}
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
const encryptedNameIDFormat = string(EncryptedNameIDFormat)

// DefaultAssertionMaker produces a SAML assertion for the
// given request and assigns it to req.Assertion.
type DefaultAssertionMaker struct {
}

// MakeAssertion implements AssertionMaker. It produces a SAML assertion from the
// given request and assigns it to req.Assertion.
func (DefaultAssertionMaker) MakeAssertion(req *IdpAuthnRequest, session *Session) error {
	service := req.AttributeConsumingService()

	// The index is not included because the request may not be authenticated.
	if service == nil && req.Request.AttributeConsumingServiceIndex != "" && req.IDP != nil {
		req.IDP.logger().Printf("releasing no attributes: the AttributeConsumingServiceIndex of the request names no service")
	}

	attributes := append(requestedNameAttributes(service, session), sessionAttributes(session)...)

	attributes, err := req.IDP.attributeReleasePolicy().ReleaseAttributes(AttributeReleaseRequest{
		HTTPRequest:             req.HTTPRequest,
		ServiceProviderMetadata: req.ServiceProviderMetadata,
		Ceiling:                 service,
		AuthnRequest:            req,
	}, session, attributes)
	if err != nil {
		return fmt.Errorf("cannot release attributes: %w", err)
	}

	lifetime := req.IDP.AssertionLifetime
	if lifetime < 0 {
		return errors.New("AssertionLifetime must not be negative")
	}

	if lifetime == 0 {
		lifetime = MaxIssueDelay
	}

	// allow for some clock skew in the validity period. This uses our own clock, because the
	// request and therefore its IssueInstant are not authenticated.
	notBefore := req.Now.Add(-1 * MaxClockSkew)
	notOnOrAfter := req.Now.Add(lifetime)

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
			Value:  req.IDP.entityID(),
		},
		Subject: &Subject{
			NameID: nameID,
			SubjectConfirmations: []SubjectConfirmation{
				{
					Method: bearerSubjectConfirmationMethod,
					SubjectConfirmationData: &SubjectConfirmationData{
						Address:      address,
						InResponseTo: req.Request.ID,
						NotOnOrAfter: notOnOrAfter,
						Recipient:    req.ACSEndpoint.Location,
					},
				},
			},
		},
		Conditions: &Conditions{
			NotBefore:    notBefore,
			NotOnOrAfter: notOnOrAfter,
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
						Value: sessionAuthnContextClassRef(session),
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

// attributeReleasePolicy returns the AttributeReleasePolicy of idp, or DefaultAttributeReleasePolicy if
// there is none.
func (idp *IdentityProvider) attributeReleasePolicy() AttributeReleasePolicy {
	if idp != nil && idp.AttributeReleasePolicy != nil {
		return idp.AttributeReleasePolicy
	}

	return DefaultAttributeReleasePolicy{}
}

// sessionAttributes returns every attribute that can be stated about the principal of session under
// the names the identity provider gives them, which DefaultAssertionMaker and ServeAttributeQuery offer
// to the AttributeReleasePolicy. The custom attributes of the session are copies, as the policy may
// change its candidates.
func sessionAttributes(session *Session) []Attribute {
	var attributes []Attribute

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

	return attributes
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

	return defaultAttributeConsumingService(services)
}

// defaultAttributeConsumingService returns a copy of the default service of services by SAMLMeta §2.4.4,
// as changed by errata E87, or nil if there are none.
func defaultAttributeConsumingService(services []AttributeConsumingService) *AttributeConsumingService {
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
// the RequestedAttribute elements of its AttributeConsumingService, which is the Ceiling of the
// AttributeReleaseRequest: the one IdpAuthnRequest.AttributeConsumingService selects for single sign-on,
// and the default one for an AttributeQuery. If there is no such service, no attributes are released,
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
//
// The attributes that an AttributeQuery names only narrow this further, in the same way, so that a query
// is never answered with an attribute or a value that single sign-on would not state.
type DefaultAttributeReleasePolicy struct {
}

// ReleaseAttributes implements AttributeReleasePolicy.
func (DefaultAttributeReleasePolicy) ReleaseAttributes(req AttributeReleaseRequest, _ *Session, candidates []Attribute) ([]Attribute, error) {
	if req.Ceiling == nil {
		return nil, nil
	}

	var released []Attribute

	for _, candidate := range candidates {
		if attribute, ok := releaseRequestedAttribute(req.Ceiling.RequestedAttributes, candidate); ok {
			released = append(released, attribute)
		}
	}

	return narrowToQueriedAttributes(req.Requested, released), nil
}

// releaseRequestedAttribute returns the part of candidate which requested asks for, and false if it
// asks for none of it.
func releaseRequestedAttribute(requested []RequestedAttribute, candidate Attribute) (Attribute, bool) {
	attributes := make([]Attribute, 0, len(requested))
	for _, r := range requested {
		attributes = append(attributes, r.Attribute)
	}

	return narrowAttribute(attributes, candidate)
}

// narrowAttribute returns the part of candidate which wanted asks for, and false if it asks for none of
// it. An entry of wanted asks for the candidate if it has the same Name and a compatible NameFormat. If
// every entry that does lists values, only those values of the candidate are kept.
func narrowAttribute(wanted []Attribute, candidate Attribute) (Attribute, bool) {
	matched, anyValue := false, false

	var values []AttributeValue

	for _, r := range wanted {
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
//
// The NameID of the Subject is sent as an EncryptedID when the NameIDPolicy of the request has the encrypted
// format (SAMLCore §3.4.1.1) or the ElementEncryptionPolicy requires it, and the attributes which that policy
// chooses are sent as EncryptedAttribute elements. They are encrypted before the assertion is signed, as
// SAMLCore §6.2 requires, so the signature covers the ciphertext. Assertion is not changed, apart from its
// Signature, and keeps the NameID and the attributes in plaintext. If a part must be encrypted and the service
// provider has no key to encrypt it to, an error is returned, which wraps ErrInvalidNameIDPolicy when it is the
// request that asked.
//
// The signed assertion is saved in the AssertionStore of the identity provider, if it has one, before it is
// encrypted as a whole: as it is sent, so with any EncryptedID and EncryptedAttribute in place of their plaintext.
func (req *IdpAuthnRequest) MakeAssertionEl() error {
	signingContext, err := req.signingContext()
	if err != nil {
		return err
	}

	encrypter, err := req.elementEncrypter()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	sent, err := req.sentAssertion(encrypter)
	if err != nil {
		return err
	}

	signedAssertionEl, err := signingContext.SignEnveloped(sent.Element())
	if err != nil {
		return err
	}

	sigEl := signedAssertionEl.Child[len(signedAssertionEl.Child)-1]
	req.Assertion.Signature = sigEl.(*etree.Element)
	sent.Signature = req.Assertion.Signature
	signedAssertionEl = sent.Element()

	req.nameIDEncrypted = sent.Subject != nil && sent.Subject.EncryptedID != nil

	req.saveAssertion(signedAssertionEl)

	if encrypter == nil {
		req.AssertionEl = signedAssertionEl
		return nil
	}

	req.AssertionEl, err = encrypter.encryptAssertion(signedAssertionEl)

	return err
}

// encryptAssertionEl returns the EncryptedAssertion element of the signed assertion, or the signed
// assertion itself when the service provider has no encryption certificate.
func (req *IdpAuthnRequest) encryptAssertionEl(signedAssertionEl *etree.Element) (*etree.Element, error) {
	encrypter, err := req.elementEncrypter()
	if errors.Is(err, os.ErrNotExist) {
		return signedAssertionEl, nil
	} else if err != nil {
		return nil, err
	}

	return encrypter.encryptAssertion(signedAssertionEl)
}

// encryptAssertion returns the EncryptedAssertion element of the signed assertion. SAMLCore §6.2: a signed
// assertion is signed first, and then encrypted.
func (e *elementEncrypter) encryptAssertion(signedAssertionEl *etree.Element) (*etree.Element, error) {
	encryptedAssertionEl, err := (&elementEncrypter{certificate: e.certificate, encrypter: e.encrypter}).
		encrypt("EncryptedAssertion", signedAssertionEl)
	if err != nil {
		return nil, err
	}

	// The Response that holds the EncryptedAssertion declares the prefix.
	encryptedAssertionEl.RemoveAttr("xmlns:saml")

	return encryptedAssertionEl, nil
}

// elementEncrypter returns the encrypter of the assertion to the service provider and of the parts of it that
// are encrypted on their own, with the algorithms negotiated from its metadata. The error is [os.ErrNotExist] if
// the service provider has no encryption key and doesn't ask for encryption.
func (req *IdpAuthnRequest) elementEncrypter() (*elementEncrypter, error) {
	cert, err := req.getSPEncryptionCert()
	if err != nil {
		return nil, err
	}

	encrypter, err := req.assertionEncrypter()
	if err != nil {
		return nil, err
	}

	return &elementEncrypter{certificate: cert, encrypter: encrypter, recipient: req.ServiceProviderMetadata.EntityID}, nil
}

// requestsEncryptedID reports whether the NameIDPolicy of the request has the encrypted format, which means the
// assertion MUST contain an EncryptedID instead of a NameID (SAMLCore §3.4.1.1).
func (req *IdpAuthnRequest) requestsEncryptedID() bool {
	policy := req.Request.NameIDPolicy

	return policy != nil && policy.Format != nil && *policy.Format == encryptedNameIDFormat
}

// elementEncryptionPolicy returns the ElementEncryptionPolicy of the identity provider, or
// DefaultElementEncryptionPolicy if there is none.
func (req *IdpAuthnRequest) elementEncryptionPolicy() ElementEncryptionPolicy {
	if req.IDP != nil && req.IDP.ElementEncryptionPolicy != nil {
		return req.IDP.ElementEncryptionPolicy
	}

	return DefaultElementEncryptionPolicy{}
}

// sentAssertion returns a copy of Assertion as it is sent: with the NameID of its Subject replaced by an
// EncryptedID, and each attribute that is to be encrypted by an EncryptedAttribute, each in the place of its
// plaintext (SAMLCore §6.1). The encrypter is nil if the service provider has no encryption key.
func (req *IdpAuthnRequest) sentAssertion(encrypter *elementEncrypter) (*Assertion, error) {
	sent := *req.Assertion
	policy := req.elementEncryptionPolicy()

	if subject := sent.Subject; subject != nil && subject.NameID != nil && subject.EncryptedID == nil {
		requested := req.requestsEncryptedID()

		if requested || policy.EncryptNameID(req) {
			if encrypter == nil {
				if requested {
					return nil, fmt.Errorf("%w: the request requires an EncryptedID, and the service provider has no encryption key", ErrInvalidNameIDPolicy)
				}

				return nil, errors.New("the NameID must be encrypted, and the service provider has no encryption key")
			}

			encryptedID, err := encrypter.encryptNameID(subject.NameID)
			if err != nil {
				return nil, fmt.Errorf("cannot encrypt the NameID: %w", err)
			}

			encrypted := *subject
			encrypted.NameID, encrypted.EncryptedID = nil, encryptedID
			sent.Subject = &encrypted
		}
	}

	statements := make([]AttributeStatement, 0, len(sent.AttributeStatements))

	for _, statement := range sent.AttributeStatements {
		out := AttributeStatement{EncryptedAttributes: slices.Clone(statement.EncryptedAttributes)}

		for i := range statement.Attributes {
			attribute := &statement.Attributes[i]

			if !policy.EncryptAttribute(req, attribute.clone()) {
				out.Attributes = append(out.Attributes, *attribute)

				continue
			}

			if encrypter == nil {
				return nil, fmt.Errorf("the attribute %q must be encrypted, and the service provider has no encryption key", attribute.Name)
			}

			encryptedAttribute, err := encrypter.encryptAttribute(attribute)
			if err != nil {
				return nil, fmt.Errorf("cannot encrypt the attribute %q: %w", attribute.Name, err)
			}

			out.EncryptedAttributes = append(out.EncryptedAttributes, encryptedAttribute)
		}

		statements = append(statements, out)
	}

	if len(statements) != 0 {
		sent.AttributeStatements = statements
	}

	return &sent, nil
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
//
// A request of the Enhanced Client or Proxy profile, which ServeECP received, is answered with the SOAP envelope of
// that profile instead.
//
// Otherwise, if ACSEndpoint has the HTTP-Artifact binding, the response is kept in the ArtifactStore and the
// browser is sent to the endpoint with the artifact from ArtifactBinding instead, in a form or, with
// ArtifactRedirectEncoding, in the query of a redirect.
func (req *IdpAuthnRequest) WriteResponse(w http.ResponseWriter) error {
	if req.binding == SOAPBinding {
		return req.writeECPResponse(w)
	}

	if req.ACSEndpoint != nil && req.ACSEndpoint.Binding == HTTPArtifactBinding {
		return req.writeArtifactResponse(w)
	}

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
			Value:  req.IDP.entityID(),
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

// signingContext returns a context which signs with the key of the identity provider. Every message that the
// identity provider sends is signed and has its entity ID as the Issuer, so this is also where an invalid entity ID
// is refused.
func (idp *IdentityProvider) signingContext() (*dsig.SigningContext, error) {
	if err := idp.checkEntityID(); err != nil {
		return nil, err
	}

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
