package saml

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"authelia.com/provider/saml/internal/dsig"
)

// ResponseSigning is which parts of a successful Response of single sign-on the identity provider signs.
// One of them always is: SAMLProf §4.1.4.5 requires that the assertion or the Response is signed when it is
// delivered through the browser.
type ResponseSigning int

const (
	// SignResponseAndAssertion signs the Response and the Assertion in it. It is the default, and satisfies a
	// service provider which verifies either.
	SignResponseAndAssertion ResponseSigning = iota

	// SignAssertion signs the Assertion and leaves the Response unsigned, for a service provider that can't
	// process a signed Response. A Response without an assertion, which reports an error, is still signed.
	SignAssertion

	// SignResponse signs the Response, and the Assertion only if the metadata of the service provider sets
	// WantAssertionsSigned. That is what SAML2Int requires: SDP-IDP09, "successful responses MUST be directly
	// signed using a <ds:Signature> element within the <samlp:Response> element", and SDP-MD01, by which the
	// "optional signing of assertions via the WantAssertionsSigned flag" is taken from metadata alone.
	SignResponse
)

// Issuance is how the identity provider issues a Response and its Assertion to a service provider, as an
// IssuancePolicy decides.
type Issuance struct {
	// Sign is which of the Response and the Assertion are signed.
	Sign ResponseSigning

	// SignatureMethod is the identifier of the signature algorithm, such as
	// http://www.w3.org/2001/04/xmldsig-more#rsa-sha256, which must be one for the type of the key of the
	// identity provider. Empty means the one that IdentityProvider.SignatureMethod gives.
	SignatureMethod string

	// DigestMethod is the identifier of the digest of what is signed, such as
	// http://www.w3.org/2001/04/xmlenc#sha256. Empty means the digest of SignatureMethod, which is SHA-1 for
	// RSA-SHA1. The supported digests are SHA-1, SHA-256, SHA-384 and SHA-512.
	DigestMethod string

	// AssertionLifetime is how long after it is made that the assertion states it is valid, as
	// IdentityProvider.AssertionLifetime describes. Zero means what that gives, and it must not be negative.
	AssertionLifetime time.Duration

	// IncludeSessionNotOnOrAfter is whether the assertion states when the session ends, as
	// IdentityProvider.IncludeSessionNotOnOrAfter describes.
	IncludeSessionNotOnOrAfter bool

	// AdditionalAudiences are further audiences that the AudienceRestriction of the assertion names, after the
	// entity ID of the service provider, for one that is known by a second name or passes the assertion on
	// (SAMLCore §2.5.1.4). None may be empty.
	AdditionalAudiences []string
}

// IssuanceRequest describes what an IssuancePolicy is asked about: a Response of single sign-on, or another
// message that the identity provider signs for a service provider.
type IssuanceRequest struct {
	// HTTPRequest is the request being served.
	HTTPRequest *http.Request

	// ServiceProviderMetadata is the metadata of the service provider that the message is for.
	ServiceProviderMetadata *EntityDescriptor

	// SPSSODescriptor is the descriptor of the service provider that an assertion is issued for, and nil when no
	// assertion is.
	SPSSODescriptor *SPSSODescriptor

	// ACSEndpoint is the assertion consumer service that the Response is delivered to, whose Binding is how. It
	// is nil unless the message is a Response of single sign-on.
	ACSEndpoint *IndexedEndpoint

	// AuthnRequest is the request, for single sign-on, and nil otherwise. Its Request has no ID when the
	// identity provider initiated the exchange.
	AuthnRequest *IdpAuthnRequest

	// Session is the session of the principal that the assertion is about. It is nil when there is none: for a
	// Response that reports an error before the principal is known, and for every other message.
	Session *Session

	// Defaults is what the settings of the identity provider give: both signatures, its SignatureMethod, or the
	// default for its key if that is empty, its AssertionLifetime, or MaxIssueDelay if that is zero, and its
	// IncludeSessionNotOnOrAfter. A policy returns it, changed as it wants.
	Defaults Issuance
}

// IssuancePolicy is an interface used by IdentityProvider to decide how a Response and its Assertion are issued
// to a service provider: what is signed, with which algorithms, and for how long the assertion is valid. It
// allows the decision to differ for each service provider. The default implementation is DefaultIssuancePolicy,
// which is used if no IssuancePolicy is specified.
type IssuancePolicy interface {
	// Issuance returns how the message of req is issued. It starts from req.Defaults, which holds the settings
	// of the identity provider. If an error is returned, or what is returned can't be done, such as a
	// SignatureMethod for another type of key, nothing is sent.
	//
	// It is asked once for each part of a Response that is made, so more than once for the same response, and
	// must give the same answer each time.
	//
	// It is also asked before any other message is signed for a service provider: a Response that reports an
	// error, an ArtifactResponse, the Response to a query, a LogoutRequest or LogoutResponse, and the messages of
	// name identifier management and mapping. Only the SignatureMethod and DigestMethod of the answer are then
	// used, as those messages are always signed, and for all but the first req only has its HTTPRequest,
	// ServiceProviderMetadata and Defaults. The metadata of the identity provider is not signed for any one
	// service provider, and always uses IdentityProvider.SignatureMethod.
	//
	// Whatever is returned, the Assertion is signed if the SPSSODescriptor of the service provider sets
	// WantAssertionsSigned.
	Issuance(req IssuanceRequest) (Issuance, error)
}

// ServiceProviderIssuance is how a DefaultIssuancePolicy issues to one service provider. A field that is zero
// leaves the setting of the identity provider as it is.
type ServiceProviderIssuance struct {
	// Sign is which of the Response and the Assertion are signed. See Issuance.Sign.
	Sign ResponseSigning

	// SignatureMethod is the identifier of the signature algorithm. See Issuance.SignatureMethod.
	SignatureMethod string

	// DigestMethod is the identifier of the digest. See Issuance.DigestMethod.
	DigestMethod string

	// AssertionLifetime replaces IdentityProvider.AssertionLifetime.
	AssertionLifetime time.Duration

	// IncludeSessionNotOnOrAfter replaces IdentityProvider.IncludeSessionNotOnOrAfter, unless it is nil.
	IncludeSessionNotOnOrAfter *bool

	// AdditionalAudiences are further audiences of the assertion. See Issuance.AdditionalAudiences.
	AdditionalAudiences []string
}

// DefaultIssuancePolicy is the default IssuancePolicy. With no options set it issues to every service provider
// with the settings of the identity provider, and signs both the Response and the Assertion.
type DefaultIssuancePolicy struct {
	// ServiceProviders holds what differs for a service provider, by its entity ID.
	ServiceProviders map[string]ServiceProviderIssuance
}

// Issuance implements IssuancePolicy.
func (p DefaultIssuancePolicy) Issuance(req IssuanceRequest) (Issuance, error) {
	issuance := req.Defaults

	if req.ServiceProviderMetadata == nil {
		return issuance, nil
	}

	override, ok := p.ServiceProviders[req.ServiceProviderMetadata.EntityID]
	if !ok {
		return issuance, nil
	}

	issuance.Sign = override.Sign
	issuance.AdditionalAudiences = override.AdditionalAudiences

	if override.SignatureMethod != "" {
		issuance.SignatureMethod = override.SignatureMethod
	}

	if override.DigestMethod != "" {
		issuance.DigestMethod = override.DigestMethod
	}

	if override.AssertionLifetime != 0 {
		issuance.AssertionLifetime = override.AssertionLifetime
	}

	if override.IncludeSessionNotOnOrAfter != nil {
		issuance.IncludeSessionNotOnOrAfter = *override.IncludeSessionNotOnOrAfter
	}

	return issuance, nil
}

// issuanceDigestMethods are the identifiers that Issuance.DigestMethod may have.
var issuanceDigestMethods = []string{
	"http://www.w3.org/2000/09/xmldsig#sha1",
	"http://www.w3.org/2001/04/xmlenc#sha256",
	"http://www.w3.org/2001/04/xmldsig-more#sha384",
	"http://www.w3.org/2001/04/xmlenc#sha512",
}

// signer returns what signs for the identity provider: its Signer, or else its Key.
func (idp *IdentityProvider) signer() (crypto.Signer, error) {
	if idp.Signer != nil {
		return idp.Signer, nil
	}

	signer, ok := idp.Key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("identity provider key of type %T does not implement crypto.Signer", idp.Key)
	}

	return signer, nil
}

// defaultSignatureMethod returns the SignatureMethod of the identity provider, or if it is empty RSA with
// SHA-256, or ECDSA with the hash matching the curve of the key. A key that can't sign is refused when it is
// signed with.
func (idp *IdentityProvider) defaultSignatureMethod() string {
	if idp.SignatureMethod != "" {
		return idp.SignatureMethod
	}

	if signer, err := idp.signer(); err == nil {
		if public, ok := signer.Public().(*ecdsa.PublicKey); ok {
			return dsig.DefaultECDSASignatureMethod(public)
		}
	}

	return dsig.RSASHA256SignatureMethod
}

// defaultIssuance returns the Issuance that the settings of the identity provider give.
func (idp *IdentityProvider) defaultIssuance() (Issuance, error) {
	defaults := Issuance{
		Sign:                       SignResponseAndAssertion,
		SignatureMethod:            idp.defaultSignatureMethod(),
		AssertionLifetime:          idp.AssertionLifetime,
		IncludeSessionNotOnOrAfter: idp.IncludeSessionNotOnOrAfter,
	}

	if defaults.AssertionLifetime < 0 {
		return defaults, errors.New("AssertionLifetime must not be negative")
	}

	if defaults.AssertionLifetime == 0 {
		defaults.AssertionLifetime = MaxIssueDelay
	}

	return defaults, nil
}

// issuance asks the IssuancePolicy of the identity provider how the message of req is issued, with the Defaults
// of req filled in, and returns the answer once it is known to be one that can be carried out. Nothing else asks
// the policy, so every message is issued by an answer that passed here.
func (idp *IdentityProvider) issuance(req IssuanceRequest) (Issuance, error) {
	defaults, err := idp.defaultIssuance()
	if err != nil {
		return Issuance{}, err
	}

	req.Defaults = defaults

	var policy IssuancePolicy = DefaultIssuancePolicy{}
	if idp.IssuancePolicy != nil {
		policy = idp.IssuancePolicy
	}

	issuance, err := policy.Issuance(req)
	if err != nil {
		return Issuance{}, fmt.Errorf("IssuancePolicy: %w", err)
	}

	issuance, err = idp.completeIssuance(req, issuance)
	if err != nil {
		return Issuance{}, fmt.Errorf("IssuancePolicy: %w", err)
	}

	return issuance, nil
}

// completeIssuance returns issuance, which the policy gave for req, with what it left empty filled in from the
// Defaults of req and with the Assertion signed if the service provider wants that, or an error if it can't be
// carried out.
func (idp *IdentityProvider) completeIssuance(req IssuanceRequest, issuance Issuance) (Issuance, error) {
	switch issuance.Sign {
	case SignResponseAndAssertion, SignAssertion:
	case SignResponse:
		// SAML2Int SDP-MD01: the service provider says in its metadata whether its assertions are signed, and
		// that can change without the operator of the identity provider.
		if req.SPSSODescriptor != nil && req.SPSSODescriptor.WantAssertionsSigned != nil && *req.SPSSODescriptor.WantAssertionsSigned {
			issuance.Sign = SignResponseAndAssertion
		}
	default:
		return Issuance{}, fmt.Errorf("unknown ResponseSigning %d", issuance.Sign)
	}

	if issuance.SignatureMethod == "" {
		issuance.SignatureMethod = req.Defaults.SignatureMethod
	}

	if issuance.AssertionLifetime < 0 {
		return Issuance{}, errors.New("AssertionLifetime must not be negative")
	}

	if issuance.AssertionLifetime == 0 {
		issuance.AssertionLifetime = req.Defaults.AssertionLifetime
	}

	if issuance.DigestMethod != "" && !slices.Contains(issuanceDigestMethods, issuance.DigestMethod) {
		return Issuance{}, fmt.Errorf("unsupported digest method %q", issuance.DigestMethod)
	}

	// A signature method that the policy chose is checked against the key here, by the context that signs with
	// it, so that the error names the policy. That of the identity provider is checked when it is signed with.
	if issuance.SignatureMethod != req.Defaults.SignatureMethod {
		if _, err := idp.signingContextWith(issuance.SignatureMethod, issuance.DigestMethod); err != nil {
			return Issuance{}, err
		}
	}

	audiences, err := additionalAudiences(req.ServiceProviderMetadata, issuance.AdditionalAudiences)
	if err != nil {
		return Issuance{}, err
	}

	issuance.AdditionalAudiences = audiences

	return issuance, nil
}

// additionalAudiences returns audiences without those that are repeated or are the entity ID of the service
// provider, which an assertion names anyway, or an error if one is empty.
func additionalAudiences(metadata *EntityDescriptor, audiences []string) ([]string, error) {
	var additional []string

	for _, audience := range audiences {
		if audience == "" {
			return nil, errors.New("an additional audience is empty")
		}

		if slices.Contains(additional, audience) || (metadata != nil && audience == metadata.EntityID) {
			continue
		}

		additional = append(additional, audience)
	}

	return additional, nil
}

// Issuance returns how the Response to this request and its Assertion are issued, as the IssuancePolicy of the
// identity provider decides for a principal with that session, which is nil if there is none. What it returns is
// complete: the SignatureMethod and the AssertionLifetime are never empty, and Sign allows for the
// WantAssertionsSigned of the service provider. An AssertionMaker other than DefaultAssertionMaker uses it for
// the AssertionLifetime, IncludeSessionNotOnOrAfter and AdditionalAudiences of the assertion that it makes;
// MakeAssertionEl and MakeResponse apply the rest, with Session as the session.
func (req *IdpAuthnRequest) Issuance(session *Session) (Issuance, error) {
	if req.ServiceProviderMetadata == nil {
		return Issuance{}, errors.New("the request has no service provider")
	}

	issuanceRequest := IssuanceRequest{
		HTTPRequest:             req.HTTPRequest,
		ServiceProviderMetadata: req.ServiceProviderMetadata,
		SPSSODescriptor:         req.SPSSODescriptor,
		Session:                 session,
	}

	// An assertion that answers a query is issued with a request that has no endpoint and no AuthnRequest.
	if req.ACSEndpoint != nil {
		issuanceRequest.ACSEndpoint, issuanceRequest.AuthnRequest = req.ACSEndpoint, req
	}

	return req.IDP.issuance(issuanceRequest)
}

// signingContextFor returns a context which signs a message for the service provider with that metadata, with
// the SignatureMethod and DigestMethod that the IssuancePolicy gives for it. The metadata is nil when the
// service provider isn't known, and the settings of the identity provider are then used.
func (idp *IdentityProvider) signingContextFor(r *http.Request, metadata *EntityDescriptor) (*dsig.SigningContext, error) {
	if metadata == nil {
		return idp.signingContext()
	}

	issuance, err := idp.issuance(IssuanceRequest{HTTPRequest: r, ServiceProviderMetadata: metadata})
	if err != nil {
		return nil, err
	}

	return idp.signingContextWith(issuance.SignatureMethod, issuance.DigestMethod)
}
