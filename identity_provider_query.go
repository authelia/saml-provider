package saml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
)

// samlAssertionNS is the namespace of SAML assertions and their content.
const samlAssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"

// The local names of the requests of the assertion query and request protocol (SAMLCore §3.3) that are served.
const (
	attributeQueryMessage     = "AttributeQuery"
	authnQueryMessage         = "AuthnQuery"
	assertionIDRequestMessage = "AssertionIDRequest"
)

// maxAssertionIDRefs is the most assertions that one AssertionIDRequest may ask for. Each one is looked up and
// encrypted, so this bounds the work of one request.
const maxAssertionIDRefs = 32

// QuerySessionProvider is an optional interface of a SessionProvider, which is required to serve an
// AttributeQuery or an AuthnQuery. Without it those requests receive a Responder status with
// RequestUnsupported, and their services are not listed in the metadata.
//
// It finds the principal that a query from a service provider names. The request comes from the server of the
// service provider, not the browser of the principal, so it carries no session cookie, and has been verified
// to come from the service provider in req.ServiceProviderMetadata. The NameID is whatever that service
// provider sent: an implementation must only answer for a NameID that the identity provider asserted to that
// service provider, or to an affiliation it belongs to, and so must check the SPNameQualifier where the format
// has one, and decide for itself whether a NameID without one, such as an email address, may be queried by
// this service provider. A transient NameID can only be found by an application whose NameIDProvider, or
// SessionParticipantProvider, stores the ones it issues.
type QuerySessionProvider interface {
	// GetQuerySubject returns a Session describing the principal that nameID identifies for the service
	// provider of req, for an AttributeQuery, or nil if there is none, which sends a Success status with no
	// assertion (SAMLCore §3.3.4), as GetAuthnSessions does. Only the fields of the Session that hold the
	// attributes of the user are used, and the principal doesn't need to be logged in. nameID is copied to the
	// assertion unchanged.
	//
	// An error sends a Responder status, and is not sent to the service provider.
	GetQuerySubject(r *http.Request, req *IdpQueryRequest, nameID *NameID) (*Session, error)

	// GetAuthnSessions returns the active sessions of the principal that nameID identifies for the service
	// provider of req, for an AuthnQuery, each of which is stated with its CreateTime, Index and
	// AuthnContextClassRef. It should return only the sessions in which the service provider was sent an
	// assertion, as the others are no business of it. It returns an empty slice and no error when there is
	// no such principal or session, which sends a Success status with no assertion (SAMLCore §3.3.4).
	//
	// An error sends a Responder status, and is not sent to the service provider.
	GetAuthnSessions(r *http.Request, req *IdpQueryRequest, nameID *NameID) ([]*Session, error)
}

// AssertionStore keeps the assertions that the identity provider issues, so that a service provider can fetch
// one by its ID with an AssertionIDRequest (SAMLCore §3.3.1). It is the IdentityProvider.AssertionStore field.
type AssertionStore interface {
	// SaveAssertion is called with each assertion as issued, signed and before it is encrypted, and the
	// entity ID of the service provider it was issued to: by single sign-on, and for the answer to an
	// AttributeQuery or AuthnQuery. assertion belongs to the store. notOnOrAfter is the end of the validity
	// of the assertion, after which there is no use in keeping it, or the zero time if it has no Conditions.
	// The assertion is a bearer token until then, and holds the attributes of the principal, so it must be
	// stored as carefully as a session.
	//
	// An error is logged and doesn't fail the request that issued the assertion.
	SaveAssertion(r *http.Request, serviceProviderEntityID string, assertion *etree.Element, notOnOrAfter time.Time) error

	// GetAssertion returns the saved assertion with that ID and the entity ID of the service provider it
	// was issued to, or a nil assertion and no error if it is unknown or has expired. The assertion is only
	// returned to that service provider, and is not modified. r is a request from the server of the service
	// provider.
	//
	// An error sends a Responder status, and is not sent to the service provider.
	GetAssertion(r *http.Request, id string) (assertion *etree.Element, serviceProviderEntityID string, err error)
}

// IdpQueryRequest is used by IdentityProvider to handle a single request of the assertion query and request
// protocol from a service provider (SAMLCore §3.3): an AttributeQuery, an AuthnQuery or an AssertionIDRequest.
// Exactly one of those fields is set, according to the service that received it.
type IdpQueryRequest struct {
	IDP           *IdentityProvider
	HTTPRequest   *http.Request
	RequestBuffer []byte

	// ServiceProviderMetadata is the metadata of the service provider that signed the request.
	ServiceProviderMetadata *EntityDescriptor

	AttributeQuery     *AttributeQuery
	AuthnQuery         *AuthnQuery
	AssertionIDRequest *AssertionIDRequest

	Now time.Time

	// message is the local name of the request that the service accepts, and endpoint is the URL of the
	// service, which a Destination must be.
	message, endpoint string

	// id is the ID of the request, which the response is in answer to.
	id string

	// verified is the element that the signature of the service provider covers.
	verified *etree.Element
}

// queryHeader is the content of RequestAbstractType (SAMLCore §3.2.1) that is checked for every request.
type queryHeader struct {
	ID           string
	Version      string
	IssueInstant time.Time
	Destination  string
	Issuer       *Issuer
}

// ServeAttributeQuery handles a SAML AttributeQuery from a service provider on the SOAP binding, at
// AttributeServiceURL, and answers on the same connection with a signed Response in a SOAP envelope (SAMLProfiles
// §6, SAMLCore §3.3.2.3). The SessionProvider must implement QuerySessionProvider, which finds the principal that
// the Subject of the query names.
//
// The attributes are those that single sign-on can state about the principal, released by the
// AttributeReleasePolicy, and then narrowed to the ones the query names. DefaultAttributeReleasePolicy releases no
// more than it does for single sign-on to the default AttributeConsumingService of the metadata of the service
// provider, so a query is not answered with anything that single sign-on would withhold. A query that
// names no attributes asks for all of them. The answer is one assertion with one AttributeStatement, whose Subject
// is the NameID of the query with no SubjectConfirmation, signed, and encrypted as for single sign-on if the
// service provider has an encryption key. If nothing is released the answer is Success with no assertion
// (SAMLCore §3.3.4).
//
// The request must carry an enveloped signature by its issuer, as there is nothing else on the binding to
// authenticate it with. Every SAML message gets a Response: one that is not an AttributeQuery gets
// Requester/RequestUnsupported, one that can't be verified gets Requester/RequestDenied, and one that is verified
// but expired, for another destination or of another version gets the matching error status. A Subject that is an
// EncryptedID or BaseID, or that has a SubjectConfirmation, gets Requester/RequestUnsupported; a NameID whose
// SPNameQualifier is not the service provider or an affiliation it is a member of gets Requester/RequestDenied;
// and a principal that is not found gets Success with no assertion, as when nothing is released, so that the
// answer doesn't tell which principals exist. A request that was already answered gets Requester/RequestDenied
// (SAMLSec §6.1.2), and a failure of the ReplayStore Responder. A request that is not a POST gets
// StatusMethodNotAllowed, one that is not a SOAP 1.1 envelope gets a Client fault, and a failure to sign or write
// the response gets a Server fault.
func (idp *IdentityProvider) ServeAttributeQuery(w http.ResponseWriter, r *http.Request) {
	idp.serveQuery(w, r, attributeQueryMessage, idp.AttributeServiceURL)
}

// ServeAuthnQuery handles a SAML AuthnQuery from a service provider on the SOAP binding, at AuthnQueryServiceURL,
// and answers on the same connection with a signed Response in a SOAP envelope (SAMLProfiles §6, SAMLCore
// §3.3.2.2). The SessionProvider must implement QuerySessionProvider, which finds the sessions of the principal
// that the Subject of the query names. Nobody is authenticated by a query.
//
// The sessions are narrowed to the one with the SessionIndex of the query, if it has one, and to those that the
// AuthnContextEnforcer finds to satisfy its RequestedAuthnContext, if it has one. The answer is one assertion with
// an AuthnStatement for each session that is left, made like that of ServeAttributeQuery, or Success with no
// assertion if none is left (SAMLCore §3.3.4).
//
// Requests are authenticated and refused as ServeAttributeQuery describes.
func (idp *IdentityProvider) ServeAuthnQuery(w http.ResponseWriter, r *http.Request) {
	idp.serveQuery(w, r, authnQueryMessage, idp.AuthnQueryServiceURL)
}

// ServeAssertionIDRequest handles a SAML AssertionIDRequest from a service provider on the SOAP binding, at
// AssertionIDRequestServiceURL, and answers on the same connection with a signed Response in a SOAP envelope
// (SAMLProfiles §6, SAMLCore §3.3.1). The identity provider must have an AssertionStore, and otherwise the answer
// is Responder/RequestUnsupported.
//
// An assertion is only returned to the service provider it was issued to, which is stricter than SAMLCore
// requires, so that a service provider can't fetch the assertions of another by their IDs. It is returned as it
// was signed, and encrypted again as for single sign-on if the service provider has an encryption key. An ID that
// is unknown, expired or of an assertion issued to another service provider is left out, and if none is left the
// answer is Success with no assertion (SAMLCore §3.3.4). A request for more than 32 assertions gets
// Responder/TooManyResponses.
//
// Requests are authenticated and refused as ServeAttributeQuery describes.
func (idp *IdentityProvider) ServeAssertionIDRequest(w http.ResponseWriter, r *http.Request) {
	idp.serveQuery(w, r, assertionIDRequestMessage, idp.AssertionIDRequestServiceURL)
}

// serveQuery handles a request of the assertion query and request protocol whose local name must be message, at
// the service with the URL endpoint.
func (idp *IdentityProvider) serveQuery(w http.ResponseWriter, r *http.Request, message string, endpoint url.URL) {
	soap, ok := idp.receiveSOAPRequest(w, r)
	if !ok {
		return
	}

	req := &IdpQueryRequest{
		IDP:           idp,
		HTTPRequest:   r,
		RequestBuffer: soap.Body,
		Now:           TimeNow(),
		message:       message,
		endpoint:      endpoint.String(),
	}

	var (
		assertions []*etree.Element
		err        error
	)

	if soap.Message.Tag != message || soap.Message.NamespaceURI() != samlProtocolNS {
		// The response answers it only if the ID is valid.
		req.id = soap.Message.SelectAttrValue("ID", "")
		err = &statusError{StatusRequester, StatusRequestUnsupported, fmt.Errorf("the message is not an %s", message)}
	} else {
		assertions, err = req.answer()
	}

	status := Status{StatusCode: StatusCode{Value: StatusSuccess}}

	if err != nil {
		idp.logger().Printf("failed to handle SOAP %s: %s", message, err)

		// An error that carries no status is not the fault of the requester, and its text is never sent.
		if status, ok = RequestStatus(err); !ok {
			status = Status{StatusCode: StatusCode{Value: StatusResponder}}
		}
	}

	if err = req.writeResponse(w, status, assertions); err != nil {
		idp.logger().Printf("failed to write SOAP %s response: %s", message, err)
		writeSOAPFault(w, &soapFault{Code: "Server", String: soapFaultStringProcessing})
	}
}

// answer validates the request and returns the assertions that answer it, each signed and possibly encrypted,
// which may be none. An error that carries no status means Responder.
func (req *IdpQueryRequest) answer() ([]*etree.Element, error) {
	if err := req.validate(); err != nil {
		if _, ok := RequestStatus(err); ok {
			return nil, err
		}

		// Anything that failed before the request stage is a request that can't be trusted.
		return nil, &statusError{StatusRequester, StatusRequestDenied, err}
	}

	switch req.message {
	case attributeQueryMessage:
		return req.answerAttributeQuery()
	case authnQueryMessage:
		return req.answerAuthnQuery()
	default:
		return req.answerAssertionIDRequest()
	}
}

// validate checks that the request is valid and signed by its service provider, and assigns
// ServiceProviderMetadata and the request field from the content that the signature covers. An error that is
// not a *statusError happened before the requester was verified.
func (req *IdpQueryRequest) validate() error {
	// This code runs before any authentication. The size of the request is limited by soapMaxMessageSize.
	if err := xrv.Validate(bytes.NewReader(req.RequestBuffer)); err != nil {
		return err
	}

	if err := req.unmarshal(func(v any) error { return xml.Unmarshal(req.RequestBuffer, v) }); err != nil {
		return err
	}

	if err := req.checkTrust(); err != nil {
		return err
	}

	doc := etree.NewDocument()

	if err := doc.ReadFromBytes(req.RequestBuffer); err != nil {
		return err
	}

	if doc.Root() == nil {
		return errors.New("request has no root element")
	}

	serviceProviderID := req.header().Issuer.Value

	metadata, verified, err := req.IDP.verifySOAPRequester(req.HTTPRequest, doc.Root(), serviceProviderID)
	if err != nil {
		return err
	}

	// The request is replaced with the content that the signature covers, and the trust checks that were made
	// on the original are repeated, as IdpAuthnRequest.useVerifiedRequest does.
	if err = req.unmarshal(func(v any) error { return unmarshalElement(verified, v) }); err != nil {
		return err
	}

	if err = req.checkTrust(); err != nil {
		return err
	}

	if req.header().Issuer.Value != serviceProviderID {
		return errors.New("signed request has a different issuer")
	}

	req.ServiceProviderMetadata, req.verified = metadata, verified

	if err = req.checkRequestStage(); err != nil {
		return err
	}

	return req.checkReplay()
}

// checkReplay consumes the ID of the request in the ReplayStore of the identity provider (SAMLSec §6.1.2). It is
// the last check of validate, so the request is verified, and only a registered service provider can add to the
// store. The ID is recorded for the kind of the message until the request would be refused for its age, which is
// MaxIssueDelay and MaxClockSkew after its IssueInstant, and MaxClockSkew longer. The error is a *statusError: Requester with
// RequestDenied for a replay, and Responder if the store failed.
func (req *IdpQueryRequest) checkReplay() error {
	header := req.header()

	kind := replayKindAssertionIDRequest

	switch req.message {
	case attributeQueryMessage:
		kind = replayKindAttributeQuery
	case authnQueryMessage:
		kind = replayKindAuthnQuery
	}

	return req.IDP.checkReplay(requestContext(req.HTTPRequest), kind, header.Issuer.Value, header.ID,
		header.IssueInstant.Add(MaxIssueDelay))
}

// unmarshal replaces the request field of the message of the service with one that decode fills.
func (req *IdpQueryRequest) unmarshal(decode func(v any) error) error {
	req.AttributeQuery, req.AuthnQuery, req.AssertionIDRequest, req.id = nil, nil, nil, ""

	var err error

	switch req.message {
	case attributeQueryMessage:
		query := &AttributeQuery{}
		if err = decode(query); err == nil {
			req.AttributeQuery = query
		}
	case authnQueryMessage:
		query := &AuthnQuery{}
		if err = decode(query); err == nil {
			req.AuthnQuery = query
		}
	default:
		request := &AssertionIDRequest{}
		if err = decode(request); err == nil {
			req.AssertionIDRequest = request
		}
	}

	if err != nil {
		return err
	}

	req.id = req.header().ID

	return nil
}

// header returns the common content of the request.
func (req *IdpQueryRequest) header() queryHeader {
	switch {
	case req.AttributeQuery != nil:
		r := req.AttributeQuery

		return queryHeader{r.ID, r.Version, r.IssueInstant, r.Destination, r.Issuer}
	case req.AuthnQuery != nil:
		r := req.AuthnQuery

		return queryHeader{r.ID, r.Version, r.IssueInstant, r.Destination, r.Issuer}
	case req.AssertionIDRequest != nil:
		r := req.AssertionIDRequest

		return queryHeader{r.ID, r.Version, r.IssueInstant, r.Destination, r.Issuer}
	default:
		return queryHeader{}
	}
}

// checkTrust makes the checks on the identity of the request that are needed before the service provider can
// be looked up. SAMLProfiles §6.4.1 requires the Issuer.
func (req *IdpQueryRequest) checkTrust() error {
	header := req.header()

	if !isValidAuthnRequestID(header.ID) {
		// The value is not included because this error is logged without authentication.
		return errors.New("invalid request ID")
	}

	if header.Issuer == nil || header.Issuer.Value == "" {
		return errors.New("request has no issuer")
	}

	return nil
}

// checkRequestStage makes the checks on the content of the request that are reported to the service provider
// with a status of their own. It must only run once the requester is verified, on the content that the
// signature covers. The error is a *statusError.
func (req *IdpQueryRequest) checkRequestStage() error {
	header := req.header()

	if statusErr := versionStatus(header.Version); statusErr != nil {
		return statusErr
	}

	if err := checkIssueInstant("request", header.IssueInstant, req.Now, MaxIssueDelay); err != nil {
		return &statusError{StatusRequester, StatusRequestDenied, err}
	}

	// SAMLBind §3.2 doesn't require a Destination on SOAP, but SAMLCore §3.2.1 requires one that is present to
	// be the location the message was received at.
	if header.Destination != "" && header.Destination != req.endpoint {
		return &statusError{StatusRequester, StatusRequestDenied,
			fmt.Errorf("expected destination to be %q, not %q", req.endpoint, header.Destination)}
	}

	return nil
}

// subjectNameID returns a copy of the NameID that the Subject of a query names the principal with, which the
// assertions in answer to it must carry unchanged (SAMLCore §3.3.4). The error is a *statusError, or means
// Responder.
func (req *IdpQueryRequest) subjectNameID(subject *Subject) (*NameID, error) {
	// SAMLCore §3.3.2.1 requires the Subject.
	if subject == nil {
		return nil, &statusError{StatusRequester, "", errors.New("the query has no Subject")}
	}

	if identifier := unsupportedSubjectIdentifier(req.verified); identifier != "" {
		return nil, &statusError{StatusRequester, StatusRequestUnsupported,
			fmt.Errorf("the Subject of the query has a %s, which is not supported", identifier)}
	}

	// SAMLCore §3.3.4 requires the Subject of the assertion to be confirmable in a manner that the query
	// lists, and the assertions made here have no SubjectConfirmation at all.
	if len(subject.SubjectConfirmations) != 0 {
		return nil, &statusError{StatusRequester, StatusRequestUnsupported,
			errors.New("the Subject of the query has a SubjectConfirmation, which is not supported")}
	}

	if subject.NameID == nil || subject.NameID.Value == "" {
		return nil, &statusError{StatusRequester, StatusUnknownPrincipal, errors.New("the Subject of the query has no NameID")}
	}

	nameID := *subject.NameID

	// A NameID that is qualified with another service provider was not asserted to this one, unless it is an
	// affiliation that this one is a member of (SAMLCore §2.2.2, §8.3.7).
	serviceProviderID := req.ServiceProviderMetadata.EntityID

	if nameID.SPNameQualifier != "" && nameID.SPNameQualifier != serviceProviderID {
		err := req.IDP.checkAffiliation(req.HTTPRequest, serviceProviderID, nameID.SPNameQualifier)

		switch {
		case errors.Is(err, ErrInvalidNameIDPolicy):
			return nil, &statusError{StatusRequester, StatusRequestDenied,
				errors.New("the SPNameQualifier of the NameID is not the service provider or an affiliation it is a member of")}
		case err != nil:
			return nil, err
		}
	}

	return &nameID, nil
}

// unsupportedSubjectIdentifier returns the local name of a BaseID or EncryptedID in the Subject of the query
// element, or "" if it has neither. Subject doesn't hold these identifiers, so they are looked for in the content
// that was verified.
func unsupportedSubjectIdentifier(query *etree.Element) string {
	for _, child := range query.ChildElements() {
		if child.Tag != "Subject" || child.NamespaceURI() != samlAssertionNS {
			continue
		}

		for _, identifier := range child.ChildElements() {
			if identifier.NamespaceURI() == samlAssertionNS && (identifier.Tag == "BaseID" || identifier.Tag == "EncryptedID") {
				return identifier.Tag
			}
		}
	}

	return ""
}

// answerAttributeQuery returns the assertion that states the attributes an AttributeQuery asks for, or none if
// no attribute is released.
func (req *IdpQueryRequest) answerAttributeQuery() ([]*etree.Element, error) {
	provider, ok := req.IDP.SessionProvider.(QuerySessionProvider)
	if !ok {
		return nil, &statusError{StatusResponder, StatusRequestUnsupported,
			errors.New("the session provider does not implement QuerySessionProvider")}
	}

	query := req.AttributeQuery

	if err := checkQueriedAttributes(query.Attributes); err != nil {
		return nil, err
	}

	nameID, err := req.subjectNameID(query.Subject)
	if err != nil {
		return nil, err
	}

	session, err := provider.GetQuerySubject(req.HTTPRequest, req, nameID)
	if err != nil {
		return nil, fmt.Errorf("cannot find the subject of the query: %w", err)
	}

	// SAMLCore §3.3.4: there is nothing to state about a principal that is not known, so the response has no
	// assertion and is a Success, as for an AuthnQuery. UnknownPrincipal would tell the service provider which
	// principals exist.
	if session == nil {
		return nil, nil
	}

	// A query is never answered with more than single sign-on states without an AttributeConsumingServiceIndex.
	ceiling := defaultAttributeConsumingService(req.spSSODescriptor().AttributeConsumingServices)

	candidates, err := req.IDP.principalAttributes(req.HTTPRequest, req.ServiceProviderMetadata, ceiling, session)
	if err != nil {
		return nil, fmt.Errorf("cannot collect attributes: %w", err)
	}

	released, err := req.IDP.attributeReleasePolicy().ReleaseAttributes(AttributeReleaseRequest{
		HTTPRequest:             req.HTTPRequest,
		ServiceProviderMetadata: req.ServiceProviderMetadata,
		Ceiling:                 ceiling,
		Requested:               query.Attributes,
		Query:                   req,
	}, session, candidates)
	if err != nil {
		return nil, fmt.Errorf("cannot release attributes: %w", err)
	}

	// The policy decides among every candidate, as it does for single sign-on, so that what it requires or
	// chooses doesn't depend on what the query names. SAMLCore §3.3.2.3: an attribute that is returned MUST NOT
	// contain a value that the query doesn't list, whatever the policy decided.
	released = narrowToQueriedAttributes(query.Attributes, released)

	// SAMLCore §3.3.4: with nothing to state, the response has no assertion and is a Success.
	if len(released) == 0 {
		return nil, nil
	}

	assertion := req.newAssertion(nameID)
	assertion.AttributeStatements = []AttributeStatement{{Attributes: released}}

	return req.issueAssertion(assertion)
}

// checkQueriedAttributes returns an error if the attributes that a query lists are not valid: SAMLCore §2.7.3.1
// requires each to have a Name, and §3.3.2.3 forbids two with the same Name and NameFormat.
func checkQueriedAttributes(queried []Attribute) error {
	for i, attribute := range queried {
		if attribute.Name == "" {
			return &statusError{StatusRequester, StatusInvalidAttrNameOrValue, errors.New("the query lists an attribute with no Name")}
		}

		if slices.ContainsFunc(queried[:i], func(other Attribute) bool {
			return other.Name == attribute.Name && cmpAttrNameFormat(other.NameFormat) == cmpAttrNameFormat(attribute.NameFormat)
		}) {
			return &statusError{StatusRequester, StatusInvalidAttrNameOrValue, errors.New("the query lists an attribute twice")}
		}
	}

	return nil
}

// cmpAttrNameFormat returns nameFormat, or the unspecified format when it is missing (SAMLCore §2.7.3.1 and
// errata E89).
func cmpAttrNameFormat(nameFormat string) string {
	if nameFormat == "" {
		return unspecifiedAttrNameFormat
	}

	return nameFormat
}

// narrowToQueriedAttributes returns the parts of attributes that an AttributeQuery listing queried asks for
// (SAMLCore §3.3.2.3): all of them if it lists none, and otherwise those it lists by Name and a compatible
// NameFormat, with only the values it lists for any that it lists values of.
func narrowToQueriedAttributes(queried, attributes []Attribute) []Attribute {
	if len(queried) == 0 {
		return attributes
	}

	var narrowed []Attribute

	for _, candidate := range attributes {
		if attribute, ok := narrowAttribute(queried, candidate); ok {
			narrowed = append(narrowed, attribute)
		}
	}

	return narrowed
}

// answerAuthnQuery returns the assertion that states the authentications an AuthnQuery asks for, or none if
// there is none to state.
func (req *IdpQueryRequest) answerAuthnQuery() ([]*etree.Element, error) {
	provider, ok := req.IDP.SessionProvider.(QuerySessionProvider)
	if !ok {
		return nil, &statusError{StatusResponder, StatusRequestUnsupported,
			errors.New("the session provider does not implement QuerySessionProvider")}
	}

	query := req.AuthnQuery

	nameID, err := req.subjectNameID(query.Subject)
	if err != nil {
		return nil, err
	}

	sessions, err := provider.GetAuthnSessions(req.HTTPRequest, req, nameID)
	if err != nil {
		return nil, fmt.Errorf("cannot find the sessions of the subject of the query: %w", err)
	}

	enforcer := req.IDP.authnContextEnforcer()

	var statements []AuthnStatement

	// The SessionIndex and RequestedAuthnContext of the query are filters (SAMLCore §3.3.2.2). The order of the
	// requested classes means nothing for a query (errata E45 to §3.3.2.2.1), only whether a session satisfies them.
	for _, session := range sessions {
		if session == nil || (query.SessionIndex != "" && session.Index != query.SessionIndex) {
			continue
		}

		if query.RequestedAuthnContext != nil && enforcer.SatisfiesAuthnContext(query.RequestedAuthnContext, session) != nil {
			continue
		}

		statements = append(statements, AuthnStatement{
			AuthnInstant:    session.CreateTime,
			SessionIndex:    session.Index,
			SubjectLocality: sessionSubjectLocality(session),
			AuthnContext: AuthnContext{
				AuthnContextClassRef: &AuthnContextClassRef{Value: sessionAuthnContextClassRef(session)},
			},
		})
	}

	// SAMLCore §3.3.4: with nothing to state, the response has no assertion and is a Success.
	if len(statements) == 0 {
		return nil, nil
	}

	assertion := req.newAssertion(nameID)
	assertion.AuthnStatements = statements

	return req.issueAssertion(assertion)
}

// sessionSubjectLocality returns the SubjectLocality of the ClientAddress of session, or nil if it has none. The
// address of the HTTP request is never used for a query, as it is that of the service provider.
func sessionSubjectLocality(session *Session) *SubjectLocality {
	ip, err := netip.ParseAddr(session.ClientAddress)
	if err != nil {
		return nil
	}

	return &SubjectLocality{Address: ip.WithZone("").String()}
}

// answerAssertionIDRequest returns the assertions that an AssertionIDRequest names and that were issued to its
// service provider, each as it was signed, and encrypted again if the service provider has an encryption key.
func (req *IdpQueryRequest) answerAssertionIDRequest() ([]*etree.Element, error) {
	store := req.IDP.AssertionStore
	if store == nil {
		return nil, &statusError{StatusResponder, StatusRequestUnsupported, errors.New("the identity provider has no AssertionStore")}
	}

	refs := req.AssertionIDRequest.AssertionIDRefs

	switch {
	case len(refs) == 0:
		// SAMLCore §3.3.1 requires at least one.
		return nil, &statusError{StatusRequester, "", errors.New("the request has no AssertionIDRef")}
	case len(refs) > maxAssertionIDRefs:
		return nil, &statusError{StatusResponder, StatusTooManyResponses,
			fmt.Errorf("the request has more than %d AssertionIDRef elements", maxAssertionIDRefs)}
	}

	var (
		assertions []*etree.Element
		seen       []string
	)

	shell := req.authnRequest()

	for _, ref := range refs {
		// The value is an xs:NCName, whose whitespace collapses.
		id := strings.TrimSpace(ref.Value)
		if id == "" || slices.Contains(seen, id) {
			continue
		}

		seen = append(seen, id)

		assertion, serviceProviderID, err := store.GetAssertion(req.HTTPRequest, id)
		if err != nil {
			return nil, fmt.Errorf("cannot get an assertion: %w", err)
		}

		// An assertion issued to another service provider is treated as unknown, which is stricter than the
		// audience rule a requester would apply itself, so that one can't fetch those of another by guessing.
		if assertion == nil || serviceProviderID != req.ServiceProviderMetadata.EntityID || !isAssertionWithID(assertion, id) {
			continue
		}

		el, err := shell.encryptAssertionEl(assertion.Copy())
		if err != nil {
			return nil, fmt.Errorf("cannot encrypt an assertion: %w", err)
		}

		assertions = append(assertions, el)
	}

	return assertions, nil
}

// isAssertionWithID reports whether el is a SAML assertion with that ID, which guards against a store that
// returns something else.
func isAssertionWithID(el *etree.Element, id string) bool {
	return el.Tag == "Assertion" && el.NamespaceURI() == samlAssertionNS && el.SelectAttrValue("ID", "") == id
}

// spSSODescriptor returns the descriptor of the service provider whose AttributeConsumingService elements and
// encryption key are used for a query, which is its first. There is no AssertionConsumerService to pick it by.
func (req *IdpQueryRequest) spSSODescriptor() *SPSSODescriptor {
	if len(req.ServiceProviderMetadata.SPSSODescriptors) == 0 {
		return &SPSSODescriptor{}
	}

	return &req.ServiceProviderMetadata.SPSSODescriptors[0]
}

// authnRequest returns an IdpAuthnRequest for the service provider of the query with no request, so that an
// assertion is signed, saved and encrypted for it by the code that does so for single sign-on.
func (req *IdpQueryRequest) authnRequest() *IdpAuthnRequest {
	return &IdpAuthnRequest{
		IDP:                     req.IDP,
		HTTPRequest:             req.HTTPRequest,
		ServiceProviderMetadata: req.ServiceProviderMetadata,
		SPSSODescriptor:         req.spSSODescriptor(),
		Now:                     req.Now,
	}
}

// newAssertion returns an assertion about the principal that nameID names, for the service provider of the
// query, with no statements. Its Subject is the NameID of the query, so that it strongly matches (SAMLCore
// §3.3.4), and has no SubjectConfirmation, as the assertion is not for presenting to anyone.
func (req *IdpQueryRequest) newAssertion(nameID *NameID) *Assertion {
	return &Assertion{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		IssueInstant: req.Now,
		Version:      "2.0",
		Issuer: Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  req.IDP.entityID(),
		},
		Subject: &Subject{NameID: nameID},
		Conditions: &Conditions{
			NotBefore:    req.Now.Add(-1 * MaxClockSkew),
			NotOnOrAfter: req.Now.Add(MaxIssueDelay),
			AudienceRestrictions: []AudienceRestriction{
				{Audiences: []Audience{{Value: req.ServiceProviderMetadata.EntityID}}},
			},
		},
	}
}

// issueAssertion signs assertion, saves it in the AssertionStore, and encrypts it if the service provider has
// an encryption key, as single sign-on does.
func (req *IdpQueryRequest) issueAssertion(assertion *Assertion) ([]*etree.Element, error) {
	shell := req.authnRequest()
	shell.Assertion = assertion

	// What the service provider may not do with the assertion of single sign-on, it may not do with this one.
	issuance, err := shell.Issuance(nil)
	if err != nil {
		return nil, fmt.Errorf("cannot make the assertion: %w", err)
	}

	if assertion.Conditions != nil {
		assertion.Conditions.ProxyRestriction = issuance.ProxyRestriction.clone()
	}

	if err := shell.MakeAssertionEl(); err != nil {
		return nil, fmt.Errorf("cannot make the assertion: %w", err)
	}

	return []*etree.Element{shell.AssertionEl}, nil
}

// writeResponse answers the request on w with a signed Response in a SOAP envelope, which has the given status
// and assertions. It has no Destination, as it goes back on the connection of the request, and no InResponseTo
// when the ID of the request is not valid. SAMLProfiles §6.4.2 requires the Issuer.
func (req *IdpQueryRequest) writeResponse(w http.ResponseWriter, status Status, assertions []*etree.Element) error {
	response := &Response{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		Version:      "2.0",
		IssueInstant: req.Now,
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  req.IDP.entityID(),
		},
		Status: status,
	}

	if isValidAuthnRequestID(req.id) {
		response.InResponseTo = req.id
	}

	element := func() *etree.Element {
		el := response.Element()
		for _, assertion := range assertions {
			el.AddChild(assertion)
		}

		return el
	}

	signingContext, err := req.IDP.signingContextFor(req.HTTPRequest, req.ServiceProviderMetadata)
	if err != nil {
		return err
	}

	signedEl, err := signingContext.SignEnveloped(element())
	if err != nil {
		return err
	}

	// SAMLCore requires the signature to follow the Issuer, rather than come last.
	response.Signature = signedEl.ChildElements()[len(signedEl.ChildElements())-1]

	return writeSOAPResponse(w, nil, element())
}

// saveAssertion saves the signed assertion of req in the AssertionStore of the identity provider, if it has
// one. A failure is logged, and doesn't stop the assertion being issued.
func (req *IdpAuthnRequest) saveAssertion(signedAssertionEl *etree.Element) {
	if req.IDP == nil || req.IDP.AssertionStore == nil || req.ServiceProviderMetadata == nil {
		return
	}

	var notOnOrAfter time.Time
	if req.Assertion.Conditions != nil {
		notOnOrAfter = req.Assertion.Conditions.NotOnOrAfter
	}

	err := req.IDP.AssertionStore.SaveAssertion(req.HTTPRequest, req.ServiceProviderMetadata.EntityID, signedAssertionEl.Copy(), notOnOrAfter)
	if err != nil {
		req.IDP.logger().Printf("failed to save assertion: %s", err)
	}
}

// addQueryMetadata adds the services of the assertion query and request protocol to the metadata, each only
// when its URL is set and what it needs is there: an AttributeAuthorityDescriptor (SAMLMeta §2.4.7) and an
// AuthnAuthorityDescriptor (SAMLMeta §2.4.5) with a QuerySessionProvider, and an AssertionIDRequestService in
// those and in the IDPSSODescriptor (SAMLMeta §2.4.3) with an AssertionStore.
func (idp *IdentityProvider) addQueryMetadata(ed *EntityDescriptor, keyDescriptors []KeyDescriptor, nameIDFormats []NameIDFormat) {
	_, queries := idp.SessionProvider.(QuerySessionProvider)

	role := RoleDescriptor{
		ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
		KeyDescriptors:             keyDescriptors,
	}

	var assertionIDRequestServices []Endpoint
	if idp.AssertionStore != nil && idp.AssertionIDRequestServiceURL.String() != "" {
		assertionIDRequestServices = []Endpoint{{Binding: SOAPBinding, Location: idp.AssertionIDRequestServiceURL.String()}}
	}

	ed.IDPSSODescriptors[0].AssertionIDRequestServices = assertionIDRequestServices

	if queries && idp.AuthnQueryServiceURL.String() != "" {
		ed.AuthnAuthorityDescriptors = []AuthnAuthorityDescriptor{{
			RoleDescriptor:             role,
			AuthnQueryServices:         []Endpoint{{Binding: SOAPBinding, Location: idp.AuthnQueryServiceURL.String()}},
			AssertionIDRequestServices: assertionIDRequestServices,
			NameIDFormats:              nameIDFormats,
		}}
	}

	if queries && idp.AttributeServiceURL.String() != "" {
		ed.AttributeAuthorityDescriptors = []AttributeAuthorityDescriptor{{
			RoleDescriptor:             role,
			AttributeServices:          []Endpoint{{Binding: SOAPBinding, Location: idp.AttributeServiceURL.String()}},
			AssertionIDRequestServices: assertionIDRequestServices,
			NameIDFormats:              nameIDFormats,
		}}
	}
}
