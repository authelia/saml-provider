package saml

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/beevik/etree"
)

// URIRequesterAuthenticator is an interface used by IdentityProvider to learn which service provider sent a
// request on the SAML URI binding (SAMLBind §3.7), which carries no signed message that would name it. It is the
// IdentityProvider.URIRequesterAuthenticator field. The identity provider authenticates nobody itself: an
// implementation does so by HTTP basic authentication, by the client certificate of mutual TLS, or by a header
// that a trusted proxy sets, which are the security models of SAMLConform §3.5.
type URIRequesterAuthenticator interface {
	// AuthenticateURIRequester returns the entity ID of the service provider that sent r, or an empty string if
	// r is not authenticated, which is answered 403 Forbidden. An error is answered 500 Internal Server Error
	// and reported to the Observer.
	AuthenticateURIRequester(r *http.Request) (serviceProviderEntityID string, err error)
}

// assertionURIContentType is the MIME type of an assertion on the SAML URI binding (SAMLBind §3.7.4).
const assertionURIContentType = "application/samlassertion+xml"

// assertionURIEnabled reports whether the identity provider serves the SAML URI binding: it has an
// AssertionURIURL, an AssertionStore to find the assertions in, and a URIRequesterAuthenticator to learn whom
// to give them to.
func (idp *IdentityProvider) assertionURIEnabled() bool {
	return idp.AssertionURIURL.String() != "" && idp.AssertionStore != nil && idp.URIRequesterAuthenticator != nil
}

// ServeAssertionURI handles a request on the SAML URI binding at AssertionURIURL (SAMLBind §3.7), which is a GET
// with a single query parameter, ID, and answers with the assertion of that ID from the AssertionStore, as it was
// stored, with the content type application/samlassertion+xml. The answer is never to be cached (SAMLBind
// §3.7.5.2). Errors are reported by the HTTP status alone, with an empty body (SAMLBind §3.7.5.4).
//
// The URIRequesterAuthenticator names the service provider that sent the request, and an assertion is only
// returned to the service provider it was issued to. A request that isn't a GET is answered 405 Method Not
// Allowed, and one whose query isn't a single ID 400 Bad Request. A requester that isn't authenticated, or whose
// metadata isn't known or has expired, is answered 403 Forbidden. An assertion that is unknown, has expired or was
// issued to another service provider is answered 404 Not Found, in the same way, so that a requester can't learn
// which assertions there are.
//
// The URI binding returns an Assertion, never an EncryptedAssertion, so an assertion that single sign-on would
// encrypt as a whole for the service provider is refused with 403 Forbidden rather than sent in plaintext: that
// is the case for a service provider with an encryption key, unless the IssuancePolicy gives NoAssertionEncryption
// for it. An EncryptedID or EncryptedAttribute in the assertion is returned as it was issued. The requester relies
// on TLS for the identity of the identity provider and the integrity of the assertion (SAMLBind §3.7.3).
//
// Without an AssertionStore or a URIRequesterAuthenticator every request is answered 404 Not Found. Each request
// is reported to the Observer as an EventAssertionURI once the answer is sent, as a failure if it couldn't be.
func (idp *IdentityProvider) ServeAssertionURI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Pragma", "no-cache")

	if idp.AssertionStore == nil || idp.URIRequesterAuthenticator == nil {
		w.WriteHeader(http.StatusNotFound)

		return
	}

	var state requestState

	assertion, code, err := idp.assertionURI(r, &state)

	var body []byte

	if err == nil {
		doc := etree.NewDocument()
		doc.SetRoot(assertion.Copy())

		if body, err = doc.WriteToBytes(); err != nil {
			code, err = http.StatusInternalServerError, ErrServerError.WithDebugf("failed to serialize the assertion: %s", err).WithWrap(err)
		}
	}

	if err != nil {
		idp.observe(r, state.event(EventAssertionURI, err))

		if code == http.StatusMethodNotAllowed {
			w.Header().Set("Allow", http.MethodGet)
		}

		w.WriteHeader(code)

		return
	}

	w.Header().Set("Content-Type", assertionURIContentType)
	w.WriteHeader(http.StatusOK)

	// The status has been sent, so a failure to send the assertion can only be reported.
	if _, err = w.Write(body); err != nil {
		err = ErrServerError.WithDebugf("failed to send the assertion: %s", err).WithWrap(err)
	}

	idp.observe(r, state.event(EventAssertionURI, err))
}

// assertionURI returns the assertion that a request on the SAML URI binding asks for, or the HTTP status to
// answer with and the error to report. state is filled in with the service provider once it is known.
func (idp *IdentityProvider) assertionURI(r *http.Request, state *requestState) (*etree.Element, int, error) {
	if r.Method != http.MethodGet {
		return nil, http.StatusMethodNotAllowed, ErrInvalidRequest.WithDebugf("the method is %s, not GET", r.Method)
	}

	id, err := assertionURIID(r)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}

	entityID, err := idp.URIRequesterAuthenticator.AuthenticateURIRequester(r)

	switch {
	case err != nil:
		return nil, http.StatusInternalServerError, ErrServerError.WithDebugf("failed to authenticate the requester: %s", err).WithWrap(err)
	case entityID == "":
		return nil, http.StatusForbidden, ErrRequestDenied.WithDebug("the requester is not authenticated")
	}

	state.serviceProvider = entityID

	metadata, err := idp.serviceProvider(r, entityID)

	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, http.StatusForbidden, ErrUnknownServiceProvider.WithDebug("the requester is not a known service provider").WithWrap(err)
	case err != nil:
		return nil, http.StatusInternalServerError, ErrServerError.WithDebugf("failed to get the metadata of the service provider: %s", err).WithWrap(err)
	case metadata == nil:
		return nil, http.StatusForbidden, ErrUnknownServiceProvider.WithDebug("the requester is not a known service provider")
	}

	state.serviceProvider, state.verified = metadata.EntityID, true

	assertion, serviceProviderID, err := idp.AssertionStore.GetAssertion(r, id)
	if err != nil {
		return nil, http.StatusInternalServerError, ErrServerError.WithDebugf("cannot get an assertion: %s", err).WithWrap(err)
	}

	// An assertion issued to another service provider is answered as an unknown one, so that the answer
	// doesn't tell a requester which IDs there are.
	if assertion == nil || serviceProviderID != metadata.EntityID || !isAssertionWithID(assertion, id) {
		return nil, http.StatusNotFound, ErrRequestDenied.WithDebug("the assertion is unknown, or was not issued to the requester")
	}

	query := &IdpQueryRequest{IDP: idp, HTTPRequest: r, ServiceProviderMetadata: metadata, Now: TimeNow()}
	shell := query.authnRequest()
	shell.serviceProviderChosen = true

	// A failure of the IssuancePolicy is the fault of the identity provider, not a refusal of the requester.
	if _, err = shell.Issuance(shell.Session); err != nil {
		return nil, http.StatusInternalServerError, ErrServerError.WithDebugf("the IssuancePolicy failed: %s", err).WithWrap(err)
	}

	// The URI binding has no EncryptedAssertion. One that would be encrypted is refused rather than sent in
	// plaintext, and so is one that couldn't be issued at all now, as single sign-on would refuse it too.
	encrypter, err := shell.wholeAssertionEncrypter()

	switch {
	case err != nil:
		return nil, http.StatusForbidden, ErrRequestDenied.WithDebugf("the assertion can't be issued to the service provider in plaintext: %s", err).WithWrap(err)
	case encrypter != nil:
		return nil, http.StatusForbidden, ErrRequestDenied.WithDebug("the assertion would be encrypted for the service provider, which the URI binding can't carry")
	}

	return assertion, http.StatusOK, nil
}

// assertionURIID returns the ID that a request on the SAML URI binding asks for, which is the only query
// parameter and has a single value (SAMLBind §3.7.5.1). The value is an xs:NCName, whose whitespace collapses.
func assertionURIID(r *http.Request) (string, error) {
	query := r.URL.Query()

	values, ok := query["ID"]
	if !ok || len(query) != 1 || len(values) != 1 {
		return "", ErrInvalidRequest.WithDebug("the query must have a single ID parameter and nothing else")
	}

	id := strings.TrimSpace(values[0])
	if id == "" {
		return "", ErrInvalidRequest.WithDebug("the ID parameter is empty")
	}

	return id, nil
}
