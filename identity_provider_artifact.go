package saml

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // SAMLBind §3.6.4 makes the SourceID of an artifact the SHA-1 of the entity ID.
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
)

const (
	// artifactTypeCode is the type code of the one artifact format of SAML V2.0 (SAMLBind §3.6.4.2). No other
	// format may be used with the binding (errata E4).
	artifactTypeCode = 0x0004

	// artifactSize is the size of an artifact of that type before it is encoded: the type code, the endpoint
	// index, the SourceID and the MessageHandle.
	artifactSize = 2 + 2 + 20 + 20

	// artifactResolutionServiceIndex is the index of the one ArtifactResolutionService in the metadata of the
	// identity provider, and so the EndpointIndex of every artifact it issues (SAMLProf §5.5).
	artifactResolutionServiceIndex = 0

	// replayKindArtifact is the kind of the key an artifact has in the ArtifactStore and the ReplayStore.
	replayKindArtifact = "artifact"
)

// DefaultArtifactLifetime is how long an artifact can be resolved for when IdentityProvider.ArtifactLifetime is
// not set. SAMLCore §3.5.3 asks for the shortest practical time: the service provider resolves the artifact
// while it handles the request that delivers it.
const DefaultArtifactLifetime = time.Minute

// DefaultMemoryArtifactStoreCapacity is the capacity of the MemoryArtifactStore an IdentityProvider uses when
// it has no ArtifactStore.
const DefaultMemoryArtifactStoreCapacity = 4096

// ErrArtifactStoreFull is returned by MemoryArtifactStore.SaveArtifact when the store holds its capacity of
// messages that have not expired. The response that was to be delivered by artifact is then not sent.
var ErrArtifactStoreFull = errors.New("the artifact store is full")

// Artifact is a SAML V2.0 artifact, of type 0x0004 (SAMLBind §3.6.4.2): a reference to a protocol message that
// is passed through the browser in its place with the HTTP-Artifact binding, and exchanged for the message with
// the artifact resolution protocol (SAMLCore §3.5).
type Artifact struct {
	// EndpointIndex is the index of the ArtifactResolutionService of the issuer to resolve the artifact at.
	EndpointIndex uint16

	// SourceID identifies the issuer. It is ArtifactSourceID of its entity ID.
	SourceID [20]byte

	// MessageHandle identifies the message at the issuer. It is random and says nothing about the message.
	MessageHandle [20]byte
}

// ArtifactSourceID returns the SourceID of the artifacts of the entity: the SHA-1 hash of its entity ID
// (SAMLBind §3.6.4).
func ArtifactSourceID(entityID string) [20]byte {
	return sha1.Sum([]byte(entityID)) //nolint:gosec // As above: the specification names the hash, which only identifies the issuer.
}

// String returns the artifact as it is sent in the SAMLart parameter: the base64 of the type code, the endpoint
// index, the SourceID and the MessageHandle (SAMLBind §3.6.4).
func (a Artifact) String() string {
	buf := make([]byte, 0, artifactSize)
	buf = binary.BigEndian.AppendUint16(buf, artifactTypeCode)
	buf = binary.BigEndian.AppendUint16(buf, a.EndpointIndex)
	buf = append(buf, a.SourceID[:]...)
	buf = append(buf, a.MessageHandle[:]...)

	return base64.StdEncoding.EncodeToString(buf)
}

// ParseArtifact parses an artifact of type 0x0004 as it is sent in the SAMLart parameter or an ArtifactResolve.
// Anything else is an error, including an artifact of another type, as artifacts of earlier versions of SAML
// have no place in SAML V2.0 (SAMLBind §3.6.4.2, errata E4).
func ParseArtifact(s string) (Artifact, error) {
	var a Artifact

	if len(s) != base64.StdEncoding.EncodedLen(artifactSize) {
		return a, errors.New("the artifact is not 44 bytes of base64")
	}

	buf, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(buf) != artifactSize {
		return a, errors.New("the artifact is not 44 bytes of base64")
	}

	if binary.BigEndian.Uint16(buf) != artifactTypeCode {
		return a, errors.New("the artifact is not of type 0x0004")
	}

	a.EndpointIndex = binary.BigEndian.Uint16(buf[2:])
	copy(a.SourceID[:], buf[4:24])
	copy(a.MessageHandle[:], buf[24:])

	return a, nil
}

// ArtifactEntry is a protocol message that waits in an ArtifactStore for its artifact to be resolved.
type ArtifactEntry struct {
	// ServiceProviderEntityID is the entity ID of the service provider that the message is for, which is the
	// only one the artifact is resolved for (SAMLCore §3.5.3).
	ServiceProviderEntityID string

	// Message is the protocol message, such as a signed Response, as serialized XML. It is returned exactly as
	// it was saved.
	Message []byte

	// Expires is when the artifact can no longer be resolved.
	Expires time.Time
}

// ArtifactStore keeps the messages that the identity provider has issued an artifact for with the HTTP-Artifact
// binding, until the service provider resolves the artifact or it expires (SAMLBind §3.6.2). It defaults to a
// MemoryArtifactStore, which is private to one process. An identity provider that runs as several instances
// must set a store they share, as the ArtifactResolve of the service provider may reach another instance than
// the one which issued the artifact.
//
// It is a plain store of values under keys. The identity provider itself checks who asks for a message and
// whether it has expired, and makes sure with its ReplayStore that a message is only given out once, so the
// store needs no atomic operation and may return an entry that has expired.
//
// A message carries an assertion, so the store holds the name and attributes of a user for as long as the
// artifact lives, which are only encrypted if the service provider publishes an encryption key. A message is
// only ever saved for the response to an authenticated user.
type ArtifactStore interface {
	// SaveArtifact stores entry under key until entry.Expires, after which it may be forgotten. An error fails
	// the response that was to be delivered by artifact.
	//
	// The key is at most 96 bytes of printable ASCII without spaces: "artifact:" and a hexadecimal SHA-256
	// digest of the identity provider and the message handle of the artifact. It is not the artifact, and the
	// artifact can't be derived from it.
	SaveArtifact(ctx context.Context, key string, entry ArtifactEntry) error

	// GetArtifact returns the entry stored under key, or nil and no error if there is none. An error is
	// reported to the service provider as a Responder status, without consuming the artifact.
	GetArtifact(ctx context.Context, key string) (*ArtifactEntry, error)

	// DeleteArtifact removes the entry stored under key, if there is one. It is called once the artifact was
	// consumed, whether or not the message was given out. An error is only logged, as the artifact can't be
	// resolved again in any case.
	DeleteArtifact(ctx context.Context, key string) error
}

// MemoryArtifactStore is an ArtifactStore that keeps its messages in the memory of the process, which is safe
// for concurrent use. It holds at most its capacity of messages that have not expired, and SaveArtifact returns
// ErrArtifactStoreFull rather than forget one to make room.
//
// It is not shared between processes, so an artifact can only be resolved at the instance that issued it.
type MemoryArtifactStore struct {
	mu       sync.Mutex
	capacity int
	entries  map[string]ArtifactEntry
}

// NewMemoryArtifactStore returns a MemoryArtifactStore which holds at most capacity messages, or
// DefaultMemoryArtifactStoreCapacity if capacity is not positive.
func NewMemoryArtifactStore(capacity int) *MemoryArtifactStore {
	if capacity <= 0 {
		capacity = DefaultMemoryArtifactStoreCapacity
	}

	return &MemoryArtifactStore{capacity: capacity, entries: map[string]ArtifactEntry{}}
}

// SaveArtifact implements ArtifactStore. Every call first forgets the entries that have expired.
func (s *MemoryArtifactStore) SaveArtifact(_ context.Context, key string, entry ArtifactEntry) error {
	now := TimeNow()

	s.mu.Lock()
	defer s.mu.Unlock()

	for k, e := range s.entries {
		if !e.Expires.After(now) {
			delete(s.entries, k)
		}
	}

	if _, ok := s.entries[key]; !ok && len(s.entries) >= s.capacity {
		return ErrArtifactStoreFull
	}

	entry.Message = bytes.Clone(entry.Message)
	s.entries[key] = entry

	return nil
}

// GetArtifact implements ArtifactStore. An entry that has expired is not returned.
func (s *MemoryArtifactStore) GetArtifact(_ context.Context, key string) (*ArtifactEntry, error) {
	now := TimeNow()

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[key]
	if !ok {
		return nil, nil
	}

	if !entry.Expires.After(now) {
		delete(s.entries, key)

		return nil, nil
	}

	entry.Message = bytes.Clone(entry.Message)

	return &entry, nil
}

// DeleteArtifact implements ArtifactStore.
func (s *MemoryArtifactStore) DeleteArtifact(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, key)

	return nil
}

// Len returns the number of messages that the store holds, which may include some that have expired since the
// last call of SaveArtifact.
func (s *MemoryArtifactStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.entries)
}

// artifactEnabled reports whether the identity provider delivers responses with the HTTP-Artifact binding, which
// it does when it has an ArtifactResolutionURL for the service provider to resolve the artifact at.
func (idp *IdentityProvider) artifactEnabled() bool {
	return idp.ArtifactResolutionURL.String() != ""
}

// artifactStore returns the ArtifactStore of the identity provider, or the MemoryArtifactStore that it uses when
// it has none, which is made on first use like the default ReplayStore.
func (idp *IdentityProvider) artifactStore() ArtifactStore {
	if idp.ArtifactStore != nil {
		return idp.ArtifactStore
	}

	if store := (*MemoryArtifactStore)(atomic.LoadPointer(&idp.defaultArtifactStore)); store != nil {
		return store
	}

	atomic.CompareAndSwapPointer(&idp.defaultArtifactStore, nil, unsafe.Pointer(NewMemoryArtifactStore(DefaultMemoryArtifactStoreCapacity)))

	return (*MemoryArtifactStore)(atomic.LoadPointer(&idp.defaultArtifactStore))
}

// artifactLifetime returns ArtifactLifetime, or DefaultArtifactLifetime if it is not set.
func (idp *IdentityProvider) artifactLifetime() time.Duration {
	if idp.ArtifactLifetime <= 0 {
		return DefaultArtifactLifetime
	}

	return idp.ArtifactLifetime
}

// artifactKey returns the key that the message of the artifact has in the ArtifactStore, and the artifact in the
// ReplayStore. It is a digest, so neither store holds a value that could be presented as an artifact.
func (idp *IdentityProvider) artifactKey(artifact Artifact) string {
	return replayKey(replayKindArtifact, idp.entityID(), string(artifact.MessageHandle[:]))
}

// issueArtifact saves message in the ArtifactStore for the service provider, which is the only one that can
// resolve it (SAMLCore §3.5.3), and returns the new artifact that stands for it and its key in the store. The
// MessageHandle is random, so it has no relationship to the message and can't be guessed (SAMLBind §3.6.4.2).
func (idp *IdentityProvider) issueArtifact(ctx context.Context, serviceProviderEntityID string, message *etree.Element) (artifact Artifact, key string, err error) {
	doc := etree.NewDocument()
	doc.SetRoot(message.Copy())

	buf, err := doc.WriteToBytes()
	if err != nil {
		return artifact, "", err
	}

	artifact = Artifact{
		EndpointIndex: artifactResolutionServiceIndex,
		SourceID:      ArtifactSourceID(idp.entityID()),
	}
	copy(artifact.MessageHandle[:], randomBytes(len(artifact.MessageHandle)))

	key = idp.artifactKey(artifact)

	entry := ArtifactEntry{
		ServiceProviderEntityID: serviceProviderEntityID,
		Message:                 buf,
		Expires:                 TimeNow().Add(idp.artifactLifetime()),
	}

	if err = idp.artifactStore().SaveArtifact(ctx, key, entry); err != nil {
		return artifact, "", fmt.Errorf("cannot save the message of an artifact: %w", err)
	}

	return artifact, key, nil
}

// IdpAuthnRequestArtifact is what the HTTP-Artifact binding sends to the assertion consumer service in place
// of a response: the artifact in the SAMLart parameter of a redirect to URL or of a form posted to it, and the
// RelayState of the request (SAMLBind §3.6.3).
type IdpAuthnRequestArtifact struct {
	URL        string
	SAMLart    string
	RelayState string

	// key is the key of the message in the ArtifactStore.
	key string
}

// RedirectURL returns URL with the SAMLart and RelayState parameters added to its query, which is where the
// browser is redirected to deliver the artifact with the URL encoding (SAMLBind §3.6.3.2).
func (a IdpAuthnRequestArtifact) RedirectURL() (*url.URL, error) {
	u, err := url.Parse(a.URL)
	if err != nil {
		return nil, err
	}

	query := u.Query()
	query.Set("SAMLart", a.SAMLart)

	if a.RelayState != "" {
		query.Set("RelayState", a.RelayState)
	}

	u.RawQuery = query.Encode()

	return u, nil
}

// ArtifactBinding issues an artifact for the response of this request to an ACSEndpoint with the HTTP-Artifact
// binding, and returns what to send to it. If `Response` is not already set, it calls MakeResponse to produce
// it. The response waits in the ArtifactStore of the identity provider for the service provider to resolve the
// artifact at ArtifactResolutionURL, for ArtifactLifetime. Every call issues a new artifact.
//
// Like PostBinding, it returns an error which wraps ErrInsecureEndpoint if ACSEndpoint is insecure. A caller
// which sends the artifact itself must do so from PublishResponse, as WriteResponse does.
func (req *IdpAuthnRequest) ArtifactBinding() (IdpAuthnRequestArtifact, error) {
	var delivery IdpAuthnRequestArtifact

	if req.ACSEndpoint == nil || req.ACSEndpoint.Binding != HTTPArtifactBinding {
		return delivery, errors.New("the assertion consumer service does not use the HTTP-Artifact binding")
	}

	if !req.IDP.artifactEnabled() {
		return delivery, errors.New("the identity provider has no ArtifactResolutionURL")
	}

	if err := req.IDP.CheckServiceProviderEndpoint(req.ACSEndpoint.Location); err != nil {
		req.ResponseEl, req.responseParticipant = nil, nil
		return delivery, err
	}

	if req.ResponseEl == nil {
		if err := req.MakeResponse(); err != nil {
			return delivery, err
		}
	}

	artifact, key, err := req.IDP.issueArtifact(requestContext(req.HTTPRequest), req.ServiceProviderMetadata.EntityID, req.ResponseEl)
	if err != nil {
		return delivery, err
	}

	delivery.URL = req.ACSEndpoint.Location
	delivery.SAMLart = artifact.String()
	delivery.RelayState = req.RelayState
	delivery.key = key

	return delivery, nil
}

var defaultArtifactFormTemplate = template.Must(template.New("saml-artifact-form").Parse(`<html>` +
	`<form method="post" action="{{.URL}}" id="SAMLArtifactForm">` +
	`<input type="hidden" name="SAMLart" value="{{.SAMLart}}" />` +
	`{{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}" />{{end}}` +
	`<input id="SAMLSubmitButton" type="submit" value="Continue" />` +
	`</form>` +
	`<script>document.getElementById('SAMLSubmitButton').style.visibility='hidden';</script>` +
	`<script>document.getElementById('SAMLArtifactForm').submit();</script>` +
	`</html>`))

// writeArtifactResponse is WriteResponse for an ACSEndpoint with the HTTP-Artifact binding: it sends the browser
// to the assertion consumer service with an artifact for the response, by a form that it posts (SAMLBind
// §3.6.3.3) or, if ArtifactRedirectEncoding is set, a redirect (§3.6.3.2). The form keeps the artifact out of
// URLs, and so out of logs and the Referer header. Its errors are those of WriteResponse.
func (req *IdpAuthnRequest) writeArtifactResponse(w http.ResponseWriter) error {
	delivery, err := req.ArtifactBinding()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrResponseNotBuilt, err)
	}

	published := false

	// The message of an artifact that was never sent is of no use to anyone.
	discard := func(err error) error {
		if deleteErr := req.IDP.artifactStore().DeleteArtifact(requestContext(req.HTTPRequest), delivery.key); deleteErr != nil {
			req.IDP.logger().Printf("failed to delete the message of an artifact that was not sent: %s", deleteErr)
		}

		return fmt.Errorf("%w: %w", ErrResponseNotBuilt, err)
	}

	var (
		location *url.URL
		body     bytes.Buffer
	)

	if req.IDP.ArtifactRedirectEncoding {
		if location, err = delivery.RedirectURL(); err != nil {
			return discard(err)
		}
	} else {
		tmpl := req.IDP.ArtifactFormTemplate
		if tmpl == nil {
			tmpl = defaultArtifactFormTemplate
		}

		if err = tmpl.Execute(&body, delivery); err != nil {
			return discard(err)
		}
	}

	err = req.PublishResponse(func() error {
		published = true

		// SAMLBind §3.6.5.1.
		setNoCacheHeaders(w)

		if location != nil {
			// SAMLBind §3.6.5: the status of the redirect is 302 or 303.
			w.Header().Set("Location", location.String())
			w.WriteHeader(http.StatusFound)

			return nil
		}

		_, err := w.Write(body.Bytes())

		return err
	})

	// The participant couldn't be recorded, so nothing was written.
	if err != nil && !published {
		return discard(err)
	}

	return err
}

// errArtifactNotResolved is the error for an ArtifactResolve that is answered with an empty response: an
// ArtifactResponse with a Success status and no message (SAMLCore §3.5.3). The Err is for logs.
type errArtifactNotResolved struct{ Err error }

func (e *errArtifactNotResolved) Error() string { return e.Err.Error() }

func (e *errArtifactNotResolved) Unwrap() error { return e.Err }

func artifactNotResolved(format string, args ...any) error {
	return &errArtifactNotResolved{Err: fmt.Errorf(format, args...)}
}

// artifactResolveRequest is an ArtifactResolve that the identity provider received on the SOAP binding.
type artifactResolveRequest struct {
	IDP           *IdentityProvider
	HTTPRequest   *http.Request
	RequestBuffer []byte
	Request       ArtifactResolve
	Now           time.Time

	// requester is the entity ID of the service provider that sent the request, once its signature is verified,
	// and metadata is its metadata.
	requester string
	metadata  *EntityDescriptor
}

// ServeArtifactResolution handles a SAML ArtifactResolve from a service provider on the SOAP binding, at
// ArtifactResolutionURL, and answers on the same connection with a signed ArtifactResponse in a SOAP envelope
// (SAMLCore §3.5, SAMLProf §5). The response contains the message that the artifact was issued for, if the
// artifact was issued by this identity provider with the HTTP-Artifact binding, has not expired, has not been
// resolved before, at any instance that shares the ReplayStore, and was issued for the service provider that
// asks.
//
// The service provider must authenticate itself with an enveloped signature on the ArtifactResolve, from a
// signing key in its metadata, as only the service provider that a response was issued to may be given it
// (SAMLProf §4.1.4.4, SAMLBind §3.6.5.2). The ArtifactResponse is signed in turn (SAMLProf §5.4.2). The
// exchange must also be confidential, so ArtifactResolutionURL must be served over TLS.
//
// SAMLCore §3.5.3 and SAMLBind §3.6.6 require that a request which is understood is answered with a Success
// status whether or not it is given the message. So a request whose sender can't be authenticated, that is too
// old or for another destination, or whose artifact is malformed, unknown, expired, already resolved or issued
// for another service provider gets an ArtifactResponse with Success and no message. Nothing in it says which,
// and the reason is logged. An artifact is used up by the first authenticated request that names it, even one
// from another service provider than it was issued for, as it is then known to be in the wrong hands (SAMLSec
// §6.5.3).
//
// A message that is not an ArtifactResolve gets Requester/RequestUnsupported, one that can't be parsed gets
// Requester, one of another version gets VersionMismatch, and a failure to look up the service provider or of
// either store gets Responder. A request that is not a POST gets StatusMethodNotAllowed, one that is not a SOAP
// 1.1 envelope gets a Client fault, and a failure to sign or write the response gets a Server fault. If
// ArtifactResolutionURL is not set the answer is StatusNotFound.
func (idp *IdentityProvider) ServeArtifactResolution(w http.ResponseWriter, r *http.Request) {
	if !idp.artifactEnabled() {
		http.NotFound(w, r)

		return
	}

	soap, ok := idp.receiveSOAPRequest(w, r)
	if !ok {
		return
	}

	req := &artifactResolveRequest{IDP: idp, HTTPRequest: r, RequestBuffer: soap.Body, Now: TimeNow()}

	// The response answers the request by this ID, if it is valid, when the request gets no further than this.
	req.Request.ID = soap.Message.SelectAttrValue("ID", "")

	var (
		message *etree.Element
		status  = Status{StatusCode: StatusCode{Value: StatusSuccess}}
		empty   *errArtifactNotResolved
	)

	if soap.Message.Tag != "ArtifactResolve" || soap.Message.NamespaceURI() != samlProtocolNS {
		idp.logger().Printf("failed to handle artifact resolution request: the message is not an ArtifactResolve")

		status = Status{StatusCode: StatusCode{Value: StatusRequester, StatusCode: &StatusCode{Value: StatusRequestUnsupported}}}
	} else if resolved, err := req.resolve(); errors.As(err, &empty) {
		idp.logger().Printf("artifact not resolved: %s", err)
	} else if err != nil {
		idp.logger().Printf("failed to resolve artifact: %s", err)

		if status, ok = RequestStatus(err); !ok {
			status = Status{StatusCode: StatusCode{Value: StatusRequester}}
		}
	} else {
		message = resolved
	}

	if err := req.writeResponse(w, status, message); err != nil {
		idp.logger().Printf("failed to write artifact response: %s", err)
		writeSOAPFault(w, &soapFault{Code: "Server", String: soapFaultStringProcessing})
	}
}

// resolve validates the request and returns the message of its artifact, which is then used up. The error is an
// *errArtifactNotResolved if the request is to be answered with an empty response, a *statusError if it is to be
// answered with that status, and otherwise means that the request could not be understood.
func (req *artifactResolveRequest) resolve() (*etree.Element, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}

	idp, ctx := req.IDP, requestContext(req.HTTPRequest)

	artifact, err := ParseArtifact(strings.TrimSpace(req.Request.Artifact))
	if err != nil {
		return nil, artifactNotResolved("%s sent a malformed artifact: %w", req.requester, err)
	}

	// SAMLBind §3.6.4.2: the SourceID names the issuer, and the EndpointIndex the endpoint to resolve it at.
	if artifact.SourceID != ArtifactSourceID(idp.entityID()) || artifact.EndpointIndex != artifactResolutionServiceIndex {
		return nil, artifactNotResolved("%s sent an artifact that this identity provider did not issue", req.requester)
	}

	key := idp.artifactKey(artifact)

	entry, err := idp.artifactStore().GetArtifact(ctx, key)
	if err != nil {
		return nil, &statusError{StatusResponder, "", fmt.Errorf("cannot look up the artifact: %w", err)}
	}

	// SAMLSec §6.5.4 asks that requests for artifacts which don't exist are noticed, which the log allows.
	if entry == nil {
		return nil, artifactNotResolved("%s sent an artifact that is unknown, expired or already resolved", req.requester)
	}

	// SAMLCore §3.5.3: once an artifact is resolved, any later request with it, by any requester, gets an empty
	// response. The ReplayStore makes that hold between concurrent requests and across instances, which the
	// ArtifactStore is not asked to. Only an authenticated service provider that holds a real artifact gets
	// this far, so nobody else can add to the store.
	switch err = idp.replayStore().Consume(ctx, key, entry.Expires.Add(MaxClockSkew)); {
	case errors.Is(err, ErrReplayed):
		return nil, artifactNotResolved("%s sent an artifact that is already resolved: %w", req.requester, err)
	case err != nil:
		return nil, &statusError{StatusResponder, "", fmt.Errorf("cannot check whether the artifact is already resolved: %w", err)}
	}

	if err = idp.artifactStore().DeleteArtifact(ctx, key); err != nil {
		idp.logger().Printf("failed to delete the message of a resolved artifact: %s", err)
	}

	// SAMLCore §3.5.3, SAMLProf §4.1.4.4 and SAMLSec §6.5.3: only the intended recipient is given the message.
	// The artifact is already used up, as another party having it means it was stolen or misdirected.
	if entry.ServiceProviderEntityID != req.requester {
		return nil, artifactNotResolved("%s sent an artifact that was issued for %s, which can no longer be resolved",
			req.requester, entry.ServiceProviderEntityID)
	}

	if !entry.Expires.After(req.Now) {
		return nil, artifactNotResolved("%s sent an artifact that expired at %s", req.requester, entry.Expires)
	}

	doc := etree.NewDocument()
	if err = doc.ReadFromBytes(entry.Message); err != nil || doc.Root() == nil {
		return nil, &statusError{StatusResponder, "", errors.New("the stored message of the artifact is not XML")}
	}

	return doc.Root(), nil
}

// validate parses the ArtifactResolve, authenticates its sender by the enveloped signature, and checks the
// content that the signature covers. The errors are those of resolve. They don't include anything from the
// request until its signature is verified.
func (req *artifactResolveRequest) validate() error {
	// This code runs before any authentication, and the cost of the XML parsing below is proportional to the
	// size of the request.
	if err := checkAuthnRequestSize(req.RequestBuffer); err != nil {
		return err
	}

	if err := xrv.Validate(bytes.NewReader(req.RequestBuffer)); err != nil {
		return err
	}

	if err := xml.Unmarshal(req.RequestBuffer, &req.Request); err != nil {
		return err
	}

	if err := req.checkTrust(); err != nil {
		return err
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(req.RequestBuffer); err != nil || doc.Root() == nil {
		return errors.New("request has no root element")
	}

	issuer := req.Request.Issuer.Value

	// SAMLBind §3.6.5.2 and SAMLProf §4.1.4.4: the sender must be authenticated, which on this binding means a
	// valid signature by a key in its metadata. SAMLCore §3.5.3: a requester that can't authenticate itself as
	// the intended recipient gets an empty response.
	metadata, verified, err := req.IDP.verifySOAPRequester(req.HTTPRequest, doc.Root(), issuer)
	if err != nil {
		if top, _, _ := requestStatus(err); top == StatusResponder {
			return err
		}

		return &errArtifactNotResolved{Err: fmt.Errorf("the requester is not authenticated: %w", err)}
	}

	req.Request = ArtifactResolve{}
	if err = unmarshalElement(verified, &req.Request); err != nil {
		return err
	}

	if err = req.checkTrust(); err != nil {
		return err
	}

	if req.Request.Issuer.Value != issuer {
		return errors.New("signed request has a different issuer")
	}

	req.requester, req.metadata = issuer, metadata

	return req.checkRequestStage()
}

// checkRequestStage makes the checks on the content of the request that its signature covers, once its sender is
// authenticated. A version that is not supported is a *statusError, and anything else an empty response.
func (req *artifactResolveRequest) checkRequestStage() error {
	issuer := req.requester

	if statusErr := versionStatus(req.Request.Version); statusErr != nil {
		return statusErr
	}

	if err := checkIssueInstant("request", req.Request.IssueInstant, req.Now, MaxIssueDelay); err != nil {
		return artifactNotResolved("%s sent a request that is not current: %w", issuer, err)
	}

	// SAMLBind §3.2 doesn't require a Destination on SOAP, but one that is present must be this endpoint.
	if destination := req.IDP.ArtifactResolutionURL.String(); req.Request.Destination != "" && req.Request.Destination != destination {
		return artifactNotResolved("the request of %s has the destination %q, not %q", issuer, req.Request.Destination, destination)
	}

	return nil
}

// checkTrust makes the checks on the identity of the request that are needed before the service provider can be
// looked up, as IdpLogoutRequest.checkTrust does. SAMLProf §5.4.1 requires the Issuer.
func (req *artifactResolveRequest) checkTrust() error {
	if !isValidAuthnRequestID(req.Request.ID) {
		// The value is not included because this error is logged without authentication.
		return errors.New("invalid request ID")
	}

	if req.Request.Issuer == nil || req.Request.Issuer.Value == "" {
		return errors.New("request has no issuer")
	}

	return nil
}

// writeResponse answers the request on w with a signed ArtifactResponse of the status in a SOAP envelope, which
// contains message if it is not nil. The response names the identity provider as its Issuer and is signed, which
// is how it authenticates itself to the requester (SAMLProf §5.3.2, §5.4.2), so it is signed whatever the
// IssuancePolicy has signed in the message, with the algorithms that the policy gives for the requester. It has no InResponseTo when the ID
// of the request is not valid.
func (req *artifactResolveRequest) writeResponse(w http.ResponseWriter, status Status, message *etree.Element) error {
	response := &ArtifactResponse{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		Version:      "2.0",
		IssueInstant: req.Now,
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  req.IDP.entityID(),
		},
		Status: status,
	}

	if isValidAuthnRequestID(req.Request.ID) {
		response.InResponseTo = req.Request.ID
	}

	element := func() *etree.Element {
		el := response.Element()
		if message != nil {
			el.AddChild(message.Copy())
		}

		return el
	}

	signingContext, err := req.IDP.signingContextFor(req.HTTPRequest, req.metadata)
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
