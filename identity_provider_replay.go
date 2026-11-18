package saml

import (
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// ErrReplayed is returned by ReplayStore.Consume when the key has already been consumed and has not yet expired,
// and wrapped by the error of the identity provider for a message that is refused as a replay.
var ErrReplayed = errors.New("the message has already been used")

// ErrReplayStoreFull is returned by MemoryReplayStore.Consume when the store holds its capacity of keys that
// have not yet expired. The identity provider treats it like any other failure of the store, and refuses the
// message.
var ErrReplayStoreFull = errors.New("the replay store is full")

// DefaultMemoryReplayStoreCapacity is the capacity of the MemoryReplayStore an IdentityProvider uses when it has
// no ReplayStore. Each key takes roughly 150 bytes, so a full store takes roughly 10 MB.
const DefaultMemoryReplayStoreCapacity = 65536

// ReplayStore records values that may be used only once, such as the ID of a request, until they expire. It is
// used by IdentityProvider to refuse a message that it has already acted on (SAMLSec §6.1.2, §7.1.1.4), and
// defaults to a MemoryReplayStore, which is private to one process. An identity provider that runs as several
// instances must set a store they share, or a message can be used once at each of them.
//
// The store is not specific to a kind of message: each key names its kind, so one store also serves any other
// value with a one-time-use property, such as an artifact (SAMLBind §3.6.5).
type ReplayStore interface {
	// Consume records key until expires, and returns nil if it was not already recorded. It returns ErrReplayed,
	// which may be wrapped, if key is recorded and has not yet expired, and any other error if that could not be
	// determined, in which case the message is refused. The check and the record must be one atomic operation
	// with respect to every other call with the same key, in every instance that shares the store, such as a
	// Redis SET with NX and PXAT or an INSERT under a unique constraint.
	//
	// The key is at most 96 bytes of printable ASCII without spaces: the kind of the value, a colon, and a
	// hexadecimal SHA-256 digest of who issued it, to whom and its identifier. It holds nothing secret or
	// personal. A key whose expires has passed may be forgotten, and one that arrives already expired need
	// not be recorded, as the message it stands for is refused for its age.
	Consume(ctx context.Context, key string, expires time.Time) error
}

// The kinds of value which the identity provider records in its ReplayStore, each the prefix of a key.
const (
	replayKindAuthnRequest       = "authnrequest"
	replayKindLogoutRequest      = "logoutrequest"
	replayKindAttributeQuery     = "attributequery"
	replayKindAuthnQuery         = "authnquery"
	replayKindAssertionIDRequest = "assertionidrequest"

	replayKindManageNameIDRequest  = "managenameidrequest"
	replayKindNameIDMappingRequest = "nameidmappingrequest"
)

// replayKey returns the key of a ReplayStore for a value of the kind, which parts identify. The parts are
// digested with their lengths, so that no two lists of parts share a key, and the key has a fixed size whatever
// the size of the parts, which come from the message.
func replayKey(kind string, parts ...string) string {
	digest := sha256.New()

	var length [8]byte

	for _, part := range parts {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		digest.Write(length[:])
		digest.Write([]byte(part))
	}

	return kind + ":" + hex.EncodeToString(digest.Sum(nil))
}

// replayStore returns the ReplayStore of the identity provider, or the MemoryReplayStore that it uses when it
// has none, which is made on first use.
func (idp *IdentityProvider) replayStore() ReplayStore {
	if idp.ReplayStore != nil {
		return idp.ReplayStore
	}

	if store := (*MemoryReplayStore)(atomic.LoadPointer(&idp.defaultReplayStore)); store != nil {
		return store
	}

	atomic.CompareAndSwapPointer(&idp.defaultReplayStore, nil, unsafe.Pointer(NewMemoryReplayStore(DefaultMemoryReplayStoreCapacity)))

	return (*MemoryReplayStore)(atomic.LoadPointer(&idp.defaultReplayStore))
}

// checkReplay consumes the ID of a message of the kind, which issuer sent to this identity provider, in the
// ReplayStore. The message states that it is valid until expires, which is its IssueInstant and its maximum age,
// or its NotOnOrAfter. It is accepted until MaxClockSkew after that (SAML2Int SDP-G01), and the ID stays in the
// store for MaxClockSkew longer still, for instances whose clocks differ. An ID is unique to the party that assigned it
// (SAMLCore §1.3.4), so it is recorded for the issuer, and one service provider can't use up the IDs of another.
//
// It must only be called for a message that is authenticated, or that the identity provider is about to act on
// for an authenticated user, and has passed every other check, so that nobody else can fill the store. That is
// after the signature is verified and after the checks of the request stage, so the endpoint for the response is
// already resolved from metadata. Every handler of a request calls it: ServeSSO and ServeECP through
// IdpAuthnRequest.CheckReplay, IdpLogoutRequest.Validate, the assertion query and request services, and the
// Validate of the name identifier management and mapping requests.
//
// The error is a *statusError. A replay is Requester with RequestDenied and wraps ErrReplayed. A failure of the
// store is Responder, as the message is refused although nothing is known to be wrong with it.
func (idp *IdentityProvider) checkReplay(ctx context.Context, kind, issuer, id string, expires time.Time) error {
	key := replayKey(kind, idp.entityID(), issuer, id)

	err := idp.replayStore().Consume(ctx, key, expires.Add(2*MaxClockSkew))

	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrReplayed):
		return &statusError{StatusRequester, StatusRequestDenied,
			fmt.Errorf("%s %s of %s is a replay: %w", kind, id, issuer, err)}
	default:
		return &statusError{StatusResponder, "",
			fmt.Errorf("cannot check whether %s %s of %s is a replay: %w", kind, id, issuer, err)}
	}
}

// requestContext returns the context of r, or the background context if there is no request.
func requestContext(r *http.Request) context.Context {
	if r == nil {
		return context.Background()
	}

	return r.Context()
}

// MemoryReplayStore is a ReplayStore that keeps its keys in the memory of the process, which is safe for
// concurrent use. It holds at most its capacity of keys, each in a fixed amount of memory whatever its length, so
// its memory is bounded however many keys it is given. Once it is full of keys that have not expired, Consume
// returns ErrReplayStoreFull until one does: it never forgets a key early to make room, which would let that
// message be replayed.
//
// It is not shared between processes, and is emptied by a restart, so it only detects a replay at the instance
// that saw the message first, while that instance runs.
type MemoryReplayStore struct {
	mu       sync.Mutex
	capacity int
	expiries map[memoryReplayKey]time.Time
	queue    memoryReplayQueue
}

// memoryReplayKey is the digest of a key, which bounds the memory that a key of any length takes.
type memoryReplayKey [sha256.Size]byte

// memoryReplayEntry is a key in the queue of a MemoryReplayStore.
type memoryReplayEntry struct {
	key     memoryReplayKey
	expires time.Time
}

// NewMemoryReplayStore returns a MemoryReplayStore which holds at most capacity keys, or
// DefaultMemoryReplayStoreCapacity if capacity is not positive.
func NewMemoryReplayStore(capacity int) *MemoryReplayStore {
	if capacity <= 0 {
		capacity = DefaultMemoryReplayStoreCapacity
	}

	return &MemoryReplayStore{
		capacity: capacity,
		expiries: map[memoryReplayKey]time.Time{},
	}
}

// Consume implements ReplayStore. The context is not used, as nothing here blocks. A key which has already
// expired is not recorded.
func (s *MemoryReplayStore) Consume(_ context.Context, key string, expires time.Time) error {
	now := TimeNow()
	digest := memoryReplayKey(sha256.Sum256([]byte(key)))

	s.mu.Lock()
	defer s.mu.Unlock()

	// Keys leave in the order they expire, so this takes time in proportion to the keys that are removed, and
	// each key is removed once.
	for len(s.queue) > 0 && !s.queue[0].expires.After(now) {
		entry := heap.Pop(&s.queue).(memoryReplayEntry)
		delete(s.expiries, entry.key)
	}

	if _, ok := s.expiries[digest]; ok {
		return ErrReplayed
	}

	if !expires.After(now) {
		return nil
	}

	if len(s.expiries) >= s.capacity {
		return ErrReplayStoreFull
	}

	s.expiries[digest] = expires
	heap.Push(&s.queue, memoryReplayEntry{key: digest, expires: expires})

	return nil
}

// Len returns the number of keys that the store holds, which may include keys that have expired since the last
// call of Consume.
func (s *MemoryReplayStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.expiries)
}

// memoryReplayQueue is a [heap.Interface] of the keys of a MemoryReplayStore, with the first to expire at the
// front.
type memoryReplayQueue []memoryReplayEntry

// Len implements [heap.Interface].
func (q memoryReplayQueue) Len() int { return len(q) }

// Less implements [heap.Interface].
func (q memoryReplayQueue) Less(i, j int) bool { return q[i].expires.Before(q[j].expires) }

// Swap implements [heap.Interface].
func (q memoryReplayQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }

// Push implements [heap.Interface].
func (q *memoryReplayQueue) Push(x any) { *q = append(*q, x.(memoryReplayEntry)) }

// Pop implements [heap.Interface].
func (q *memoryReplayQueue) Pop() any {
	old := *q
	last := len(old) - 1
	entry := old[last]
	*q = old[:last]

	return entry
}

// CheckReplay consumes the ID of the request in the ReplayStore of the identity provider, and returns an error
// if the request was consumed before. ServeSSO calls it once the SessionProvider has returned a session, and
// before the assertion is made, so an application that serves requests with its own handler must do the same.
//
// It is not part of Validate, because a SessionProvider that shows a login form re-presents the same request
// when the form is posted, perhaps several times, which is not a replay: the request is only used up when it is
// answered for a session. That also means the store only ever holds requests of authenticated users, as an
// AuthnRequest need not be signed. The ID is recorded for the issuer until the request would be refused for its
// age, which is MaxAuthnRequestAge and MaxClockSkew after its IssueInstant, and MaxClockSkew longer.
//
// It must only be called after Validate has returned nil. The error carries a status for RequestStatus: Requester
// with RequestDenied for a replay, which wraps ErrReplayed, and Responder if the store failed, in which case the
// request must not be answered with an assertion either.
func (req *IdpAuthnRequest) CheckReplay() error {
	return req.IDP.checkReplay(requestContext(req.HTTPRequest), replayKindAuthnRequest, req.Request.Issuer.Value,
		req.Request.ID, req.Request.IssueInstant.Add(req.IDP.maxAuthnRequestAge()))
}

// checkReplay consumes the ID of the request in the ReplayStore of the identity provider. It is the last check of
// Validate, so the request is verified and its response endpoint resolved. The ID is recorded until the request
// would be refused for its age, which is MaxClockSkew after the sooner of its NotOnOrAfter and MaxIssueDelay after
// its IssueInstant, and MaxClockSkew longer.
func (req *IdpLogoutRequest) checkReplay() error {
	expires := req.Request.IssueInstant.Add(MaxIssueDelay)
	if notOnOrAfter := req.Request.NotOnOrAfter; notOnOrAfter != nil && notOnOrAfter.Before(expires) {
		expires = *notOnOrAfter
	}

	return req.IDP.checkReplay(requestContext(req.HTTPRequest), replayKindLogoutRequest, req.Request.Issuer.Value,
		req.Request.ID, expires)
}
