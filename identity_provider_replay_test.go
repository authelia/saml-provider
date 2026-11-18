package saml

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml/xmlenc"
)

// replayTestClock sets TimeNow to a time that the returned function advances, until the test ends.
func replayTestClock(t *testing.T) func(time.Duration) {
	t.Helper()

	previous := TimeNow

	t.Cleanup(func() { TimeNow = previous })

	var offset atomic.Int64

	start := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	TimeNow = func() time.Time { return start.Add(time.Duration(offset.Load())) }

	return func(d time.Duration) { offset.Add(int64(d)) }
}

// recordingReplayStore is a ReplayStore which records its calls, and returns err if it is set and otherwise
// the answer of a MemoryReplayStore.
type recordingReplayStore struct {
	mu       sync.Mutex
	store    *MemoryReplayStore
	keys     []string
	expiries []time.Time
	contexts []context.Context
	err      error
}

func newRecordingReplayStore() *recordingReplayStore {
	return &recordingReplayStore{store: NewMemoryReplayStore(0)}
}

func (s *recordingReplayStore) Consume(ctx context.Context, key string, expires time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.keys = append(s.keys, key)
	s.expiries = append(s.expiries, expires)
	s.contexts = append(s.contexts, ctx)

	if s.err != nil {
		return s.err
	}

	return s.store.Consume(ctx, key, expires)
}

func (s *recordingReplayStore) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.keys)
}

func TestMemoryReplayStoreRefusesSecondUse(t *testing.T) {
	replayTestClock(t)

	store := NewMemoryReplayStore(8)
	expires := TimeNow().Add(time.Minute)

	assert.NilError(t, store.Consume(context.Background(), "kind:a", expires))
	assert.Check(t, errors.Is(store.Consume(context.Background(), "kind:a", expires), ErrReplayed))
	assert.Check(t, errors.Is(store.Consume(context.Background(), "kind:a", expires.Add(time.Hour)), ErrReplayed))
	assert.NilError(t, store.Consume(context.Background(), "kind:b", expires))
	assert.NilError(t, store.Consume(context.Background(), "other:a", expires))
	assert.Check(t, is.Equal(store.Len(), 3))
}

func TestMemoryReplayStoreForgetsExpiredKeys(t *testing.T) {
	advance := replayTestClock(t)

	store := NewMemoryReplayStore(8)

	assert.NilError(t, store.Consume(context.Background(), "kind:short", TimeNow().Add(time.Minute)))
	assert.NilError(t, store.Consume(context.Background(), "kind:long", TimeNow().Add(time.Hour)))

	advance(time.Minute - time.Nanosecond)
	assert.Check(t, errors.Is(store.Consume(context.Background(), "kind:short", TimeNow().Add(time.Minute)), ErrReplayed))

	// At its expiry the key is forgotten, and may be recorded again.
	advance(time.Nanosecond)
	assert.NilError(t, store.Consume(context.Background(), "kind:short", TimeNow().Add(time.Minute)))
	assert.Check(t, errors.Is(store.Consume(context.Background(), "kind:long", TimeNow().Add(time.Hour)), ErrReplayed))
	assert.Check(t, is.Equal(store.Len(), 2))

	advance(2 * time.Hour)
	assert.NilError(t, store.Consume(context.Background(), "kind:other", TimeNow().Add(time.Minute)))
	assert.Check(t, is.Equal(store.Len(), 1))
}

func TestMemoryReplayStoreDoesNotRecordExpiredKey(t *testing.T) {
	replayTestClock(t)

	store := NewMemoryReplayStore(8)

	assert.NilError(t, store.Consume(context.Background(), "kind:a", TimeNow()))
	assert.NilError(t, store.Consume(context.Background(), "kind:a", TimeNow().Add(-time.Minute)))
	assert.Check(t, is.Equal(store.Len(), 0))
}

func TestMemoryReplayStoreIsBounded(t *testing.T) {
	advance := replayTestClock(t)

	store := NewMemoryReplayStore(100)
	expires := TimeNow().Add(time.Minute)

	// A flood of unique keys, each as long as a message can make it.
	long := strings.Repeat("x", 64*1024)

	var full int

	for i := range 10000 {
		switch err := store.Consume(context.Background(), fmt.Sprintf("kind:%s%d", long, i), expires); {
		case errors.Is(err, ErrReplayStoreFull):
			full++
		default:
			assert.NilError(t, err)
		}
	}

	assert.Check(t, is.Equal(full, 9900))
	assert.Check(t, is.Equal(store.Len(), 100))
	assert.Check(t, len(store.queue) == 100 && cap(store.queue) < 1000)

	// A full store still refuses a key that it holds as a replay, and never forgets one to make room.
	assert.Check(t, errors.Is(store.Consume(context.Background(), "kind:"+long+"0", expires), ErrReplayed))
	assert.Check(t, !errors.Is(ErrReplayStoreFull, ErrReplayed))

	// There is room again once the keys expire.
	advance(time.Minute)
	assert.NilError(t, store.Consume(context.Background(), "kind:new", TimeNow().Add(time.Minute)))
	assert.Check(t, is.Equal(store.Len(), 1))
}

func TestNewMemoryReplayStoreDefaultCapacity(t *testing.T) {
	assert.Check(t, is.Equal(NewMemoryReplayStore(0).capacity, DefaultMemoryReplayStoreCapacity))
	assert.Check(t, is.Equal(NewMemoryReplayStore(-1).capacity, DefaultMemoryReplayStoreCapacity))
	assert.Check(t, is.Equal(NewMemoryReplayStore(7).capacity, 7))
}

func TestMemoryReplayStoreConcurrentUse(t *testing.T) {
	replayTestClock(t)

	store := NewMemoryReplayStore(0)
	expires := TimeNow().Add(time.Minute)

	const workers = 32

	var (
		wg       sync.WaitGroup
		accepted atomic.Int64
		replayed atomic.Int64
	)

	for worker := range workers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for i := range 100 {
				// Every worker races for the shared key, and has keys of its own.
				for _, key := range []string{fmt.Sprintf("kind:shared-%d", i), fmt.Sprintf("kind:own-%d-%d", worker, i)} {
					switch err := store.Consume(context.Background(), key, expires); {
					case err == nil:
						accepted.Add(1)
					case errors.Is(err, ErrReplayed):
						replayed.Add(1)
					default:
						t.Errorf("unexpected error: %s", err)
					}
				}
			}
		}()
	}

	wg.Wait()

	assert.Check(t, is.Equal(accepted.Load(), int64(100+workers*100)))
	assert.Check(t, is.Equal(replayed.Load(), int64((workers-1)*100)))
	assert.Check(t, is.Equal(store.Len(), 100+workers*100))
}

func TestReplayKey(t *testing.T) {
	key := replayKey(replayKindAuthnRequest, "https://idp.example.com/metadata", "https://sp.example.com/metadata", "id-1")

	assert.Check(t, strings.HasPrefix(key, "authnrequest:"))
	assert.Check(t, len(key) <= 96)
	assert.Check(t, is.Equal(key, replayKey(replayKindAuthnRequest, "https://idp.example.com/metadata", "https://sp.example.com/metadata", "id-1")))

	// The parts are kept apart, and the kind is part of the key.
	assert.Check(t, replayKey("kind", "ab", "c") != replayKey("kind", "a", "bc"))
	assert.Check(t, replayKey("kind", "a", "") != replayKey("kind", "", "a"))
	assert.Check(t, replayKey("kind", "a") != replayKey("other", "a"))

	// The size doesn't depend on the parts, which come from the message.
	assert.Check(t, is.Equal(len(replayKey("kind", strings.Repeat("x", 64*1024))), len(replayKey("kind", "x"))))

	for _, c := range key {
		assert.Check(t, c > ' ' && c < 0x7f)
	}
}

func TestIdentityProviderDefaultReplayStore(t *testing.T) {
	idp := &IdentityProvider{}

	store := idp.replayStore()
	assert.Assert(t, store != nil)
	assert.Check(t, store == idp.replayStore())
	assert.Check(t, is.Equal(store.(*MemoryReplayStore).capacity, DefaultMemoryReplayStoreCapacity))

	// A copy shares the store that was already made, and an identity provider of its own doesn't.
	duplicate := *idp
	assert.Check(t, duplicate.replayStore() == store)
	assert.Check(t, (&IdentityProvider{}).replayStore() != store)

	custom := newRecordingReplayStore()
	idp.ReplayStore = custom
	assert.Check(t, idp.replayStore() == ReplayStore(custom))
}

func TestIdentityProviderDefaultReplayStoreConcurrentFirstUse(t *testing.T) {
	idp := &IdentityProvider{}
	stores := make([]ReplayStore, 16)

	var wg sync.WaitGroup

	for i := range stores {
		wg.Add(1)

		go func() {
			defer wg.Done()

			stores[i] = idp.replayStore()
		}()
	}

	wg.Wait()

	for _, store := range stores {
		assert.Check(t, store == stores[0])
	}
}

func TestCheckReplayKeysByIssuerKindAndIdentityProvider(t *testing.T) {
	replayTestClock(t)

	idp := &IdentityProvider{MetadataURL: mustParseURL("https://idp.example.com/metadata")}
	expires := TimeNow().Add(time.Minute)
	ctx := context.Background()

	assert.NilError(t, idp.checkReplay(ctx, replayKindAuthnRequest, "https://sp-a.example.com", "id-1", expires))

	err := idp.checkReplay(ctx, replayKindAuthnRequest, "https://sp-a.example.com", "id-1", expires)
	assert.Check(t, errors.Is(err, ErrReplayed))

	status, ok := RequestStatus(err)
	assert.Assert(t, ok)
	assert.Check(t, is.Equal(status.StatusCode.Value, StatusRequester))
	assert.Check(t, is.Equal(status.StatusCode.StatusCode.Value, StatusRequestDenied))

	// The same ID is not a replay from another issuer (SAMLCore §1.3.4), in a message of another kind, or at
	// another identity provider that shares the store.
	assert.NilError(t, idp.checkReplay(ctx, replayKindAuthnRequest, "https://sp-b.example.com", "id-1", expires))
	assert.NilError(t, idp.checkReplay(ctx, replayKindLogoutRequest, "https://sp-a.example.com", "id-1", expires))

	other := &IdentityProvider{MetadataURL: mustParseURL("https://other.example.com/metadata"), ReplayStore: idp.replayStore()}
	assert.NilError(t, other.checkReplay(ctx, replayKindAuthnRequest, "https://sp-a.example.com", "id-1", expires))
}

func TestCheckReplayStoreFailureIsResponder(t *testing.T) {
	replayTestClock(t)

	for name, storeErr := range map[string]error{
		"backend": errors.New("connection refused"),
		"full":    ErrReplayStoreFull,
	} {
		t.Run(name, func(t *testing.T) {
			store := newRecordingReplayStore()
			store.err = storeErr
			idp := &IdentityProvider{ReplayStore: store}

			err := idp.checkReplay(context.Background(), replayKindAuthnRequest, "https://sp.example.com", "id-1", TimeNow())
			assert.Check(t, errors.Is(err, storeErr))
			assert.Check(t, !errors.Is(err, ErrReplayed))

			status, ok := RequestStatus(err)
			assert.Assert(t, ok)
			assert.Check(t, is.Equal(status.StatusCode.Value, StatusResponder))
			assert.Check(t, status.StatusCode.StatusCode == nil)
		})
	}
}

// replayPostRequest returns a new HTTP-POST of the AuthnRequest in body to the SSO URL, with any other form
// fields in extra.
func replayPostRequest(body []byte, extra url.Values) *http.Request {
	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}}
	for name, values := range extra {
		form[name] = values
	}

	r := httptest.NewRequest(http.MethodPost, signatureTestSSOURL, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return r
}

func serveSSO(test *IdentityProviderTest, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, r)

	return w
}

// assertAssertionResponse checks that w carries a success Response to the request with the ID.
func assertAssertionResponse(t *testing.T, w *httptest.ResponseRecorder, id string) {
	t.Helper()

	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())

	_, response := postedResponse(t, w.Body.String())

	assert.Check(t, is.Equal(response.InResponseTo, id))
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	assert.Check(t, response.Assertion != nil || response.EncryptedAssertion != nil)
}

// authnRequestID returns the ID of the AuthnRequest in body.
func authnRequestID(t *testing.T, body []byte) string {
	t.Helper()

	start := strings.Index(string(body), ` ID="`)
	assert.Assert(t, start >= 0)

	id, _, _ := strings.Cut(string(body[start+len(` ID="`):]), `"`)

	return id
}

func TestServeSSORefusesReplayedPost(t *testing.T) {
	test := signatureTestIDP(t)
	useSession(test)

	body := signedPostBody(t, &test.SP, nil)
	id := authnRequestID(t, body)

	assertAssertionResponse(t, serveSSO(test, replayPostRequest(body, nil)), id)

	// The replay is answered at the ACS of the metadata, with no assertion.
	for range 2 {
		w := serveSSO(test, replayPostRequest(body, nil))
		assertRequestStatus(t, w, id, StatusRequester, StatusRequestDenied)
		assert.Check(t, is.Contains(w.Body.String(), `action="https://sp.example.com/saml2/acs"`))
	}

	// Another request of the same service provider is not affected.
	other := signedPostBody(t, &test.SP, nil)
	assert.Assert(t, authnRequestID(t, other) != id)
	assertAssertionResponse(t, serveSSO(test, replayPostRequest(other, nil)), authnRequestID(t, other))
}

func TestServeSSORefusesReplayedUnsignedPost(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	useSession(test)

	w, id := serveSSOModified(t, test, func(*AuthnRequest) {})
	assertAssertionResponse(t, w, id)

	// serveSSOModified makes the same request again, as the test random reader repeats itself.
	RandReader = &testRandomReader{}

	w, replayedID := serveSSOModified(t, test, func(request *AuthnRequest) { request.ID = id })
	assert.Check(t, is.Equal(replayedID, id))
	assertRequestStatus(t, w, id, StatusRequester, StatusRequestDenied)
}

func TestServeSSORefusesReplayedRedirect(t *testing.T) {
	test := signatureTestIDP(t)
	useSession(test)

	u := signedRedirectURL(t, test)

	first := serveSSO(test, httptest.NewRequest(http.MethodGet, u.String(), nil))
	assert.Assert(t, is.Equal(first.Code, http.StatusOK), "body: %s", first.Body.String())

	_, response := postedResponse(t, first.Body.String())
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))

	id := response.InResponseTo

	assertRequestStatus(t, serveSSO(test, httptest.NewRequest(http.MethodGet, u.String(), nil)), id, StatusRequester, StatusRequestDenied)

	// The request is the same one when a login form re-presents it as a POST.
	replay := replayPostRequest([]byte("<ignored/>"), url.Values{RedirectQueryFormField: {u.RawQuery}})
	assertRequestStatus(t, serveSSO(test, replay), id, StatusRequester, StatusRequestDenied)
}

// A SessionProvider that shows a login form is presented with the same request again when the form is posted,
// and again if the credentials were wrong. None of those is a replay: the request is used up when it is answered.
func TestServeSSOAllowsRequestRepresentedAfterLogin(t *testing.T) {
	for name, forced := range map[string]bool{"session": false, "forced": true} {
		t.Run(name, func(t *testing.T) {
			test := signatureTestIDP(t)
			store := newRecordingReplayStore()
			test.IDP.ReplayStore = store

			provider := &loginFormSessionProvider{}
			test.IDP.SessionProvider = provider

			body := signedPostBody(t, &test.SP, func(request *AuthnRequest) {
				if forced {
					forceAuthn := true
					request.ForceAuthn = &forceAuthn
				}
			})
			id := authnRequestID(t, body)

			// The request arrives, and then a login form posts it back with the wrong password.
			for range 3 {
				w := serveSSO(test, replayPostRequest(body, nil))
				assert.Check(t, is.Equal(w.Code, http.StatusOK))
				assert.Check(t, is.Equal(w.Body.String(), "login form"))
			}

			assert.Check(t, is.Equal(store.calls(), 0))

			provider.session = &Session{ID: "f00f00", UserName: "alice", NameID: "alice"}

			assertAssertionResponse(t, serveSSO(test, replayPostRequest(body, url.Values{"password": {"correct"}})), id)
			assert.Check(t, is.Equal(store.calls(), 1))

			// Once it is answered, presenting it again is a replay.
			assertRequestStatus(t, serveSSO(test, replayPostRequest(body, url.Values{"password": {"correct"}})), id, StatusRequester, StatusRequestDenied)
		})
	}
}

// loginFormSessionProvider is a SessionProvider which writes a login form until it has a session.
type loginFormSessionProvider struct {
	session *Session
}

func (p *loginFormSessionProvider) GetSession(w http.ResponseWriter, _ *http.Request, _ *IdpAuthnRequest) *Session {
	if p.session == nil {
		_, _ = w.Write([]byte("login form"))
	}

	return p.session
}

func (p *loginFormSessionProvider) GetForcedSession(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
	return p.GetSession(w, r, req)
}

func (p *loginFormSessionProvider) GetPassiveSession(*http.Request, *IdpAuthnRequest) *Session {
	return p.session
}

// Nothing is recorded for a request that isn't answered for a session, so a caller who is not authenticated
// can't fill the store.
func TestServeSSODoesNotRecordUnansweredRequests(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*AuthnRequest)
		body   func([]byte) []byte
		code   int
	}{
		"no session": {code: http.StatusOK},
		"passive without session": {code: http.StatusOK, mutate: func(request *AuthnRequest) {
			isPassive := true
			request.IsPassive = &isPassive
		}},
		"expired": {code: http.StatusOK, mutate: func(request *AuthnRequest) {
			request.IssueInstant = request.IssueInstant.Add(-time.Hour)
		}},
		"wrong destination": {code: http.StatusOK, mutate: func(request *AuthnRequest) {
			request.Destination = "https://other.example.com/saml/sso"
		}},
		"unknown issuer": {code: http.StatusBadRequest, mutate: func(request *AuthnRequest) {
			request.Issuer.Value = "https://unknown.example.com/metadata"
		}},
		"invalid signature": {code: http.StatusBadRequest, body: func(body []byte) []byte {
			return []byte(strings.Replace(string(body), `ForceAuthn="false"`, `ForceAuthn="true"`, 1))
		}},
	} {
		t.Run(name, func(t *testing.T) {
			test := signatureTestIDP(t)
			store := newRecordingReplayStore()
			test.IDP.ReplayStore = store
			test.IDP.SessionProvider = &loginFormSessionProvider{}

			body := signedPostBody(t, &test.SP, func(request *AuthnRequest) {
				forceAuthn := false
				request.ForceAuthn = &forceAuthn

				if tc.mutate != nil {
					tc.mutate(request)
				}
			})
			if tc.body != nil {
				body = tc.body(body)
			}

			for range 2 {
				w := serveSSO(test, replayPostRequest(body, nil))
				assert.Check(t, is.Equal(w.Code, tc.code), "body: %s", w.Body.String())
			}

			assert.Check(t, is.Equal(store.calls(), 0))
		})
	}
}

func TestServeSSORecordsRequestUntilItExpires(t *testing.T) {
	for name, maxAge := range map[string]time.Duration{"default": 0, "configured": 10 * time.Minute} {
		t.Run(name, func(t *testing.T) {
			test := signatureTestIDP(t)
			useSession(test)

			store := newRecordingReplayStore()
			test.IDP.ReplayStore = store
			test.IDP.MaxAuthnRequestAge = maxAge

			issued := TimeNow().Add(-30 * time.Second)
			body := signedPostBody(t, &test.SP, func(request *AuthnRequest) { request.IssueInstant = issued })

			r := replayPostRequest(body, nil)
			ctx := context.WithValue(r.Context(), replayTestContextKey{}, "value")
			assertAssertionResponse(t, serveSSO(test, r.WithContext(ctx)), authnRequestID(t, body))

			if maxAge == 0 {
				maxAge = MaxIssueDelay
			}

			assert.Assert(t, is.Equal(store.calls(), 1))
			assert.Check(t, store.expiries[0].Equal(issued.Add(maxAge).Add(2*MaxClockSkew)), "expires %s", store.expiries[0])
			assert.Check(t, is.Equal(store.contexts[0].Value(replayTestContextKey{}), "value"))
			assert.Check(t, is.Equal(store.keys[0], replayKey(replayKindAuthnRequest,
				test.IDP.MetadataURL.String(), test.SP.MetadataURL.String(), authnRequestID(t, body))))
		})
	}
}

type replayTestContextKey struct{}

// When the store can't tell whether a request is a replay, the request is refused.
func TestServeSSOFailsClosedWhenStoreFails(t *testing.T) {
	for name, storeErr := range map[string]error{
		"backend": errors.New("connection refused"),
		"full":    ErrReplayStoreFull,
	} {
		t.Run(name, func(t *testing.T) {
			test := signatureTestIDP(t)
			useSession(test)

			store := newRecordingReplayStore()
			store.err = storeErr
			test.IDP.ReplayStore = store

			body := signedPostBody(t, &test.SP, nil)
			id := authnRequestID(t, body)

			assertRequestStatus(t, serveSSO(test, replayPostRequest(body, nil)), id, StatusResponder, "")

			// The request was not used up, so it is answered once the store works again.
			store.err = nil

			assertAssertionResponse(t, serveSSO(test, replayPostRequest(body, nil)), id)
		})
	}
}

// A store that wraps ErrReplayed, as one with its own error type may, still reports a replay.
func TestServeSSOWrappedReplayError(t *testing.T) {
	test := signatureTestIDP(t)
	useSession(test)

	store := newRecordingReplayStore()
	store.err = fmt.Errorf("key exists: %w", ErrReplayed)
	test.IDP.ReplayStore = store

	body := signedPostBody(t, &test.SP, nil)

	assertRequestStatus(t, serveSSO(test, replayPostRequest(body, nil)), authnRequestID(t, body), StatusRequester, StatusRequestDenied)
}

func TestServeSSOConcurrentReplayIsAnsweredOnce(t *testing.T) {
	test := signatureTestIDP(t)
	useSession(test)

	body := signedPostBody(t, &test.SP, nil)

	// The deterministic readers of the fixture are not safe for concurrent use.
	previousRand, previousEncryptionRand := RandReader, xmlenc.RandReader

	t.Cleanup(func() { RandReader, xmlenc.RandReader = previousRand, previousEncryptionRand })

	RandReader, xmlenc.RandReader = rand.Reader, rand.Reader

	const workers = 16

	recorders := make([]*httptest.ResponseRecorder, workers)

	var wg sync.WaitGroup

	for i := range recorders {
		wg.Add(1)

		go func() {
			defer wg.Done()

			recorders[i] = serveSSO(test, replayPostRequest(body, nil))
		}()
	}

	wg.Wait()

	var answered, refused int

	for _, w := range recorders {
		_, response := postedResponse(t, w.Body.String())

		switch response.Status.StatusCode.Value {
		case StatusSuccess:
			answered++
		case StatusRequester:
			refused++
		}
	}

	assert.Check(t, is.Equal(answered, 1))
	assert.Check(t, is.Equal(refused, workers-1))
}

func TestIdpAuthnRequestCheckReplay(t *testing.T) {
	test := signatureTestIDP(t)
	body := signedPostBody(t, &test.SP, nil)

	validated := func() *IdpAuthnRequest {
		req, err := NewIdpAuthnRequest(&test.IDP, replayPostRequest(body, nil))
		assert.NilError(t, err)
		// Validate records nothing, however often the request is presented.
		assert.NilError(t, req.Validate())

		return req
	}

	assert.NilError(t, validated().CheckReplay())

	err := validated().CheckReplay()
	assert.Check(t, errors.Is(err, ErrReplayed))

	status, ok := RequestStatus(err)
	assert.Assert(t, ok)
	assert.Check(t, is.Equal(status.StatusCode.Value, StatusRequester))

	// A request made without an HTTP request has no context to pass on.
	req := validated()
	req.HTTPRequest = nil
	assert.Check(t, errors.Is(req.CheckReplay(), ErrReplayed))
}

func TestServeSLORefusesReplayedRequest(t *testing.T) {
	for binding, request := range map[string]func(*testing.T, *ServiceProvider, func(*LogoutRequest)) (*http.Request, string){
		"redirect": redirectLogoutRequest,
		"post":     postLogoutRequest,
	} {
		t.Run(binding, func(t *testing.T) {
			test, provider := logoutTestIDP(t)

			response := func(w *httptest.ResponseRecorder) LogoutResponse {
				if binding == "redirect" {
					location, response := redirectedLogoutResponse(t, w)
					assert.Check(t, strings.HasPrefix(location.String(), "https://sp.example.com/saml2/slo?"))

					return response
				}

				assert.Check(t, is.Contains(w.Body.String(), `action="https://sp.example.com/saml2/slo"`))

				_, _, response := postedLogoutResponse(t, w)

				return response
			}

			// The helpers make the same message each time, as the test random reader repeats itself.
			RandReader = &testRandomReader{}
			r, id := request(t, &test.SP, nil)
			first := response(serveSLO(test, r))
			assertLogoutStatus(t, &first, StatusSuccess, "")
			assert.Check(t, is.Len(provider.terminated, 1))

			RandReader = &testRandomReader{}
			r, replayedID := request(t, &test.SP, nil)
			assert.Assert(t, is.Equal(replayedID, id))

			replayed := response(serveSLO(test, r))
			assert.Check(t, is.Equal(replayed.InResponseTo, id))
			assertLogoutStatus(t, &replayed, StatusRequester, StatusRequestDenied)

			// The replay reached no session.
			assert.Check(t, is.Len(provider.lookups, 1))
			assert.Check(t, is.Len(provider.terminated, 1))
		})
	}
}

func TestServeSOAPLogoutRefusesReplayedRequest(t *testing.T) {
	test, provider := soapLogoutTestIDP(t)

	el, id := soapLogoutRequestElement(t, &test.SP, nil)
	body := soapLogoutEnvelope(t, el)

	first := soapLogoutResponse(t, serveSOAPLogout(test, soapLogoutPost(body)))
	assertLogoutStatus(t, first, StatusSuccess, "")
	assert.Check(t, is.Len(provider.terminated, 1))

	replayed := soapLogoutResponse(t, serveSOAPLogout(test, soapLogoutPost(body)))
	assert.Check(t, is.Equal(replayed.InResponseTo, id))
	assertLogoutStatus(t, replayed, StatusRequester, StatusRequestDenied)
	assert.Check(t, is.Len(provider.lookups, 1))
	assert.Check(t, is.Len(provider.terminated, 1))

	// The same request is a replay on the front channel too: the ID is recorded for the issuer, not the binding.
	assert.Check(t, errors.Is(test.IDP.checkReplay(context.Background(), replayKindLogoutRequest,
		test.SP.MetadataURL.String(), id, TimeNow()), ErrReplayed))
}

// A logout request is only recorded once it is verified and has passed every other check.
func TestLogoutDoesNotRecordRefusedRequests(t *testing.T) {
	for name, tc := range map[string]struct {
		unsigned bool
		mutate   func(*LogoutRequest)
	}{
		"unsigned":          {unsigned: true},
		"expired":           {mutate: func(request *LogoutRequest) { request.IssueInstant = request.IssueInstant.Add(-time.Hour) }},
		"wrong destination": {mutate: func(request *LogoutRequest) { request.Destination = "https://other.example.com/slo" }},
		"unknown issuer":    {mutate: func(request *LogoutRequest) { request.Issuer.Value = "https://unknown.example.com/metadata" }},
		"no name id":        {mutate: func(request *LogoutRequest) { request.NameID = nil }},
	} {
		t.Run(name, func(t *testing.T) {
			test, provider := soapLogoutTestIDP(t)
			store := newRecordingReplayStore()
			test.IDP.ReplayStore = store

			sp := test.SP
			if tc.unsigned {
				sp.SignatureMethod = ""
			}

			for range 2 {
				r, _ := postLogoutRequest(t, &sp, tc.mutate)
				serveSLO(test, r)

				r, _ = redirectLogoutRequest(t, &sp, tc.mutate)
				serveSLO(test, r)

				r, _ = soapLogoutRequest(t, &sp, tc.mutate)
				serveSOAPLogout(test, r)
			}

			assert.Check(t, is.Equal(store.calls(), 0))
			assert.Check(t, is.Len(provider.terminated, 0))
		})
	}
}

func TestLogoutRecordsRequestUntilItExpires(t *testing.T) {
	for name, tc := range map[string]struct {
		notOnOrAfter time.Duration
		expires      time.Duration
	}{
		"issue instant":        {expires: MaxIssueDelay},
		"earlier NotOnOrAfter": {notOnOrAfter: 20 * time.Second, expires: 20 * time.Second},
		"later NotOnOrAfter":   {notOnOrAfter: time.Hour, expires: MaxIssueDelay},
	} {
		t.Run(name, func(t *testing.T) {
			test, _ := soapLogoutTestIDP(t)
			store := newRecordingReplayStore()
			test.IDP.ReplayStore = store

			var issued time.Time

			r, id := soapLogoutRequest(t, &test.SP, func(request *LogoutRequest) {
				issued = request.IssueInstant

				if tc.notOnOrAfter != 0 {
					notOnOrAfter := issued.Add(tc.notOnOrAfter)
					request.NotOnOrAfter = &notOnOrAfter
				}
			})

			assertLogoutStatus(t, soapLogoutResponse(t, serveSOAPLogout(test, r)), StatusSuccess, "")

			assert.Assert(t, is.Equal(store.calls(), 1))
			assert.Check(t, store.expiries[0].Equal(issued.Add(tc.expires).Add(2*MaxClockSkew)), "expires %s", store.expiries[0])
			assert.Check(t, is.Equal(store.keys[0], replayKey(replayKindLogoutRequest,
				test.IDP.MetadataURL.String(), test.SP.MetadataURL.String(), id)))
		})
	}
}

func TestLogoutFailsClosedWhenStoreFails(t *testing.T) {
	test, provider := soapLogoutTestIDP(t)
	store := newRecordingReplayStore()
	store.err = errors.New("connection refused")
	test.IDP.ReplayStore = store

	r, id := postLogoutRequest(t, &test.SP, nil)
	_, _, posted := postedLogoutResponse(t, serveSLO(test, r))
	assert.Check(t, is.Equal(posted.InResponseTo, id))
	assertLogoutStatus(t, &posted, StatusResponder, "")

	r, _ = redirectLogoutRequest(t, &test.SP, nil)
	_, redirected := redirectedLogoutResponse(t, serveSLO(test, r))
	assertLogoutStatus(t, &redirected, StatusResponder, "")

	r, _ = soapLogoutRequest(t, &test.SP, nil)
	assertLogoutStatus(t, soapLogoutResponse(t, serveSOAPLogout(test, r)), StatusResponder, "")

	assert.Check(t, is.Equal(store.calls(), 3))
	assert.Check(t, is.Len(provider.lookups, 0))
	assert.Check(t, is.Len(provider.terminated, 0))
}
