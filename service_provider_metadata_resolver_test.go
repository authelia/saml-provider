package saml

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/golden"
)

var _ ServiceProviderProvider = (*ServiceProviderMetadataResolver)(nil)

// resolverTest has a fake clock, which TimeNow follows for as long as the test runs, and a verifier which trusts
// negotiationKey, the key that signMetadataXML signs with.
type resolverTest struct {
	t        *testing.T
	clock    *fakeClock
	verifier *MetadataVerifier
}

func newResolverTest(t *testing.T) *resolverTest {
	t.Helper()

	clock := newFakeClockAt(time.Date(2015, 12, 1, 1, 57, 9, 0, time.UTC))

	previous := TimeNow
	TimeNow = clock.Now

	t.Cleanup(func() { TimeNow = previous })

	_, cert := negotiationKey()

	return &resolverTest{t: t, clock: clock, verifier: &MetadataVerifier{Certificates: []*x509.Certificate{cert}}}
}

// resolver returns a resolver with the fake clock and no jitter, which is closed when the test ends.
func (rt *resolverTest) resolver(opts ServiceProviderMetadataResolverOptions) *ServiceProviderMetadataResolver {
	rt.t.Helper()

	opts.Clock = rt.clock
	if opts.RefreshJitter == 0 {
		opts.RefreshJitter = -1
	}

	resolver, err := NewServiceProviderMetadataResolver(opts)
	require.NoError(rt.t, err)

	rt.t.Cleanup(func() { assert.NoError(rt.t, resolver.Close()) })

	return resolver
}

// waitTimers waits until n goroutines wait for the fake clock, which is when every source of a started resolver
// has finished its refresh and waits for the next.
func (rt *resolverTest) waitTimers(n int) {
	rt.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.NoError(rt.t, rt.clock.BlockUntilContext(ctx, n))
}

// in returns the attribute for a validUntil that is d after the time of the fake clock.
func (rt *resolverTest) in(d time.Duration) string {
	return fmt.Sprintf(` validUntil="%s"`, rt.clock.Now().Add(d).UTC().Format("2006-01-02T15:04:05Z"))
}

const resolverTestNamespace = ` xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"`

func testSPDescriptor(entityID string) string {
	return `<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + entityID + `/acs" index="0"/></md:SPSSODescriptor>`
}

// testSPEntity returns an EntityDescriptor of a service provider, for use within a group.
func testSPEntity(entityID string) string {
	return `<md:EntityDescriptor entityID="` + entityID + `">` + testSPDescriptor(entityID) + `</md:EntityDescriptor>`
}

// testSPRoot returns an EntityDescriptor of a service provider that is the root of a document.
func testSPRoot(entityID, attrs string) string {
	return `<md:EntityDescriptor` + resolverTestNamespace + ` ID="e" entityID="` + entityID + `"` + attrs + `>` + testSPDescriptor(entityID) + `</md:EntityDescriptor>`
}

const testIDPEntity = `<md:EntityDescriptor entityID="https://idp.example.org"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
	`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.org/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`

// testGroup returns an EntitiesDescriptor that is the root of a document, with the service providers named.
func testGroup(attrs string, entityIDs ...string) string {
	var b strings.Builder

	b.WriteString(`<md:EntitiesDescriptor` + resolverTestNamespace + ` ID="agg"` + attrs + `>`)

	for _, entityID := range entityIDs {
		b.WriteString(testSPEntity(entityID))
	}

	b.WriteString(`</md:EntitiesDescriptor>`)

	return b.String()
}

const (
	sp1 = "https://sp1.example.org"
	sp2 = "https://sp2.example.org"
	sp3 = "https://sp3.example.org"
)

// metadataServer serves a document that a test can change, and counts the requests.
type metadataServer struct {
	*httptest.Server

	mu           sync.Mutex
	body         string
	status       int
	etag         string
	lastModified string
	hits         int
	notModified  int
	headers      []http.Header
}

func newMetadataServer(t *testing.T, body string) *metadataServer {
	t.Helper()

	s := &metadataServer{body: body}
	s.Server = httptest.NewServer(s)

	t.Cleanup(s.Close)

	return s
}

func (s *metadataServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.hits++
	s.headers = append(s.headers, r.Header.Clone())

	if s.status != 0 {
		w.WriteHeader(s.status)
		return
	}

	if s.etag != "" {
		w.Header().Set("ETag", s.etag)
	}

	if s.lastModified != "" {
		w.Header().Set("Last-Modified", s.lastModified)
	}

	if (s.etag != "" && r.Header.Get("If-None-Match") == s.etag) || (s.lastModified != "" && r.Header.Get("If-Modified-Since") == s.lastModified) {
		s.notModified++

		w.WriteHeader(http.StatusNotModified)

		return
	}

	_, _ = w.Write([]byte(s.body))
}

func (s *metadataServer) set(f func(s *metadataServer)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f(s)
}

func (s *metadataServer) count() (hits, notModified int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.hits, s.notModified
}

func isNotExist(t *testing.T, resolver *ServiceProviderMetadataResolver, entityID string) {
	t.Helper()

	_, err := resolver.GetServiceProvider(nil, entityID)
	assert.True(t, errors.Is(err, os.ErrNotExist), "%s: %v", entityID, err)
}

func isServed(t *testing.T, resolver *ServiceProviderMetadataResolver, entityID string) {
	t.Helper()

	metadata, err := resolver.GetServiceProvider(nil, entityID)
	if assert.NoError(t, err, entityID) {
		assert.Equal(t, entityID, metadata.EntityID)
	}
}

func TestMetadataResolverLoadsASignedAggregate(t *testing.T) {
	rt := newResolverTest(t)

	group := strings.Replace(testGroup(rt.in(7*24*time.Hour), sp1, sp2, sp3), `</md:EntitiesDescriptor>`, testIDPEntity+`</md:EntitiesDescriptor>`, 1)
	server := newMetadataServer(t, signMetadataXML(t, group))

	resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
		Sources: []MetadataSource{{URL: server.URL, Verifier: rt.verifier}},
	})

	// Nothing is served before the first load.
	isNotExist(t, resolver, sp1)

	require.NoError(t, resolver.Refresh(context.Background()))

	isServed(t, resolver, sp1)
	isServed(t, resolver, sp2)
	isServed(t, resolver, sp3)
	isNotExist(t, resolver, "https://idp.example.org")
	isNotExist(t, resolver, "https://unknown.example.org")

	// An entity in a group expires with the group.
	metadata, err := resolver.GetServiceProvider(nil, sp2)
	require.NoError(t, err)
	assert.True(t, metadata.ValidUntil.Equal(rt.clock.Now().Add(7*24*time.Hour)))
	assert.Len(t, metadata.SPSSODescriptors, 1)

	status := resolver.Status()
	require.Len(t, status, 1)
	assert.Equal(t, server.URL, status[0].Source)
	assert.Equal(t, 3, status[0].Entities)
	assert.NoError(t, status[0].Err)
	assert.True(t, status[0].LastSuccess.Equal(rt.clock.Now()))
	assert.True(t, status[0].ValidUntil.Equal(rt.clock.Now().Add(7*24*time.Hour)))

	assert.Contains(t, server.headers[0].Get("Accept"), "application/samlmetadata+xml")
}

func TestMetadataResolverLoadsASingleEntity(t *testing.T) {
	rt := newResolverTest(t)
	server := newMetadataServer(t, signMetadataXML(t, testSPRoot(sp1, rt.in(time.Hour))))

	resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
		Sources: []MetadataSource{{URL: server.URL, Verifier: rt.verifier}},
	})

	require.NoError(t, resolver.Refresh(context.Background()))
	isServed(t, resolver, sp1)
}

func TestMetadataResolverLoadsAFile(t *testing.T) {
	rt := newResolverTest(t)
	path := filepath.Join(t.TempDir(), "metadata.xml")

	require.NoError(t, os.WriteFile(path, []byte(testGroup(rt.in(24*time.Hour), sp1)), 0o600))

	// A file needs no signature.
	resolver := rt.resolver(ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{{File: path}}})

	require.NoError(t, resolver.Refresh(context.Background()))
	isServed(t, resolver, sp1)
	isNotExist(t, resolver, sp2)

	// A file that didn't change is not read again, as a 304 is not.
	loaded := resolver.sources[0].snapshot.Load()

	require.NoError(t, resolver.Refresh(context.Background()))
	assert.True(t, loaded == resolver.sources[0].snapshot.Load())

	require.NoError(t, os.WriteFile(path, []byte(testGroup(rt.in(24*time.Hour), sp1, sp2)), 0o600))
	require.NoError(t, os.Chtimes(path, time.Now().Add(time.Minute), time.Now().Add(time.Minute)))
	require.NoError(t, resolver.Refresh(context.Background()))
	isServed(t, resolver, sp2)

	// A file that is removed is a failed refresh.
	require.NoError(t, os.Remove(path))
	assert.ErrorContains(t, resolver.Refresh(context.Background()), path)
	isServed(t, resolver, sp2)
}

func TestMetadataResolverVerifiesAFileThatHasAVerifier(t *testing.T) {
	rt := newResolverTest(t)
	path := filepath.Join(t.TempDir(), "metadata.xml")

	require.NoError(t, os.WriteFile(path, []byte(testGroup(rt.in(24*time.Hour), sp1)), 0o600))

	resolver := rt.resolver(ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{{File: path, Verifier: rt.verifier}}})

	assert.ErrorContains(t, resolver.Refresh(context.Background()), "metadata is not signed")
	isNotExist(t, resolver, sp1)
}

func TestMetadataResolverSchedule(t *testing.T) {
	const (
		minInterval = 5 * time.Minute
		maxInterval = 4 * time.Hour
	)

	testCases := map[string]struct {
		validUntil    time.Duration
		cacheDuration string
		expected      time.Duration
	}{
		"cacheDuration":                       {validUntil: 7 * 24 * time.Hour, cacheDuration: "PT1H", expected: time.Hour},
		"no cacheDuration is the maximum":     {validUntil: 7 * 24 * time.Hour, expected: maxInterval},
		"cacheDuration above the maximum":     {validUntil: 7 * 24 * time.Hour, cacheDuration: "P1D", expected: maxInterval},
		"cacheDuration below the minimum":     {validUntil: 7 * 24 * time.Hour, cacheDuration: "PT1S", expected: minInterval},
		"validUntil before cacheDuration":     {validUntil: 40 * time.Minute, cacheDuration: "PT1H", expected: 30 * time.Minute},
		"validUntil before the maximum":       {validUntil: 2 * time.Hour, expected: 90 * time.Minute},
		"validUntil too near for the minimum": {validUntil: 4 * time.Minute, cacheDuration: "PT1H", expected: minInterval},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			rt := newResolverTest(t)

			attrs := rt.in(tc.validUntil)
			if tc.cacheDuration != "" {
				attrs += ` cacheDuration="` + tc.cacheDuration + `"`
			}

			server := newMetadataServer(t, signMetadataXML(t, testGroup(attrs, sp1)))

			resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
				Sources:            []MetadataSource{{URL: server.URL, Verifier: rt.verifier}},
				MinRefreshInterval: minInterval,
				MaxRefreshInterval: maxInterval,
			})

			require.NoError(t, resolver.Refresh(context.Background()))
			assert.Equal(t, tc.expected, resolver.Status()[0].NextRefresh.Sub(rt.clock.Now()))
		})
	}
}

func TestMetadataResolverDefaultIntervals(t *testing.T) {
	rt := newResolverTest(t)
	server := newMetadataServer(t, signMetadataXML(t, testGroup(rt.in(7*24*time.Hour), sp1)))

	resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
		Sources: []MetadataSource{{URL: server.URL, Verifier: rt.verifier}},
	})

	require.NoError(t, resolver.Refresh(context.Background()))
	assert.Equal(t, DefaultMetadataMaxRefreshInterval, resolver.Status()[0].NextRefresh.Sub(rt.clock.Now()))

	server.set(func(s *metadataServer) { s.status = http.StatusBadGateway })

	assert.NotNil(t, resolver.Refresh(context.Background()))
	assert.Equal(t, DefaultMetadataMinRefreshInterval, resolver.Status()[0].NextRefresh.Sub(rt.clock.Now()))
}

func TestMetadataResolverJitterOnlyShortensTheInterval(t *testing.T) {
	rt := newResolverTest(t)
	server := newMetadataServer(t, signMetadataXML(t, testGroup(rt.in(7*24*time.Hour)+` cacheDuration="PT1H"`, sp1)))

	previous := RandReader
	RandReader = strings.NewReader(strings.Repeat("\xff", 64) + strings.Repeat("\x00", 64))

	t.Cleanup(func() { RandReader = previous })

	resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
		Sources:       []MetadataSource{{URL: server.URL, Verifier: rt.verifier}},
		RefreshJitter: 0.5,
	})

	// The most that the jitter can take off, then the least.
	require.NoError(t, resolver.Refresh(context.Background()))

	interval := resolver.Status()[0].NextRefresh.Sub(rt.clock.Now())
	assert.True(t, interval >= 30*time.Minute && interval < 31*time.Minute, "%s", interval)

	RandReader = strings.NewReader(strings.Repeat("\x00", 64))

	require.NoError(t, resolver.Refresh(context.Background()))
	assert.Equal(t, time.Hour, resolver.Status()[0].NextRefresh.Sub(rt.clock.Now()))
}

func TestMetadataResolverRefreshesInTheBackground(t *testing.T) {
	rt := newResolverTest(t)
	server := newMetadataServer(t, signMetadataXML(t, testGroup(rt.in(7*24*time.Hour)+` cacheDuration="PT1H"`, sp1)))

	resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
		Sources: []MetadataSource{{URL: server.URL, Verifier: rt.verifier}},
	})

	// A source that was never loaded is loaded as soon as the resolver starts.
	require.NoError(t, resolver.Start(context.Background()))
	rt.waitTimers(1)
	isServed(t, resolver, sp1)

	hits, _ := server.count()
	assert.Equal(t, 1, hits)

	server.set(func(s *metadataServer) {
		s.body = signMetadataXML(t, testGroup(rt.in(7*24*time.Hour)+` cacheDuration="PT1H"`, sp1, sp2))
	})

	// Nothing happens before the cacheDuration has passed.
	rt.clock.Advance(59 * time.Minute)

	hits, _ = server.count()
	assert.Equal(t, 1, hits)
	isNotExist(t, resolver, sp2)

	rt.clock.Advance(time.Minute)
	rt.waitTimers(1)

	hits, _ = server.count()
	assert.Equal(t, 2, hits)
	isServed(t, resolver, sp2)

	rt.clock.Advance(time.Hour)
	rt.waitTimers(1)

	hits, _ = server.count()
	assert.Equal(t, 3, hits)
}

func TestMetadataResolverStartKeepsTheScheduleOfRefresh(t *testing.T) {
	rt := newResolverTest(t)
	server := newMetadataServer(t, signMetadataXML(t, testGroup(rt.in(7*24*time.Hour)+` cacheDuration="PT1H"`, sp1)))

	resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
		Sources: []MetadataSource{{URL: server.URL, Verifier: rt.verifier}},
	})

	require.NoError(t, resolver.Refresh(context.Background()))
	require.NoError(t, resolver.Start(context.Background()))
	rt.waitTimers(1)

	// The source was loaded by Refresh, so Start doesn't load it again.
	hits, _ := server.count()
	assert.Equal(t, 1, hits)

	// A call to Refresh moves the time that the source is due.
	rt.clock.Advance(30 * time.Minute)
	require.NoError(t, resolver.Refresh(context.Background()))

	rt.clock.Advance(30 * time.Minute)
	rt.waitTimers(1)

	hits, _ = server.count()
	assert.Equal(t, 2, hits)

	rt.clock.Advance(30 * time.Minute)
	rt.waitTimers(1)

	hits, _ = server.count()
	assert.Equal(t, 3, hits)
}

func TestMetadataResolverConditionalGet(t *testing.T) {
	testCases := map[string]struct {
		set    func(s *metadataServer)
		header string
		value  string
	}{
		"ETag":          {set: func(s *metadataServer) { s.etag = `"v1"` }, header: "If-None-Match", value: `"v1"`},
		"Last-Modified": {set: func(s *metadataServer) { s.lastModified = "Tue, 01 Dec 2015 00:00:00 GMT" }, header: "If-Modified-Since", value: "Tue, 01 Dec 2015 00:00:00 GMT"},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			rt := newResolverTest(t)
			server := newMetadataServer(t, signMetadataXML(t, testGroup(rt.in(24*time.Hour)+` cacheDuration="PT1H"`, sp1)))
			server.set(tc.set)

			resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
				Sources: []MetadataSource{{URL: server.URL, Verifier: rt.verifier}},
			})

			require.NoError(t, resolver.Refresh(context.Background()))
			assert.Equal(t, "", server.headers[0].Get(tc.header))

			loaded := resolver.sources[0].snapshot.Load()

			rt.clock.Advance(time.Hour)
			require.NoError(t, resolver.Refresh(context.Background()))

			hits, notModified := server.count()
			assert.Equal(t, 2, hits)
			assert.Equal(t, 1, notModified)
			assert.Equal(t, tc.value, server.headers[1].Get(tc.header))

			// The copy is kept as it is, counts as a success, and is scheduled from the time of the 304.
			assert.True(t, loaded == resolver.sources[0].snapshot.Load())
			isServed(t, resolver, sp1)

			status := resolver.Status()[0]
			assert.NoError(t, status.Err)
			assert.True(t, status.LastSuccess.Equal(rt.clock.Now()))
			assert.Equal(t, time.Hour, status.NextRefresh.Sub(rt.clock.Now()))

			// A changed document replaces it.
			server.set(func(s *metadataServer) {
				s.etag, s.lastModified = "", ""
				s.body = signMetadataXML(t, testGroup(rt.in(24*time.Hour), sp2))
			})

			require.NoError(t, resolver.Refresh(context.Background()))
			isServed(t, resolver, sp2)
			isNotExist(t, resolver, sp1)
		})
	}
}

// A publisher that answers 304 for ever doesn't keep a copy alive after its validUntil.
func TestMetadataResolverNotModifiedDoesNotExtendValidity(t *testing.T) {
	rt := newResolverTest(t)
	server := newMetadataServer(t, signMetadataXML(t, testGroup(rt.in(time.Hour), sp1)))
	server.set(func(s *metadataServer) { s.etag = `"v1"` })

	resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
		Sources: []MetadataSource{{URL: server.URL, Verifier: rt.verifier}},
	})

	require.NoError(t, resolver.Refresh(context.Background()))

	rt.clock.Advance(2 * time.Hour)
	assert.ErrorContains(t, resolver.Refresh(context.Background()), "expired")
	isNotExist(t, resolver, sp1)

	// The next request is not conditional.
	_ = resolver.Refresh(context.Background())

	assert.Equal(t, "", server.headers[2].Get("If-None-Match"))
}

func TestMetadataResolverKeepsTheLastGoodCopyUntilItExpires(t *testing.T) {
	failures := map[string]func(rt *resolverTest, s *metadataServer){
		"server error":   func(_ *resolverTest, s *metadataServer) { s.status = http.StatusInternalServerError },
		"not found":      func(_ *resolverTest, s *metadataServer) { s.status = http.StatusNotFound },
		"not XML":        func(_ *resolverTest, s *metadataServer) { s.body = "<html>" },
		"unsigned":       func(rt *resolverTest, s *metadataServer) { s.body = testGroup(rt.in(time.Hour), sp2) },
		"no validUntil":  func(rt *resolverTest, s *metadataServer) { s.body = signMetadataXML(rt.t, testGroup("", sp2)) },
		"no SP":          func(rt *resolverTest, s *metadataServer) { s.body = signMetadataXML(rt.t, testGroup(rt.in(time.Hour))) },
		"connection":     func(_ *resolverTest, s *metadataServer) { s.CloseClientConnections(); s.Listener.Close() },
		"not modified":   func(_ *resolverTest, s *metadataServer) { s.status = http.StatusNotModified },
		"partial answer": func(_ *resolverTest, s *metadataServer) { s.status = http.StatusPartialContent },
	}

	for name, fail := range failures {
		t.Run(name, func(t *testing.T) {
			rt := newResolverTest(t)
			server := newMetadataServer(t, signMetadataXML(t, testGroup(rt.in(24*time.Hour), sp1)))

			resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
				Sources: []MetadataSource{{URL: server.URL, Verifier: rt.verifier}},
			})

			require.NoError(t, resolver.Refresh(context.Background()))

			loaded := rt.clock.Now()

			server.set(func(s *metadataServer) { fail(rt, s) })

			// Each failure in a row doubles the wait, up to the maximum.
			for _, wait := range []time.Duration{5 * time.Minute, 10 * time.Minute, 20 * time.Minute, 40 * time.Minute, 80 * time.Minute, 160 * time.Minute, 4 * time.Hour, 4 * time.Hour} {
				err := resolver.Refresh(context.Background())
				assert.ErrorContains(t, err, server.URL)

				status := resolver.Status()[0]
				assert.NotNil(t, status.Err)
				assert.True(t, status.LastSuccess.Equal(loaded))
				assert.True(t, status.LastAttempt.Equal(rt.clock.Now()))
				assert.Equal(t, wait, status.NextRefresh.Sub(rt.clock.Now()))
				assert.Equal(t, 1, status.Entities)

				isServed(t, resolver, sp1)
				isNotExist(t, resolver, sp2)

				rt.clock.Advance(time.Hour)
			}

			// 8 hours have passed. It is served until MaxClockSkew after the validUntil (SAML2Int SDP-G01): one
			// second before that it is, and at that instant it is not.
			rt.clock.Advance(16*time.Hour + MaxClockSkew - time.Second)
			isServed(t, resolver, sp1)

			rt.clock.Advance(time.Second)
			isNotExist(t, resolver, sp1)

			// The next failed refresh drops it.
			assert.NotNil(t, resolver.Refresh(context.Background()))
			assert.Equal(t, 0, resolver.Status()[0].Entities)
			assert.Nil(t, resolver.sources[0].snapshot.Load())
		})
	}
}

func TestMetadataResolverRecoversAfterAFailure(t *testing.T) {
	rt := newResolverTest(t)
	server := newMetadataServer(t, signMetadataXML(t, testGroup(rt.in(24*time.Hour), sp1)))
	server.set(func(s *metadataServer) { s.status = http.StatusServiceUnavailable })

	resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
		Sources: []MetadataSource{{URL: server.URL, Verifier: rt.verifier}},
	})

	require.NoError(t, resolver.Start(context.Background()))
	rt.waitTimers(1)
	isNotExist(t, resolver, sp1)
	assert.ErrorContains(t, resolver.Status()[0].Err, "503")

	server.set(func(s *metadataServer) { s.status = 0 })

	rt.clock.Advance(5 * time.Minute)
	rt.waitTimers(1)
	isServed(t, resolver, sp1)
	assert.NoError(t, resolver.Status()[0].Err)
	assert.Equal(t, DefaultMetadataMaxRefreshInterval, resolver.Status()[0].NextRefresh.Sub(rt.clock.Now()))
}

func TestMetadataResolverSignature(t *testing.T) {
	rt := newResolverTest(t)

	signed := signMetadataXML(t, testSPRoot(sp1, rt.in(time.Hour)))
	evil := testSPEntity("https://evil.example.org")
	other := &MetadataVerifier{Certificates: []*x509.Certificate{mustParseCertificate(golden.Get(t, "idp_cert.pem"))}}

	// The signature of the entity, moved to a new root that has the ID it refers to, next to the entity it was
	// made for.
	signature := signed[strings.Index(signed, "<ds:Signature") : strings.Index(signed, "</ds:Signature>")+len("</ds:Signature>")]
	require.True(t, strings.Contains(signature, `URI="#e"`))

	moved := `<md:EntitiesDescriptor` + resolverTestNamespace + ` ID="e"` + rt.in(time.Hour) + `>` + signature + evil +
		strings.Replace(strings.Replace(signed, signature, "", 1), ` ID="e"`, ` ID="f"`, 1) + `</md:EntitiesDescriptor>`

	testCases := map[string]struct {
		body     string
		verifier *MetadataVerifier
		err      string
	}{
		"valid": {body: signed},
		"unsigned": {
			body: testSPRoot(sp1, rt.in(time.Hour)),
			err:  "metadata is not signed",
		},
		"tampered": {
			body: strings.Replace(signed, sp1+"/acs", "https://evil.example.org/acs", 1),
			err:  "cannot verify the signature of the metadata",
		},
		"validUntil extended": {
			body: strings.Replace(signed, rt.in(time.Hour), rt.in(2*time.Hour), 1),
			err:  "cannot verify the signature of the metadata",
		},
		"wrong key": {
			body:     signed,
			verifier: other,
			err:      "cannot verify the signature of the metadata",
		},
		"signed entity wrapped in an unsigned group": {
			body: `<md:EntitiesDescriptor` + resolverTestNamespace + ` ID="g"` + rt.in(time.Hour) + `>` + evil + signed + `</md:EntitiesDescriptor>`,
			err:  "metadata is not signed",
		},
		"signature moved to a new root": {
			body: moved,
			err:  "cannot verify the signature of the metadata",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			server := newMetadataServer(t, tc.body)

			verifier := rt.verifier
			if tc.verifier != nil {
				verifier = tc.verifier
			}

			resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
				Sources: []MetadataSource{{URL: server.URL, Verifier: verifier}},
			})

			err := resolver.Refresh(context.Background())
			isNotExist(t, resolver, "https://evil.example.org")

			if tc.err == "" {
				assert.NoError(t, err)
				isServed(t, resolver, sp1)

				return
			}

			assert.ErrorContains(t, err, tc.err)
			isNotExist(t, resolver, sp1)
		})
	}
}

// What is outside the element that the signature covers is not used.
func TestMetadataResolverUsesOnlyTheSignedElement(t *testing.T) {
	rt := newResolverTest(t)

	signed := signMetadataXML(t, testSPRoot(sp1, rt.in(time.Hour)))
	server := newMetadataServer(t, `<!-- `+testSPRoot("https://evil.example.org", rt.in(time.Hour))+` -->`+signed+`<?evil?>`)

	resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
		Sources: []MetadataSource{{URL: server.URL, Verifier: rt.verifier}},
	})

	require.NoError(t, resolver.Refresh(context.Background()))
	isServed(t, resolver, sp1)
	isNotExist(t, resolver, "https://evil.example.org")

	metadata, err := resolver.GetServiceProvider(nil, sp1)
	require.NoError(t, err)
	assert.Nil(t, metadata.Signature)
}

func TestMetadataResolverUnsignedURL(t *testing.T) {
	rt := newResolverTest(t)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(testSPRoot(sp1, rt.in(time.Hour))))
	}))
	t.Cleanup(server.Close)

	resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
		Sources:    []MetadataSource{{URL: server.URL, AllowUnsigned: true}},
		HTTPClient: server.Client(),
	})

	require.NoError(t, resolver.Refresh(context.Background()))
	isServed(t, resolver, sp1)

	// The certificate of the server is what authenticates the metadata, so one that isn't trusted is a failure.
	resolver = rt.resolver(ServiceProviderMetadataResolverOptions{
		Sources: []MetadataSource{{URL: server.URL, AllowUnsigned: true}},
	})

	assert.ErrorContains(t, resolver.Refresh(context.Background()), "certificate")
	isNotExist(t, resolver, sp1)
}

func TestMetadataResolverValidity(t *testing.T) {
	const day = 24 * time.Hour

	testCases := map[string]struct {
		attrs  func(rt *resolverTest) string
		source MetadataSource
		err    string
	}{
		"within the default": {
			attrs: func(rt *resolverTest) string { return rt.in(14 * day) },
		},
		"no validUntil": {
			attrs: func(*resolverTest) string { return "" },
			err:   "metadata has no validUntil",
		},
		"only a cacheDuration": {
			attrs: func(*resolverTest) string { return ` cacheDuration="PT1H"` },
			err:   "metadata has no validUntil",
		},
		"a validUntil in another namespace": {
			attrs: func(rt *resolverTest) string { return ` xmlns:x="urn:x" x:` + strings.TrimSpace(rt.in(day)) },
			err:   "metadata has no validUntil",
		},
		"validUntil in the past": {
			attrs: func(rt *resolverTest) string { return rt.in(-time.Hour) },
			err:   "metadata has expired",
		},
		// SAML2Int SDP-G01: the clock of the publisher may be MaxClockSkew behind or ahead.
		"validUntil the clock skew ago": {
			attrs: func(rt *resolverTest) string { return rt.in(-MaxClockSkew) },
			err:   "metadata has expired",
		},
		"validUntil within the clock skew": {
			attrs: func(rt *resolverTest) string { return rt.in(-MaxClockSkew + time.Second) },
		},
		"validUntil now": {
			attrs: func(rt *resolverTest) string { return rt.in(0) },
		},
		"validUntil at the default": {
			attrs: func(rt *resolverTest) string { return rt.in(14 * day) },
		},
		"validUntil beyond the default, within the clock skew": {
			attrs: func(rt *resolverTest) string { return rt.in(14*day + MaxClockSkew) },
		},
		"validUntil beyond the default and the clock skew": {
			attrs: func(rt *resolverTest) string { return rt.in(14*day + MaxClockSkew + time.Second) },
			err:   "metadata is valid for longer than 336h0m0s",
		},
		"validUntil beyond MaxValidity": {
			attrs:  func(rt *resolverTest) string { return rt.in(2 * day) },
			source: MetadataSource{MaxValidity: day},
			err:    "metadata is valid for longer than 24h0m0s",
		},
		"validUntil within MaxValidity": {
			attrs:  func(rt *resolverTest) string { return rt.in(28 * day) },
			source: MetadataSource{MaxValidity: 28 * day},
		},
		"validUntil that isn't a time": {
			attrs: func(*resolverTest) string { return ` validUntil="tomorrow"` },
			err:   "invalid validUntil",
		},
		"no validUntil, allowed": {
			attrs:  func(*resolverTest) string { return "" },
			source: MetadataSource{AllowMissingValidUntil: true},
		},
		"validUntil in the past, with AllowMissingValidUntil": {
			attrs:  func(rt *resolverTest) string { return rt.in(-MaxClockSkew) },
			source: MetadataSource{AllowMissingValidUntil: true},
			err:    "metadata has expired",
		},
		"validUntil too far, with AllowMissingValidUntil": {
			attrs:  func(rt *resolverTest) string { return rt.in(15 * day) },
			source: MetadataSource{AllowMissingValidUntil: true},
			err:    "metadata is valid for longer than",
		},
	}

	for name, tc := range testCases {
		for _, root := range []string{"EntitiesDescriptor", "EntityDescriptor"} {
			// The rule is the same for a signed URL and for a file.
			t.Run(name+"/"+root+"/url", func(t *testing.T) {
				rt := newResolverTest(t)

				body := testGroup(tc.attrs(rt), sp1)
				if root == "EntityDescriptor" {
					body = testSPRoot(sp1, tc.attrs(rt))
				}

				// The verifier refuses expired metadata itself, with its own message.
				tc := tc
				if tc.err == "metadata has expired" {
					tc.err = "signed metadata has expired"
				}

				server := newMetadataServer(t, signMetadataXML(t, body))

				source := tc.source
				source.URL, source.Verifier = server.URL, rt.verifier

				resolver := rt.resolver(ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{source}})
				checkValidity(t, resolver, tc.err)
			})

			t.Run(name+"/"+root+"/file", func(t *testing.T) {
				rt := newResolverTest(t)

				body := testGroup(tc.attrs(rt), sp1)
				if root == "EntityDescriptor" {
					body = testSPRoot(sp1, tc.attrs(rt))
				}

				source := tc.source
				source.File = filepath.Join(t.TempDir(), "metadata.xml")

				require.NoError(t, os.WriteFile(source.File, []byte(body), 0o600))

				resolver := rt.resolver(ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{source}})
				checkValidity(t, resolver, tc.err)
			})
		}
	}
}

func checkValidity(t *testing.T, resolver *ServiceProviderMetadataResolver, expected string) {
	t.Helper()

	err := resolver.Refresh(context.Background())

	if expected == "" {
		assert.NoError(t, err)
		isServed(t, resolver, sp1)

		return
	}

	assert.ErrorContains(t, err, expected)
	isNotExist(t, resolver, sp1)
}

// Metadata with no validUntil never expires, and is replaced by the next refresh that succeeds.
func TestMetadataResolverWithoutValidUntilIsServedUntilReplaced(t *testing.T) {
	rt := newResolverTest(t)
	server := newMetadataServer(t, signMetadataXML(t, testSPRoot(sp1, "")))

	resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
		Sources: []MetadataSource{{URL: server.URL, Verifier: rt.verifier, AllowMissingValidUntil: true}},
	})

	require.NoError(t, resolver.Refresh(context.Background()))
	assert.True(t, resolver.Status()[0].ValidUntil.IsZero())

	server.set(func(s *metadataServer) { s.status = http.StatusInternalServerError })
	rt.clock.Advance(365 * 24 * time.Hour)

	assert.NotNil(t, resolver.Refresh(context.Background()))
	isServed(t, resolver, sp1)
}

func TestMetadataResolverSourcesInOrder(t *testing.T) {
	rt := newResolverTest(t)

	first := newMetadataServer(t, signMetadataXML(t, testGroup(rt.in(time.Hour), sp1, sp2)))
	second := newMetadataServer(t, signMetadataXML(t, strings.Replace(testGroup(rt.in(2*time.Hour), sp2, sp3), sp2+"/acs", sp2+"/second", 1)))
	path := filepath.Join(t.TempDir(), "metadata.xml")

	require.NoError(t, os.WriteFile(path, []byte(testSPRoot("https://local.example.org", "")), 0o600))

	resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
		Sources: []MetadataSource{
			{URL: first.URL, Verifier: rt.verifier},
			{URL: second.URL, Verifier: rt.verifier},
			{File: path, AllowMissingValidUntil: true},
		},
	})

	require.NoError(t, resolver.Refresh(context.Background()))

	for _, entityID := range []string{sp1, sp2, sp3, "https://local.example.org"} {
		isServed(t, resolver, entityID)
	}

	acs := func() string {
		metadata, err := resolver.GetServiceProvider(nil, sp2)
		require.NoError(t, err)

		return metadata.SPSSODescriptors[0].AssertionConsumerServices[0].Location
	}

	// An entity that two sources have comes from the first.
	assert.Equal(t, sp2+"/acs", acs())

	// One source that fails doesn't stop the others, and the error names it.
	first.set(func(s *metadataServer) { s.status = http.StatusInternalServerError })
	second.set(func(s *metadataServer) { s.body = signMetadataXML(t, testGroup(rt.in(2*time.Hour), sp2)) })

	err := resolver.Refresh(context.Background())
	assert.ErrorContains(t, err, first.URL)
	assert.False(t, strings.Contains(err.Error(), second.URL))
	isNotExist(t, resolver, sp3)

	// When the first has expired, the second is what is left.
	rt.clock.Advance(time.Hour + MaxClockSkew)
	isNotExist(t, resolver, sp1)
	assert.Equal(t, sp2+"/acs", acs())
	isServed(t, resolver, "https://local.example.org")
}

func TestMetadataResolverFilter(t *testing.T) {
	rt := newResolverTest(t)
	server := newMetadataServer(t, signMetadataXML(t, testGroup(rt.in(time.Hour), sp1, sp2, sp3)))

	resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
		Sources: []MetadataSource{{URL: server.URL, Verifier: rt.verifier, Filter: func(metadata *EntityDescriptor) bool {
			return metadata.EntityID == sp2
		}}},
	})

	require.NoError(t, resolver.Refresh(context.Background()))
	isServed(t, resolver, sp2)
	isNotExist(t, resolver, sp1)
	isNotExist(t, resolver, sp3)
	assert.Equal(t, 1, resolver.Status()[0].Entities)
}

func TestMetadataResolverLimitsTheSize(t *testing.T) {
	rt := newResolverTest(t)

	body := signMetadataXML(t, testGroup(rt.in(time.Hour), sp1))
	server := newMetadataServer(t, body)
	path := filepath.Join(t.TempDir(), "metadata.xml")

	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	for _, source := range []MetadataSource{{URL: server.URL, Verifier: rt.verifier}, {File: path}} {
		resolver := rt.resolver(ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{source}, MaxSize: int64(len(body)) - 1})

		assert.ErrorContains(t, resolver.Refresh(context.Background()), fmt.Sprintf("larger than %d bytes", len(body)-1))
		isNotExist(t, resolver, sp1)

		resolver = rt.resolver(ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{source}, MaxSize: int64(len(body))})

		assert.NoError(t, resolver.Refresh(context.Background()))
		isServed(t, resolver, sp1)
	}
}

func TestMetadataResolverFetchTimeout(t *testing.T) {
	rt := newResolverTest(t)

	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)

	resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
		Sources:      []MetadataSource{{URL: server.URL, Verifier: rt.verifier}},
		FetchTimeout: 50 * time.Millisecond,
	})

	assert.ErrorContains(t, resolver.Refresh(context.Background()), "deadline exceeded")

	// The context of the caller bounds it as well.
	resolver = rt.resolver(ServiceProviderMetadataResolverOptions{
		Sources: []MetadataSource{{URL: server.URL, Verifier: rt.verifier}},
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	assert.ErrorContains(t, resolver.Refresh(ctx), "context canceled")
}

func TestMetadataResolverConcurrentUse(t *testing.T) {
	rt := newResolverTest(t)

	bodies := []string{
		signMetadataXML(t, testGroup(rt.in(time.Hour), sp1, sp2)),
		signMetadataXML(t, testGroup(rt.in(time.Hour), sp1, sp3)),
	}
	server := newMetadataServer(t, bodies[0])
	path := filepath.Join(t.TempDir(), "metadata.xml")

	require.NoError(t, os.WriteFile(path, []byte(testSPRoot("https://local.example.org", rt.in(time.Hour))), 0o600))

	resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
		Sources:            []MetadataSource{{URL: server.URL, Verifier: rt.verifier}, {File: path}},
		MinRefreshInterval: time.Millisecond,
		MaxRefreshInterval: time.Millisecond,
	})

	require.NoError(t, resolver.Refresh(context.Background()))
	require.NoError(t, resolver.Start(context.Background()))

	var wg sync.WaitGroup

	for range 8 {
		wg.Go(func() {
			for range 200 {
				metadata, err := resolver.GetServiceProvider(nil, sp1)
				if err != nil || metadata.EntityID != sp1 {
					t.Errorf("sp1 must always be served: %v", err)
				}

				_, _ = resolver.GetServiceProvider(nil, sp2)
				_, _ = resolver.GetServiceProvider(nil, "https://local.example.org")
				_ = resolver.Status()
			}
		})
	}

	for i := range 4 {
		wg.Go(func() {
			for j := range 10 {
				server.set(func(s *metadataServer) { s.body = bodies[(i+j)%2] })

				if err := resolver.Refresh(context.Background()); err != nil {
					t.Errorf("refresh: %v", err)
				}
			}
		})
	}

	wg.Go(func() {
		for range 50 {
			rt.clock.Advance(time.Millisecond)
			runtime.Gosched()
		}
	})

	wg.Wait()
	assert.NoError(t, resolver.Close())
}

func TestMetadataResolverLifecycle(t *testing.T) {
	rt := newResolverTest(t)

	server := newMetadataServer(t, signMetadataXML(t, testGroup(rt.in(time.Hour), sp1)))
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

	options := ServiceProviderMetadataResolverOptions{
		Sources: []MetadataSource{
			{URL: server.URL, Verifier: rt.verifier},
			{URL: server.URL + "/second", Verifier: rt.verifier},
			{URL: server.URL + "/third", Verifier: rt.verifier},
		},
		HTTPClient: client,
	}

	goroutines := func() int {
		client.CloseIdleConnections()
		runtime.Gosched()

		return runtime.NumGoroutine()
	}

	before := goroutines()

	// Close stops every goroutine, whether the resolver waits or not.
	resolver := rt.resolver(options)

	require.NoError(t, resolver.Start(context.Background()))
	rt.waitTimers(3)
	assert.True(t, goroutines() >= before+3)

	assert.ErrorContains(t, resolver.Start(context.Background()), "already started")

	require.NoError(t, resolver.Close())
	require.NoError(t, resolver.Close())
	assertGoroutines(t, goroutines, before)

	assert.ErrorContains(t, resolver.Start(context.Background()), "closed")

	// What was loaded is still served, and Refresh still works.
	isServed(t, resolver, sp1)
	assert.NoError(t, resolver.Refresh(context.Background()))

	// So does the end of the context it was started with.
	resolver = rt.resolver(options)

	ctx, cancel := context.WithCancel(context.Background())

	require.NoError(t, resolver.Start(ctx))
	rt.waitTimers(3)
	cancel()
	assertGoroutines(t, goroutines, before)
	require.NoError(t, resolver.Close())

	// A resolver that was never started can be closed.
	require.NoError(t, rt.resolver(options).Close())
}

func assertGoroutines(t *testing.T, goroutines func() int, expected int) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)

	for goroutines() > expected && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	assert.True(t, goroutines() <= expected, "%d goroutines, expected %d", goroutines(), expected)
}

// Close doesn't wait for a publisher that doesn't answer.
func TestMetadataResolverCloseAbortsAFetch(t *testing.T) {
	rt := newResolverTest(t)

	started := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		started <- struct{}{}

		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)

	resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
		Sources: []MetadataSource{{URL: server.URL, Verifier: rt.verifier}},
	})

	require.NoError(t, resolver.Start(context.Background()))
	<-started

	closed := make(chan error, 1)

	go func() { closed <- resolver.Close() }()

	select {
	case err := <-closed:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Close didn't return")
	}

	assert.ErrorContains(t, resolver.Status()[0].Err, "context canceled")
}

func TestNewServiceProviderMetadataResolverRefuses(t *testing.T) {
	verifier := newResolverTest(t).verifier

	testCases := map[string]struct {
		opts ServiceProviderMetadataResolverOptions
		err  string
	}{
		"no sources": {
			err: "no metadata sources",
		},
		"neither a URL nor a file": {
			opts: ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{{}}},
			err:  "metadata source 0 must have either a URL or a File",
		},
		"a URL and a file": {
			opts: ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{{URL: "https://md.example.org/", File: "md.xml", Verifier: verifier}}},
			err:  "metadata source 0 must have either a URL or a File",
		},
		"a URL with no verifier": {
			opts: ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{{URL: "https://md.example.org/"}}},
			err:  "metadata source https://md.example.org/ must have a Verifier, or set AllowUnsigned",
		},
		"an unsigned URL that is not https": {
			opts: ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{{URL: "http://md.example.org/", AllowUnsigned: true}}},
			err:  "metadata source http://md.example.org/ must be an https URL to be used without a signature",
		},
		"a verifier and AllowUnsigned": {
			opts: ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{{URL: "https://md.example.org/", Verifier: verifier, AllowUnsigned: true}}},
			err:  "metadata source https://md.example.org/ has both a Verifier and AllowUnsigned",
		},
		"a verifier with no certificates": {
			opts: ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{{URL: "https://md.example.org/", Verifier: &MetadataVerifier{}}}},
			err:  "metadata source https://md.example.org/ has a Verifier with no certificates",
		},
		"a URL of another scheme": {
			opts: ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{{URL: "file:///etc/passwd", Verifier: verifier}}},
			err:  "metadata source file:///etc/passwd must be an absolute http or https URL",
		},
		"a relative URL": {
			opts: ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{{URL: "/metadata", Verifier: verifier}}},
			err:  "must be an absolute http or https URL",
		},
		"a negative MaxValidity": {
			opts: ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{{File: "md.xml", MaxValidity: -time.Second}}},
			err:  "metadata source md.xml has a negative MaxValidity",
		},
		"the second source": {
			opts: ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{{File: "md.xml"}, {}}},
			err:  "metadata source 1 must have either a URL or a File",
		},
		"a minimum above the maximum": {
			opts: ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{{File: "md.xml"}}, MinRefreshInterval: time.Hour, MaxRefreshInterval: time.Minute},
			err:  "MinRefreshInterval is longer than MaxRefreshInterval",
		},
		"a negative interval": {
			opts: ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{{File: "md.xml"}}, MinRefreshInterval: -time.Hour},
			err:  "must not be negative",
		},
		"a jitter of one": {
			opts: ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{{File: "md.xml"}}, RefreshJitter: 1},
			err:  "RefreshJitter must be less than 1",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			_, err := NewServiceProviderMetadataResolver(tc.opts)
			assert.ErrorContains(t, err, tc.err)
		})
	}
}

// The identity provider uses the resolver as its ServiceProviderProvider.
func TestMetadataResolverAsTheProviderOfAnIdentityProvider(t *testing.T) {
	test := NewIdentityProviderTest(t)
	rt := newResolverTest(t)
	server := newMetadataServer(t, signMetadataXML(t, testGroup(rt.in(time.Hour), sp1)))

	resolver := rt.resolver(ServiceProviderMetadataResolverOptions{
		Sources: []MetadataSource{{URL: server.URL, Verifier: rt.verifier}},
	})

	require.NoError(t, resolver.Refresh(context.Background()))

	test.IDP.ServiceProviderProvider = resolver

	metadata, err := test.IDP.serviceProvider(httptest.NewRequest(http.MethodGet, "/", nil), sp1)
	require.NoError(t, err)
	assert.Equal(t, sp1, metadata.EntityID)

	_, err = test.IDP.serviceProvider(httptest.NewRequest(http.MethodGet, "/", nil), sp2)
	assert.True(t, errors.Is(err, os.ErrNotExist))

	rt.clock.Advance(time.Hour + MaxClockSkew)

	_, err = test.IDP.serviceProvider(httptest.NewRequest(http.MethodGet, "/", nil), sp1)
	assert.True(t, errors.Is(err, os.ErrNotExist))
}

// Without a Clock, the time is that of TimeNow, as for the rest of the package.
func TestMetadataResolverDefaultClockFollowsTimeNow(t *testing.T) {
	rt := newResolverTest(t)
	path := filepath.Join(t.TempDir(), "metadata.xml")

	require.NoError(t, os.WriteFile(path, []byte(testSPRoot(sp1, rt.in(time.Hour))), 0o600))

	resolver, err := NewServiceProviderMetadataResolver(ServiceProviderMetadataResolverOptions{Sources: []MetadataSource{{File: path}}})
	require.NoError(t, err)

	require.NoError(t, resolver.Refresh(context.Background()))
	isServed(t, resolver, sp1)
	assert.True(t, resolver.Status()[0].LastSuccess.Equal(rt.clock.Now()))

	rt.clock.Advance(time.Hour + MaxClockSkew)
	isNotExist(t, resolver, sp1)
}
