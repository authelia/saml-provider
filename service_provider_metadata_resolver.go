package saml

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jonboulle/clockwork"

	"authelia.com/provider/saml/logger"
)

// The defaults of a ServiceProviderMetadataResolver.
const (
	// DefaultMetadataMaxValidity is how far in the future the validUntil of metadata may be, see
	// MetadataSource.MaxValidity. It is how long a key that was withdrawn can still be used by someone who
	// replays the last metadata that had it, and it is what large federations publish.
	DefaultMetadataMaxValidity = 14 * 24 * time.Hour

	// DefaultMetadataMinRefreshInterval is the least time between two requests to a source.
	DefaultMetadataMinRefreshInterval = 5 * time.Minute

	// DefaultMetadataMaxRefreshInterval is the most time between two requests to a source.
	DefaultMetadataMaxRefreshInterval = 4 * time.Hour

	// DefaultMetadataRefreshJitter is the part of the time until a refresh that is random.
	DefaultMetadataRefreshJitter = 0.1

	// DefaultMetadataFetchTimeout is the time a source has to answer a request in full.
	DefaultMetadataFetchTimeout = time.Minute

	// DefaultMetadataMaxSize is the size of the largest document that is read, which allows for the aggregate of
	// a large federation.
	DefaultMetadataMaxSize int64 = 128 << 20
)

// MetadataSource is where a ServiceProviderMetadataResolver loads metadata from: a URL or a file, which holds an
// EntityDescriptor, or an EntitiesDescriptor such as the aggregate of a federation.
type MetadataSource struct {
	// URL is the http or https URL of the metadata. Either it or File is set.
	URL string

	// File is the path of a file that holds the metadata.
	File string

	// Verifier verifies the signature on the root element of the metadata, and only the element that the
	// signature covers is used. A URL must have one, unless AllowUnsigned is set. A file may have one, for a
	// file that comes from somewhere else, and is otherwise trusted as the configuration is.
	Verifier *MetadataVerifier

	// AllowUnsigned lets a URL be used without a Verifier. The URL must be https, as the certificate of the
	// server is then all that authenticates the metadata (SAML2Int SDP-MD02): whoever can answer for that
	// host, or issue a certificate for it that the HTTPClient trusts, decides which keys are trusted.
	AllowUnsigned bool

	// MaxValidity is how far in the future the validUntil of the root element may be. Metadata that is valid for
	// longer is refused (SAML2Int SDP-MD03). Zero means DefaultMetadataMaxValidity.
	MaxValidity time.Duration

	// AllowMissingValidUntil accepts metadata whose root element has no validUntil, which SAML2Int SDP-MD03
	// requires to be refused and which is refused by default, from a URL and from a file. It is for the
	// metadata of a single service provider that is maintained by hand. Such metadata never expires: a key in
	// it is trusted until a refresh succeeds that no longer has it. A validUntil that is there must still be in
	// the future, and no further than MaxValidity.
	AllowMissingValidUntil bool

	// Filter, when it isn't nil, is called for each service provider in the metadata, and one that it returns
	// false for is not served. The aggregate of a federation names every service provider in it.
	Filter func(metadata *EntityDescriptor) bool
}

// ServiceProviderMetadataResolverOptions are the settings of a ServiceProviderMetadataResolver.
type ServiceProviderMetadataResolverOptions struct {
	// Sources are where the metadata comes from. A service provider that more than one source has is served
	// from the first that has it and has not expired.
	Sources []MetadataSource

	// HTTPClient makes the requests. If it is nil, a client with no settings of its own is used. Redirects
	// are followed as it decides.
	HTTPClient *http.Client

	// Clock gives the time and the timers. If it is nil, the timers are real and the time is that of TimeNow,
	// as everywhere else in this package. The signature is verified at the time of TimeNow whatever the Clock
	// is, so a test that sets a Clock points TimeNow at it.
	Clock clockwork.Clock

	// Logger is where a failed refresh is logged. If it is nil, logger.DefaultLogger is used.
	Logger logger.Interface

	// MinRefreshInterval and MaxRefreshInterval bound the time between two requests to a source. The metadata
	// is refreshed when its cacheDuration has passed, and before its validUntil, within these. Zero means
	// DefaultMetadataMinRefreshInterval and DefaultMetadataMaxRefreshInterval.
	MinRefreshInterval time.Duration
	MaxRefreshInterval time.Duration

	// RefreshJitter is the largest part of the time until a refresh that is taken off it at random, so that
	// identity providers which start together don't all ask at once. Zero means DefaultMetadataRefreshJitter,
	// and a negative value means none.
	RefreshJitter float64

	// FetchTimeout is the time a source has to answer in full. Zero means DefaultMetadataFetchTimeout.
	FetchTimeout time.Duration

	// MaxSize is the size in bytes of the largest document that is read. Zero means DefaultMetadataMaxSize.
	MaxSize int64
}

// MetadataSourceStatus is the state of a source of a ServiceProviderMetadataResolver.
type MetadataSourceStatus struct {
	// Source is the URL or the file.
	Source string

	// Entities is the number of service providers that were loaded, whether or not they have expired since.
	Entities int

	// ValidUntil is the validUntil of the metadata that was loaded, or zero if it has none.
	ValidUntil time.Time

	// LastAttempt and LastSuccess are when the source was last asked, and when that last succeeded.
	LastAttempt time.Time
	LastSuccess time.Time

	// NextRefresh is when a resolver that was started asks again.
	NextRefresh time.Time

	// Err is why the last attempt failed, or nil if it didn't.
	Err error
}

// ServiceProviderMetadataResolver is a ServiceProviderProvider which loads the metadata of service providers from
// URLs and files, and keeps it fresh. For each source it verifies the signature of the metadata, refuses metadata
// that doesn't expire or expires too late (SAML2Int SDP-MD03), and asks again when the cacheDuration of the
// metadata has passed and before its validUntil. When a refresh fails, what was loaded last is served until its
// validUntil. It is safe for concurrent use.
//
// Refresh loads every source once. Start refreshes them in the background, until Close.
type ServiceProviderMetadataResolver struct {
	sources []*metadataSource
	client  *http.Client
	clock   clockwork.Clock
	log     logger.Interface

	minInterval time.Duration
	maxInterval time.Duration
	jitter      float64
	timeout     time.Duration
	maxSize     int64

	mu      sync.Mutex
	started bool
	closed  bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// metadataSource is a source and what was loaded from it.
type metadataSource struct {
	MetadataSource

	name string

	// snapshot is what is served, or nil.
	snapshot atomic.Pointer[metadataSnapshot]

	// mu is held for a refresh, so that there is one at a time, and guards what follows.
	mu          sync.Mutex
	validators  metadataValidators
	failures    int
	lastAttempt time.Time
	lastSuccess time.Time
	nextRefresh time.Time
	err         error
}

// metadataSnapshot is a document that was loaded. It is never changed.
type metadataSnapshot struct {
	entities      map[string]*EntityDescriptor
	validUntil    time.Time
	cacheDuration time.Duration
}

// metadataValidators identify the document that was loaded, to ask for it only if it has changed.
type metadataValidators struct {
	etag         string
	lastModified string
	modTime      time.Time
	size         int64
}

// timeNowClock is the real clock, but for the time, which is that of TimeNow.
type timeNowClock struct {
	clockwork.Clock
}

// Now returns the time of TimeNow.
func (timeNowClock) Now() time.Time {
	return TimeNow()
}

// NewServiceProviderMetadataResolver returns a resolver for the sources of opts, or an error if opts can't be
// used. It doesn't load anything: call Refresh to load the sources once, and Start to keep them fresh.
func NewServiceProviderMetadataResolver(opts ServiceProviderMetadataResolverOptions) (*ServiceProviderMetadataResolver, error) {
	r := &ServiceProviderMetadataResolver{
		client:      opts.HTTPClient,
		clock:       opts.Clock,
		log:         opts.Logger,
		minInterval: opts.MinRefreshInterval,
		maxInterval: opts.MaxRefreshInterval,
		jitter:      opts.RefreshJitter,
		timeout:     opts.FetchTimeout,
		maxSize:     opts.MaxSize,
	}

	if r.minInterval < 0 || r.maxInterval < 0 || r.timeout < 0 || r.maxSize < 0 {
		return nil, errors.New("MinRefreshInterval, MaxRefreshInterval, FetchTimeout and MaxSize must not be negative")
	}

	r.setDefaults()

	if r.minInterval > r.maxInterval {
		return nil, errors.New("MinRefreshInterval is longer than MaxRefreshInterval")
	}

	if r.jitter >= 1 {
		return nil, errors.New("RefreshJitter must be less than 1")
	}

	if len(opts.Sources) == 0 {
		return nil, errors.New("no metadata sources")
	}

	for i, source := range opts.Sources {
		s, err := newMetadataSource(i, source)
		if err != nil {
			return nil, err
		}

		r.sources = append(r.sources, s)
	}

	return r, nil
}

// setDefaults replaces each setting that is zero with its default.
func (r *ServiceProviderMetadataResolver) setDefaults() {
	if r.client == nil {
		r.client = &http.Client{}
	}

	if r.clock == nil {
		r.clock = timeNowClock{Clock: clockwork.NewRealClock()}
	}

	if r.log == nil {
		r.log = logger.DefaultLogger
	}

	if r.minInterval == 0 {
		r.minInterval = DefaultMetadataMinRefreshInterval
	}

	if r.maxInterval == 0 {
		r.maxInterval = DefaultMetadataMaxRefreshInterval
	}

	switch {
	case r.jitter == 0:
		r.jitter = DefaultMetadataRefreshJitter
	case r.jitter < 0:
		r.jitter = 0
	}

	if r.timeout == 0 {
		r.timeout = DefaultMetadataFetchTimeout
	}

	if r.maxSize == 0 {
		r.maxSize = DefaultMetadataMaxSize
	}
}

// newMetadataSource returns the state of the source at index, or an error if the source can't be used.
func newMetadataSource(index int, source MetadataSource) (*metadataSource, error) {
	if (source.URL == "") == (source.File == "") {
		return nil, fmt.Errorf("metadata source %d must have either a URL or a File", index)
	}

	s := &metadataSource{MetadataSource: source, name: source.URL + source.File}

	if source.MaxValidity < 0 {
		return nil, fmt.Errorf("metadata source %s has a negative MaxValidity", s.name)
	}

	if s.MaxValidity == 0 {
		s.MaxValidity = DefaultMetadataMaxValidity
	}

	if source.Verifier != nil && len(source.Verifier.Certificates) == 0 {
		return nil, fmt.Errorf("metadata source %s has a Verifier with no certificates", s.name)
	}

	if source.URL != "" {
		if err := checkMetadataSourceURL(source, s.name); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// checkMetadataSourceURL returns an error unless the URL of the source is an http or https URL, and the source
// either has a verifier, or allows unsigned metadata and is an https URL.
func checkMetadataSourceURL(source MetadataSource, name string) error {
	location, err := url.Parse(source.URL)
	if err != nil || (location.Scheme != "http" && location.Scheme != "https") || location.Host == "" {
		return fmt.Errorf("metadata source %s must be an absolute http or https URL", name)
	}

	switch {
	case source.Verifier != nil && source.AllowUnsigned:
		return fmt.Errorf("metadata source %s has both a Verifier and AllowUnsigned", name)
	case source.Verifier == nil && !source.AllowUnsigned:
		return fmt.Errorf("metadata source %s must have a Verifier, or set AllowUnsigned", name)
	case source.Verifier == nil && location.Scheme != "https":
		// SAML2Int SDP-MD02: a signature, or the certificate of the server.
		return fmt.Errorf("metadata source %s must be an https URL to be used without a signature", name)
	}

	return nil
}

// GetServiceProvider returns the metadata of the service provider from the first source that has it and has not
// expired, or [os.ErrNotExist]. The metadata is shared with every other caller and must not be changed.
func (r *ServiceProviderMetadataResolver) GetServiceProvider(_ *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
	now := r.clock.Now()

	for _, s := range r.sources {
		snapshot := s.snapshot.Load()
		if snapshot == nil || expiredAt(snapshot.validUntil, now) {
			continue
		}

		if metadata, ok := snapshot.entities[serviceProviderID]; ok {
			return metadata, nil
		}
	}

	return nil, os.ErrNotExist
}

// Refresh loads every source now, whether or not it is due, and returns when all have answered. The error names
// each source that failed; the others were loaded, and what a failed source had before is still served until it
// expires. It can be used before Start to wait for the first load and to decide what to do if it fails, and
// without Start by an application that has a schedule of its own.
func (r *ServiceProviderMetadataResolver) Refresh(ctx context.Context) error {
	errs := make([]error, len(r.sources))

	var wg sync.WaitGroup

	for i, s := range r.sources {
		wg.Go(func() {
			errs[i] = r.refresh(ctx, s)
		})
	}

	wg.Wait()

	return errors.Join(errs...)
}

// Start begins to refresh the sources in the background, each when it is due, and a source that was never loaded
// at once. It returns without waiting for them. The refreshing ends when ctx is done or Close is called. It is an
// error to start a resolver twice, or after Close.
func (r *ServiceProviderMetadataResolver) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	switch {
	case r.closed:
		return errors.New("the metadata resolver is closed")
	case r.started:
		return errors.New("the metadata resolver is already started")
	}

	r.started = true

	ctx, r.cancel = context.WithCancel(ctx)

	for _, s := range r.sources {
		r.wg.Go(func() {
			r.run(ctx, s)
		})
	}

	return nil
}

// Close ends the refreshing that Start began, including a request that is being made, and waits until it has
// ended. What was loaded is still served until it expires. Close can be called more than once, and always returns
// nil.
func (r *ServiceProviderMetadataResolver) Close() error {
	r.mu.Lock()

	r.closed = true

	if r.cancel != nil {
		r.cancel()
	}

	r.mu.Unlock()

	r.wg.Wait()

	return nil
}

// Status returns the state of each source, in the order of the sources.
func (r *ServiceProviderMetadataResolver) Status() []MetadataSourceStatus {
	status := make([]MetadataSourceStatus, 0, len(r.sources))

	for _, s := range r.sources {
		s.mu.Lock()

		entry := MetadataSourceStatus{
			Source:      s.name,
			LastAttempt: s.lastAttempt,
			LastSuccess: s.lastSuccess,
			NextRefresh: s.nextRefresh,
			Err:         s.err,
		}

		if snapshot := s.snapshot.Load(); snapshot != nil {
			entry.Entities = len(snapshot.entities)
			entry.ValidUntil = snapshot.validUntil
		}

		s.mu.Unlock()

		status = append(status, entry)
	}

	return status
}

// run refreshes the source when it is due, until ctx is done.
func (r *ServiceProviderMetadataResolver) run(ctx context.Context, s *metadataSource) {
	for ctx.Err() == nil {
		// The wait is worked out again when it is over, as a call to Refresh in the meantime moves the time
		// that the source is due.
		if wait := r.untilRefresh(s); wait > 0 {
			timer := r.clock.NewTimer(wait)

			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.Chan():
			}

			continue
		}

		if err := r.refresh(ctx, s); err != nil && ctx.Err() == nil {
			r.log.Printf("ERROR: %s", err)
		}
	}
}

// untilRefresh returns how long it is until the source is due, which is not positive if it is. A source that was
// never tried is due. A refresh always schedules the next one at least the minimum interval ahead.
func (r *ServiceProviderMetadataResolver) untilRefresh(s *metadataSource) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.lastAttempt.IsZero() {
		return 0
	}

	return s.nextRefresh.Sub(r.clock.Now())
}

// refresh loads the source, replaces what it serves if that succeeds, and schedules the next refresh.
func (r *ServiceProviderMetadataResolver) refresh(ctx context.Context, s *metadataSource) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := r.clock.Now()
	s.lastAttempt = now

	snapshot, validators, err := r.load(ctx, s, now)
	if err != nil {
		s.failures++
		s.err = fmt.Errorf("metadata source %s: %w", s.name, err)
		s.nextRefresh = now.Add(r.retryInterval(s.failures))

		// What was loaded before is served until it expires. Once it has, it is dropped, and so is what would
		// make the next request conditional on it.
		if current := s.snapshot.Load(); current != nil && expiredAt(current.validUntil, now) {
			s.snapshot.Store(nil)
			s.validators = metadataValidators{}
		}

		return s.err
	}

	s.snapshot.Store(snapshot)
	s.validators = validators
	s.failures = 0
	s.err = nil
	s.lastSuccess = now
	s.nextRefresh = now.Add(r.refreshInterval(snapshot, now))

	return nil
}

// load returns the document of the source, which is the one that is served already if the source says that it
// has not changed, and what identifies it.
func (r *ServiceProviderMetadataResolver) load(ctx context.Context, s *metadataSource, now time.Time) (*metadataSnapshot, metadataValidators, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// A request is only conditional on a document that is still there.
	current := s.snapshot.Load()

	previous := s.validators
	if current == nil {
		previous = metadataValidators{}
	}

	var (
		data       []byte
		validators metadataValidators
		err        error
	)

	if s.URL != "" {
		data, validators, err = r.fetchURL(ctx, s.URL, previous)
	} else {
		data, validators, err = r.readFile(s.File, previous)
	}

	if err != nil {
		return nil, validators, err
	}

	if data == nil {
		// Not modified. That doesn't make the document valid for any longer than it says.
		if expiredAt(current.validUntil, now) {
			return nil, validators, errors.New("metadata has expired, and the source has no newer")
		}

		return current, previous, nil
	}

	snapshot, err := s.parse(data, now)

	return snapshot, validators, err
}

// fetchURL returns the document at location and what identifies it, or no document if previous still does.
func (r *ServiceProviderMetadataResolver) fetchURL(ctx context.Context, location string, previous metadataValidators) ([]byte, metadataValidators, error) {
	none := metadataValidators{}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, none, err
	}

	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml;q=0.9, text/xml;q=0.8")

	conditional := previous.etag != "" || previous.lastModified != ""

	if previous.etag != "" {
		req.Header.Set("If-None-Match", previous.etag)
	}

	if previous.lastModified != "" {
		req.Header.Set("If-Modified-Since", previous.lastModified)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, none, err
	}

	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotModified && conditional:
		return nil, previous, nil
	case resp.StatusCode != http.StatusOK:
		return nil, none, fmt.Errorf("unexpected status %s", resp.Status)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, r.maxSize+1))
	if err != nil {
		return nil, none, err
	}

	if int64(len(data)) > r.maxSize {
		return nil, none, fmt.Errorf("metadata is larger than %d bytes", r.maxSize)
	}

	return data, metadataValidators{etag: resp.Header.Get("ETag"), lastModified: resp.Header.Get("Last-Modified")}, nil
}

// readFile returns the content of the file and what identifies it, or no content if previous still does.
func (r *ServiceProviderMetadataResolver) readFile(path string, previous metadataValidators) ([]byte, metadataValidators, error) {
	none := metadataValidators{}

	file, err := os.Open(path)
	if err != nil {
		return nil, none, err
	}

	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, none, err
	}

	if info.Size() > r.maxSize {
		return nil, none, fmt.Errorf("metadata is larger than %d bytes", r.maxSize)
	}

	validators := metadataValidators{modTime: info.ModTime(), size: info.Size()}
	if !previous.modTime.IsZero() && validators == previous {
		return nil, previous, nil
	}

	// The limit is applied again, as the file may have grown.
	data, err := io.ReadAll(io.LimitReader(file, r.maxSize+1))
	if err != nil {
		return nil, none, err
	}

	if int64(len(data)) > r.maxSize {
		return nil, none, fmt.Errorf("metadata is larger than %d bytes", r.maxSize)
	}

	return data, validators, nil
}

// parse verifies the signature of the document if the source has a verifier, checks the validity of what the
// signature covers, and returns the service providers in it.
func (s *metadataSource) parse(data []byte, now time.Time) (*metadataSnapshot, error) {
	if s.Verifier != nil {
		// From here on data is the element that the signature covers, and nothing else of what was received
		// is used.
		var err error
		if data, err = s.Verifier.Verify(data); err != nil {
			return nil, err
		}
	}

	snapshot := &metadataSnapshot{}

	var err error
	if snapshot.validUntil, snapshot.cacheDuration, err = metadataRootValidity(data); err != nil {
		return nil, err
	}

	if err = s.checkValidUntil(snapshot.validUntil, now); err != nil {
		return nil, err
	}

	entities, err := ParseServiceProvidersMetadata(data)
	if err != nil {
		return nil, err
	}

	snapshot.entities = make(map[string]*EntityDescriptor, len(entities))

	for _, entity := range entities {
		if _, ok := snapshot.entities[entity.EntityID]; ok {
			continue
		}

		if s.Filter != nil && !s.Filter(entity) {
			continue
		}

		snapshot.entities[entity.EntityID] = entity
	}

	return snapshot, nil
}

// checkValidUntil returns an error if the validUntil of the root element is missing, unless the source allows
// that, or is not after now, or is further than MaxValidity after it (SAML2Int SDP-MD03).
func (s *metadataSource) checkValidUntil(validUntil, now time.Time) error {
	switch {
	case validUntil.IsZero():
		if s.AllowMissingValidUntil {
			return nil
		}

		return errors.New("metadata has no validUntil")
	case expiredAt(validUntil, now):
		return errors.New("metadata has expired")
	case validUntil.After(now.Add(s.MaxValidity)):
		return fmt.Errorf("metadata is valid for longer than %s", s.MaxValidity)
	}

	return nil
}

// metadataRootValidity returns the validUntil and the cacheDuration of the root element of data, each zero if the
// element doesn't have it. Only an attribute in no namespace counts. A cacheDuration that can't be parsed, or
// isn't positive, counts as none, as it only decides when to ask again.
func metadataRootValidity(data []byte) (validUntil time.Time, cacheDuration time.Duration, err error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))

	for {
		token, err := decoder.Token()
		if err != nil {
			return time.Time{}, 0, err
		}

		root, ok := token.(xml.StartElement)
		if !ok {
			continue
		}

		for _, attr := range root.Attr {
			if attr.Name.Space != "" {
				continue
			}

			switch attr.Name.Local {
			case "validUntil":
				var value RelaxedTime
				if err = value.UnmarshalText([]byte(attr.Value)); err != nil || time.Time(value).IsZero() {
					return time.Time{}, 0, fmt.Errorf("metadata has an invalid validUntil %q", attr.Value)
				}

				validUntil = time.Time(value)
			case "cacheDuration":
				var value Duration
				if value.UnmarshalText([]byte(attr.Value)) == nil && value > 0 {
					cacheDuration = time.Duration(value)
				}
			}
		}

		return validUntil, cacheDuration, nil
	}
}

// refreshInterval returns the time until the next refresh of a document that was loaded, or found not to have
// changed, at now: its cacheDuration (SAMLMeta §4.3.1), and no more than three quarters of the time until its
// validUntil, so that a refresh that fails can be tried again before the document expires, less the jitter, and
// within the minimum and the maximum interval.
func (r *ServiceProviderMetadataResolver) refreshInterval(snapshot *metadataSnapshot, now time.Time) time.Duration {
	interval := r.maxInterval

	if snapshot.cacheDuration > 0 && snapshot.cacheDuration < interval {
		interval = snapshot.cacheDuration
	}

	if !snapshot.validUntil.IsZero() {
		interval = min(interval, snapshot.validUntil.Sub(now)/4*3)
	}

	if r.jitter > 0 {
		// 53 random bits make a number that is evenly spread over [0, 1).
		random := float64(binary.BigEndian.Uint64(randomBytes(8))>>11) / (1 << 53)
		interval -= time.Duration(float64(interval) * r.jitter * random)
	}

	return max(interval, r.minInterval)
}

// retryInterval returns the time until the next attempt after a number of failures in a row: the minimum
// interval, doubled for each failure after the first, up to the maximum interval.
func (r *ServiceProviderMetadataResolver) retryInterval(failures int) time.Duration {
	interval := r.minInterval

	for range failures - 1 {
		if interval >= r.maxInterval {
			break
		}

		interval *= 2
	}

	return min(interval, r.maxInterval)
}
