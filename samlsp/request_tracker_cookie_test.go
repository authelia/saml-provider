package samlsp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCookieRequestTrackerGetTrackedRequestRejectsIndexMismatch(t *testing.T) {
	tracker, req := newIndexMismatchRequest(t)

	_, err := tracker.GetTrackedRequest(req, "mine")
	assert.EqualError(t, err, `expected index "mine", got "theirs"`)
}

func TestCookieRequestTrackerGetTrackedRequestsSkipsIndexMismatch(t *testing.T) {
	tracker, req := newIndexMismatchRequest(t)

	assert.Len(t, tracker.GetTrackedRequests(req), 0)
}

func newIndexMismatchRequest(t *testing.T) (CookieRequestTracker, *http.Request) {
	test := NewMiddlewareTest(t)
	tracker := test.Middleware.RequestTracker.(CookieRequestTracker)

	token, err := tracker.Codec.Encode(TrackedRequest{Index: "theirs", SAMLRequestID: "id-1", URI: "/"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "https://15661444.ngrok.io/saml2/acs", nil)
	req.Header.Set("Cookie", tracker.NamePrefix+"mine="+token)

	return tracker, req
}
