package samlsp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestCookieRequestTrackerGetTrackedRequestRejectsIndexMismatch(t *testing.T) {
	tracker, req := newIndexMismatchRequest(t)

	_, err := tracker.GetTrackedRequest(req, "mine")
	assert.Check(t, is.Error(err, `expected index "mine", got "theirs"`))
}

func TestCookieRequestTrackerGetTrackedRequestsSkipsIndexMismatch(t *testing.T) {
	tracker, req := newIndexMismatchRequest(t)

	assert.Check(t, is.Len(tracker.GetTrackedRequests(req), 0))
}

func newIndexMismatchRequest(t *testing.T) (CookieRequestTracker, *http.Request) {
	test := NewMiddlewareTest(t)
	tracker := test.Middleware.RequestTracker.(CookieRequestTracker)

	token, err := tracker.Codec.Encode(TrackedRequest{Index: "theirs", SAMLRequestID: "id-1", URI: "/"})
	assert.NilError(t, err)

	req := httptest.NewRequest(http.MethodPost, "https://15661444.ngrok.io/saml2/acs", nil)
	req.Header.Set("Cookie", tracker.NamePrefix+"mine="+token)

	return tracker, req
}
