package samlsp

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestFetchMetadataLimitsSize(t *testing.T) {
	previous := maxMetadataSize
	maxMetadataSize = 1024
	t.Cleanup(func() { maxMetadataSize = previous })

	for _, tc := range []struct {
		name    string
		size    int
		tooMuch bool
	}{
		{"at the limit", 1024, false},
		{"over the limit", 1025, true},
		{"far over the limit", 1 << 20, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(bytes.Repeat([]byte(" "), tc.size))
			}))
			defer server.Close()
			u, err := url.Parse(server.URL)
			assert.NilError(t, err)

			_, err = FetchMetadata(context.Background(), server.Client(), *u)
			assert.Assert(t, err != nil)
			if tc.tooMuch {
				assert.Check(t, is.ErrorContains(err, "too large"))
			} else {
				assert.Check(t, !strings.Contains(err.Error(), "too large"), err.Error())
			}
		})
	}
}

func TestFetchMetadataWithoutClientHasTimeout(t *testing.T) {
	previous := defaultFetchMetadataTimeout
	defaultFetchMetadataTimeout = 50 * time.Millisecond
	t.Cleanup(func() { defaultFetchMetadataTimeout = previous })

	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })
	u, err := url.Parse(server.URL)
	assert.NilError(t, err)

	start := time.Now()
	_, err = FetchMetadata(context.Background(), nil, *u)
	assert.Assert(t, err != nil)
	assert.Check(t, time.Since(start) < 5*time.Second)
}
