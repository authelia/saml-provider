package saml

import (
	"crypto/rand"
	"io"
	"time"

	"authelia.com/provider/saml/internal/dsig"
)

// TimeNow is a function that returns the current time. The default
// value is [time.Now], but it can be replaced for testing.
var TimeNow = func() time.Time { return time.Now().UTC() }

// Clock is assigned to dsig validation and signing contexts if it is
// not nil, otherwise the default clock is used.
var Clock *dsig.Clock

// DSigClock is the clock type assigned to Clock.
type DSigClock = dsig.Clock

// NewFakeClockAt returns a clock fixed at t. It is intended for tests, which assign it to Clock.
func NewFakeClockAt(t time.Time) *DSigClock {
	return dsig.NewFakeClockAt(t)
}

// RandReader is the [io.Reader] that produces cryptographically random
// bytes when they are need by the library. The default value is
// rand.Reader, but it can be replaced for testing.
var RandReader = rand.Reader

func randomBytes(n int) []byte {
	rv := make([]byte, n)

	if _, err := io.ReadFull(RandReader, rv); err != nil {
		panic(err)
	}

	return rv
}
