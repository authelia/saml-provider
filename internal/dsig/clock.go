package dsig

import (
	"time"
)

// Clock gives the time at which signatures are validated. A nil *Clock is the system clock, so that a Clock can be
// added to a struct without every instantiation of it having to set one.
type Clock struct {
	at time.Time
}

// Now returns the time of the clock, which is the time of the system for a nil *Clock.
func (c *Clock) Now() time.Time {
	if c == nil {
		return time.Now()
	}

	return c.at
}

// NewFakeClockAt returns a clock which is always at t.
func NewFakeClockAt(t time.Time) *Clock {
	return &Clock{at: t}
}
