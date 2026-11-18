package saml

import (
	"context"
	"sync"
	"time"
)

var _ MetadataClock = (*fakeClock)(nil)

// fakeClock is a MetadataClock whose time only moves when it is advanced, which fires the timers that are due.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	timers  []*fakeTimer
	changed chan struct{}
}

func newFakeClockAt(t time.Time) *fakeClock {
	return &fakeClock{now: t, changed: make(chan struct{})}
}

// Now returns the time of the clock.
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

// NewTimer returns a timer which fires once the clock has been advanced by d.
func (c *fakeClock) NewTimer(d time.Duration) MetadataTimer {
	c.mu.Lock()
	defer c.mu.Unlock()

	t := &fakeTimer{clock: c, at: c.now.Add(d), ch: make(chan time.Time, 1)}

	if d <= 0 {
		t.ch <- c.now

		return t
	}

	c.timers = append(c.timers, t)
	c.notify()

	return t
}

// Advance moves the time on by d, and fires each timer that is then due.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)

	pending := c.timers[:0]

	for _, t := range c.timers {
		if t.at.After(c.now) {
			pending = append(pending, t)

			continue
		}

		t.ch <- c.now
	}

	clear(c.timers[len(pending):])
	c.timers = pending
	c.notify()
}

// BlockUntilContext waits until exactly n timers wait for the clock, or ctx is done.
func (c *fakeClock) BlockUntilContext(ctx context.Context, n int) error {
	for {
		c.mu.Lock()
		count, changed := len(c.timers), c.changed
		c.mu.Unlock()

		if count == n {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

// notify wakes those that wait for the timers to change. c.mu must be held.
func (c *fakeClock) notify() {
	close(c.changed)
	c.changed = make(chan struct{})
}

// fakeTimer is a timer of a fakeClock.
type fakeTimer struct {
	clock *fakeClock
	at    time.Time
	ch    chan time.Time
}

// Chan returns the channel the time is sent on when the timer fires.
func (t *fakeTimer) Chan() <-chan time.Time {
	return t.ch
}

// Stop removes the timer from the clock, and returns false if it had already fired or been stopped.
func (t *fakeTimer) Stop() bool {
	c := t.clock

	c.mu.Lock()
	defer c.mu.Unlock()

	for i, other := range c.timers {
		if other == t {
			c.timers = append(c.timers[:i], c.timers[i+1:]...)
			c.notify()

			return true
		}
	}

	return false
}
