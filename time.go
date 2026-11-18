package saml

import (
	"fmt"
	"time"
)

// RelaxedTime is a version of [time.Time] that supports the time format
// found in SAML documents.
type RelaxedTime time.Time

const timeFormat = "2006-01-02T15:04:05.999Z07:00"

// MarshalText implements [encoding.TextMarshaler].
func (m RelaxedTime) MarshalText() ([]byte, error) {
	// According to section 1.2.2 of the OASIS SAML 1.1 spec, we can't trust
	// other applications to handle time resolution finer than a millisecond.
	//
	// The time MUST be expressed in UTC.
	return []byte(m.String()), nil
}

// String implements [fmt.Stringer].
func (m RelaxedTime) String() string {
	return time.Time(m).Round(time.Millisecond).UTC().Format(timeFormat)
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (m *RelaxedTime) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*m = RelaxedTime(time.Time{})
		return nil
	}

	t, err1 := time.Parse(time.RFC3339, string(text))
	if err1 == nil {
		t = t.Round(time.Millisecond)
		*m = RelaxedTime(t)

		return nil
	}

	t, err2 := time.Parse(time.RFC3339Nano, string(text))
	if err2 == nil {
		t = t.Round(time.Millisecond)
		*m = RelaxedTime(t)

		return nil
	}

	t, err2 = time.Parse("2006-01-02T15:04:05.999999999", string(text))
	if err2 == nil {
		t = t.Round(time.Millisecond)
		*m = RelaxedTime(t)

		return nil
	}

	return err1
}

// The validity of a message is the half-open interval from its NotBefore to its NotOnOrAfter (SAMLCore §2.5.1.2),
// and SAML2Int SDP-G01 requires clock skew to be allowed for at each end of it, so every check of a time that
// another party stated is one of the functions below: with now on the clock of this party, the time is valid from
// MaxClockSkew before its NotBefore, inclusive, to MaxClockSkew after its NotOnOrAfter, exclusive.

// beforeValidity reports whether now is before a NotBefore, allowing for MaxClockSkew: it is so until
// MaxClockSkew before notBefore, and not at that instant.
func beforeValidity(notBefore, now time.Time) bool {
	return now.Before(notBefore.Add(-MaxClockSkew))
}

// pastValidity reports whether now is at or after a NotOnOrAfter, allowing for MaxClockSkew: it is so from
// MaxClockSkew after notOnOrAfter, and at that instant. The zero time is in the past, so a caller for which a
// time that is absent means no limit checks for that first.
func pastValidity(notOnOrAfter, now time.Time) bool {
	return !now.Before(notOnOrAfter.Add(MaxClockSkew))
}

// expiredAt reports whether a validUntil has passed, allowing for MaxClockSkew (SAMLMeta §2.3.2, SAML2Int
// SDP-G01), as pastValidity does for a NotOnOrAfter. The zero time counts as no validUntil.
func expiredAt(validUntil, now time.Time) bool {
	return !validUntil.IsZero() && pastValidity(validUntil, now)
}

// validBeyond reports whether a validUntil is further than maxValidity after now, allowing for MaxClockSkew, as
// the clock of the publisher that worked the validUntil out may be ahead (SAML2Int SDP-MD03 and SDP-G01).
func validBeyond(validUntil, now time.Time, maxValidity time.Duration) bool {
	return validUntil.After(now.Add(maxValidity).Add(MaxClockSkew))
}

// checkIssueInstant returns an error if a message, which what names in the error, is older than maxAge or was
// issued in the future. An IssueInstant with a maximum age is a validity period that begins at the IssueInstant
// and ends maxAge after it, and is checked as one: the message is accepted from MaxClockSkew before its
// IssueInstant, inclusive, to maxAge and MaxClockSkew after it, exclusive. Every check of the age of a message in
// this package is this one.
func checkIssueInstant(what string, issueInstant, now time.Time, maxAge time.Duration) error {
	if expires := issueInstant.Add(maxAge); pastValidity(expires, now) {
		return fmt.Errorf("%s expired at %s", what, expires)
	}

	if beforeValidity(issueInstant, now) {
		return fmt.Errorf("%s issued in the future at %s", what, issueInstant)
	}

	return nil
}
