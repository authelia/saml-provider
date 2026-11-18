package saml

import (
	"compress/flate"
	"fmt"
	"io"
)

// flateUncompressLimit is the most that a message of the HTTP-Redirect binding is inflated to. The message is in a
// URL, and inflates to a few kilobytes in practice. Every byte that is inflated is then checked and parsed before any
// signature is verified, and DEFLATE compresses repetitive XML about a thousand times, so the limit bounds the work
// that a request of a few kilobytes can cause.
const flateUncompressLimit = 1024 * 1024

func newSaferFlateReader(r io.Reader) io.ReadCloser {
	return &saferFlateReader{r: flate.NewReader(r)}
}

type saferFlateReader struct {
	r     io.ReadCloser
	count int
}

// Read reads at most one byte past the limit, and fails if it is given it, so that a message of exactly
// flateUncompressLimit bytes is read in full whatever the size of p.
func (r *saferFlateReader) Read(p []byte) (n int, err error) {
	if remaining := flateUncompressLimit - r.count; len(p) > remaining+1 {
		p = p[:remaining+1]
	}

	n, err = r.r.Read(p)
	r.count += n

	if r.count > flateUncompressLimit {
		return 0, fmt.Errorf("flate: uncompress limit exceeded (%d bytes)", flateUncompressLimit)
	}

	return n, err
}

func (r *saferFlateReader) Close() error {
	return r.r.Close()
}
