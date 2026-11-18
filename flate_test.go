package saml

import (
	"bytes"
	"compress/flate"
	"io"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func deflate(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer

	w, err := flate.NewWriter(&buf, flate.BestCompression)
	assert.NilError(t, err)

	_, err = w.Write(data)
	assert.NilError(t, err)
	assert.NilError(t, w.Close())

	return buf.Bytes()
}

// The limit is of the bytes that are inflated, not of the buffer they are read into, which io.ReadAll grows past the
// limit well before the data reaches it.
func TestSaferFlateReaderReadsMessageAtLimit(t *testing.T) {
	data := bytes.Repeat([]byte("a"), flateUncompressLimit)

	inflated, err := io.ReadAll(newSaferFlateReader(bytes.NewReader(deflate(t, data))))
	assert.NilError(t, err)
	assert.Check(t, is.Len(inflated, flateUncompressLimit))
}

func TestSaferFlateReaderRejectsMessageOverLimit(t *testing.T) {
	data := bytes.Repeat([]byte("a"), flateUncompressLimit+1)

	_, err := io.ReadAll(newSaferFlateReader(bytes.NewReader(deflate(t, data))))
	assert.Error(t, err, "flate: uncompress limit exceeded (1048576 bytes)")
}

// A reader of a single byte at a time is not refused until it is given the byte past the limit.
func TestSaferFlateReaderSmallReads(t *testing.T) {
	data := bytes.Repeat([]byte("a"), flateUncompressLimit+1)
	r := newSaferFlateReader(bytes.NewReader(deflate(t, data)))

	inflated, err := io.ReadAll(io.LimitReader(r, flateUncompressLimit))
	assert.NilError(t, err)
	assert.Check(t, is.Len(inflated, flateUncompressLimit))

	_, err = r.Read(make([]byte, 1))
	assert.Error(t, err, "flate: uncompress limit exceeded (1048576 bytes)")
}
