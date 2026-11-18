package saml

import (
	"bytes"
	"compress/flate"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func deflate(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer

	w, err := flate.NewWriter(&buf, flate.BestCompression)
	require.NoError(t, err)

	_, err = w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	return buf.Bytes()
}

// The limit is of the bytes that are inflated, not of the buffer they are read into, which io.ReadAll grows past the
// limit well before the data reaches it.
func TestSaferFlateReaderReadsMessageAtLimit(t *testing.T) {
	data := bytes.Repeat([]byte("a"), flateUncompressLimit)

	inflated, err := io.ReadAll(newSaferFlateReader(bytes.NewReader(deflate(t, data))))
	require.NoError(t, err)
	assert.Len(t, inflated, flateUncompressLimit)
}

func TestSaferFlateReaderRejectsMessageOverLimit(t *testing.T) {
	data := bytes.Repeat([]byte("a"), flateUncompressLimit+1)

	_, err := io.ReadAll(newSaferFlateReader(bytes.NewReader(deflate(t, data))))
	require.EqualError(t, err, "flate: uncompress limit exceeded (1048576 bytes)")
}

// A reader of a single byte at a time is not refused until it is given the byte past the limit.
func TestSaferFlateReaderSmallReads(t *testing.T) {
	data := bytes.Repeat([]byte("a"), flateUncompressLimit+1)
	r := newSaferFlateReader(bytes.NewReader(deflate(t, data)))

	inflated, err := io.ReadAll(io.LimitReader(r, flateUncompressLimit))
	require.NoError(t, err)
	assert.Len(t, inflated, flateUncompressLimit)

	_, err = r.Read(make([]byte, 1))
	require.EqualError(t, err, "flate: uncompress limit exceeded (1048576 bytes)")
}
