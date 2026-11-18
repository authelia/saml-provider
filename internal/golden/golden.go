// Package golden provides helpers for tests which compare against or load files in the testdata directory of the
// package under test.
package golden

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("test.update-golden", false, "update golden files")

// Path returns the path to the named file in the testdata directory.
func Path(filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	}

	return filepath.Join("testdata", filename)
}

// Get returns the contents of the named file in the testdata directory, failing the test if it can't be read.
func Get(t testing.TB, filename string) []byte {
	t.Helper()

	data, err := os.ReadFile(Path(filename))
	require.NoError(t, err)

	return data
}

// Assert checks that actual matches the contents of the named file in the testdata directory, ignoring the
// difference between CRLF and LF line endings. When the test is run with -test.update-golden the file is
// overwritten with actual instead.
func Assert(t testing.TB, actual string, filename string, msgAndArgs ...any) bool {
	t.Helper()

	if *update {
		require.NoError(t, os.WriteFile(Path(filename), []byte(actual), 0o600))
	}

	expected := Get(t, filename)

	return assert.Equal(t, string(crlf(expected)), string(crlf([]byte(actual))), msgAndArgs...)
}

func crlf(in []byte) []byte {
	return bytes.ReplaceAll(in, []byte("\r\n"), []byte("\n"))
}
