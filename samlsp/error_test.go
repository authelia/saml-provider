package samlsp

import (
	"bytes"
	"errors"
	"log"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml"
)

func captureDefaultOnError(t *testing.T, err error) string {
	t.Helper()
	var output bytes.Buffer
	previousWriter, previousFlags := log.Writer(), log.Flags()
	log.SetOutput(&output)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	})

	recorder := httptest.NewRecorder()
	DefaultOnError(recorder, httptest.NewRequest("POST", "/saml/acs", nil), err)
	assert.Check(t, is.Equal(403, recorder.Code))
	return output.String()
}

func TestDefaultOnErrorDoesNotAllowForgedLogLines(t *testing.T) {
	const forged = "x\nERROR: forged log line\r\n"

	for name, err := range map[string]error{
		"response": &saml.InvalidResponseError{Response: forged, Now: time.Unix(0, 0), PrivateErr: errors.New("reason")},
		"private":  &saml.InvalidResponseError{Response: "response", Now: time.Unix(0, 0), PrivateErr: errors.New(forged)},
		"other":    errors.New(forged),
	} {
		t.Run(name, func(t *testing.T) {
			output := captureDefaultOnError(t, err)
			assert.Check(t, is.Equal(1, strings.Count(output, "\n")), output)
			assert.Check(t, !strings.Contains(output, "\r"), output)
			assert.Check(t, strings.Contains(output, `x\nERROR: forged log line`), output)
		})
	}
}

func TestDefaultOnErrorLimitsLoggedResponse(t *testing.T) {
	output := captureDefaultOnError(t, &saml.InvalidResponseError{
		Response:   strings.Repeat("a", 10*1024*1024),
		Now:        time.Unix(0, 0),
		PrivateErr: errors.New("the reason"),
	})
	assert.Check(t, len(output) < 8192, "logged %d bytes", len(output))
	assert.Check(t, strings.Contains(output, "truncated"))
	assert.Check(t, strings.Contains(output, "the reason"))
}

func TestDefaultOnErrorKeepsShortResponse(t *testing.T) {
	output := captureDefaultOnError(t, &saml.InvalidResponseError{
		Response:   "<samlp:Response/>",
		Now:        time.Unix(0, 0),
		PrivateErr: errors.New("the reason"),
	})
	assert.Check(t, strings.Contains(output, "<samlp:Response/>"), output)
	assert.Check(t, !strings.Contains(output, "truncated"), output)
}
