package samlsp

import (
	"fmt"
	"log"
	"net/http"
	"strconv"

	"authelia.com/provider/saml"
)

// ErrorFunction is a callback that is invoked to return an error to the
// web user.
type ErrorFunction func(w http.ResponseWriter, r *http.Request, err error)

// maxLoggedValueSize limits how much of a value from a client is logged. A response can otherwise be
// logged at up to the size of the largest request the server accepts.
const maxLoggedValueSize = 4096

// DefaultOnError is the default ErrorFunction implementation. It prints
// an message via the standard log package and returns a simple text
// "Forbidden" message to the user.
//
// Values are quoted, because they can contain text from the client which would otherwise be able to
// forge log lines.
func DefaultOnError(w http.ResponseWriter, _ *http.Request, err error) {
	if parseErr, ok := err.(*saml.InvalidResponseError); ok {
		log.Printf("WARNING: received invalid saml response: %s (now: %s) %s",
			logValue(parseErr.Response), parseErr.Now, logValue(fmt.Sprint(parseErr.PrivateErr)))
	} else {
		log.Printf("ERROR: %s", logValue(fmt.Sprint(err)))
	}
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}

// logValue returns value quoted and limited in size, for logging.
func logValue(value string) string {
	if len(value) > maxLoggedValueSize {
		return fmt.Sprintf("%q (truncated from %d bytes)", value[:maxLoggedValueSize], len(value))
	}
	return strconv.Quote(value)
}
