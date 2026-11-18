package samlsp

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"authelia.com/provider/saml"
)

// ErrorFunction is a callback that is invoked to return an error to the
// web user.
type ErrorFunction func(w http.ResponseWriter, r *http.Request, err error)

// maxLoggedValueSize limits how much of a value from a client is logged. A response can otherwise be
// logged at up to the size of the largest request the server accepts.
const maxLoggedValueSize = 4096

// DefaultOnError is the default ErrorFunction implementation. It logs the error with [slog.Default], with the
// context of the request, and returns a simple text "Forbidden" message to the user. An application that wants
// the errors elsewhere sets its own ErrorFunction.
//
// The values are attributes of the record and not part of its message, because they can contain text from the
// client or from the identity provider, which a [slog.Handler] escapes, so that it can't forge log lines. When
// the identity provider answered with a status that is not a success, the status is logged as the group that
// saml.StatusError.LogValue returns, with each of its text values limited in size as the others are.
func DefaultOnError(w http.ResponseWriter, r *http.Request, err error) {
	var (
		parseErr  *saml.InvalidResponseError
		statusErr *saml.StatusError
		attrs     []slog.Attr
	)

	if errors.As(err, &parseErr) {
		attrs = append(attrs,
			slog.String("response", logValue(parseErr.Response)),
			slog.Time("now", parseErr.Now),
			slog.String("error", logValue(fmt.Sprint(parseErr.PrivateErr))))
	} else {
		attrs = append(attrs, slog.String("error", logValue(fmt.Sprint(err))))
	}

	if errors.As(err, &statusErr) {
		attrs = append(attrs, slog.Any("status", logStatus(statusErr)))
	}

	slog.Default().LogAttrs(r.Context(), slog.LevelWarn, "saml: received invalid response", attrs...)

	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}

// logStatus returns the group that the LogValue of statusErr returns with each string in it limited in size, as
// the debug message and the cause can hold text from the identity provider of any size.
func logStatus(statusErr *saml.StatusError) slog.Value {
	attrs := statusErr.LogValue().Group()
	limited := make([]slog.Attr, len(attrs))

	for i, attr := range attrs {
		if attr.Value.Kind() == slog.KindString {
			attr.Value = slog.StringValue(logValue(attr.Value.String()))
		}

		limited[i] = attr
	}

	return slog.GroupValue(limited...)
}

// logValue returns value limited in size, for logging.
func logValue(value string) string {
	if len(value) > maxLoggedValueSize {
		return fmt.Sprintf("%s (truncated from %d bytes)", value[:maxLoggedValueSize], len(value))
	}

	return value
}
