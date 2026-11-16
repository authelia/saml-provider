package samlidp

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"authelia.com/provider/saml"
)

func randomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := saml.RandReader.Read(rv); err != nil {
		panic(err)
	}
	return rv
}

// decodeJSONBody reads the whole of r, so that a body over maxAdminBodySize is refused even when its
// first JSON value is within the limit, and decodes it into v.
func decodeJSONBody(r io.Reader, v any) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// writeBodyError responds to a request whose body can't be read or parsed, with 413 Request Entity
// Too Large if it is over maxAdminBodySize, or else 400 Bad Request.
func writeBodyError(w http.ResponseWriter, err error) {
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
}
