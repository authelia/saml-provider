package samlsp

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestJWTTrackedRequestCodecRoundTrip(t *testing.T) {
	codec := newTestTrackedRequestCodec(t)
	want := TrackedRequest{Index: "idx", SAMLRequestID: "id-1", URI: "/frob"}

	token, err := codec.Encode(want)
	assert.NilError(t, err)

	got, err := codec.Decode(token)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(want, *got))
}

func TestJWTTrackedRequestCodecDecodeRejects(t *testing.T) {
	testCases := []struct {
		name   string
		encode func(t *testing.T, codec JWTTrackedRequestCodec) string
		err    string
	}{
		{
			name: "RS512",
			encode: func(t *testing.T, codec JWTTrackedRequestCodec) string {
				codec.SigningMethod = jwt.SigningMethodRS512
				token, err := codec.Encode(TrackedRequest{Index: "idx", SAMLRequestID: "id-1", URI: "/"})
				assert.NilError(t, err)
				return token
			},
			err: "token signature is invalid: signing method RS512 is invalid",
		},
		{
			name: "session",
			encode: func(t *testing.T, codec JWTTrackedRequestCodec) string {
				return encodeTestSession(t, JWTSessionCodec(codec))
			},
			err: "expected saml-authn-request",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			codec := newTestTrackedRequestCodec(t)

			_, err := codec.Decode(tc.encode(t, codec))
			assert.Check(t, is.Error(err, tc.err))
		})
	}
}

func newTestTrackedRequestCodec(t *testing.T) JWTTrackedRequestCodec {
	test := NewMiddlewareTest(t)
	return DefaultTrackedRequestCodec(Options{
		URL: mustParseURL("https://15661444.ngrok.io/"),
		Key: test.Key,
	})
}
