package samlsp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
)

func TestJWTTrackedRequestCodecRoundTrip(t *testing.T) {
	codec := newTestTrackedRequestCodec(t)
	want := TrackedRequest{Index: "idx", SAMLRequestID: "id-1", URI: "/frob"}

	token, err := codec.Encode(want)
	require.NoError(t, err)

	got, err := codec.Decode(token)
	require.NoError(t, err)
	assert.Equal(t, want, *got)
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
				codec.SigningMethod = jose.RS512
				token, err := codec.Encode(TrackedRequest{Index: "idx", SAMLRequestID: "id-1", URI: "/"})
				require.NoError(t, err)

				return token
			},
			err: `unexpected signature algorithm "RS512"; expected ["RS256"]`,
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
			assert.EqualError(t, err, tc.err)
		})
	}
}

func newTestTrackedRequestCodec(t *testing.T) JWTTrackedRequestCodec {
	test := NewMiddlewareTest(t)

	return DefaultTrackedRequestCodec(Options{
		URL: mustParseURL("https://15661444.ngrok.io/"),
		Key: test.JWTKey,
	})
}
