package samlsp

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml"
)

func TestJWTSessionCodecRoundTrip(t *testing.T) {
	codec := newTestSessionCodec(t)

	session, err := codec.Decode(encodeTestSession(t, codec))
	assert.NilError(t, err)
	assert.Check(t, is.Equal("alice", session.(JWTSessionClaims).Subject))
}

func TestJWTSessionCodecDecodeRejects(t *testing.T) {
	testCases := []struct {
		name   string
		encode func(t *testing.T, codec JWTSessionCodec) string
		err    string
	}{
		{
			name: "RS512",
			encode: func(t *testing.T, codec JWTSessionCodec) string {
				codec.SigningMethod = jwt.SigningMethodRS512
				return encodeTestSession(t, codec)
			},
			err: "token signature is invalid: signing method RS512 is invalid",
		},
		{
			name: "PS256",
			encode: func(t *testing.T, codec JWTSessionCodec) string {
				codec.SigningMethod = jwt.SigningMethodPS256
				return encodeTestSession(t, codec)
			},
			err: "token signature is invalid: signing method PS256 is invalid",
		},
		{
			name: "wrong audience",
			encode: func(t *testing.T, codec JWTSessionCodec) string {
				codec.Audience = "https://other.example.com/"
				return encodeTestSession(t, codec)
			},
			err: "token has invalid claims: token has invalid audience",
		},
		{
			name: "wrong issuer",
			encode: func(t *testing.T, codec JWTSessionCodec) string {
				codec.Issuer = "https://other.example.com/"
				return encodeTestSession(t, codec)
			},
			err: "token has invalid claims: token has invalid issuer",
		},
		{
			name: "tracked request",
			encode: func(t *testing.T, codec JWTSessionCodec) string {
				token, err := JWTTrackedRequestCodec(codec).Encode(TrackedRequest{Index: "alice", SAMLRequestID: "id-1", URI: "/"})
				assert.NilError(t, err)
				return token
			},
			err: "expected saml-session",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			codec := newTestSessionCodec(t)

			_, err := codec.Decode(tc.encode(t, codec))
			assert.Check(t, is.Error(err, tc.err))
		})
	}
}

func newTestSessionCodec(t *testing.T) JWTSessionCodec {
	test := NewMiddlewareTest(t)
	return DefaultSessionCodec(Options{
		URL: mustParseURL("https://15661444.ngrok.io/"),
		Key: test.Key,
	})
}

func encodeTestSession(t *testing.T, codec JWTSessionCodec) string {
	session, err := codec.New(&saml.Assertion{Subject: &saml.Subject{NameID: &saml.NameID{Value: "alice"}}})
	assert.NilError(t, err)
	token, err := codec.Encode(session)
	assert.NilError(t, err)
	return token
}
