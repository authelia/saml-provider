package samlsp

import (
	"crypto"
	"fmt"
	"time"

	"authelia.com/provider/jose"
	"authelia.com/provider/jose/jwt"

	"authelia.com/provider/saml"
)

// JWTTrackedRequestCodec encodes TrackedRequests as signed JWTs
type JWTTrackedRequestCodec struct {
	SigningMethod jose.SignatureAlgorithm
	Audience      string
	Issuer        string
	MaxAge        time.Duration
	Key           crypto.Signer
}

var _ TrackedRequestCodec = JWTTrackedRequestCodec{}

// JWTTrackedRequestClaims represents the JWT claims for a tracked request.
type JWTTrackedRequestClaims struct {
	jwt.Claims
	TrackedRequest
	SAMLAuthnRequest bool `json:"saml-authn-request"`
}

// Encode returns an encoded string representing the TrackedRequest.
func (s JWTTrackedRequestCodec) Encode(value TrackedRequest) (string, error) {
	now := saml.TimeNow()
	claims := JWTTrackedRequestClaims{
		Claims: jwt.Claims{
			Audience:  jwt.Audience{s.Audience},
			Expiry:    jwt.NewNumericDate(now.Add(s.MaxAge)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    s.Issuer,
			NotBefore: jwt.NewNumericDate(now), // TODO(ross): correct for clock skew
			Subject:   value.Index,
		},
		TrackedRequest:   value,
		SAMLAuthnRequest: true,
	}
	return signJWT(s.SigningMethod, s.Key, claims)
}

// Decode returns a Tracked request from an encoded string.
func (s JWTTrackedRequestCodec) Decode(signed string) (*TrackedRequest, error) {
	claims := JWTTrackedRequestClaims{}
	err := verifyJWT(signed, s.SigningMethod, s.Key, s.Audience, s.Issuer, &claims, &claims.Claims)
	if err != nil {
		return nil, err
	}
	if !claims.SAMLAuthnRequest {
		return nil, fmt.Errorf("expected saml-authn-request")
	}
	claims.Index = claims.Subject
	return &claims.TrackedRequest, nil
}
