package saml

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	spCertTestKeysOnce sync.Once
	spCertTestRSA2048  *rsa.PrivateKey
	spCertTestRSA1024  *rsa.PrivateKey
)

// spCertTestKeys returns RSA keys of 2048 and 1024 bits, which are generated once because it is slow.
func spCertTestKeys(t *testing.T) (rsa2048, rsa1024 *rsa.PrivateKey) {
	t.Helper()
	spCertTestKeysOnce.Do(func() {
		var err error
		if spCertTestRSA2048, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}

		if spCertTestRSA1024, err = rsa.GenerateKey(rand.Reader, 1024); err != nil { //nolint:gosec // a weak key is what is tested
			panic(err)
		}
	})

	return spCertTestRSA2048, spCertTestRSA1024
}

type spCertTemplate struct {
	key       crypto.Signer
	notBefore time.Time
	notAfter  time.Time
	keyUsage  x509.KeyUsage
}

// makeSPCert returns a self-signed certificate made from the template.
func makeSPCert(t *testing.T, tmpl spCertTemplate) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sp.example.com"},
		NotBefore:    tmpl.notBefore,
		NotAfter:     tmpl.notAfter,
		KeyUsage:     tmpl.keyUsage,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, tmpl.key.Public(), tmpl.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

// spCertRequest returns a request whose service provider offers cert for encryption.
func spCertRequest(idp *IdentityProvider, cert *x509.Certificate, keys ...KeyDescriptor) *IdpAuthnRequest {
	certData := base64.StdEncoding.EncodeToString(cert.Raw)
	keys = append([]KeyDescriptor{{Use: "encryption", KeyInfo: KeyInfo{X509Data: X509Data{X509Certificates: []X509Certificate{{Data: certData}}}}}}, keys...)
	descriptor := SPSSODescriptor{SSODescriptor: SSODescriptor{RoleDescriptor: RoleDescriptor{KeyDescriptors: keys}}}

	return &IdpAuthnRequest{
		IDP:                     idp,
		Now:                     TimeNow(),
		SPSSODescriptor:         &descriptor,
		ServiceProviderMetadata: &EntityDescriptor{EntityID: "https://sp.example.com/saml2/metadata", SPSSODescriptors: []SPSSODescriptor{descriptor}},
	}
}

func TestIDPEncryptionCertificatePolicy(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	now := TimeNow()
	rsa2048, rsa1024 := spCertTestKeys(t)
	valid := spCertTemplate{key: rsa2048, notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour)}
	with := func(change func(*spCertTemplate)) spCertTemplate {
		tmpl := valid
		change(&tmpl)

		return tmpl
	}
	expired := with(func(c *spCertTemplate) { c.notBefore, c.notAfter = now.Add(-48*time.Hour), now.Add(-24*time.Hour) })
	notYetValid := with(func(c *spCertTemplate) { c.notBefore, c.notAfter = now.Add(24*time.Hour), now.Add(48*time.Hour) })
	weak := with(func(c *spCertTemplate) { c.key = rsa1024 })
	signingOnly := with(func(c *spCertTemplate) { c.keyUsage = x509.KeyUsageDigitalSignature })

	for _, tc := range []struct {
		name     string
		cert     spCertTemplate
		enforcer EncryptionKeyEnforcer
		err      string
	}{
		{name: "valid", cert: valid},
		{name: "default enforcer", cert: valid, enforcer: DefaultEncryptionKeyEnforcer{}},
		{name: "expired", cert: expired, err: "expired"},
		{name: "not yet valid", cert: notYetValid, err: "not yet valid"},
		{name: "expired within the clock skew", cert: with(func(c *spCertTemplate) { c.notAfter = now.Add(-MaxClockSkew / 2) })},
		{name: "not yet valid within the clock skew", cert: with(func(c *spCertTemplate) { c.notBefore = now.Add(MaxClockSkew / 2) })},
		{name: "expired beyond the clock skew", cert: with(func(c *spCertTemplate) { c.notAfter = now.Add(-2 * MaxClockSkew) }), err: "expired"},
		{name: "RSA-1024", cert: weak, err: "1024-bit"},
		{name: "key usage without key encipherment", cert: signingOnly, err: "keyEncipherment"},
		{name: "key usage with key encipherment", cert: with(func(c *spCertTemplate) { c.keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment })},
		{name: "key usage absent", cert: with(func(c *spCertTemplate) { c.keyUsage = 0 })},

		{name: "expired allowed", cert: expired, enforcer: DefaultEncryptionKeyEnforcer{IgnoreValidityPeriod: true}},
		{name: "not yet valid allowed", cert: notYetValid, enforcer: DefaultEncryptionKeyEnforcer{IgnoreValidityPeriod: true}},
		{name: "expired allowed does not allow RSA-1024", cert: with(func(c *spCertTemplate) { c.key = rsa1024; c.notAfter = now.Add(-24 * time.Hour) }), enforcer: DefaultEncryptionKeyEnforcer{IgnoreValidityPeriod: true}, err: "1024-bit"},
		{name: "expired allowed does not allow a signing only key", cert: with(func(c *spCertTemplate) {
			c.keyUsage = x509.KeyUsageDigitalSignature
			c.notAfter = now.Add(-24 * time.Hour)
		}), enforcer: DefaultEncryptionKeyEnforcer{IgnoreValidityPeriod: true}, err: "keyEncipherment"},
		{name: "RSA-1024 allowed", cert: weak, enforcer: DefaultEncryptionKeyEnforcer{MinimumRSAKeySize: 1024}},
		{name: "RSA-1024 allowed does not allow expired", cert: with(func(c *spCertTemplate) { c.key = rsa1024; c.notAfter = now.Add(-24 * time.Hour) }), enforcer: DefaultEncryptionKeyEnforcer{MinimumRSAKeySize: 1024}, err: "expired"},
		{name: "stricter minimum", cert: valid, enforcer: DefaultEncryptionKeyEnforcer{MinimumRSAKeySize: 3072}, err: "2048-bit"},
		{name: "key usage ignored", cert: signingOnly, enforcer: DefaultEncryptionKeyEnforcer{IgnoreKeyUsage: true}},
		{name: "key usage ignored does not allow expired", cert: with(func(c *spCertTemplate) {
			c.keyUsage = x509.KeyUsageDigitalSignature
			c.notAfter = now.Add(-24 * time.Hour)
		}), enforcer: DefaultEncryptionKeyEnforcer{IgnoreKeyUsage: true}, err: "expired"},
		{name: "everything allowed", cert: with(func(c *spCertTemplate) {
			c.key = rsa1024
			c.keyUsage = x509.KeyUsageDigitalSignature
			c.notAfter = now.Add(-24 * time.Hour)
		}), enforcer: DefaultEncryptionKeyEnforcer{IgnoreValidityPeriod: true, IgnoreKeyUsage: true, MinimumRSAKeySize: 1024}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := test.IDP
			idp.EncryptionKeyEnforcer = tc.enforcer
			req := spCertRequest(&idp, makeSPCert(t, tc.cert))

			cert, err := req.spEncryptionKey()
			if tc.err == "" {
				assert.NoError(t, err)
				assert.NotNil(t, cert)

				return
			}

			assert.ErrorContains(t, err, tc.err)
			assert.False(t, errors.Is(err, os.ErrNotExist), "a rejected certificate must not fall back to plaintext")
			assert.Nil(t, cert)
		})
	}
}

func TestIDPEncryptionCertificateRejectionDoesNotFallBack(t *testing.T) {
	// The first encryption key is the one used, so a rejected key must not make the identity
	// provider try another one, or the service provider's metadata could pick a weaker key.
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.EncryptionKeyEnforcer = nil
	now := TimeNow()
	rsa2048, _ := spCertTestKeys(t)
	expired := makeSPCert(t, spCertTemplate{key: rsa2048, notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-24 * time.Hour)})
	valid := makeSPCert(t, spCertTemplate{key: rsa2048, notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour)})
	validData := base64.StdEncoding.EncodeToString(valid.Raw)

	for _, use := range []string{"encryption", ""} {
		req := spCertRequest(&test.IDP, expired, KeyDescriptor{Use: use, KeyInfo: KeyInfo{X509Data: X509Data{X509Certificates: []X509Certificate{{Data: validData}}}}})
		cert, err := req.spEncryptionKey()
		assert.ErrorContains(t, err, "expired", "use=%q", use)
		assert.Nil(t, cert)
	}
}

// An elliptic curve key is encrypted to by ECDH-ES, unless it is on a curve that ECDH-ES isn't supported on, or
// its certificate doesn't allow key agreement.
func TestIDPEncryptionCertificateElliptic(t *testing.T) {
	now := TimeNow()

	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		template spCertTemplate
		err      string
	}{
		"P-256":                  {spCertTemplate{key: p256}, ""},
		"P-256 key agreement":    {spCertTemplate{key: p256, keyUsage: x509.KeyUsageKeyAgreement}, ""},
		"P-256 signing only":     {spCertTemplate{key: p256, keyUsage: x509.KeyUsageDigitalSignature}, "does not assert keyAgreement"},
		"P-256 key encipherment": {spCertTemplate{key: p256, keyUsage: x509.KeyUsageKeyEncipherment}, "does not assert keyAgreement"},
		"P-224":                  {spCertTemplate{key: p224}, "no usable key"},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			test.IDP.EncryptionKeyEnforcer = nil

			tc.template.notBefore, tc.template.notAfter = now.Add(-time.Hour), now.Add(time.Hour)

			req := spCertRequest(&test.IDP, makeSPCert(t, tc.template))
			req.Assertion = &Assertion{ID: "id-1", IssueInstant: now, Version: "2.0", Issuer: Issuer{Value: "https://idp.example.com/saml/metadata"}}

			err := req.MakeAssertionEl()
			if tc.err != "" {
				assert.ErrorContains(t, err, tc.err)
				assert.Nil(t, req.AssertionEl)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, req.AssertionEl.Tag, "EncryptedAssertion")
		})
	}

	// MinimumECKeySize may only make it stricter.
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.EncryptionKeyEnforcer = DefaultEncryptionKeyEnforcer{MinimumECKeySize: 384}

	req := spCertRequest(&test.IDP, makeSPCert(t, spCertTemplate{key: p256, notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour)}))
	_, err = req.spEncryptionKey()
	assert.ErrorContains(t, err, "256-bit curve, smaller than the minimum of 384 bits")
}

// entityEnforcer allows weak certificates for one service provider only.
type entityEnforcer struct {
	legacy string
	seen   []string
}

func (e *entityEnforcer) EnforceEncryptionKey(req *IdpAuthnRequest, key ServiceProviderEncryptionKey) error {
	e.seen = append(e.seen, req.ServiceProviderMetadata.EntityID)
	if req.ServiceProviderMetadata.EntityID == e.legacy {
		return DefaultEncryptionKeyEnforcer{IgnoreValidityPeriod: true, MinimumRSAKeySize: 1024}.EnforceEncryptionKey(req, key)
	}

	return DefaultEncryptionKeyEnforcer{}.EnforceEncryptionKey(req, key)
}

func TestIDPEncryptionKeyEnforcerPerServiceProvider(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	enforcer := &entityEnforcer{legacy: "https://legacy.example.com/saml2/metadata"}
	test.IDP.EncryptionKeyEnforcer = enforcer

	// The fixture certificate of the service provider is RSA-1024 and expired at the mocked time.
	legacy := spCertRequest(&test.IDP, test.SPCertificate)
	legacy.ServiceProviderMetadata.EntityID = enforcer.legacy
	_, err := legacy.spEncryptionKey()
	assert.NoError(t, err)

	other := spCertRequest(&test.IDP, test.SPCertificate)
	_, err = other.spEncryptionKey()
	assert.ErrorContains(t, err, "expired")

	assert.Equal(t, []string{enforcer.legacy, "https://sp.example.com/saml2/metadata"}, enforcer.seen)
}

func TestIDPServeSSORefusesRejectedEncryptionCertificate(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.EncryptionKeyEnforcer = nil

	var logs bytes.Buffer

	test.IDP.Observer = logObserver(&logs)
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(_ http.ResponseWriter, _ *http.Request, _ *IdpAuthnRequest) *Session {
			return &Session{ID: "f00df00df00d", NameID: "alice", UserName: "alice"}
		},
	}

	now := TimeNow()
	rsa2048, _ := spCertTestKeys(t)
	test.SP.Key = rsa2048
	test.SP.Certificate = makeSPCert(t, spCertTemplate{key: rsa2048, notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-24 * time.Hour)})

	requestURL, err := test.SP.MakeRedirectAuthenticationRequest("ThisIsTheRelayState")
	require.NoError(t, err)

	r, _ := http.NewRequest("GET", requestURL.String(), nil)
	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	_, refused := postedResponse(t, w.Body.String())
	assert.Equal(t, refused.Status.StatusCode.Value, StatusResponder)
	assert.Nil(t, refused.Assertion)
	assert.Nil(t, refused.EncryptedAssertion)
	assert.Contains(t, logs.String(), "encryption key")
	assert.Contains(t, logs.String(), "expired")

	// The same service provider gets an encrypted assertion once the operator allows it.
	test.IDP.EncryptionKeyEnforcer = DefaultEncryptionKeyEnforcer{IgnoreValidityPeriod: true}
	w = httptest.NewRecorder()
	test.IDP.ServeSSO(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "SAMLResponse")
}
