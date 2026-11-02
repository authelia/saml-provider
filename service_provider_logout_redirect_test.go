package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"authelia.com/provider/saml/internal/dsig"
	"authelia.com/provider/saml/testsaml"
)

func logoutRedirectSP(t *testing.T) (ServiceProvider, *ServiceProviderTest) {
	t.Helper()
	test := NewServiceProviderTest(t)
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://sp.example.com/saml2/metadata"),
		AcsURL:      mustParseURL("https://sp.example.com/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	assert.NilError(t, xml.Unmarshal(test.IDPMetadata, s.IDPMetadata))
	return s, test
}

// assertRedirectParameterOrder checks the query has exactly the given parameters in order.
func assertRedirectParameterOrder(t *testing.T, rawQuery string, keys ...string) {
	t.Helper()
	pairs := strings.Split(rawQuery, "&")
	got := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		key, _, _ := strings.Cut(pair, "=")
		got = append(got, key)
	}
	assert.Check(t, is.DeepEqual(keys, got))
}

func TestSPSignsRedirectLogoutMessagesInTheQuery(t *testing.T) {
	messages := map[string]struct {
		parameter string
		redirect  func(*ServiceProvider) (*url.URL, error)
	}{
		"request": {"SAMLRequest", func(s *ServiceProvider) (*url.URL, error) {
			return s.MakeRedirectLogoutRequest("alice", "relay state&more")
		}},
		"response": {"SAMLResponse", func(s *ServiceProvider) (*url.URL, error) {
			return s.MakeRedirectLogoutResponse("id-request", "relay state&more")
		}},
	}
	decode := func(t *testing.T, parameter string, u *url.URL) []byte {
		t.Helper()
		var (
			decoded []byte
			err     error
		)
		if parameter == "SAMLRequest" {
			decoded, err = testsaml.ParseRedirectRequest(u)
		} else {
			decoded, err = testsaml.ParseRedirectResponse(u)
		}
		assert.NilError(t, err)
		return decoded
	}

	for name, tc := range messages {
		t.Run(name+"/rsa", func(t *testing.T) {
			s, test := logoutRedirectSP(t)
			s.SignatureMethod = dsig.RSASHA256SignatureMethod

			u, err := tc.redirect(&s)
			assert.NilError(t, err)
			assertRedirectParameterOrder(t, u.RawQuery, tc.parameter, "RelayState", "SigAlg", "Signature")
			assert.Check(t, is.Equal("relay state&more", u.Query().Get("RelayState")))
			assert.Check(t, !strings.Contains(string(decode(t, tc.parameter, u)), "Signature>"))

			signed, signature := signedRedirectQuery(t, u.RawQuery)
			assert.Check(t, test.Certificate.CheckSignature(x509.SHA256WithRSA, []byte(signed), signature))
		})

		for _, curve := range ecdsaTestCurves {
			t.Run(name+"/"+curve.name, func(t *testing.T) {
				s, _ := logoutRedirectSP(t)
				key, cert := newECDSATestKey(t, curve.curve)
				s.Key, s.Certificate, s.SignatureMethod = key, cert, curve.method

				u, err := tc.redirect(&s)
				assert.NilError(t, err)
				assert.Check(t, is.Equal(curve.method, u.Query().Get("SigAlg")))
				assert.Check(t, !strings.Contains(string(decode(t, tc.parameter, u)), "Signature>"))

				signed, signature := signedRedirectQuery(t, u.RawQuery)
				size := (curve.curve.Params().N.BitLen() + 7) / 8
				assert.Assert(t, is.Len(signature, 2*size))
				hash := curve.newHash.New()
				hash.Write([]byte(signed))
				r := new(big.Int).SetBytes(signature[:size])
				sValue := new(big.Int).SetBytes(signature[size:])
				assert.Check(t, ecdsa.Verify(&key.PublicKey, hash.Sum(nil), r, sValue))
			})
		}

		t.Run(name+"/unsigned", func(t *testing.T) {
			s, _ := logoutRedirectSP(t)
			u, err := tc.redirect(&s)
			assert.NilError(t, err)
			assertRedirectParameterOrder(t, u.RawQuery, tc.parameter, "RelayState")
		})
	}
}

func TestLogoutRedirectRemovesEmbeddedSignatureWithoutChangingTheMessage(t *testing.T) {
	s, _ := logoutRedirectSP(t)
	s.SignatureMethod = dsig.RSASHA256SignatureMethod

	request, err := s.MakeLogoutRequest("https://idp.example.com/slo?tenant=a", "alice")
	assert.NilError(t, err)
	assert.Assert(t, request.Signature != nil)
	u, err := request.Redirect("", &s)
	assert.NilError(t, err)
	assert.Check(t, request.Signature != nil)
	assertRedirectParameterOrder(t, u.RawQuery, "tenant", "SAMLRequest", "SigAlg", "Signature")
	signed, _ := signedRedirectQuery(t, u.RawQuery)
	assert.Check(t, strings.HasPrefix(strings.TrimPrefix(signed, "tenant=a&"), "SAMLRequest="))
	decoded, err := testsaml.ParseRedirectRequest(u)
	assert.NilError(t, err)
	assert.Check(t, !strings.Contains(string(decoded), "Signature>"))

	response, err := s.MakeLogoutResponse("https://idp.example.com/slo", "id-request")
	assert.NilError(t, err)
	assert.Assert(t, response.Signature != nil)
	u, err = response.Redirect("", &s)
	assert.NilError(t, err)
	assert.Check(t, response.Signature != nil)
	decoded, err = testsaml.ParseRedirectResponse(u)
	assert.NilError(t, err)
	assert.Check(t, !strings.Contains(string(decoded), "Signature>"))
}

// logoutResponseFixture is a service provider and an unsigned logout response from its identity provider.
type logoutResponseFixture struct {
	sp      ServiceProvider
	key     crypto.Signer
	cert    *x509.Certificate
	message string
}

func newLogoutResponseFixture(t *testing.T) *logoutResponseFixture {
	t.Helper()
	test := NewIdentityProviderTest(t, applyKey)
	TimeNow = time.Now
	previous := Clock
	t.Cleanup(func() { Clock = previous })
	Clock = dsig.NewFakeClockAt(test.Certificate.NotBefore)

	sp := test.SP
	sp.IDPMetadata = test.IDP.Metadata()
	sp.SloURL = mustParseURL("https://sp.example.com/saml2/slo")
	f := &logoutResponseFixture{sp: sp, key: test.IDP.Key.(crypto.Signer), cert: test.Certificate}
	f.setMessage(t, sp.SloURL.String())
	return f
}

func (f *logoutResponseFixture) setMessage(t *testing.T, destination string) {
	t.Helper()
	body := fmt.Sprintf(`<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id-response" InResponseTo="id-request" Version="2.0" IssueInstant="%s" Destination="%s"><saml:Issuer>%s</saml:Issuer><samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status></samlp:LogoutResponse>`,
		time.Now().UTC().Format(time.RFC3339), destination, f.sp.IDPMetadata.EntityID, StatusSuccess)
	var compressed bytes.Buffer
	w, err := flate.NewWriter(&compressed, flate.BestCompression)
	assert.NilError(t, err)
	_, err = w.Write([]byte(body))
	assert.NilError(t, err)
	assert.NilError(t, w.Close())
	f.message = base64.StdEncoding.EncodeToString(compressed.Bytes())
}

// signQuery signs the query with the standard library, independently of the code being tested.
func signQuery(t *testing.T, key crypto.Signer, method, message, relayState string) string {
	t.Helper()
	query := "SAMLResponse=" + url.QueryEscape(message)
	if relayState != "" {
		query += "&RelayState=" + url.QueryEscape(relayState)
	}
	query += "&SigAlg=" + url.QueryEscape(method)
	digest := sha256.Sum256([]byte(query))
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	assert.NilError(t, err)
	if public, ok := key.Public().(*ecdsa.PublicKey); ok {
		var parsed struct{ R, S *big.Int }
		_, err = asn1.Unmarshal(signature, &parsed)
		assert.NilError(t, err)
		size := (public.Params().N.BitLen() + 7) / 8
		signature = make([]byte, 2*size)
		parsed.R.FillBytes(signature[:size])
		parsed.S.FillBytes(signature[size:])
	}
	return query + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(signature))
}

func (f *logoutResponseFixture) signed(t *testing.T, relayState string) string {
	t.Helper()
	return signQuery(t, f.key, dsig.RSASHA256SignatureMethod, f.message, relayState)
}

func (f *logoutResponseFixture) validate(rawQuery string) error {
	return f.sp.ValidateLogoutResponseRedirect(&url.URL{RawQuery: rawQuery})
}

func TestSPValidatesRedirectLogoutResponseSignedInTheQuery(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		f := newLogoutResponseFixture(t)
		assert.Check(t, f.validate(f.signed(t, "")))
	})

	t.Run("with relay state", func(t *testing.T) {
		f := newLogoutResponseFixture(t)
		assert.Check(t, f.validate(f.signed(t, "relay state&more")))
	})

	t.Run("parameters in any order with others ignored", func(t *testing.T) {
		f := newLogoutResponseFixture(t)
		pairs := strings.Split(f.signed(t, "relay"), "&")
		assert.Check(t, f.validate(strings.Join([]string{"extra=1", pairs[3], pairs[2], pairs[1], pairs[0]}, "&")))
	})

	t.Run("through the request", func(t *testing.T) {
		f := newLogoutResponseFixture(t)
		req, err := http.NewRequest(http.MethodGet, "https://sp.example.com/saml2/slo?"+f.signed(t, "relay"), nil)
		assert.NilError(t, err)
		assert.Check(t, f.sp.ValidateLogoutResponseRequest(req))
	})

	t.Run("ecdsa", func(t *testing.T) {
		f := newLogoutResponseFixture(t)
		key, cert := newECDSATestKey(t, elliptic.P256())
		certificate := base64.StdEncoding.EncodeToString(cert.Raw)
		f.sp.IDPCertificate = &certificate
		Clock = dsig.NewFakeClockAt(time.Now())
		assert.Check(t, f.validate(signQuery(t, key, dsig.ECDSASHA256SignatureMethod, f.message, "")))
	})

	t.Run("pinned certificate", func(t *testing.T) {
		f := newLogoutResponseFixture(t)
		certificate := base64.StdEncoding.EncodeToString(f.cert.Raw)
		f.sp.IDPCertificate = &certificate
		assert.Check(t, f.validate(f.signed(t, "")))
	})

	t.Run("fields of the message are still checked", func(t *testing.T) {
		f := newLogoutResponseFixture(t)
		f.setMessage(t, "https://other.example.com/slo")
		assert.Check(t, is.ErrorContains(f.validate(f.signed(t, "")), "Destination"))
	})
}

func TestSPRejectsInvalidRedirectLogoutResponseSignature(t *testing.T) {
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)

	for _, tc := range []struct {
		name   string
		query  func(*testing.T, *logoutResponseFixture) string
		reason string
	}{
		{"changed relay state", func(t *testing.T, f *logoutResponseFixture) string {
			return strings.Replace(f.signed(t, "relay"), "RelayState=relay", "RelayState=other", 1)
		}, "verifies the signature"},
		{"removed relay state", func(t *testing.T, f *logoutResponseFixture) string {
			return strings.Replace(f.signed(t, "relay"), "&RelayState=relay", "", 1)
		}, "verifies the signature"},
		{"changed message", func(t *testing.T, f *logoutResponseFixture) string {
			query := f.signed(t, "")
			f.setMessage(t, "https://forged.example.com/slo")
			_, rest, _ := strings.Cut(query, "&")
			return "SAMLResponse=" + url.QueryEscape(f.message) + "&" + rest
		}, "verifies the signature"},
		{"signed by another key", func(t *testing.T, f *logoutResponseFixture) string {
			return signQuery(t, otherKey, dsig.RSASHA256SignatureMethod, f.message, "")
		}, "verifies the signature"},
		{"missing signature", func(t *testing.T, f *logoutResponseFixture) string {
			query, _, _ := strings.Cut(f.signed(t, ""), "&Signature=")
			return query
		}, "missing Signature"},
		{"missing algorithm", func(t *testing.T, f *logoutResponseFixture) string {
			pairs := strings.Split(f.signed(t, ""), "&")
			return pairs[0] + "&" + pairs[2]
		}, "missing SigAlg"},
		{"unsupported algorithm", func(t *testing.T, f *logoutResponseFixture) string {
			return strings.Replace(f.signed(t, ""), url.QueryEscape(dsig.RSASHA256SignatureMethod), "none", 1)
		}, "unsupported signature algorithm"},
		{"algorithm for another type of key", func(t *testing.T, f *logoutResponseFixture) string {
			return signQuery(t, f.key, dsig.ECDSASHA256SignatureMethod, f.message, "")
		}, ""},
		{"repeated message", func(t *testing.T, f *logoutResponseFixture) string {
			return "SAMLResponse=forged&" + f.signed(t, "")
		}, "repeated SAMLResponse"},
		{"repeated message with an encoded name", func(t *testing.T, f *logoutResponseFixture) string {
			return "SAML%52esponse=forged&" + f.signed(t, "")
		}, "repeated SAMLResponse"},
		{"malformed signature", func(t *testing.T, f *logoutResponseFixture) string {
			query, _, _ := strings.Cut(f.signed(t, ""), "&Signature=")
			return query + "&Signature=%"
		}, "malformed Signature"},
		{"no signature of either kind", func(_ *testing.T, f *logoutResponseFixture) string {
			return "SAMLResponse=" + url.QueryEscape(f.message)
		}, "signature"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLogoutResponseFixture(t)
			err := f.validate(tc.query(t, f))
			assert.Assert(t, err != nil)
			if tc.reason != "" {
				private := err
				if invalid, ok := err.(*InvalidResponseError); ok {
					private = invalid.PrivateErr
				}
				assert.Check(t, is.ErrorContains(private, tc.reason))
			}
		})
	}

	t.Run("ecdsa der", func(t *testing.T) {
		f := newLogoutResponseFixture(t)
		key, cert := newECDSATestKey(t, elliptic.P256())
		certificate := base64.StdEncoding.EncodeToString(cert.Raw)
		f.sp.IDPCertificate = &certificate
		Clock = dsig.NewFakeClockAt(time.Now())

		query := "SAMLResponse=" + url.QueryEscape(f.message) + "&SigAlg=" + url.QueryEscape(dsig.ECDSASHA256SignatureMethod)
		h := crypto.SHA256.New()
		h.Write([]byte(query))
		der, err := key.Sign(rand.Reader, h.Sum(nil), crypto.SHA256)
		assert.NilError(t, err)
		err = f.validate(query + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(der)))
		assert.Assert(t, err != nil)
	})

	t.Run("expired certificate", func(t *testing.T) {
		f := newLogoutResponseFixture(t)
		Clock = dsig.NewFakeClockAt(f.cert.NotAfter.Add(time.Hour))
		assert.Assert(t, f.validate(f.signed(t, "")) != nil)
	})

	t.Run("repeated message through the request", func(t *testing.T) {
		f := newLogoutResponseFixture(t)
		req, err := http.NewRequest(http.MethodGet, "https://sp.example.com/saml2/slo?SAML%52esponse=forged&"+f.signed(t, ""), nil)
		assert.NilError(t, err)
		assert.Assert(t, f.sp.ValidateLogoutResponseRequest(req) != nil)
	})
}

func TestSPValidatesRedirectLogoutResponseWithFingerprint(t *testing.T) {
	f := newLogoutResponseFixture(t)
	sum := dsigFingerprintForTest(f.cert)
	algorithm := "http://www.w3.org/2001/04/xmlenc#sha256"
	f.sp.IDPCertificateFingerprint = &sum
	f.sp.IDPCertificateFingerprintAlgorithm = &algorithm
	assert.Check(t, f.validate(f.signed(t, "")))

	other := strings.Repeat("00", 32)
	f.sp.IDPCertificateFingerprint = &other
	assert.Assert(t, f.validate(f.signed(t, "")) != nil)
}

func TestSPStillAcceptsEmbeddedSignatureOnRedirectLogoutResponse(t *testing.T) {
	f := newLogoutResponseFixture(t)
	idp := ServiceProvider{Key: f.key, Certificate: f.cert, SignatureMethod: dsig.RSASHA256SignatureMethod}
	idp.EntityID = f.sp.IDPMetadata.EntityID
	idp.IDPMetadata = f.sp.IDPMetadata

	response, err := idp.MakeLogoutResponse(f.sp.SloURL.String(), "id-request")
	assert.NilError(t, err)
	doc := etree.NewDocument()
	doc.SetRoot(response.Element())
	body, err := doc.WriteToBytes()
	assert.NilError(t, err)
	var compressed bytes.Buffer
	w, err := flate.NewWriter(&compressed, flate.BestCompression)
	assert.NilError(t, err)
	_, err = w.Write(body)
	assert.NilError(t, err)
	assert.NilError(t, w.Close())

	assert.Check(t, f.validate("SAMLResponse="+url.QueryEscape(base64.StdEncoding.EncodeToString(compressed.Bytes()))))
}

func dsigFingerprintForTest(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	pairs := make([]string, len(sum))
	for i, b := range sum {
		pairs[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(pairs, ":")
}

func TestLogoutResponseRedirectRoundTrip(t *testing.T) {
	f := newLogoutResponseFixture(t)
	sender := ServiceProvider{
		EntityID:        f.sp.IDPMetadata.EntityID,
		Key:             f.key,
		Certificate:     f.cert,
		IDPMetadata:     f.sp.IDPMetadata,
		SignatureMethod: dsig.RSASHA256SignatureMethod,
	}
	response, err := sender.MakeLogoutResponse(f.sp.SloURL.String(), "id-request")
	assert.NilError(t, err)
	u, err := response.Redirect("relay state&more", &sender)
	assert.NilError(t, err)

	assert.Check(t, f.sp.ValidateLogoutResponseRedirect(u))

	u.RawQuery = strings.Replace(u.RawQuery, "RelayState=relay", "RelayState=other", 1)
	assert.Assert(t, f.sp.ValidateLogoutResponseRedirect(u) != nil)
}
