package dsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedSigner returns a chosen signature, which lets a test control the values of r and s.
type fixedSigner struct {
	public    crypto.PublicKey
	signature []byte
}

func (s fixedSigner) Public() crypto.PublicKey { return s.public }

func (s fixedSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return s.signature, nil
}

func mustDER(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	require.NoError(t, err)
	return der
}

// rewriteRootSignatureValue applies fn to the decoded value of the signature on the root element. The
// signature on the nested assertion is left alone, because the digest of the root signature covers it.
func rewriteRootSignatureValue(t *testing.T, doc *etree.Document, fn func([]byte) []byte) {
	t.Helper()
	value := doc.Root().FindElement("./Signature/SignatureValue")
	require.NotNil(t, value)
	decoded, err := base64.StdEncoding.DecodeString(value.Text())
	require.NoError(t, err)
	value.SetText(base64.StdEncoding.EncodeToString(fn(decoded)))
}

// derToRawForTest is deliberately separate from the production conversion.
func derToRawForTest(t *testing.T, size int) func([]byte) []byte {
	return func(der []byte) []byte {
		var parsed struct{ R, S *big.Int }
		_, err := asn1.Unmarshal(der, &parsed)
		require.NoError(t, err)
		raw := make([]byte, 2*size)
		parsed.R.FillBytes(raw[:size])
		parsed.S.FillBytes(raw[size:])
		return raw
	}
}

func validateECDSAFixture(t *testing.T, fn func([]byte) []byte) error {
	t.Helper()
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes([]byte(ecdsaResponse)))
	rewriteRootSignatureValue(t, doc, fn)

	block, _ := pem.Decode([]byte(ecdsaCert))
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	vc := NewDefaultValidationContext(&MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	vc.Clock = NewFakeClockAt(cert.NotBefore)
	_, err = vc.Validate(doc.Root())
	return err
}

func TestValidateECDSAAcceptsRawSignature(t *testing.T) {
	assert.NoError(t, validateECDSAFixture(t, derToRawForTest(t, 32)))
}

func TestValidateECDSARejectsOtherEncodings(t *testing.T) {
	testCases := []struct {
		name string
		fn   func([]byte) []byte
	}{
		{"der", func(der []byte) []byte { return der }},
		{"truncated", func(der []byte) []byte { return derToRawForTest(t, 32)(der)[:63] }},
		{"odd length", func(der []byte) []byte { return append(derToRawForTest(t, 32)(der), 0) }},
		{"padded", func(der []byte) []byte { return derToRawForTest(t, 33)(der) }},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ErrorContains(t, validateECDSAFixture(t, tc.fn), "invalid ECDSA signature length")
		})
	}
}

func TestSignStringECDSAWritesRawSignatureVerifiedByStdlib(t *testing.T) {
	for name, curve := range map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()} {
		t.Run(name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			require.NoError(t, err)
			ctx, err := NewSigningContext(key, nil)
			require.NoError(t, err)
			require.NoError(t, ctx.SetSignatureMethod(ECDSASHA256SignatureMethod))

			signature, err := ctx.SignString("content")
			require.NoError(t, err)

			size := (curve.Params().N.BitLen() + 7) / 8
			require.Len(t, signature, 2*size)
			digest := sha256.Sum256([]byte("content"))
			r := new(big.Int).SetBytes(signature[:size])
			s := new(big.Int).SetBytes(signature[size:])
			assert.True(t, ecdsa.Verify(&key.PublicKey, digest[:], r, s))
		})
	}
}

func TestSignECDSAPadsToCurveSize(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ctx, err := NewSigningContext(fixedSigner{key.Public(), mustDER(t, big.NewInt(1), big.NewInt(2))}, nil)
	require.NoError(t, err)
	require.NoError(t, ctx.SetSignatureMethod(ECDSASHA256SignatureMethod))

	signature, err := ctx.SignString("content")
	require.NoError(t, err)

	expected := make([]byte, 64)
	expected[31], expected[63] = 1, 2
	assert.Equal(t, expected, signature)
}

func TestSignECDSARejectsInvalidSignerOutput(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tooLarge := new(big.Int).Lsh(big.NewInt(1), 256)
	valid := mustDER(t, big.NewInt(1), big.NewInt(2))

	testCases := map[string][]byte{
		"not der":       []byte("not der"),
		"trailing data": append(append([]byte{}, valid...), 0),
		"r too large":   mustDER(t, tooLarge, big.NewInt(1)),
		"s too large":   mustDER(t, big.NewInt(1), tooLarge),
		"negative":      mustDER(t, big.NewInt(-1), big.NewInt(1)),
		"zero":          mustDER(t, big.NewInt(0), big.NewInt(1)),
	}
	for name, signature := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx, err := NewSigningContext(fixedSigner{key.Public(), signature}, nil)
			require.NoError(t, err)
			require.NoError(t, ctx.SetSignatureMethod(ECDSASHA256SignatureMethod))
			_, err = ctx.SignString("content")
			assert.Error(t, err)
		})
	}
}

func TestSignAndValidateECDSARoundTrip(t *testing.T) {
	curves := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}
	methods := []string{ECDSASHA1SignatureMethod, ECDSASHA256SignatureMethod, ECDSASHA384SignatureMethod, ECDSASHA512SignatureMethod}
	for name, curve := range curves {
		for _, method := range methods {
			t.Run(name+"/"+method, func(t *testing.T) {
				key, err := ecdsa.GenerateKey(curve, rand.Reader)
				require.NoError(t, err)
				template := &x509.Certificate{
					SerialNumber: big.NewInt(1),
					Subject:      pkix.Name{CommonName: "test"},
					NotBefore:    time.Now().Add(-time.Hour),
					NotAfter:     time.Now().Add(time.Hour),
				}
				der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
				require.NoError(t, err)
				cert, err := x509.ParseCertificate(der)
				require.NoError(t, err)

				ctx, err := NewSigningContext(key, [][]byte{der})
				require.NoError(t, err)
				ctx.Canonicalizer = MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
				require.NoError(t, ctx.SetSignatureMethod(method))

				el := etree.NewElement("Root")
				el.CreateAttr("ID", "_id")
				el.CreateElement("Child")
				signed, err := ctx.SignEnveloped(el)
				require.NoError(t, err)

				doc := etree.NewDocument()
				doc.SetRoot(signed)
				serialized, err := doc.WriteToBytes()
				require.NoError(t, err)
				parsed := etree.NewDocument()
				require.NoError(t, parsed.ReadFromBytes(serialized))

				vc := NewDefaultValidationContext(&MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
				_, err = vc.Validate(parsed.Root())
				assert.NoError(t, err)
			})
		}
	}
}
