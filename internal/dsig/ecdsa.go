package dsig

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// ecdsaSignature is the DER structure crypto.Signer and x509.Certificate.CheckSignature use.
type ecdsaSignature struct {
	R, S *big.Int
}

// ecdsaFieldSize returns the size of r and s in a signature, which is the size of the base point
// order of the curve in bytes.
func ecdsaFieldSize(public *ecdsa.PublicKey) int {
	return (public.Curve.Params().N.BitLen() + 7) / 8
}

// ecdsaDERToRaw converts a DER signature to the r||s form required by XML Signature 1.1 §6.4.3,
// where each value is padded to the size of the curve.
func ecdsaDERToRaw(public *ecdsa.PublicKey, der []byte) ([]byte, error) {
	var signature ecdsaSignature
	rest, err := asn1.Unmarshal(der, &signature)
	if err != nil {
		return nil, fmt.Errorf("invalid ECDSA signature from signer: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("invalid ECDSA signature from signer: trailing data")
	}

	size := ecdsaFieldSize(public)
	for _, value := range []*big.Int{signature.R, signature.S} {
		if value.Sign() <= 0 || value.BitLen() > size*8 {
			return nil, errors.New("invalid ECDSA signature from signer: value out of range")
		}
	}

	raw := make([]byte, 2*size)
	signature.R.FillBytes(raw[:size])
	signature.S.FillBytes(raw[size:])
	return raw, nil
}

// ecdsaRawToDER converts an r||s signature to DER. Any other length is rejected, which includes DER
// signatures, because XML Signature does not allow them.
func ecdsaRawToDER(public *ecdsa.PublicKey, raw []byte) ([]byte, error) {
	size := ecdsaFieldSize(public)
	if len(raw) != 2*size {
		return nil, fmt.Errorf("invalid ECDSA signature length %d, expected %d", len(raw), 2*size)
	}
	return asn1.Marshal(ecdsaSignature{
		R: new(big.Int).SetBytes(raw[:size]),
		S: new(big.Int).SetBytes(raw[size:]),
	})
}

// checkSignature verifies a decoded SignatureValue or query string signature against the certificate.
func checkSignature(cert *x509.Certificate, algorithm x509.SignatureAlgorithm, signed, signature []byte) error {
	public, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if ok && isECDSAAlgorithm(algorithm) {
		der, err := ecdsaRawToDER(public, signature)
		if err != nil {
			return err
		}
		signature = der
	}
	return cert.CheckSignature(algorithm, signed, signature)
}

func isECDSAAlgorithm(algorithm x509.SignatureAlgorithm) bool {
	switch algorithm {
	case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return true
	default:
		return false
	}
}

// DefaultECDSASignatureMethod returns the signature method whose hash matches the strength of the
// curve of the key.
func DefaultECDSASignatureMethod(public *ecdsa.PublicKey) string {
	switch size := public.Curve.Params().N.BitLen(); {
	case size <= 256:
		return ECDSASHA256SignatureMethod
	case size <= 384:
		return ECDSASHA384SignatureMethod
	default:
		return ECDSASHA512SignatureMethod
	}
}
