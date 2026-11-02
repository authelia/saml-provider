package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"

	"github.com/beevik/etree"

	"authelia.com/provider/saml/internal/dsig"
)

// redirectSignatureHashes lists the signature algorithms accepted on the HTTP-Redirect binding.
var redirectSignatureHashes = map[string]crypto.Hash{
	dsig.RSASHA1SignatureMethod:     crypto.SHA1,
	dsig.RSASHA256SignatureMethod:   crypto.SHA256,
	dsig.RSASHA384SignatureMethod:   crypto.SHA384,
	dsig.RSASHA512SignatureMethod:   crypto.SHA512,
	dsig.ECDSASHA1SignatureMethod:   crypto.SHA1,
	dsig.ECDSASHA256SignatureMethod: crypto.SHA256,
	dsig.ECDSASHA384SignatureMethod: crypto.SHA384,
	dsig.ECDSASHA512SignatureMethod: crypto.SHA512,
}

// verifyAuthnRequestSignature verifies any signature on the request, and returns an error if there is
// none and one is required. ServiceProviderMetadata must be set.
func (req *IdpAuthnRequest) verifyAuthnRequestSignature() error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(req.RequestBuffer); err != nil {
		return err
	}
	if doc.Root() == nil {
		return errors.New("request has no root element")
	}
	signatureEl, err := findChild(doc.Root(), "http://www.w3.org/2000/09/xmldsig#", "Signature")
	if err != nil {
		return err
	}

	if req.RedirectQuery == "" && signatureEl == nil {
		if req.IDP.WantAuthnRequestsSigned || req.serviceProviderSignsAuthnRequests() {
			return errors.New("request is not signed")
		}
		return nil
	}

	certificates, err := req.serviceProviderSigningCertificates()
	if err != nil {
		return err
	}
	if len(certificates) == 0 {
		return errors.New("request is signed but the service provider has no signing certificate")
	}

	if req.RedirectQuery != "" {
		if err := verifyRedirectSignature(req.RedirectQuery, "SAMLRequest", certificates); err != nil {
			return fmt.Errorf("invalid request signature: %w", err)
		}
	}
	if signatureEl != nil {
		verified, err := verifyEnvelopedSignature(doc.Root(), certificates)
		if err != nil {
			return fmt.Errorf("invalid request signature: %w", err)
		}
		if err := req.useVerifiedRequest(verified); err != nil {
			return err
		}
	}

	// SAMLBind §3.4.5.2 and §3.5.5.2 require this of a signed message. Validate has already checked
	// any value that is present.
	if req.Request.Destination == "" {
		return errors.New("signed request has no destination")
	}
	return nil
}

// useVerifiedRequest replaces Request with the content that the signature covers, and repeats the
// checks that were made on the original.
//
// The original can't be trusted even with a valid signature. Exclusive canonicalization drops unused
// namespace declarations, so xmlns:IssueInstant="..." doesn't change the digest, while encoding/xml
// matches attributes on their local name in any namespace and would read it as the IssueInstant.
func (req *IdpAuthnRequest) useVerifiedRequest(verified *etree.Element) error {
	serviceProviderID := req.Request.Issuer.Value

	req.Request = AuthnRequest{}
	if err := unmarshalElement(verified, &req.Request); err != nil {
		return err
	}
	if err := req.checkRequest(); err != nil {
		return err
	}
	if req.Request.Issuer.Value != serviceProviderID {
		return errors.New("signed request has a different issuer")
	}
	return nil
}

// serviceProviderSignsAuthnRequests returns true if any SPSSODescriptor declares that its requests
// are signed. All are considered because the descriptor in use is selected by the ACS in the request,
// which must not be able to avoid the signature.
func (req *IdpAuthnRequest) serviceProviderSignsAuthnRequests() bool {
	for _, descriptor := range req.ServiceProviderMetadata.SPSSODescriptors {
		if descriptor.AuthnRequestsSigned != nil && *descriptor.AuthnRequestsSigned {
			return true
		}
	}
	return false
}

// serviceProviderSigningCertificates returns the certificates that the service provider may sign with.
func (req *IdpAuthnRequest) serviceProviderSigningCertificates() ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	for _, descriptor := range req.ServiceProviderMetadata.SPSSODescriptors {
		for _, keyDescriptor := range descriptor.KeyDescriptors {
			if keyDescriptor.Use != "signing" && keyDescriptor.Use != "" {
				continue
			}
			for _, certificate := range keyDescriptor.KeyInfo.X509Data.X509Certificates {
				der, err := base64.StdEncoding.DecodeString(whitespaceRemover.Replace(certificate.Data))
				if err != nil {
					return nil, fmt.Errorf("cannot decode service provider certificate: %w", err)
				}
				// ServiceProvider.Metadata concatenates any intermediates after the certificate. Those
				// aren't what the service provider signs with, and must not become trusted signers.
				parsed, err := x509.ParseCertificates(der)
				if err != nil {
					return nil, fmt.Errorf("cannot parse service provider certificate: %w", err)
				}
				if len(parsed) != 0 {
					certificates = append(certificates, parsed[0])
				}
			}
		}
	}
	return certificates, nil
}

var whitespaceRemover = strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "")

// verifyEnvelopedSignature verifies the signature on el with any of the certificates, and returns the
// content that it covers. They are tried in turn because a signature with no KeyInfo can only be
// checked against a single certificate.
func verifyEnvelopedSignature(el *etree.Element, certificates []*x509.Certificate) (*etree.Element, error) {
	var err error
	for _, certificate := range certificates {
		validationContext, detached, contextErr := signatureValidationContext(el, []*x509.Certificate{certificate})
		if contextErr != nil {
			return nil, contextErr
		}
		var verified *etree.Element
		if verified, err = validationContext.Validate(detached); err == nil {
			return verified, nil
		}
	}
	return nil, err
}

// redirectParameters returns the undecoded values of the parameters which take part in a signature.
//
// The keys are decoded to match, and a repeat is an error, because url.Values also decodes the keys
// and returns the first value. Otherwise SAML%52equest=forged placed before the signed parameter
// would be the request that is processed, while this signature is checked over the signed one.
func redirectParameters(rawQuery string) (map[string]string, error) {
	parameters := map[string]string{}
	for _, pair := range strings.Split(rawQuery, "&") {
		rawKey, value, _ := strings.Cut(pair, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			return nil, errors.New("malformed query parameter")
		}
		switch key {
		case "SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature":
			if _, repeated := parameters[key]; repeated {
				return nil, fmt.Errorf("repeated %s parameter", key)
			}
			parameters[key] = value
		}
	}
	return parameters, nil
}

// verifyRedirectSignature verifies the signature of the HTTP-Redirect binding. As SAMLBind §3.4.4.1
// requires, it covers the parameters as they were received rather than a new encoding of their values.
func verifyRedirectSignature(rawQuery, messageParameter string, certificates []*x509.Certificate) error {
	parameters, err := redirectParameters(rawQuery)
	if err != nil {
		return err
	}
	for _, key := range []string{messageParameter, "SigAlg", "Signature"} {
		if _, ok := parameters[key]; !ok {
			return fmt.Errorf("missing %s parameter", key)
		}
	}

	signed := messageParameter + "=" + parameters[messageParameter]
	if relayState, ok := parameters["RelayState"]; ok {
		signed += "&RelayState=" + relayState
	}
	signed += "&SigAlg=" + parameters["SigAlg"]

	algorithm, err := url.QueryUnescape(parameters["SigAlg"])
	if err != nil {
		return errors.New("malformed SigAlg parameter")
	}
	hash, ok := redirectSignatureHashes[algorithm]
	if !ok {
		return errors.New("unsupported signature algorithm")
	}
	encodedSignature, err := url.QueryUnescape(parameters["Signature"])
	if err != nil {
		return errors.New("malformed Signature parameter")
	}
	signature, err := base64.StdEncoding.DecodeString(encodedSignature)
	if err != nil {
		return errors.New("malformed Signature parameter")
	}

	h := hash.New()
	h.Write([]byte(signed))
	digest := h.Sum(nil)

	now := TimeNow()
	if Clock != nil {
		now = Clock.Now()
	}
	for _, certificate := range certificates {
		if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
			continue
		}
		if verifyDigest(certificate, algorithm, hash, digest, signature) {
			return nil
		}
	}
	return errors.New("no currently valid certificate verifies the signature")
}

// verifyDigest returns true if signature is valid for digest, under an algorithm that matches the
// type of the key.
func verifyDigest(certificate *x509.Certificate, algorithm string, hash crypto.Hash, digest, signature []byte) bool {
	switch key := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		switch algorithm {
		case dsig.RSASHA1SignatureMethod, dsig.RSASHA256SignatureMethod, dsig.RSASHA384SignatureMethod, dsig.RSASHA512SignatureMethod:
			return rsa.VerifyPKCS1v15(key, hash, digest, signature) == nil
		}
	case *ecdsa.PublicKey:
		switch algorithm {
		case dsig.ECDSASHA1SignatureMethod, dsig.ECDSASHA256SignatureMethod, dsig.ECDSASHA384SignatureMethod, dsig.ECDSASHA512SignatureMethod:
			// XML Signature §6.4.3 specifies r||s, so any other length is rejected.
			size := (key.Curve.Params().BitSize + 7) / 8
			if len(signature) == 2*size {
				r := new(big.Int).SetBytes(signature[:size])
				s := new(big.Int).SetBytes(signature[size:])
				return ecdsa.Verify(key, digest, r, s)
			}
		}
	}
	return false
}
