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
	"slices"
	"strings"
	"time"

	"github.com/beevik/etree"

	"authelia.com/provider/saml/internal/dsig"
)

// redirectSignatureHashes lists the signature algorithms that can be verified on the HTTP-Redirect binding, which
// are those that can be verified in an XML signature.
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

// defaultSignatureMethods are the signature algorithms the identity provider accepts on what it receives when
// IdentityProvider.SignatureMethods is empty: all that it can verify but those of SHA-1.
var defaultSignatureMethods = []string{
	dsig.RSASHA256SignatureMethod,
	dsig.RSASHA384SignatureMethod,
	dsig.RSASHA512SignatureMethod,
	dsig.ECDSASHA256SignatureMethod,
	dsig.ECDSASHA384SignatureMethod,
	dsig.ECDSASHA512SignatureMethod,
}

// defaultDigestMethods are the digest algorithms the identity provider accepts in the signature of what it
// receives when IdentityProvider.DigestMethods is empty: all that it can verify but SHA-1.
var defaultDigestMethods = []string{
	dsig.SHA256DigestMethod,
	dsig.SHA384DigestMethod,
	dsig.SHA512DigestMethod,
}

// sha1SignatureMethods and sha1DigestMethods can be verified, and are only accepted when they are listed.
var (
	sha1SignatureMethods = []string{dsig.RSASHA1SignatureMethod, dsig.ECDSASHA1SignatureMethod}
	sha1DigestMethods    = []string{dsig.SHA1DigestMethod}
)

// signaturePolicy is the algorithms that a signature is accepted with.
type signaturePolicy struct {
	signatureMethods []string
	digestMethods    []string
}

// supportedSignatureMethods and supportedDigestMethods are every algorithm that can be verified, which a list
// that is configured may name.
var (
	supportedSignatureMethods = slices.Concat(defaultSignatureMethods, sha1SignatureMethods)
	supportedDigestMethods    = slices.Concat(defaultDigestMethods, sha1DigestMethods)
)

// anySignaturePolicy accepts every algorithm that can be verified. It is the policy of the ServiceProvider,
// which has no setting for it. Its digest methods are left nil so that the digest of every Reference isn't
// checked, and the service provider accepts what it did before there were policies.
var anySignaturePolicy = &signaturePolicy{
	signatureMethods: supportedSignatureMethods,
}

// newSignaturePolicy returns the policy of the lists of signature and digest methods, which are the fields of the
// type named owner. An empty list means the default, and an algorithm that can't be verified is an error.
func newSignaturePolicy(owner string, signatureMethods, digestMethods []string) (*signaturePolicy, error) {
	policy := &signaturePolicy{signatureMethods: defaultSignatureMethods, digestMethods: defaultDigestMethods}

	if len(signatureMethods) != 0 {
		for _, algorithm := range signatureMethods {
			if !slices.Contains(supportedSignatureMethods, algorithm) {
				return nil, fmt.Errorf("%s.SignatureMethods: unsupported algorithm %q", owner, algorithm)
			}
		}

		policy.signatureMethods = signatureMethods
	}

	if len(digestMethods) != 0 {
		for _, algorithm := range digestMethods {
			if !slices.Contains(supportedDigestMethods, algorithm) {
				return nil, fmt.Errorf("%s.DigestMethods: unsupported algorithm %q", owner, algorithm)
			}
		}

		policy.digestMethods = digestMethods
	}

	return policy, nil
}

// signaturePolicy returns the algorithms the identity provider accepts a signature with, or an error if it is
// configured with an algorithm it can't verify.
func (idp *IdentityProvider) signaturePolicy() (*signaturePolicy, error) {
	return newSignaturePolicy("IdentityProvider", idp.SignatureMethods, idp.DigestMethods)
}

// verifyAuthnRequestSignature verifies any signature on the request, and returns an error if there is
// none and one is required. ServiceProviderMetadata must be set. An error that is not a StatusError is
// ErrInvalidSignature to the caller.
//
// It sets requestEl to the element of the request, which is the content that the signature covers if there is one.
// An enveloped signature covers the element that it verifies (HTTP-POST, and the SOAP binding of the Enhanced
// Client or Proxy profile, whose message is taken out of its envelope first). The signature of the HTTP-Redirect
// binding is over the SAMLRequest parameter as it was received (SAMLBind §3.4.4.1), so it covers every byte that
// RequestBuffer was inflated from, and the whole of the document.
//
//nolint:gocyclo // Complexity is inherent to the specification being implemented.
func (req *IdpAuthnRequest) verifyAuthnRequestSignature() error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(req.RequestBuffer); err != nil {
		return err
	}

	if doc.Root() == nil {
		return errors.New("request has no root element")
	}

	req.requestEl = doc.Root()

	signatureEl, err := findChild(doc.Root(), "http://www.w3.org/2000/09/xmldsig#", "Signature")
	if err != nil {
		return err
	}

	if req.RedirectQuery == "" && signatureEl == nil {
		if req.IDP.WantAuthnRequestsSigned || req.serviceProviderSignsAuthnRequests() {
			return ErrSignatureRequired.WithDebug("request is not signed")
		}

		return nil
	}

	keys, err := req.serviceProviderSigningKeys()
	if err != nil {
		return ErrServerError.WithDebugError(err)
	}

	if len(keys) == 0 {
		return errors.New("request is signed but the service provider has no signing key")
	}

	// A list that can't be used is a fault of the identity provider, and not of the requester.
	policy, err := req.IDP.signaturePolicy()
	if err != nil {
		return ErrServerError.WithDebugError(err)
	}

	if req.RedirectQuery != "" {
		if err := verifyRedirectSignature(req.RedirectQuery, "SAMLRequest", keys, policy); err != nil {
			return fmt.Errorf("invalid request signature: %w", err)
		}
	}

	if signatureEl != nil {
		verified, err := verifyEnvelopedSignature(doc.Root(), keys, policy)
		if err != nil {
			return fmt.Errorf("invalid request signature: %w", err)
		}

		if err := req.useVerifiedRequest(verified); err != nil {
			return err
		}

		req.requestEl = verified
	}

	// SAMLBind §3.4.5.2 and §3.5.5.2 require this of a signed message on the browser bindings. The value is
	// checked against the SSO URL later, by checkRequestStage. The SOAP binding has no such rule, and a request of
	// the Enhanced Client or Proxy profile is signed before its destination is known (see checkRequestStage).
	if req.Request.Destination == "" && req.binding != SOAPBinding {
		return errors.New("signed request has no destination")
	}

	req.requestAuthenticated = true

	return nil
}

// useVerifiedRequest replaces Request with the content that the signature covers, and repeats the
// trust checks that were made on the original.
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

	if err := req.checkTrust(); err != nil {
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

// signatureVerificationKey is a key that a signature is verified with.
type signatureVerificationKey struct {
	// certificate is the certificate that the key was given in, or nil for a key that was given only as a
	// ds:KeyValue. There is then no validity period to check, and no certificate that the KeyInfo of a signature
	// could be matched with.
	certificate *x509.Certificate

	// publicKey is the key: that of certificate, or else of the ds:RSAKeyValue. It is never nil.
	publicKey crypto.PublicKey
}

// validAt returns true if now is within the validity period of the certificate of the key. A key that was given
// as a ds:KeyValue has no certificate, and so no validity period.
func (k signatureVerificationKey) validAt(now time.Time) bool {
	return k.certificate == nil || (!now.Before(k.certificate.NotBefore) && !now.After(k.certificate.NotAfter))
}

// certificateVerificationKeys returns the keys of the certificates, for those who only trust certificates.
func certificateVerificationKeys(certificates []*x509.Certificate) []signatureVerificationKey {
	keys := make([]signatureVerificationKey, 0, len(certificates))

	for _, certificate := range certificates {
		keys = append(keys, signatureVerificationKey{certificate: certificate, publicKey: certificate.PublicKey})
	}

	return keys
}

// serviceProviderSigningKeys returns the keys that the service provider may sign with.
func (req *IdpAuthnRequest) serviceProviderSigningKeys() ([]signatureVerificationKey, error) {
	return serviceProviderSigningKeys(req.ServiceProviderMetadata)
}

// serviceProviderSigningKeys returns the keys that a service provider may sign with, according to its metadata:
// those of every KeyDescriptor of its SPSSODescriptors whose use is signing, or which has no use and so is for
// both signing and encryption (SAMLMeta §2.4.1.1).
//
// MetaIOP §2.6.1 requires the two representations of a key that are read to be supported, and they are read as
// they are for an encryption key (see keyDescriptorEncryptionKey): the X509Certificates of the descriptor, and if
// none of them holds a certificate the first ds:KeyValue with an RSAKeyValue. When there are both they must
// represent the same key (MetaIOP §2.5.1), and the certificate is the one used. A KeyValue which holds anything
// but an RSAKeyValue, such as a DSAKeyValue or an ECKeyValue, gives no key that can be used and is passed over, as
// is a descriptor which only names its key with a KeyName.
//
// A certificate or an RSAKeyValue which is present and can't be parsed is an error instead, as the metadata is
// then broken rather than merely of no use. A ds:KeyValue has no validity period and no key usage that could be
// checked, and the size of its key is not checked either, as that of a certificate is not.
func serviceProviderSigningKeys(metadata *EntityDescriptor) ([]signatureVerificationKey, error) {
	var keys []signatureVerificationKey

	for _, descriptor := range metadata.SPSSODescriptors {
		for _, keyDescriptor := range descriptor.KeyDescriptors {
			if keyDescriptor.Use != "signing" && keyDescriptor.Use != "" {
				continue
			}

			certificates, err := keyDescriptorSigningCertificates(&keyDescriptor)
			if err != nil {
				return nil, err
			}

			if len(certificates) != 0 {
				keys = append(keys, certificateVerificationKeys(certificates)...)

				continue
			}

			public, err := keyDescriptorSigningKeyValue(&keyDescriptor)
			if err != nil {
				return nil, err
			}

			if public != nil {
				keys = append(keys, signatureVerificationKey{publicKey: public})
			}
		}
	}

	return keys, nil
}

// keyDescriptorSigningCertificates returns the certificates of keyDescriptor that the service provider may sign
// with. An X509Certificate that is empty holds none.
func keyDescriptorSigningCertificates(keyDescriptor *KeyDescriptor) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate

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

	return certificates, nil
}

// keyDescriptorSigningKeyValue returns the key of the first ds:KeyValue of keyDescriptor which holds an
// RSAKeyValue, or nil if there is none.
func keyDescriptorSigningKeyValue(keyDescriptor *KeyDescriptor) (*rsa.PublicKey, error) {
	for _, keyValue := range keyDescriptor.KeyInfo.KeyValues {
		if keyValue.RSAKeyValue == nil {
			continue
		}

		public, err := keyValue.RSAKeyValue.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("cannot parse service provider key value: %w", err)
		}

		return public, nil
	}

	return nil, nil
}

var whitespaceRemover = strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "")

// verifyEnvelopedSignature verifies the signature on el with any of the keys, and returns the content that it
// covers. They are tried in turn because a signature with no KeyInfo can only be checked against a single
// certificate. A signature made with a signature method that the policy doesn't list, or with a Reference whose
// digest method it doesn't list, is refused as one that doesn't verify is.
//
// A key that has a certificate verifies a signature whose KeyInfo holds that certificate or has no certificate,
// while the certificate is valid. A key that has none, which was given as a ds:KeyValue, verifies a signature
// whatever its KeyInfo holds: MetaIOP §2.6.1 has the key be what is trusted, and a certificate that the signer put
// in its signature says nothing that the metadata didn't.
func verifyEnvelopedSignature(el *etree.Element, keys []signatureVerificationKey, policy *signaturePolicy) (*etree.Element, error) {
	var err error

	for _, key := range keys {
		var certificates []*x509.Certificate
		if key.certificate != nil {
			certificates = []*x509.Certificate{key.certificate}
		}

		validationContext, detached, contextErr := signatureValidationContext(el, certificates, policy)
		if contextErr != nil {
			return nil, contextErr
		}

		var verified *etree.Element

		if key.certificate != nil {
			verified, err = validationContext.Validate(detached)
		} else {
			verified, err = validationContext.ValidateWithKey(detached, key.publicKey)
		}

		if err == nil {
			return verified, nil
		}
	}

	return nil, err
}

// redirectParameters returns the undecoded values of the parameters which take part in a signature.
//
// The keys are decoded to match, and a repeat is an error, because [url.Values] also decodes the keys
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
// requires, it covers the parameters as they were received rather than a new encoding of their values. A SigAlg
// that the policy doesn't list is refused as a signature that doesn't verify is. The digest methods of the policy
// have no part in it, as the signature is over the query itself and there is no Reference.
func verifyRedirectSignature(rawQuery, messageParameter string, keys []signatureVerificationKey, policy *signaturePolicy) error {
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

	if !slices.Contains(policy.signatureMethods, algorithm) {
		return fmt.Errorf("signature method %s is not allowed", algorithm)
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

	for _, key := range keys {
		if !key.validAt(now) {
			continue
		}

		if verifyDigest(key.publicKey, algorithm, hash, digest, signature) {
			return nil
		}
	}

	return errors.New("no currently valid key verifies the signature")
}

// verifyDigest returns true if signature is valid for digest, under an algorithm that matches the
// type of the key.
func verifyDigest(public crypto.PublicKey, algorithm string, hash crypto.Hash, digest, signature []byte) bool {
	switch key := public.(type) {
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
