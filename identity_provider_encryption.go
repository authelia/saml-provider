package saml

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"authelia.com/provider/saml/xmlenc"
)

const (
	algorithmRSAOAEPMGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	algorithmRSAOAEP2009  = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
)

// contentEncryptionCiphers are the block ciphers this identity provider can encrypt an assertion with, in the
// default order of IdentityProvider.ContentEncryptionMethods. AES-128-CBC is first because a service provider
// which lists no algorithm is most likely to support it, as XML Encryption §5.1 requires every implementation to.
var contentEncryptionCiphers = []xmlenc.BlockCipher{
	xmlenc.AES128CBC,
	xmlenc.AES192CBC,
	xmlenc.AES256CBC,
	xmlenc.AES128GCM,
	xmlenc.AES192GCM,
	xmlenc.AES256GCM,
}

// keyTransportAlgorithms are the key transport algorithms this identity provider can encrypt the key of an
// assertion with, in the default order of IdentityProvider.KeyTransportMethods. RSA-OAEP-MGF1P is first for the
// same reason as AES-128-CBC.
var keyTransportAlgorithms = []string{
	algorithmRSAOAEPMGF1P,
	algorithmRSAOAEP2009,
}

// keyTransportDigest is a digest this identity provider can use for RSA-OAEP, with the MGF1 mask generation
// function of the same hash (XML Encryption 1.1 §5.5.2).
type keyTransportDigest struct {
	method xmlenc.DigestMethod
	hash   crypto.Hash
	mgf    string
}

// keyTransportDigests are the digests this identity provider can use for RSA-OAEP, in the default order of
// IdentityProvider.KeyTransportDigestMethods. SHA-1 is first because it is the default of XML Encryption §5.4.2,
// and so the digest a service provider which names none is certain to support.
var keyTransportDigests = []keyTransportDigest{
	{xmlenc.SHA1, crypto.SHA1, "http://www.w3.org/2009/xmlenc11#mgf1sha1"},
	{xmlenc.SHA256, crypto.SHA256, "http://www.w3.org/2009/xmlenc11#mgf1sha256"},
	{xmlenc.SHA512, crypto.SHA512, "http://www.w3.org/2009/xmlenc11#mgf1sha512"},
}

// legacyDigestIdentifiers are the identifiers which some implementations write for a digest in place of its
// standard one, which are accepted but never written.
var legacyDigestIdentifiers = map[string]string{
	xmlenc.LegacySHA256.Algorithm(): xmlenc.SHA256.Algorithm(),
	xmlenc.LegacySHA512.Algorithm(): xmlenc.SHA512.Algorithm(),
}

// contentEncryptionIdentifiers are the identifiers of the block encryption algorithms of XML Encryption §5.2,
// XML Encryption 1.1 §5.2 and RFC 6931, including those this identity provider can't use. They tell which
// algorithms a service provider lists are content encryption algorithms, as the Metadata Profile for Algorithm
// Support §2.5 has a metadata consumer choose from the algorithms of each type separately.
var contentEncryptionIdentifiers = []string{
	"http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
	"http://www.w3.org/2001/04/xmlenc#aes128-cbc",
	"http://www.w3.org/2001/04/xmlenc#aes192-cbc",
	"http://www.w3.org/2001/04/xmlenc#aes256-cbc",
	"http://www.w3.org/2009/xmlenc11#aes128-gcm",
	"http://www.w3.org/2009/xmlenc11#aes192-gcm",
	"http://www.w3.org/2009/xmlenc11#aes256-gcm",
	"http://www.w3.org/2001/04/xmldsig-more#camellia128-cbc",
	"http://www.w3.org/2001/04/xmldsig-more#camellia192-cbc",
	"http://www.w3.org/2001/04/xmldsig-more#camellia256-cbc",
	"http://www.w3.org/2007/05/xmldsig-more#seed128-cbc",
}

// keyTransportIdentifiers are the identifiers of the key transport and key agreement algorithms of XML
// Encryption §5.4 and §5.5 and XML Encryption 1.1 §5.5 and §5.6, which the Metadata Profile for Algorithm Support
// §2.3 treats as one type, including those this identity provider can't use.
var keyTransportIdentifiers = []string{
	"http://www.w3.org/2001/04/xmlenc#rsa-1_5",
	algorithmRSAOAEPMGF1P,
	algorithmRSAOAEP2009,
	"http://www.w3.org/2001/04/xmlenc#dh",
	"http://www.w3.org/2009/xmlenc11#dh-es",
	"http://www.w3.org/2009/xmlenc11#ECDH-ES",
}

// encryptionPolicy is what the IdentityProvider allows assertions to be encrypted with, in its order of preference.
type encryptionPolicy struct {
	content       []xmlenc.BlockCipher
	keyTransports []string
	digests       []keyTransportDigest
}

// encryptionPolicy returns the algorithms the identity provider allows, or an error if it is configured with an
// algorithm it does not support.
func (idp *IdentityProvider) encryptionPolicy() (*encryptionPolicy, error) {
	policy := &encryptionPolicy{
		content:       contentEncryptionCiphers,
		keyTransports: keyTransportAlgorithms,
		digests:       keyTransportDigests,
	}
	if idp == nil {
		return policy, nil
	}

	if len(idp.ContentEncryptionMethods) != 0 {
		policy.content = nil

		for _, algorithm := range idp.ContentEncryptionMethods {
			i := slices.IndexFunc(contentEncryptionCiphers, func(c xmlenc.BlockCipher) bool { return c.Algorithm() == algorithm })
			if i < 0 {
				return nil, fmt.Errorf("IdentityProvider.ContentEncryptionMethods: unsupported algorithm %q", algorithm)
			}

			policy.content = append(policy.content, contentEncryptionCiphers[i])
		}
	}

	if len(idp.KeyTransportMethods) != 0 {
		policy.keyTransports = nil

		for _, algorithm := range idp.KeyTransportMethods {
			if !slices.Contains(keyTransportAlgorithms, algorithm) {
				return nil, fmt.Errorf("IdentityProvider.KeyTransportMethods: unsupported algorithm %q", algorithm)
			}

			policy.keyTransports = append(policy.keyTransports, algorithm)
		}
	}

	if len(idp.KeyTransportDigestMethods) != 0 {
		policy.digests = nil

		for _, algorithm := range idp.KeyTransportDigestMethods {
			digest, ok := lookupKeyTransportDigest(keyTransportDigests, algorithm)
			if !ok {
				return nil, fmt.Errorf("IdentityProvider.KeyTransportDigestMethods: unsupported algorithm %q", algorithm)
			}

			policy.digests = append(policy.digests, digest)
		}
	}

	return policy, nil
}

// lookupKeyTransportDigest returns the digest of digests with the identifier algorithm, which may be legacy.
func lookupKeyTransportDigest(digests []keyTransportDigest, algorithm string) (keyTransportDigest, bool) {
	if standard, ok := legacyDigestIdentifiers[algorithm]; ok {
		algorithm = standard
	}

	for _, digest := range digests {
		if digest.method.Algorithm() == algorithm {
			return digest, true
		}
	}

	return keyTransportDigest{}, false
}

// assertionEncrypter returns the encrypter for an assertion to the service provider, with the algorithms
// negotiated from the EncryptionMethods of its encryption key.
//
// The Metadata Profile for Algorithm Support §2.5 requires a metadata consumer to use the intersection of the
// algorithms and parameters it and its peer support, and to select the first the peer lists that it supports,
// for each type of algorithm. If the service provider lists algorithms of a type and none of them can be used,
// this fails rather than choose one the service provider might not support, or send the assertion unencrypted.
// If it lists none of a type, §2.5 leaves the choice to the identity provider, which uses the first one it allows.
func (req *IdpAuthnRequest) assertionEncrypter() (xmlenc.RSA, error) {
	policy, err := req.IDP.encryptionPolicy()
	if err != nil {
		return xmlenc.RSA{}, err
	}

	var methods []EncryptionMethod
	if keyDescriptor := req.spEncryptionKeyDescriptor(); keyDescriptor != nil {
		methods = keyDescriptor.EncryptionMethods
	}

	encrypter, err := policy.encrypter(methods)
	if err != nil {
		return xmlenc.RSA{}, fmt.Errorf("%s: %w", req.ServiceProviderMetadata.EntityID, err)
	}

	return encrypter, nil
}

// contentEncryption returns the first block cipher of methods that the policy allows, or the first the policy
// allows if methods lists none.
func (policy *encryptionPolicy) contentEncryption(methods []EncryptionMethod) (xmlenc.BlockCipher, error) {
	listed := false

	for _, method := range methods {
		if !slices.Contains(contentEncryptionIdentifiers, method.Algorithm) {
			continue
		}

		listed = true

		for _, cipher := range policy.content {
			// The key size of these ciphers is fixed by the algorithm, so one that lists another can't be met.
			if cipher.Algorithm() == method.Algorithm && (method.KeySize == 0 || method.KeySize == cipher.KeySize()*8) {
				return cipher, nil
			}
		}
	}

	if listed {
		return nil, fmt.Errorf("the encryption key lists no content encryption algorithm the identity provider allows")
	}

	return policy.content[0], nil
}

// keyTransport returns an encrypter for the first key transport algorithm of methods that the policy allows
// with its parameters, or for the first the policy allows if methods lists none.
func (policy *encryptionPolicy) keyTransport(methods []EncryptionMethod) (xmlenc.RSA, error) {
	listed := false

	for _, method := range methods {
		if !slices.Contains(keyTransportIdentifiers, method.Algorithm) {
			continue
		}

		listed = true

		if encrypter, ok := policy.keyTransportFor(method); ok {
			return encrypter, nil
		}
	}

	if listed {
		return xmlenc.RSA{}, fmt.Errorf("the encryption key lists no key transport algorithm the identity provider allows with the parameters it gives")
	}

	return policy.defaultKeyTransport(), nil
}

// defaultKeyTransport returns an encrypter for the first key transport algorithm the policy allows, with its first
// digest as the digest and, for XML Encryption 1.1 RSA-OAEP, the hash of the mask generation function.
func (policy *encryptionPolicy) defaultKeyTransport() xmlenc.RSA {
	var encrypter xmlenc.RSA
	if policy.keyTransports[0] == algorithmRSAOAEP2009 {
		encrypter = xmlenc.OAEP_SHA256()
		encrypter.MGFHash = policy.digests[0].hash
	} else {
		encrypter = xmlenc.OAEP()
	}

	encrypter.DigestMethod = policy.digests[0].method

	return encrypter
}

// keyTransportFor returns an encrypter for method, if the policy allows its algorithm and parameters. A digest or
// mask generation function the method does not name is the default of its algorithm, SHA-1 and MGF1 with SHA-1
// (XML Encryption §5.4.2 and XML Encryption 1.1 §5.5.2), as that may be all the service provider supports, so
// the method is not allowed if the policy excludes SHA-1. An OAEP label is not supported, so a method which names
// one is not allowed.
func (policy *encryptionPolicy) keyTransportFor(method EncryptionMethod) (xmlenc.RSA, bool) {
	if !slices.Contains(policy.keyTransports, method.Algorithm) || method.OAEPParams != "" {
		return xmlenc.RSA{}, false
	}

	digestAlgorithm := keyTransportDigests[0].method.Algorithm()
	if method.DigestMethod != nil {
		digestAlgorithm = method.DigestMethod.Algorithm
	}

	digest, ok := lookupKeyTransportDigest(policy.digests, digestAlgorithm)
	if !ok {
		return xmlenc.RSA{}, false
	}

	var encrypter xmlenc.RSA

	switch method.Algorithm {
	case algorithmRSAOAEPMGF1P:
		// XML Encryption §5.4.2 fixes the mask generation function to MGF1 with SHA-1.
		if method.MGF != nil && method.MGF.Algorithm != keyTransportDigests[0].mgf {
			return xmlenc.RSA{}, false
		}

		encrypter = xmlenc.OAEP()
	case algorithmRSAOAEP2009:
		mgfAlgorithm := keyTransportDigests[0].mgf
		if method.MGF != nil {
			mgfAlgorithm = method.MGF.Algorithm
		}

		i := slices.IndexFunc(policy.digests, func(d keyTransportDigest) bool { return d.mgf == mgfAlgorithm })
		if i < 0 {
			return xmlenc.RSA{}, false
		}

		encrypter = xmlenc.OAEP_SHA256()
		encrypter.MGFHash = policy.digests[i].hash
	default:
		return xmlenc.RSA{}, false
	}

	encrypter.DigestMethod = digest.method

	return encrypter, true
}

// DecryptionKey is a key pair that the identity provider decrypts with: an RSA key of at least 2048 bits, and
// the certificate that a service provider encrypted to. See IdentityProvider.DecryptionKeys.
type DecryptionKey struct {
	// Certificate is the certificate of Key. Nothing but its key and, if it has the extension, its key usage is
	// looked at, so it may have expired.
	Certificate *x509.Certificate

	// Key is the private key, which is an *rsa.PrivateKey or a key held elsewhere, such as in a hardware security
	// module. See IdentityProvider.EncryptionKey.
	Key crypto.Decrypter
}

// decryptionKey is a key pair that an entity decrypts with.
type decryptionKey struct {
	// certificate is the certificate of key, which the KeyInfo of an EncryptedKey is compared with. It is nil
	// when the entity has none for the key.
	certificate *x509.Certificate

	key crypto.Decrypter
}

const (
	// minimumEncryptionKeySize is the size in bits of the smallest RSA key that the identity provider publishes
	// or accepts as its own for encryption (SAML V2.0 Deployment Profile for Federation Interoperability
	// SDP-MD06).
	minimumEncryptionKeySize = 2048

	// maxDecryptionKeys is the most IdentityProvider.DecryptionKeys there can be. Each of them may cost a private
	// key operation for each EncryptedKey of a request, of which maxEncryptedKeys are tried.
	maxDecryptionKeys = 4
)

// CheckEncryptionKeys returns an error unless EncryptionCertificate, EncryptionKey and DecryptionKeys are valid:
// each certificate has its private key and the other way round, the key is an RSA key of at least 2048 bits, the
// private key is that of the certificate, and the certificate allows key encipherment if it has a key usage
// extension. The validity period of a certificate is not checked. There are no more than four DecryptionKeys.
//
// An identity provider with keys that are not valid publishes no encryption key, serves no metadata and decrypts
// nothing, so an application should call this when it is configured.
func (idp *IdentityProvider) CheckEncryptionKeys() error {
	_, _, err := idp.encryptionKeys()

	return err
}

// encryptionKeys returns the key that the metadata of the identity provider publishes for encryption, which is
// nil if it has none, and every key that it decrypts with, the published one first.
//
// The published key is EncryptionCertificate and EncryptionKey, or else Certificate and Key when Key is an RSA
// private key that the certificate does not rule out for key encipherment. A Signer can't decrypt.
func (idp *IdentityProvider) encryptionKeys() (published *decryptionKey, keys []decryptionKey, err error) {
	switch hasCertificate, hasKey := idp.EncryptionCertificate != nil, !isNilDecrypter(idp.EncryptionKey); {
	case hasCertificate != hasKey:
		return nil, nil, errors.New("IdentityProvider.EncryptionCertificate and EncryptionKey must be set together")
	case hasCertificate:
		if err = checkEncryptionKeyPair(idp.EncryptionCertificate, idp.EncryptionKey, "EncryptionCertificate", "EncryptionKey"); err != nil {
			return nil, nil, err
		}

		keys = append(keys, decryptionKey{certificate: idp.EncryptionCertificate, key: idp.EncryptionKey})
	default:
		if key, ok := idp.signingKeyForDecryption(); ok {
			keys = append(keys, key)
		}
	}

	hasPublished := len(keys) != 0

	if len(idp.DecryptionKeys) > maxDecryptionKeys {
		// The keys that repeat count too, so that the limit doesn't depend on what the keys are.
		return nil, nil, fmt.Errorf("IdentityProvider.DecryptionKeys: more than %d keys", maxDecryptionKeys)
	}

	for i, pair := range idp.DecryptionKeys {
		field := fmt.Sprintf("DecryptionKeys[%d]", i)

		if pair.Certificate == nil || isNilDecrypter(pair.Key) {
			return nil, nil, fmt.Errorf("IdentityProvider.%s: the certificate and the key must both be set", field)
		}

		if err = checkEncryptionKeyPair(pair.Certificate, pair.Key, field, field); err != nil {
			return nil, nil, err
		}

		// A key may be listed while it is also the published one, so that the two can be changed in any order.
		if slices.ContainsFunc(keys, func(k decryptionKey) bool { return k.certificate.Equal(pair.Certificate) }) {
			continue
		}

		keys = append(keys, decryptionKey{certificate: pair.Certificate, key: pair.Key})
	}

	if hasPublished {
		published = &keys[0]
	}

	return published, keys, nil
}

// signingKeyForDecryption returns Certificate and Key as a key to decrypt with, which they are when Key is an
// RSA private key and Certificate, which holds its public key, either has no key usage extension or allows key
// encipherment with it. It is not checked further, as it is not when it signs.
func (idp *IdentityProvider) signingKeyForDecryption() (decryptionKey, bool) {
	if idp.Certificate == nil {
		return decryptionKey{}, false
	}

	if _, ok := idp.Certificate.PublicKey.(*rsa.PublicKey); !ok {
		return decryptionKey{}, false
	}

	if !allowsKeyEncipherment(idp.Certificate) {
		return decryptionKey{}, false
	}

	// A nil *rsa.PrivateKey in the interface would not be recognised as no key.
	key, _ := idp.Key.(*rsa.PrivateKey)
	if key == nil {
		return decryptionKey{}, false
	}

	return decryptionKey{certificate: idp.Certificate, key: key}, true
}

// isNilDecrypter returns whether key is nil, or a nil *[rsa.PrivateKey], which is not nil as an interface.
func isNilDecrypter(key crypto.Decrypter) bool {
	if key == nil {
		return true
	}

	rsaKey, ok := key.(*rsa.PrivateKey)

	return ok && rsaKey == nil
}

// allowsKeyEncipherment returns whether cert may be used to encrypt keys to: it has no key usage extension, or
// one with keyEncipherment, the usage of RSA key transport (RFC 5280 §4.2.1.3).
func allowsKeyEncipherment(cert *x509.Certificate) bool {
	return cert.KeyUsage == 0 || cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0
}

// checkEncryptionKeyPair returns an error unless cert and key are a key pair that the identity provider can be
// encrypted to. The errors name the field of the IdentityProvider that the certificate or the key is in.
func checkEncryptionKeyPair(cert *x509.Certificate, key crypto.Decrypter, certificateField, keyField string) error {
	public, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("IdentityProvider.%s: the certificate does not have an RSA key", certificateField)
	}

	if bits := public.N.BitLen(); bits < minimumEncryptionKeySize {
		return fmt.Errorf("IdentityProvider.%s: the RSA key has %d bits, which is fewer than %d", certificateField, bits, minimumEncryptionKeySize)
	}

	if !allowsKeyEncipherment(cert) {
		return fmt.Errorf("IdentityProvider.%s: the key usage of the certificate does not include key encipherment", certificateField)
	}

	if private, ok := key.Public().(*rsa.PublicKey); !ok || !private.Equal(public) {
		return fmt.Errorf("IdentityProvider.%s: the private key is not that of the certificate", keyField)
	}

	return nil
}

// encryptionKeyDescriptor returns the KeyDescriptor which publishes the encryption key of the identity provider,
// with the algorithms it accepts, if it has a key and its keys and algorithms are valid. Each key must be in its
// own KeyDescriptor with a single certificate (Metadata Interoperability Profile §2.5.1), and a consumer may
// encrypt to any encryption key it finds (§2.6.1), so only the one key is published, and never one of
// DecryptionKeys.
func (idp *IdentityProvider) encryptionKeyDescriptor() (KeyDescriptor, bool) {
	published, _, err := idp.encryptionKeys()
	if err != nil || published == nil {
		return KeyDescriptor{}, false
	}

	methods := idp.encryptionMethods()
	if methods == nil {
		return KeyDescriptor{}, false
	}

	return KeyDescriptor{
		Use: "encryption",
		KeyInfo: KeyInfo{
			X509Data: X509Data{
				X509Certificates: []X509Certificate{
					{Data: base64.StdEncoding.EncodeToString(published.certificate.Raw)},
				},
			},
		},
		EncryptionMethods: methods,
	}, true
}

// encryptionMethods returns the EncryptionMethods of the encryption key in the metadata of the identity provider
// (SAMLMeta §2.4.1.1), which are the algorithms it accepts an EncryptedID to be encrypted with, or nil if it has
// no key to decrypt with or its algorithms are misconfigured. A peer that follows the Metadata Profile for
// Algorithm Support §2.5 uses the first of each type that it supports, so the block ciphers in GCM mode, which
// protect the integrity of what they encrypt, come before those in CBC mode, which don't (errata E93). A key
// transport algorithm states its digest and mask generation function only when the default of SHA-1 isn't
// accepted.
func (idp *IdentityProvider) encryptionMethods() []EncryptionMethod {
	if published, _, err := idp.encryptionKeys(); err != nil || published == nil {
		return nil
	}

	policy, err := idp.encryptionPolicy()
	if err != nil {
		return nil
	}

	var gcm, cbc []EncryptionMethod

	for _, cipher := range policy.content {
		method := EncryptionMethod{Algorithm: cipher.Algorithm()}
		if strings.HasSuffix(method.Algorithm, "-gcm") {
			gcm = append(gcm, method)
		} else {
			cbc = append(cbc, method)
		}
	}

	methods := slices.Concat(gcm, cbc)

	_, sha1 := lookupKeyTransportDigest(policy.digests, keyTransportDigests[0].method.Algorithm())

	for _, algorithm := range policy.keyTransports {
		method := EncryptionMethod{Algorithm: algorithm}

		if !sha1 {
			method.DigestMethod = &DigestMethod{Algorithm: policy.digests[0].method.Algorithm()}

			if algorithm == algorithmRSAOAEP2009 {
				method.MGF = &MGF{Algorithm: policy.digests[0].mgf}
			}
		}

		methods = append(methods, method)
	}

	return methods
}

// elementDecrypter returns the decrypter of the elements which are encrypted to the identity provider, with the
// key that its metadata publishes and then its DecryptionKeys. It only accepts the algorithms that the identity
// provider allows. If the keys are not valid it decrypts with none of them.
func (idp *IdentityProvider) elementDecrypter() (elementDecrypter, error) {
	policy, err := idp.encryptionPolicy()
	if err != nil {
		return elementDecrypter{}, err
	}

	_, keys, err := idp.encryptionKeys()
	if err != nil {
		return elementDecrypter{}, err
	}

	return elementDecrypter{keys: keys, recipient: idp.entityID(), policy: policy}, nil
}

// serviceProviderElementEncrypter returns the encrypter of elements to a service provider outside an
// AuthnRequest, such as of the NameID of a LogoutRequest: to the encryption key of the first of its
// SPSSODescriptors that has one, which the EncryptionCertificateEnforcer accepts as for an assertion. The enforcer
// is given a request of the identity provider's own making, to its logout URL, as the HTTP request in which a
// logout continues is not one from the service provider that is encrypted to.
func (idp *IdentityProvider) serviceProviderElementEncrypter(metadata *EntityDescriptor) (*elementEncrypter, error) {
	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, idp.LogoutURL.String(), nil)
	if err != nil {
		return nil, err
	}

	for i := range metadata.SPSSODescriptors {
		req := &IdpAuthnRequest{
			IDP:                     idp,
			HTTPRequest:             r,
			ServiceProviderMetadata: metadata,
			SPSSODescriptor:         &metadata.SPSSODescriptors[i],
			Now:                     TimeNow(),
		}

		if req.spEncryptionKeyDescriptor() == nil {
			continue
		}

		return req.elementEncrypter()
	}

	return nil, fmt.Errorf("the service provider %q has no encryption key", metadata.EntityID)
}
