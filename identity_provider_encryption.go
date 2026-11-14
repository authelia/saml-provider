package saml

import (
	"crypto"
	"fmt"
	"slices"

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

	content, err := policy.contentEncryption(methods)
	if err != nil {
		return xmlenc.RSA{}, fmt.Errorf("%s: %w", req.ServiceProviderMetadata.EntityID, err)
	}
	encrypter, err := policy.keyTransport(methods)
	if err != nil {
		return xmlenc.RSA{}, fmt.Errorf("%s: %w", req.ServiceProviderMetadata.EntityID, err)
	}
	encrypter.BlockCipher = content
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
	encrypter, _ := policy.keyTransportFor(EncryptionMethod{Algorithm: policy.keyTransports[0]})
	return encrypter, nil
}

// keyTransportFor returns an encrypter for method, if the policy allows its algorithm and parameters. A digest or
// mask generation function the method does not name is the first digest the policy allows. An OAEP label is not
// supported, so a method which names one is not allowed.
func (policy *encryptionPolicy) keyTransportFor(method EncryptionMethod) (xmlenc.RSA, bool) {
	if !slices.Contains(policy.keyTransports, method.Algorithm) || method.OAEPParams != "" {
		return xmlenc.RSA{}, false
	}

	digest := policy.digests[0]
	if method.DigestMethod != nil {
		var ok bool
		if digest, ok = lookupKeyTransportDigest(policy.digests, method.DigestMethod.Algorithm); !ok {
			return xmlenc.RSA{}, false
		}
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
		mgf := policy.digests[0]
		if method.MGF != nil {
			i := slices.IndexFunc(policy.digests, func(d keyTransportDigest) bool { return d.mgf == method.MGF.Algorithm })
			if i < 0 {
				return xmlenc.RSA{}, false
			}
			mgf = policy.digests[i]
		}
		encrypter = xmlenc.OAEP_SHA256()
		encrypter.MGFHash = mgf.hash
	default:
		return xmlenc.RSA{}, false
	}
	encrypter.DigestMethod = digest.method
	return encrypter, true
}
