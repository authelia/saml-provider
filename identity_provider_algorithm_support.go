package saml

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"authelia.com/provider/saml/internal/dsig"
)

// describeAlgorithmSupport lists the signature and digest algorithms that the identity provider accepts on what
// it receives in the Extensions of the entity, as alg:SigningMethod and alg:DigestMethod, in the order of
// SignatureMethods and DigestMethods, which is its order of preference.
//
// They are on the entity and not on a role because the two lists are held to for every signature that is
// verified, whichever role the message is for, and what an entity lists applies to each role that lists nothing
// (Metadata Profile for Algorithm Support §2.5). No key size is stated, as the key of a service provider is not
// held to one. Nothing is listed that would be refused (SAML2Int SDP-MD04), so nothing at all is when the lists
// can't be used, as every signed message is then refused.
func (idp *IdentityProvider) describeAlgorithmSupport(ed *EntityDescriptor) {
	policy, err := idp.signaturePolicy()
	if err != nil {
		return
	}

	extensions := ed.extensions()

	extensions.DigestMethods = make([]DigestMethod, 0, len(policy.digestMethods))
	for _, algorithm := range policy.digestMethods {
		extensions.DigestMethods = append(extensions.DigestMethods, DigestMethod{Algorithm: algorithm})
	}

	extensions.SigningMethods = make([]SigningMethod, 0, len(policy.signatureMethods))
	for _, algorithm := range policy.signatureMethods {
		extensions.SigningMethods = append(extensions.SigningMethods, SigningMethod{Algorithm: algorithm})
	}
}

// The signature methods that are negotiated with a service provider, for each type of key, and the digests. Those
// of SHA-1 are not among them: the Metadata Profile for Algorithm Support §2.6 warns that metadata can be used to
// step down to a weaker algorithm than the parties support, so a service provider is only signed for with SHA-1
// when the operator chose it, as the SignatureMethod of the identity provider or in an IssuancePolicy.
var (
	negotiatedRSASignatureMethods = []string{
		dsig.RSASHA256SignatureMethod,
		dsig.RSASHA384SignatureMethod,
		dsig.RSASHA512SignatureMethod,
	}
	negotiatedECDSASignatureMethods = []string{
		dsig.ECDSASHA256SignatureMethod,
		dsig.ECDSASHA384SignatureMethod,
		dsig.ECDSASHA512SignatureMethod,
	}
	negotiatedDigestMethods = []string{
		dsig.SHA256DigestMethod,
		dsig.SHA384DigestMethod,
		dsig.SHA512DigestMethod,
	}
)

// negotiatedSigningKey returns the signature methods that are negotiated for the key that the identity provider
// signs with, and the size of the key in bits as an alg:SigningMethod bounds it: the modulus of an RSA key and
// the size of the curve of an ECDSA key. There are none for a key that can't sign, which is refused when it is
// signed with.
func (idp *IdentityProvider) negotiatedSigningKey() (methods []string, bits int) {
	signer, err := idp.signer()
	if err != nil || signer == nil {
		return nil, 0
	}

	switch public := signer.Public().(type) {
	case *rsa.PublicKey:
		return negotiatedRSASignatureMethods, public.N.BitLen()
	case *ecdsa.PublicKey:
		return negotiatedECDSASignatureMethods, public.Curve.Params().BitSize
	}

	return nil, 0
}

// negotiationNote is why the signature method, or else the digest method, of a message is not one that the
// metadata of its service provider lists, although it lists some.
type negotiationNote struct {
	signature bool
	text      string
}

// algorithmRole returns the role of the service provider whose algorithms are negotiated for the message of req:
// the SPSSODescriptor that an assertion is issued for, or else the first, or nil if it has none.
func algorithmRole(req IssuanceRequest) *RoleDescriptor {
	if req.SPSSODescriptor != nil {
		return &req.SPSSODescriptor.RoleDescriptor
	}

	if req.ServiceProviderMetadata != nil && len(req.ServiceProviderMetadata.SPSSODescriptors) != 0 {
		return &req.ServiceProviderMetadata.SPSSODescriptors[0].RoleDescriptor
	}

	return nil
}

// negotiateAlgorithms returns defaults with the signature and digest method negotiated from the alg:SigningMethod
// and alg:DigestMethod elements of the metadata of the service provider of req, and what to log about each that
// was not.
//
// The Metadata Profile for Algorithm Support §2.5 requires a metadata consumer to use the intersection of what it
// and its peer support, and to select the first algorithm the peer lists that it supports, for each type of
// algorithm. What the identity provider supports here is a method with SHA-256, SHA-384 or SHA-512 for the type of
// its key, with a key of a size that the service provider supports with it, and the method that defaults has,
// which is the SignatureMethod of the identity provider; and for a digest the same three, and that of the method
// of defaults. If the service provider lists none of a type, §2.5 leaves the choice to the identity provider, and
// defaults is left as it is.
//
// If it lists some and none can be used, defaults is also left as it is, which is reported to the Observer. This differs from the
// encryption of an assertion, which fails rather than use an algorithm the service provider doesn't list. The
// profile does not make what is listed a policy (§2.4), the message is signed no weaker than the operator set for
// every service provider, and it is what such a service provider was sent before its metadata was read for this,
// when metadata that is out of date or incomplete did no harm. A service provider that really can't verify the
// signature refuses it.
func (idp *IdentityProvider) negotiateAlgorithms(req IssuanceRequest, defaults Issuance) (Issuance, []negotiationNote) {
	metadata := req.ServiceProviderMetadata
	if metadata == nil {
		return defaults, nil
	}

	var notes []negotiationNote

	role := algorithmRole(req)
	own := defaults.SignatureMethod

	if listed := metadata.SigningMethods(role); len(listed) != 0 {
		methods, bits := idp.negotiatedSigningKey()

		i := slices.IndexFunc(listed, func(method SigningMethod) bool {
			return (slices.Contains(methods, method.Algorithm) || method.Algorithm == own) && (bits == 0 || method.allows(bits))
		})
		if i >= 0 {
			defaults.SignatureMethod = listed[i].Algorithm
		} else {
			notes = append(notes, negotiationNote{signature: true, text: fmt.Sprintf(
				"none of its alg:SigningMethod elements (%s) is a method the identity provider can sign with using its key of %d bits, so %s is used",
				describeSigningMethods(listed), bits, own)})
		}
	}

	if listed := metadata.DigestMethods(role); len(listed) != 0 {
		// The digest that the signature method of the identity provider has is one it uses, even if it is SHA-1.
		sha1 := slices.Contains(sha1SignatureMethods, own)

		i := slices.IndexFunc(listed, func(method DigestMethod) bool {
			return slices.Contains(negotiatedDigestMethods, method.Algorithm) || (sha1 && method.Algorithm == dsig.SHA1DigestMethod)
		})
		if i >= 0 {
			defaults.DigestMethod = listed[i].Algorithm
		} else {
			algorithms := make([]string, 0, len(listed))
			for _, method := range listed {
				algorithms = append(algorithms, method.Algorithm)
			}

			notes = append(notes, negotiationNote{text: fmt.Sprintf(
				"none of its alg:DigestMethod elements (%s) is a digest the identity provider uses, so that of the signature method is used",
				strings.Join(algorithms, ", "))})
		}
	}

	return defaults, notes
}

// describeSigningMethods returns the algorithms of methods, each with the sizes of key it is bounded to, for a
// log.
func describeSigningMethods(methods []SigningMethod) string {
	described := make([]string, 0, len(methods))

	for _, method := range methods {
		switch {
		case method.MinKeySize > 0 && method.MaxKeySize > 0:
			described = append(described, fmt.Sprintf("%s for %d to %d bits", method.Algorithm, method.MinKeySize, method.MaxKeySize))
		case method.MinKeySize > 0:
			described = append(described, fmt.Sprintf("%s for %d bits or more", method.Algorithm, method.MinKeySize))
		case method.MaxKeySize > 0:
			described = append(described, fmt.Sprintf("%s for %d bits or fewer", method.Algorithm, method.MaxKeySize))
		default:
			described = append(described, method.Algorithm)
		}
	}

	return strings.Join(described, ", ")
}

// observeAlgorithmFallback reports each of notes, which negotiateAlgorithms returned for the service provider, as
// an EventAlgorithmFallback of the request r, which may be nil, in the state of the request that the message
// answers.
func (idp *IdentityProvider) observeAlgorithmFallback(r *http.Request, state requestState, metadata *EntityDescriptor, notes []negotiationNote) {
	if metadata == nil {
		return
	}

	for _, note := range notes {
		idp.observe(r, state.warning(EventAlgorithmFallback,
			ErrServerError.WithStatusMessage("an algorithm was not negotiated with the service provider").
				WithDebugf("signing for service provider %s: %s", metadata.EntityID, note.text)))
	}
}
