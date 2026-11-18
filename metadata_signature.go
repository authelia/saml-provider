package saml

import (
	"bytes"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"time"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"

	"authelia.com/provider/saml/internal/dsig"
)

// metadataNamespace is the namespace of the elements of SAML metadata.
const metadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata"

// SignedMetadata returns the metadata of the identity provider as an XML document whose EntityDescriptor has an
// enveloped signature by the key of the identity provider (SAMLMeta §3), so that it can be published over a
// channel which doesn't authenticate it, or added to a federation which checks who signed it. The signature
// refers to the ID of the EntityDescriptor, which is random for each call (SAMLMeta §3.1.2), and is its first
// child, as the schema requires. The document isn't cached, so it is signed again for every call. It returns an
// error if MetadataInfo is not valid, see MetadataInfo.Validate.
func (idp *IdentityProvider) SignedMetadata() ([]byte, error) {
	if err := idp.checkMetadataInfo(); err != nil {
		return nil, err
	}

	metadata := idp.Metadata()
	metadata.ID = fmt.Sprintf("id-%x", randomBytes(20))

	buf, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, err
	}

	doc := etree.NewDocument()
	if err = doc.ReadFromBytes(buf); err != nil {
		return nil, err
	}

	signingContext, err := idp.signingContext()
	if err != nil {
		return nil, err
	}

	signed, err := signingContext.SignEnveloped(doc.Root())
	if err != nil {
		return nil, err
	}

	// SignEnveloped appends the signature, but the schema puts it before every other child of the
	// EntityDescriptor. The enveloped signature transform removes it wherever it is, so the digest is unchanged.
	last := len(signed.Child) - 1
	signature := signed.Child[last]
	signed.RemoveChildAt(last)
	signed.InsertChildAt(0, signature)

	doc.SetRoot(signed)

	return doc.WriteToBytes()
}

// MetadataVerifier verifies the signature of metadata from a source that doesn't authenticate it, such as the
// aggregate of a federation or metadata fetched over plain http, before it is parsed with
// ParseServiceProviderMetadata or ParseServiceProvidersMetadata.
type MetadataVerifier struct {
	// Certificates are the certificates that the metadata may be signed with. Only the key of a certificate is
	// used, as SAMLMetaIOP §2.5.1 treats a certificate as a container for a key, but a certificate that is
	// expired or not yet valid is refused, as for any other signature this package verifies.
	Certificates []*x509.Certificate

	// MaxValidity, when it isn't zero, refuses metadata which has no validUntil, or whose validUntil is further
	// than MaxValidity in the future. Signed metadata that never expires can be replayed with a key that has
	// since been withdrawn (SAMLMetaIOP §2.7), so a federation sets it to bound how old the metadata may be.
	//
	// MaxClockSkew is allowed for in both checks of the validUntil (SAML2Int SDP-G01): metadata is refused as
	// expired once its validUntil is MaxClockSkew ago, and as valid for too long if its validUntil is further
	// than MaxValidity and MaxClockSkew ahead.
	MaxValidity time.Duration

	// SignatureMethods and DigestMethods list the identifiers of the signature algorithms the metadata may be
	// signed with, and of the digest algorithms the Reference of the signature may name. They are the
	// IdentityProvider fields of the same names: empty means every supported algorithm but those of SHA-1, an
	// algorithm that is not supported is an error, and metadata signed with one that isn't listed is refused.
	SignatureMethods []string
	DigestMethods    []string
}

// Verify verifies the signature on the root element of metadata, an EntityDescriptor or an
// EntitiesDescriptor, with any of the certificates, and returns the XML that it covers. Only what Verify returns
// is authenticated, so that is what must be parsed, and never data.
//
// SAMLMeta §3.1 is followed strictly: the root element must have an ID, and a signature as its child with a
// single reference, to that ID. Signatures on elements within the root are ignored, as the one on the root covers
// them. Metadata whose validUntil has passed is refused.
func (v *MetadataVerifier) Verify(data []byte) ([]byte, error) {
	if len(v.Certificates) == 0 {
		return nil, errors.New("no certificates to verify the metadata with")
	}

	policy, err := newSignaturePolicy("MetadataVerifier", v.SignatureMethods, v.DigestMethods)
	if err != nil {
		return nil, err
	}

	if err := xrv.Validate(bytes.NewReader(data)); err != nil {
		return nil, err
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, err
	}

	root := doc.Root()
	if root == nil || root.NamespaceURI() != metadataNamespace || (root.Tag != "EntityDescriptor" && root.Tag != "EntitiesDescriptor") {
		return nil, errors.New("metadata must be an EntityDescriptor or an EntitiesDescriptor")
	}

	if err := checkMetadataSignature(root); err != nil {
		return nil, err
	}

	verified, err := verifyEnvelopedSignature(root, v.Certificates, policy)
	if err != nil {
		return nil, fmt.Errorf("cannot verify the signature of the metadata: %w", err)
	}

	if err = v.checkValidUntil(verified); err != nil {
		return nil, err
	}

	out := etree.NewDocument()
	out.SetRoot(verified)

	return out.WriteToBytes()
}

// checkMetadataSignature returns an error unless root has an ID, and exactly one signature as its child, which has
// exactly one reference, to that ID (SAMLMeta §3.1.2).
func checkMetadataSignature(root *etree.Element) error {
	id := root.SelectAttrValue("ID", "")
	if id == "" {
		return errors.New("signed metadata must have an ID")
	}

	var signatures []*etree.Element

	for _, child := range root.ChildElements() {
		if child.Tag == dsig.SignatureTag && child.NamespaceURI() == dsig.Namespace {
			signatures = append(signatures, child)
		}
	}

	switch len(signatures) {
	case 0:
		return errors.New("metadata is not signed")
	case 1:
	default:
		return errors.New("metadata has more than one signature")
	}

	var references []*etree.Element

	for _, signedInfo := range signatures[0].ChildElements() {
		if signedInfo.Tag != dsig.SignedInfoTag || signedInfo.NamespaceURI() != dsig.Namespace {
			continue
		}

		for _, reference := range signedInfo.ChildElements() {
			if reference.Tag == dsig.ReferenceTag && reference.NamespaceURI() == dsig.Namespace {
				references = append(references, reference)
			}
		}
	}

	if len(references) != 1 || references[0].SelectAttrValue(dsig.URIAttr, "") != "#"+id {
		return errors.New("the signature of the metadata must have a single reference to its ID")
	}

	return nil
}

// checkValidUntil returns an error if the validUntil of the verified metadata has passed, or if MaxValidity is set
// and it has none, or one that is too far in the future. MaxClockSkew is allowed for in both directions.
func (v *MetadataVerifier) checkValidUntil(verified *etree.Element) error {
	attr := verified.SelectAttrValue("validUntil", "")
	if attr == "" {
		if v.MaxValidity != 0 {
			return errors.New("signed metadata has no validUntil")
		}

		return nil
	}

	var validUntil RelaxedTime
	if err := validUntil.UnmarshalText([]byte(attr)); err != nil {
		return fmt.Errorf("signed metadata has an invalid validUntil: %w", err)
	}

	now := TimeNow()

	if expiredAt(time.Time(validUntil), now) {
		return errors.New("signed metadata has expired")
	}

	if v.MaxValidity != 0 && validBeyond(time.Time(validUntil), now, v.MaxValidity) {
		return fmt.Errorf("signed metadata is valid for longer than %s", v.MaxValidity)
	}

	return nil
}
