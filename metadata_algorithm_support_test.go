package saml

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/dsig"
)

const testNSAlg = "urn:oasis:names:tc:SAML:metadata:algsupport"

// algorithmSupportExample is the example of the Metadata Profile for Algorithm Support §2.7, with a role that
// lists a signing method of its own.
const algorithmSupportExample = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"
    entityID="https://serviceprovider.example.com/SAML">
  <Extensions>
    <alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384"/>
    <alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <alg:SigningMethod MinKeySize="256" MaxKeySize="511" Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>
    <alg:SigningMethod MinKeySize="2048" MaxKeySize="4096" Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <other:Thing xmlns:other="https://example.com/other"/>
  </Extensions>
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <Extensions>
      <alg:SigningMethod Algorithm="http://www.w3.org/2007/05/xmldsig-more#rsa-pss">
        <pss:RSAPSSParams xmlns:pss="http://www.w3.org/2007/05/xmldsig-more#">
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <pss:SaltLength>32</pss:SaltLength>
        </pss:RSAPSSParams>
      </alg:SigningMethod>
    </Extensions>
  </SPSSODescriptor>
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
</EntityDescriptor>`

func parseAlgorithmSupportExample(t *testing.T) *EntityDescriptor {
	t.Helper()

	var metadata EntityDescriptor
	require.NoError(t, xml.Unmarshal([]byte(algorithmSupportExample), &metadata))

	return &metadata
}

func TestParseAlgorithmSupport(t *testing.T) {
	metadata := parseAlgorithmSupportExample(t)

	require.NotNil(t, metadata.Extensions)

	// The elements are in the order of preference of the entity, which is the order they are in.
	assert.Equal(t, []DigestMethod{
		{Algorithm: dsig.SHA384DigestMethod},
		{Algorithm: dsig.SHA256DigestMethod},
	}, metadata.Extensions.DigestMethods)
	assert.Equal(t, []SigningMethod{
		{Algorithm: dsig.ECDSASHA256SignatureMethod, MinKeySize: 256, MaxKeySize: 511},
		{Algorithm: dsig.RSASHA256SignatureMethod, MinKeySize: 2048, MaxKeySize: 4096},
	}, metadata.Extensions.SigningMethods)

	// They are no longer among the elements that aren't modelled.
	require.Len(t, metadata.Extensions.Other, 1)
	assert.Equal(t, "Thing", metadata.Extensions.Other[0].XMLName.Local)

	// What an algorithm defines beyond its identifier is kept.
	role := metadata.SPSSODescriptors[0].Extensions
	require.NotNil(t, role)
	require.Len(t, role.SigningMethods, 1)
	assert.Equal(t, "http://www.w3.org/2007/05/xmldsig-more#rsa-pss", role.SigningMethods[0].Algorithm)
	assert.Equal(t, 0, role.SigningMethods[0].MinKeySize)
	assert.Equal(t, 0, role.SigningMethods[0].MaxKeySize)
	require.Len(t, role.SigningMethods[0].Parameters, 1)
	assert.Equal(t, xml.Name{Space: "http://www.w3.org/2007/05/xmldsig-more#", Local: "RSAPSSParams"}, role.SigningMethods[0].Parameters[0].XMLName)
	assert.Len(t, role.SigningMethods[0].Parameters[0].Children, 2)
	assert.Len(t, role.Other, 0)
}

func TestParseAlgorithmSupportKeySizesThatAreNotNumbers(t *testing.T) {
	// A size that isn't a positive integer states none, so the metadata around it, which may be an aggregate, is
	// still read.
	var metadata EntityDescriptor
	require.NoError(t, xml.Unmarshal([]byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <Extensions xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport">
    <alg:SigningMethod Algorithm="a" MinKeySize="large" MaxKeySize="-1"/>
    <alg:SigningMethod Algorithm="b" MinKeySize=" 2048 " MaxKeySize="0"/>
  </Extensions>
</EntityDescriptor>`), &metadata))

	assert.Equal(t, []SigningMethod{
		{Algorithm: "a"},
		{Algorithm: "b", MinKeySize: 2048},
	}, metadata.Extensions.SigningMethods)
}

func TestAlgorithmSupportMarshalsWithTheAlgPrefix(t *testing.T) {
	metadata := &EntityDescriptor{
		EntityID: "https://idp.example.org/metadata",
		Extensions: &Extensions{
			Scopes:        []Scope{{Value: "example.org"}},
			DigestMethods: []DigestMethod{{Algorithm: dsig.SHA256DigestMethod}},
			SigningMethods: []SigningMethod{
				{Algorithm: dsig.RSASHA256SignatureMethod, MinKeySize: 2048, MaxKeySize: 4096},
				{Algorithm: dsig.ECDSASHA256SignatureMethod},
			},
			Other: []ExtensionElement{{XMLName: xml.Name{Space: "https://example.com/other", Local: "Thing"}}},
		},
	}

	buf, err := xml.Marshal(metadata)
	require.NoError(t, err)

	marshalled := string(buf)
	assert.Contains(t, marshalled, `<alg:DigestMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></alg:DigestMethod>`)
	assert.Contains(t, marshalled, `<alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" MinKeySize="2048" MaxKeySize="4096"></alg:SigningMethod>`)
	assert.Contains(t, marshalled, `<alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"></alg:SigningMethod>`)

	// After the other extensions that are modelled and before those that aren't, digests first.
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(buf))
	assert.Equal(t, []xml.Name{
		{Space: testNSShibMD, Local: "Scope"},
		{Space: testNSAlg, Local: "DigestMethod"},
		{Space: testNSAlg, Local: "SigningMethod"},
		{Space: testNSAlg, Local: "SigningMethod"},
		{Space: "https://example.com/other", Local: "Thing"},
	}, childrenOf(doc.Root().ChildElements()[0]))
}

func TestAlgorithmSupportAloneIsNotAnEmptyExtensions(t *testing.T) {
	for _, extensions := range []*Extensions{
		{DigestMethods: []DigestMethod{{Algorithm: dsig.SHA256DigestMethod}}},
		{SigningMethods: []SigningMethod{{Algorithm: dsig.RSASHA256SignatureMethod}}},
	} {
		buf, err := xml.Marshal(&EntityDescriptor{EntityID: "https://idp.example.org/metadata", Extensions: extensions})
		require.NoError(t, err)
		assert.True(t, strings.Contains(string(buf), "<Extensions>"), string(buf))
	}
}

func TestAlgorithmSupportRoundTrip(t *testing.T) {
	metadata := parseAlgorithmSupportExample(t)

	buf, err := xml.MarshalIndent(metadata, "", "  ")
	require.NoError(t, err)

	var again EntityDescriptor
	require.NoError(t, xml.Unmarshal(buf, &again))

	assert.Equal(t, metadata.Extensions, again.Extensions)
	assert.Equal(t, metadata.SPSSODescriptors[0].Extensions, again.SPSSODescriptors[0].Extensions)

	// The parameters of a signing method are in their namespace.
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(buf))

	params := doc.Root().FindElement("./SPSSODescriptor/Extensions/SigningMethod/RSAPSSParams")
	require.True(t, params != nil, string(buf))
	assert.Equal(t, "http://www.w3.org/2007/05/xmldsig-more#", params.NamespaceURI())
	assert.Equal(t, "32", params.ChildElements()[1].Text())
}

func TestAlgorithmSupportPrecedence(t *testing.T) {
	metadata := parseAlgorithmSupportExample(t)

	withBoth, withNone := &metadata.SPSSODescriptors[0].RoleDescriptor, &metadata.SPSSODescriptors[1].RoleDescriptor

	entitySigning := metadata.Extensions.SigningMethods
	entityDigests := metadata.Extensions.DigestMethods

	// §2.5: what a role lists takes precedence over what the entity lists, and the two are not combined.
	assert.Equal(t, withBoth.Extensions.SigningMethods, metadata.SigningMethods(withBoth))

	// Each type of algorithm on its own: the role lists no digest, so those of the entity apply to it.
	assert.Equal(t, entityDigests, metadata.DigestMethods(withBoth))

	// A role that lists nothing, or has no Extensions, has what the entity lists, and so has no role.
	assert.Equal(t, entitySigning, metadata.SigningMethods(withNone))
	assert.Equal(t, entityDigests, metadata.DigestMethods(withNone))
	assert.Equal(t, entitySigning, metadata.SigningMethods(nil))
	assert.Equal(t, entityDigests, metadata.DigestMethods(nil))

	// A role that lists digests hides those of the entity.
	withBoth.Extensions.DigestMethods = []DigestMethod{{Algorithm: dsig.SHA512DigestMethod}}
	assert.Equal(t, []DigestMethod{{Algorithm: dsig.SHA512DigestMethod}}, metadata.DigestMethods(withBoth))

	// Metadata that lists nothing gives no information.
	empty := &EntityDescriptor{SPSSODescriptors: []SPSSODescriptor{{}}}
	assert.Len(t, empty.SigningMethods(&empty.SPSSODescriptors[0].RoleDescriptor), 0)
	assert.Len(t, empty.DigestMethods(nil), 0)
}

func TestAlgorithmSupportOfAFederationServiceProviderIsTyped(t *testing.T) {
	metadata := parseExtensionsFixture(t)

	assert.Equal(t, []DigestMethod{{Algorithm: dsig.SHA256DigestMethod}}, metadata.Extensions.DigestMethods)

	for _, other := range metadata.Extensions.Other {
		assert.True(t, other.XMLName.Space != testNSAlg)
	}
}
