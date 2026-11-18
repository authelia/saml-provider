package saml

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/beevik/etree"
)

// HTTPPostBinding is the official URN for the HTTP-POST binding (transport).
const HTTPPostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

// HTTPRedirectBinding is the official URN for the HTTP-Redirect binding (transport).
const HTTPRedirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

// HTTPArtifactBinding is the official URN for the HTTP-Artifact binding (transport).
const HTTPArtifactBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"

// SOAPBinding is the official URN for the SOAP binding (transport).
const SOAPBinding = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"

// PAOSBinding is the official URN for the reverse SOAP (PAOS) binding, which a service provider receives the Response
// of the Enhanced Client or Proxy profile on.
const PAOSBinding = "urn:oasis:names:tc:SAML:2.0:bindings:PAOS"

// SOAPBindingV1 is the URN for the SOAP binding in SAML 1.0.
const SOAPBindingV1 = "urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding"

// EntitiesDescriptor represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.3.1.
type EntitiesDescriptor struct {
	XMLName             xml.Name       `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
	ID                  *string        `xml:",attr,omitempty"`
	ValidUntil          *time.Time     `xml:"validUntil,attr,omitempty"`
	CacheDuration       *time.Duration `xml:"cacheDuration,attr,omitempty"`
	Name                *string        `xml:",attr,omitempty"`
	Signature           *etree.Element
	Extensions          *Extensions          `xml:"Extensions,omitempty"`
	EntitiesDescriptors []EntitiesDescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
	EntityDescriptors   []EntityDescriptor   `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
}

// MarshalXML implements [xml.Marshaler].
func (m EntitiesDescriptor) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	var (
		validUntil    *RelaxedTime
		cacheDuration *Duration
	)

	if m.ValidUntil != nil {
		vu := RelaxedTime(*m.ValidUntil)
		validUntil = &vu
	}

	if m.CacheDuration != nil {
		cd := Duration(*m.CacheDuration)
		cacheDuration = &cd
	}

	type Alias EntitiesDescriptor

	aux := &struct {
		ValidUntil    *RelaxedTime `xml:"validUntil,attr,omitempty"`
		CacheDuration *Duration    `xml:"cacheDuration,attr,omitempty"`
		*Alias
	}{
		ValidUntil:    validUntil,
		CacheDuration: cacheDuration,
		Alias:         (*Alias)(&m),
	}

	return e.Encode(aux)
}

// UnmarshalXML implements [xml.Unmarshaler].
func (m *EntitiesDescriptor) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias EntitiesDescriptor

	aux := &struct {
		ValidUntil    *RelaxedTime `xml:"validUntil,attr,omitempty"`
		CacheDuration *Duration    `xml:"cacheDuration,attr,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}
	if err := d.DecodeElement(aux, &start); err != nil {
		return err
	}

	if aux.ValidUntil != nil {
		t := time.Time(*aux.ValidUntil)
		m.ValidUntil = &t
	}

	if aux.CacheDuration != nil {
		d := time.Duration(*aux.CacheDuration)
		m.CacheDuration = &d
	}

	return nil
}

// Metadata as been renamed to EntityDescriptor
//
// This change was made to be consistent with the rest of the API which uses names
// from the SAML specification for types.
//
// This is a tombstone to help you discover this fact. You should update references
// to saml.Metadata to be saml.EntityDescriptor.
var Metadata = struct{}{}

// EntityDescriptor represents the SAML EntityDescriptor object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.3.2.
type EntityDescriptor struct {
	XMLName                       xml.Name      `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID                      string        `xml:"entityID,attr"`
	ID                            string        `xml:",attr,omitempty"`
	ValidUntil                    time.Time     `xml:"validUntil,attr,omitempty"`
	CacheDuration                 time.Duration `xml:"cacheDuration,attr,omitempty"`
	Signature                     *etree.Element
	Extensions                    *Extensions                    `xml:"Extensions,omitempty"`
	RoleDescriptors               []RoleDescriptor               `xml:"RoleDescriptor"`
	IDPSSODescriptors             []IDPSSODescriptor             `xml:"IDPSSODescriptor"`
	SPSSODescriptors              []SPSSODescriptor              `xml:"SPSSODescriptor"`
	AuthnAuthorityDescriptors     []AuthnAuthorityDescriptor     `xml:"AuthnAuthorityDescriptor"`
	AttributeAuthorityDescriptors []AttributeAuthorityDescriptor `xml:"AttributeAuthorityDescriptor"`
	PDPDescriptors                []PDPDescriptor                `xml:"PDPDescriptor"`
	AffiliationDescriptor         *AffiliationDescriptor
	Organization                  *Organization
	ContactPeople                 []ContactPerson `xml:"ContactPerson"`
	AdditionalMetadataLocations   []string        `xml:"AdditionalMetadataLocation"`
}

// MarshalXML implements [xml.Marshaler].
func (m EntityDescriptor) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias EntityDescriptor

	aux := &struct {
		ValidUntil    RelaxedTime `xml:"validUntil,attr,omitempty"`
		CacheDuration Duration    `xml:"cacheDuration,attr,omitempty"`
		*Alias
	}{
		ValidUntil:    RelaxedTime(m.ValidUntil),
		CacheDuration: Duration(m.CacheDuration),
		Alias:         (*Alias)(&m),
	}

	return e.Encode(aux)
}

// UnmarshalXML implements [xml.Unmarshaler].
func (m *EntityDescriptor) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias EntityDescriptor

	aux := &struct {
		ValidUntil    RelaxedTime `xml:"validUntil,attr,omitempty"`
		CacheDuration Duration    `xml:"cacheDuration,attr,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}
	if err := d.DecodeElement(aux, &start); err != nil {
		return err
	}

	m.ValidUntil = time.Time(aux.ValidUntil)
	m.CacheDuration = time.Duration(aux.CacheDuration)

	return nil
}

// Organization represents the SAML Organization object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.3.2.1.
type Organization struct {
	Extensions               *Extensions     `xml:"Extensions,omitempty"`
	OrganizationNames        []LocalizedName `xml:"OrganizationName"`
	OrganizationDisplayNames []LocalizedName `xml:"OrganizationDisplayName"`
	OrganizationURLs         []LocalizedURI  `xml:"OrganizationURL"`
}

// LocalizedName represents the SAML type localizedNameType.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.2.4.
type LocalizedName struct {
	Lang  string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
	Value string `xml:",chardata"`
}

// LocalizedURI represents the SAML type localizedURIType.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.2.5.
type LocalizedURI struct {
	Lang  string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
	Value string `xml:",chardata"`
}

// ContactPerson represents the SAML element ContactPerson.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.3.2.2.
type ContactPerson struct {
	// ContactType is technical, support, administrative, billing or other.
	ContactType string `xml:"contactType,attr"`

	// REFEDSContactType is the remd:contactType attribute of the REFEDS Security Contact Metadata Extension, which
	// is REFEDSSecurityContactType for the security contact that Sirtfi requires, whose ContactType is other.
	REFEDSContactType string `xml:"http://refeds.org/metadata contactType,attr,omitempty"`

	Extensions *Extensions `xml:"Extensions,omitempty"`
	Company    string      `xml:",omitempty"`
	GivenName  string      `xml:",omitempty"`
	SurName    string      `xml:",omitempty"`

	// EmailAddresses are URIs, so an address is written as mailto:someone@example.com.
	EmailAddresses   []string `xml:"EmailAddress"`
	TelephoneNumbers []string `xml:"TelephoneNumber"`
}

// UnmarshalXML implements [xml.Unmarshaler]. The contactType and the remd:contactType attributes have the same
// local name, and each is only read from its own namespace.
func (m *ContactPerson) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type alias ContactPerson

	if err := d.DecodeElement((*alias)(m), &start); err != nil {
		return err
	}

	m.ContactType = ""

	for _, attr := range start.Attr {
		if attr.Name.Space == "" && attr.Name.Local == "contactType" {
			m.ContactType = attr.Value
		}
	}

	return nil
}

// RoleDescriptor represents the SAML element RoleDescriptor.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.1.
type RoleDescriptor struct {
	ID                         string      `xml:",attr,omitempty"`
	ValidUntil                 *time.Time  `xml:"validUntil,attr,omitempty"`
	CacheDuration              XSDDuration `xml:"cacheDuration,attr,omitempty"`
	ProtocolSupportEnumeration string      `xml:"protocolSupportEnumeration,attr"`
	ErrorURL                   string      `xml:"errorURL,attr,omitempty"`
	Signature                  *etree.Element
	Extensions                 *Extensions     `xml:"Extensions,omitempty"`
	KeyDescriptors             []KeyDescriptor `xml:"KeyDescriptor,omitempty"`
	Organization               *Organization   `xml:"Organization,omitempty"`
	ContactPeople              []ContactPerson `xml:"ContactPerson,omitempty"`
}

// KeyDescriptor represents the md:KeyDescriptor element of SAMLMeta §2.4.1.1, which holds one key of an entity.
type KeyDescriptor struct {
	// Use is "signing" or "encryption". It is optional, and empty when the attribute is absent, which means that
	// the key is for both (SAMLMeta §2.4.1.1), and is how it is written again.
	Use               string             `xml:"use,attr,omitempty"`
	KeyInfo           KeyInfo            `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	EncryptionMethods []EncryptionMethod `xml:"EncryptionMethod"`
}

// EncryptionMethod represents the md:EncryptionMethod element, of the xenc:EncryptionMethodType of XML
// Encryption §3.2.1, which a KeyDescriptor lists for each algorithm its entity supports (SAMLMeta §2.4.1.1).
// The Metadata Profile for Algorithm Support §2.3 allows the KeySize and any parameters an algorithm defines,
// such as the DigestMethod and OAEPparams of RSA-OAEP (XML Encryption §5.4.2) and its MGF in XML Encryption
// 1.1 (§5.5.2), so that the entity can say which of them it accepts.
type EncryptionMethod struct {
	Algorithm string `xml:"Algorithm,attr"`

	// KeySize is the size of key in bits that the entity accepts for an algorithm with keys of more than one size,
	// or zero if it gives none.
	KeySize int `xml:"http://www.w3.org/2001/04/xmlenc# KeySize,omitempty"`

	// OAEPParams is the base64 encoded OAEP label of RSA-OAEP, or empty if there is none.
	OAEPParams string `xml:"http://www.w3.org/2001/04/xmlenc# OAEPparams,omitempty"`

	// DigestMethod is the digest of RSA-OAEP, or nil if it gives none.
	DigestMethod *DigestMethod `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod,omitempty"`

	// MGF is the mask generation function of XML Encryption 1.1 RSA-OAEP, or nil if it gives none.
	MGF *MGF `xml:"http://www.w3.org/2009/xmlenc11# MGF,omitempty"`
}

// DigestMethod represents a ds:DigestMethod element, which identifies a digest algorithm of XML Signature, and the
// alg:DigestMethod element of Extensions, which says that an entity can verify a signature whose digest is made
// with the algorithm (Metadata Profile for Algorithm Support §2.4). The schema allows an alg:DigestMethod to hold
// what an algorithm defines beyond its identifier; no digest of XML Signature defines anything, and it is not kept.
type DigestMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// MGF represents the xenc11:MGF element, which identifies the mask generation function of XML Encryption 1.1
// RSA-OAEP (§5.5.2).
type MGF struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// KeyInfo represents the ds:KeyInfo element of XML Signature §4.4 as a KeyDescriptor holds it. The Metadata
// Interoperability Profile (MetaIOP §2.5.1) has it give the key as a KeyValue, an X509Certificate, or both, and
// lets it name the key as well, which is only a hint.
//
// A KeyName, an RSAKeyValue and an X509Certificate are kept, and written again in that order whatever the order
// they were read in. Every other child is dropped when the element is read, such as a DSAKeyValue or an
// ECKeyValue, an X509SubjectName and a RetrievalMethod, none of which this package can use.
type KeyInfo struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`

	// KeyNames are the names of the key (XML Signature §4.4.1). A name is a reference which only its producer can
	// resolve, so a KeyInfo with nothing else gives no key.
	KeyNames []string `xml:"http://www.w3.org/2000/09/xmldsig# KeyName"`

	// KeyValues are the bare public keys (XML Signature §4.4.2), which MetaIOP §2.6.1 requires a metadata consumer
	// to support.
	KeyValues []KeyValue `xml:"http://www.w3.org/2000/09/xmldsig# KeyValue"`

	// X509Data holds the certificates of the key. It is not written when it has none, as a ds:X509Data must not be
	// empty (XML Signature §4.4.4).
	X509Data X509Data `xml:"X509Data"`
}

// MarshalXML implements [xml.Marshaler]. It leaves out what the schema of XML Signature doesn't allow to be empty:
// an X509Data that has no certificate, which a KeyInfo that only names its key or only has a KeyValue would
// otherwise gain, and a KeyValue that has no RSAKeyValue, which is one whose key was of a type that is not kept.
func (k KeyInfo) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type keyInfo struct {
		XMLName   xml.Name   `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
		KeyNames  []string   `xml:"http://www.w3.org/2000/09/xmldsig# KeyName"`
		KeyValues []KeyValue `xml:"http://www.w3.org/2000/09/xmldsig# KeyValue"`
		X509Data  *X509Data  `xml:"X509Data,omitempty"`
	}

	out := keyInfo{KeyNames: k.KeyNames}

	for _, keyValue := range k.KeyValues {
		if keyValue.RSAKeyValue != nil {
			out.KeyValues = append(out.KeyValues, keyValue)
		}
	}

	if len(k.X509Data.X509Certificates) != 0 {
		out.X509Data = &k.X509Data
	}

	return e.Encode(out)
}

// KeyValue represents the ds:KeyValue element of XML Signature §4.4.2, which holds a single public key. Only an
// RSA key is kept: RSAKeyValue is nil for a KeyValue which held a key of another type, such as a DSAKeyValue or
// the ECKeyValue of XML Signature 1.1, and such a KeyValue is not written again.
type KeyValue struct {
	XMLName     xml.Name     `xml:"http://www.w3.org/2000/09/xmldsig# KeyValue"`
	RSAKeyValue *RSAKeyValue `xml:"http://www.w3.org/2000/09/xmldsig# RSAKeyValue,omitempty"`
}

// RSAKeyValue represents the ds:RSAKeyValue element of XML Signature §4.4.2.2. Modulus and Exponent are each a
// ds:CryptoBinary: the base64 encoding of the big-endian octets of the number (XML Signature §4.0.1).
type RSAKeyValue struct {
	Modulus  string `xml:"http://www.w3.org/2000/09/xmldsig# Modulus"`
	Exponent string `xml:"http://www.w3.org/2000/09/xmldsig# Exponent"`
}

// NewRSAKeyValue returns the KeyValue which holds key.
func NewRSAKeyValue(key *rsa.PublicKey) KeyValue {
	return KeyValue{RSAKeyValue: &RSAKeyValue{
		Modulus:  base64.StdEncoding.EncodeToString(key.N.Bytes()),
		Exponent: base64.StdEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}
}

// PublicKey returns the RSA public key that v holds, or an error if either number is not a ds:CryptoBinary, the
// modulus is zero, or the exponent is not one an RSA public key can have. Whitespace in the encoding is ignored,
// as that of a long value is wrapped.
func (v RSAKeyValue) PublicKey() (*rsa.PublicKey, error) {
	modulus, err := base64.StdEncoding.DecodeString(whitespaceRemover.Replace(v.Modulus))
	if err != nil {
		return nil, fmt.Errorf("cannot decode the Modulus of the RSAKeyValue: %w", err)
	}

	exponent, err := base64.StdEncoding.DecodeString(whitespaceRemover.Replace(v.Exponent))
	if err != nil {
		return nil, fmt.Errorf("cannot decode the Exponent of the RSAKeyValue: %w", err)
	}

	n, e := new(big.Int).SetBytes(modulus), new(big.Int).SetBytes(exponent)

	if n.Sign() == 0 {
		return nil, errors.New("the RSAKeyValue has no Modulus")
	}

	// The bounds are those of crypto/rsa, which refuses an exponent that doesn't fit in 31 bits.
	if !e.IsInt64() || e.Int64() < 2 || e.Int64() > 1<<31-1 {
		return nil, errors.New("the RSAKeyValue has an Exponent that can't be used")
	}

	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// X509Data represents the ds:X509Data element of XML Signature §4.4.4. Only its certificates are kept.
type X509Data struct {
	XMLName          xml.Name          `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	X509Certificates []X509Certificate `xml:"X509Certificate"`
}

// X509Certificate represents the XMLSEC object of the same name.
type X509Certificate struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
	Data    string   `xml:",chardata"`
}

// Endpoint represents the SAML EndpointType object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.2.2.
type Endpoint struct {
	Binding          string `xml:"Binding,attr"`
	Location         string `xml:"Location,attr"`
	ResponseLocation string `xml:"ResponseLocation,attr,omitempty"`
}

func checkEndpointLocation(binding string, location string) (string, error) {
	// Within the SAML standard, the complex type EndpointType describes a
	// SAML protocol binding endpoint at which a SAML entity can be sent
	// protocol messages. In particular, the location of an endpoint type is
	// defined as follows in the Metadata for the OASIS Security Assertion
	// Markup Language (SAML) V2.0 - 2.2.2 Complex Type EndpointType:
	//
	//   Location [Required] A required URI attribute that specifies the
	//   location of the endpoint. The allowable syntax of this URI depends
	//   on the protocol binding.
	switch binding {
	case HTTPPostBinding,
		HTTPRedirectBinding,
		HTTPArtifactBinding,
		SOAPBinding,
		PAOSBinding,
		SOAPBindingV1:
		locationURL, err := url.Parse(location)
		if err != nil {
			return "", fmt.Errorf("invalid url %q: %w", location, err)
		}

		switch locationURL.Scheme {
		case "http", "https":
		// ok.
		default:
			return "", fmt.Errorf("invalid url scheme %q for binding %q",
				locationURL.Scheme, binding)
		}
	default:
		// We don't know what form location should take, but the protocol
		// requires that we validate its syntax.
		//
		// In practice, lots of metadata contains random bindings, for example
		// "urn:mace:shibboleth:1.0:profiles:AuthnRequest" from our own test suite.
		//
		// We can't fail, but we also can't allow a location parameter whose syntax we
		// cannot verify. The least-bad course of action here is to set location to
		// and empty string, and hope the caller doesn't care need it.
		location = ""
	}

	return location, nil
}

// UnmarshalXML implements [xml.Unmarshaler].
func (m *Endpoint) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias Endpoint

	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(m),
	}
	if err := d.DecodeElement(aux, &start); err != nil {
		return err
	}

	var err error

	m.Location, err = checkEndpointLocation(m.Binding, m.Location)
	if err != nil {
		return err
	}

	if m.ResponseLocation != "" {
		m.ResponseLocation, err = checkEndpointLocation(m.Binding, m.ResponseLocation)
		if err != nil {
			return err
		}
	}

	return nil
}

// IndexedEndpoint represents the SAML IndexedEndpointType object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.2.3.
type IndexedEndpoint struct {
	Binding          string  `xml:"Binding,attr"`
	Location         string  `xml:"Location,attr"`
	ResponseLocation *string `xml:"ResponseLocation,attr,omitempty"`
	Index            int     `xml:"index,attr"`
	IsDefault        *bool   `xml:"isDefault,attr"`
}

// UnmarshalXML implements [xml.Unmarshaler].
func (m *IndexedEndpoint) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias IndexedEndpoint

	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(m),
	}
	if err := d.DecodeElement(aux, &start); err != nil {
		return err
	}

	var err error

	m.Location, err = checkEndpointLocation(m.Binding, m.Location)
	if err != nil {
		return err
	}

	if m.ResponseLocation != nil {
		responseLocation, err := checkEndpointLocation(m.Binding, *m.ResponseLocation)
		if err != nil {
			return err
		}

		if responseLocation != "" {
			m.ResponseLocation = &responseLocation
		} else {
			m.ResponseLocation = nil
		}
	}

	return nil
}

// SSODescriptor represents the SAML complex type SSODescriptor
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.2.
type SSODescriptor struct {
	RoleDescriptor
	ArtifactResolutionServices []IndexedEndpoint `xml:"ArtifactResolutionService"`
	SingleLogoutServices       []Endpoint        `xml:"SingleLogoutService"`
	ManageNameIDServices       []Endpoint        `xml:"ManageNameIDService"`
	NameIDFormats              []NameIDFormat    `xml:"NameIDFormat"`
}

// IDPSSODescriptor represents the SAML IDPSSODescriptorType object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.3.
type IDPSSODescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	SSODescriptor
	WantAuthnRequestsSigned *bool `xml:",attr"`

	SingleSignOnServices       []Endpoint  `xml:"SingleSignOnService"`
	NameIDMappingServices      []Endpoint  `xml:"NameIDMappingService"`
	AssertionIDRequestServices []Endpoint  `xml:"AssertionIDRequestService"`
	AttributeProfiles          []string    `xml:"AttributeProfile"`
	Attributes                 []Attribute `xml:"Attribute"`
}

// SPSSODescriptor represents the SAML SPSSODescriptorType object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.2.
type SPSSODescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
	SSODescriptor
	AuthnRequestsSigned        *bool                       `xml:",attr"`
	WantAssertionsSigned       *bool                       `xml:",attr"`
	AssertionConsumerServices  []IndexedEndpoint           `xml:"AssertionConsumerService"`
	AttributeConsumingServices []AttributeConsumingService `xml:"AttributeConsumingService"`
}

// AttributeConsumingService represents the SAML AttributeConsumingService object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.4.1.
type AttributeConsumingService struct {
	Index               int                  `xml:"index,attr"`
	IsDefault           *bool                `xml:"isDefault,attr"`
	ServiceNames        []LocalizedName      `xml:"ServiceName"`
	ServiceDescriptions []LocalizedName      `xml:"ServiceDescription"`
	RequestedAttributes []RequestedAttribute `xml:"RequestedAttribute"`
}

// RequestedAttribute represents the SAML RequestedAttribute object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.4.2.
type RequestedAttribute struct {
	Attribute
	IsRequired *bool `xml:"isRequired,attr"`
}

// AuthnAuthorityDescriptor represents the SAML AuthnAuthorityDescriptor object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.5.
type AuthnAuthorityDescriptor struct {
	RoleDescriptor
	AuthnQueryServices         []Endpoint     `xml:"AuthnQueryService"`
	AssertionIDRequestServices []Endpoint     `xml:"AssertionIDRequestService"`
	NameIDFormats              []NameIDFormat `xml:"NameIDFormat"`
}

// PDPDescriptor represents the SAML PDPDescriptor object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.6.
type PDPDescriptor struct {
	RoleDescriptor
	AuthzServices              []Endpoint     `xml:"AuthzService"`
	AssertionIDRequestServices []Endpoint     `xml:"AssertionIDRequestService"`
	NameIDFormats              []NameIDFormat `xml:"NameIDFormat"`
}

// AttributeAuthorityDescriptor represents the SAML AttributeAuthorityDescriptor object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.7.
type AttributeAuthorityDescriptor struct {
	RoleDescriptor
	AttributeServices          []Endpoint     `xml:"AttributeService"`
	AssertionIDRequestServices []Endpoint     `xml:"AssertionIDRequestService"`
	NameIDFormats              []NameIDFormat `xml:"NameIDFormat"`
	AttributeProfiles          []string       `xml:"AttributeProfile"`
	Attributes                 []Attribute    `xml:"Attribute"`
}

// AffiliationDescriptor represents the SAML AffiliationDescriptor object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.5.
type AffiliationDescriptor struct {
	AffiliationOwnerID string       `xml:"affiliationOwnerID,attr"`
	ID                 string       `xml:",attr"`
	ValidUntil         time.Time    `xml:"validUntil,attr,omitempty"`
	CacheDuration      *XSDDuration `xml:"cacheDuration,attr,omitempty"`
	Signature          *etree.Element
	Extensions         *Extensions     `xml:"Extensions,omitempty"`
	AffiliateMembers   []string        `xml:"AffiliateMember"`
	KeyDescriptors     []KeyDescriptor `xml:"KeyDescriptor"`
}
