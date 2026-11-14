package saml

import (
	"encoding/xml"
	"testing"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"
)

func TestCanParseMetadata(t *testing.T) {
	buf := golden.Get(t, "TestCanParseMetadata_metadata.xml")

	metadata := EntityDescriptor{}
	err := xml.Unmarshal(buf, &metadata)
	assert.Check(t, err)

	var False = false
	var True = true

	expected := EntityDescriptor{
		EntityID:      "https://dev.aa.kndr.org/users/auth/saml/metadata",
		ID:            "_af805d1c-c2e3-444e-9cf5-efc664eeace6",
		ValidUntil:    time.Date(2001, time.February, 3, 4, 5, 6, 789000000, time.UTC),
		CacheDuration: time.Hour,
		SPSSODescriptors: []SPSSODescriptor{
			{
				XMLName: xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:metadata", Local: "SPSSODescriptor"},
				SSODescriptor: SSODescriptor{
					RoleDescriptor: RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
					},
				},
				AuthnRequestsSigned:  &False,
				WantAssertionsSigned: &False,
				AssertionConsumerServices: []IndexedEndpoint{
					{
						Binding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
						Location:  "https://dev.aa.kndr.org/users/auth/saml/callback",
						Index:     0,
						IsDefault: &True,
					},
				},
				AttributeConsumingServices: []AttributeConsumingService{
					{
						Index:        1,
						IsDefault:    &True,
						ServiceNames: []LocalizedName{{Lang: "en", Value: "Required attributes"}},
						RequestedAttributes: []RequestedAttribute{
							{
								Attribute: Attribute{
									FriendlyName: "Email address",
									Name:         "email",
									NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
								},
							},
							{
								Attribute: Attribute{
									FriendlyName: "Full name",
									Name:         "name",
									NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
								},
							},
							{
								Attribute: Attribute{
									FriendlyName: "Given name",
									Name:         "first_name",
									NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
								},
							},
							{
								Attribute: Attribute{
									FriendlyName: "Family name",
									Name:         "last_name",
									NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
								},
							},
						},
					},
				},
			},
		},
	}
	assert.Check(t, is.DeepEqual(expected, metadata))

}

func TestCanProduceSPMetadata(t *testing.T) {
	validUntil, _ := time.Parse("2006-01-02T15:04:05.000000", "2013-03-10T00:32:19.104000")
	AuthnRequestsSigned := true
	WantAssertionsSigned := true
	metadata := EntityDescriptor{
		EntityID:      "http://localhost:5000/e087a985171710fb9fb30f30f41384f9/saml2/metadata/",
		ValidUntil:    validUntil,
		CacheDuration: time.Hour,
		SPSSODescriptors: []SPSSODescriptor{
			{
				AuthnRequestsSigned:  &AuthnRequestsSigned,
				WantAssertionsSigned: &WantAssertionsSigned,
				SSODescriptor: SSODescriptor{
					RoleDescriptor: RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors: []KeyDescriptor{
							{
								Use: "encryption",
								KeyInfo: KeyInfo{
									X509Data: X509Data{
										X509Certificates: []X509Certificate{
											{
												Data: `MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UE
CAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoX
DTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28x
EjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308
kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTv
SPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gf
nqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90Dv
TLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+
cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==`,
											},
										},
									},
								},
							},
							{
								Use: "signing",
								KeyInfo: KeyInfo{
									X509Data: X509Data{
										X509Certificates: []X509Certificate{
											{
												Data: `MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UE
CAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoX
DTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28x
EjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308
kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTv
SPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gf
nqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90Dv
TLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+
cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==`,
											},
										},
									},
								},
							},
						},
					},

					SingleLogoutServices: []Endpoint{{
						Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
						Location: "http://localhost:5000/e087a985171710fb9fb30f30f41384f9/saml2/ls/",
					}},
				},

				AssertionConsumerServices: []IndexedEndpoint{{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: "http://localhost:5000/e087a985171710fb9fb30f30f41384f9/saml2/ls/",
					Index:    1,
				}},
			},
		},
	}

	buf, err := xml.MarshalIndent(metadata, "", "  ")
	assert.Check(t, err)
	golden.Assert(t, string(buf), "TestCanProduceSPMetadata_expected")
}

func TestMetadataValidatesUrlSchemeForProtocolBinding(t *testing.T) {
	buf := golden.Get(t, "TestMetadataValidatesUrlSchemeForProtocolBinding_metadata.xml")

	metadata := EntityDescriptor{}
	err := xml.Unmarshal(buf, &metadata)
	assert.Error(t, err, "invalid url scheme \"javascript\" for binding \"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"")
}

func TestEncryptionMethodKeepsItsParameters(t *testing.T) {
	const metadata = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
	xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
	xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
	xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" entityID="https://sp.example.com/saml2/metadata">
	<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
		<md:KeyDescriptor use="encryption">
			<ds:KeyInfo><ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
			<md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"><xenc:KeySize>256</xenc:KeySize></md:EncryptionMethod>
			<md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep">
				<xenc:OAEPparams>9lWu3Q==</xenc:OAEPparams>
				<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
				<xenc11:MGF Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/>
			</md:EncryptionMethod>
			<md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">
				<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
			</md:EncryptionMethod>
			<md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
		</md:KeyDescriptor>
		<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml2/acs" index="1"/>
	</md:SPSSODescriptor>
</md:EntityDescriptor>`

	want := []EncryptionMethod{
		{Algorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm", KeySize: 256},
		{
			Algorithm:    "http://www.w3.org/2009/xmlenc11#rsa-oaep",
			OAEPParams:   "9lWu3Q==",
			DigestMethod: &DigestMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256"},
			MGF:          &MGF{Algorithm: "http://www.w3.org/2009/xmlenc11#mgf1sha256"},
		},
		{
			Algorithm:    "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
			DigestMethod: &DigestMethod{Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1"},
		},
		{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
	}

	var parsed EntityDescriptor
	assert.NilError(t, xml.Unmarshal([]byte(metadata), &parsed))
	assert.Check(t, is.DeepEqual(want, parsed.SPSSODescriptors[0].KeyDescriptors[0].EncryptionMethods))

	// The parameters are marshalled in the namespaces they were parsed from, so that they survive a round trip.
	buf, err := xml.Marshal(parsed)
	assert.NilError(t, err)
	var again EntityDescriptor
	assert.NilError(t, xml.Unmarshal(buf, &again))
	assert.Check(t, is.DeepEqual(want, again.SPSSODescriptors[0].KeyDescriptors[0].EncryptionMethods))
	for _, fragment := range []string{
		`<KeySize xmlns="http://www.w3.org/2001/04/xmlenc#">256</KeySize>`,
		`<OAEPparams xmlns="http://www.w3.org/2001/04/xmlenc#">9lWu3Q==</OAEPparams>`,
		`<DigestMethod xmlns="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></DigestMethod>`,
		`<MGF xmlns="http://www.w3.org/2009/xmlenc11#" Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"></MGF>`,
		`<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"></EncryptionMethod>`,
	} {
		assert.Check(t, is.Contains(string(buf), fragment))
	}
}

func TestEncryptionMethodIgnoresParametersInOtherNamespaces(t *testing.T) {
	const keyDescriptor = `<KeyDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" use="encryption">
		<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">
			<DigestMethod xmlns="urn:example:other" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
		</EncryptionMethod>
	</KeyDescriptor>`

	var parsed KeyDescriptor
	assert.NilError(t, xml.Unmarshal([]byte(keyDescriptor), &parsed))
	assert.Check(t, is.DeepEqual([]EncryptionMethod{{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"}}, parsed.EncryptionMethods))
}
