package saml

import (
	"crypto/rsa"
	"encoding/xml"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/saml/internal/golden"
)

func TestCanParseMetadata(t *testing.T) {
	buf := golden.Get(t, "TestCanParseMetadata_metadata.xml")

	metadata := EntityDescriptor{}
	err := xml.Unmarshal(buf, &metadata)
	assert.NoError(t, err)

	var (
		False = false
		True  = true
	)

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
	assert.Equal(t, expected, metadata)
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
	assert.NoError(t, err)
	golden.Assert(t, string(buf), "TestCanProduceSPMetadata_expected")
}

func TestMetadataValidatesUrlSchemeForProtocolBinding(t *testing.T) {
	buf := golden.Get(t, "TestMetadataValidatesUrlSchemeForProtocolBinding_metadata.xml")

	metadata := EntityDescriptor{}
	err := xml.Unmarshal(buf, &metadata)
	require.EqualError(t, err, "invalid url scheme \"javascript\" for binding \"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"")
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
	require.NoError(t, xml.Unmarshal([]byte(metadata), &parsed))
	assert.Equal(t, want, parsed.SPSSODescriptors[0].KeyDescriptors[0].EncryptionMethods)

	// The parameters are marshalled in the namespaces they were parsed from, so that they survive a round trip.
	buf, err := xml.Marshal(parsed)
	require.NoError(t, err)

	var again EntityDescriptor
	require.NoError(t, xml.Unmarshal(buf, &again))
	assert.Equal(t, want, again.SPSSODescriptors[0].KeyDescriptors[0].EncryptionMethods)

	for _, fragment := range []string{
		`<KeySize xmlns="http://www.w3.org/2001/04/xmlenc#">256</KeySize>`,
		`<OAEPparams xmlns="http://www.w3.org/2001/04/xmlenc#">9lWu3Q==</OAEPparams>`,
		`<DigestMethod xmlns="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></DigestMethod>`,
		`<MGF xmlns="http://www.w3.org/2009/xmlenc11#" Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"></MGF>`,
		`<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"></EncryptionMethod>`,
	} {
		assert.Contains(t, string(buf), fragment)
	}
}

func TestEncryptionMethodIgnoresParametersInOtherNamespaces(t *testing.T) {
	const keyDescriptor = `<KeyDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" use="encryption">
		<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">
			<DigestMethod xmlns="urn:example:other" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
		</EncryptionMethod>
	</KeyDescriptor>`

	var parsed KeyDescriptor
	require.NoError(t, xml.Unmarshal([]byte(keyDescriptor), &parsed))
	assert.Equal(t, []EncryptionMethod{{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"}}, parsed.EncryptionMethods)
}

// SAMLMeta §2.4.1.1: the use of a KeyDescriptor is optional, and a key with none is for both signing and
// encryption. It is not written as an empty use, which is not a value of the KeyTypes of the schema.
func TestKeyDescriptorWithoutUseRoundTrips(t *testing.T) {
	const in = `<KeyDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` +
		`<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIB</ds:X509Certificate></ds:X509Data></ds:KeyInfo>` +
		`</KeyDescriptor>`

	var keyDescriptor KeyDescriptor

	require.NoError(t, xml.Unmarshal([]byte(in), &keyDescriptor))
	assert.Equal(t, keyDescriptor.Use, "")

	out, err := xml.Marshal(keyDescriptor)
	require.NoError(t, err)
	assert.Equal(t, string(out), `<KeyDescriptor>`+
		`<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data xmlns="http://www.w3.org/2000/09/xmldsig#">`+
		`<X509Certificate xmlns="http://www.w3.org/2000/09/xmldsig#">MIIB</X509Certificate></X509Data></KeyInfo>`+
		`</KeyDescriptor>`)

	// A use that is given is kept.
	keyDescriptor.Use = "signing"

	out, err = xml.Marshal(keyDescriptor)
	require.NoError(t, err)
	assert.Contains(t, string(out), `<KeyDescriptor use="signing">`)
}

// A KeyInfo keeps the names and the RSA key values it is read with, and is not written with an X509Data it never
// had, which may not be empty (XML Signature §4.4.4).
func TestKeyInfoRoundTrips(t *testing.T) {
	const (
		modulus  = "xA7SEU+e0yQH5rm9kbCDN9o3aPIo7HbP7tX6WOocLZAtNfyxSZDU16ksL6WjubafOqNEpcwR3RdFsT7bCqnXPBe5ELh5u4VEy19MzxkXRgrMvavzyBpVRgBUwUlV5foK5hhmbktQhyNdy/6LpQRhDUDsTvK+g9Ucj47es9AQJ3U="
		exponent = "AQAB"
	)

	for _, tc := range []struct {
		name     string
		in       string
		expected KeyInfo
		out      string
	}{
		{
			name:     "key name only",
			in:       `<ds:KeyName>ServiceProvider.com Encrypt Key</ds:KeyName>`,
			expected: KeyInfo{KeyNames: []string{"ServiceProvider.com Encrypt Key"}},
			out:      `<KeyName xmlns="http://www.w3.org/2000/09/xmldsig#">ServiceProvider.com Encrypt Key</KeyName>`,
		},
		{
			name: "key value only",
			in:   `<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>` + modulus + `</ds:Modulus><ds:Exponent>` + exponent + `</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>`,
			expected: KeyInfo{KeyValues: []KeyValue{{RSAKeyValue: &RSAKeyValue{
				Modulus:  modulus,
				Exponent: exponent,
			}}}},
			out: `<KeyValue xmlns="http://www.w3.org/2000/09/xmldsig#"><RSAKeyValue xmlns="http://www.w3.org/2000/09/xmldsig#">` +
				`<Modulus xmlns="http://www.w3.org/2000/09/xmldsig#">` + modulus + `</Modulus>` +
				`<Exponent xmlns="http://www.w3.org/2000/09/xmldsig#">` + exponent + `</Exponent></RSAKeyValue></KeyValue>`,
		},
		{
			name: "every representation, in another order",
			in: `<ds:X509Data><ds:X509Certificate>MIIB</ds:X509Certificate></ds:X509Data>` +
				`<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>` + modulus + `</ds:Modulus><ds:Exponent>` + exponent + `</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>` +
				`<ds:KeyName>one</ds:KeyName><ds:KeyName>two</ds:KeyName>`,
			expected: KeyInfo{
				KeyNames:  []string{"one", "two"},
				KeyValues: []KeyValue{{RSAKeyValue: &RSAKeyValue{Modulus: modulus, Exponent: exponent}}},
				X509Data:  X509Data{X509Certificates: []X509Certificate{{Data: "MIIB"}}},
			},
			out: `<KeyName xmlns="http://www.w3.org/2000/09/xmldsig#">one</KeyName><KeyName xmlns="http://www.w3.org/2000/09/xmldsig#">two</KeyName>` +
				`<KeyValue xmlns="http://www.w3.org/2000/09/xmldsig#"><RSAKeyValue xmlns="http://www.w3.org/2000/09/xmldsig#">` +
				`<Modulus xmlns="http://www.w3.org/2000/09/xmldsig#">` + modulus + `</Modulus>` +
				`<Exponent xmlns="http://www.w3.org/2000/09/xmldsig#">` + exponent + `</Exponent></RSAKeyValue></KeyValue>` +
				`<X509Data xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Certificate xmlns="http://www.w3.org/2000/09/xmldsig#">MIIB</X509Certificate></X509Data>`,
		},
		{
			// A key value of another type is dropped, and with it the KeyValue that would be left empty.
			name: "key value that is not RSA",
			in: `<ds:KeyName>ec</ds:KeyName><ds:KeyValue><dsig11:ECKeyValue xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">` +
				`<dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><dsig11:PublicKey>BA==</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue>`,
			expected: KeyInfo{KeyNames: []string{"ec"}, KeyValues: []KeyValue{{}}},
			out:      `<KeyName xmlns="http://www.w3.org/2000/09/xmldsig#">ec</KeyName>`,
		},
		{
			name:     "nothing",
			expected: KeyInfo{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := `<KeyDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" use="encryption">` +
				`<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` + tc.in + `</ds:KeyInfo></KeyDescriptor>`

			var keyDescriptor KeyDescriptor

			require.NoError(t, xml.Unmarshal([]byte(in), &keyDescriptor))

			actual := keyDescriptor.KeyInfo
			actual.XMLName = xml.Name{}
			actual.X509Data.XMLName = xml.Name{}

			for i := range actual.KeyValues {
				actual.KeyValues[i].XMLName = xml.Name{}
			}

			for i := range actual.X509Data.X509Certificates {
				actual.X509Data.X509Certificates[i].XMLName = xml.Name{}
			}

			assert.Equal(t, actual, tc.expected)

			out, err := xml.Marshal(keyDescriptor)
			require.NoError(t, err)
			assert.Equal(t, string(out), `<KeyDescriptor use="encryption"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">`+tc.out+`</KeyInfo></KeyDescriptor>`)

			// What is written is read as what was kept.
			var again KeyDescriptor

			require.NoError(t, xml.Unmarshal(out, &again))

			reread, err := xml.Marshal(again)
			require.NoError(t, err)
			assert.Equal(t, string(reread), string(out))
		})
	}
}

func TestRSAKeyValuePublicKey(t *testing.T) {
	key := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(0xc5), 2040), E: 65537}

	keyValue := NewRSAKeyValue(key)
	assert.Equal(t, keyValue.RSAKeyValue.Exponent, "AQAB")

	parsed, err := keyValue.RSAKeyValue.PublicKey()
	require.NoError(t, err)
	assert.True(t, key.Equal(parsed))

	// The encoding of a long value is wrapped.
	wrapped := RSAKeyValue{Modulus: "\n  " + keyValue.RSAKeyValue.Modulus[:40] + "\r\n\t" + keyValue.RSAKeyValue.Modulus[40:] + "\n", Exponent: " AQAB "}
	parsed, err = wrapped.PublicKey()
	require.NoError(t, err)
	assert.True(t, key.Equal(parsed))

	for name, tc := range map[string]struct {
		value RSAKeyValue
		err   string
	}{
		"modulus that is not base64":  {RSAKeyValue{Modulus: "!!!", Exponent: "AQAB"}, "Modulus"},
		"exponent that is not base64": {RSAKeyValue{Modulus: keyValue.RSAKeyValue.Modulus, Exponent: "!!!"}, "Exponent"},
		"no modulus":                  {RSAKeyValue{Exponent: "AQAB"}, "Modulus"},
		"zero modulus":                {RSAKeyValue{Modulus: "AA==", Exponent: "AQAB"}, "Modulus"},
		"no exponent":                 {RSAKeyValue{Modulus: keyValue.RSAKeyValue.Modulus}, "Exponent"},
		"exponent of one":             {RSAKeyValue{Modulus: keyValue.RSAKeyValue.Modulus, Exponent: "AQ=="}, "Exponent"},
		"exponent that is too large":  {RSAKeyValue{Modulus: keyValue.RSAKeyValue.Modulus, Exponent: "AQAAAAAAAAAB"}, "Exponent"},
	} {
		t.Run(name, func(t *testing.T) {
			parsed, err := tc.value.PublicKey()
			assert.ErrorContains(t, err, tc.err)
			assert.Nil(t, parsed)
		})
	}
}
