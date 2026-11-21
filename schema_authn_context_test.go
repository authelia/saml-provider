package saml

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthnContextClassConstants(t *testing.T) {
	const prefix = "urn:oasis:names:tc:SAML:2.0:ac:classes:"

	testCases := []struct {
		constant string
		suffix   string
	}{
		{AuthnContextClassInternetProtocol, "InternetProtocol"},
		{AuthnContextClassInternetProtocolPassword, "InternetProtocolPassword"},
		{AuthnContextClassKerberos, "Kerberos"},
		{AuthnContextClassMobileOneFactorUnregistered, "MobileOneFactorUnregistered"},
		{AuthnContextClassMobileTwoFactorUnregistered, "MobileTwoFactorUnregistered"},
		{AuthnContextClassMobileOneFactorContract, "MobileOneFactorContract"},
		{AuthnContextClassMobileTwoFactorContract, "MobileTwoFactorContract"},
		{AuthnContextClassPassword, "Password"},
		{AuthnContextClassPasswordProtectedTransport, "PasswordProtectedTransport"},
		{AuthnContextClassPreviousSession, "PreviousSession"},
		{AuthnContextClassX509, "X509"},
		{AuthnContextClassPGP, "PGP"},
		{AuthnContextClassSPKI, "SPKI"},
		{AuthnContextClassXMLDSig, "XMLDSig"},
		{AuthnContextClassSmartcard, "Smartcard"},
		{AuthnContextClassSmartcardPKI, "SmartcardPKI"},
		{AuthnContextClassSoftwarePKI, "SoftwarePKI"},
		{AuthnContextClassTelephony, "Telephony"},
		{AuthnContextClassNomadTelephony, "NomadTelephony"},
		{AuthnContextClassPersonalTelephony, "PersonalTelephony"},
		{AuthnContextClassAuthenticatedTelephony, "AuthenticatedTelephony"},
		{AuthnContextClassSecureRemotePassword, "SecureRemotePassword"},
		{AuthnContextClassTLSClient, "TLSClient"},
		{AuthnContextClassTimeSyncToken, "TimeSyncToken"},
		{AuthnContextClassUnspecified, "unspecified"},
	}

	assert.Len(t, testCases, 25)

	seen := map[string]bool{}

	for _, tc := range testCases {
		t.Run(tc.suffix, func(t *testing.T) {
			assert.Equal(t, prefix+tc.suffix, tc.constant)
			assert.False(t, seen[tc.constant], "repeated value")

			seen[tc.constant] = true
		})
	}
}

func TestAuthnContextElement(t *testing.T) {
	full := AuthnContext{
		AuthnContextClassRef: &AuthnContextClassRef{Value: "urn:example:class"},
		AuthnContextDeclRef:  &AuthnContextDeclRef{Value: "urn:example:decl"},
		AuthenticatingAuthorities: []string{
			"https://one.example.com/idp",
			"https://two.example.com/idp",
		},
	}

	testCases := []struct {
		name     string
		have     AuthnContext
		expected string
	}{
		{"ShouldWriteEmpty", AuthnContext{}, `<saml:AuthnContext/>`},
		{
			"ShouldWriteClassOnly",
			AuthnContext{AuthnContextClassRef: full.AuthnContextClassRef},
			`<saml:AuthnContext><saml:AuthnContextClassRef>urn:example:class</saml:AuthnContextClassRef></saml:AuthnContext>`,
		},
		{
			"ShouldWriteDeclarationOnly",
			AuthnContext{AuthnContextDeclRef: full.AuthnContextDeclRef},
			`<saml:AuthnContext><saml:AuthnContextDeclRef>urn:example:decl</saml:AuthnContextDeclRef></saml:AuthnContext>`,
		},
		{
			"ShouldWriteEverythingInSchemaOrder",
			full,
			`<saml:AuthnContext><saml:AuthnContextClassRef>urn:example:class</saml:AuthnContextClassRef><saml:AuthnContextDeclRef>urn:example:decl</saml:AuthnContextDeclRef><saml:AuthenticatingAuthority>https://one.example.com/idp</saml:AuthenticatingAuthority><saml:AuthenticatingAuthority>https://two.example.com/idp</saml:AuthenticatingAuthority></saml:AuthnContext>`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			doc := etree.NewDocument()
			doc.SetRoot(tc.have.Element())

			actual, err := doc.WriteToString()
			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestAuthnContextUnmarshal(t *testing.T) {
	const ns = ` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`

	t.Run("ShouldRoundTripEverything", func(t *testing.T) {
		expected := AuthnContext{
			AuthnContextClassRef: &AuthnContextClassRef{Value: "urn:example:class"},
			AuthnContextDeclRef:  &AuthnContextDeclRef{Value: "urn:example:decl"},
			AuthenticatingAuthorities: []string{
				"https://one.example.com/idp",
				"https://two.example.com/idp",
			},
		}

		doc := etree.NewDocument()
		doc.SetRoot(expected.Element())

		data, err := doc.WriteToString()
		require.NoError(t, err)

		data = strings.Replace(data, "<saml:AuthnContext>", "<saml:AuthnContext"+ns+">", 1)

		var actual AuthnContext

		require.NoError(t, xml.Unmarshal([]byte(data), &actual))
		assert.Equal(t, expected, actual)
	})

	t.Run("ShouldSkipDeclarationByValue", func(t *testing.T) {
		data := `<saml:AuthnContext` + ns + `><saml:AuthnContextClassRef>urn:example:class</saml:AuthnContextClassRef>` +
			`<saml:AuthnContextDecl><ac:AuthenticationContextDeclaration xmlns:ac="urn:oasis:names:tc:SAML:2.0:ac"/></saml:AuthnContextDecl></saml:AuthnContext>`

		var actual AuthnContext

		require.NoError(t, xml.Unmarshal([]byte(data), &actual))
		require.NotNil(t, actual.AuthnContextClassRef)
		assert.Equal(t, "urn:example:class", actual.AuthnContextClassRef.Value)
		assert.Nil(t, actual.AuthnContextDeclRef)
		assert.Empty(t, actual.AuthenticatingAuthorities)
	})
}
