package saml

// The authentication context classes of SAMLAuthnCxt §3.4, for Session.AuthnContextClassRef,
// RequestedAuthnContext.AuthnContextClassRefs and DefaultAuthnContextEnforcer.Strength. The specification gives
// them no order of strength.
//
//nolint:gosec // G101: these are URIs of authentication context classes, not credentials.
const (
	// AuthnContextClassInternetProtocol is the authentication context class of SAMLAuthnCxt §3.4.1.
	AuthnContextClassInternetProtocol = "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol"

	// AuthnContextClassInternetProtocolPassword is the authentication context class of SAMLAuthnCxt §3.4.2.
	AuthnContextClassInternetProtocolPassword = "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword"

	// AuthnContextClassKerberos is the authentication context class of SAMLAuthnCxt §3.4.3.
	AuthnContextClassKerberos = "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos"

	// AuthnContextClassMobileOneFactorUnregistered is the authentication context class of SAMLAuthnCxt §3.4.4.
	AuthnContextClassMobileOneFactorUnregistered = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorUnregistered"

	// AuthnContextClassMobileTwoFactorUnregistered is the authentication context class of SAMLAuthnCxt §3.4.5.
	AuthnContextClassMobileTwoFactorUnregistered = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered"

	// AuthnContextClassMobileOneFactorContract is the authentication context class of SAMLAuthnCxt §3.4.6.
	AuthnContextClassMobileOneFactorContract = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorContract"

	// AuthnContextClassMobileTwoFactorContract is the authentication context class of SAMLAuthnCxt §3.4.7.
	AuthnContextClassMobileTwoFactorContract = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"

	// AuthnContextClassPassword is the authentication context class of SAMLAuthnCxt §3.4.8.
	AuthnContextClassPassword = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"

	// AuthnContextClassPasswordProtectedTransport is the authentication context class of SAMLAuthnCxt §3.4.9.
	AuthnContextClassPasswordProtectedTransport = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

	// AuthnContextClassPreviousSession is the authentication context class of SAMLAuthnCxt §3.4.10.
	AuthnContextClassPreviousSession = "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession"

	// AuthnContextClassX509 is the authentication context class of SAMLAuthnCxt §3.4.11.
	AuthnContextClassX509 = "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"

	// AuthnContextClassPGP is the authentication context class of SAMLAuthnCxt §3.4.12.
	AuthnContextClassPGP = "urn:oasis:names:tc:SAML:2.0:ac:classes:PGP"

	// AuthnContextClassSPKI is the authentication context class of SAMLAuthnCxt §3.4.13.
	AuthnContextClassSPKI = "urn:oasis:names:tc:SAML:2.0:ac:classes:SPKI"

	// AuthnContextClassXMLDSig is the authentication context class of SAMLAuthnCxt §3.4.14.
	AuthnContextClassXMLDSig = "urn:oasis:names:tc:SAML:2.0:ac:classes:XMLDSig"

	// AuthnContextClassSmartcard is the authentication context class of SAMLAuthnCxt §3.4.15.
	AuthnContextClassSmartcard = "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard"

	// AuthnContextClassSmartcardPKI is the authentication context class of SAMLAuthnCxt §3.4.16.
	AuthnContextClassSmartcardPKI = "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"

	// AuthnContextClassSoftwarePKI is the authentication context class of SAMLAuthnCxt §3.4.17.
	AuthnContextClassSoftwarePKI = "urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI"

	// AuthnContextClassTelephony is the authentication context class of SAMLAuthnCxt §3.4.18.
	AuthnContextClassTelephony = "urn:oasis:names:tc:SAML:2.0:ac:classes:Telephony"

	// AuthnContextClassNomadTelephony is the authentication context class of SAMLAuthnCxt §3.4.19.
	AuthnContextClassNomadTelephony = "urn:oasis:names:tc:SAML:2.0:ac:classes:NomadTelephony"

	// AuthnContextClassPersonalTelephony is the authentication context class of SAMLAuthnCxt §3.4.20. The schema
	// listing of that section spells the class PersonalizedTelephony.
	AuthnContextClassPersonalTelephony = "urn:oasis:names:tc:SAML:2.0:ac:classes:PersonalTelephony"

	// AuthnContextClassAuthenticatedTelephony is the authentication context class of SAMLAuthnCxt §3.4.21.
	AuthnContextClassAuthenticatedTelephony = "urn:oasis:names:tc:SAML:2.0:ac:classes:AuthenticatedTelephony"

	// AuthnContextClassSecureRemotePassword is the authentication context class of SAMLAuthnCxt §3.4.22.
	AuthnContextClassSecureRemotePassword = "urn:oasis:names:tc:SAML:2.0:ac:classes:SecureRemotePassword"

	// AuthnContextClassTLSClient is the authentication context class of SAMLAuthnCxt §3.4.23.
	AuthnContextClassTLSClient = "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient"

	// AuthnContextClassTimeSyncToken is the authentication context class of SAMLAuthnCxt §3.4.24.
	AuthnContextClassTimeSyncToken = "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"

	// AuthnContextClassUnspecified is the authentication context class of SAMLAuthnCxt §3.4.25.
	AuthnContextClassUnspecified = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
)
