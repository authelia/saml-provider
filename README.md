# SAML

[![](https://godoc.org/authelia.com/provider/saml?status.svg)](http://godoc.org/authelia.com/provider/saml)

[![Build Status](https://github.com/authelia/saml-provider/actions/workflows/go.yml/badge.svg)](https://github.com/authelia/saml-provider/actions/workflows/go.yml)
[![codecov](https://codecov.io/github/authelia/saml-provider/graph/badge.svg)](https://codecov.io/github/authelia/saml-provider)

Package saml contains an implementation of the SAML / SAML 2.0 standard in golang.

SAML is a standard for identity federation, i.e. either allowing a third party to authenticate your users or allowing
third parties to rely on us to authenticate their users.

## Introduction

In SAML parlance an **Identity Provider** (IdP) is a service that knows how to authenticate users. A 
**Service Provider** (SP) is a service that delegates authentication to an IDP. If you are building a service where
users log in with someone else's credentials, then you are a **Service Provider**. This package supports implementing 
both service providers and identity providers.

The core package contains the implementation of SAML. The package samlsp provides helper middleware suitable for use in 
Service Provider applications. The package samlidp provides a rudimentary IDP service that is useful for testing or as 
a starting point for other integrations.

## Support

The SAML standard is huge and complex with many dark corners and strange, unused features. This package implements the 
most commonly used subset of these features required to provide a single sign on experience. The package supports at 
least the subset of SAML known as [interoperable SAML](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html).

### Support Matrix

| Symbol | Meaning                                                  |
|:------:|:---------------------------------------------------------|
|   ✅   | Full: supported                                          |
|   ⚠️   | Partial: supported with limitations, see the notes below |
|   ❌   | None: not supported                                      |
|  N/A   | Not applicable to this role                              |

#### Profiles

| Feature                                     | IdP | SP |
|:--------------------------------------------|:---:|:--:|
| Web Browser SSO (SP-initiated)              | ✅  | ✅ |
| Web Browser SSO (IdP-initiated/unsolicited) | ✅  | ✅ |
| Single Logout                               | ❌  | ⚠️ |
| Artifact Resolution                         | ❌  | ✅ |
| Enhanced Client or Proxy (ECP)              | ❌  | ❌ |
| Holder-of-Key Web Browser SSO               | ❌  | ❌ |
| Name Identifier Management                  | ❌  | ❌ |
| Name Identifier Mapping                     | ❌  | ❌ |
| Assertion Query/Request and Attribute Query | ❌  | ❌ |
| Identity Provider Discovery                 | ❌  | ❌ |
| SP Request Initiation                       | N/A | ❌ |

#### Bindings

| Feature                        | IdP | SP |
|:-------------------------------|:---:|:--:|
| HTTP Redirect (`AuthnRequest`) | ✅  | ✅ |
| HTTP POST (`AuthnRequest`)     | ✅  | ✅ |
| HTTP POST (`Response`)         | ✅  | ✅ |
| HTTP Artifact (`Response`)     | ❌  | ✅ |
| SOAP                           | ❌  | ⚠️ |
| HTTP POST "SimpleSign"         | ❌  | ❌ |
| Reverse SOAP (PAOS)            | ❌  | ❌ |

#### Protocol

| Feature                                           | IdP | SP  |
|:--------------------------------------------------|:---:|:---:|
| `AssertionConsumerServiceURL` / `Index` selection | ✅  | N/A |
| `RelayState`                                      | ✅  | ✅  |
| `NameIDPolicy`                                    | ⚠️  | ✅  |
| `ForceAuthn` / `IsPassive`                        | ⚠️  | ✅  |
| `RequestedAuthnContext`                           | ⚠️  | ✅  |
| `Scoping` (proxying)                              | ❌  | ❌  |
| Error status responses                            | ❌  | ✅  |
| Multiple assertions in a single `Response`        | N/A | ⚠️  |
| Replay detection                                  | ❌  | ⚠️  |

#### Signing and Encryption

| Feature                                      | IdP | SP  |
|:---------------------------------------------|:---:|:---:|
| Sign `Response` and `Assertion`              | ✅  | N/A |
| Verify signed `Response` and `Assertion`     | N/A | ✅  |
| Sign `AuthnRequest`                          | N/A | ✅  |
| Verify signed `AuthnRequest`                 | ❌  | N/A |
| RSA and ECDSA signatures (SHA-1/256/384/512) | ✅  | ✅  |
| Encrypt `Assertion`                          | ⚠️  | N/A |
| Decrypt `EncryptedAssertion`                 | N/A | ⚠️  |
| `EncryptedID` and `EncryptedAttribute`       | ❌  | ❌  |

#### Metadata

| Feature                      | IdP | SP |
|:-----------------------------|:---:|:--:|
| Publish own metadata         | ✅  | ✅ |
| Consume `EntityDescriptor`   | ✅  | ✅ |
| Consume `EntitiesDescriptor` | N/A | ⚠️ |
| Sign published metadata      | ❌  | ❌ |
| Verify metadata signatures   | ❌  | ❌ |

### Identity Provider Limitations

- **Single Logout:** there is no SLO endpoint. Setting `IdentityProvider.LogoutURL` only advertises an HTTP Redirect
  `SingleLogoutService` in the metadata; `LogoutRequest` and `LogoutResponse` messages are neither handled nor sent.
- **Artifact Resolution, HTTP Artifact and SOAP:** responses are only ever delivered via HTTP POST, and there is no
  `ArtifactResolutionService`.
- **Verify signed `AuthnRequest`:** request signatures are ignored. Metadata never sets `WantAuthnRequestsSigned`, and
  a request is rejected outright if it does.
- **`NameIDPolicy`:** the requested format is ignored. The `NameID` format comes from `Session.NameIDFormat` and
  defaults to transient, and the metadata only advertises transient.
- **`ForceAuthn` / `IsPassive`:** not enforced by the library. The parsed request is passed to
  `SessionProvider.GetSession`, so enforcing them is left to the implementation.
- **`RequestedAuthnContext`:** ignored by `DefaultAssertionMaker`, which always asserts
  `PasswordProtectedTransport`. A custom `AssertionMaker` can set a different context.
- **Error status responses:** failures produce an HTTP error rather than a SAML `Response` carrying a non-success
  status.
- **Replay detection:** `AuthnRequest` IDs are not checked for reuse.
- **Encrypt `Assertion`:** encryption always uses AES-128-CBC with RSA-OAEP-MGF1P (SHA-1), regardless of the
  `EncryptionMethod` the SP advertises, and cannot be configured.
- **Signature defaults:** `SignatureMethod` defaults to RSA-SHA1; set it explicitly to use a stronger algorithm.

### Service Provider Limitations

- **Single Logout:** `LogoutRequest` messages can be created and sent (HTTP Redirect or HTTP POST) and `LogoutResponse`
  messages can be validated, however:
  - Incoming `LogoutRequest` messages (IdP-initiated logout) cannot be parsed or validated.
  - `samlsp.Middleware` does not serve the SLO endpoint.
  - HTTP Redirect messages are signed with an embedded XML signature rather than the `SigAlg` and `Signature` query
    parameters the binding requires, and received HTTP Redirect messages are validated the same way.
- **SOAP:** only used as a client to send `ArtifactResolve`.
- **Multiple assertions in a single `Response`:** only the first valid assertion is returned.
- **Replay detection:** SP-initiated responses must match a tracked request ID, but assertion IDs are not remembered,
  so an unsolicited response accepted with `AllowIDPInitiated` can be replayed until it expires.
- **Decrypt `EncryptedAssertion`:** supported algorithms are AES-128/192/256-CBC, AES-128-GCM and 3DES for content
  and RSA-OAEP-MGF1P for key transport. AES-192/256-GCM and XML Encryption 1.1 RSA-OAEP are not supported by default.
  RSA PKCS#1 v1.5 key transport is disabled by default and can be enabled with
  `xmlenc.RegisterDecrypter(xmlenc.PKCS1v15())`.
- **Consume `EntitiesDescriptor`:** `samlsp.ParseMetadata` uses the first entity that has an `IDPSSODescriptor`; there
  is no way to select a different entity.

## RelayState

The _RelayState_ parameter allows you to pass user state information across the authentication flow. The most common use
for this is to allow a user to request a deep link into your site, be redirected through the SAML login flow, and upon
successful completion, be directed to the originally requested link, rather than the root.

Unfortunately, _RelayState_ is less useful than it could be. Firstly, it is **not** authenticated, so anything you 
supply must be signed to avoid XSS or CSRF. Secondly, it is limited to 80 bytes in length, which precludes signing. (See
section 3.6.3.1 of SAMLProfiles.)

## References

The SAML specification is a collection of PDFs. Each is linked below to the original published by OASIS and to a
plain text conversion kept in [spec](spec).

The core SAML V2.0 standard:

- SAMLCore defines data types
  ([PDF](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf),
  [TXT](spec/saml-core-2.0-os.txt)).
- SAMLBindings defines the details of the HTTP requests in play
  ([PDF](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf),
  [TXT](spec/saml-bindings-2.0-os.txt)).
- SAMLProfiles describes data flows
  ([PDF](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf),
  [TXT](spec/saml-profiles-2.0-os.txt)).
- SAMLMetadata defines the metadata format used to describe entities
  ([PDF](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf),
  [TXT](spec/saml-metadata-2.0-os.txt)).
- SAMLAuthnContext defines the authentication context classes
  ([PDF](https://docs.oasis-open.org/security/saml/v2.0/saml-authn-context-2.0-os.pdf),
  [TXT](spec/saml-authn-context-2.0-os.txt)).
- SAMLConformance includes a support matrix for various parts of the protocol
  ([PDF](https://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf),
  [TXT](spec/saml-conformance-2.0-os.txt)).
- SAMLSecurity covers security and privacy considerations
  ([PDF](https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf),
  [TXT](spec/saml-sec-consider-2.0-os.txt)).
- SAMLGloss is the glossary of terms
  ([PDF](https://docs.oasis-open.org/security/saml/v2.0/saml-glossary-2.0-os.pdf),
  [TXT](spec/saml-glossary-2.0-os.txt)).
- SAML V2.0 Errata 05 amends all of the above
  ([PDF](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.pdf),
  [TXT](spec/saml-v2.0-errata05-os.txt)).
- SAML V2.0 Technical Overview is a non-normative introduction
  ([PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.pdf),
  [TXT](spec/sstc-saml-tech-overview-2.0.txt)).

Extensions and profiles published after SAML V2.0:

| Specification                                                    | Original                                                                                                                               | Text                                                                |
|:-----------------------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------|:--------------------------------------------------------------------|
| Metadata Interoperability Profile                                | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-metadata-iop-os.pdf)                                                      | [TXT](spec/sstc-metadata-iop-os.txt)                                |
| Metadata Extension for Entity Attributes                         | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-metadata-attr-cs-01.pdf)                                                  | [TXT](spec/sstc-metadata-attr-cs-01.txt)                            |
| Metadata Extensions for Login and Discovery User Interface       | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-ui/v1.0/os/sstc-saml-metadata-ui-v1.0-os.pdf)               | [TXT](spec/sstc-saml-metadata-ui-v1.0-os.txt)                       |
| Metadata Extensions for Registration and Publication Info        | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/saml-metadata-rpi/v1.0/cs01/saml-metadata-rpi-v1.0-cs01.pdf)                   | [TXT](spec/saml-metadata-rpi-v1.0-cs01.txt)                         |
| Metadata Profile for Algorithm Support                           | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-algsupport-v1.0-cs01.pdf)                                   | [TXT](spec/sstc-saml-metadata-algsupport-v1.0-cs01.txt)             |
| Metadata Extension for SAML V2.0 and V1.x Query Requesters       | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-ext-query-os.pdf)                                           | [TXT](spec/sstc-saml-metadata-ext-query-os.txt)                     |
| HTTP POST "SimpleSign" Binding                                   | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cs-01.pdf)                                        | [TXT](spec/sstc-saml-binding-simplesign-cs-01.txt)                  |
| Service Provider Request Initiation Protocol and Profile         | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-request-initiation-cs-01.pdf)                                             | [TXT](spec/sstc-request-initiation-cs-01.txt)                       |
| Identity Provider Discovery Service Protocol and Profile         | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-idp-discovery-cs-01.pdf)                                             | [TXT](spec/sstc-saml-idp-discovery-cs-01.txt)                       |
| Asynchronous Single Logout Profile Extension                     | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/saml-async-slo/v1.0/cs01/saml-async-slo-v1.0-cs01.pdf)                         | [TXT](spec/saml-async-slo-v1.0-cs01.txt)                            |
| Enhanced Client or Proxy (ECP) Profile Version 2.0               | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/saml-ecp/v2.0/cs01/saml-ecp-v2.0-cs01.pdf)                                     | [TXT](spec/saml-ecp-v2.0-cs01.txt)                                  |
| Channel Binding Extensions                                       | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/saml-channel-binding-ext/v1.0/cs01/saml-channel-binding-ext-v1.0-cs01.pdf)     | [TXT](spec/saml-channel-binding-ext-v1.0-cs01.txt)                  |
| Holder-of-Key Assertion Profile                                  | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml2-holder-of-key-cs-02.pdf)                                            | [TXT](spec/sstc-saml2-holder-of-key-cs-02.txt)                      |
| Holder-of-Key Web Browser SSO Profile                            | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-holder-of-key-browser-sso-cs-02.pdf)                                 | [TXT](spec/sstc-saml-holder-of-key-browser-sso-cs-02.txt)           |
| Condition for Delegation Restriction                             | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-delegation-cs-01.pdf)                                                | [TXT](spec/sstc-saml-delegation-cs-01.txt)                          |
| Identity Assurance Profiles                                      | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-assurance-profile-cs-01.pdf)                                         | [TXT](spec/sstc-saml-assurance-profile-cs-01.txt)                   |
| Session Token Profile                                            | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/saml-session-token/v1.0/cs01/saml-session-token-v1.0-cs01.pdf)                 | [TXT](spec/saml-session-token-v1.0-cs01.txt)                        |
| Change Notify Protocol                                           | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml2-notify-protocol/v1.0/cs01/sstc-saml2-notify-protocol-v1.0-cs01.pdf) | [TXT](spec/sstc-saml2-notify-protocol-v1.0-cs01.txt)                |
| Attribute Extensions                                             | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-attribute-ext-cs-01.pdf)                                             | [TXT](spec/sstc-saml-attribute-ext-cs-01.txt)                       |
| Attribute Predicate Profile                                      | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-attr-predicate/v1.0/cs01/sstc-saml-attr-predicate-v1.0-cs01.pdf)     | [TXT](spec/sstc-saml-attr-predicate-v1.0-cs01.txt)                  |
| X.500/LDAP Attribute Profile                                     | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-attribute-x500-cs-01.pdf)                                            | [TXT](spec/sstc-saml-attribute-x500-cs-01.txt)                      |
| Attribute Sharing Profile for X.509 Authentication-Based Systems | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-x509-authn-attrib-profile-cs-01.pdf)                                 | [TXT](spec/sstc-saml-x509-authn-attrib-profile-cs-01.txt)           |
| Deployment Profiles for X.509 Subjects                           | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml2-profiles-deploy-x509-cs-01.pdf)                                     | [TXT](spec/sstc-saml2-profiles-deploy-x509-cs-01.txt)               |
| Kerberos Attribute Profile                                       | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-attribute-kerberos-cs01.pdf)                                         | [TXT](spec/sstc-saml-attribute-kerberos-cs01.txt)                   |
| Kerberos Subject Confirmation Method                             | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-kerberos-subject-confirmation-method-cs01.pdf)                       | [TXT](spec/sstc-saml-kerberos-subject-confirmation-method-cs01.txt) |
| Kerberos Web Browser SSO Profile                                 | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/saml-kerberos-browser-sso/v1.0/cs01/saml-kerberos-browser-sso-v1.0-cs01.pdf)   | [TXT](spec/saml-kerberos-browser-sso-v1.0-cs01.txt)                 |

## Thanks

This is a hard fork of [Ross Kinder's SAML Library](https://github.com/crewjam/saml) under the 
[BSD 2-Clause License](LICENSE) for the purpose of performing self-maintenance of this critical Authelia dependency.

We however:

- Acknowledge the amazing hard work of Ross Kinder and other contributors in making such an amazing library that we can
  do this with.
- Plan to continue to contribute back to te original repository and related projects should Ross return.
- Have ensured the licensing is unchanged in this fork of the library.
- Do not have a formal affiliation with Ross Kinder and individuals utilizing this library should not allow their usage
  to be a reflection on Ross Kinder as this library is not maintained by him and intentionally diverges from the
  original implementation.