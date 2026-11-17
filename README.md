# SAML

<p>
  <a href="https://pkg.go.dev/authelia.com/provider/saml"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/badge/go-reference-blue.svg?logo=go&logoColor=%2300add8&mode=dark&size=sm&variant=outline"><img alt="Go Reference" src="https://shieldcn.dev/badge/go-reference-blue.svg?logo=go&logoColor=%2300add8&mode=light&size=sm&variant=outline"></picture></a>
  <a href="https://github.com/authelia/saml-provider/actions/workflows/go.yml"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fgithub%2Factions%2Fworkflow%2Fstatus%2Fauthelia%2Fsaml-provider%2Fgo.yml.json%3Fbranch%3Dmaster&query=%24.message&label=build&logo=githubactions&logoColor=%232088ff&mode=dark&size=sm&variant=outline"><img alt="Build" src="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fgithub%2Factions%2Fworkflow%2Fstatus%2Fauthelia%2Fsaml-provider%2Fgo.yml.json%3Fbranch%3Dmaster&query=%24.message&label=build&logo=githubactions&logoColor=%232088ff&mode=light&size=sm&variant=outline"></picture></a>
  <a href="https://github.com/authelia/saml-provider/tags"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fgithub%2Fv%2Ftag%2Fauthelia%2Fsaml-provider.json%3Fsort%3Dsemver&query=%24.message&label=tag&logo=github&logoColor=%23181717&mode=dark&size=sm&variant=outline"><img alt="GitHub Tag" src="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fgithub%2Fv%2Ftag%2Fauthelia%2Fsaml-provider.json%3Fsort%3Dsemver&query=%24.message&label=tag&logo=github&logoColor=%23181717&mode=light&size=sm&variant=outline"></picture></a>
  <a href="https://github.com/authelia/saml-provider/blob/master/go.mod"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fgithub%2Fgo-mod%2Fgo-version%2Fauthelia%2Fsaml-provider.json&query=%24.message&label=go&logo=go&logoColor=%2300add8&mode=dark&size=sm&variant=outline"><img alt="Go Version" src="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fgithub%2Fgo-mod%2Fgo-version%2Fauthelia%2Fsaml-provider.json&query=%24.message&label=go&logo=go&logoColor=%2300add8&mode=light&size=sm&variant=outline"></picture></a>
  <a href="https://codecov.io/gh/authelia/saml-provider"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fcodecov%2Fc%2Fgithub%2Fauthelia%2Fsaml-provider.json&query=%24.message&label=coverage&logo=codecov&logoColor=%23f01f7a&mode=dark&size=sm&variant=outline"><img alt="Codecov" src="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fcodecov%2Fc%2Fgithub%2Fauthelia%2Fsaml-provider.json&query=%24.message&label=coverage&logo=codecov&logoColor=%23f01f7a&mode=light&size=sm&variant=outline"></picture></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/authelia/saml-provider"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fossf-scorecard%2Fgithub.com%2Fauthelia%2Fsaml-provider.json&query=%24.message&label=openssf%20scorecard&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyMzAgMjMwIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxwYXRoIGQ9Ik0xMTgsMiAxMzIsMiAxNDUsNyAxNTYsMTcgMTYzLDM0IDE2MSw1MiAxNDUsNzcgMTM0LDEwNCAxMjksMTIzIDEzNCwxMjUgMTQ2LDEzOSAxNTksMTQxIDE2MywxMzYgMTY2LDEzNiAxODEsMTQ4IDE5NCwxNTMgMjEyLDE1MyAyMTYsMTUxIDIyMSwxNTMgMjI3LDE4NyAyMjUsMjI5IDI3LDIyOSAyNywyMjQgMzUsMjE2IDI0LDE5NCAyNCwxODUgMjcsMTc5IDU0LDE1MCA3MCwxMzkgODMsMTM0IDg2LDEyNSA5OCwxMTggMTAyLDEwNyAxMjAsNzggMTEyLDc1IDg2LDgyIDYxLDgyIDU2LDc4IDU2LDc1IDYzLDY2IDg4LDQ0IDg4LDMxIDk1LDE2IDEwNSw3IDExOCwyWiIvPjwvc3ZnPg%3D%3D&logoColor=%230f3b63&mode=dark&size=sm&variant=outline"><img alt="OpenSSF Scorecard" src="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fossf-scorecard%2Fgithub.com%2Fauthelia%2Fsaml-provider.json&query=%24.message&label=openssf%20scorecard&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyMzAgMjMwIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxwYXRoIGQ9Ik0xMTgsMiAxMzIsMiAxNDUsNyAxNTYsMTcgMTYzLDM0IDE2MSw1MiAxNDUsNzcgMTM0LDEwNCAxMjksMTIzIDEzNCwxMjUgMTQ2LDEzOSAxNTksMTQxIDE2MywxMzYgMTY2LDEzNiAxODEsMTQ4IDE5NCwxNTMgMjEyLDE1MyAyMTYsMTUxIDIyMSwxNTMgMjI3LDE4NyAyMjUsMjI5IDI3LDIyOSAyNywyMjQgMzUsMjE2IDI0LDE5NCAyNCwxODUgMjcsMTc5IDU0LDE1MCA3MCwxMzkgODMsMTM0IDg2LDEyNSA5OCwxMTggMTAyLDEwNyAxMjAsNzggMTEyLDc1IDg2LDgyIDYxLDgyIDU2LDc4IDU2LDc1IDYzLDY2IDg4LDQ0IDg4LDMxIDk1LDE2IDEwNSw3IDExOCwyWiIvPjwvc3ZnPg%3D%3D&logoColor=%230f3b63&mode=light&size=sm&variant=outline"></picture></a>
  <a href="https://github.com/authelia/saml-provider/blob/master/LICENSE"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/github/authelia/saml-provider/license.svg?logo=opensourceinitiative&logoColor=%233da639&mode=dark&size=sm&variant=outline"><img alt="License" src="https://shieldcn.dev/github/authelia/saml-provider/license.svg?logo=opensourceinitiative&logoColor=%233da639&mode=light&size=sm&variant=outline"></picture></a>
</p>

<p align="center">
  <img src=".github/assets/gopher.svg" alt="A Go gopher in front of a shield, presenting a signed SAML assertion scroll sealed with red wax and holding up an encrypted envelope, beneath a federation arc from the identity provider to the service provider" width="280">
</p>

Package saml contains an implementation of the SAML / SAML 2.0 standard in golang.

SAML is a standard for identity federation, i.e. either allowing a third party to authenticate your users or allowing
third parties to rely on us to authenticate their users.

## Introduction

In SAML parlance an **Identity Provider** (IdP) is a service that knows how to authenticate users. A 
**Service Provider** (SP) is a service that delegates authentication to an IDP. If you are building a service where
users log in with someone else's credentials, then you are a **Service Provider**. This package supports implementing 
both service providers and identity providers.

The core package contains the implementation of SAML. The package samlsp provides helper middleware suitable for use in 
Service Provider applications. The package `example/idp/samlidp`, in a separate module, is a rudimentary IDP service
that is useful for testing or as a starting point for other integrations. It is a demo outside the library, which
holds the SAML logic it uses, such as `CheckServiceProviderMetadata`, `CurrentMetadata`, `MatchesSession` and
`ResumeFormValues`.

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
| Single Logout                               | ⚠️  | ⚠️ |
| Artifact Resolution                         | ✅  | ✅ |
| Enhanced Client or Proxy (ECP)              | ⚠️  | ❌ |
| Holder-of-Key Web Browser SSO               | ❌  | ❌ |
| Name Identifier Management                  | ❌  | ❌ |
| Name Identifier Mapping                     | ❌  | ❌ |
| Assertion Query/Request and Attribute Query | ⚠️  | ❌ |
| Identity Provider Discovery                 | ❌  | ❌ |
| SP Request Initiation                       | N/A | ❌ |

#### Bindings

| Feature                        | IdP | SP |
|:-------------------------------|:---:|:--:|
| HTTP Redirect (`AuthnRequest`) | ✅  | ✅ |
| HTTP POST (`AuthnRequest`)     | ✅  | ✅ |
| HTTP POST (`Response`)         | ✅  | ✅ |
| HTTP Artifact (`Response`)     | ✅  | ✅ |
| SOAP                           | ⚠️  | ⚠️ |
| HTTP POST "SimpleSign"         | ❌  | ❌ |
| Reverse SOAP (PAOS)            | ❌  | ❌ |

#### Protocol

| Feature                                           | IdP | SP  |
|:--------------------------------------------------|:---:|:---:|
| `AssertionConsumerServiceURL` / `Index` selection | ✅  | N/A |
| `RelayState`                                      | ✅  | ✅  |
| `NameIDPolicy`                                    | ✅  | ✅  |
| `ForceAuthn` / `IsPassive`                        | ✅  | ✅  |
| `RequestedAuthnContext`                           | ⚠️  | ✅  |
| `AttributeConsumingService` attribute release     | ⚠️  | ❌  |
| `Scoping` (proxying)                              | ❌  | ❌  |
| Error status responses                            | ✅  | ✅  |
| Multiple assertions in a single `Response`        | N/A | ⚠️  |
| Replay detection                                  | ✅  | ⚠️  |

#### Signing and Encryption

| Feature                                      | IdP | SP  |
|:---------------------------------------------|:---:|:---:|
| Sign `Response` and `Assertion`              | ✅  | N/A |
| Verify signed `Response` and `Assertion`     | N/A | ✅  |
| Sign `AuthnRequest`                          | N/A | ✅  |
| Verify signed `AuthnRequest`                 | ✅  | N/A |
| RSA signatures (SHA-1/256/384/512)           | ✅  | ✅  |
| ECDSA signatures (SHA-1/256/384/512)[^ecdsa] | ⚠️  | ⚠️  |
| Encrypt `Assertion`                          | ⚠️  | N/A |
| Decrypt `EncryptedAssertion`                 | N/A | ⚠️  |
| `EncryptedID` and `EncryptedAttribute`       | ⚠️  | ⚠️  |

[^ecdsa]: Signatures use the `r||s` encoding XML Signature requires, and DER signatures are rejected unless
    `SignatureVerifier` is set. ECDSA keys cannot be used for assertion encryption or decryption, which require RSA,
    so metadata does not advertise encryption for an ECDSA certificate. XML signatures are verified against `xmlsec1` 1.3.13
    in both directions, on P-256, P-384 and P-521. Other implementations and HTTP-Redirect signatures have not been tested.

#### Metadata

| Feature                      | IdP | SP |
|:-----------------------------|:---:|:--:|
| Publish own metadata         | ✅  | ✅ |
| Consume `EntityDescriptor`   | ✅  | ✅ |
| Consume `EntitiesDescriptor` | N/A | ⚠️ |
| Sign published metadata      | ❌  | ❌ |
| Verify metadata signatures   | ❌  | ❌ |

### Identity Provider Limitations

- **Single Logout:** the front channel and the SOAP back channel are supported; the Asynchronous Single Logout Profile
  Extension is not. `IdentityProvider.ServeSLO` handles a `LogoutRequest` from an SP on the HTTP Redirect or HTTP POST
  binding at `IdentityProvider.LogoutURL`, and answers with a signed `LogoutResponse`. The request must be signed.
  `IdentityProvider.StartLogout` starts a logout from the IdP (SAMLProfiles §4.4).
  - A `SessionProvider` that implements `SessionParticipantProvider` has every SP that receives an assertion recorded as
    a participant of the session, with the NameID and `SessionIndex` it was given. The participant is recorded each
    time the response is sent, just before it is, by `IdpAuthnRequest.PublishResponse`, which `WriteResponse` calls; a
    caller that sends the form of `PostBinding` itself must send it from `PublishResponse`.
  - `StartLogout`, and a `LogoutRequest` from an SP, send the browser to each participant in turn, with the SP that sent
    the request left out. A participant is sent a signed `LogoutRequest` at its `SingleLogoutService`, HTTP Redirect
    preferred and else HTTP POST, and answers at `IdentityProvider.LogoutURL`. A participant whose only usable
    `SingleLogoutService` is on the SOAP binding is sent its `LogoutRequest` over SOAP instead, during the same
    request, without the browser. The logout state is saved between requests by `LogoutStateProvider`, and expires
    after `IdentityProvider.LogoutStateLifetime` (5 minutes by default). Each save carries the next
    `LogoutState.Revision`, and `SaveLogoutState` must store it only if it follows the stored revision, atomically, so
    that concurrent copies of one response can't overwrite newer progress or recreate a finished logout. The copy that
    loses gets `409 Conflict`.
    It finishes by redirecting to the return URL of `StartLogout`, or with `LogoutResultHandler` if the
    `SessionProvider` implements it, or by sending the SP that started it a `LogoutResponse`. If the state can't be
    saved, the logout still finishes, as partial, so that the browser isn't stranded. Without a working store
    duplicate responses can't be told apart, so the finish may happen more than once.
  - A participant's `LogoutResponse` on the front channel must be signed. One to the outstanding request that is
    invalid or unsigned, or that has a status other than `Success`, or `Success` with a nested `PartialLogout`
    second-level status, counts as not logged out. One that can't be read, or isn't to the outstanding request from
    that participant, such as a replayed response of an earlier participant, is refused with `400 Bad Request` and
    changes nothing. A `LogoutResponse` over SOAP may be unsigned over TLS, and is verified when it is signed (see below); any
    failure of it counts as not logged out.
  - The logout state is found by the `RelayState` alone, without a cookie, so a participant could answer for the
    browser and receive the next participant's `LogoutRequest`. This is an accepted risk of the front channel.
  - A logout begins with `SessionParticipantProvider.CloseSessionParticipants`, which must atomically return the
    participants and stop `AddSessionParticipant` from recording more. A response is only sent once its participant is
    recorded, so no assertion is sent once the logout has begun, and no SP is sent an assertion that the logout won't
    reach. An assertion that was sent before the logout began, but which the browser delivers only after the logout
    has visited its SP, can't be recalled, and is only bounded by its `NotOnOrAfter`. This is inherent to the front
    channel.
  - A session whose participants are closed must no longer be returned by the `SessionProvider`, even if ending it
    fails, so that the user logs in to a new session rather than being refused every assertion.
  - The session at the IdP ends first, by `LogoutSessionProvider.TerminateSession`, before any participant is visited
    (SAMLProfiles §4.4.3.2 leaves the timing to the IdP). An SP that never returns the browser can't be detected, and
    can't leave the user logged in at the IdP.
  - The `LogoutResponse` to an SP that started the logout has a `Responder` status if the session provider can't find
    the sessions (`GetLogoutSessions` fails) or the session didn't end. Otherwise it is `Success`, with a
    `PartialLogout` second-level status (SAMLCore §3.2.2.2) if `TerminateSession` returned `ErrPartialLogout` or any
    participant didn't report success.
  - A participant without a `SingleLogoutService` that is HTTP Redirect, HTTP POST or SOAP and passes the check of
    insecure endpoints is skipped, and counts as not logged out.
  - `StartLogout` and an SP-started logout need a `SessionProvider` that implements all of `LogoutSessionProvider`,
    `SessionParticipantProvider` and `LogoutStateProvider`. Without them a request from an SP is only answered for the
    session at the IdP.
  - `samlidp` ends the session of the browser if the request matches it with `IdpLogoutRequest.MatchesSession(r,
    session)`: the whole NameID (value, Format and qualifiers, none of them omitted) and any session indexes must
    match. `Session.NameID` is only compared when `Session.NameIDFormat` is set. It also matches the NameID that was
    recorded for the requesting SP in a `SessionParticipant`, which is how a transient NameID or one with an
    affiliation is found. Set `IdentityProvider.LogoutNameIDValueOnly` to compare only the value, with
    `Session.NameID` and with the NameID of a `SessionParticipant` of the requesting SP. Its `SameSite=Lax` cookie
    isn't sent with a cross-site POST, so SPs must use HTTP Redirect to end it. `POST /logout/start` calls
    `StartLogout` for the session of the cookie, and refuses with 403 a request that isn't from the same origin, so
    that another site can't log the user out.
  - `IdentityProvider.ServeSOAPLogout` handles a `LogoutRequest` on the SOAP binding at
    `IdentityProvider.SOAPLogoutURL`, which the metadata lists when it is set and the `SessionProvider` implements
    `LogoutSessionProvider`. It may share its path with `LogoutURL`: `Handler` then sends a POST with a `text/xml` body
    to `ServeSOAPLogout` and anything else to `ServeSLO`. The request must
    carry an enveloped signature by its issuer; one that is unsigned or can't be verified is answered
    `Requester/RequestDenied`, a message that isn't a `LogoutRequest` `Requester/RequestUnsupported`, and a request
    that isn't a SOAP 1.1 envelope gets a SOAP fault. The signed `LogoutResponse` is answered on the same connection.
    `TerminateSession` is called without the browser's cookies, and headers it sets are discarded.
  - With a `SessionProvider` that also implements `SessionParticipantProvider`, a SOAP `LogoutRequest` ends the
    session and then logs every other participant out over SOAP, in turn, before it is answered. `LogoutStateProvider`
    is not needed, as nothing is saved. A participant with no SOAP `SingleLogoutService` can't be reached without the
    browser, so it is skipped, and the answer is `Success` with a `PartialLogout` second-level status. The status is
    otherwise as for the front channel.
  - A `LogoutRequest` over SOAP is sent with `IdentityProvider.HTTPClient`, which defaults to a client with a 10 second
    timeout. A client that is set is copied, and the copy never follows a redirect and has the 10 second timeout if
    its `Timeout` is 0. The SP's `LogoutResponse` is verified if it is signed, and may be unsigned only when it comes
    back over TLS on the connection the IdP opened; over plain http, with `AllowInsecureServiceProviderEndpoints`, it
    must be signed. A client whose transport skips certificate verification removes that authentication. One that is a SOAP fault, not HTTP 200, or not `Success` counts as not logged out.
  - Participants are contacted over SOAP one at a time, so a logout can take up to the number of SOAP participants
    times the timeout of `HTTPClient`, and the client of an SP that sent its `LogoutRequest` over SOAP may time out
    first. The outgoing requests are not cancelled when the incoming one is, so the remaining participants are still
    logged out.
  - A SOAP `SingleLogoutService` must be `https`: unlike an endpoint the browser is sent to, an `http` one on a
    loopback host is refused, as the IdP itself would connect to it (`CheckServiceProviderBackChannelEndpoint`).
    `AllowInsecureServiceProviderEndpoints` allows any `http` URL.
- **Enhanced Client or Proxy (ECP):** `IdentityProvider.ServeECP` handles an `AuthnRequest` that a non-browser client
  relays in a SOAP envelope at `IdentityProvider.ECPURL`, and answers on the same connection with the signed `Response`
  in a SOAP envelope, with the `ecp:Response` header block, and `ecp:RequestAuthenticated` when the request's signature
  was verified (SAMLProfiles §4.2, ECP v2.0 §2.3.4 to §2.3.6). The metadata lists a SOAP `SingleSignOnService` when
  `ECPURL` is set and the `SessionProvider` implements `ECPSessionProvider`, and `ECPURL` may share its path with
  `SSOURL`.
  - The principal is authenticated by `ECPSessionProvider.GetECPSession`, typically from HTTP Basic credentials, which
    answers `401` itself when there are none. `GetSession` and browser sessions are not used. `IsPassive` is answered
    `Responder/NoPassive`, and `ForceAuthn` is left to the provider. Once the principal is authenticated the request
    is used up, as for Web SSO: a replay is answered `Requester/RequestDenied`, and the assertion is given to
    `IdentityProvider.AssertionStore`.
  - The `Response` is bound to an `AssertionConsumerService` with the PAOS binding from the SP's metadata, named by the
    request or the default. A request that fails before that endpoint is known, such as one from an unknown SP, with a
    missing or invalid signature, or naming an unlisted ACS, gets a SOAP `Client` fault; later failures are error
    statuses as for Web SSO, in the same envelope. A signed request needs no `Destination`.
  - Only bearer confirmation is supported. Channel bindings are not verified: a request or client that sends
    `cb:ChannelBindings` is answered `Requester/RequestUnsupported`. Holder-of-key confirmation, the delegation
    audience and unsolicited responses with `ecp:RelayState` are not supported. PAOS is only used between the client
    and the SP, so the IdP doesn't speak it.
- **Insecure endpoints:** assertions are bearer tokens, so responses are only sent to an SP endpoint that is `https`, or
  `http` on a loopback host (`localhost`, `*.localhost`, `127.0.0.0/8` or `::1`). This covers the
  `AssertionConsumerService` and the `SingleLogoutService` that receives a `LogoutResponse`. A request that names an
  `http` ACS by URL or index is refused with an HTTP error, and when none is named an `http` endpoint is skipped for a
  secure one, even if it is the default. Set `IdentityProvider.AllowInsecureServiceProviderEndpoints`, or
  `samlidp.Options.AllowInsecureServiceProviderEndpoints`, to allow any `http` URL, only for testing. `samlidp` refuses
  to register an SP whose HTTP-POST ACS endpoints are all refused, using `CheckServiceProviderMetadata`, and the
  identity provider only uses metadata that `CurrentMetadata` finds unexpired.
- **Artifact Resolution and HTTP Artifact:** off unless `IdentityProvider.ArtifactResolutionURL` is set. Then the
  metadata lists the `ArtifactResolutionService` (SOAP, index 0), and an SSO `Response`, error responses included, is
  delivered by artifact when the selected `AssertionConsumerService` has the HTTP Artifact binding: because the request
  names it by index, URL or `ProtocolBinding`, or because it is the default. The browser posts a form to the ACS with
  a type 0x0004 artifact, which keeps it out of URLs, logs and the `Referer` header, or is redirected there with
  `ArtifactRedirectEncoding`, and the SP resolves it at `IdentityProvider.ServeArtifactResolution`.
  - The `ArtifactResolve` must be signed by the SP the response was issued for. Any other request that is understood
    gets a `Success` response with no message, as SAMLCore §3.5.3 requires: unsigned or unverifiable, expired, or for
    an artifact that is unknown, expired, already resolved or issued for another SP. An artifact that another SP
    presents is used up. The `ArtifactResponse` is always signed. The endpoint must be served over TLS.
  - An artifact is single use and lives for `ArtifactLifetime`, one minute by default. The response waits in
    `IdentityProvider.ArtifactStore`, and single use is enforced with `ReplayStore`. Both default to in-memory stores
    that are private to the process, so an IdP which runs as several instances must set stores they share. The
    stored response holds the assertion, which is only encrypted if the SP publishes an encryption key.
  - Only the SSO `Response` is sent by artifact. Logout messages are not, and the IdP does not receive artifacts.
    `samlidp` does not serve the endpoint.
- **Assertion Query/Request and Attribute Query:** `AttributeQuery`, `AuthnQuery` and `AssertionIDRequest` are served
  on the SOAP binding only (SAMLProf §6); the URI binding and `AuthzDecisionQuery` are not supported. Each has its own
  handler and URL: `ServeAttributeQuery` at `IdentityProvider.AttributeServiceURL`, `ServeAuthnQuery` at
  `AuthnQueryServiceURL` and `ServeAssertionIDRequest` at `AssertionIDRequestServiceURL`, and `Handler` serves those
  that are set.
  - The request must carry an enveloped signature by its issuer, as for a `LogoutRequest` over SOAP, and is answered
    on the same connection with a signed `Response`. One that is unsigned or can't be verified is answered
    `Requester/RequestDenied`, another message `Requester/RequestUnsupported`, and a wrong version, age or
    `Destination` the status single sign-on uses. A request that isn't a SOAP 1.1 envelope gets a SOAP fault.
    A request that was already answered is a replay, and is answered `Requester/RequestDenied`.
  - Queries need a `SessionProvider` that implements `QuerySessionProvider`, which finds the principal and its
    sessions by the `NameID` of the query. Without it they are answered `Responder/RequestUnsupported`, and the
    metadata has no `AttributeAuthorityDescriptor` or `AuthnAuthorityDescriptor`. The provider decides which NameIDs
    an SP may ask about, and a transient NameID can only be found if the application stores the ones it issues. The
    `Subject` must be a `NameID` alone: an `EncryptedID`, a `BaseID` or a `SubjectConfirmation` is answered
    `Requester/RequestUnsupported`, a `SPNameQualifier` that isn't the SP or an affiliation it is a member of
    `Requester/RequestDenied`. A principal that isn't found is answered `Success` with no assertion.
  - The assertion carries the `NameID` of the query and no `SubjectConfirmation`, is signed, and is encrypted as for
    single sign-on when the SP has an encryption key. When there is nothing to state the answer is `Success` with no
    assertion (SAMLCore §3.3.4).
  - An `AttributeQuery` is never answered with more than single sign-on would state. The attributes are those of the
    default `AttributeConsumingService` in the SP metadata, narrowed to the attributes and values the query names, so
    an SP whose metadata requests none receives none. `IdentityProvider.AttributeReleasePolicy` decides for queries
    too, and gets an `AttributeReleaseRequest` with that service as `Ceiling` and the attributes of the query as
    `Requested`; whatever it releases is still narrowed to the query. An attribute named twice or without a `Name` is
    answered `Requester/InvalidAttrNameOrValue`.
  - An `AuthnQuery` is answered with one `AuthnStatement` for each session that `GetAuthnSessions` returns, has the
    `SessionIndex` of the query, and satisfies its `RequestedAuthnContext` by `IdentityProvider.AuthnContextEnforcer`.
    Nobody is authenticated by it.
  - An `AssertionIDRequest` needs `IdentityProvider.AssertionStore`, which is given every assertion that single
    sign-on or a query issues, signed and before encryption. Without it the request is answered
    `Responder/RequestUnsupported` and the service isn't in the metadata. An assertion is only returned to the SP it
    was issued to, and at most 32 are returned for one request. `samlidp` implements neither interface.
- **SOAP:** used for single logout, artifact resolution, the assertion query and request protocol and ECP only. The
  URLs of these services may share a path with each other, and with `SSOURL` or `LogoutURL`: `Handler` sends a POST
  with a `text/xml` body to the SOAP service for the message in the `Body` of the envelope, which it reads within the
  64 KiB limit of a SOAP request, and anything else to the front-channel service of the path.
- **Verify signed `AuthnRequest`:** any signature on the HTTP Redirect or HTTP POST bindings is verified, and one is
  required if the SP metadata sets `AuthnRequestsSigned` or `IdentityProvider.WantAuthnRequestsSigned` is set. SHA-1
  signatures are accepted. A custom login form must send `IdpAuthnRequest.RedirectQuery` in the `SAMLRedirectQuery`
  field, because the signature of a redirect does not survive being re-presented as a POST.
- **`NameIDPolicy`:** a request that the assertion can't satisfy receives an `InvalidNameIDPolicy` status. The
  `NameIDProvider` of `IdentityProvider` issues the `NameID`, and `DefaultNameIDProvider` is used if there is none. The
  metadata advertises `NameIDProvider.NameIDFormats`, which is transient by default.
  - A format that the request names is the only one tried. If it leaves the format open (omitted or unspecified), the
    format of the NameID in the request's `Subject` is tried first, if it has one, then the formats of the SP metadata
    that the provider supports in order, then `Session.NameIDFormat`, then transient.
  - `DefaultNameIDProvider` issues `Session.NameID` for the format in `Session.NameIDFormat`, and a random transient
    value, which it doesn't store, for the transient format, even when the session is transient, as the session's NameID
    would be the same for every SP (SAMLCore §8.3.8). It refuses any other format, and never issues the persistent
    format, even for a persistent session: a persistent NameID must be an opaque pseudonym for one SP or affiliation
    (SAMLCore §8.3.7), so an application that issues them needs its own `NameIDProvider`, which must keep them. A
    request that leaves the format open then falls back to transient. A session only needs a `NameID` if its own is
    asserted, and one with a `NameIDFormat` but no `NameID` is refused; no NameID is asserted without a value.
  - Unless the session sets a `NameIDFormat` other than transient or persistent, the default configuration asserts a
    random transient NameID rather than `Session.NameID`, as earlier versions did. If the `SessionProvider` is a
    `SessionParticipantProvider`, the transient NameID last asserted to an SP in the session (with the same
    `SPNameQualifier`) is asserted to it again, so it is usually random once for each SP in each session, and that SP
    receives one `LogoutRequest`. It is only recorded when the response is sent, so concurrent first requests to an SP
    may each receive their own, and that SP is then sent a `LogoutRequest` for each. Without a
    `SessionParticipantProvider` it is random for each assertion. Single logout by such a NameID needs a
    `SessionParticipantProvider`, because `MatchesSession` can only find it in a `SessionParticipant`.
  - `SPNameQualifier` may name an affiliation, which `ServiceProviderProvider` must return with an
    `AffiliationDescriptor` that is unexpired and lists the SP as a member. Otherwise the request is refused. If the
    lookup fails for another reason than that the entity doesn't exist, the status is `Responder`.
  - `AllowCreate` is passed to the provider and isn't checked by default: a provider that issues persistent
    identifiers must check it, and `IdentityProvider.NameIDPolicyEnforcer` can check it, or decide differently for
    each SP.
  - The encrypted format asks for an `EncryptedID` and for no particular identifier (errata E6), so the format is
    chosen as if it were left open, and the request is refused if the SP has no encryption key.
  - A NameID of the entity format is asserted without `NameQualifier`, `SPNameQualifier` or `SPProvidedID`, which
    SAMLCore §8.3.6 requires to be omitted, even if the provider sets them. Logout matches it without them.
- **Error statuses:** `AuthnRequest` and `LogoutRequest` validation has two stages. The first establishes the request is
  from a known SP, and a failure is an HTTP 400 and never an error status, because the response has nowhere trusted to
  go: size, XML, issuer and ID, the SP lookup, the signature (including a signed request with no `Destination`), the ACS
  or SLO endpoint, an `AssertionConsumerServiceIndex` with an `AssertionConsumerServiceURL` or `ProtocolBinding`
  (SAMLCore §3.4.1 makes them mutually exclusive), and for a `LogoutRequest` a missing `NameID` or `EncryptedID`. The second is answered
  to the SP at its endpoint from metadata. A `Version` other than 2.0 is `VersionMismatch`, with `RequestVersionTooHigh`
  or `RequestVersionTooLow` if it is a version number whose major version is above or below 2, and none otherwise (such
  as 2.1 or a version that isn't a number). A request that is expired, issued in the future, past its `NotOnOrAfter` (a
  `LogoutRequest`) or has the wrong `Destination` is `Requester` with `RequestDenied`. The `Destination` of an
  `AuthnRequest` is only checked when `IdentityProvider.WantAuthnRequestsSigned` is set or the request has one. A
  `ProtocolBinding` other than HTTP POST, or HTTP Artifact when `ArtifactResolutionURL` is set, is `Responder` with
  `UnsupportedBinding`, sent to the default endpoint of the metadata with a supported binding, provided any
  `AssertionConsumerServiceURL` of the request is listed there. A failure of `AssertionMaker` is `Responder`, or
  `Requester` with `InvalidNameIDPolicy` if it wraps `ErrInvalidNameIDPolicy`. A failure to sign or encrypt the response
  or to render the template is `Responder`. An application with its own handler gets the same mapping from
  `RequestStatus`, and `WriteResponse` wraps `ErrResponseNotBuilt` when nothing has been written. IdP-initiated SSO has
  no request to answer, so its failures are HTTP errors.
- **`ForceAuthn` / `IsPassive`:** a `SessionProvider` must also implement `ForceAuthnSessionProvider` or
  `PassiveSessionProvider` to serve these requests. Otherwise they receive an `AuthnFailed` or `NoPassive` status.
  `samlidp` implements both, resuming its login form with `IdpAuthnRequest.ResumeFormValues`, and returns `NoPassive`
  if both are set, as it can only authenticate with a login form.
- **`RequestedAuthnContext`:** a request that the assertion can't satisfy receives a `NoAuthnContext` status. The
  `AuthnContextEnforcer` is asked about the class of each `AuthnStatement` with `SatisfiesAuthnContext`.
  `DefaultAssertionMaker` asserts `Session.AuthnContextClassRef`, or `PasswordProtectedTransport` when the session sets
  none, and a custom `AssertionMaker` can set a different class. `minimum`, `maximum` and `better` need `DefaultAuthnContextEnforcer.Strength` to rank classes. Without it,
  `minimum` and `maximum` only match a listed class, and `better` never matches. `AuthnContextDeclRef` is not supported and is always refused. Set
  `IdentityProvider.AuthnContextEnforcer` to decide differently.
- **Request `Subject`:** the assertion must strongly match the subject the request names, or the request receives an
  `AuthnFailed` status. The request must name the principal with a `NameID` of the same value, and the same format,
  qualifiers and `SPProvidedID` where it gives them. If it lists `SubjectConfirmation` elements, the assertion must have
  a bearer confirmation meeting one of them, so a request that only accepts holder-of-key is refused. Set
  `IdentityProvider.SubjectEnforcer` to accept another identifier for the same principal, or the confirmations of a
  custom `AssertionMaker`.
- **Attribute release:** `DefaultAssertionMaker` only states the attributes that the SP requests with the
  `RequestedAttribute` elements of an `AttributeConsumingService` in its metadata, and states none if it requests none,
  so the assertion only carries the `NameID`. The service is the one named by the `AttributeConsumingServiceIndex` of
  the request, or else the default by SAMLMeta §2.4.4 as changed by errata E87. An index that names no service releases
  nothing. A requested attribute matches by `Name`, compared exactly, and a compatible `NameFormat`, where a missing
  format is `unspecified` (errata E89) and `unspecified` matches any format. `FriendlyName` is ignored. If the
  `RequestedAttribute` lists values, only those values are released. An SP may also request the email, common name,
  given name, surname or user name of the user under a name of its own, such as `email` or `first_name`, in the `basic`
  or `unspecified` format, and these are omitted when the session has no value. Set
  `IdentityProvider.AttributeReleasePolicy`, or `samlidp.Options.AttributeReleasePolicy`, to decide differently for
  each SP, for example to release attributes to an SP whose metadata requests none. A custom `AssertionMaker` decides
  for itself. `isRequired` is not enforced.
- **Client address:** assertions state the IP address of the HTTP request. Behind a proxy that is the proxy's address,
  so the `SessionProvider` should set `Session.ClientAddress` to the address of the user.
- **Error status responses:** `IdpAuthnRequest.WriteErrorResponse` sends a SAML `Response` with a non-success status once
  the ACS has been validated, and `Subject`, `NameIDPolicy`, `ForceAuthn`, `IsPassive` and `RequestedAuthnContext`
  refusals use it.
  Other failures produce an HTTP error.
- **Replay detection:** the ID of every `AuthnRequest` that is answered for a session, and of every verified
  `LogoutRequest` on any binding, `AttributeQuery`, `AuthnQuery` and `AssertionIDRequest`, is recorded in `IdentityProvider.ReplayStore` until the request expires, and a
  request presented again is answered with `Requester` and `RequestDenied`. A request that a login form re-presents
  is not a replay. The default store is a bounded `MemoryReplayStore` that is private to the process, so an IdP which
  runs as several instances must set a `ReplayStore` they share. If the store fails or is full the request is refused.
- **Encrypt `Assertion`:** the algorithms are negotiated from the `EncryptionMethod` elements of the SP's encryption
  key, as the Metadata Profile for Algorithm Support §2.5 requires. For content encryption and for key transport
  separately, the first algorithm the SP lists that the IdP allows is used, and if the SP lists algorithms of that
  type but none the IdP allows, the assertion is not sent. Content encryption may use AES-128/192/256-CBC and
  AES-128/192/256-GCM, and key transport RSA-OAEP-MGF1P or XML Encryption 1.1 RSA-OAEP, with the SHA-1, SHA-256 or
  SHA-512 digest and MGF1 hash the SP names in `ds:DigestMethod` and `xenc11:MGF`. An SP that lists nothing of a type
  receives the first the IdP allows, which is AES-128-CBC and RSA-OAEP-MGF1P with SHA-1 by default. Set
  `IdentityProvider.ContentEncryptionMethods`, `KeyTransportMethods` and `KeyTransportDigestMethods` to restrict or
  reorder them. 3DES, RSA PKCS#1 v1.5, key agreement and an OAEP label (`OAEPparams`) are never used, and
  algorithms the IdP doesn't recognise as either type are ignored.
- **`EncryptedID` and `EncryptedAttribute`:** the `NameID` of an assertion is sent as an `EncryptedID` when the
  `NameIDPolicy` has the encrypted format, or when `IdentityProvider.ElementEncryptionPolicy` requires it for the SP,
  and that policy also chooses the attributes sent as `EncryptedAttribute`. `DefaultElementEncryptionPolicy` lists the
  SPs for either, and encrypts nothing by default. They are encrypted before the assertion is signed (SAMLCore §6.2),
  to the key and with the algorithms that **Encrypt `Assertion`** describes, and the assertion is still encrypted as a
  whole afterwards. If one can't be encrypted, no assertion is sent. A `LogoutRequest` may identify the principal with
  an `EncryptedID` on any binding, which is decrypted with `IdentityProvider.Key` after the signature is verified.
  That needs an RSA private key, not only a `Signer`, and the metadata lists an encryption key only then, with the
  algorithms the IdP allows and GCM first. One that can't be decrypted is answered like a `NameID` which names no
  session, with `Success`, so that the answer says nothing about the ciphertext, and the reason is only logged
  (`IdpLogoutRequest.Unidentified`). An SP that was sent an `EncryptedID` is sent one again in the `LogoutRequest` of a
  propagated logout, and is skipped if it can no longer be encrypted to. `BaseID`, an `EncryptedID` that holds
  anything but a `NameID`, and one in the `Subject` of an `AuthnRequest` or of a query are not supported. The answer to
  a query is made like any other assertion, so its `NameID` and attributes are encrypted when the policy says so, and
  `AssertionStore` is given the assertion as it was signed, with those parts encrypted.
- **Signature defaults:** `SignatureMethod` defaults to RSA-SHA256 for RSA keys, and SHA-1 is only used if set explicitly.
  For ECDSA keys it defaults to the hash matching the curve: SHA-256 for P-256, SHA-384 for P-384 and SHA-512 for P-521.
- **SPs with ECDSA certificates:** a service provider whose metadata allows encryption with an ECDSA certificate is
  rejected, including a certificate with no `use`, because assertions cannot be encrypted to it. It must set
  `use="signing"`.
- **SP encryption certificates:** by default the IdP refuses to encrypt to a certificate that is expired or not yet
  valid at the time of the request (allowing `MaxClockSkew`), whose RSA key is shorter than 2048 bits, or whose
  `KeyUsage` extension does not assert `keyEncipherment`. A certificate without a `KeyUsage` extension is accepted. The
  login then fails with an HTTP error, and the assertion is neither sent in plaintext nor encrypted to another key.
  This is a local policy: the SAML V2.0 Metadata Interoperability Profile treats the certificate as a container for the
  key, which may be expired or carry any usage flags. To interoperate with SPs following it, set
  `IdentityProvider.EncryptionCertificateEnforcer` to a `DefaultEncryptionCertificateEnforcer` with
  `IgnoreValidityPeriod`, `IgnoreKeyUsage` or a lower `MinimumRSAKeySize`, each of which relaxes only its own check, or
  to a custom enforcer to decide differently for each SP. With `samlidp`, set it on `Server.IDP`. The certificates
  used to verify signed requests from SPs are not checked.

### Service Provider Limitations

- **Single Logout:** `LogoutRequest` messages can be created and sent (HTTP Redirect or HTTP POST) and `LogoutResponse`
  messages can be validated, however:
  - Incoming `LogoutRequest` messages (IdP-initiated logout) cannot be parsed or validated.
  - `samlsp.Middleware` does not serve the SLO endpoint.
  - The caller must track the IDs of the requests it sends, and pass them when validating a `LogoutResponse`.
  - A received HTTP Redirect `LogoutResponse` may also use an embedded XML signature instead of the `SigAlg` and
    `Signature` query parameters the binding requires. `SignatureVerifier` does not apply to the query parameters.
- **SOAP:** only used as a client to send `ArtifactResolve`.
- **Multiple assertions in a single `Response`:** only the first valid assertion is returned.
- **Replay detection:** SP-initiated responses must match a tracked request ID, but assertion IDs are not remembered,
  so an unsolicited response accepted with `AllowIDPInitiated` can be replayed until it expires.
- **ECDSA signatures:** only the `r||s` form XML Signature requires is accepted, so an IdP which signs in DER fails
  verification unless `SignatureVerifier` is set.
- **Decrypt `EncryptedAssertion`:** supported algorithms are AES-128/192/256-CBC, AES-128/192/256-GCM and 3DES for
  content, and RSA-OAEP-MGF1P and XML Encryption 1.1 RSA-OAEP for key transport, with any MGF1 hash from SHA-1 to
  SHA-512. An OAEP label (`OAEPparams`) is not supported. The SP's metadata advertises AES-128-GCM, AES-128/192/256-CBC
  and RSA-OAEP-MGF1P.
  RSA PKCS#1 v1.5 key transport is disabled by default and can be enabled with
  `xmlenc.RegisterDecrypter(xmlenc.PKCS1v15())`.
- **`EncryptedID` and `EncryptedAttribute`:** an `EncryptedID` in the `Subject` or a `SubjectConfirmation` and every
  `EncryptedAttribute` of an assertion are decrypted after its signature is verified, with the algorithms of
  **Decrypt `EncryptedAssertion`**, so the `Assertion` returned is the same as for plaintext. The `EncryptedKey` may be
  inside the `EncryptedData` or beside it (errata E43). An `EncryptedID` must hold a `NameID`. Set
  `ServiceProvider.EncryptNameID`, or `samlsp.Options.EncryptNameID`, to request the encrypted format and to send the
  `NameID` of a `LogoutRequest` as an `EncryptedID`, encrypted to the IdP's encryption key. `AuthnNameIDFormat` is then
  only listed in metadata. `ServiceProvider.DecryptNameID` decrypts the `EncryptedID` of a `LogoutRequest` that the
  application has received and verified.
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