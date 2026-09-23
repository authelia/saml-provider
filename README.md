# SAML

[![](https://godoc.org/authelia.com/provider/saml?status.svg)](http://godoc.org/authelia.com/provider/saml)

![Build Status](https://authelia.com/provider/saml/actions/workflows/test.yml/badge.svg)

Package saml contains a partial implementation of the SAML standard in golang.
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

## Getting Started as a Service Provider

Let us assume we have a simple web application to protect. We'll modify this application so it uses SAML to 
authenticate users.

```golang
package main

import (
    "fmt"
    "net/http"
)

func hello(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello, World!")
}

func main() {
    app := http.HandlerFunc(hello)
    http.Handle("/hello", app)
    http.ListenAndServe(":8000", nil)
}
```

Each service provider must have an self-signed X.509 key pair established. You can generate your own with something 
like this:

    openssl req -x509 -newkey rsa:2048 -keyout myservice.key -out myservice.cert -days 365 -nodes -subj "/CN=myservice.example.com"

We will use `samlsp.Middleware` to wrap the endpoint we want to protect. Middleware provides both an `http.Handler` to
serve the SAML specific URLs **and** a set of wrappers to require the user to be logged in. We also provide the URL
where the service provider can fetch the metadata from the IDP at startup. In our case, we'll use [samltest.id](https://samltest.id/), an
identity provider designed for testing.

```golang
package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"

	"authelia.com/provider/saml/samlsp"
)

func hello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %s!", samlsp.AttributeFromContext(r.Context(), "displayName"))
}

func main() {
	keyPair, err := tls.LoadX509KeyPair("myservice.cert", "myservice.key")
	if err != nil {
		panic(err) // TODO handle error
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err) // TODO handle error
	}

	idpMetadataURL, err := url.Parse("https://samltest.id/saml/idp")
	if err != nil {
		panic(err) // TODO handle error
	}
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		panic(err) // TODO handle error
	}

	rootURL, err := url.Parse("http://localhost:8000")
	if err != nil {
		panic(err) // TODO handle error
	}

	samlSP, _ := samlsp.New(samlsp.Options{
		URL:            *rootURL,
		Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:    keyPair.Leaf,
		IDPMetadata: idpMetadata,
	})
	app := http.HandlerFunc(hello)
	http.Handle("/hello", samlSP.RequireAccount(app))
	http.Handle("/saml/", samlSP)
	http.ListenAndServe(":8000", nil)
}
```

Next we'll have to register our service provider with the identity provider to establish trust from the service provider
to the IDP. For [samltest.id](https://samltest.id/), you can do something like:

    mdpath=saml-test-$USER-$HOST.xml
    curl localhost:8000/saml/metadata > $mdpath

Navigate to https://samltest.id/upload.php and upload the file you fetched.

Now you should be able to authenticate. The flow should look like this:

1. You browse to `localhost:8000/hello`
2. The middleware redirects you to `https://samltest.id/idp/profile/SAML2/Redirect/SSO`
3. samltest.id prompts you for a username and password.
4. samltest.id returns you an HTML document which contains an HTML form setup to POST to `localhost:8000/saml/acs`. The
   form is automatically submitted if you have javascript enabled. 
5. The local service validates the response, issues a session cookie, and redirects you to the original URL,
   `localhost:8000/hello`. 
6. This time when `localhost:8000/hello` is requested there is a valid session and so the main content is served.

## Getting Started as an Identity Provider

Please see `example/idp/` for a substantially complete example of how to use the library and helpers to be an identity 
provider.

## Support

The SAML standard is huge and complex with many dark corners and strange, unused features. This package implements the 
most commonly used subset of these features required to provide a single sign on experience. The package supports at 
least the subset of SAML known as [interoperable SAML](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html).

This package supports the **Web SSO** profile. Message flows from the service provider to the IDP are supported using 
the **HTTP Redirect** binding and the **HTTP POST** binding. Message flows from the IDP to the service provider are
supported via the **HTTP POST** binding.

The package can produce signed SAML assertions, and can validate both signed and encrypted SAML assertions.

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
  [text](spec/saml-core-2.0-os.txt)).
- SAMLBindings defines the details of the HTTP requests in play
  ([PDF](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf),
  [text](spec/saml-bindings-2.0-os.txt)).
- SAMLProfiles describes data flows
  ([PDF](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf),
  [text](spec/saml-profiles-2.0-os.txt)).
- SAMLMetadata defines the metadata format used to describe entities
  ([PDF](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf),
  [text](spec/saml-metadata-2.0-os.txt)).
- SAMLAuthnContext defines the authentication context classes
  ([PDF](https://docs.oasis-open.org/security/saml/v2.0/saml-authn-context-2.0-os.pdf),
  [text](spec/saml-authn-context-2.0-os.txt)).
- SAMLConformance includes a support matrix for various parts of the protocol
  ([PDF](https://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf),
  [text](spec/saml-conformance-2.0-os.txt)).
- SAMLSecurity covers security and privacy considerations
  ([PDF](https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf),
  [text](spec/saml-sec-consider-2.0-os.txt)).
- SAMLGloss is the glossary of terms
  ([PDF](https://docs.oasis-open.org/security/saml/v2.0/saml-glossary-2.0-os.pdf),
  [text](spec/saml-glossary-2.0-os.txt)).
- SAML V2.0 Errata 05 amends all of the above
  ([PDF](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.pdf),
  [text](spec/saml-v2.0-errata05-os.txt)).
- SAML V2.0 Technical Overview is a non-normative introduction
  ([PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.pdf),
  [text](spec/sstc-saml-tech-overview-2.0.txt)).

Extensions and profiles published after SAML V2.0:

| Specification                                                    | Original                                                                                                                               | Text                                                                 |
|:-----------------------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------|:---------------------------------------------------------------------|
| Metadata Interoperability Profile                                | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-metadata-iop-os.pdf)                                                      | [text](spec/sstc-metadata-iop-os.txt)                                |
| Metadata Extension for Entity Attributes                         | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-metadata-attr-cs-01.pdf)                                                  | [text](spec/sstc-metadata-attr-cs-01.txt)                            |
| Metadata Extensions for Login and Discovery User Interface       | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-ui/v1.0/os/sstc-saml-metadata-ui-v1.0-os.pdf)               | [text](spec/sstc-saml-metadata-ui-v1.0-os.txt)                       |
| Metadata Extensions for Registration and Publication Info        | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/saml-metadata-rpi/v1.0/cs01/saml-metadata-rpi-v1.0-cs01.pdf)                   | [text](spec/saml-metadata-rpi-v1.0-cs01.txt)                         |
| Metadata Profile for Algorithm Support                           | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-algsupport-v1.0-cs01.pdf)                                   | [text](spec/sstc-saml-metadata-algsupport-v1.0-cs01.txt)             |
| Metadata Extension for SAML V2.0 and V1.x Query Requesters       | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-ext-query-os.pdf)                                           | [text](spec/sstc-saml-metadata-ext-query-os.txt)                     |
| HTTP POST "SimpleSign" Binding                                   | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cs-01.pdf)                                        | [text](spec/sstc-saml-binding-simplesign-cs-01.txt)                  |
| Service Provider Request Initiation Protocol and Profile         | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-request-initiation-cs-01.pdf)                                             | [text](spec/sstc-request-initiation-cs-01.txt)                       |
| Identity Provider Discovery Service Protocol and Profile         | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-idp-discovery-cs-01.pdf)                                             | [text](spec/sstc-saml-idp-discovery-cs-01.txt)                       |
| Asynchronous Single Logout Profile Extension                     | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/saml-async-slo/v1.0/cs01/saml-async-slo-v1.0-cs01.pdf)                         | [text](spec/saml-async-slo-v1.0-cs01.txt)                            |
| Enhanced Client or Proxy (ECP) Profile Version 2.0               | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/saml-ecp/v2.0/cs01/saml-ecp-v2.0-cs01.pdf)                                     | [text](spec/saml-ecp-v2.0-cs01.txt)                                  |
| Channel Binding Extensions                                       | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/saml-channel-binding-ext/v1.0/cs01/saml-channel-binding-ext-v1.0-cs01.pdf)     | [text](spec/saml-channel-binding-ext-v1.0-cs01.txt)                  |
| Holder-of-Key Assertion Profile                                  | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml2-holder-of-key-cs-02.pdf)                                            | [text](spec/sstc-saml2-holder-of-key-cs-02.txt)                      |
| Holder-of-Key Web Browser SSO Profile                            | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-holder-of-key-browser-sso-cs-02.pdf)                                 | [text](spec/sstc-saml-holder-of-key-browser-sso-cs-02.txt)           |
| Condition for Delegation Restriction                             | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-delegation-cs-01.pdf)                                                | [text](spec/sstc-saml-delegation-cs-01.txt)                          |
| Identity Assurance Profiles                                      | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-assurance-profile-cs-01.pdf)                                         | [text](spec/sstc-saml-assurance-profile-cs-01.txt)                   |
| Session Token Profile                                            | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/saml-session-token/v1.0/cs01/saml-session-token-v1.0-cs01.pdf)                 | [text](spec/saml-session-token-v1.0-cs01.txt)                        |
| Change Notify Protocol                                           | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml2-notify-protocol/v1.0/cs01/sstc-saml2-notify-protocol-v1.0-cs01.pdf) | [text](spec/sstc-saml2-notify-protocol-v1.0-cs01.txt)                |
| Attribute Extensions                                             | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-attribute-ext-cs-01.pdf)                                             | [text](spec/sstc-saml-attribute-ext-cs-01.txt)                       |
| Attribute Predicate Profile                                      | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-attr-predicate/v1.0/cs01/sstc-saml-attr-predicate-v1.0-cs01.pdf)     | [text](spec/sstc-saml-attr-predicate-v1.0-cs01.txt)                  |
| X.500/LDAP Attribute Profile                                     | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-attribute-x500-cs-01.pdf)                                            | [text](spec/sstc-saml-attribute-x500-cs-01.txt)                      |
| Attribute Sharing Profile for X.509 Authentication-Based Systems | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-x509-authn-attrib-profile-cs-01.pdf)                                 | [text](spec/sstc-saml-x509-authn-attrib-profile-cs-01.txt)           |
| Deployment Profiles for X.509 Subjects                           | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml2-profiles-deploy-x509-cs-01.pdf)                                     | [text](spec/sstc-saml2-profiles-deploy-x509-cs-01.txt)               |
| Kerberos Attribute Profile                                       | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-attribute-kerberos-cs01.pdf)                                         | [text](spec/sstc-saml-attribute-kerberos-cs01.txt)                   |
| Kerberos Subject Confirmation Method                             | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-kerberos-subject-confirmation-method-cs01.pdf)                       | [text](spec/sstc-saml-kerberos-subject-confirmation-method-cs01.txt) |
| Kerberos Web Browser SSO Profile                                 | [PDF](https://docs.oasis-open.org/security/saml/Post2.0/saml-kerberos-browser-sso/v1.0/cs01/saml-kerberos-browser-sso-v1.0-cs01.pdf)   | [text](spec/saml-kerberos-browser-sso-v1.0-cs01.txt)                 |
