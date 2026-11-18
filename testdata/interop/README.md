# Interop fixtures

These fixtures show that the identity provider works with an independent SAML implementation, pysaml2, and not
only with the service provider of this module, which shares its code and could share its mistakes.

## What they prove

The proof runs in two directions.

**pysaml2 to us.** pysaml2 wrote the service provider metadata in `sp/metadata` and the requests in
`sp/requests`, and `manifest.json` lists every case. `TestInterop` in `interop_test.go` replays each request
against the identity provider, with the clock stopped at the instant the fixtures were made, and asserts what the
case's `expect` says of the response. It needs nothing but Go, so `go test ./...` runs it on every change.

**Us to pysaml2.** The responses of the identity provider have random IDs, keys and nonces, so they are not
committed. `generate.sh` has `TestInterop` write them to a scratch directory and then runs `pysaml2/verify.py`,
which parses each with pysaml2 as the service provider: it verifies the signatures, decrypts what is encrypted, and
checks what the case's `verify` lists. This direction only runs when `generate.sh` is run.

## Regenerating

Run `testdata/interop/generate.sh` from anywhere in the repository. It needs Docker and Go. It builds the image in
`Dockerfile`, makes the keys in `keys/` if any is missing, rewrites `idp/idp-rsa.xml` from the identity provider,
has pysaml2 rewrite `sp/` and `manifest.json`, replays the requests, and has pysaml2 check the responses. It prints
one line for each case and exits non-zero if any fails.

A run without a change to the code or to `pysaml2/` changes no file. pysaml2 signs with RSA PKCS #1 v1.5, which is
deterministic, and every `IssueInstant` is the fixed instant.

`TestInteropIDPMetadata` fails when the metadata of the identity provider no longer matches `idp/idp-rsa.xml`,
because the committed requests were made from it. Run `generate.sh` and commit what it changes.

## Versions

The image is Alpine 3.22, for xmlsec1 1.3.7: ECDH-ES, AES-GCM and RSA-OAEP 1.1 need xmlsec1 1.3, which the stable
Debian release doesn't ship. pysaml2 is 7.5.5. `Dockerfile` pins the base image by digest and pysaml2 exactly, but
holds the Alpine packages only to their minor version, because Alpine drops a package revision as soon as it is
replaced. `manifest.json` records the versions of pysaml2 and xmlsec1 that made the fixtures.

The keys are RSA 2048 (`idp-rsa`, `sp-rsa`) and P-256 (`idp-ec`, `sp-ec`), with certificates valid from 2026-01-01
to 2036-01-01. The fixed instant is 2026-01-01T00:00:00Z.

## Cases

The cases are listed in `pysaml2/config.py`, and `generate.py` writes them to `manifest.json`, adding the
`request` that pysaml2 made and the `request_id` it was given. Each case names:

- the service provider (`sp`), whose pysaml2 configuration is in `config.py`;
- how the identity provider is set up (`idp_profile`), a name in `interopProfiles` in `interop_test.go`, which holds
  everything that service provider metadata can't express, such as whether the assertion is encrypted;
- the binding of the request, `redirect-signed` or `post-signed`;
- what the replay asserts (`expect`), and what `verify.py` checks (`verify`).

A case that names an unknown profile, service provider or binding fails. It is never skipped.

`skip` records a case that can't be run, with the reason, and is only ever set by `generate.py` for one of two
reasons declared on the case in `config.py`.

`unmakeable` declares that pysaml2 can't make the request, with the reason and the text of the error pysaml2 raises:
pysaml2 7.5.5 only signs with RSA, so the cases of a request signed with ECDSA declare that. Any other failure to make
a request stops `generate.py`, which then writes nothing, and so does a request that pysaml2 makes although the case
declares it can't.

`known_bug` declares that pysaml2 makes the request but the identity provider is known to get it wrong, naming the
bug, its issue or its TODO reference. The request is still written, and the case is skipped with that reason until
the bug is fixed and the declaration removed.

`TestInterop` fails if no case runs or two cases have the same id, and checks the names of a skipped case too.

`verify_with: "xmlsec1"`, with a `verify_reason`, has `verify.py` check the response with xmlsec1 instead, for a
response pysaml2 can't consume for reasons of its own. It is set in `config.py`, never decided while verifying,
and the case prints as `pass (xmlsec1: <reason>)`. The fallback runs every check the case lists, from the XML that
xmlsec1 verified and decrypted, and fails on one it can't perform. Any other value of `verify_with` fails the case.

## Adding a case

Add it to `CASES` in `pysaml2/config.py`, add a profile to `interopProfiles` if none fits, and run `generate.sh`.
Commit the new request and the changed `manifest.json`.
