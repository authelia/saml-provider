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
`Dockerfile`, makes the keys in `keys/` if any is missing, rewrites the identity provider metadata in `idp/`, has
pysaml2 rewrite `sp/` and `manifest.json`, replays the requests, and has pysaml2 check the responses. It prints one
line for each case and exits non-zero if any fails. `generate.py` writes nothing unless every case is made, and
removes a request or metadata file that no case or service provider makes any more.

A run without a change to the code or to `pysaml2/` changes no file. pysaml2 signs with RSA PKCS #1 v1.5, which is
deterministic, and every `IssueInstant` is the fixed instant. A request that xmlsec1 encrypts would differ every
time, as its key and IV are random, so `manifest.json` records the `source` of each request, a digest of the case,
the entry of its service provider, `generate.py` itself, the metadata it is made from and the versions of pysaml2
and xmlsec1, and the `request_sha256` of the request. A request whose source is unchanged, and whose file still has
that digest, is kept as it is; any other is made again.

Each IdP profile that names an `IDPMetadata` file has its metadata committed in `idp/`: `idp-rsa.xml`, which every
service provider of pysaml2 is configured with, and `idp-rsa-ec-encryption.xml`, which also publishes the elliptic
curve encryption key of `idp-ec`. `TestInteropIDPMetadata` fails when the identity provider no longer publishes what
is committed, because the requests were made from it. Run `generate.sh` and commit what it changes.

## Versions

The image is Alpine 3.22 with xmlsec1 1.3.13, which `Dockerfile` builds from its release, pinned by its SHA-256
(the same as Homebrew's). Encrypting with ECDH-ES needs xmlsec1's `--max-encrypted-key-level`, which none of the
1.3.7 to 1.3.11 that Alpine and Debian ship has. pysaml2 is 7.5.5. `Dockerfile` pins the base image by digest and
pysaml2 exactly, but holds the Alpine packages only to their minor version, because Alpine drops a package revision
as soon as it is replaced. `manifest.json` records the versions of pysaml2 and xmlsec1 that made the fixtures.

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

`verify_with: "xmlsec1"`, with a `verify_reason` and a `pysaml2_error`, has `verify.py` check the response with
xmlsec1 instead, for a response pysaml2 can't consume for reasons of its own. It is set in `config.py`, never decided
while verifying, and the case prints as `pass (xmlsec1: <reason>)`. pysaml2 is still run on the case first, and the
case fails unless pysaml2 fails with the `pysaml2_error` it declares, so that the fallback can't outlive its reason
or hide a different failure. The fallback runs every check the case lists, from the XML that
xmlsec1 verified and decrypted, and fails on one it can't perform. Any other value of `verify_with` fails the case.

## Service providers

`SERVICE_PROVIDERS` in `pysaml2/config.py` lists the service providers. Each has the key pair it signs its requests
with and the one it decrypts with, and may request attributes in its metadata. pysaml2 writes the metadata of each,
and lists in it every signature and digest algorithm xmlsec1 supports, but has no setting for `md:EncryptionMethod`,
for a shorter algorithm list or for a key given as a `ds:KeyValue`. A service provider that needs one of those names
the transforms that `generate.py` applies to what pysaml2 wrote, each a function in `TRANSFORMS`:
`algorithms_rsa_sha512_sha384`, `encryption_methods_gcm256_oaep11`, `encryption_methods_cbc256_mgf1p` and
`encryption_key_value`. `TestInteropSPVariants` checks that each did what it says.

`made_by` in `manifest.json` says how a request was made: `pysaml2`, `pysaml2+transform` when its service provider's
metadata was transformed, or `pysaml2+xmlsec1` when its Subject is an `EncryptedID`. For one of those, pysaml2 makes
the request with a NameID in its Subject and a signature template, xmlsec1 encrypts the NameID to the encryption key
in the identity provider metadata the case names, with RSA-OAEP or with ECDH-ES and a fresh originator key, and
pysaml2 then signs the request, so that its signature covers the `EncryptedID`.

## What a case asserts

`expect` holds the status of the response (`outcome`, and `second_level` for an error), the `signature_method` of
the Response, whether the assertion is encrypted as a whole, the format and value of its NameID, and, each only when
it is set, the algorithms of an encrypted assertion (`content_encryption_method`, `key_transport_method` with its
`key_transport_digest_method` and `key_transport_mgf`, or `key_agreement_method` and `key_wrap_method` for ECDH-ES),
whether the NameID is an `EncryptedID` (`encrypted_name_id`), and the value of each attribute that must be an
`EncryptedAttribute` (`encrypted_attributes`). The Go replay decrypts what is encrypted with the key of the service
provider before it checks what is inside.

`verify` names the checks of `verify.py`: `signature`, `in-response-to`, `subject`, `decrypt-assertion`,
`decrypt-name-id`, `decrypt-attributes` and `error-status`. A Response that reports an error passes `error-status`
only if its StatusCodes are those expected and pysaml2, having verified its signature, reports it as a
`StatusError`; any other exception fails it.

Two cases declare the xmlsec1 fallback, for reasons of pysaml2's. It can't decrypt what is encrypted to an elliptic
curve key: its fixed xmlsec1 command doesn't enable the `agreement-method` key data, allow the AgreementMethod nested
in the EncryptedKey (`--max-encrypted-key-level 3`) or search for the key laxly, as xmlsec1 doesn't resolve the
`RecipientKeyInfo`. And it can't decrypt an `EncryptedAttribute` at all, as it passes an object where its decryption
needs a string.

## Adding a case

Add it to `CASES` in `pysaml2/config.py`, add a profile to `interopProfiles` if none fits, and run `generate.sh`.
Commit everything it changes under `testdata/interop`: new and removed requests, service provider and identity
provider metadata, and `manifest.json`.
