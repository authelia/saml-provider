"""Checks with pysaml2, as the service provider, every response that the identity provider gave to a fixture.

Usage: verify.py <dir>, where <dir> holds <id>.b64 for each case of manifest.json, as TestInterop writes them with
SAML_INTEROP_EMIT. Prints one line per case and exits 1 if any case fails. A case that declares verify_with
"xmlsec1" is checked with xmlsec1 instead of pysaml2, for the reason it gives, and passes as "pass (xmlsec1)".
"""

import base64
import json
import os
import subprocess
import sys
import tempfile
from xml.etree import ElementTree

import freezegun
from saml2 import BINDING_HTTP_POST

import config


class Failure(Exception):
    pass


def check(condition, message):
    if not condition:
        raise Failure(message)


def verify_pysaml2(case, encoded):
    """Runs each check of case["verify"] on what pysaml2 makes of the response."""
    client = config.client(case["sp"])

    try:
        response = client.parse_authn_request_response(
            encoded, BINDING_HTTP_POST, outstanding={case["request_id"]: "/"}
        )
    except Exception as e:  # noqa: BLE001 - any rejection by pysaml2 is the failure being looked for.
        raise Failure(f"pysaml2 rejected the response: {type(e).__name__}: {e}") from e

    check(response is not None, "pysaml2 returned no response")

    for name in case["verify"]:
        if name == "signature":
            # parse_authn_request_response raises unless the signatures that want_response_signed asks for verify.
            check(response.response.signature is not None, "the Response is not signed")
        elif name == "in-response-to":
            check(response.in_response_to == case["request_id"], f"InResponseTo is {response.in_response_to!r}")
        elif name == "subject":
            subject = response.get_subject()
            check(subject is not None and subject.text, "no NameID in the subject")
            check(subject.format == case["expect"]["name_id_format"], f"NameID format is {subject.format!r}")
        elif name == "decrypt-assertion":
            # pysaml2 empties encrypted_assertion once it has decrypted it, so the response as sent is looked at.
            sent = ElementTree.fromstring(base64.b64decode(encoded))
            check(sent.find("{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedAssertion") is not None,
                  "the assertion was not encrypted")
            check(response.assertion is not None, "the assertion was not decrypted")
        else:
            raise Failure(f"unknown check {name!r}")


SAML = "{urn:oasis:names:tc:SAML:2.0:assertion}"


def verify_xmlsec1(case, encoded):
    """Runs each check of case["verify"] with xmlsec1 and the XML of the response, for a case pysaml2 can't consume.

    xmlsec1 verifies the signature of the Response and decrypts its assertion; the rest is read from the XML. A check
    this can't perform fails the case.
    """
    sent = base64.b64decode(encoded)
    response = ElementTree.fromstring(sent)

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "response.xml")
        with open(path, "wb") as f:
            f.write(sent)

        result = subprocess.run(
            [
                # The options pysaml2 itself verifies with: the key is the certificate given, not one to be trusted.
                "xmlsec1", "--verify", "--enabled-key-data", "raw-x509-cert", "--lax-key-search",
                "--pubkey-cert-pem", "keys/idp-rsa.crt",
                "--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:protocol:Response", path,
            ],
            capture_output=True,
            text=True,
        )
        check(result.returncode == 0, f"xmlsec1 rejected the signature: {result.stderr.strip()}")

        assertion = response.find(SAML + "Assertion")

        if response.find(SAML + "EncryptedAssertion") is not None:
            result = subprocess.run(
                ["xmlsec1", "--decrypt", "--lax-key-search", "--privkey-pem", f"keys/{case['sp']}.key", path],
                capture_output=True,
            )
            check(result.returncode == 0, f"xmlsec1 could not decrypt: {result.stderr.decode().strip()}")
            assertion = ElementTree.fromstring(result.stdout).find(f"{SAML}EncryptedAssertion/{SAML}Assertion")

    for name in case["verify"]:
        if name == "signature":
            pass  # xmlsec1 --verify succeeded above.
        elif name == "in-response-to":
            got = response.get("InResponseTo")
            check(got == case["request_id"], f"InResponseTo is {got!r}")
        elif name == "subject":
            name_id = assertion.find(f"{SAML}Subject/{SAML}NameID") if assertion is not None else None
            check(name_id is not None and name_id.text, "no NameID in the subject")
            check(name_id.get("Format") == case["expect"]["name_id_format"], f"NameID format is {name_id.get('Format')!r}")
        elif name == "decrypt-assertion":
            check(response.find(SAML + "EncryptedAssertion") is not None, "the assertion was not encrypted")
            check(assertion is not None, "the assertion was not decrypted")
        else:
            raise Failure(f"unknown check {name!r}")


# The verifiers a case may name in verify_with. A case without verify_with is verified with pysaml2.
FALLBACKS = {"xmlsec1": verify_xmlsec1}


def verifier(case):
    """Returns the verifier of a case and the label its pass is printed with, or fails the case for a verify_with that
    names no fallback: null, a value that is not a string, or a string that is not a name in FALLBACKS."""
    if "verify_with" not in case:
        return verify_pysaml2, ""

    verify_with = case["verify_with"]
    check(isinstance(verify_with, str) and verify_with in FALLBACKS, f"unknown verify_with {verify_with!r}")
    check(isinstance(case.get("verify_reason"), str) and case["verify_reason"], "verify_with without a verify_reason")

    return FALLBACKS[verify_with], f" ({verify_with}: {case['verify_reason']})"


def main(directory):
    with open("manifest.json") as f:
        manifest = json.load(f)

    failed = 0

    with freezegun.freeze_time(manifest["instant"]):
        for case in manifest["cases"]:
            if case.get("skip"):
                print(f"{case['id']}: skip ({case['skip']})")
                continue

            path = os.path.join(directory, case["id"] + ".b64")

            try:
                check(os.path.exists(path), "missing response")

                with open(path) as f:
                    encoded = f.read().strip()

                verify, label = verifier(case)
                verify(case, encoded)
                print(f"{case['id']}: pass{label}")
            except Failure as e:
                failed += 1
                print(f"{case['id']}: FAIL {e}")

    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: verify.py <dir>")

    sys.exit(main(sys.argv[1]))
