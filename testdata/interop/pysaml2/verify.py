"""Checks with pysaml2, as the service provider, every response that the identity provider gave to a fixture.

Usage: verify.py <dir>, where <dir> holds <id>.b64 for each case of manifest.json, as TestInterop writes them with
SAML_INTEROP_EMIT. Prints one line per case and exits 1 if any case fails. A case that declares verify_with
"xmlsec1" is checked with xmlsec1 instead of pysaml2, for the reason it gives, and passes as "pass (xmlsec1)".
"""

import base64
import contextlib
import hashlib
import json
import re
import os
import subprocess
import sys
import tempfile
from xml.etree import ElementTree

import freezegun
import saml2.entity
import saml2.response
import saml2.soap
from saml2 import BINDING_HTTP_ARTIFACT, BINDING_HTTP_POST, BINDING_SOAP
from saml2.response import StatusError

import config


class Failure(Exception):
    pass


def check(condition, message):
    if not condition:
        raise Failure(message)


SAMLP = "{urn:oasis:names:tc:SAML:2.0:protocol}"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"


def check_error_status(case, sent):
    """Checks that the StatusCode of the Response and the one nested in it are those the case expects."""
    top = sent.find(f"{SAMLP}Status/{SAMLP}StatusCode")
    check(top is not None, "no StatusCode")
    check(top.get("Value") == case["expect"]["outcome"], f"StatusCode is {top.get('Value')!r}")

    if case["expect"].get("second_level"):
        second = top.find(f"{SAMLP}StatusCode")
        got = second.get("Value") if second is not None else None
        check(got == case["expect"]["second_level"], f"second-level StatusCode is {got!r}")

    check(sent.find(f"{SAML}Assertion") is None and sent.find(f"{SAML}EncryptedAssertion") is None,
          "an assertion in a Response that reports an error")


def verify_pysaml2_error(case, encoded, client):
    """Checks a Response that reports an error: its StatusCodes as sent, and that pysaml2, having verified its
    signature, reports it as a StatusError. Any other exception, or none, fails the case."""
    sent = sent_message(case, encoded)
    check_error_status(case, sent)

    try:
        client.parse_authn_request_response(encoded, BINDING_HTTP_POST, outstanding={case["request_id"]: "/"})
    except StatusError:
        pass
    except Exception as e:  # noqa: BLE001 - only the StatusError of the expected status passes.
        raise Failure(f"pysaml2 rejected the response other than by its status: {type(e).__name__}: {e}") from e
    else:
        raise Failure("pysaml2 accepted a Response that reports an error")

    for name in case["verify"]:
        if name == "signature":
            # parse_authn_request_response verifies the signature, which want_response_signed requires, before it
            # looks at the status.
            check(sent.find("{http://www.w3.org/2000/09/xmldsig#}Signature") is not None, "the Response is not signed")
        elif name == "in-response-to":
            check(sent.get("InResponseTo") == case["request_id"], f"InResponseTo is {sent.get('InResponseTo')!r}")
        elif name != "error-status":
            raise Failure(f"check {name!r} doesn't apply to a Response that reports an error")


def verify_pysaml2(case, encoded):
    """Runs each check of case["verify"] on what pysaml2 makes of the response."""
    client = config.client(case["sp"])

    if "error-status" in case["verify"]:
        return verify_pysaml2_error(case, encoded, client)

    try:
        response = parse(client, case, encoded)
        check(response is not None, "pysaml2 returned no response")
        run_pysaml2_checks(case, encoded, response)
    except Failure:
        raise
    except Exception as e:  # noqa: BLE001 - any rejection by pysaml2 is the failure being looked for.
        raise Failure(f"pysaml2 rejected the response: {type(e).__name__}: {e}") from e


def soap_message_bytes(text):
    """Returns the message in the Body of a SOAP envelope as it was sent, byte for byte, unlike pysaml2, which
    serializes it again (see config.PYSAML2_SOAP_RESERIALIZES)."""
    if isinstance(text, bytes):
        text = text.decode()
    match = re.search(r"<(?P<prefix>[\w.-]+):Body\b[^>]*>(?P<message>.*)</(?P=prefix):Body>", text, re.S)
    check(match is not None, "no SOAP Body")
    return match.group("message").strip()


def inner_response_bytes(artifact_response):
    """Returns the Response that an ArtifactResponse carries as it was sent, byte for byte."""
    match = re.search(r"<(?P<prefix>[\w.-]+):Response\b.*</(?P=prefix):Response>", artifact_response, re.S)
    check(match is not None, "the ArtifactResponse carries no Response")
    return match.group(0)


@contextlib.contextmanager
def pysaml2_unwrap_keeping_bytes():
    """Replaces, while it is entered, the one function of pysaml2 that takes a message out of a SOAP Body, with one
    that keeps its bytes, so that the rest of pysaml2 verifies and parses the message as it was sent."""
    original = saml2.soap.parse_soap_enveloped_saml_thingy

    def keeping_bytes(text, expected_tags):
        return soap_message_bytes(text)

    modules = [m for m in (saml2.soap, saml2.entity) if hasattr(m, "parse_soap_enveloped_saml_thingy")]
    for module in modules:
        module.parse_soap_enveloped_saml_thingy = keeping_bytes
    try:
        yield
    finally:
        for module in modules:
            module.parse_soap_enveloped_saml_thingy = original


def parse(client, case, encoded):
    """Returns what pysaml2 makes of the answer to a case: a Response posted to the service provider, or the SOAP
    envelope that answers a query, with the method pysaml2 has for it."""
    if case["binding"] != "soap":
        return client.parse_authn_request_response(encoded, BINDING_HTTP_POST, outstanding={case["request_id"]: "/"})

    envelope = base64.b64decode(encoded).decode()

    if case["endpoint"] == "artifact":
        # The ArtifactResponse, and then the Response it carries, which answers the case it comes after and was
        # delivered by artifact, as the service provider consumes it.
        # parse_artifact_resolve_response verifies the ArtifactResponse and returns only what it carries, so the
        # _parse_response it does that with is called, to keep the ArtifactResponse.
        artifact_response = client._parse_response(
            envelope, saml2.response.ArtifactResponse, "artifact_resolve", BINDING_SOAP,
            entity_id=client.config.entityid, attribute_converters=client.config.attribute_converters,
        ).response
        check(artifact_response is not None, "pysaml2 returned no ArtifactResponse")
        response = client.parse_authn_request_response(
            base64.b64encode(inner_response_bytes(soap_message_bytes(envelope)).encode()).decode(),
            BINDING_HTTP_ARTIFACT,
            outstanding={CASES[case["after"]]["request_id"]: "/"},
        )
        response.artifact_response = artifact_response
        return response

    parsers = {
        "attribute": lambda: client.parse_attribute_query_response(envelope, BINDING_SOAP),
        "authn-query": lambda: client.parse_authn_query_response(envelope, BINDING_SOAP),
        "artifact": lambda: client.parse_artifact_resolve_response(envelope),
        "assertion-id": lambda: client.parse_assertion_id_request_response(envelope, BINDING_SOAP),
    }
    check(case["endpoint"] in parsers, f"no pysaml2 parser for endpoint {case['endpoint']!r}")

    return parsers[case["endpoint"]]()


def sent_message(case, encoded):
    """Returns the SAML message the identity provider sent: the Response, or the message in the SOAP Body."""
    return message_of(case, ElementTree.fromstring(base64.b64decode(encoded)))


def message_of(case, root):
    """Returns the SAML message of a document: the root itself, or the message in the Body of a SOAP envelope."""
    if case["binding"] == "soap":
        body = root.find("{http://schemas.xmlsoap.org/soap/envelope/}Body")
        check(body is not None and len(body) == 1, "the SOAP Body holds other than one message")
        return body[0]

    return root


def run_pysaml2_checks(case, encoded, response):
    """Runs each check of case["verify"] on the response pysaml2 parsed."""

    for name in case["verify"]:
        if name == "signature":
            # parse_authn_request_response raises unless the signatures that want_response_signed asks for verify.
            check(response.response.signature is not None, "the Response is not signed")
        elif name == "in-response-to":
            answer = getattr(response, "artifact_response", response)
            check(answer.in_response_to == case["request_id"], f"InResponseTo is {answer.in_response_to!r}")
        elif name == "artifact-response":
            # parse_authn_request_response checked the Response answers the case this one comes after.
            outer = response.artifact_response
            check(outer.status.status_code.value == SUCCESS, "the ArtifactResponse is not a success")
            check(outer.signature is not None, "the ArtifactResponse is not signed")
            check(response.response.destination == case["expect"]["destination"],
                  f"the Response is for {response.response.destination!r}")
            check(response.response.signature is not None, "the Response is not signed")
        elif name == "subject":
            subject = response.get_subject()
            check(subject is not None and subject.text, "no NameID in the subject")
            check(subject.format == case["expect"]["name_id_format"], f"NameID format is {subject.format!r}")
            if case["expect"].get("name_id"):
                check(subject.text == case["expect"]["name_id"], f"NameID is {subject.text!r}")
        elif name == "authn-statement":
            statements = response.assertion.authn_statement
            check(len(statements) == 1, f"{len(statements)} AuthnStatements")
            check(statements[0].authn_instant == case["expect"]["authn_instant"],
                  f"AuthnInstant is {statements[0].authn_instant!r}")
        elif name == "no-assertion":
            sent = sent_message(case, encoded)
            check(sent.find(f"{SAML}Assertion") is None and sent.find(f"{SAML}EncryptedAssertion") is None,
                  "the Response carries an assertion")
            check(response.assertion is None, "pysaml2 found an assertion")
        elif name == "attributes":
            check(sent_message(case, encoded).find(f".//{SAML}EncryptedAttribute") is None, "an attribute is encrypted")
            got = {}
            for statement in response.assertion.attribute_statement:
                for attribute in statement.attribute:
                    got.setdefault(attribute.name, []).extend(v.text for v in attribute.attribute_value)
            for attribute, value in case["expect"]["attributes"].items():
                check(got.get(attribute) == [value], f"attribute {attribute} is {got.get(attribute)!r}")
        elif name == "decrypt-name-id":
            sent = sent_message(case, encoded)
            check(sent.find(f".//{SAML}Subject/{SAML}EncryptedID") is not None, "the NameID was not encrypted")
            check(sent.find(f".//{SAML}Subject/{SAML}NameID") is None, "a plaintext NameID beside the EncryptedID")
            subject = response.get_subject()
            check(subject is not None and subject.text, "pysaml2 decrypted no NameID")
            check(subject.format == case["expect"]["name_id_format"], f"NameID format is {subject.format!r}")
            if case["expect"].get("name_id"):
                check(subject.text == case["expect"]["name_id"], f"NameID is {subject.text!r}")
        elif name == "decrypt-attributes":
            sent = sent_message(case, encoded)
            check(sent.find(f".//{SAML}EncryptedAttribute") is not None, "no attribute was encrypted")
            check_no_plaintext_attributes(case, sent)
            # pysaml2 appends what it decrypts to the attributes of the AttributeStatement.
            got = {}
            for statement in response.assertion.attribute_statement:
                for attribute in statement.attribute:
                    got.setdefault(attribute.name, []).extend(v.text for v in attribute.attribute_value)
            for attribute, value in case["expect"]["encrypted_attributes"].items():
                check(got.get(attribute) == [value], f"attribute {attribute} is {got.get(attribute)!r}")
        elif name == "decrypt-assertion":
            # pysaml2 empties encrypted_assertion once it has decrypted it, so the response as sent is looked at.
            sent = sent_message(case, encoded)
            check(sent.find("{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedAssertion") is not None,
                  "the assertion was not encrypted")
            check(response.assertion is not None, "the assertion was not decrypted")
        else:
            raise Failure(f"unknown check {name!r}")


SAML = "{urn:oasis:names:tc:SAML:2.0:assertion}"
XENC_DATA = "{http://www.w3.org/2001/04/xmlenc#}EncryptedData"


def check_no_plaintext_attributes(case, element):
    """Fails the case if an attribute it expects to be encrypted is anywhere in the element in plaintext."""
    for attribute in element.iter(f"{SAML}Attribute"):
        check(attribute.get("Name") not in case["expect"]["encrypted_attributes"],
              f"attribute {attribute.get('Name')} in plaintext")


def xmlsec1_decrypt(case, path):
    """Decrypts the first EncryptedData of the file with xmlsec1 and the encryption key of the case's SP, and returns
    the document xmlsec1 writes, with the plaintext in place of the EncryptedData."""
    # The key data of ECDH-ES, agreement-method, is not enabled unless it is named, and its AgreementMethod is
    # nested one level below the EncryptedKey that holds it. xmlsec1 doesn't resolve the RecipientKeyInfo of the
    # agreement to the key loaded, so the search for the key is lax.
    key = config.SERVICE_PROVIDERS[case["sp"]]["encryption_key"]
    result = subprocess.run(
        [
            "xmlsec1", "--decrypt", "--lax-key-search",
            "--enabled-key-data", "agreement-method,enc-key,key-value,key-name,ec,rsa,x509",
            "--max-encrypted-key-level", "3",
            "--privkey-pem", f"keys/{key}.key,keys/{key}.crt", path,
        ],
        capture_output=True,
    )
    check(result.returncode == 0, f"xmlsec1 could not decrypt: {result.stderr.decode().strip()}")

    return ElementTree.fromstring(result.stdout)


def xmlsec1_decrypt_element(case, encrypted):
    """Decrypts an EncryptedID or EncryptedAttribute on its own, and returns the element it held."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "element.xml")
        with open(path, "wb") as f:
            f.write(ElementTree.tostring(encrypted))

        decrypted = xmlsec1_decrypt(case, path)

    check(decrypted.find(XENC_DATA) is None and len(decrypted) == 1, "xmlsec1 left the element encrypted")
    return decrypted[0]


IDP_ENTITY_ID = "https://idp.example.com/saml/metadata"
IDP_ARTIFACT_RESOLUTION = "https://idp.example.com/saml/artifact"

# The cases of manifest.json by id, for a case that refers to another.
CASES = {}


def verify_artifact(case, encoded):
    """Checks the artifact the identity provider issued in place of a Response: that it is of type 0x0004 for the
    first ArtifactResolutionService, and that pysaml2 resolves its SourceID to the artifact resolution service of
    the identity provider in its metadata."""
    raw = base64.b64decode(encoded)
    check(len(raw) == 44 and raw[:2] == b"\x00\x04", f"not an artifact of type 0x0004: {raw[:2].hex()}")
    check(raw[2:4] == b"\x00\x00", f"EndpointIndex is {int.from_bytes(raw[2:4], 'big')}")
    check(raw[4:24] == hashlib.sha1(IDP_ENTITY_ID.encode()).digest(), "the SourceID is not that of the identity provider")

    destination = config.client(case["sp"]).artifact2destination(encoded, "idpsso")
    check(destination == IDP_ARTIFACT_RESOLUTION, f"pysaml2 resolves the artifact at {destination!r}")


def xmlsec1_verify(path, *args):
    """Verifies a signature of the file with xmlsec1 and the certificate of the identity provider."""
    result = subprocess.run(
        [
            # The options pysaml2 itself verifies with: the key is the certificate given, not one to be trusted.
            "xmlsec1", "--verify", "--enabled-key-data", "raw-x509-cert", "--lax-key-search",
            "--pubkey-cert-pem", "keys/idp-rsa.crt",
            "--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:protocol:Response",
            "--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:protocol:ArtifactResponse",
            *args, path,
        ],
        capture_output=True,
        text=True,
    )
    check(result.returncode == 0, f"xmlsec1 rejected the signature: {result.stderr.strip()}")


def verify_xmlsec1(case, encoded):
    """Runs each check of case["verify"] with xmlsec1 and the XML of the response, for a case pysaml2 can't consume.

    xmlsec1 verifies the signature of the Response and decrypts its assertion; the rest is read from the XML. A check
    this can't perform fails the case.
    """
    sent = base64.b64decode(encoded)
    response = sent_message(case, encoded)

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "response.xml")
        with open(path, "wb") as f:
            f.write(sent)

        # The signature of the message itself, which is the first in the document.
        xmlsec1_verify(path)

        # An ArtifactResponse carries the Response it resolved, signed on its own.
        inner = response
        if response.tag == SAMLP + "ArtifactResponse":
            inner = response.find(SAMLP + "Response")
            check(inner is not None, "the ArtifactResponse carries no Response")
            xmlsec1_verify(
                path, "--node-xpath",
                "//*[local-name()='ArtifactResponse']/*[local-name()='Response']/*[local-name()='Signature']",
            )

        assertion = inner.find(SAML + "Assertion")

        # An assertion that is fetched by its ID is returned as it was signed when it was issued.
        if "assertion-id" in case["verify"]:
            check(assertion is not None, "no assertion")
            xmlsec1_verify(
                path, "--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:assertion:Assertion",
                "--node-xpath", "//*[local-name()='Assertion']/*[local-name()='Signature']",
            )

        if inner.find(SAML + "EncryptedAssertion") is not None:
            decrypted = message_of(case, xmlsec1_decrypt(case, path))
            if decrypted.tag == SAMLP + "ArtifactResponse":
                decrypted = decrypted.find(SAMLP + "Response")
            assertion = decrypted.find(f"{SAML}EncryptedAssertion/{SAML}Assertion")

    for name in case["verify"]:
        if name == "signature":
            pass  # xmlsec1 --verify succeeded above.
        elif name == "error-status":
            check_error_status(case, response)
        elif name == "in-response-to":
            got = response.get("InResponseTo")
            check(got == case["request_id"], f"InResponseTo is {got!r}")
        elif name == "decrypt-name-id":
            encrypted = assertion.find(f"{SAML}Subject/{SAML}EncryptedID") if assertion is not None else None
            check(encrypted is not None, "the NameID was not encrypted")
            check(assertion.find(f"{SAML}Subject/{SAML}NameID") is None, "a plaintext NameID beside the EncryptedID")
            name_id = xmlsec1_decrypt_element(case, encrypted)
            check(name_id.tag == SAML + "NameID" and name_id.text, "no NameID in the EncryptedID")
            check(name_id.get("Format") == case["expect"]["name_id_format"], f"NameID format is {name_id.get('Format')!r}")
            if case["expect"].get("name_id"):
                check(name_id.text == case["expect"]["name_id"], f"NameID is {name_id.text!r}")
        elif name == "decrypt-attributes":
            encrypted = assertion.findall(f"{SAML}AttributeStatement/{SAML}EncryptedAttribute") if assertion is not None else []
            check(encrypted, "no attribute was encrypted")
            check_no_plaintext_attributes(case, assertion)
            got = {}
            for el in encrypted:
                attribute = xmlsec1_decrypt_element(case, el)
                check(attribute.tag == SAML + "Attribute", f"an EncryptedAttribute holds {attribute.tag}")
                got.setdefault(attribute.get("Name"), []).extend(
                    v.text for v in attribute.findall(f"{SAML}AttributeValue")
                )
            for attribute, value in case["expect"]["encrypted_attributes"].items():
                check(got.get(attribute) == [value], f"attribute {attribute} is {got.get(attribute)!r}")
        elif name == "assertion-id":
            with open(config.ISSUED) as f:
                want = json.load(f)[case["expect"]["assertion_of"]]["assertion_id"]
            check(assertion is not None, "no assertion")
            check(assertion.get("ID") == want, f"the assertion is {assertion.get('ID')!r}, not {want!r}")
        elif name == "artifact-response":
            check(response.tag == SAMLP + "ArtifactResponse", f"the answer is a {response.tag}")
            status = response.find(f"{SAMLP}Status/{SAMLP}StatusCode")
            check(status is not None and status.get("Value") == SUCCESS, "the ArtifactResponse is not a success")
            after = CASES[case["after"]]
            check(inner.get("InResponseTo") == after["request_id"], f"the Response answers {inner.get('InResponseTo')!r}")
            check(inner.get("Destination") == case["expect"]["destination"], f"the Response is for {inner.get('Destination')!r}")
            status = inner.find(f"{SAMLP}Status/{SAMLP}StatusCode")
            check(status is not None and status.get("Value") == SUCCESS, "the Response is not a success")
        elif name == "no-assertion":
            check(response.find(f"{SAML}Assertion") is None and response.find(f"{SAML}EncryptedAssertion") is None,
                  "the Response carries an assertion")
        elif name == "authn-statement":
            statements = assertion.findall(f"{SAML}AuthnStatement") if assertion is not None else []
            check(len(statements) == 1, f"{len(statements)} AuthnStatements")
            check(statements[0].get("AuthnInstant") == case["expect"]["authn_instant"],
                  f"AuthnInstant is {statements[0].get('AuthnInstant')!r}")
        elif name == "attributes":
            check(assertion is not None, "no assertion")
            check(assertion.find(f".//{SAML}EncryptedAttribute") is None, "an attribute is encrypted")
            got = {}
            for attribute in assertion.iter(f"{SAML}Attribute"):
                got.setdefault(attribute.get("Name"), []).extend(
                    v.text for v in attribute.findall(f"{SAML}AttributeValue")
                )
            for attribute, value in case["expect"]["attributes"].items():
                check(got.get(attribute) == [value], f"attribute {attribute} is {got.get(attribute)!r}")
        elif name == "subject":
            name_id = assertion.find(f"{SAML}Subject/{SAML}NameID") if assertion is not None else None
            check(name_id is not None and name_id.text, "no NameID in the subject")
            check(name_id.get("Format") == case["expect"]["name_id_format"], f"NameID format is {name_id.get('Format')!r}")
            if case["expect"].get("name_id"):
                check(name_id.text == case["expect"]["name_id"], f"NameID is {name_id.text!r}")
        elif name == "decrypt-assertion":
            check(response.find(SAML + "EncryptedAssertion") is not None, "the assertion was not encrypted")
            check(assertion is not None, "the assertion was not decrypted")
        else:
            raise Failure(f"unknown check {name!r}")


# The verifiers a case may name in verify_with. A case without verify_with is verified with pysaml2.
# "pysaml2-unwrapped" is pysaml2 itself, with its SOAP unwrap keeping the bytes of the message.
FALLBACKS = {"xmlsec1": verify_xmlsec1, "pysaml2-unwrapped": None}


def verifier(case):
    """Returns the verifier of a case and the label its pass is printed with, or fails the case for a verify_with that
    names no fallback: null, a value that is not a string, or a string that is not a name in FALLBACKS. A fallback
    also needs a verify_reason, and the pysaml2_error that pysaml2 raises for the case."""
    if "artifact" in case["verify"]:
        return verify_artifact, ""

    if "verify_with" not in case:
        return verify_pysaml2, ""

    verify_with = case["verify_with"]
    check(isinstance(verify_with, str) and verify_with in FALLBACKS, f"unknown verify_with {verify_with!r}")
    check(isinstance(case.get("verify_reason"), str) and case["verify_reason"], "verify_with without a verify_reason")
    check(isinstance(case.get("pysaml2_error"), str) and case["pysaml2_error"], "verify_with without a pysaml2_error")

    def verify(case, encoded):
        check_pysaml2_still_fails(case, encoded)

        if case["binding"] == "soap":
            # pysaml2 again, with its SOAP unwrap keeping the bytes: it must verify the case, or fail with the second
            # error the case declares, after which the fallback checks what pysaml2 couldn't.
            with pysaml2_unwrap_keeping_bytes():
                if verify_with == "pysaml2-unwrapped":
                    verify_pysaml2(case, encoded)
                    return

                unwrapped_error = case.get("pysaml2_unwrapped_error")
                check(isinstance(unwrapped_error, str) and unwrapped_error,
                      "a SOAP case with an xmlsec1 fallback without a pysaml2_unwrapped_error")
                check_pysaml2_still_fails(case, encoded, unwrapped_error)

        FALLBACKS[verify_with](case, encoded)

    return verify, f" ({verify_with}: {case['verify_reason']})"


def check_pysaml2_still_fails(case, encoded, error=None):
    """Fails the case unless pysaml2 still fails to verify it with the error it declares, so that a fallback can't
    outlive its reason, nor hide a failure of pysaml2's for another one."""
    error = error or case["pysaml2_error"]
    try:
        verify_pysaml2(case, encoded)
    except Failure as e:
        check(error in str(e), f"pysaml2 fails other than as declared ({error}): {e}")
    else:
        raise Failure("pysaml2 now verifies the response: remove or change its verify_with")


def main(directory):
    with open("manifest.json") as f:
        manifest = json.load(f)

    CASES.update((case["id"], case) for case in manifest["cases"])

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
            except Exception as e:  # noqa: BLE001 - a case that breaks the verifier fails, and the rest still run.
                failed += 1
                print(f"{case['id']}: FAIL {type(e).__name__}: {e}")

    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: verify.py <dir>")

    sys.exit(main(sys.argv[1]))
