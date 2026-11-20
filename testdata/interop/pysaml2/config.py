"""What generate.py and verify.py share: the service providers, the cases, and how pysaml2 is set up for them.

Paths are relative to testdata/interop, which is the working directory in the container.
"""

import datetime
import shutil

from saml2 import BINDING_HTTP_ARTIFACT, BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, BINDING_SOAP
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.xmldsig import DIGEST_SHA256, SIG_ECDSA_SHA256, SIG_RSA_SHA256

INSTANT = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
IDP_METADATA = "idp/idp-rsa.xml"
RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
XENC = "http://www.w3.org/2001/04/xmlenc#"
XENC11 = "http://www.w3.org/2009/xmlenc11#"
MAIL = "urn:oid:0.9.2342.19200300.100.1.3"
EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

# Why pysaml2 can't make a request signed with ECDSA. A case may only be skipped for a reason declared on it as
# "unmakeable", whose "error" must be in the message of the exception pysaml2 raises; any other failure to make a
# request stops generate.py.
PYSAML2_RSA_ONLY = {
    "reason": (
        "pysaml2 7.5.5 only signs with RSA: saml2/entity.py checks the signature algorithm against "
        "saml2.xmldsig.SIG_ALLOWED_ALG, which lists only RSA (\"XXX SIG_ALLOWED_ALG should be configurable\")"
    ),
    "error": "Signature algo not in allowed list: ",
}

# Why pysaml2 can't decrypt what is encrypted to an elliptic curve key, for a case that declares verify_with
# "xmlsec1" with it. A case that declares verify_with also declares, as pysaml2_error, what pysaml2 raises for it,
# and verify.py fails the case unless pysaml2 still raises that.
PYSAML2_NO_KEY_AGREEMENT = (
    "pysaml2 7.5.5 decrypts with a fixed xmlsec1 --decrypt --privkey-pem command (saml2/sigver.py "
    "CryptoBackendXmlSec1.decrypt), and xmlsec1 only decrypts ECDH-ES with the agreement-method key data enabled, "
    "--max-encrypted-key-level 3 for the AgreementMethod nested in the EncryptedKey, and --lax-key-search, as it "
    "doesn't resolve the RecipientKeyInfo; without them it fails with KEY-NOT-FOUND and pysaml2 finds no assertion"
)

# Why pysaml2 can't decrypt an EncryptedAttribute, for a case that declares verify_with "xmlsec1" with it.
PYSAML2_ENCRYPTED_ATTRIBUTE_BUG = (
    "pysaml2 7.5.5 can't decrypt an EncryptedAttribute: AuthnResponse.decrypt_attributes (saml2/response.py) passes "
    "the EncryptedData object to decrypt_keys, where its EncryptedID path passes to_string(), and xmlsec1's "
    "decrypt then fails with TypeError: object of type 'EncryptedData' has no len()"
)

# Why pysaml2 can't verify the answer to a request on the SOAP binding, for each such case, which declares
# verify_with "xmlsec1" with it.
PYSAML2_SOAP_RESERIALIZES = (
    "pysaml2 7.5.5 takes the message out of a SOAP Body by serializing it again with ElementTree.tostring "
    "(saml2/soap.py parse_soap_enveloped_saml_thingy), which renames its namespace prefixes, so the signature, made "
    "over the exclusive canonical form that keeps them, no longer verifies"
)
PYSAML2_SOAP_ERROR = "SignatureError: Failed to verify signature"

# Why pysaml2 still can't consume the answer to a query once its SOAP unwrap keeps the bytes (see verify.py), for a
# case that declares it as pysaml2_unwrapped_error: it verifies the signature, then rejects what SAMLCore §3.3.4
# allows, or requires, of the answer to a query.
PYSAML2_NO_SUBJECT_CONFIRMATION = (
    "; and with the bytes kept, pysaml2 verifies the signature but requires a SubjectConfirmation, which SAMLCore "
    "§3.3.4 doesn't ask of the answer to a query that has none, and fails with VerificationError: No valid attesting "
    "address"
)
PYSAML2_NO_EMPTY_SUCCESS = (
    "; and with the bytes kept, pysaml2 verifies the signature but rejects the Success with no assertion that SAMLCore "
    "§3.3.4 requires when nothing matches the query, with InvalidAssertion: Invalid number of assertions in Response: 0"
)

# Why pysaml2 can't make or read an AssertionIDRequest on the SOAP binding, for each such case.
PYSAML2_NO_SOAP_ASSERTION_ID = (
    "pysaml2 7.5.5 only knows an AssertionIDRequest on the URI binding (SAMLBind §3.7): its "
    "create_assertion_id_request returns the ID it is given, and its AssertionIDResponse takes the whole message for "
    "the Assertion that binding returns, so a samlp:Response on the SOAP binding fails with TypeError: Not a assertion"
)

# A case whose request pysaml2 makes, but which the identity provider is known to get wrong, declares "known_bug"
# with the bug, its issue or its TODO reference. Its request is still written, and it is skipped with that reason
# until the bug is fixed and the declaration removed.

# The service providers of the fixtures, by name. Each signs its requests with sign_key and decrypts with
# encryption_key, both names in keys/, and generate.py applies its transforms, names in generate.TRANSFORMS, to the
# metadata pysaml2 writes for it, for what pysaml2 can't put in metadata itself. required_attributes are the
# pysaml2 names of the attributes its metadata requests.
SERVICE_PROVIDERS = {
    "sp-rsa": {"sign_key": "sp-rsa", "encryption_key": "sp-rsa", "sigalg": SIG_RSA_SHA256},
    "sp-ec": {"sign_key": "sp-ec", "encryption_key": "sp-ec", "sigalg": SIG_ECDSA_SHA256},
    "sp-rsa-negotiate": {
        "sign_key": "sp-rsa",
        "encryption_key": "sp-rsa",
        "sigalg": SIG_RSA_SHA256,
        "transforms": ["algorithms_rsa_sha512_sha384", "encryption_methods_gcm256_oaep11"],
    },
    "sp-rsa-cbc": {
        "sign_key": "sp-rsa",
        "encryption_key": "sp-rsa",
        "sigalg": SIG_RSA_SHA256,
        "transforms": ["encryption_methods_cbc256_mgf1p"],
    },
    "sp-rsa-keyvalue": {
        "sign_key": "sp-rsa",
        "encryption_key": "sp-rsa",
        "sigalg": SIG_RSA_SHA256,
        "transforms": ["encryption_key_value"],
    },
    "sp-ecdh": {"sign_key": "sp-rsa", "encryption_key": "sp-ec", "sigalg": SIG_RSA_SHA256},
    "sp-rsa-mail": {
        "sign_key": "sp-rsa",
        "encryption_key": "sp-rsa",
        "sigalg": SIG_RSA_SHA256,
        "required_attributes": ["mail"],
    },
    "sp-rsa-artifact": {"sign_key": "sp-rsa", "encryption_key": "sp-rsa", "sigalg": SIG_RSA_SHA256, "artifact_acs": True},
}

# The file in which TestInteropIssued records what the identity provider issues on a replay, by case id: the
# artifact of a case that is answered by artifact, and the assertion ID of one whose assertion is fetched later.
ISSUED = "idp/issued.json"

BINDINGS = {
    "redirect-signed": BINDING_HTTP_REDIRECT,
    "post-signed": BINDING_HTTP_POST,
    "soap": BINDING_SOAP,
}

# Every case of the fixtures. generate.py makes the request of each and writes manifest.json from this list;
# verify.py reads the manifest, not this list.
CASES = [
    {
        "id": "authn-request-redirect-rsa-sha256",
        "feature": "authn-request/signed",
        "sp": "sp-rsa",
        "idp_profile": "rsa",
        "binding": "redirect-signed",
        "expect": {"outcome": "success", "signature_method": RSA_SHA256, "encrypted_assertion": False, "name_id_format": TRANSIENT},
        "verify": ["signature", "in-response-to", "subject"],
    },
    {
        "id": "authn-request-post-rsa-sha256",
        "feature": "authn-request/signed",
        "sp": "sp-rsa",
        "idp_profile": "rsa",
        "binding": "post-signed",
        "expect": {"outcome": "success", "signature_method": RSA_SHA256, "encrypted_assertion": False, "name_id_format": TRANSIENT},
        "verify": ["signature", "in-response-to", "subject"],
    },
    {
        "id": "authn-request-redirect-ecdsa-sha256",
        "feature": "authn-request/signed",
        "sp": "sp-ec",
        "idp_profile": "rsa",
        "binding": "redirect-signed",
        "expect": {"outcome": "success", "signature_method": RSA_SHA256, "encrypted_assertion": False, "name_id_format": TRANSIENT},
        "verify": ["signature", "in-response-to", "subject"],
        "unmakeable": PYSAML2_RSA_ONLY,
    },
    {
        "id": "authn-request-post-ecdsa-sha256",
        "feature": "authn-request/signed",
        "sp": "sp-ec",
        "idp_profile": "rsa",
        "binding": "post-signed",
        "expect": {"outcome": "success", "signature_method": RSA_SHA256, "encrypted_assertion": False, "name_id_format": TRANSIENT},
        "verify": ["signature", "in-response-to", "subject"],
        "unmakeable": PYSAML2_RSA_ONLY,
    },
    {
        "id": "assertion-encrypted-rsa-oaep-mgf1p",
        "feature": "assertion-encryption",
        "sp": "sp-rsa",
        "idp_profile": "rsa-encrypt-assertion",
        "binding": "post-signed",
        "expect": {"outcome": "success", "signature_method": RSA_SHA256, "encrypted_assertion": True, "name_id_format": TRANSIENT,
                   "key_transport_method": "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
        "verify": ["signature", "in-response-to", "subject", "decrypt-assertion"],
    },
    {
        "id": "assertion-encrypted-negotiated",
        "feature": "assertion-encryption/negotiated",
        "sp": "sp-rsa-negotiate",
        "idp_profile": "rsa-encrypt-assertion",
        "binding": "post-signed",
        "expect": {
            "outcome": "success",
            "signature_method": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            "digest_method": "http://www.w3.org/2001/04/xmldsig-more#sha384",
            "encrypted_assertion": True,
            "name_id_format": TRANSIENT,
            "content_encryption_method": XENC11 + "aes256-gcm",
            "key_transport_method": XENC11 + "rsa-oaep",
            "key_transport_digest_method": XENC + "sha256",
            "key_transport_mgf": XENC11 + "mgf1sha256",
        },
        "verify": ["signature", "in-response-to", "subject", "decrypt-assertion"],
    },
    {
        "id": "assertion-encrypted-aes256-cbc",
        "feature": "assertion-encryption/cbc",
        "sp": "sp-rsa-cbc",
        "idp_profile": "rsa-encrypt-assertion",
        "binding": "post-signed",
        "expect": {
            "outcome": "success",
            "signature_method": RSA_SHA256,
            "encrypted_assertion": True,
            "name_id_format": TRANSIENT,
            "content_encryption_method": XENC + "aes256-cbc",
            "key_transport_method": XENC + "rsa-oaep-mgf1p",
        },
        "verify": ["signature", "in-response-to", "subject", "decrypt-assertion"],
    },
    {
        "id": "assertion-encrypted-key-value",
        "feature": "assertion-encryption/key-value",
        "sp": "sp-rsa-keyvalue",
        "idp_profile": "rsa-encrypt-assertion",
        "binding": "post-signed",
        "expect": {
            "outcome": "success",
            "signature_method": RSA_SHA256,
            "encrypted_assertion": True,
            "name_id_format": TRANSIENT,
            "content_encryption_method": XENC11 + "aes128-gcm",
            "key_transport_method": XENC + "rsa-oaep-mgf1p",
        },
        "verify": ["signature", "in-response-to", "subject", "decrypt-assertion"],
    },
    {
        "id": "assertion-encrypted-ecdh-es",
        "feature": "assertion-encryption/ecdh-es",
        "sp": "sp-ecdh",
        "idp_profile": "rsa-encrypt-assertion",
        "binding": "post-signed",
        "expect": {
            "outcome": "success",
            "signature_method": RSA_SHA256,
            "encrypted_assertion": True,
            "name_id_format": TRANSIENT,
            "content_encryption_method": XENC11 + "aes128-gcm",
            "key_agreement_method": XENC11 + "ECDH-ES",
            "key_wrap_method": XENC + "kw-aes256",
        },
        "verify": ["signature", "in-response-to", "subject", "decrypt-assertion"],
        "verify_with": "xmlsec1",
        "verify_reason": PYSAML2_NO_KEY_AGREEMENT,
        "pysaml2_error": "ValueError: Missing assertion",
    },
    {
        "id": "assertion-encrypted-name-id",
        "feature": "encrypted-id/assertion",
        "sp": "sp-rsa-mail",
        "idp_profile": "rsa-encrypt-name-id",
        "binding": "post-signed",
        "expect": {
            "outcome": "success",
            "signature_method": RSA_SHA256,
            "encrypted_assertion": False,
            "name_id_format": TRANSIENT,
            "encrypted_name_id": True,
        },
        "verify": ["signature", "in-response-to", "decrypt-name-id"],
    },
    {
        "id": "assertion-encrypted-attribute",
        "feature": "encrypted-attribute/assertion",
        "sp": "sp-rsa-mail",
        "idp_profile": "rsa-encrypt-attribute",
        "binding": "post-signed",
        "expect": {
            "outcome": "success",
            "signature_method": RSA_SHA256,
            "encrypted_assertion": False,
            "name_id_format": TRANSIENT,
            "encrypted_attributes": {MAIL: "alice@example.com"},
        },
        "verify": ["signature", "in-response-to", "subject", "decrypt-attributes"],
        "verify_with": "xmlsec1",
        "verify_reason": PYSAML2_ENCRYPTED_ATTRIBUTE_BUG,
        "pysaml2_error": "TypeError: object of type 'EncryptedData' has no len()",
    },
    {
        "id": "authn-request-encrypted-subject-rsa-oaep",
        "feature": "encrypted-id/authn-request",
        "sp": "sp-rsa",
        "idp_profile": "rsa-subject",
        "binding": "post-signed",
        "encrypt_subject": {"name_id": "alice@example.com", "template": "oaep", "to": "idp/idp-rsa.xml"},
        "expect": {
            "outcome": "success",
            "signature_method": RSA_SHA256,
            "encrypted_assertion": False,
            "name_id_format": EMAIL,
            "name_id": "alice@example.com",
            "encrypted_name_id": True,
        },
        "verify": ["signature", "in-response-to", "decrypt-name-id"],
    },
    {
        "id": "authn-request-encrypted-subject-ecdh-es",
        "feature": "encrypted-id/authn-request/ecdh-es",
        "sp": "sp-rsa",
        "idp_profile": "rsa-ec-encryption-subject",
        "binding": "post-signed",
        "encrypt_subject": {"name_id": "alice@example.com", "template": "ecdh-es", "to": "idp/idp-rsa-ec-encryption.xml"},
        "expect": {
            "outcome": "success",
            "signature_method": RSA_SHA256,
            "encrypted_assertion": False,
            "name_id_format": EMAIL,
            "name_id": "alice@example.com",
            "encrypted_name_id": True,
        },
        "verify": ["signature", "in-response-to", "decrypt-name-id"],
    },
    {
        "id": "authn-request-encrypted-subject-other-principal",
        "feature": "encrypted-id/authn-request/mismatch",
        "sp": "sp-rsa",
        "idp_profile": "rsa-subject",
        "binding": "post-signed",
        "encrypt_subject": {"name_id": "bob@example.com", "template": "oaep", "to": "idp/idp-rsa.xml"},
        "expect": {
            "outcome": "urn:oasis:names:tc:SAML:2.0:status:Responder",
            "second_level": "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            "signature_method": RSA_SHA256,
        },
        "verify": ["signature", "in-response-to", "error-status"],
    },
    {
        "id": "attribute-query",
        "feature": "attribute-query",
        "sp": "sp-rsa-mail",
        "idp_profile": "rsa-query",
        "binding": "soap",
        "endpoint": "attribute",
        "query": {"name_id": "alice@example.com", "attributes": [MAIL]},
        "expect": {
            "outcome": "success",
            "signature_method": RSA_SHA256,
            "encrypted_assertion": False,
            "name_id_format": EMAIL,
            "name_id": "alice@example.com",
            "attributes": {MAIL: "alice@example.com"},
        },
        "verify": ["signature", "in-response-to", "subject", "attributes"],
        "verify_with": "xmlsec1",
        "verify_reason": PYSAML2_SOAP_RESERIALIZES + PYSAML2_NO_SUBJECT_CONFIRMATION,
        "pysaml2_error": PYSAML2_SOAP_ERROR,
        "pysaml2_unwrapped_error": "VerificationError: No valid attesting address",
    },
    {
        "id": "attribute-query-encrypted-assertion",
        "feature": "attribute-query/encrypted-assertion",
        "sp": "sp-rsa-mail",
        "idp_profile": "rsa-query-encrypt-assertion",
        "binding": "soap",
        "endpoint": "attribute",
        "query": {"name_id": "alice@example.com", "attributes": [MAIL]},
        "expect": {
            "outcome": "success",
            "signature_method": RSA_SHA256,
            "encrypted_assertion": True,
            "name_id_format": EMAIL,
            "name_id": "alice@example.com",
            "key_transport_method": XENC + "rsa-oaep-mgf1p",
            "attributes": {MAIL: "alice@example.com"},
        },
        "verify": ["signature", "in-response-to", "decrypt-assertion", "subject", "attributes"],
        "verify_with": "xmlsec1",
        "verify_reason": PYSAML2_SOAP_RESERIALIZES + PYSAML2_NO_SUBJECT_CONFIRMATION,
        "pysaml2_error": PYSAML2_SOAP_ERROR,
        "pysaml2_unwrapped_error": "VerificationError: No valid attesting address",
    },
    {
        "id": "attribute-query-encrypted-id",
        "feature": "encrypted-id/attribute-query",
        "sp": "sp-rsa-mail",
        "idp_profile": "rsa-query",
        "binding": "soap",
        "endpoint": "attribute",
        "query": {"attributes": [MAIL]},
        "encrypt_subject": {"name_id": "alice@example.com", "template": "oaep", "to": "idp/idp-rsa.xml"},
        "expect": {
            "outcome": "success",
            "signature_method": RSA_SHA256,
            "encrypted_assertion": False,
            "name_id_format": EMAIL,
            "name_id": "alice@example.com",
            "encrypted_name_id": True,
            "attributes": {MAIL: "alice@example.com"},
        },
        "verify": ["signature", "in-response-to", "decrypt-name-id", "attributes"],
        "verify_with": "xmlsec1",
        "verify_reason": PYSAML2_SOAP_RESERIALIZES + PYSAML2_NO_SUBJECT_CONFIRMATION,
        "pysaml2_error": PYSAML2_SOAP_ERROR,
        "pysaml2_unwrapped_error": "VerificationError: No valid attesting address",
    },
    {
        "id": "attribute-query-unknown-principal",
        "feature": "attribute-query/unknown-principal",
        "sp": "sp-rsa-mail",
        "idp_profile": "rsa-query",
        "binding": "soap",
        "endpoint": "attribute",
        "query": {"name_id": "bob@example.com", "attributes": [MAIL]},
        "expect": {"outcome": "success", "signature_method": RSA_SHA256, "no_assertion": True},
        "verify": ["signature", "in-response-to", "no-assertion"],
        "verify_with": "xmlsec1",
        "verify_reason": PYSAML2_SOAP_RESERIALIZES + PYSAML2_NO_EMPTY_SUCCESS,
        "pysaml2_error": PYSAML2_SOAP_ERROR,
        "pysaml2_unwrapped_error": "InvalidAssertion: Invalid number of assertions in Response: 0",
    },
    {
        "id": "authn-query",
        "feature": "authn-query",
        "sp": "sp-rsa",
        "idp_profile": "rsa-query",
        "binding": "soap",
        "endpoint": "authn-query",
        "query": {"name_id": "alice@example.com"},
        "expect": {
            "outcome": "success",
            "signature_method": RSA_SHA256,
            "encrypted_assertion": False,
            "name_id_format": EMAIL,
            "name_id": "alice@example.com",
            "authn_instant": "2026-01-01T00:00:00Z",
        },
        "verify": ["signature", "in-response-to", "subject", "authn-statement"],
        "verify_with": "xmlsec1",
        "verify_reason": PYSAML2_SOAP_RESERIALIZES + PYSAML2_NO_SUBJECT_CONFIRMATION,
        "pysaml2_error": PYSAML2_SOAP_ERROR,
        "pysaml2_unwrapped_error": "VerificationError: No valid attesting address",
    },
    {
        "id": "artifact-sso",
        "feature": "artifact/sso",
        "sp": "sp-rsa-artifact",
        "idp_profile": "rsa",
        "binding": "post-signed",
        "response_binding": "artifact",
        "expect": {"outcome": "success", "artifact": True},
        "verify": ["artifact"],
    },
    {
        "id": "artifact-resolve",
        "feature": "artifact/resolve",
        "sp": "sp-rsa-artifact",
        "idp_profile": "rsa",
        "binding": "soap",
        "endpoint": "artifact",
        "after": "artifact-sso",
        "artifact_of": "artifact-sso",
        "expect": {
            "outcome": "success",
            "signature_method": RSA_SHA256,
            "encrypted_assertion": False,
            "name_id_format": TRANSIENT,
            "destination": "https://sp-rsa-artifact.example.com/saml2/acs-artifact",
        },
        "verify": ["signature", "in-response-to", "artifact-response", "subject"],
        "verify_with": "pysaml2-unwrapped",
        "verify_reason": PYSAML2_SOAP_RESERIALIZES,
        "pysaml2_error": PYSAML2_SOAP_ERROR,
    },
    {
        "id": "assertion-id-sso",
        "feature": "assertion-id-request/sso",
        "sp": "sp-rsa",
        "idp_profile": "rsa-query",
        "binding": "post-signed",
        "expect": {
            "outcome": "success",
            "signature_method": RSA_SHA256,
            "encrypted_assertion": False,
            "name_id_format": EMAIL,
            "name_id": "alice@example.com",
            "issues_assertion": True,
        },
        "verify": ["signature", "in-response-to", "subject"],
    },
    {
        "id": "assertion-id-request",
        "feature": "assertion-id-request",
        "sp": "sp-rsa",
        "idp_profile": "rsa-query",
        "binding": "soap",
        "endpoint": "assertion-id",
        "after": "assertion-id-sso",
        "assertion_of": "assertion-id-sso",
        "expect": {
            "outcome": "success",
            "signature_method": RSA_SHA256,
            "encrypted_assertion": False,
            "name_id_format": EMAIL,
            "name_id": "alice@example.com",
            "assertion_of": "assertion-id-sso",
        },
        "verify": ["signature", "in-response-to", "subject", "assertion-id"],
        "verify_with": "xmlsec1",
        "verify_reason": PYSAML2_NO_SOAP_ASSERTION_ID,
        "pysaml2_error": "TypeError: Not a assertion",
        "pysaml2_unwrapped_error": "TypeError: Not a assertion",
    },
    {
        "id": "assertion-uri",
        "feature": "assertion-id-request/uri",
        "sp": "sp-rsa",
        "idp_profile": "rsa-query",
        "binding": "uri",
        "after": "assertion-id-sso",
        "assertion_of": "assertion-id-sso",
        "expect": {
            "outcome": "success",
            "signature_method": RSA_SHA256,
            "encrypted_assertion": False,
            "name_id_format": EMAIL,
            "name_id": "alice@example.com",
            "assertion_of": "assertion-id-sso",
        },
        "verify": ["signature", "subject", "assertion-id"],
    },
    {
        "id": "assertion-id-request-other-sp",
        "feature": "assertion-id-request/other-sp",
        "sp": "sp-rsa-mail",
        "idp_profile": "rsa-query",
        "binding": "soap",
        "endpoint": "assertion-id",
        "after": "assertion-id-sso",
        "assertion_of": "assertion-id-sso",
        "expect": {"outcome": "success", "signature_method": RSA_SHA256, "no_assertion": True},
        "verify": ["signature", "in-response-to", "no-assertion"],
        "verify_with": "xmlsec1",
        "verify_reason": PYSAML2_NO_SOAP_ASSERTION_ID,
        "pysaml2_error": "TypeError: Not a assertion",
        "pysaml2_unwrapped_error": "TypeError: Not a assertion",
    },
]


def entity_id(sp):
    return f"https://{sp}.example.com/saml2/metadata"


def client(sp, allow_unsolicited=False):
    """Returns the pysaml2 service provider of a name in SERVICE_PROVIDERS. allow_unsolicited is for the answer to a
    query, which pysaml2 can only parse as unsolicited, as its AttributeResponse and AuthnQueryResponse take no
    outstanding request IDs; the InResponseTo of such an answer is checked by verify.py itself."""
    entry = SERVICE_PROVIDERS[sp]
    key, cert = f"keys/{entry['sign_key']}.key", f"keys/{entry['sign_key']}.crt"
    enc_key, enc_cert = f"keys/{entry['encryption_key']}.key", f"keys/{entry['encryption_key']}.crt"

    service = {
        "endpoints": {
            "assertion_consumer_service": [(f"https://{sp}.example.com/saml2/acs", BINDING_HTTP_POST)],
        },
        "authn_requests_signed": True,
        "want_response_signed": True,
        "want_assertions_signed": False,
        "allow_unsolicited": allow_unsolicited,
        "signing_algorithm": entry["sigalg"],
        "digest_algorithm": DIGEST_SHA256,
    }

    if entry.get("required_attributes"):
        service["required_attributes"] = entry["required_attributes"]

    if entry.get("artifact_acs"):
        service["endpoints"]["assertion_consumer_service"].append(
            (f"https://{sp}.example.com/saml2/acs-artifact", BINDING_HTTP_ARTIFACT)
        )

    config = SPConfig()
    config.load(
        {
            "entityid": entity_id(sp),
            "key_file": key,
            "cert_file": cert,
            "encryption_keypairs": [{"key_file": enc_key, "cert_file": enc_cert}],
            "xmlsec_binary": shutil.which("xmlsec1"),
            "metadata": {"local": [IDP_METADATA]},
            "accepted_time_diff": 180,
            "service": {"sp": service},
        }
    )

    return Saml2Client(config)
