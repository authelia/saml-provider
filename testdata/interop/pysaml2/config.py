"""What generate.py and verify.py share: the service providers, the cases, and how pysaml2 is set up for them.

Paths are relative to testdata/interop, which is the working directory in the container.
"""

import datetime
import shutil

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
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
}

BINDINGS = {
    "redirect-signed": BINDING_HTTP_REDIRECT,
    "post-signed": BINDING_HTTP_POST,
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
]


def entity_id(sp):
    return f"https://{sp}.example.com/saml2/metadata"


def client(sp):
    """Returns the pysaml2 service provider of a name in SERVICE_PROVIDERS."""
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
        "allow_unsolicited": False,
        "signing_algorithm": entry["sigalg"],
        "digest_algorithm": DIGEST_SHA256,
    }

    if entry.get("required_attributes"):
        service["required_attributes"] = entry["required_attributes"]

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
