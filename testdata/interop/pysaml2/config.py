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

# A case whose request pysaml2 makes, but which the identity provider is known to get wrong, declares "known_bug"
# with the bug, its issue or its TODO reference. Its request is still written, and it is skipped with that reason
# until the bug is fixed and the declaration removed.

SERVICE_PROVIDERS = {
    "sp-rsa": SIG_RSA_SHA256,
    "sp-ec": SIG_ECDSA_SHA256,
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
]


def entity_id(sp):
    return f"https://{sp}.example.com/saml2/metadata"


def client(sp):
    """Returns the pysaml2 service provider of a name in SERVICE_PROVIDERS."""
    key, cert = f"keys/{sp}.key", f"keys/{sp}.crt"

    config = SPConfig()
    config.load(
        {
            "entityid": entity_id(sp),
            "key_file": key,
            "cert_file": cert,
            "encryption_keypairs": [{"key_file": key, "cert_file": cert}],
            "xmlsec_binary": shutil.which("xmlsec1"),
            "metadata": {"local": [IDP_METADATA]},
            "accepted_time_diff": 180,
            "service": {
                "sp": {
                    "endpoints": {
                        "assertion_consumer_service": [(f"https://{sp}.example.com/saml2/acs", BINDING_HTTP_POST)],
                    },
                    "authn_requests_signed": True,
                    "want_response_signed": True,
                    "want_assertions_signed": False,
                    "allow_unsolicited": False,
                    "signing_algorithm": SERVICE_PROVIDERS[sp],
                    "digest_algorithm": DIGEST_SHA256,
                },
            },
        }
    )

    return Saml2Client(config)
