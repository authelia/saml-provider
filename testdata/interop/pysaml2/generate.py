"""Writes the service provider metadata and requests of the interop fixtures, and manifest.json, with pysaml2.

Run in the container from testdata/interop, by generate.sh. Everything pysaml2 writes is kept as it is, except
that a request is taken out of the HTTP message pysaml2 would send: the query string of a redirect, and the form
body of a POST.

Nothing is written until every case has been made, or skipped for the reason it declares, so a failure leaves the
fixtures as they were.
"""

import base64
import hashlib
import html.parser
import json
import os
import subprocess
import sys
import tempfile
import urllib.parse
from xml.etree import ElementTree

import freezegun
import saml2
from cryptography import x509
from saml2 import class_name
from saml2.metadata import create_metadata_string
from saml2.saml import NAMEID_FORMAT_EMAILADDRESS, AssertionIDRef, NameID, Subject
from saml2.samlp import AssertionIDRequest
from saml2.sigver import pre_signature_part

import config

MD = "urn:oasis:names:tc:SAML:2.0:metadata"
DS = "http://www.w3.org/2000/09/xmldsig#"
ALG = "urn:oasis:names:tc:SAML:metadata:algsupport"
XENC = "http://www.w3.org/2001/04/xmlenc#"
XENC11 = "http://www.w3.org/2009/xmlenc11#"

# No prefix is registered with ElementTree: the registry is global, and pysaml2 serializes with ElementTree too, so a
# registered prefix would change every message pysaml2 writes.


# The transforms of the metadata pysaml2 writes, by the name SERVICE_PROVIDERS gives them in config.py. Each puts in
# what pysaml2 has no setting for, and changes the metadata in place.


def _encryption_key_descriptor(metadata):
    descriptors = [
        kd for kd in metadata.iter(f"{{{MD}}}KeyDescriptor") if kd.get("use") == "encryption"
    ]
    if len(descriptors) != 1:
        raise RuntimeError(f"expected one encryption KeyDescriptor, found {len(descriptors)}")

    return descriptors[0]


def _encryption_method(algorithm, digest=None, mgf=None):
    method = ElementTree.Element(f"{{{MD}}}EncryptionMethod", Algorithm=algorithm)
    if digest:
        ElementTree.SubElement(method, f"{{{DS}}}DigestMethod", Algorithm=digest)
    if mgf:
        ElementTree.SubElement(method, f"{{{XENC11}}}MGF", Algorithm=mgf)

    return method


def algorithms_rsa_sha512_sha384(metadata):
    """Lists RSA-SHA512 as the only signature algorithm and SHA-384 as the only digest the SP supports, in place of
    every algorithm pysaml2 lists from xmlsec1 (Metadata Profile for Algorithm Support §2.4). The digest differs from
    the hash of the signature algorithm, which is what the identity provider would use if it ignored the list."""
    extensions = metadata.find(f"{{{MD}}}Extensions")
    for el in list(extensions):
        if el.tag in (f"{{{ALG}}}SigningMethod", f"{{{ALG}}}DigestMethod"):
            extensions.remove(el)

    ElementTree.SubElement(
        extensions, f"{{{ALG}}}DigestMethod", Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384"
    )
    ElementTree.SubElement(
        extensions, f"{{{ALG}}}SigningMethod", Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
    )


def encryption_methods_gcm256_oaep11(metadata):
    """Lists AES-256-GCM, and RSA-OAEP of XML Encryption 1.1 with SHA-256 and MGF1 with SHA-256, as the only
    algorithms of the encryption key (SAMLMeta §2.4.1.1)."""
    kd = _encryption_key_descriptor(metadata)
    kd.append(_encryption_method(XENC11 + "aes256-gcm"))
    kd.append(_encryption_method(XENC11 + "rsa-oaep", digest=XENC + "sha256", mgf=XENC11 + "mgf1sha256"))


def encryption_methods_cbc256_mgf1p(metadata):
    """Lists AES-256-CBC and RSA-OAEP-MGF1P as the only algorithms of the encryption key."""
    kd = _encryption_key_descriptor(metadata)
    kd.append(_encryption_method(XENC + "aes256-cbc"))
    kd.append(_encryption_method(XENC + "rsa-oaep-mgf1p"))


def _crypto_binary(number):
    return base64.b64encode(number.to_bytes((number.bit_length() + 7) // 8, "big")).decode()


def encryption_key_value(metadata):
    """Gives the encryption key as a ds:KeyValue in place of its certificate (MetaIOP §2.5.1, §2.6.1)."""
    key_info = _encryption_key_descriptor(metadata).find(f"{{{DS}}}KeyInfo")
    x509_data = key_info.find(f"{{{DS}}}X509Data")
    der = base64.b64decode("".join(x509_data.find(f"{{{DS}}}X509Certificate").text.split()))
    numbers = x509.load_der_x509_certificate(der).public_key().public_numbers()

    key_info.remove(x509_data)
    rsa = ElementTree.SubElement(ElementTree.SubElement(key_info, f"{{{DS}}}KeyValue"), f"{{{DS}}}RSAKeyValue")
    ElementTree.SubElement(rsa, f"{{{DS}}}Modulus").text = _crypto_binary(numbers.n)
    ElementTree.SubElement(rsa, f"{{{DS}}}Exponent").text = _crypto_binary(numbers.e)


TRANSFORMS = {
    f.__name__: f
    for f in (algorithms_rsa_sha512_sha384, encryption_methods_gcm256_oaep11, encryption_methods_cbc256_mgf1p, encryption_key_value)
}


def metadata(client, sp):
    """Returns the metadata of a service provider: what pysaml2 writes, with the transforms of its entry applied."""
    data = create_metadata_string(None, config=client.config)
    transforms = config.SERVICE_PROVIDERS[sp].get("transforms", [])
    if not transforms:
        return data

    root = ElementTree.fromstring(data)
    for name in transforms:
        TRANSFORMS[name](root)

    return ElementTree.tostring(root, xml_declaration=True, encoding="utf-8")


class _FormInputs(html.parser.HTMLParser):
    """Collects the hidden inputs of the auto-submitting form pysaml2 writes for the POST binding."""

    def __init__(self):
        super().__init__()
        self.inputs = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and "name" in attrs:
            self.inputs[attrs["name"]] = attrs.get("value", "")


def request(client, case):
    """Returns what is sent to the identity provider for a case: a query string or a form body."""
    binding = config.BINDINGS[case["binding"]]
    response_binding = {"artifact": saml2.BINDING_HTTP_ARTIFACT}.get(case.get("response_binding"), saml2.BINDING_HTTP_POST)
    _, info = client.prepare_for_authenticate(
        binding=binding,
        response_binding=response_binding,
        relay_state="interop",
        message_id=case["request_id"],
        sign=True,
        sigalg=config.SERVICE_PROVIDERS[case["sp"]]["sigalg"],
        digest_alg=config.DIGEST_SHA256,
    )

    if binding == saml2.BINDING_HTTP_REDIRECT:
        location = dict(info["headers"])["Location"]
        return urllib.parse.urlsplit(location).query

    form = _FormInputs()
    form.feed(info["data"])
    return urllib.parse.urlencode({"SAMLRequest": form.inputs["SAMLRequest"], "RelayState": form.inputs["RelayState"]})


SAML = "urn:oasis:names:tc:SAML:2.0:assertion"

# What xmlsec1 fills in to encrypt a NameID to the identity provider, by the template a case names. "oaep" transports
# the key with RSA-OAEP-MGF1P to the certificate loaded as "idp". "ecdh-es" agrees it by ECDH-ES between a fresh
# originator key and the certificate loaded as "recipient", as xmlenc/ecdhes_interop_test.go does, and xmlsec1
# writes the ECKeyValue of the originator.
SUBJECT_TEMPLATES = {
    "oaep": """<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
 xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element">
<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
<ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
<ds:KeyInfo><ds:KeyName>idp</ds:KeyName></ds:KeyInfo><xenc:CipherData><xenc:CipherValue/></xenc:CipherData>
</xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>""",
    "ecdh-es": """<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
 xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xenc11="http://www.w3.org/2009/xmlenc11#"
 Type="http://www.w3.org/2001/04/xmlenc#Element">
<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
<ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes128"/>
<ds:KeyInfo><xenc:AgreementMethod Algorithm="http://www.w3.org/2009/xmlenc11#ECDH-ES">
<xenc11:KeyDerivationMethod Algorithm="http://www.w3.org/2009/xmlenc11#ConcatKDF">
<xenc11:ConcatKDFParams AlgorithmID="00" PartyUInfo="00" PartyVInfo="00">
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></xenc11:ConcatKDFParams>
</xenc11:KeyDerivationMethod>
<xenc:OriginatorKeyInfo><ds:KeyName>originator</ds:KeyName><ds:KeyValue/></xenc:OriginatorKeyInfo>
<xenc:RecipientKeyInfo><ds:KeyName>recipient</ds:KeyName></xenc:RecipientKeyInfo>
</xenc:AgreementMethod></ds:KeyInfo><xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedKey>
</ds:KeyInfo><xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>""",
}


def _encryption_certificate(metadata_path):
    """Returns, in PEM, the certificate of the encryption key that identity provider metadata publishes."""
    root = ElementTree.parse(metadata_path).getroot()
    certificates = [
        kd.find(f".//{{{DS}}}X509Certificate").text
        for kd in root.iter(f"{{{MD}}}KeyDescriptor")
        if kd.get("use") == "encryption"
    ]
    if len(certificates) != 1:
        raise RuntimeError(f"{metadata_path}: expected one encryption certificate, found {len(certificates)}")

    body = "".join(certificates[0].split())
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def _encrypt_with_xmlsec1(data, template, metadata_path):
    """Encrypts the XML data with xmlsec1 to the encryption key in the identity provider metadata, and returns the
    xenc:EncryptedData."""
    with tempfile.TemporaryDirectory() as tmp:
        cert, data_path, template_path = (os.path.join(tmp, n) for n in ("idp.crt", "data.xml", "template.xml"))
        for path, content in ((cert, _encryption_certificate(metadata_path)), (template_path, SUBJECT_TEMPLATES[template])):
            with open(path, "w") as f:
                f.write(content)
        with open(data_path, "wb") as f:
            f.write(data)

        if template == "ecdh-es":
            originator = os.path.join(tmp, "originator.key")
            subprocess.run(
                ["openssl", "genpkey", "-quiet", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", originator],
                check=True,
            )
            keys = [
                # xmlsec1 only reads the key data of ECDH-ES when it is enabled, and nests the AgreementMethod one
                # level below the EncryptedKey that holds it.
                "--enabled-key-data", "agreement-method,enc-key,key-value,key-name,ec,x509",
                "--max-encrypted-key-level", "3",
                "--privkey-pem:originator", originator, "--pubkey-cert-pem:recipient", cert,
            ]
        else:
            keys = ["--pubkey-cert-pem:idp", cert]

        result = subprocess.run(
            ["xmlsec1", "--encrypt", *keys, "--session-key", "aes-128", "--xml-data", data_path, template_path],
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"xmlsec1 could not encrypt: {result.stderr.decode().strip()}")

        return ElementTree.fromstring(result.stdout)


def encrypt_subject_and_sign(client, case, message):
    """Returns the request message, which pysaml2 made unsigned with a NameID in its Subject, with that NameID
    encrypted in place by xmlsec1 to the key the case names (SAMLCore §2.2.4) and then signed by pysaml2, so that the
    signature covers the EncryptedID."""
    spec = case["encrypt_subject"]
    entry = config.SERVICE_PROVIDERS[case["sp"]]
    message.signature = pre_signature_part(
        message.id, client.sec.my_cert, 1, sign_alg=entry["sigalg"], digest_alg=config.DIGEST_SHA256
    )

    root = ElementTree.fromstring(str(message))
    subject = root.find(f"{{{SAML}}}Subject")
    name_id = subject.find(f"{{{SAML}}}NameID")
    index = list(subject).index(name_id)

    encrypted_id = ElementTree.Element(f"{{{SAML}}}EncryptedID")
    encrypted_id.append(_encrypt_with_xmlsec1(ElementTree.tostring(name_id), spec["template"], spec["to"]))
    subject.remove(name_id)
    subject.insert(index, encrypted_id)

    return client.sec.sign_statement(ElementTree.tostring(root).decode(), class_name(message), node_id=message.id)


def subject_name_id(case):
    """Returns the NameID that the Subject of the request of a case names, before it is encrypted if it is."""
    value = case.get("encrypt_subject", case.get("query", {})).get("name_id")
    return NameID(format=NAMEID_FORMAT_EMAILADDRESS, text=value)


def encrypted_subject_request(client, case):
    """Returns the POST form body of an AuthnRequest whose Subject is an EncryptedID."""
    idp = next(iter(client.metadata.identity_providers()))
    destination = client.metadata.single_sign_on_service(idp, saml2.BINDING_HTTP_POST)[0]["location"]

    _, request = client.create_authn_request(
        destination,
        binding=saml2.BINDING_HTTP_POST,
        message_id=case["request_id"],
        sign=False,
        subject=Subject(name_id=subject_name_id(case)),
    )
    signed = encrypt_subject_and_sign(client, case, request)

    return urllib.parse.urlencode(
        {"SAMLRequest": base64.b64encode(signed.encode()).decode(), "RelayState": "interop"}
    )


URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"


def soap_request(client, case):
    """Returns the SOAP envelope of a query or ArtifactResolve that pysaml2 makes and signs for a case, to the
    service of the identity provider its endpoint names, as listed in the identity provider metadata."""
    entry = config.SERVICE_PROVIDERS[case["sp"]]
    idp = next(iter(client.metadata.identity_providers()))
    # A request whose Subject is encrypted is made unsigned, and signed once it is encrypted.
    encrypt = "encrypt_subject" in case
    sign = {"sign": not encrypt, "sign_alg": entry["sigalg"], "digest_alg": config.DIGEST_SHA256}
    spec = case.get("query", {})

    if case["endpoint"] == "attribute":
        destination = client.metadata.attribute_service(idp, saml2.BINDING_SOAP)[0]["location"]
        attributes = {(name, URI, None): [] for name in spec.get("attributes", [])}
        _, message = client.create_attribute_query(
            destination, name_id=subject_name_id(case), attribute=attributes or None, message_id=case["request_id"], **sign
        )
    elif case["endpoint"] == "artifact":
        destination = client.metadata.artifact_resolution_service(idp, saml2.BINDING_SOAP, "idpsso")[0]["location"]
        _, message = client.create_artifact_resolve(
            issued(case["artifact_of"])["artifact"], destination, case["request_id"], **sign
        )
    elif case["endpoint"] == "assertion-id":
        # pysaml2's create_assertion_id_request only returns the ID it is given, so the request is made with
        # _message, which each of its create_ methods makes and signs its message with.
        destination = client.metadata.assertion_id_request_service(idp, saml2.BINDING_SOAP, "idpsso")[0]["location"]
        _, message = client._message(
            AssertionIDRequest,
            destination,
            case["request_id"],
            assertion_id_ref=[AssertionIDRef(text=issued(case["assertion_of"])["assertion_id"])],
            **sign,
        )
    elif case["endpoint"] == "authn-query":
        destination = client.metadata.authn_query_service(idp, saml2.BINDING_SOAP)[0]["location"]
        _, message = client.create_authn_query(
            Subject(name_id=subject_name_id(case)), destination, message_id=case["request_id"], **sign
        )
    else:
        raise RuntimeError(f"{case['id']}: unknown endpoint {case['endpoint']!r}")

    if encrypt:
        message = encrypt_subject_and_sign(client, case, message)

    # The message is signed already: apply_binding would sign the envelope again.
    return client.apply_binding(saml2.BINDING_SOAP, str(message), destination, sign=False)["data"]


def uri_request(client, case):
    """Returns the query string of the GET that pysaml2 makes on the SAML URI binding (SAMLBind §3.7) for a case: to
    the AssertionIDRequestService of that binding in the identity provider metadata, for the assertion the case
    names."""
    idp = next(iter(client.metadata.identity_providers()))
    destination = client.metadata.assertion_id_request_service(idp, saml2.BINDING_URI, "idpsso")[0]["location"]
    _, ref = client.create_assertion_id_request(issued(case["assertion_of"])["assertion_id"])
    url = client.apply_binding(saml2.BINDING_URI, ref, destination)["url"]

    base, _, query = url.partition("?")
    if base != destination:
        raise RuntimeError(f"{case['id']}: pysaml2 sends the request to {base!r}, not {destination!r}")

    return query


def issued(case_id):
    """Returns what the identity provider issued for a case on a replay, as TestInteropIssued records it."""
    try:
        with open(config.ISSUED) as f:
            record = json.load(f)
    except FileNotFoundError:
        record = {}

    if case_id not in record:
        raise RuntimeError(f"{config.ISSUED} records nothing for {case_id}: run generate.sh, which records it")

    return record[case_id]


def depends_on_issued(case):
    """Reports whether the request of a case is made from what the identity provider issued for another."""
    return "artifact_of" in case or "assertion_of" in case


def source(case, files, versions):
    """Returns the digest of everything the request of a case is made from: the case and the entry of its service
    provider as config.py gives them, this file, which holds the templates and the code that makes the request, the
    metadata of the service provider, the identity provider metadata it encrypts to, and the versions of pysaml2 and
    xmlsec1."""
    digest = hashlib.sha256(json.dumps(case, sort_keys=True).encode())
    digest.update(json.dumps(config.SERVICE_PROVIDERS[case["sp"]], sort_keys=True).encode())
    with open(__file__, "rb") as f:
        digest.update(f.read())
    digest.update(files[f"sp/metadata/{case['sp']}.xml"])
    # The identity provider metadata pysaml2 is configured with, which the request is addressed from, and the one an
    # EncryptedID is encrypted to.
    for path in (config.IDP_METADATA, case.get("encrypt_subject", {}).get("to")):
        if path:
            with open(path, "rb") as f:
                digest.update(f.read())
    for of in ("artifact_of", "assertion_of"):
        if of in case:
            digest.update(json.dumps(issued(case[of]), sort_keys=True).encode())
    digest.update(json.dumps(versions, sort_keys=True).encode())

    return digest.hexdigest()


def previous_requests():
    """Returns, by case id, the source and request of each case of the manifest.json that is there, whose request
    file is there too and is still the one manifest.json records the digest of. A manifest.json that is missing or
    can't be read keeps nothing, and every request is made again."""
    try:
        with open("manifest.json") as f:
            cases = json.load(f)["cases"]
    except FileNotFoundError:
        return {}
    except (ValueError, KeyError, TypeError) as e:
        print(f"manifest.json can't be read, so every request is made again: {type(e).__name__}: {e}", file=sys.stderr)
        return {}

    previous = {}
    for case in cases:
        if case.get("source") and case.get("request") and os.path.exists(case["request"]):
            with open(case["request"], "rb") as f:
                data = f.read()
            if hashlib.sha256(data).hexdigest() == case.get("request_sha256"):
                previous[case["id"]] = (case["source"], data)

    return previous


def make_case(client, case, files, versions, previous):
    """Makes the request of a case into files, and returns the case as manifest.json lists it.

    A request that xmlsec1 encrypts differs each time it is made, as its key and IV are random. One whose source is
    unchanged is kept as it is, so that regenerating the fixtures changes no file unless what they are made from
    changed."""
    digest = source(case, files, versions)
    made_by = "pysaml2+transform" if config.SERVICE_PROVIDERS[case["sp"]].get("transforms") else "pysaml2"
    if "encrypt_subject" in case:
        made_by = "pysaml2+xmlsec1"
    case = dict(case, made_by=made_by, request_id="id-" + case["id"])
    path = f"sp/requests/{case['id']}.{ {'redirect-signed': 'query', 'uri': 'query', 'soap': 'soap'}.get(case['binding'], 'form') }"

    unmakeable = case.pop("unmakeable", None)
    known_bug = case.pop("known_bug", None)

    if ("encrypt_subject" in case or depends_on_issued(case)) and previous.get(case["id"], (None,))[0] == digest:
        data = previous[case["id"]][1]
        case.update(request=path, source=digest, request_sha256=hashlib.sha256(data).hexdigest())
        files[path] = data
        if known_bug is not None:
            case["skip"] = f"known bug: {known_bug}"

        return case

    try:
        if case["binding"] == "soap":
            body = soap_request(client, case)
        elif case["binding"] == "uri":
            body = uri_request(client, case)
        elif "encrypt_subject" in case:
            body = encrypted_subject_request(client, case)
        else:
            body = request(client, case)
    except Exception as e:  # noqa: BLE001 - re-raised unless it is the error the case declares.
        if unmakeable is None or unmakeable["error"] not in str(e):
            raise RuntimeError(f"pysaml2 could not make the request of {case['id']}") from e

        case["skip"] = f"{unmakeable['reason']}: {type(e).__name__}: {e}"
        files[path] = None
    else:
        if unmakeable is not None:
            raise RuntimeError(f"pysaml2 made the request of {case['id']}: remove its unmakeable")

        files[path] = body.encode()
        case.update(request=path, source=digest, request_sha256=hashlib.sha256(files[path]).hexdigest())

        if known_bug is not None:
            case["skip"] = f"known bug: {known_bug}"

    return case


def write(files):
    """Writes every file, or removes it for None, each through a temporary file renamed into place."""
    for path, data in files.items():
        if data is None:
            if os.path.exists(path):
                os.remove(path)

            continue

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

        with open(path + ".tmp", "wb") as f:
            f.write(data)

        os.replace(path + ".tmp", path)


def main(first_pass=False):
    """Writes the fixtures. On the first pass, the cases whose requests are made from what the identity provider
    issued are left out, as TestInteropIssued records that from the requests of this pass."""
    ids = [case["id"] for case in config.CASES]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise RuntimeError(f"duplicate case ids: {', '.join(duplicates)}")

    files, cases, previous = {}, [], previous_requests()
    xmlsec1 = subprocess.run(["xmlsec1", "--version"], capture_output=True, text=True, check=True).stdout.strip()
    versions = {"pysaml2": _version(), "xmlsec1": xmlsec1}

    with freezegun.freeze_time(config.INSTANT):
        clients = {sp: config.client(sp) for sp in config.SERVICE_PROVIDERS}

        for sp, client in clients.items():
            files[f"sp/metadata/{sp}.xml"] = metadata(client, sp)

        for case in config.CASES:
            if first_pass and depends_on_issued(case):
                continue

            cases.append(make_case(clients[case["sp"]], case, files, versions, previous))

    manifest = {
        "pysaml2": versions["pysaml2"],
        "xmlsec1": versions["xmlsec1"],
        "instant": config.INSTANT.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cases": cases,
    }
    files["manifest.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()

    # A request or metadata file that no case or service provider makes any more is removed with the rest.
    for directory in ("sp/requests", "sp/metadata"):
        for name in os.listdir(directory) if os.path.isdir(directory) else []:
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                files.setdefault(path, None)

    write(files)


def _version():
    from importlib.metadata import version

    return version("pysaml2")


if __name__ == "__main__":
    main(first_pass="--first-pass" in sys.argv[1:])
