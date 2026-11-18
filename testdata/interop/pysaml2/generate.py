"""Writes the service provider metadata and requests of the interop fixtures, and manifest.json, with pysaml2.

Run in the container from testdata/interop, by generate.sh. Everything pysaml2 writes is kept as it is, except
that a request is taken out of the HTTP message pysaml2 would send: the query string of a redirect, and the form
body of a POST.

Nothing is written until every case has been made, or skipped for the reason it declares, so a failure leaves the
fixtures as they were.
"""

import html.parser
import json
import os
import subprocess
import urllib.parse

import freezegun
import saml2
from saml2.metadata import create_metadata_string

import config


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
    _, info = client.prepare_for_authenticate(
        binding=binding,
        relay_state="interop",
        message_id=case["request_id"],
        sign=True,
        sigalg=config.SERVICE_PROVIDERS[case["sp"]],
        digest_alg=config.DIGEST_SHA256,
    )

    if binding == saml2.BINDING_HTTP_REDIRECT:
        location = dict(info["headers"])["Location"]
        return urllib.parse.urlsplit(location).query

    form = _FormInputs()
    form.feed(info["data"])
    return urllib.parse.urlencode({"SAMLRequest": form.inputs["SAMLRequest"], "RelayState": form.inputs["RelayState"]})


def make_case(client, case, files):
    """Makes the request of a case into files, and returns the case as manifest.json lists it."""
    case = dict(case, made_by="pysaml2", request_id="id-" + case["id"])
    path = f"sp/requests/{case['id']}.{'query' if case['binding'] == 'redirect-signed' else 'form'}"

    unmakeable = case.pop("unmakeable", None)
    known_bug = case.pop("known_bug", None)

    try:
        body = request(client, case)
    except Exception as e:  # noqa: BLE001 - re-raised unless it is the error the case declares.
        if unmakeable is None or unmakeable["error"] not in str(e):
            raise RuntimeError(f"pysaml2 could not make the request of {case['id']}") from e

        case["skip"] = f"{unmakeable['reason']}: {type(e).__name__}: {e}"
        files[path] = None
    else:
        if unmakeable is not None:
            raise RuntimeError(f"pysaml2 made the request of {case['id']}: remove its unmakeable")

        case["request"] = path
        files[path] = body.encode()

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


def main():
    ids = [case["id"] for case in config.CASES]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise RuntimeError(f"duplicate case ids: {', '.join(duplicates)}")

    files, cases = {}, []

    with freezegun.freeze_time(config.INSTANT):
        clients = {sp: config.client(sp) for sp in config.SERVICE_PROVIDERS}

        for sp, client in clients.items():
            files[f"sp/metadata/{sp}.xml"] = create_metadata_string(None, config=client.config)

        for case in config.CASES:
            cases.append(make_case(clients[case["sp"]], case, files))

    xmlsec1 = subprocess.run(["xmlsec1", "--version"], capture_output=True, text=True, check=True).stdout.strip()

    manifest = {
        "pysaml2": saml2.__version__ if hasattr(saml2, "__version__") else _version(),
        "xmlsec1": xmlsec1,
        "instant": config.INSTANT.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cases": cases,
    }
    files["manifest.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()

    write(files)


def _version():
    from importlib.metadata import version

    return version("pysaml2")


if __name__ == "__main__":
    main()
