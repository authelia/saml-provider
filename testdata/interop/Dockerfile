# The independent SAML stack that the interop fixtures are made and checked with. See README.md.
#
# Alpine 3.22 rather than Debian: xmlsec1 1.3 or later is needed for ECDH-ES, AES-GCM and RSA-OAEP 1.1, and the
# stable Debian release ships 1.2.
#
# The base is pinned by digest. Alpine keeps only the latest revision of a package in a release's repository, so an
# exact apk version would stop building at the next security fix: the packages are held to their minor version, and
# manifest.json records the xmlsec1 that made the fixtures. pysaml2 and freezegun are pinned exactly.
FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f

RUN apk add --no-cache \
		'openssl~3.5' \
		'python3~3.12' \
		'xmlsec~1.3' \
	&& python3 -m venv /venv \
	&& /venv/bin/pip install --no-cache-dir \
		pysaml2==7.5.5 \
		freezegun==1.5.5

ENV PATH=/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1

WORKDIR /work
