# The independent SAML stack that the interop fixtures are made and checked with. See README.md.
#
# The base is pinned by digest. Alpine keeps only the latest revision of a package in a release's repository, so an
# exact apk version would stop building at the next security fix: the packages are held to their minor version, and
# manifest.json records the xmlsec1 that made the fixtures. pysaml2 and freezegun are pinned exactly.
#
# xmlsec1 is built from its release, pinned by SHA-256 (the same as Homebrew's), because encrypting with ECDH-ES
# needs --max-encrypted-key-level, which the 1.3.7 to 1.3.11 that Alpine and Debian ship don't have.
ARG ALPINE=alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f

FROM ${ALPINE} AS xmlsec1

ARG XMLSEC1_VERSION=1.3.13
ARG XMLSEC1_SHA256=7e500061eed734c55d74c786998e7562e55b1aaa72a2dff8ce3130b4c5b832d5

RUN apk add --no-cache build-base 'openssl-dev~3.5' libxml2-dev libxslt-dev libtool \
	&& wget -q -O /tmp/xmlsec1.tar.gz \
		"https://github.com/lsh123/xmlsec/releases/download/${XMLSEC1_VERSION}/xmlsec1-${XMLSEC1_VERSION}.tar.gz" \
	&& echo "${XMLSEC1_SHA256}  /tmp/xmlsec1.tar.gz" | sha256sum -c - \
	&& tar -xzf /tmp/xmlsec1.tar.gz -C /tmp \
	&& cd "/tmp/xmlsec1-${XMLSEC1_VERSION}" \
	&& ./configure --prefix=/opt/xmlsec1 --with-default-crypto=openssl --disable-static \
		--without-gnutls --without-gcrypt --without-nss --disable-docs \
	&& make -j"$(nproc)" \
	&& make install

FROM ${ALPINE}

COPY --from=xmlsec1 /opt/xmlsec1 /opt/xmlsec1

RUN apk add --no-cache \
		'openssl~3.5' \
		'python3~3.12' \
		libxml2 \
		libxslt \
		libltdl \
	&& python3 -m venv /venv \
	&& /venv/bin/pip install --no-cache-dir \
		pysaml2==7.5.5 \
		freezegun==1.5.5

ENV PATH=/venv/bin:/opt/xmlsec1/bin:$PATH PYTHONDONTWRITEBYTECODE=1

WORKDIR /work
