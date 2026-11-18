#!/bin/sh
# Makes the key pairs of the interop fixtures, once. A complete pair is kept, so that regenerating the fixtures
# doesn't change every certificate and every metadata document. A key without its certificate gets one made for it;
# a certificate without its key is replaced with the new pair. Each file is written to a temporary name and renamed
# into place only once openssl has succeeded.
set -eu

cd "$(dirname "$0")/keys"

for name in idp-rsa idp-ec sp-rsa sp-ec; do
	[ -f "$name.key" ] && [ -f "$name.crt" ] && continue

	case "$name" in
	*-rsa)
		algorithm="-algorithm RSA -pkeyopt rsa_keygen_bits:2048"
		usage="digitalSignature,keyEncipherment"
		;;
	*-ec)
		algorithm="-algorithm EC -pkeyopt ec_paramgen_curve:P-256"
		usage="digitalSignature,keyAgreement"
		;;
	esac

	if [ ! -f "$name.key" ]; then
		# shellcheck disable=SC2086 # $algorithm is several arguments.
		openssl genpkey -quiet $algorithm -out "$name.key.tmp"
		mv "$name.key.tmp" "$name.key"
	fi

	openssl req -x509 -new -key "$name.key" -subj "/CN=$name" -sha256 \
		-not_before 20260101000000Z -not_after 20360101000000Z \
		-addext "keyUsage=critical,$usage" -out "$name.crt.tmp"
	mv "$name.crt.tmp" "$name.crt"
done
