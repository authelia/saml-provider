#!/usr/bin/env bash
# Regenerates the interop fixtures with pysaml2, replays them against the identity provider, and has pysaml2 check
# every response. See README.md. Exits non-zero if any response is rejected.
set -euo pipefail

cd "$(dirname "$0")/../.."

if ! command -v docker >/dev/null 2>&1; then
	echo "docker is required" >&2
	exit 2
fi

image=saml-provider-interop:local
interop="$PWD/testdata/interop"
emit="$(mktemp -d)"
trap 'rm -rf "$emit"' EXIT

# run runs a command in the image as the host user, so that what it writes, such as a new key, is owned by that user
# and keeps the permissions it was made with.
run() {
	docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$interop:/work" -v "$emit:/emit" "$image" "$@"
}

# gotest runs go test, printing its output only if it fails.
gotest() {
	local out
	if ! out="$(go test -count=1 "$@" 2>&1)"; then
		printf '%s\n' "$out" >&2
		return 1
	fi
}

docker build -q -t "$image" "$interop" >/dev/null
run sh keys.sh
SAML_INTEROP_UPDATE=1 gotest -run '^TestInteropIDPMetadata$' .
# The first pass makes the requests that don't depend on what the identity provider issues, TestInteropIssued
# replays them and records what it issues, and the second pass makes every request.
run python pysaml2/generate.py --first-pass
SAML_INTEROP_UPDATE=1 gotest -run '^TestInteropIssued$' .
run python pysaml2/generate.py
SAML_INTEROP_EMIT="$emit" gotest -run '^TestInterop$' .
run python pysaml2/verify.py /emit
