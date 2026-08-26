#!/bin/sh
# Real end-to-end install test against an ACTUAL published GitHub release.
#
# Unlike e2e.sh (which mocks GitHub offline), this downloads the real signed
# release through the real installer and confirms the real husk binary runs. It
# only makes sense once a release exists, so CI gates it on release/dispatch.
#
# Env:
#   VERSION       release tag to install (e.g. v0.0.1). Empty => latest.
#   GITHUB_TOKEN  optional, to avoid the unauthenticated API rate limit.
#
# Installs its own minimal deps so it can run in a bare distro container.

set -eu

if command -v apk >/dev/null 2>&1; then
  apk add --no-cache curl tar gzip ca-certificates >/dev/null
elif command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null && apt-get install -y -qq curl tar gzip ca-certificates >/dev/null
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q curl tar gzip ca-certificates >/dev/null
fi

bindir="$(mktemp -d)/bin"
ver="${VERSION:-}"

# shellcheck disable=SC2086 # intentional word-splitting of the optional flag.
sh ./install.sh ${ver:+--version "$ver"} --force -b "$bindir"

"$bindir/husk" --version
printf '\033[32mreal-release e2e OK\033[0m: %s\n' "$("$bindir/husk" --version)"
