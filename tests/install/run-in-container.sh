#!/bin/sh
# Entry point used by CI to test install.sh inside a distro container.
#
# It is invoked as `docker run ... <distro-image> sh tests/install/run-in-container.sh`
# so the install matrix sidesteps the well-known "glibc node can't run in a musl
# (Alpine) container" problem with actions/checkout: we check out on the host and
# mount the source in, then run the tests under the distro's own shells/tools.
#
# It installs the handful of tools the tests need via whatever package manager
# the distro has, then runs the portability + offline end-to-end suites.

set -eu

log() { printf '\033[36m[container]\033[0m %s\n' "$*"; }

# Core tools the installer + tests require; the optional shells widen coverage.
if command -v apk >/dev/null 2>&1; then
  log "alpine: apk"
  apk add --no-cache curl tar openssl python3 coreutils gawk gzip util-linux >/dev/null
  apk add --no-cache bash dash >/dev/null 2>&1 || true   # busybox sh is built in
elif command -v apt-get >/dev/null 2>&1; then
  log "debian/ubuntu: apt-get"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq curl tar openssl python3 ca-certificates coreutils gawk gzip util-linux >/dev/null
  apt-get install -y -qq bash dash busybox >/dev/null 2>&1 || true
elif command -v dnf >/dev/null 2>&1; then
  log "fedora: dnf"
  dnf install -y -q curl tar openssl python3 coreutils gawk gzip util-linux >/dev/null
  dnf install -y -q bash dash busybox >/dev/null 2>&1 || true
elif command -v pacman >/dev/null 2>&1; then
  log "arch: pacman"
  pacman -Sy --noconfirm --needed curl tar openssl python coreutils gawk gzip util-linux >/dev/null
  pacman -S --noconfirm --needed bash dash busybox >/dev/null 2>&1 || true
elif command -v zypper >/dev/null 2>&1; then
  log "opensuse: zypper"
  zypper --non-interactive --quiet install curl tar openssl python3 coreutils gawk gzip util-linux >/dev/null
  zypper --non-interactive --quiet install bash dash busybox >/dev/null 2>&1 || true
else
  log "no known package manager; assuming required tools are already present"
fi

# Arch (and some minimal images) ship python3 as `python`; give the tests a
# `python3` to call.
if ! command -v python3 >/dev/null 2>&1 && command -v python >/dev/null 2>&1; then
  ln -sf "$(command -v python)" /usr/local/bin/python3
fi

log "available shells/tools:"
for c in sh bash dash busybox curl wget tar openssl python3 sha256sum shasum awk script; do
  if command -v "$c" >/dev/null 2>&1; then printf '  %-10s %s\n' "$c" "$(command -v "$c")"; fi
done

dir=$(cd "$(dirname "$0")" && pwd)
log "running portability.sh"
sh "$dir/portability.sh"
log "running path-guidance.sh"
sh "$dir/path-guidance.sh"
log "running e2e.sh"
sh "$dir/e2e.sh"
