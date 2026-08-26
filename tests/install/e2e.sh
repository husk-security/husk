#!/bin/sh
# Offline end-to-end test for install.sh.
#
# Stands up a localhost HTTPS server that mimics the GitHub release + API URLs
# install.sh talks to, then drives the installer end-to-end against it:
#   - latest-version resolution (the /releases/latest API path),
#   - pinned-version download,
#   - SHA-256 checksum verification (and that a BAD checksum is rejected),
#   - archive extraction + atomic install into a target dir,
#   - the installed binary actually runs.
#
# This proves the whole download->verify->extract->install pipeline without a
# real GitHub release and WITHOUT weakening the installer: it uses only the
# overrides install.sh already exposes (HUSK_GITHUB_API/HUSK_GITHUB_DOWNLOAD)
# plus curl's standard CURL_CA_BUNDLE env var to trust the test's self-signed
# cert. The installer's `--proto '=https' --tlsv1.2` hardening stays on.
#
# POSIX sh. Requires: curl, tar, openssl, python3, and a sha256 tool.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$here/../.." && pwd)
install_sh="$repo_root/install.sh"
serve_py="$here/serve.py"

[ -f "$install_sh" ] || { echo "e2e: cannot find install.sh at $install_sh" >&2; exit 1; }

VERSION="v9.9.9"
REPO="husk-security/husk"

pass=0
fail=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail + 1)); }
note() { printf '\033[36m==>\033[0m %s\n' "$1"; }

# --- Replicate install.sh's target-triple detection so the mock archive name
#     matches exactly what the installer will request. -------------------------
uname_s=$(uname -s 2>/dev/null || echo unknown)
uname_m=$(uname -m 2>/dev/null || echo unknown)
case "$uname_s" in
  Linux | linux) os="unknown-linux-gnu" ;;
  Darwin | darwin) os="apple-darwin" ;;
  *) echo "e2e: unsupported test OS: $uname_s" >&2; exit 1 ;;
esac
case "$uname_m" in
  x86_64 | amd64 | x64) arch="x86_64" ;;
  aarch64 | arm64) arch="aarch64" ;;
  *) echo "e2e: unsupported test arch: $uname_m" >&2; exit 1 ;;
esac
TARGET="${arch}-${os}"
archive="husk-${VERSION}-${TARGET}.tar.gz"
note "host target triple: $TARGET"

# --- Portable sha256 helper (mirrors install.sh's fallbacks). ----------------
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else openssl dgst -sha256 "$1" | awk '{print $NF}'; fi
}

work=$(mktemp -d 2>/dev/null || mktemp -d -t husk-e2e)
srv_pid=""
bad_pid=""
cleanup() {
  if [ -n "$srv_pid" ]; then kill "$srv_pid" 2>/dev/null || true; fi
  if [ -n "$bad_pid" ]; then kill "$bad_pid" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

# --- Build the mock release tree the installer expects. ----------------------
dl_root="$work/srv"
rel_dir="$dl_root/${REPO}/releases/download/${VERSION}"
api_dir="$dl_root/repos/${REPO}/releases"
mkdir -p "$rel_dir" "$api_dir"

# A stub "husk" binary: enough to prove extract + install + exec work. The real
# binary is exercised by the gated real-release job, not this offline test.
stage="$work/stage"
mkdir -p "$stage"
cat > "$stage/husk" <<'STUB'
#!/bin/sh
echo "husk 9.9.9 (e2e stub)"
STUB
chmod +x "$stage/husk"
tar -czf "$rel_dir/$archive" -C "$stage" husk

# Per-archive checksum file in GitHub's "<hex>  <name>" format.
( cd "$rel_dir" && printf '%s  %s\n' "$(sha256_of "$archive")" "$archive" > "${archive}.sha256" )

# The /releases/latest API response install.sh greps tag_name out of.
printf '{ "tag_name": "%s", "name": "%s" }\n' "$VERSION" "$VERSION" > "$api_dir/latest"

# --- Self-signed cert for localhost, and start the HTTPS mock. ---------------
# A config file (rather than -addext) so this works on both OpenSSL and the
# LibreSSL that ships on macOS. curl verifies the SAN, not the CN.
cat > "$work/openssl.cnf" <<'CNF'
[req]
distinguished_name = dn
x509_extensions = v3
prompt = no
[dn]
CN = localhost
[v3]
subjectAltName = DNS:localhost, IP:127.0.0.1
CNF
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$work/key.pem" -out "$work/cert.pem" \
  -config "$work/openssl.cnf" -extensions v3 \
  >/dev/null 2>&1 || { echo "e2e: openssl cert generation failed" >&2; exit 1; }

port_file="$work/port"
python3 "$serve_py" "$dl_root" "$work/cert.pem" "$work/key.pem" "$port_file" &
srv_pid=$!

# Wait for the server to come up and report its port.
i=0
while [ ! -s "$port_file" ]; do
  i=$((i + 1)); [ "$i" -gt 100 ] && { echo "e2e: server never reported a port" >&2; exit 1; }
  sleep 0.1
done
port=$(cat "$port_file")
base="https://127.0.0.1:${port}"
note "mock GitHub serving at $base (pid $srv_pid)"

# curl trusts the self-signed CA via this standard env var (no script change).
CURL_CA_BUNDLE="$work/cert.pem"
export CURL_CA_BUNDLE
# Confirm the server answers before driving the installer.
curl -fsS "$base/${REPO}/releases/download/${VERSION}/${archive}.sha256" >/dev/null \
  || { echo "e2e: mock server not reachable" >&2; exit 1; }

run_install() {
  # run_install <bindir> <extra-args...>
  # --no-modify-path keeps these cases hermetic: they assert the download and
  # install pipeline, and PATH handling has its own suite (path-guidance.sh).
  _bindir="$1"; shift
  HUSK_GITHUB_DOWNLOAD="$base" \
  HUSK_GITHUB_API="$base" \
  HUSK_NO_COSIGN=1 \
  HUSK_FORCE=1 \
  NO_COLOR=1 \
    sh "$install_sh" -b "$_bindir" --no-modify-path "$@"
}

# === Test 1: pinned version installs and runs. ===============================
note "test: pinned --version $VERSION"
b1="$work/bin1"
if run_install "$b1" --version "$VERSION" >"$work/log1" 2>&1 && [ -x "$b1/husk" ] \
   && "$b1/husk" --version | grep -q "husk 9.9.9"; then
  ok "pinned-version install + run"
else
  bad "pinned-version install + run"; sed 's/^/    /' "$work/log1" >&2
fi

# === Test 2: latest-version resolution via the API. =========================
note "test: latest-version resolution"
b2="$work/bin2"
if run_install "$b2" >"$work/log2" 2>&1 && [ -x "$b2/husk" ]; then
  ok "latest-version resolution + install"
else
  bad "latest-version resolution + install"; sed 's/^/    /' "$work/log2" >&2
fi

# === Test 3: a corrupted checksum MUST be rejected (no install). ============
note "test: bad checksum is rejected"
bad_rel="$work/srv-bad/${REPO}/releases/download/${VERSION}"
mkdir -p "$bad_rel"
cp "$rel_dir/$archive" "$bad_rel/$archive"
printf '%s  %s\n' "0000000000000000000000000000000000000000000000000000000000000000" "$archive" \
  > "$bad_rel/${archive}.sha256"
# Point a second server at the tampered tree.
python3 "$serve_py" "$work/srv-bad" "$work/cert.pem" "$work/key.pem" "$work/port2" &
bad_pid=$!
i=0; while [ ! -s "$work/port2" ]; do i=$((i+1)); [ "$i" -gt 100 ] && break; sleep 0.1; done
bad_port=$(cat "$work/port2" 2>/dev/null || echo "")
b3="$work/bin3"
# A failed server start, a download failure, or any non-checksum error must NOT
# count as a pass: this is the test that proves checksum verification is
# load-bearing, so the pass requires the installer to actually run, exit
# non-zero, leave nothing installed, AND report a checksum MISMATCH.
if [ -z "$bad_port" ]; then
  bad "bad-checksum mock server failed to start (test could not run)"
elif HUSK_GITHUB_DOWNLOAD="https://127.0.0.1:${bad_port}" \
     HUSK_NO_COSIGN=1 HUSK_FORCE=1 NO_COLOR=1 \
     sh "$install_sh" -b "$b3" --version "$VERSION" >"$work/log3" 2>&1; then
  bad "bad checksum was NOT rejected (installer exited 0)"
elif [ -x "$b3/husk" ]; then
  bad "bad checksum rejected but a binary was still installed"
elif grep -qi 'mismatch' "$work/log3"; then
  ok "bad checksum rejected (checksum MISMATCH), nothing installed"
else
  bad "installer exited non-zero but NOT via a checksum mismatch"
  sed 's/^/    /' "$work/log3" >&2
fi
kill "$bad_pid" 2>/dev/null || true
bad_pid=""

# === Test 4: --no-verify still works (escape hatch). ========================
note "test: --no-verify path"
b4="$work/bin4"
if run_install "$b4" --version "$VERSION" --no-verify >"$work/log4" 2>&1 && [ -x "$b4/husk" ]; then
  ok "--no-verify install"
else
  bad "--no-verify install"; sed 's/^/    /' "$work/log4" >&2
fi

# === Test 5: `curl | sh` really leaves husk runnable in a new shell. =========
# The whole point of the PATH handling, exercised in its real shape: the script
# arrives on stdin, so the prompt has to come from the terminal instead. `script`
# supplies that terminal; without one the installer must not write anything, and
# that case is covered in path-guidance.sh.
#
# script(1) is three different programs wearing one name (util-linux, busybox,
# BSD/macOS), so the working invocation is probed rather than assumed.
pty_run() {
  case "$pty_style" in
    util) script -qec "$1" /dev/null ;;
    busybox) script -q -c "$1" /dev/null ;;
    bsd) script -q /dev/null sh -c "$1" ;;
  esac
}
pty_style=""
if command -v script >/dev/null 2>&1; then
  if script -qec true /dev/null >/dev/null 2>&1; then
    pty_style=util
  elif script -q -c true /dev/null >/dev/null 2>&1; then
    pty_style=busybox
  elif script -q /dev/null true >/dev/null 2>&1; then
    pty_style=bsd
  fi
fi

note "test: piped install leaves husk on PATH in a new shell"
if [ -z "$pty_style" ]; then
  note "skipped: no usable script(1) to allocate a pty"
else
  b5="$work/home5"
  mkdir -p "$b5"
  cat >"$work/piped.sh" <<EOF
HOME="$b5" SHELL=/bin/bash HUSK_INSTALL_DIR="$b5/.local/bin" \\
  HUSK_GITHUB_DOWNLOAD="$base" HUSK_GITHUB_API="$base" HUSK_NO_COSIGN=1 \\
  NO_COLOR=1 CURL_CA_BUNDLE="$CURL_CA_BUNDLE" \\
  sh -c 'cat "\$0" | sh -s -- --version $VERSION' "$install_sh"
EOF
  # The newline is the answer to the prompt, and has to reach the pty rather
  # than the pipeline inside it.
  printf '\n' | pty_run "sh $work/piped.sh" >"$work/log5" 2>&1 || true
  # A new login shell reads the startup file; that must be enough to find husk.
  # shellcheck disable=SC1091 # the file under test is written at run time.
  if [ -x "$b5/.local/bin/husk" ] && [ -f "$b5/.bashrc" ] && (
    HOME="$b5"
    PATH=/usr/bin:/bin
    export HOME PATH
    . "$b5/.bashrc"
    command -v husk >/dev/null
  ); then
    ok "piped install: husk resolves by name in a new shell"
  else
    bad "piped install: husk does NOT resolve by name in a new shell"
    tr -d '\r' <"$work/log5" | sed 's/^/    /' >&2
  fi
fi

printf '\n\033[36me2e:\033[0m %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
