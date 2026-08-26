#!/bin/sh
# husk installer: download, verify, and install the husk binary.
#
# Usage:
#   curl -fsSL https://husk-security.dev/install.sh | sh
#
# Pass flags through the pipe with `sh -s --`:
#   curl -fsSL <url> | sh -s -- --version v0.0.1
#
# Privacy: this installer phones home NOTHING beyond fetching the release archive,
# its checksum, and its signature from GitHub. No analytics, no install ping, in
# keeping with husk's local-first, no-account promise.
#
# It writes exactly two things: the binary, and (only after asking, and only
# when the install dir is not already on PATH) one PATH line in one shell
# startup file. With no terminal to ask on it writes nothing but the binary.
#
# This script is POSIX sh: it runs under dash and busybox sh, not just bash.
# No bashisms, no `pipefail`. It fails loudly and never installs a partial or
# unverified binary.

set -eu

# If husk ever moves repos, update this AND the cosign identity regexp below.
REPO="${HUSK_REPO:-husk-security/husk}"

BIN="${HUSK_BIN:-husk}"

# ~/.local/bin is the XDG-ish per-user default and needs no sudo.
HUSK_INSTALL_DIR="${HUSK_INSTALL_DIR:-${HOME}/.local/bin}"

# Empty means "resolve the latest release". Accepts both "v0.0.1" and "0.0.1";
# normalized to a leading "v" later (tags are vX.Y.Z).
HUSK_VERSION="${HUSK_VERSION:-}"

# Verification toggles, both ON by default; any non-empty value turns the
# corresponding check off (the checksum skip is always warned loudly).
HUSK_NO_VERIFY="${HUSK_NO_VERIFY:-}"
HUSK_NO_COSIGN="${HUSK_NO_COSIGN:-}"

HUSK_FORCE="${HUSK_FORCE:-}"

# Whether the installer may add the install dir to the user's shell startup
# file. Asked for interactively; never done silently. Any non-empty value here
# refuses outright.
HUSK_NO_MODIFY_PATH="${HUSK_NO_MODIFY_PATH:-}"

# cosign trust anchors; must match the README's "Verifying a release" section.
# The certificate identity is the release workflow's OIDC subject, not an email.
# If the repo or workflow file is renamed, update both this and that README section.
COSIGN_IDENTITY_RE="${HUSK_COSIGN_IDENTITY_RE:-^https://github.com/husk-security/husk/\.github/workflows/release\.yml@refs/tags/v}"
COSIGN_OIDC_ISSUER="${HUSK_COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

# Overridable mostly for testing against a mirror.
GH_API="${HUSK_GITHUB_API:-https://api.github.com}"
GH_DOWNLOAD="${HUSK_GITHUB_DOWNLOAD:-https://github.com}"

# GitHub's API requires a User-Agent.
USER_AGENT="husk-installer"

# Output helpers. Everything goes to stderr so a caller can safely capture or
# pipe stdout; err exits non-zero.

if [ -t 2 ] && [ -z "${NO_COLOR-}" ]; then
  C_RESET="$(printf '\033[0m')"
  C_BOLD="$(printf '\033[1m')"
  C_DIM="$(printf '\033[2m')"
  C_RED="$(printf '\033[31m')"
  C_GREEN="$(printf '\033[32m')"
  C_YELLOW="$(printf '\033[33m')"
  C_CYAN="$(printf '\033[36m')"
else
  C_RESET=""
  C_BOLD=""
  C_DIM=""
  C_RED=""
  C_GREEN=""
  C_YELLOW=""
  C_CYAN=""
fi

info() {
  printf '%shusk%s %s\n' "${C_CYAN}" "${C_RESET}" "$*" >&2
}

ok() {
  printf '%shusk%s %s%s%s\n' "${C_CYAN}" "${C_RESET}" "${C_GREEN}" "$*" "${C_RESET}" >&2
}

warn() {
  printf '%shusk%s %swarning:%s %s\n' "${C_CYAN}" "${C_RESET}" "${C_YELLOW}" "${C_RESET}" "$*" >&2
}

err() {
  printf '%shusk%s %serror:%s %s\n' "${C_CYAN}" "${C_RESET}" "${C_RED}" "${C_RESET}" "$*" >&2
  exit 1
}

has() {
  command -v "$1" >/dev/null 2>&1
}

need_cmd() {
  has "$1" || err "required command not found: $1"
}

usage() {
  cat >&2 <<EOF
${C_BOLD}husk installer${C_RESET}

Installs the husk binary from GitHub Releases, verifying its checksum (and, if
cosign is present, its Sigstore signature) before installing.

${C_BOLD}Usage:${C_RESET}
  curl -fsSL https://husk-security.dev/install.sh | sh
  curl -fsSL <url> | sh -s -- [options]
  ./install.sh [options]

${C_BOLD}Options:${C_RESET}
  --version <ver>        Install a specific version (e.g. v0.0.1). Default: latest.
  -b, --install-dir <d>  Install into directory <d>. Default: \$HOME/.local/bin.
  --no-verify            Skip SHA-256 checksum verification (NOT recommended).
  --no-verify-signature  Skip cosign signature verification even if cosign
                         exists (NOT recommended). Alias: --no-cosign.
  --no-modify-path       Never write to a shell startup file; just print the
                         command that adds the install dir to PATH.
  -y, -f, --force        Non-interactive; accept the defaults without asking,
                         which includes adding the install dir to PATH.
  -h, --help             Show this help and exit.

${C_BOLD}Environment variables${C_RESET} (flags take precedence):
  HUSK_VERSION           Same as --version.
  HUSK_INSTALL_DIR       Same as --install-dir.
  HUSK_NO_VERIFY         Set to skip checksum verification.
  HUSK_NO_COSIGN         Set to skip cosign verification (same as
                         --no-verify-signature).
  HUSK_NO_MODIFY_PATH    Same as --no-modify-path.
  HUSK_FORCE             Set to run non-interactively.
  HUSK_REPO              Override the source repo (default: ${REPO}).
  GITHUB_TOKEN           Used for the GitHub API call to dodge rate limits in CI.
  NO_COLOR               Disable colored output.

${C_BOLD}Supported platforms:${C_RESET}
  Linux  (glibc): x86_64, aarch64
  macOS:          x86_64 (Intel), aarch64 (Apple Silicon)
  There is no native Windows build. On Windows, run this script inside WSL,
  which installs the Linux binary.

${C_BOLD}Supply-chain verification:${C_RESET}
  This script enforces a SHA-256 checksum. When cosign is installed it also
  requires a valid keyless Sigstore signature: a signature that is missing,
  undownloadable, or invalid aborts the install rather than falling back to the
  checksum, because the checksum arrives over the same channel as the archive.
  Maintainers and CI can additionally verify the SLSA build provenance with:
  gh attestation verify <archive> --repo ${REPO}
  (this script does not attempt provenance verification itself).
EOF
}

# Flags override environment defaults.
while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      [ $# -ge 2 ] || err "--version requires a value"
      HUSK_VERSION="$2"
      shift 2
      ;;
    --version=*)
      HUSK_VERSION="${1#*=}"
      shift
      ;;
    -b | --install-dir)
      [ $# -ge 2 ] || err "$1 requires a value"
      HUSK_INSTALL_DIR="$2"
      shift 2
      ;;
    --install-dir=*)
      HUSK_INSTALL_DIR="${1#*=}"
      shift
      ;;
    --no-verify)
      HUSK_NO_VERIFY=1
      shift
      ;;
    --no-cosign | --no-verify-signature)
      HUSK_NO_COSIGN=1
      shift
      ;;
    -y | -f | --force | --yes)
      HUSK_FORCE=1
      shift
      ;;
    --no-modify-path)
      HUSK_NO_MODIFY_PATH=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      err "unknown option: $1 (try --help)"
      ;;
    *)
      err "unexpected argument: $1 (try --help)"
      ;;
  esac
done

detect_target() {
  uname_s="$(uname -s 2>/dev/null || echo unknown)"
  uname_m="$(uname -m 2>/dev/null || echo unknown)"

  os=""
  case "$uname_s" in
    Linux | linux) os="unknown-linux-gnu" ;;
    Darwin | darwin) os="apple-darwin" ;;
    MINGW* | MSYS* | CYGWIN* | Windows_NT)
      err "there is no native Windows build; run this script inside WSL to install the Linux binary"
      ;;
    *)
      err "unsupported operating system: ${uname_s}. Download a binary manually from ${GH_DOWNLOAD}/${REPO}/releases"
      ;;
  esac

  arch=""
  case "$uname_m" in
    x86_64 | amd64 | x64) arch="x86_64" ;;
    aarch64 | arm64) arch="aarch64" ;;
    *)
      err "unsupported architecture: ${uname_m}. Download a binary manually from ${GH_DOWNLOAD}/${REPO}/releases"
      ;;
  esac

  # On Apple Silicon, a shell running under Rosetta 2 (x86_64 Homebrew, x86_64
  # terminal/CI) reports uname -m = x86_64. Ask the hardware so we install the
  # native arm64 build instead of the slower translated Intel one.
  if [ "$os" = "apple-darwin" ] && [ "$arch" = "x86_64" ]; then
    if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = "1" ]; then
      arch="aarch64"
    fi
  fi

  TARGET="${arch}-${os}"

  # Validate against the exact set the release workflow publishes.
  case "$TARGET" in
    x86_64-unknown-linux-gnu | aarch64-unknown-linux-gnu | \
      x86_64-apple-darwin | aarch64-apple-darwin) ;;
    *)
      err "no published husk binary for target ${TARGET}; see ${GH_DOWNLOAD}/${REPO}/releases"
      ;;
  esac

  # The published Linux builds are glibc (-unknown-linux-gnu), not musl. On a
  # musl-only host (e.g. Alpine) the gnu binary will not run. Warn rather than
  # fail: a glibc compat layer may be present, and we cannot prove it won't run.
  if [ "$os" = "unknown-linux-gnu" ] && is_musl; then
    warn "this looks like a musl libc system (e.g. Alpine); husk publishes glibc Linux builds only, so the binary may not run. See ${GH_DOWNLOAD}/${REPO}/releases"
  fi
}

# Best-effort musl detection, used only to drive the warning above. A positive
# musl signal always wins; importantly the common Alpine/distroless case where
# `ldd` is absent entirely is still caught via the loader file and os-release,
# unlike a bare `ldd | grep musl` (which would silently fall through to "gnu").
is_musl() {
  if has ldd && ldd --version 2>&1 | grep -qi musl; then
    return 0
  fi
  for _loader in /lib/ld-musl-* /lib/libc.musl-*; do
    [ -e "$_loader" ] && return 0
  done
  if [ -r /etc/os-release ] && grep -qi '^ID=alpine' /etc/os-release; then
    return 0
  fi
  return 1
}

# curl or wget, hardened to HTTPS + TLS 1.2 with retries.
# download <url> <dest> -> 0 on success, non-zero on any failure (incl. 404).
download() {
  _url="$1"
  _dest="$2"
  if [ "$DL_TOOL" = "curl" ]; then
    curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
      --user-agent "$USER_AGENT" \
      --silent --show-error --output "$_dest" "$_url"
  else
    wget --https-only --secure-protocol=TLSv1_2 --tries=3 -q \
      --user-agent="$USER_AGENT" -O "$_dest" "$_url"
  fi
}

# Normalize a version string to a leading "v" (tags are vX.Y.Z).
normalize_version() {
  case "$1" in
    v*) printf '%s' "$1" ;;
    *) printf 'v%s' "$1" ;;
  esac
}

resolve_latest_version() {
  _api_url="${GH_API}/repos/${REPO}/releases/latest"
  _resp="${tmp}/release-latest.json"

  # Authenticate when a token is available to dodge the 60/hr unauthenticated
  # rate limit (matters in CI). Done via a curl/wget header either way.
  if [ "$DL_TOOL" = "curl" ]; then
    if [ -n "${GITHUB_TOKEN:-}" ]; then
      curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
        --silent --show-error --user-agent "$USER_AGENT" \
        -H 'Accept: application/vnd.github+json' \
        -H "Authorization: Bearer ${GITHUB_TOKEN}" \
        -o "$_resp" "$_api_url" || _resp=""
    else
      curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
        --silent --show-error --user-agent "$USER_AGENT" \
        -H 'Accept: application/vnd.github+json' \
        -o "$_resp" "$_api_url" || _resp=""
    fi
  else
    if [ -n "${GITHUB_TOKEN:-}" ]; then
      wget --https-only --secure-protocol=TLSv1_2 --tries=3 -q \
        --user-agent="$USER_AGENT" \
        --header='Accept: application/vnd.github+json' \
        --header="Authorization: Bearer ${GITHUB_TOKEN}" \
        -O "$_resp" "$_api_url" || _resp=""
    else
      wget --https-only --secure-protocol=TLSv1_2 --tries=3 -q \
        --user-agent="$USER_AGENT" \
        --header='Accept: application/vnd.github+json' \
        -O "$_resp" "$_api_url" || _resp=""
    fi
  fi

  if [ -z "$_resp" ] || [ ! -s "$_resp" ]; then
    err "could not query the latest release from ${_api_url}. Pin a version with --version v0.0.1, or check ${GH_DOWNLOAD}/${REPO}/releases"
  fi

  # Extract tag_name without requiring jq.
  _tag="$(grep '"tag_name"' "$_resp" | head -1 |
    sed -e 's/.*"tag_name"[[:space:]]*:[[:space:]]*"//' -e 's/".*//')"

  if [ -z "$_tag" ]; then
    err "no release found for ${REPO} (no tag_name in API response). The first release may not be cut yet; see ${GH_DOWNLOAD}/${REPO}/releases"
  fi

  printf '%s' "$_tag"
}

# Portable SHA-256. sha256_of <file> -> lowercase hex digest on stdout.
sha256_of() {
  _f="$1"
  if has sha256sum; then
    sha256sum "$_f" | awk '{print $1}'
  elif has shasum; then
    shasum -a 256 "$_f" | awk '{print $1}'
  elif has openssl; then
    # openssl prints e.g. "SHA256(file)= <hex>" or "SHA2-256(file)= <hex>".
    openssl dgst -sha256 "$_f" | awk '{print $NF}'
  else
    err "no SHA-256 tool found (need sha256sum, shasum, or openssl) to verify the download. Re-run with --no-verify to skip at your own risk."
  fi
}

to_lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

main() {
  if has curl; then
    DL_TOOL="curl"
  elif has wget; then
    DL_TOOL="wget"
  else
    err "need either curl or wget to download husk"
  fi

  need_cmd uname
  need_cmd tar
  need_cmd mkdir
  need_cmd grep
  need_cmd sed
  need_cmd awk
  need_cmd tr

  detect_target

  if [ -n "$HUSK_VERSION" ]; then
    version="$(normalize_version "$HUSK_VERSION")"
  fi

  # Workspace; cleaned up on any exit path so a failed run leaves nothing behind.
  tmp="$(mktemp -d 2>/dev/null || mktemp -d -t husk-install)"
  if [ -z "$tmp" ] || [ ! -d "$tmp" ]; then
    err "could not create a temporary directory"
  fi
  trap 'rm -rf "$tmp"' EXIT
  trap 'rm -rf "$tmp"; exit 130' INT
  trap 'rm -rf "$tmp"; exit 143' TERM

  if [ -z "${version:-}" ]; then
    info "resolving the latest release of ${REPO} ..."
    version="$(resolve_latest_version)"
  fi

  info "installing ${C_BOLD}husk ${version}${C_RESET} for ${C_BOLD}${TARGET}${C_RESET}"

  archive_name="${BIN}-${version}-${TARGET}.tar.gz"
  base_url="${GH_DOWNLOAD}/${REPO}/releases/download/${version}"
  archive_url="${base_url}/${archive_name}"
  archive_path="${tmp}/${archive_name}"

  info "downloading ${archive_name} ..."
  if ! download "$archive_url" "$archive_path"; then
    err "failed to download ${archive_url}. The version (${version}) or target (${TARGET}) may not be published; see ${GH_DOWNLOAD}/${REPO}/releases"
  fi
  [ -s "$archive_path" ] || err "downloaded archive is empty: ${archive_url}"

  if [ -n "$HUSK_NO_VERIFY" ]; then
    warn "checksum verification SKIPPED (HUSK_NO_VERIFY / --no-verify). You are installing an unverified binary."
  else
    sum_name="${archive_name}.sha256"
    sum_url="${base_url}/${sum_name}"
    sum_path="${tmp}/${sum_name}"
    info "verifying checksum ..."
    if ! download "$sum_url" "$sum_path"; then
      err "could not download the checksum file ${sum_url}. Refusing to install unverified. Re-run with --no-verify to override at your own risk."
    fi
    # The .sha256 file is the standard "<hex>  <filename>" line; take field 1.
    expected="$(to_lower "$(awk '{print $1}' "$sum_path")")"
    actual="$(to_lower "$(sha256_of "$archive_path")")"
    if [ -z "$expected" ]; then
      err "checksum file ${sum_name} is empty or malformed"
    fi
    if [ "$expected" != "$actual" ]; then
      err "checksum MISMATCH for ${archive_name}: expected ${expected}, got ${actual}. Refusing to install."
    fi
    ok "checksum verified (sha256: ${actual})"
  fi

  if [ -n "$HUSK_NO_COSIGN" ]; then
    info "cosign verification disabled (HUSK_NO_COSIGN / --no-cosign)."
  elif has cosign; then
    info "verifying cosign signature ..."
    bundle_url="${archive_url}.sigstore.json"
    bundle_path="${archive_path}.sigstore.json"
    # A missing signature is fatal, not a warning. The .sha256 travels the same
    # channel as the archive, so whoever can substitute one can substitute the
    # other: the checksum proves the download was not corrupted, not that it is
    # the release we published. The cosign signature is the only control here
    # that survives a hostile channel, so it must not be skippable by anything
    # an attacker can cause (a suppressed 404 on the bundle is exactly that).
    if ! download "$bundle_url" "$bundle_path"; then
      err "could not download the cosign bundle ${bundle_url}. Refusing to install: the checksum alone cannot prove this archive is the release we signed. Re-run with --no-verify-signature to override at your own risk."
    fi
    if cosign verify-blob \
      --bundle "$bundle_path" \
      --certificate-identity-regexp "$COSIGN_IDENTITY_RE" \
      --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
      "$archive_path" >/dev/null 2>&1; then
      ok "cosign signature verified (Sigstore keyless)"
    else
      err "cosign signature verification FAILED for ${archive_name}. A bad signature is worse than none; refusing to install. (Override with --no-verify-signature only if you understand the risk.)"
    fi
  else
    info "cosign not found; skipping signature verification (checksum still enforced). Install cosign for full supply-chain verification."
  fi

  info "extracting ..."
  ensure_dir="${tmp}/extract"
  mkdir -p "$ensure_dir"
  # --no-same-owner so a hostile archive can't try to restore arbitrary uid/gid
  # ownership. GNU/bsd tar support it; busybox tar may not (and extracts as the
  # current user anyway), so probe for support with --version rather than
  # swallowing stderr on the real extraction; that way a genuine extraction
  # failure (corrupt archive, disk full) is always surfaced, never hidden.
  if tar --no-same-owner --version >/dev/null 2>&1; then
    tar --no-same-owner -xzf "$archive_path" -C "$ensure_dir" \
      || err "failed to extract ${archive_name}"
  else
    tar -xzf "$archive_path" -C "$ensure_dir" \
      || err "failed to extract ${archive_name}"
  fi

  src_bin="${ensure_dir}/${BIN}"
  [ -f "$src_bin" ] || err "archive did not contain the expected ${BIN} binary"
  chmod +x "$src_bin" 2>/dev/null || true

  # Install atomically: copy to a temp name in the destination dir, then mv
  # over the final path so a running copy of husk is never clobbered mid-write.
  mkdir -p "$HUSK_INSTALL_DIR" || err "could not create install directory ${HUSK_INSTALL_DIR}"
  if [ ! -w "$HUSK_INSTALL_DIR" ]; then
    err "install directory ${HUSK_INSTALL_DIR} is not writable. Choose another with --install-dir, e.g. --install-dir \"\$HOME/.local/bin\", or fix permissions."
  fi

  dest="${HUSK_INSTALL_DIR}/${BIN}"
  dest_tmp="${HUSK_INSTALL_DIR}/.${BIN}.install.$$"
  cp "$src_bin" "$dest_tmp" || err "failed to copy the binary into ${HUSK_INSTALL_DIR}"
  chmod 0755 "$dest_tmp" 2>/dev/null || true
  mv -f "$dest_tmp" "$dest" || {
    rm -f "$dest_tmp" 2>/dev/null || true
    err "failed to move the binary into place at ${dest}"
  }

  ok "installed ${BIN} ${version} to ${dest}"

  installed_version=""
  if installed_version="$("$dest" --version 2>/dev/null)"; then
    info "${installed_version}"
  else
    warn "installed binary did not run cleanly (\"${dest} --version\" failed). On Linux this often means a libc mismatch; see ${GH_DOWNLOAD}/${REPO}/releases for alternatives."
  fi

  # If running inside GitHub Actions, make husk available to later steps.
  if [ -n "${GITHUB_PATH:-}" ] && [ -w "${GITHUB_PATH}" ]; then
    printf '%s\n' "$HUSK_INSTALL_DIR" >>"$GITHUB_PATH"
    info "added ${HUSK_INSTALL_DIR} to \$GITHUB_PATH for subsequent CI steps."
  fi

  configure_path
}

# Whether HUSK_INSTALL_DIR is already an entry in PATH. The colon-wrapped
# comparison is the portable idiom; splitting PATH on IFS instead would subject
# each entry to pathname expansion, so a PATH holding a glob character could
# match a directory that is not actually on it.
dir_on_path() {
  case ":${PATH}:" in
    *":${HUSK_INSTALL_DIR%/}:"* | *":${HUSK_INSTALL_DIR%/}/:"*) return 0 ;;
    *) return 1 ;;
  esac
}

# Rewrite a path under the home directory to use a literal $HOME, so a line
# written into a startup file survives a renamed, moved, or shared home.
home_relative() {
  # SC2016: $HOME is emitted literally so the startup file expands it, not us.
  # shellcheck disable=SC2016
  case "$1" in
    "${HOME}"/*) printf '$HOME/%s' "${1#"${HOME}"/}" ;;
    *) printf '%s' "$1" ;;
  esac
}

# The startup file a NEW terminal would read, as "<syntax> <file>". $SHELL is
# the right signal: it names the login shell a new terminal starts, which is
# what "husk still works tomorrow" actually depends on, whereas the shell
# running this script is whatever the pipe happened to use.
shell_rc_target() {
  # Parameter expansion rather than basename: the shell startup files this
  # decides between must still be named correctly on a stripped-down PATH.
  _sh="${SHELL:-}"
  case "${_sh##*/}" in
    # A file of fish's own under conf.d, so fish's config is never edited.
    fish) printf 'fish %s/fish/conf.d/husk.fish' "${XDG_CONFIG_HOME:-${HOME}/.config}" ;;
    zsh) printf 'posix %s/.zshrc' "${ZDOTDIR:-${HOME}}" ;;
    # macOS terminals start login shells, which read .bash_profile and never
    # .bashrc; on Linux every interactive shell reads .bashrc.
    bash)
      if [ "$(uname -s 2>/dev/null)" = "Darwin" ]; then
        printf 'posix %s/.bash_profile' "${HOME}"
      else
        printf 'posix %s/.bashrc' "${HOME}"
      fi
      ;;
    *) printf 'posix %s/.profile' "${HOME}" ;;
  esac
}

# The PATH line to write. Both forms are guarded: a startup file is re-read by
# every new shell, and an unguarded prepend would grow PATH without bound.
rc_path_line() {
  # SC2016: $PATH belongs to the line being written, not to this script.
  # shellcheck disable=SC2016
  case "$1" in
    fish) printf 'fish_add_path -g %s' "$2" ;;
    *) printf 'case ":$PATH:" in *":%s:"*) ;; *) export PATH="%s:$PATH" ;; esac' "$2" "$2" ;;
  esac
}

# Whether a startup file already puts the directory on PATH. Debian and Ubuntu
# ship a ~/.profile that adds ~/.local/bin only `if [ -d ]` at login, so a
# directory this installer just created is already configured but not yet
# active. The fix there is a fresh login, not a second PATH line.
rc_already_adds_dir() {
  _lit="${HUSK_INSTALL_DIR%/}"
  _rel="$(home_relative "$_lit")"
  _cfg="${XDG_CONFIG_HOME:-${HOME}/.config}"
  for _f in "${HOME}/.profile" "${HOME}/.bash_profile" "${HOME}/.bash_login" \
    "${HOME}/.bashrc" "${ZDOTDIR:-${HOME}}/.zshrc" "${ZDOTDIR:-${HOME}}/.zshenv" \
    "${ZDOTDIR:-${HOME}}/.zprofile" "${_cfg}/fish/config.fish" \
    "${_cfg}"/fish/conf.d/*.fish; do
    [ -r "$_f" ] || continue
    grep -qF -e "$_lit" -e "$_rel" "$_f" 2>/dev/null && return 0
  done
  return 1
}

# Append the PATH line to the user's startup file. Non-zero means nothing was
# written, which is not fatal: the caller falls back to printing the command.
add_dir_to_rc() {
  _style="${1%% *}"
  _file="${1#* }"
  _line="$(rc_path_line "$_style" "$(home_relative "${HUSK_INSTALL_DIR%/}")")"

  # A startup file generated by Nix, home-manager, or chezmoi is a read-only
  # symlink into a store; appending would fail, and succeeding would be worse
  # because the next rebuild silently discards it.
  if [ -e "$_file" ] && [ ! -w "$_file" ]; then
    return 1
  fi
  mkdir -p "${_file%/*}" 2>/dev/null || return 1
  printf '\n# added by the husk installer\n%s\n' "$_line" >>"$_file" 2>/dev/null || return 1
}

# Whether there is a person present to answer. Piping this script into sh leaves
# stdin holding the script itself, so the terminal has to be opened directly;
# where there is none (CI, automation, a container) nothing is ever written.
# The probe runs in a subshell because a failed redirection on a special
# built-in exits a non-interactive POSIX shell, and "there is no terminal" must
# report false rather than abort the install.
have_tty() {
  (: </dev/tty) 2>/dev/null
}

confirm_modify_path() {
  # -y/--force means "accept the defaults", and configuring PATH is the default.
  [ -n "$HUSK_FORCE" ] && return 0
  have_tty || return 1
  printf '%shusk%s add %s to your PATH in %s? [Y/n] ' \
    "${C_CYAN}" "${C_RESET}" "$HUSK_INSTALL_DIR" "$1" >&2
  _reply=""
  read -r _reply </dev/tty 2>/dev/null || return 1
  case "$_reply" in
    [nN]*) return 1 ;;
    *) return 0 ;;
  esac
}

configure_path() {
  if dir_on_path; then
    ok "Ready. Run: ${C_BOLD}${BIN}${C_RESET}"
    return 0
  fi

  if rc_already_adds_dir; then
    info "Your shell startup files already add ${HUSK_INSTALL_DIR} to PATH, just not in this shell."
    printf '\n  Open a new terminal, or run this once here:\n' >&2
    # shellcheck disable=SC2016 # $PATH is shown to the user, not expanded here.
    printf '    %sexport PATH="%s:$PATH"%s\n' \
      "${C_DIM}" "$HUSK_INSTALL_DIR" "${C_RESET}" >&2
    printf '\n  Still not found in a new terminal? Log out and back in: Debian and\n' >&2
    printf '  Ubuntu add this directory only when it exists at login, and it was\n' >&2
    printf '  just created.\n' >&2
    printf '\n  Then run: %s%s%s\n' "${C_BOLD}" "$BIN" "${C_RESET}" >&2
    return 0
  fi

  _target="$(shell_rc_target)"
  _rc_file="${_target#* }"

  if [ -z "$HUSK_NO_MODIFY_PATH" ] && confirm_modify_path "$_rc_file" \
    && add_dir_to_rc "$_target"; then
    ok "Added ${HUSK_INSTALL_DIR} to PATH in ${_rc_file}"
    printf '\n  Open a new terminal and run: %s%s%s\n' "${C_BOLD}" "$BIN" "${C_RESET}" >&2
    return 0
  fi

  # One command that actually persists, naming the exact file. An `export` typed
  # into this shell would be gone with the window, which is the whole problem.
  warn "${HUSK_INSTALL_DIR} is not on your PATH, so ${BIN} will not be found by name."
  printf '\n  Add it permanently by running:\n' >&2
  case "${_target%% *}" in
    fish)
      printf '    %sfish_add_path -g %s%s\n' "${C_DIM}" "$HUSK_INSTALL_DIR" "${C_RESET}" >&2
      ;;
    *)
      # shellcheck disable=SC2016 # $PATH is shown to the user, not expanded here.
      printf '    %secho '"'"'export PATH="%s:$PATH"'"'"' >> %s%s\n' \
        "${C_DIM}" "$HUSK_INSTALL_DIR" "$_rc_file" "${C_RESET}" >&2
      ;;
  esac
  printf '\n  Then open a new terminal and run: %s%s%s\n' "${C_BOLD}" "$BIN" "${C_RESET}" >&2
}

main "$@"
