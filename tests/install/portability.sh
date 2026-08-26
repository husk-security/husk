#!/bin/sh
# Portability + argument-handling checks for install.sh that need no network.
#
# Runs the installer's syntax check and its no-network code paths (--help, bad
# flags, missing values) under every POSIX shell available on the host (dash,
# busybox ash, bash-as-sh), so bashisms and shell-specific breakage on
# Alpine/Debian/macOS are caught before anything ever touches a release.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
install_sh=$(cd "$here/../.." && pwd)/install.sh
[ -f "$install_sh" ] || { echo "portability: cannot find $install_sh" >&2; exit 1; }

pass=0
fail=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail + 1)); }

# Discover the POSIX shells present on this machine.
shells=""
for cand in sh dash bash; do
  if command -v "$cand" >/dev/null 2>&1; then shells="$shells $cand"; fi
done
if command -v busybox >/dev/null 2>&1; then shells="$shells busybox-sh"; fi

# Run install.sh under the given shell, returning its exit status WITHOUT
# tripping `set -e` (expected-failure cases exit non-zero on purpose).
run_under() {
  _sh=$1; shift
  if [ "$_sh" = "busybox-sh" ]; then
    if busybox sh "$install_sh" "$@" >/dev/null 2>&1; then return 0; else return $?; fi
  else
    if "$_sh" "$install_sh" "$@" >/dev/null 2>&1; then return 0; else return $?; fi
  fi
}

# expect_status <wanted> <label> <shell> <args...>
expect_status() {
  _want=$1; _label=$2; _sh=$3; shift 3
  _got=0
  run_under "$_sh" "$@" || _got=$?
  if [ "$_got" -eq "$_want" ]; then ok "$_label (exit $_got)"
  else bad "$_label (wanted exit $_want, got $_got)"; fi
}

# syntax_check <shell>
syntax_check() {
  _got=0
  if [ "$1" = "busybox-sh" ]; then
    busybox sh -n "$install_sh" 2>/dev/null || _got=$?
  else
    "$1" -n "$install_sh" 2>/dev/null || _got=$?
  fi
  if [ "$_got" -eq 0 ]; then ok "syntax check under $1"
  else bad "syntax check under $1"; fi
}

for s in $shells; do
  printf '\033[36m==>\033[0m shell: %s\n' "$s"
  syntax_check "$s"
  # --help and --version-printing must succeed and need no network.
  expect_status 0 "--help exits 0" "$s" --help
  # Unknown flags, missing values, and stray args must fail BEFORE any download.
  expect_status 1 "unknown flag rejected" "$s" --definitely-not-a-flag
  expect_status 1 "--version with no value rejected" "$s" --version
  expect_status 1 "stray positional arg rejected" "$s" some-extra-arg
done

# The --help output should actually render (catch heredoc/printf breakage).
if sh "$install_sh" --help 2>&1 | grep -q "husk installer"; then
  ok "--help renders the usage banner"
else
  bad "--help did not render the usage banner"
fi

# Truncation safety: the curl|sh partial-download guard. The whole installer
# runs only from its final `main "$@"` line, so ANY truncated prefix (a dropped
# connection mid-pipe) must define functions but install nothing. Feed many
# truncated prefixes to sh and assert none ever drops a binary. The unreachable
# endpoints are belt-and-suspenders in case a prefix somehow reached the network.
printf '\033[36m==>\033[0m truncation safety (curl|sh guard)\n'
total=$(wc -c < "$install_sh")
trunc_dir=$(mktemp -d)
trunc_fail=0
for frac in 10 25 50 75 90 95 99; do
  off=$((total * frac / 100))
  tbin="$trunc_dir/bin-$frac"
  head -c "$off" "$install_sh" | \
    HUSK_INSTALL_DIR="$tbin" HUSK_FORCE=1 NO_COLOR=1 \
    HUSK_VERSION="v0.0.0" \
    HUSK_GITHUB_DOWNLOAD="https://127.0.0.1:1" \
    HUSK_GITHUB_API="https://127.0.0.1:1" \
    sh >/dev/null 2>&1 || true
  if [ -e "$tbin/husk" ]; then
    trunc_fail=$((trunc_fail + 1))
    bad "truncated at ${frac}% installed a binary (guard FAILED)"
  fi
done
rm -rf "$trunc_dir"
[ "$trunc_fail" -eq 0 ] && ok "no truncated prefix (10-99%) ever installed"

printf '\n\033[36mportability:\033[0m %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
