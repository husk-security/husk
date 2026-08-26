#!/bin/sh
# Tests for install.sh's PATH handling: the part that decides whether `husk`
# will be found by name in a NEW terminal after the install.
#
# The installer is loaded with its final `main "$@"` line removed so the
# individual functions can be driven directly against a throwaway $HOME. The
# full download->verify->install pipeline is covered by e2e.sh instead.
#
# Every case asserts BOTH the message and whether a startup file was written:
# writing to a dotfile without being asked is the failure mode that matters
# most here, so "printed the right thing" alone is never a pass.
#
# SC1090/SC1091: the installer and the startup files it writes are sourced by
# path, which is the point. SC2030/SC2031: each case deliberately runs in a
# subshell with its own HOME, SHELL, and PATH. SC2034: BIN is read by the
# sourced installer.
# shellcheck disable=SC1090,SC1091,SC2030,SC2031,SC2034

set -eu

# The ambient PATH, captured before any case rewrites it in a subshell.
host_path="$PATH"

# A literal "$HOME": what the installer must write into a startup file, rather
# than the expanded path, so the file survives a moved or shared home.
# shellcheck disable=SC2016 # not expanding it is the point.
dollar_home='$HOME'

here=$(cd "$(dirname "$0")" && pwd)
install_sh=$(cd "$here/../.." && pwd)/install.sh
[ -f "$install_sh" ] || {
  echo "path-guidance: cannot find $install_sh" >&2
  exit 1
}

pass=0
fail=0
ok() {
  printf '  \033[32mPASS\033[0m %s\n' "$1"
  pass=$((pass + 1))
}
bad() {
  printf '  \033[31mFAIL\033[0m %s\n' "$1"
  fail=$((fail + 1))
}
note() { printf '\033[36m==>\033[0m %s\n' "$1"; }

work=$(mktemp -d 2>/dev/null || mktemp -d -t husk-path)
trap 'rm -rf "$work"' EXIT INT TERM

# The installer minus its entrypoint, so functions can be called in isolation.
lib="$work/lib.sh"
sed 's/^main "\$@"$/:/' "$install_sh" >"$lib"
grep -q '^main "\$@"$' "$install_sh" || {
  echo "path-guidance: install.sh no longer ends in 'main \"\$@\"'" >&2
  exit 1
}

# run_case <label> <home> <shell> <install-dir> <path> <extra-env...>
# Runs configure_path in a subshell and leaves its output in $out.
out="$work/out"
run_case() {
  _home="$1"
  _shell="$2"
  _dir="$3"
  _path="$4"
  shift 4
  (
    HOME="$_home"
    SHELL="$_shell"
    PATH="$_path"
    export HOME SHELL PATH
    NO_COLOR=1
    export NO_COLOR
    for _kv in "$@"; do
      eval "export $_kv"
    done
    # HUSK_INSTALL_DIR is read at load time, like every other setting.
    HUSK_INSTALL_DIR="$_dir"
    export HUSK_INSTALL_DIR
    # Clear the positional parameters: sourcing runs the installer's own
    # argument parser, which would otherwise see this function's arguments.
    set --
    # No controlling terminal: stdin is closed, so have_tty() fails exactly as
    # it does under `curl | sh` in CI.
    . "$lib"
    BIN=husk
    configure_path
  ) >"$out" 2>&1 </dev/null || true
}

# said <pattern> / not_said <pattern>
said() { grep -qF -- "$1" "$out"; }

new_home() {
  _h="$work/home.$1"
  rm -rf "$_h"
  mkdir -p "$_h"
  printf '%s' "$_h"
}

# macOS terminals start login shells, which read .bash_profile and never
# .bashrc; every other platform's interactive bash reads .bashrc.
if [ "$(uname -s 2>/dev/null)" = "Darwin" ]; then
  bash_rc=".bash_profile"
else
  bash_rc=".bashrc"
fi

# ---------------------------------------------------------------------------
note "already on PATH: no warning, no file written"
h=$(new_home onpath)
run_case "$h" /bin/bash "$h/.local/bin" "$h/.local/bin:$host_path"
if said "Run: husk" && ! said "not on your PATH" && [ ! -e "$h/$bash_rc" ]; then
  ok "on PATH: confirms and writes nothing"
else
  bad "on PATH: unexpected output"
  sed 's/^/    /' "$out" >&2
fi

# A PATH entry holding a glob character must not be expanded into a false match.
note "glob in PATH is not treated as a match"
h=$(new_home glob)
mkdir -p "$h/opt/a/bin"
run_case "$h" /bin/bash "$h/opt/a/bin" "$h/opt/*/bin"
if said "not on your PATH"; then
  ok "glob PATH entry does not falsely match"
else
  bad "glob PATH entry falsely matched"
  sed 's/^/    /' "$out" >&2
fi

# ---------------------------------------------------------------------------
note "not on PATH, no terminal: prints the exact file, writes nothing"
for shell_case in "bash $bash_rc" "zsh .zshrc"; do
  sh_bin=${shell_case%% *}
  rc=${shell_case#* }
  h=$(new_home "notty.$sh_bin")
  run_case "$h" "/bin/$sh_bin" "$h/.local/bin" "$host_path"
  if said "not on your PATH" && said "$h/$rc" && said 'export PATH=' \
    && [ ! -e "$h/$rc" ]; then
    ok "$sh_bin: names $rc and writes nothing without a terminal"
  else
    bad "$sh_bin: wrong guidance or wrote a file unasked"
    sed 's/^/    /' "$out" >&2
  fi
done

note "fish gets fish syntax, not an export line"
h=$(new_home notty.fish)
run_case "$h" /usr/bin/fish "$h/.local/bin" "$host_path"
if said "fish_add_path" && ! said 'export PATH=' \
  && [ ! -e "$h/.config/fish/conf.d/husk.fish" ]; then
  ok "fish: fish_add_path, no export, nothing written"
else
  bad "fish: wrong guidance"
  sed 's/^/    /' "$out" >&2
fi

note "unknown shell falls back to ~/.profile"
h=$(new_home notty.unknown)
run_case "$h" "" "$h/.local/bin" "$host_path"
if said "$h/.profile"; then
  ok "unknown shell: names ~/.profile"
else
  bad "unknown shell: no concrete file named"
  sed 's/^/    /' "$out" >&2
fi

# ---------------------------------------------------------------------------
# Debian and Ubuntu add ~/.local/bin from ~/.profile only `if [ -d ]` at login,
# so a directory just created is configured but inactive. Telling that user to
# append a second PATH line is wrong; the fix is a fresh login.
note "startup file already adds it: says re-login, adds no second line"
h=$(new_home debian)
cat >"$h/.profile" <<'EOF'
if [ -d "$HOME/.local/bin" ] ; then
    PATH="$HOME/.local/bin:$PATH"
fi
EOF
before=$(cat "$h/.profile")
run_case "$h" /bin/bash "$h/.local/bin" "$host_path"
if said "already add" && said "Log out and back in" \
  && [ "$(cat "$h/.profile")" = "$before" ] && [ ! -e "$h/$bash_rc" ]; then
  ok "already-configured: re-login advice, no file touched"
else
  bad "already-configured case not detected"
  sed 's/^/    /' "$out" >&2
fi

# ---------------------------------------------------------------------------
note "--force writes one guarded line to the right file"
h=$(new_home force)
run_case "$h" /bin/bash "$h/.local/bin" "$host_path" HUSK_FORCE=1
if said "Added" && [ -f "$h/$bash_rc" ] && grep -qF 'export PATH=' "$h/$bash_rc" \
  && grep -qF "$dollar_home/.local/bin" "$h/$bash_rc"; then
  ok "force: wrote ~/$bash_rc using a literal \$HOME"
else
  bad "force: did not write the expected line"
  sed 's/^/    /' "$out" >&2
  [ -f "$h/$bash_rc" ] && sed 's/^/    rc: /' "$h/$bash_rc" >&2
fi

# The written line must not prepend again on every shell start.
if [ -f "$h/$bash_rc" ] && (
  HOME="$h"
  start="$h/.local/bin:/usr/bin"
  PATH="$start"
  export PATH HOME
  . "$h/$bash_rc"
  . "$h/$bash_rc"
  [ "$PATH" = "$start" ]
); then
  ok "force: written line is idempotent (PATH does not grow)"
else
  bad "force: written line grows PATH on every shell start"
fi

# And it must actually put the directory on PATH from a shell that lacked it.
if [ -f "$h/$bash_rc" ] && (
  PATH=/usr/bin
  HOME="$h"
  export PATH HOME
  . "$h/$bash_rc"
  case ":$PATH:" in *":$h/.local/bin:"*) exit 0 ;; *) exit 1 ;; esac
); then
  ok "force: sourcing the file puts the dir on PATH"
else
  bad "force: sourcing the file did NOT put the dir on PATH"
fi

note "--force under fish writes conf.d, never config.fish"
h=$(new_home force.fish)
mkdir -p "$h/.config/fish"
: >"$h/.config/fish/config.fish"
run_case "$h" /usr/bin/fish "$h/.local/bin" "$host_path" HUSK_FORCE=1
if [ -f "$h/.config/fish/conf.d/husk.fish" ] \
  && grep -qF 'fish_add_path' "$h/.config/fish/conf.d/husk.fish" \
  && [ ! -s "$h/.config/fish/config.fish" ]; then
  ok "fish: wrote conf.d/husk.fish, left config.fish untouched"
else
  bad "fish: wrote the wrong file"
  sed 's/^/    /' "$out" >&2
fi

# ---------------------------------------------------------------------------
note "--no-modify-path never writes, even with --force"
h=$(new_home nomodify)
run_case "$h" /bin/bash "$h/.local/bin" "$host_path" HUSK_FORCE=1 HUSK_NO_MODIFY_PATH=1
if said "not on your PATH" && [ ! -e "$h/$bash_rc" ]; then
  ok "no-modify-path: printed guidance, wrote nothing"
else
  bad "no-modify-path: wrote a startup file anyway"
  sed 's/^/    /' "$out" >&2
fi

# A Nix/home-manager/chezmoi startup file is a read-only symlink into a store.
# Appending must fail over to printing rather than erroring out.
note "read-only startup file falls back to printing"
if [ "$(id -u 2>/dev/null || echo 0)" = "0" ]; then
  # root ignores the permission bits, so the case cannot be staged here. It is
  # covered whenever the suite runs as an ordinary user.
  note "skipped: running as root, which can write a mode-444 file anyway"
else
  h=$(new_home readonly)
  : >"$h/$bash_rc"
  chmod 444 "$h/$bash_rc"
  run_case "$h" /bin/bash "$h/.local/bin" "$host_path" HUSK_FORCE=1
  if said "not on your PATH" && [ ! -s "$h/$bash_rc" ]; then
    ok "read-only rc: fell back to printing, file unchanged"
  else
    bad "read-only rc: unexpected result"
    sed 's/^/    /' "$out" >&2
  fi
  chmod 644 "$h/$bash_rc"
fi

# ---------------------------------------------------------------------------
note "a custom install dir is honoured throughout"
h=$(new_home customdir)
run_case "$h" /bin/bash "$h/opt/husk/bin" "$host_path" HUSK_FORCE=1
if said "$h/opt/husk/bin" && grep -qF "$dollar_home/opt/husk/bin" "$h/$bash_rc"; then
  ok "custom install dir appears in the message and the written line"
else
  bad "custom install dir not honoured"
  sed 's/^/    /' "$out" >&2
fi

printf '\n\033[36mpath-guidance:\033[0m %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
