# shellcheck shell=bash
#
# Shared helpers for local-ca: logging, state paths, platform detection
# and small pure helpers. Sourced by the entry script and every lib/*.sh.
#
# Logging rule: all human-readable output goes to stderr. stdout is
# reserved for machine-readable results (identity names, file paths) so
# callers can capture it with command substitution.

# --- logging (stderr only) -------------------------------------------------

## Print an informational line to stderr.
log()  { printf 'local-ca: %s\n' "$*" >&2; }

## Print a warning line to stderr.
warn() { printf 'local-ca: warning: %s\n' "$*" >&2; }

## Print an error line to stderr.
err()  { printf 'local-ca: error: %s\n' "$*" >&2; }

## Print an error line and exit non-zero.
die()  { err "$*"; exit 1; }

# --- state paths -----------------------------------------------------------

## Root of all generated state. Defaults to ~/.local-ca so a fresh clone
## of the repo holds zero secrets. Tests override it with LOCAL_CA_HOME.
state_home() { printf '%s' "${LOCAL_CA_HOME:-$HOME/.local-ca}"; }

ca_dir()       { printf '%s/ca' "$(state_home)"; }
ca_key()       { printf '%s/ca.key' "$(ca_dir)"; }
ca_crt()       { printf '%s/ca.crt' "$(ca_dir)"; }
ca_serial()    { printf '%s/serial' "$(ca_dir)"; }

certs_dir()    { printf '%s/certs' "$(state_home)"; }
## Directory holding one leaf cert's material. $1 = cert name.
cert_dir()     { printf '%s/%s' "$(certs_dir)" "$1"; }
cert_key()     { printf '%s/%s.key' "$(cert_dir "$1")" "$1"; }
cert_crt()     { printf '%s/%s.crt' "$(cert_dir "$1")" "$1"; }
cert_cnf()     { printf '%s/%s.cnf' "$(cert_dir "$1")" "$1"; }

codesign_dir() { printf '%s/codesign' "$(state_home)"; }
## Exported public cert path for a code-signing identity. $1 = name.
codesign_cer() { printf '%s/%s.cer' "$(codesign_dir)" "$1"; }

# --- platform --------------------------------------------------------------

## Echo "macos", "linux" or "unknown".
platform() {
  case "$(uname -s)" in
    Darwin) printf 'macos' ;;
    Linux)  printf 'linux' ;;
    *)      printf 'unknown' ;;
  esac
}

is_macos() { [ "$(platform)" = macos ]; }
is_linux() { [ "$(platform)" = linux ]; }

# --- small pure helpers ----------------------------------------------------

## Exit 0 if $1 looks like an IPv4 or IPv6 address, else exit 1. Used to
## decide whether a SAN argument is an IP SAN or a DNS SAN.
is_ip() {
  local v="$1"
  # IPv6: contains a colon.
  case "$v" in
    *:*) return 0 ;;
  esac
  # IPv4: four 0-255 octets.
  case "$v" in
    *[!0-9.]*) return 1 ;;
  esac
  local IFS=. a b c d extra
  read -r a b c d extra <<<"$v"
  [ -n "$a" ] && [ -n "$b" ] && [ -n "$c" ] && [ -n "$d" ] && [ -z "$extra" ] || return 1
  local o
  for o in "$a" "$b" "$c" "$d"; do
    [ "$o" -ge 0 ] 2>/dev/null && [ "$o" -le 255 ] 2>/dev/null || return 1
  done
  return 0
}

## Fail with a clear message if a required command is missing. $1 = the
## command, remaining args = a hint shown to the user.
need_cmd() {
  local cmd="$1"; shift
  command -v "$cmd" >/dev/null 2>&1 || die "missing required command '$cmd'${*:+ ($*)}"
}

## Create the state home and a subdirectory with safe permissions.
## $1 = absolute directory path.
ensure_dir() {
  mkdir -p "$1"
  chmod 700 "$(state_home)" 2>/dev/null || true
}
