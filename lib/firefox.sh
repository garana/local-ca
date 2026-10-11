# shellcheck shell=bash
#
# Firefox trusts the CA through its own NSS store, not the OS one, so the
# CA must be imported into every Firefox profile's NSS database with
# certutil. This is the explicit per-profile path; the simpler
# enterprise-roots alternative is documented in docs/firefox-nss.md.

## NSS nickname for the CA inside Firefox profiles. Fixed string so
## re-imports and removals target the same entry.
FIREFOX_NSS_NICK="local-ca development CA"

## Base directory holding Firefox profiles, by platform. Prints nothing
## on unsupported platforms.
firefox_profiles_base() {
  if is_macos; then
    printf '%s/Library/Application Support/Firefox/Profiles' "$HOME"
  elif is_linux; then
    printf '%s/.mozilla/firefox' "$HOME"
  fi
}

## List profile directories under a base dir that contain an NSS store
## (cert9.db for the modern sql store, or cert8.db for the legacy one).
## $1 = base dir. Pure: prints one dir path per line, reads only the
## filesystem. Tested with a fake base dir.
firefox_profile_dirs() {
  local base="$1" d
  [ -d "$base" ] || return 0
  for d in "$base"/*/; do
    d="${d%/}"
    if [ -f "$d/cert9.db" ] || [ -f "$d/cert8.db" ]; then
      printf '%s\n' "$d"
    fi
  done
}

## The certutil -d argument for a profile dir: sql: for cert9.db, dbm:
## for the legacy cert8.db. $1 = profile dir.
firefox_nss_db_arg() {
  if [ -f "$1/cert9.db" ]; then printf 'sql:%s' "$1"; else printf 'dbm:%s' "$1"; fi
}

## Import the CA into every Firefox profile as a trusted CA ("C,,").
## Idempotent: certutil -A with the same nickname updates in place. No-op
## (with a note) if there are no profiles or certutil is absent.
firefox_trust() {
  local base; base="$(firefox_profiles_base)"
  local dirs; dirs="$(firefox_profile_dirs "$base")"
  if [ -z "$dirs" ]; then
    log "no Firefox profiles found under ${base:-<none>}; skipping Firefox"
    return 0
  fi
  if ! command -v certutil >/dev/null 2>&1; then
    warn "certutil not found; cannot trust CA in Firefox"
    warn "install it (macOS: 'brew install nss'; Linux: libnss3-tools / nss-tools) and re-run 'ca trust'"
    return 0
  fi
  local d
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    log "trusting CA in Firefox profile $(basename "$d")"
    certutil -A -n "$FIREFOX_NSS_NICK" -t "C,," -i "$(ca_crt)" \
      -d "$(firefox_nss_db_arg "$d")" \
      || warn "certutil failed for profile $d"
  done <<<"$dirs"
}

## Remove the CA from every Firefox profile. Best-effort.
firefox_untrust() {
  local base; base="$(firefox_profiles_base)"
  local dirs; dirs="$(firefox_profile_dirs "$base")"
  [ -n "$dirs" ] || { log "no Firefox profiles found; skipping Firefox"; return 0; }
  command -v certutil >/dev/null 2>&1 || { warn "certutil not found; cannot untrust in Firefox"; return 0; }
  local d
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    certutil -D -n "$FIREFOX_NSS_NICK" -d "$(firefox_nss_db_arg "$d")" 2>/dev/null \
      && log "removed CA from Firefox profile $(basename "$d")" || true
  done <<<"$dirs"
}
