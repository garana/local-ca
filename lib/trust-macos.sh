# shellcheck shell=bash
#
# macOS OS-trust for the CA. Uses the user's login keychain so no sudo is
# needed; macOS shows a one-time authorization dialog, which matches the
# goal of "allow the CA only once". Set LOCAL_CA_SYSTEM_TRUST=1 to trust
# system-wide instead (all users), which needs sudo.

## Path to the login keychain (the modern -db suffixed file).
login_keychain() {
  local k="$HOME/Library/Keychains/login.keychain-db"
  [ -f "$k" ] || k="$HOME/Library/Keychains/login.keychain"
  printf '%s' "$k"
}

## Add the CA to the macOS trust store. Idempotent: re-adding the same
## root is harmless (it updates the same trust setting).
os_trust_macos() {
  need_cmd security
  local crt; crt="$(ca_crt)"
  if [ "${LOCAL_CA_SYSTEM_TRUST:-0}" = 1 ]; then
    log "trusting CA system-wide (needs sudo)"
    sudo security add-trusted-cert -d -r trustRoot \
      -k /Library/Keychains/System.keychain "$crt" \
      || die "security add-trusted-cert (system) failed"
  else
    log "trusting CA in the login keychain (a one-time auth dialog may appear)"
    security add-trusted-cert -r trustRoot \
      -k "$(login_keychain)" "$crt" \
      || die "security add-trusted-cert (login) failed"
  fi
  log "CA trusted by the OS"
}

## Remove the CA from the macOS trust store and delete the cert.
os_untrust_macos() {
  need_cmd security
  local crt; crt="$(ca_crt)"
  [ -f "$crt" ] || { warn "no CA cert on disk; nothing to untrust"; return 0; }
  if [ "${LOCAL_CA_SYSTEM_TRUST:-0}" = 1 ]; then
    sudo security remove-trusted-cert -d "$crt" 2>/dev/null || true
  else
    security remove-trusted-cert "$crt" 2>/dev/null || true
  fi
  # Also remove the cert itself from the login keychain, matched by CN.
  local cn; cn="$(ca_cn)"
  if [ -n "$cn" ]; then
    security delete-certificate -c "$cn" "$(login_keychain)" 2>/dev/null || true
  fi
  log "CA untrusted in the OS"
}
