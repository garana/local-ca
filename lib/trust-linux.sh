# shellcheck shell=bash
#
# Linux OS-trust for the CA. Two families, picked by which update tool is
# present:
#   - Debian/Ubuntu: drop the CA in /usr/local/share/ca-certificates and
#     run update-ca-certificates. Files there must end in .crt.
#   - RHEL/Fedora/SUSE: drop the CA in /etc/pki/ca-trust/source/anchors
#     and run update-ca-trust.
# Both need root, so these use sudo.

## Fixed base name for the installed anchor file.
LINUX_ANCHOR_NAME="local-ca.crt"

## Add the CA to the Linux system trust store. Idempotent: copying over
## the same anchor and re-running the update tool is harmless.
os_trust_linux() {
  local crt; crt="$(ca_crt)"
  if command -v update-ca-certificates >/dev/null 2>&1; then
    log "installing CA anchor (Debian family, needs sudo)"
    sudo install -m 0644 "$crt" "/usr/local/share/ca-certificates/$LINUX_ANCHOR_NAME" \
      || die "failed to copy CA anchor"
    sudo update-ca-certificates || die "update-ca-certificates failed"
  elif command -v update-ca-trust >/dev/null 2>&1; then
    log "installing CA anchor (RHEL family, needs sudo)"
    sudo install -m 0644 "$crt" "/etc/pki/ca-trust/source/anchors/$LINUX_ANCHOR_NAME" \
      || die "failed to copy CA anchor"
    sudo update-ca-trust || die "update-ca-trust failed"
  else
    die "no supported trust updater found (need update-ca-certificates or update-ca-trust)"
  fi
  log "CA trusted by the OS"
}

## Remove the CA anchor and refresh the trust store.
os_untrust_linux() {
  if command -v update-ca-certificates >/dev/null 2>&1; then
    sudo rm -f "/usr/local/share/ca-certificates/$LINUX_ANCHOR_NAME"
    sudo update-ca-certificates --fresh >/dev/null 2>&1 || sudo update-ca-certificates || true
  elif command -v update-ca-trust >/dev/null 2>&1; then
    sudo rm -f "/etc/pki/ca-trust/source/anchors/$LINUX_ANCHOR_NAME"
    sudo update-ca-trust || true
  else
    warn "no supported trust updater found; nothing removed"
  fi
  log "CA untrusted in the OS"
}
