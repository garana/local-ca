# shellcheck shell=bash
#
# Trust dispatcher: installs/removes the CA in the OS trust store (by
# platform) and in Firefox. Job 1, cross-platform.

## Install the CA in the OS trust store and in Firefox. Idempotent.
ca_trust() {
  require_ca
  case "$(platform)" in
    macos) os_trust_macos ;;
    linux) os_trust_linux ;;
    *)     die "unsupported platform for OS trust: $(uname -s)" ;;
  esac
  firefox_trust
  log "done; browsers using the OS store or Firefox will now trust leaf certs from this CA"
}

## Remove the CA from the OS trust store and from Firefox.
ca_untrust() {
  case "$(platform)" in
    macos) os_untrust_macos ;;
    linux) os_untrust_linux ;;
    *)     die "unsupported platform for OS trust: $(uname -s)" ;;
  esac
  firefox_untrust
  log "done"
}
