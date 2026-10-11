# shellcheck shell=bash
#
# Job 2 (macOS only): ensure a stable, reusable self-signed code-signing
# identity exists in the login keychain, so `codesign` can sign local CLI
# builds with a constant identity and macOS keeps its LAN-access grant
# across rebuilds.
#
# The identity's common name is the given name, identical across
# rebuilds. stdout prints ONLY that name (one line) so callers can do
#   IDENT=$(local-ca codesign-identity pbw_miner)
# and pass "$IDENT" to `codesign --sign` and to CMake's
# -DPBW_CODESIGN_IDENTITY=. All logging goes to stderr.

## Default key size and validity for a code-signing cert.
DEFAULT_CODESIGN_BITS=2048
DEFAULT_CODESIGN_DAYS=3650

## Exit 0 if a code-signing identity with common name $1 is in the
## keychain, else 1. Deliberately uses 'find-identity -p codesigning'
## WITHOUT -v: our certs are self-signed and therefore untrusted, and the
## -v (valid-only) filter hides untrusted identities. An untrusted
## identity still signs fine (trust is a verification concern, not a
## signing one; the macOS LAN-access grant keys on the code identity, not
## on chain trust), so -v is the wrong gate here. Using the same
## predicate for the idempotency check and the post-import gate also
## means a re-run reuses an existing cert instead of duplicating it. See
## issue #3.
##
## Do NOT reintroduce -v with a trust setting (that was issue #5 / Option
## A): on macOS a user-domain 'add-trusted-cert' does not make a
## self-signed code-signing cert pass 'find-identity -v', so the gate
## died even after the trust dialog was answered. Reverted in issue #7.
codesign_identity_exists() {
  security find-identity -p codesigning 2>/dev/null \
    | grep -Fq "\"$1\""
}

## Ensure a code-signing identity named $1 exists. Extra options:
##   --bundle-id ID   informational OU in the subject (default: name)
##   --bits N         RSA key size (default 2048)
##   --days N         validity (default 3650)
## Idempotent: if the identity already exists, print its name and return.
codesign_ensure() {
  is_macos || die "codesign-identity is macOS-only"
  need_cmd openssl
  need_cmd security
  need_cmd codesign

  [ "$#" -ge 1 ] || die "usage: local-ca codesign-identity <name> [--bundle-id ID] [--bits N] [--days N]"
  local name="$1"; shift
  case "$name" in
    *[!A-Za-z0-9._-]*|''|.*) die "invalid identity name '$name' (use letters, digits, dot, dash, underscore)" ;;
  esac

  local bundle_id="$name" bits="$DEFAULT_CODESIGN_BITS" days="$DEFAULT_CODESIGN_DAYS"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --bundle-id) bundle_id="$2"; shift 2 ;;
      --bits)      bits="$2";      shift 2 ;;
      --days)      days="$2";      shift 2 ;;
      *) die "unknown option '$1'" ;;
    esac
  done

  ensure_dir "$(codesign_dir)"
  local cer; cer="$(codesign_cer "$name")"

  if codesign_identity_exists "$name"; then
    log "code-signing identity '$name' already exists, reusing it"
    [ -f "$cer" ] && log "exported cert: $cer"
    printf '%s\n' "$name"
    return 0
  fi

  log "creating self-signed code-signing identity '$name'"
  local tmp; tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  local key="$tmp/$name.key" crt="$tmp/$name.crt" p12="$tmp/$name.p12"
  local p12pass; p12pass="$name-$$-import"

  # Self-signed cert with the code-signing EKU. basicConstraints CA:FALSE,
  # keyUsage digitalSignature, extendedKeyUsage critical codeSigning.
  ( umask 077
    openssl req -x509 -new -nodes \
      -newkey "rsa:$bits" -sha256 -days "$days" \
      -keyout "$key" -out "$crt" \
      -subj "/CN=$name/OU=$bundle_id/O=local-ca codesign" \
      -addext "basicConstraints=critical,CA:FALSE" \
      -addext "keyUsage=critical,digitalSignature" \
      -addext "extendedKeyUsage=critical,codeSigning" >&2
  ) || die "openssl failed to create the code-signing cert"

  # -legacy makes OpenSSL 3/4 write the older PKCS#12 MAC/PBE algorithms
  # (SHA1 + 3DES) that macOS 'security import' (SecurityFramework) can
  # verify. Without it, OpenSSL's modern default (AES-256-CBC + PBKDF2,
  # SHA-256 MAC) makes security import fail with a misleading
  # "MAC verification failed ... (wrong password?)". See issue #1.
  openssl pkcs12 -export -legacy -out "$p12" -inkey "$key" -in "$crt" \
    -name "$name" -passout "pass:$p12pass" >&2 \
    || die "openssl failed to bundle the PKCS#12"

  local kc; kc="$(login_keychain)"
  # Import key+cert; allow codesign (and security) to use the private key.
  security import "$p12" -k "$kc" -P "$p12pass" \
    -T /usr/bin/codesign -T /usr/bin/security >&2 \
    || die "security import into the login keychain failed"

  # Set the key partition list so codesign reads the private key without a
  # prompt on every sign. This needs the keychain (login) password.
  local kcpass
  if [ -n "${LOCAL_CA_KEYCHAIN_PASSWORD+x}" ]; then
    kcpass="$LOCAL_CA_KEYCHAIN_PASSWORD"
  elif [ -t 0 ]; then
    printf 'local-ca: enter your macOS login/keychain password (for set-key-partition-list): ' >&2
    read -rs kcpass; printf '\n' >&2
  else
    kcpass=""
  fi

  if [ -n "$kcpass" ]; then
    security set-key-partition-list -S apple-tool:,apple:,codesign: \
      -s -k "$kcpass" "$kc" >/dev/null 2>&1 \
      || warn "set-key-partition-list failed; codesign may prompt on first sign"
  else
    warn "no keychain password given; skipping set-key-partition-list"
    warn "codesign may prompt once on first sign (grant 'Always Allow' there)"
  fi

  # Export the public cert for callers (DER .cer), key stays in keychain.
  openssl x509 -outform der -in "$crt" -out "$cer" 2>/dev/null || true
  chmod 644 "$cer" 2>/dev/null || true

  # Verify the identity is usable for code signing. The cert is
  # self-signed, so it lists as untrusted (CSSMERR_TP_NOT_TRUSTED); that
  # is expected and does not stop codesign from signing with it.
  if ! codesign_identity_exists "$name"; then
    die "identity '$name' not listed by 'security find-identity -p codesigning' after import"
  fi
  log "verified: 'security find-identity -p codesigning' lists '$name' (self-signed, shown untrusted; still usable to sign)"
  [ -f "$cer" ] && log "exported cert: $cer"

  printf '%s\n' "$name"
}
