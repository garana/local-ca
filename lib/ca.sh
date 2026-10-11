# shellcheck shell=bash
#
# Job 1, part 1: the root CA. Create the CA key and cert once, into
# gitignored state. Idempotent: the verb is "ensure it exists".

## Human-readable subject for the root CA. Includes the local user and
## host so the cert is easy to spot in Keychain Access / cert managers.
## Generated at runtime only; never written to a versioned file.
ca_subject() {
  printf '/CN=local-ca dev CA (%s@%s)/O=local-ca' \
    "$(id -un 2>/dev/null || printf user)" \
    "$(hostname -s 2>/dev/null || printf host)"
}

## Ensure the root CA key and cert exist. If both are present, report the
## paths and do nothing (idempotent). Root key: RSA 4096, 10-year
## validity, CA:TRUE, keyCertSign + cRLSign. Key file mode 600.
ca_init() {
  need_cmd openssl
  ensure_dir "$(ca_dir)"

  if [ -f "$(ca_key)" ] && [ -f "$(ca_crt)" ]; then
    log "CA already exists, leaving it as is"
    log "CA cert: $(ca_crt)"
    return 0
  fi

  if [ -f "$(ca_key)" ] || [ -f "$(ca_crt)" ]; then
    die "CA state is half-present (one of key/cert exists). Inspect $(ca_dir) and fix by hand, or run 'ca rotate'."
  fi

  log "creating root CA at $(ca_dir)"
  ( umask 077
    openssl req -x509 -new -nodes \
      -newkey rsa:4096 -sha256 -days 3650 \
      -keyout "$(ca_key)" -out "$(ca_crt)" \
      -subj "$(ca_subject)" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -addext "subjectKeyIdentifier=hash" >&2
  ) || die "openssl failed to create the CA"

  chmod 600 "$(ca_key)"
  # Start the leaf serial at a random-ish but fixed-width value.
  printf '1000\n' >"$(ca_serial)"

  log "CA cert: $(ca_crt)"
}

## Explicit, separate rotation. Never called by ca_init. Replaces the CA
## key and cert. After this, the CA must be re-trusted everywhere and all
## previously issued leaves become untrusted, so this is opt-in only.
ca_rotate() {
  need_cmd openssl
  if [ -f "$(ca_key)" ] || [ -f "$(ca_crt)" ]; then
    warn "rotating the CA: existing CA and all certs it signed will stop being trusted"
    warn "you must run 'ca untrust' before and 'ca trust' after, and re-issue leaf certs"
    rm -f "$(ca_key)" "$(ca_crt)" "$(ca_serial)"
  fi
  ca_init
}

## Read the CA certificate's Common Name from disk. Prints it to stdout,
## or nothing if the cert is missing. Used to find the CA in keychains
## and NSS stores for removal.
ca_cn() {
  [ -f "$(ca_crt)" ] || return 0
  openssl x509 -noout -subject -nameopt multiline -in "$(ca_crt)" 2>/dev/null \
    | awk -F' = ' '/[[:space:]]commonName/ {print $2; exit}'
}

## Fail unless the CA exists. Used by commands that sign against it.
require_ca() {
  [ -f "$(ca_key)" ] && [ -f "$(ca_crt)" ] || \
    die "no CA yet; run 'local-ca ca init' first"
}
