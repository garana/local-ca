# shellcheck shell=bash
#
# Job 1, part 2: issue leaf server certs signed by the CA. Modern
# browsers ignore the Common Name and require Subject Alternative Names,
# and reject leaf certs valid for more than 398 days, so we build SANs
# explicitly and cap validity below that.

## Default leaf validity in days. Kept just under the 398-day browser
## limit for publicly-rooted-style leaves (browsers apply it to any leaf).
DEFAULT_LEAF_DAYS=397

## Build the openssl [san] section from the requested names. localhost
## and 127.0.0.1 are always included. Each argument is classified as an
## IP SAN or a DNS SAN, and duplicates are dropped. Pure function: prints
## the section to stdout, touches nothing. Used by leaf_config and tested
## directly.
san_section() {
  local dns=() ip=() seen_dns=" localhost " seen_ip=" 127.0.0.1 " item
  # Always-present entries first.
  dns+=("localhost")
  ip+=("127.0.0.1")
  for item in "$@"; do
    if is_ip "$item"; then
      case "$seen_ip" in *" $item "*) continue ;; esac
      seen_ip+="$item "
      ip+=("$item")
    else
      case "$seen_dns" in *" $item "*) continue ;; esac
      seen_dns+="$item "
      dns+=("$item")
    fi
  done

  printf '[san]\n'
  local i=1 d
  for d in "${dns[@]}"; do printf 'DNS.%d = %s\n' "$i" "$d"; i=$((i+1)); done
  i=1
  local p
  for p in "${ip[@]}"; do printf 'IP.%d = %s\n' "$i" "$p"; i=$((i+1)); done
}

## Write the openssl config for a leaf cert. $1 = CN/name, rest = extra
## SANs. Prints nothing; writes to cert_cnf "$1".
leaf_config() {
  local name="$1"; shift
  local cnf; cnf="$(cert_cnf "$name")"
  {
    printf '[req]\n'
    printf 'distinguished_name = dn\n'
    printf 'req_extensions = v3_req\n'
    printf 'prompt = no\n\n'
    printf '[dn]\n'
    printf 'CN = %s\n\n' "$name"
    printf '[v3_req]\n'
    printf 'basicConstraints = CA:FALSE\n'
    printf 'keyUsage = critical, digitalSignature, keyEncipherment\n'
    printf 'extendedKeyUsage = serverAuth\n'
    printf 'subjectAltName = @san\n\n'
    san_section "$@"
  } >"$cnf"
}

## Issue (or reuse) a leaf cert. $1 = name (first SAN + CN), rest = extra
## SANs. Idempotent: if a cert for the name exists and is not expired,
## reuse it and print its paths. Pass --rotate as the first argument to
## force a fresh key+cert. Prints "cert <path>" and "key <path>" to
## stdout.
cert_issue() {
  need_cmd openssl
  require_ca

  local rotate=0
  if [ "${1:-}" = --rotate ]; then rotate=1; shift; fi
  [ "$#" -ge 1 ] || die "usage: local-ca cert [--rotate] <name> [more-sans...]"

  local name="$1"
  # Guard the name: it becomes a directory and file stem.
  case "$name" in
    *[!A-Za-z0-9._-]*|''|.*) die "invalid cert name '$name' (use letters, digits, dot, dash, underscore)" ;;
  esac

  local dir; dir="$(cert_dir "$name")"
  local crt; crt="$(cert_crt "$name")"
  local key; key="$(cert_key "$name")"

  if [ "$rotate" -eq 0 ] && [ -f "$crt" ] && [ -f "$key" ]; then
    if openssl x509 -checkend 0 -noout -in "$crt" >/dev/null 2>&1; then
      log "cert '$name' already exists and is valid, reusing it"
      printf 'cert %s\n' "$crt"
      printf 'key %s\n' "$key"
      return 0
    fi
    warn "cert '$name' is expired; reissuing"
  fi

  ensure_dir "$dir"
  leaf_config "$@"
  local cnf; cnf="$(cert_cnf "$name")"
  local csr="$dir/$name.csr"

  log "issuing leaf cert '$name' (SANs: localhost 127.0.0.1 ${*:2})"
  ( umask 077
    openssl req -new -nodes \
      -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -keyout "$key" -out "$csr" -config "$cnf" >&2
  ) || die "openssl failed to create the leaf key/CSR"

  openssl x509 -req -in "$csr" \
    -CA "$(ca_crt)" -CAkey "$(ca_key)" -CAserial "$(ca_serial)" \
    -days "$DEFAULT_LEAF_DAYS" -sha256 \
    -extfile "$cnf" -extensions v3_req \
    -out "$crt" >&2 || die "openssl failed to sign the leaf cert"

  chmod 600 "$key"
  rm -f "$csr"

  log "leaf cert ready"
  printf 'cert %s\n' "$crt"
  printf 'key %s\n' "$key"
}
