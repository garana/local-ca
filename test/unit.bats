#!/usr/bin/env bats
#
# Unit tests for local-ca's pure logic and the idempotent CA/cert flow.
# These never touch the real keychain, OS trust store, or Firefox; they
# run entirely under a temp LOCAL_CA_HOME.
#
# Run: bats test/   (install with 'brew install bats-core')

bats_require_minimum_version 1.5.0

setup() {
  LIB="$BATS_TEST_DIRNAME/../lib"
  ROOT="$BATS_TEST_DIRNAME/.."
  # shellcheck source=../lib/common.sh
  . "$LIB/common.sh"
  . "$LIB/ca.sh"
  . "$LIB/cert.sh"
  . "$LIB/firefox.sh"
  export LOCAL_CA_HOME="$BATS_TEST_TMPDIR/state"
}

# --- is_ip -----------------------------------------------------------------

@test "is_ip accepts IPv4" {
  is_ip 127.0.0.1
  is_ip 192.168.1.10
  is_ip 255.255.255.255
}

@test "is_ip accepts IPv6" {
  is_ip ::1
  is_ip fe80::1
}

@test "is_ip rejects host names and bad octets" {
  run is_ip localhost;     [ "$status" -ne 0 ]
  run is_ip mysite.local;  [ "$status" -ne 0 ]
  run is_ip 256.1.1.1;     [ "$status" -ne 0 ]
  run is_ip 1.2.3;         [ "$status" -ne 0 ]
  run is_ip 1.2.3.4.5;     [ "$status" -ne 0 ]
}

# --- san_section -----------------------------------------------------------

@test "san_section always includes localhost and 127.0.0.1" {
  run san_section
  [ "$status" -eq 0 ]
  [[ "$output" == *"DNS.1 = localhost"* ]]
  [[ "$output" == *"IP.1 = 127.0.0.1"* ]]
}

@test "san_section classifies names and IPs and de-duplicates" {
  run san_section mysite.local 192.168.1.10 localhost 127.0.0.1
  [ "$status" -eq 0 ]
  # localhost and 127.0.0.1 appear exactly once despite being repeated.
  [ "$(grep -c '= localhost' <<<"$output")" -eq 1 ]
  [ "$(grep -c '= 127.0.0.1' <<<"$output")" -eq 1 ]
  [[ "$output" == *"DNS.2 = mysite.local"* ]]
  [[ "$output" == *"IP.2 = 192.168.1.10"* ]]
}

# --- ca init idempotency ---------------------------------------------------

@test "ca_init creates key+cert then is idempotent" {
  ca_init
  [ -f "$(ca_key)" ]
  [ -f "$(ca_crt)" ]
  # key must be owner-only.
  perm="$(stat -f '%Lp' "$(ca_key)" 2>/dev/null || stat -c '%a' "$(ca_key)")"
  [ "$perm" = "600" ]
  before="$(cat "$(ca_crt)")"
  ca_init
  after="$(cat "$(ca_crt)")"
  [ "$before" = "$after" ]
}

@test "ca_cn reads the CA common name" {
  ca_init
  run ca_cn
  [ "$status" -eq 0 ]
  [[ "$output" == local-ca\ dev\ CA* ]]
}

# --- cert issuance ---------------------------------------------------------

@test "cert_issue builds a valid leaf with the right SANs and EKU" {
  ca_init
  run cert_issue web mysite.local 10.0.0.5
  [ "$status" -eq 0 ]
  crt="$(cert_crt web)"
  [ -f "$crt" ]
  txt="$(openssl x509 -in "$crt" -noout -text)"
  [[ "$txt" == *"DNS:localhost"* ]]
  [[ "$txt" == *"DNS:mysite.local"* ]]
  [[ "$txt" == *"IP Address:127.0.0.1"* ]]
  [[ "$txt" == *"IP Address:10.0.0.5"* ]]
  [[ "$txt" == *"TLS Web Server Authentication"* ]]
}

@test "cert_issue caps validity under 398 days" {
  ca_init
  cert_issue web >/dev/null
  nb="$(openssl x509 -in "$(cert_crt web)" -noout -startdate | cut -d= -f2)"
  na="$(openssl x509 -in "$(cert_crt web)" -noout -enddate   | cut -d= -f2)"
  nbs="$(date -j -f '%b %e %T %Y %Z' "$nb" +%s 2>/dev/null || date -d "$nb" +%s)"
  nas="$(date -j -f '%b %e %T %Y %Z' "$na" +%s 2>/dev/null || date -d "$na" +%s)"
  days=$(( (nas - nbs) / 86400 ))
  [ "$days" -lt 398 ]
  [ "$days" -ge 395 ]
}

@test "cert_issue prints only cert/key lines on stdout" {
  ca_init >/dev/null 2>&1
  run --separate-stderr cert_issue web
  [ "$status" -eq 0 ]
  # stdout is exactly two lines: 'cert <path>' and 'key <path>'.
  [ "${#lines[@]}" -eq 2 ]
  [[ "${lines[0]}" == cert\ * ]]
  [[ "${lines[1]}" == key\ * ]]
}

@test "cert_issue is idempotent (same cert content on reissue)" {
  ca_init
  cert_issue web >/dev/null
  before="$(cat "$(cert_crt web)")"
  cert_issue web >/dev/null
  after="$(cat "$(cert_crt web)")"
  [ "$before" = "$after" ]
}

@test "cert_issue rejects bad names" {
  ca_init
  run cert_issue "../evil"
  [ "$status" -ne 0 ]
  run cert_issue "a b"
  [ "$status" -ne 0 ]
}

# --- firefox profile discovery ---------------------------------------------

@test "firefox_profile_dirs finds dirs with an NSS store" {
  base="$BATS_TEST_TMPDIR/ff"
  mkdir -p "$base/a.default" "$base/b.dev" "$base/c.empty"
  : >"$base/a.default/cert9.db"
  : >"$base/b.dev/cert8.db"
  run firefox_profile_dirs "$base"
  [ "$status" -eq 0 ]
  [[ "$output" == *"a.default"* ]]
  [[ "$output" == *"b.dev"* ]]
  [[ "$output" != *"c.empty"* ]]
}

@test "firefox_profile_dirs is empty for a missing base" {
  run firefox_profile_dirs "$BATS_TEST_TMPDIR/nope"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "firefox_nss_db_arg picks sql: for cert9 and dbm: for cert8" {
  d1="$BATS_TEST_TMPDIR/p9"; mkdir -p "$d1"; : >"$d1/cert9.db"
  d2="$BATS_TEST_TMPDIR/p8"; mkdir -p "$d2"; : >"$d2/cert8.db"
  [ "$(firefox_nss_db_arg "$d1")" = "sql:$d1" ]
  [ "$(firefox_nss_db_arg "$d2")" = "dbm:$d2" ]
}

# --- codesign PKCS#12 legacy guard (issue #1) ------------------------------

# The keychain import itself is not run in the automated suite (it mutates
# the login keychain). This guards the one-flag regression that broke it:
# OpenSSL 3/4 must export the PKCS#12 with -legacy, or macOS 'security
# import' fails with "MAC verification failed".
@test "codesign.sh exports the PKCS#12 with -legacy" {
  run grep -E 'openssl[[:space:]]+pkcs12[[:space:]]+-export[[:space:]]+-legacy' "$LIB/codesign.sh"
  [ "$status" -eq 0 ]
}

# Belt-and-braces: prove an OpenSSL -legacy p12 round-trips, so a future
# OpenSSL that drops -legacy support is caught here too. No keychain.
@test "openssl can export and re-read a -legacy PKCS#12" {
  k="$BATS_TEST_TMPDIR/t.key"; c="$BATS_TEST_TMPDIR/t.crt"; p="$BATS_TEST_TMPDIR/t.p12"
  openssl req -x509 -new -nodes -newkey rsa:2048 -sha256 -days 30 \
    -keyout "$k" -out "$c" -subj "/CN=legacy-p12-test" >/dev/null 2>&1
  run openssl pkcs12 -export -legacy -out "$p" -inkey "$k" -in "$c" -name t -passout pass:pw
  [ "$status" -eq 0 ]
  [ -s "$p" ]
  # Reading legacy algorithms back also needs the legacy provider; this
  # round-trips the file the same way it was written.
  run openssl pkcs12 -legacy -in "$p" -passin pass:pw -noout
  [ "$status" -eq 0 ]
}

# --- codesign find-identity predicate guard (issues #3, #5, #7) ------------

# Our certs are self-signed, hence untrusted. 'find-identity -v' hides
# untrusted identities, so the existence-check and success-gate must use
# 'find-identity -p codesigning' WITHOUT -v, or the command dies after a
# successful import and re-runs duplicate the cert. Option A (#5) tried to
# fix this by trusting the cert so -v would list it, but a user-domain
# add-trusted-cert does not make a self-signed code-signing cert valid on
# macOS; reverted in #7. So: no -v in the actual code.
@test "codesign.sh code never uses find-identity with -v" {
  # Strip comment lines first; the guard is about the code, not prose that
  # may mention the -v flag while explaining why it is not used.
  run bash -c "grep -vE '^[[:space:]]*#' \"$LIB/codesign.sh\" | grep -nE 'find-identity[[:space:]]+-v'"
  [ "$status" -ne 0 ]
}

@test "codesign_identity_exists uses find-identity -p codesigning (no -v)" {
  run grep -E 'security[[:space:]]+find-identity[[:space:]]+-p[[:space:]]+codesigning' "$LIB/codesign.sh"
  [ "$status" -eq 0 ]
}
