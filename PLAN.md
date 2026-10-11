# PLAN

Design notes and open questions for `local-ca`. This file holds the plan.
`README.md` holds the current, working features. Neither is a log.

## Scope

Two separate jobs, two separate trust domains:

1. Local development CA: create a root CA once, issue leaf TLS certs
   signed by it, and trust the CA in the OS and in Firefox so browsers
   accept the leaf certs without warnings.
2. Self-signed code-signing certs (macOS only): create one stable,
   reused self-signed code-signing identity per name, so `codesign` can
   sign local CLI builds with a constant identity and macOS keeps the
   LAN-access grant across rebuilds.

The two jobs do not share keys or trust. A code-signing cert is never
signed by the CA; the CA never signs code-signing certs.

## Language and layout

Bash (not POSIX sh) for arrays and cleaner string handling. Tested with
`bats-core`. The whole tool wraps external binaries: `openssl`,
`security` and `codesign` (macOS), `update-ca-trust` /
`update-ca-certificates` (Linux), and `certutil` from NSS (Firefox).

```
local-ca              entry script, dispatches subcommands
lib/
  common.sh           shared helpers: logging, state paths, platform
  ca.sh               ca init / rotate
  cert.sh             leaf cert issuance
  trust.sh            OS trust install/remove (dispatches by platform)
  trust-macos.sh      security add-trusted-cert / remove
  trust-linux.sh      anchors + update-ca-trust / update-ca-certificates
  firefox.sh          NSS per-profile certutil import/remove
  codesign.sh         macOS code-signing identity ensure (job 2)
docs/
  codesign-macos.md   EKU, partition list, find-identity verification
  firefox-nss.md      Firefox NSS trust path and its caveats
test/
  *.bats              unit tests for the pure logic
PLAN.md  README.md  .gitignore
```

Keeping each job's logic in its own `lib/*.sh` file lets the pure parts
(argument parsing, SAN list building, OpenSSL config generation, Firefox
profile discovery) be unit-tested without touching the real keychain or
trust store.

## State layout

All generated secrets live outside the repo so a fresh clone has zero
secrets. Default state home: `~/.local-ca`, overridable with the
`LOCAL_CA_HOME` environment variable (used by tests to point at a temp
dir).

```
$LOCAL_CA_HOME/
  ca/
    ca.key            root CA private key, mode 600
    ca.crt            root CA certificate
    serial            issuance serial counter
    index.txt         issued-cert index (openssl ca db), optional
  certs/
    <name>/
      <name>.key      leaf private key, mode 600
      <name>.crt      leaf certificate
      <name>.cnf      the openssl config used (for reproducibility)
  codesign/
    <name>.cer        exported public cert for callers (key stays in
                      the login keychain, never on disk)
```

Even though state defaults outside the repo, `.gitignore` also excludes
`state/`, `*.key`, `*.crt`, `*.cer`, `*.p12`, `*.csr` in case someone
points `LOCAL_CA_HOME` inside the tree.

## Commands

### Job 1: CA and web-dev certs

- `local-ca ca init`
  Ensure the root CA key and cert exist. Idempotent: if `ca.crt` and
  `ca.key` already exist, do nothing and report the existing paths.
  CA key is 4096-bit RSA (or P-256; see open questions), long validity
  (~10 years), `basicConstraints=critical,CA:TRUE`, `keyCertSign` +
  `cRLSign` key usage. Key file mode 600.

- `local-ca ca trust`
  Install the CA into the OS trust store and into Firefox NSS.
  Idempotent. macOS: `security add-trusted-cert`. Linux: copy to the
  distro anchor dir and run `update-ca-trust` or
  `update-ca-certificates`. Firefox: per-profile `certutil -A`.

- `local-ca ca untrust`
  Remove the CA from the OS trust store and from Firefox NSS.

- `local-ca cert <name> [more-sans...]`
  Issue a leaf server cert signed by the CA. SANs always include
  `localhost` and `127.0.0.1`; every argument is added as a DNS SAN,
  or as an IP SAN if it parses as an IP. `serverAuth` EKU. Validity
  under 398 days (browsers reject longer leaf certs). Idempotent on the
  first name: re-running `cert foo` returns the existing cert if present
  and still valid. Prints cert and key paths.

- `local-ca ca rotate` / `local-ca cert <name> --rotate`
  Explicit, separate rotation. Never implied by `init` or `cert`,
  because a changed identity defeats browser trust and the code-signing
  grant.

### Job 2: code-signing identity (macOS only)

- `local-ca codesign-identity <name> [--bundle-id ID] [--bits N] [--days N]`
  Ensure a self-signed code-signing identity named `<name>` exists in
  the login keychain. If `security find-identity -v -p codesigning`
  already lists `<name>`, print the identity name and the exported
  `.cer` path and exit 0 without creating anything.
  Otherwise:
  1. Generate a key + self-signed cert with
     `extendedKeyUsage=critical,codeSigning` and a stable common name
     equal to `<name>`.
  2. Import key+cert into the login keychain with `-T /usr/bin/codesign`
     so `codesign` is allowed to use the key.
  3. Run `security set-key-partition-list -S apple-tool:,apple:,codesign:`
     so `codesign` reads the private key non-interactively (no prompt
     per sign).
  4. Verify with `security find-identity -v -p codesigning`.
  stdout must be a clean, parseable identity string on its own line so
  callers can do `IDENT=$(local-ca codesign-identity pbw_miner)` and pass
  it to `codesign --sign "$IDENT"` and to CMake's
  `-DPBW_CODESIGN_IDENTITY=<name>`. All human-readable logging goes to
  stderr so it never pollutes that stdout contract.

## stdout / stderr contract

Machine-readable output (identity name, cert/key paths) goes to stdout.
All progress, warnings and errors go to stderr. This keeps command
substitution in callers' build scripts clean.

## Platform handling

`uname -s` picks the platform. macOS = `Darwin`, Linux = `Linux`.
`codesign-identity` refuses to run off macOS with a clear error. Linux
trust supports both the Debian path (`/usr/local/share/ca-certificates`
+ `update-ca-certificates`) and the RHEL path
(`/etc/pki/ca-trust/source/anchors` + `update-ca-trust`), picked by which
tool is present.

## Firefox NSS

Firefox ignores the OS trust store, so the CA must be added to each
Firefox profile's own NSS database. Primary path (the one we implement):
per-profile `certutil -A -n "<ca name>" -t "C,," -i ca.crt -d
sql:<profile-dir>` for every profile under the profiles directory
(macOS: `~/Library/Application Support/Firefox/Profiles/*`; Linux:
`~/.mozilla/firefox/*`). Needs `certutil` (macOS: `brew install nss`;
Linux: `libnss3-tools` / `nss-tools`). We detect `cert9.db` (the modern
`sql:` store) in a profile dir to decide it is a real profile.

Documented alternative (not implemented, noted in docs): set
`security.enterprise_roots.enabled = true` so Firefox reads OS-trusted
roots. Simpler but it is a browser setting we cannot guarantee per
profile, so we prefer the explicit NSS import. This mirrors `mkcert`,
which is the reference for CA + OS trust + Firefox/NSS; we mirror its
approach rather than wrapping the binary, to keep the dependency surface
to tools already on the fleet.

## Testing strategy

`bats-core`. Unit tests cover the pure logic with `LOCAL_CA_HOME` set to
a temp dir and no system mutation:
- SAN list building (names vs IPs, always-included localhost/127.0.0.1).
- OpenSSL config generation for CA, leaf and code-signing certs.
- `ca init` idempotency: second run does not change key/cert mtime.
- `cert` idempotency and the 398-day validity cap.
- Firefox profile discovery given a fake profiles dir with `cert9.db`.
- Argument parsing and the stdout/stderr split.

System-touching steps (OS trust, keychain import, real certutil) are not
run in the default test suite because they mutate the host; they are
covered by the manual acceptance steps in the brief's "Done when".

## Open questions

- CA key type: RSA 4096 (broad compatibility) vs EC P-256 (smaller,
  modern, fine for all current browsers). Leaning RSA 4096 for the root
  for maximum compatibility, EC P-256 for leaves. To confirm.
- macOS OS trust scope: trust the CA in the login keychain (user-only,
  no sudo, may still prompt once) vs the System keychain (all users,
  needs sudo). Leaning login keychain to avoid sudo, matching mkcert's
  default. To confirm.
- Code-signing cert trust: `find-identity` listing + non-interactive
  signing is the stated bar. Whether to also add a codeSign trust
  setting (so `codesign --verify` is fully happy) is an extra; document
  and decide.
- Leaf validity default: 397 days (just under the 398 cap). To confirm.
