# local-ca

A small personal certificate toolkit for one developer's fleet (Apple
Silicon Macs plus some Linux hosts). It does two separate jobs:

1. A local development Certificate Authority (CA): create a root CA once,
   issue leaf TLS certs signed by it for local web development, and trust
   the CA in the operating system and in Firefox, so browsers accept
   those certs without warnings. Cross-platform (macOS and Linux).

2. Self-signed code-signing identities: create one stable, reused
   self-signed code-signing cert per name, so `codesign` can sign local
   CLI builds with a constant identity and macOS keeps its LAN-access
   grant across rebuilds. macOS only.

The two jobs are separate trust domains. A code-signing cert is never
signed by the CA; the CA never signs code-signing certs.

Everything is idempotent: the verb is "ensure it exists", not "make a
new one". Re-running never rotates a cert that already exists. Rotation
is a separate, explicit command.

## Requirements

- `openssl` (all jobs).
- macOS: `security` and `codesign` (built in); `certutil` for Firefox
  (`brew install nss`).
- Linux: `update-ca-certificates` (Debian/Ubuntu) or `update-ca-trust`
  (RHEL/Fedora) for OS trust; `certutil` for Firefox
  (`libnss3-tools` / `nss-tools`).

## State and secrets

All generated keys and certs live under `$LOCAL_CA_HOME` (default
`~/.local-ca`), outside the repo. A fresh clone contains zero secrets.
Set `LOCAL_CA_HOME` to use a different location.

```
~/.local-ca/
  ca/        root CA key (mode 600), cert, serial
  certs/     one subdir per leaf cert: <name>.key, <name>.crt
  codesign/  exported <name>.cer (the private key stays in the keychain)
```

## Commands

### Job 1: CA and web-dev certs

```
local-ca ca init
local-ca ca trust
local-ca cert <name> [extra-sans...]
```

- `ca init` creates the root CA key and cert if they do not exist.
- `ca trust` trusts the CA in the OS store and in every Firefox profile.
  `ca untrust` reverses it.
- `cert <name> [sans...]` issues a leaf server cert signed by the CA.
  `localhost` and `127.0.0.1` are always included; each extra argument
  is added as a DNS name, or an IP address if it parses as one. The cert
  has the `serverAuth` usage and is valid for 397 days (browsers reject
  longer leaf certs). It prints the cert and key paths on stdout.

Example:

```
local-ca ca init
local-ca ca trust
local-ca cert web mysite.local 192.168.1.10
# -> cert ~/.local-ca/certs/web/web.crt
#    key  ~/.local-ca/certs/web/web.key
```

On macOS, `ca trust` uses your login keychain and shows a one-time
authorization dialog (no sudo). Set `LOCAL_CA_SYSTEM_TRUST=1` to trust
system-wide instead (needs sudo). On Linux it installs a system anchor
and needs sudo.

### Job 2: code-signing identity (macOS only)

```
local-ca codesign-identity <name> [--bundle-id ID] [--bits N] [--days N]
```

Ensures a self-signed code-signing identity named `<name>` exists in the
login keychain, set up so `codesign` can use it with no per-sign prompt.
It prints only the identity name on stdout, so build scripts can capture
it:

```
IDENT=$(local-ca codesign-identity pbw_miner)
codesign --sign "$IDENT" ./build/pbw_miner
cmake -DPBW_CODESIGN_IDENTITY="$IDENT" ...
```

The first run creates the identity (and may prompt for your login
password to finish the non-interactive setup; see the doc below). A
second run returns the same identity without creating another.

### Rotation (explicit)

```
local-ca ca rotate            # replace the CA; breaks existing trust
local-ca cert <name> --rotate # replace one leaf cert
```

Use these only on purpose. A changed CA must be re-trusted everywhere,
and all certs it signed stop being trusted.

## Docs for the two hard parts

- `docs/codesign-macos.md`: the code-signing cert extensions, the
  keychain partition list, and how to verify with `find-identity`.
- `docs/firefox-nss.md`: why Firefox needs its own trust path and how the
  per-profile NSS import works.

## Tests

The logic is covered by a `bats-core` suite that uses a temp
`LOCAL_CA_HOME` and does not touch your real keychain, OS trust store, or
Firefox:

```
brew install bats-core   # or apt-get install bats
bats test/
```

System-mutating steps (OS trust, keychain import, Firefox) are verified
by hand using the examples above.
