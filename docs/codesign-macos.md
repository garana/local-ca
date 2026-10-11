# macOS code-signing keychain setup

This explains the hard part of Job 2: making a self-signed code-signing
cert that `codesign` can use with no prompt on every sign, and verifying
it. Run it with:

```
local-ca codesign-identity <name> [--bundle-id ID] [--bits N] [--days N]
```

## Why this exists

A locally built macOS CLI gets an automatic "ad-hoc" signature. macOS
treats that as effectively unsigned and blocks the binary's LAN access
(outgoing `connect()` to a LAN peer returns "No route to host"; incoming
is blocked by the application firewall). Signing with a deliberate
identity lets macOS grant network access and remember the grant.

The ad-hoc signature's identity is the binary's content hash, which
changes on every rebuild, so the grant is lost after each build. A
stable signing identity (one self-signed cert reused across builds)
keeps the identity constant, so the grant is given once and sticks. That
is why the command is idempotent: the same common name every time.

This is a separate trust domain from the CA in Job 1. A code-signing
cert is never signed by the CA.

## The three things that must be right

1. Correct extended key usage on the cert.
   The cert must carry `extendedKeyUsage = critical, codeSigning`.
   Without it, `codesign` and the OS will not accept it as a signing
   identity. We also set `basicConstraints = critical, CA:FALSE` and
   `keyUsage = critical, digitalSignature`.

2. `codesign` allowed to read the private key.
   On `security import` we pass `-T /usr/bin/codesign` (and
   `-T /usr/bin/security`). The `-T` flag adds those tools to the key's
   access control list, so the key can be used by them.

3. The key partition list set.
   Even with the ACL, modern macOS gates key use behind a "partition
   list". We run:

   ```
   security set-key-partition-list \
     -S apple-tool:,apple:,codesign: \
     -s -k <login-password> ~/Library/Keychains/login.keychain-db
   ```

   This is the step that stops the per-sign password prompt. It needs
   your macOS login (keychain) password. `local-ca` prompts for it, or
   reads it from `LOCAL_CA_KEYCHAIN_PASSWORD` if set (useful in CI). If
   you skip it, `codesign` will prompt once on first use; clicking
   "Always Allow" there achieves the same result by hand.

## Verify success

The identity must show up for the codesigning policy:

```
security find-identity -v -p codesigning
```

You should see a line containing `"<name>"`. `local-ca` runs this check
itself and fails if the name is not listed. Then a real sign must not
prompt:

```
codesign --force --sign "<name>" /path/to/your/binary
codesign --display --verbose=2 /path/to/your/binary
```

## Using it from a build

The command prints only the identity name on stdout, so build scripts
can capture it directly:

```
IDENT=$(local-ca codesign-identity pbw_miner)
codesign --sign "$IDENT" ./build/pbw_miner
# or, for solonode's CMake:
cmake -DPBW_CODESIGN_IDENTITY="$IDENT" ...
```

All logging goes to stderr, so `$IDENT` is a clean string. An exported
public cert is also written to
`~/.local-ca/codesign/<name>.cer` for callers that want the cert file;
the private key stays in the login keychain and is never written to
disk.

## Rotating or removing

To remove an identity, delete it in Keychain Access (login keychain), or:

```
security delete-identity -c "<name>" ~/Library/Keychains/login.keychain-db
```

Removing it means the next build with a fresh identity re-prompts for the
network grant, which is exactly what the stable identity avoids. Only do
this on purpose.
