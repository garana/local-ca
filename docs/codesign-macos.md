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

## PKCS#12 must be exported with -legacy

To move the key and cert into the keychain, `local-ca` bundles them into
a PKCS#12 file and runs `security import`. OpenSSL 3 and 4 default to a
modern PKCS#12 scheme (AES-256-CBC + PBKDF2 with a SHA-256 MAC) that
macOS's `security import` cannot verify; it fails with the misleading
message `MAC verification failed during PKCS12 import (wrong password?)`
even though the password is correct. The fix is to export with the
`-legacy` flag (OpenSSL 3.0+), which writes the older SHA1 + 3DES
algorithms macOS accepts. `local-ca` does this; do not remove the flag.

## The four things that must be right

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

4. The cert trusted for the code-signing policy.
   A self-signed cert imports untrusted (`CSSMERR_TP_NOT_TRUSTED`), so
   `find-identity -v` (valid-only) hides it and signature verification
   sees an untrusted signer. We add a trust setting in the user/login
   domain:

   ```
   security add-trusted-cert -r trustRoot -p codeSign \
     -k ~/Library/Keychains/login.keychain-db <cert>
   ```

   `-p codeSign` scopes the trust to code signing; no `-d`, so it is the
   user/login domain (the `-d` admin/system domain needs sudo). This
   shows a one-time "you are making changes to your Certificate Trust
   Settings" dialog asking for your login password. Unlike the partition
   list, `add-trusted-cert` has no command-line password flag, so this
   dialog cannot be bypassed with `LOCAL_CA_KEYCHAIN_PASSWORD`; it needs a
   GUI session.

## Verify success

The identity must show up as valid for the codesigning policy:

```
security find-identity -v -p codesigning
```

You should see a line containing `"<name>"`. The `-v` means valid-only;
because step 4 trusted the cert, it is valid and listed. If you see "0
valid identities", the trust step did not take (re-run the command and
complete the trust-settings dialog). `local-ca` runs this `-v` check
itself and fails if the name is not listed.

A real sign confirms it and must not prompt once the partition list is
set:

```
codesign --force --sign "<name>" /path/to/your/binary
codesign -dvvv /path/to/your/binary   # shows Authority=<name>
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
