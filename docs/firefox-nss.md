# Firefox NSS trust path

This explains the hard part of Job 1's browser trust: Firefox.

## The problem

Firefox does not use the operating system trust store by default. It
ships its own trust store, NSS, with a separate certificate database per
profile. So trusting the CA in macOS or Linux is not enough; Safari and
Chrome will trust leaf certs from the CA, but Firefox still warns.

## The path local-ca uses: per-profile NSS import

`ca trust` imports the CA into every Firefox profile's NSS database with
`certutil` from NSS:

```
certutil -A -n "local-ca development CA" -t "C,," \
  -i <ca.crt> -d sql:<firefox-profile-dir>
```

- `-A` adds a cert; re-running with the same nickname updates in place,
  so it is idempotent.
- `-n` is the nickname (the fixed string above).
- `-t "C,,"` sets the trust flags: trusted to issue server certs (the
  first field, `C`, is the SSL trust).
- `-d sql:<dir>` points at the profile's modern `cert9.db` store. Legacy
  profiles use `cert8.db`, selected with `dbm:<dir>` instead.

Profiles live under:

- macOS: `~/Library/Application Support/Firefox/Profiles/*`
- Linux: `~/.mozilla/firefox/*`

`local-ca` treats a directory as a real profile when it contains
`cert9.db` or `cert8.db`. `ca untrust` removes the CA from each profile
with `certutil -D -n "local-ca development CA" -d ...`.

## Requirement: certutil

`certutil` comes from NSS tools:

- macOS: `brew install nss`
- Linux (Debian/Ubuntu): `apt-get install libnss3-tools`
- Linux (RHEL/Fedora): `dnf install nss-tools`

If `certutil` is missing, `ca trust` still trusts the CA in the OS store
and prints a note telling you to install it and re-run for Firefox. If no
Firefox profiles exist, the Firefox step is skipped quietly.

## The alternative we do not use: enterprise roots

Firefox can be told to read OS-trusted roots instead, with the pref:

```
security.enterprise_roots.enabled = true
```

Set it in `about:config`, or via a profile `user.js`. On macOS and
Windows this makes Firefox honor the CA you trusted in the OS store, so
you would not need the per-profile import.

We prefer the per-profile NSS import because the enterprise-roots pref is
a browser setting we cannot guarantee from a cert-install step: it is
per-profile, a user can turn it off, and it behaves differently across
platforms. The NSS import puts the trust exactly where Firefox looks, for
each profile, which is what `mkcert` does. We mirror `mkcert`'s approach
rather than wrapping it, to keep the dependencies to tools already on the
fleet (`openssl` and `certutil`).
