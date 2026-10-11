---
name: test
description: Run the local-ca test suite. Use whenever asked to test, run tests, or verify changes to local-ca. This project has no build step (it is bash); testing is the only gate.
---

# Test local-ca

`local-ca` is bash, so there is no build step. The only gate is the
`bats-core` unit suite under `test/`. These tests use a temp
`LOCAL_CA_HOME` and never touch the real keychain, OS trust store, or
Firefox.

## Prerequisite

`bats` must be installed:

- macOS: `brew install bats-core`
- Linux: `apt-get install bats` or `npm install -g bats`

## Run the suite

From the repo root:

```
bats test/
```

To capture output for grepping (per project conventions, do not edit
source with shell pipelines; use a temp file under `.local-dev/`):

```
bats test/ >.local-dev/test.out 2>&1 || true
grep -E 'not ok|failures' .local-dev/test.out
```

A clean run ends with every line `ok N ...` and no `not ok`.

## What is NOT covered here

System-mutating steps are deliberately excluded from the automated suite
because they change the host:

- OS trust install/remove (`ca trust` / `ca untrust`)
- Firefox NSS import against real profiles
- macOS code-signing keychain import (`codesign-identity`)

Verify those by hand with the acceptance steps in `README.md`.
