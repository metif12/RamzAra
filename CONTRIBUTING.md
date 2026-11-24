# Contributing to RamzAra

## Development setup

The package imports itself as `metif12.ramzara.*`, so the checkout must be
visible at that path. Either install it:

```sh
v install metif12.ramzara
```

or link/copy the checkout there during development:

```sh
# Unix
mkdir -p ~/.vmodules/metif12
ln -s /path/to/ramzara ~/.vmodules/metif12/ramzara
# Windows (no admin needed)
mkdir %USERPROFILE%\.vmodules\metif12
mklink /J %USERPROFILE%\.vmodules\metif12\ramzara C:\path\to\ramzara
```

You need a V toolchain newer than 0.5.2 (the code uses
`x.crypto.mldsa`/`x.crypto.mlkem`-era stdlib APIs). CI builds V from
source at the pinned commit in `.github/workflows/ci.yml` (`V_PIN`);
use the same commit locally when in doubt.

## Gates

```sh
# full library + toolkit suite (needs -enable-globals for tls12)
v -Wimpure-v -enable-globals -silent test tls/ tls12/ dtls12/ x509/ \
  pkcs12/ slh_dsa/ rsa/ kat/ mlkem/ toolkit/
# the CLI must also build on all three OSes
v -o ramzara cmd/ramzara
# release binaries: -prod shrinks the CLI ~15% with identical behavior
# (measured 4,557,312 -> 3,847,633 bytes); keep default flags until CI
# proves -prod on the pinned toolchain.
# formatting is a CI gate: run before every commit
v fmt -w <every .v file you touched>
v fmt -l tls/ tls12/ dtls12/ x509/ pkcs12/ slh_dsa/ rsa/ kat/ mlkem/ toolkit/ cmd/
```

Rules: pure V in module code (`-Wimpure-v` clean), verify every fix by
execution, test-adequacy fixes are test-only unless a lens proves a
source bug.

## Origin

This package was extracted from the V project's TLS/PKI stack and is
now maintained independently: `toolkit/`, `cmd/`, and `docs/` are the
package's own layer on top of the ported modules.
Upstream syncs are not planned; fixes and features land here directly
and are recorded in CHANGELOG.md (bump `V_PIN` in CI when the required
toolchain moves).
