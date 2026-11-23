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
# (measured 4,557,312 -> 3,847,633 bytes); the C shared libs stay on the
# plain flags in c-lib-release.yml because -prod interacts with the
# -Wimpure-v backend gate there — re-measure before changing that.
# formatting is a CI gate: run before every commit
v fmt -w <every .v file you touched>
v fmt -l tls/ tls12/ dtls12/ x509/ pkcs12/ slh_dsa/ rsa/ kat/ mlkem/ toolkit/ cmd/ capi/
```

Rules: pure V in module code (`-Wimpure-v` clean), verify every fix by
execution, test-adequacy fixes are test-only unless a lens proves a
source bug, and never widen `capi/` without updating `c/ramzara.h`.

## Syncing from vlang/v#32052

1. In a vlang/v checkout on the `tls-final` branch (or newer):
   `git archive HEAD <paths>` for `vlib/net/tls{,12}`, `vlib/net/dtls12`,
   `vlib/crypto/{x509,pkcs12,slh_dsa,rsa,kat_test.v}`,
   `vlib/x/crypto/mlkem`.
2. Move them onto `tls/ tls12/ dtls12/ x509/ pkcs12/ slh_dsa/ rsa/
   kat/ mlkem/` and re-apply the import rewrite
   (`crypto.x509` → `metif12.ramzara.x509`, `net.tls` → `metif12.ramzara.tls`,
   `net.tls12`, `net.dtls12`, `crypto.rsa/slh_dsa/pkcs12`,
   `x.crypto.mlkem` → `metif12.ramzara.mlkem` on `^import` lines;
   `@VEXEROOT + 'vlib/...` → `@VMODROOT + '<pkg>/...`).
3. Keep `toolkit/`, `cmd/`, `capi/`, `c/`, `docs/` as the package's own
   layer; re-run the full gate plus the CLI and C builds.
4. Record the new base in CHANGELOG.md and bump `V_PIN` in CI.
