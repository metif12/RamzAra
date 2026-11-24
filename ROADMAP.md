# RamzAra roadmap and goals

## Goal

`RamzAra` is a pure-V TLS/PKI stack and a practical OpenSSL replacement
for the TLS/PKI subset: connect, serve, issue, verify, convert.
Everything is `-Wimpure-v` clean (no C interop in module code);
every claim is gated by tests, including live OpenSSL interop.

## Where it comes from

Extracted from the V project with
import paths rewritten (`crypto.x509` → `metif12.ramzara.x509`, etc.) and
`x.crypto.mlkem` vendored as `mlkem/`. Deliberately left behind: the legacy
`net/dtls` module (superseded by `dtls12`) and QUIC test vectors (one
fixture vendored into `tls/testdata` with provenance noted below).

In November 2026 the project was renamed `vtls` → `RamzAra`
(module/binary `ramzara`, GitHub `metif12/RamzAra`). The old GitHub URL redirects; code references were
renamed without behavior change (see CHANGELOG.md).

Fixture provenance: `tls/testdata/quiche_p256_handshake_server_cert.pem`
is copied from the upstream V repo's QUIC test vectors
and used only to exercise EC public-key extraction.

## v1 (shipped, currently v0.1.2; trunk holds rename + docs + opt pass 1)

- [x] Library: `tls` (1.3), `tls12` (1.2), `dtls12`, `x509`, `pkcs12`,
  `rsa`, `slh_dsa`, `mlkem`, `kat`, `toolkit`
- [x] CLI: `s_client s_server req x509 verify crl ocsp pkcs12 enc dgst
  rand speed` (full scope)
- [x] C ABI removed: was `c/ramzara.h` + `capi/` shim + `c/demo.c`
  with prebuilt-lib release artifacts; the package is pure V now
  (library + CLI), no C sources or artifacts remain
- [x] Docs: usage-v, openssl-map, api, module READMEs, goals
- [x] CI: fmt/vet/test matrix + OpenSSL interop
  (concurrency cancel, timeouts, cache restore-keys, `.git`-free
  module copies, artifact gitignore — see appendix B)
- [x] Rename `vtls` → `RamzAra` shipped end to end: code, docs, file
  names, GitHub repo + metadata, README notice (old URL redirects)
- [x] VPM install verified (`v install --git https://github.com/metif12/RamzAra`
  resolves `metif12.ramzara.*`); tags `v0.1.0`–`v0.1.2` pushed.
  Registry search listing remains a manual step on vpm.vlang.io.

## v1.1 (next)

- Cache hot paths without behavior change: per-epoch AEAD objects
  (record data path), parsed system roots/CRLs (handshake path),
  FFDHE/P-256 curve params (big-int setup). Each lands only with
  before/after test proof.
- CI: split fast/slow test jobs (deterministic units vs loopback/PQC),
  so the `VJOBS=2` handshake throttle stops serializing everything.
- Re-measure `-prod` for CLI release binaries on the pinned toolchain
  (locally verified at −15% size; left on default flags until CI proves it).
- Leak gate `tls/leak_test.v` stays green: N verified loopbacks, RSS
  must not grow (Linux-only; skips elsewhere). Proven both directions
  on the pinned toolchain (passes on GC; fails without it at ~2.5 MiB
  leaked per RSA session: 101008 KiB over 40 sessions). Full `-gc none`
  stays out of scope: every allocation on a handshake path would need
  freeing, including inside the V standard library.
- `s_client`: interactive TTY mode (today it relays piped stdin).
- `req`: CSRs (`-new`, no `-x509`) and CA signing (`-CA` with a real CA).
- OCSP responder mode (`ocsp -index`, nonce handling).
- Fuzz corpus in CI (short) + nightly long fuzz.
- VPM registry search listing (manual step).

## Non-goals (carried over)

3DES/RC4/export, MD5/SHA-1 chains, TLS < 1.2, ARIA/Camellia/SEED/IDEA,
Ed448, static-RSA key exchange, GOST/SM, full async state machine,
HSM/provider/PKCS#11, assembly acceleration, QUIC/ECH, CMS/S/MIME,
C ABI / shared-library distribution (removed; pure V library + CLI).
DTLS 1.2 stays anonymous-by-default unless the peer key is pinned.
CBC length-timing residual and socket write-timeout limits are
documented in `docs/usage-v.md`.

## Appendix A: CI hardening log

Recorded during the first green-board runs, before the rename. Names
below are preserved verbatim as written at the time (`vtls` = today's
`ramzara`, `Vtls` = today's `RamzAra`); only the tooling lessons carry
forward.

- `.gitignore` must not shadow source dirs: a bare `vtls` pattern
  silently dropped `cmd/vtls/` from every push. Anchor binary patterns
  (`/vtls`, `/vtls.exe`).
- Build pinned V outside the checkout (`~/vlang-build`, `VBIN` env);
  copying the workspace into `.vmodules` tripped over dangling
  thirdparty symlinks (macOS `cp`).
- `-shared` builds need `-enable-globals` (capi uses `__global`).
- Windows `-shared` emits no named exports with GCC; link with
  `-Wl,--export-all-symbols` and verify names via `objdump -p`.
  `c/vtls.def` + `dlltool` cover MSVC import-lib creation.
- Every test failure must print its cause: bare `panic('gen')` cost
  a full round-trip to diagnose. Propagate `${err}` everywhere.
- `v install --git <url>` installs flat (`~/.vmodules/<repo>`);
  `import metif12.vtls.*` needs the nested layout — documented in
  README; registry listing remains the preferred path.
- Serial numbers: strip-then-mask produced a redundant leading zero
  whenever the first random byte was exactly 0x80 (~1/256 draws);
  the parser rightly rejects that shape, so issuance failed its own
  round-trip about once per 500 certs (one Windows CI hit). Fix:
  `normalize_serial_bytes` strips zeros then *prepends* a zero byte
  when the top bit is set; `test_pki_generate_serial_minimal_encoding`
  locks vectors plus a 64-draw property loop.
- SEC1 keys: the hardcoded P-256 curve OID was wrong (1.3.132 prefix
  instead of 1.2.840.10045.3.1.7), so OpenSSL 3.5 refused our `k.pem`
  with "unsupported" while our own loader (which skips the OID) was
  happy. Fixed bytes verified with `openssl pkey` + a live
  `s_server`/`s_client` handshake. P-384/P-521 prefixes were correct.
- Windows Git bash rewrites `/CN=...` to a path (MSYS conversion),
  which broke `req -subj /CN=localhost` only on that runner.
  Fix: `MSYS_NO_PATHCONV: 1` on the interop job.
- Load flakes, verdict reached: the rerun cleared the `x509`
  crosscheck `gen` and toolkit ecdsa failures (both pass locally
  under pinned V too), while slh loopback timeouts recurred on
  windows/macos under load — root-caused to the pinned toolchain's
  30s default socket read timeout vs slow-variant SLH-DSA signs in
  non-prod builds (always the slow `*s` sets). Fix: 120s handshake
  bound in `test_slh_loopback` plus `VJOBS=2` for general headroom.
- Root-caused the ubuntu+macos `tls12` openssl-interop ECONNRESET:
  OpenSSL 3.x `s_server` quits on stdin EOF, and `os.exec` inherits
  the closed harness stdin — the server accept-then-quits instantly
  (0 accepts, exit 0) before our ClientHello arrives; 4.1 stays up,
  which is why it passed locally. Reproduced locally against
  OpenSSL 3.0 (MITM proxy proved the server EOF'd before our flight
  arrived; holding stdin open made the same handshake succeed).
  Fix (`s_server_cmd`): Unix spawns via `sh -c 'sleep 30 | exec ...'`
  (pipe holds stdin open; proven: `&`-background form is a no-op that
  still quits exit=0, `|` form stays up and completes HS+appdata vs
  OpenSSL 3.0); Windows spawns direct (runners stay green with inherited
  stdin; MSYS2/native shell pipes misbehave there). The s_server
  exit/output capture stays as permanent diagnostics.
- Mirror image on the reverse direction (`test_openssl_s_client_server`):
  a bare `echo ... | s_client` closes s_client's stdin before our
  server's echo arrives, and 3.x s_client quits on that EOF (handshake
  prints, echo missing — the run6 ubuntu/macos failure). Proven vs 3.0
  with a 3s-delayed echo server (EOF form: 0 echoes; hold-open form: 1).
  Unix `run_s_client` now uses `(echo ping-tls12-ssl; sleep 10) | ...`;
  Windows unchanged (green in CI).
- Serial follow-up: the standalone `rsa/cert_gen.v` kept the old
  strip-then-mask (missed in the first port) and flaked the same way
  (ubuntu toolkit RSA round-trip + both CLI interop steps in one run —
  all RSA-cert paths). Now calls `x509.fresh_serial` (`pub` since);
  CRL-number path verified safe (forces non-zero). Break-fix: old
  logic 3/2000 non-minimal, new 0/2000; 15/15 RSA round-trips.
- Release workflow (`c-lib-release.yml`, runs on `v*` tags): the v0.1.1
  tag-push run failed only at `Upload artifact` on Windows —
  `~/.vmodules/...` outputs sit outside the workspace root and break
  upload-artifact's rootDirectory computation (ubuntu passed the same
  mix by LCA luck). Fix: emit `-o $GITHUB_WORKSPACE/<lib>`, verify and
  link against the workspace copy, upload workspace-relative paths
  (same pattern as the `vtls-bin` CLI build). macOS never failed on
  its own (canceled by fail-fast); v0.1.2 re-runs everything.
- CI workflow carries the same stdin-EOF bug class: the interop step's
  bare `openssl s_server ... &` shares the step stdin, which runners
  don't guarantee open (ACCEPT then instant DONE, 0 accepts — flaked
  ubuntu+windows in run8 while the V suite was fully green). Tried
  `sleep 30 |` first: holds Unix stdin open (proven vs 3.0) but makes
  Windows Git-bash openssl deaf for 30s, 0 accepts (MSYS2/native pipe
  boundary — reproduced locally with Git's own 3.5.6). Closed stdin
  (`<&-`) serves fine on both (proven vs 3.0 and 3.5.6 with real
  handshakes), so the step closes it outright. The in-test wrappers
  keep their Unix-pipe / Windows-direct split (green as-is).
- Compile every touched `_test.v` before pushing: an illegal `mut`
  on a `chan` parameter broke the whole matrix for a full cycle
  (channels are handles; pass by value even for `try_pop`).
- The CLI `s_client` interop step must pass `-servername localhost`:
  our client verifies the hostname against the dial host (like Go)
  while `openssl s_client` skips that check without
  `-verify_hostname`; connecting to 127.0.0.1 with a localhost cert
  otherwise fails with `error_chain_untrusted`.
- SLH-DSA loopback vs the pinned toolchain: every `TcpConn` there
  carries a 30s default read timeout, and slow-variant signs in
  non-prod builds exceed it under CI contention (windows 0919 twice,
  macos 0913 once — always the slow `*s` sets, never logic).
  `test_slh_loopback` now dials with a 120s handshake bound;
  `VJOBS=2` stays for general headroom.
- Windows `Build pinned V` flaked once (clone reported 100% yet the
  next `cd` found nothing; the sibling test job built fine): the
  clone step now wipes the target first and fails loudly with a
  listing, the build step re-clones when the checkout is absent,
  and the cache key carries a `-v1` suffix to isolate layout
  changes.

## Appendix B: optimization log (pass 1, post-rename)

Rule for this log: no behavior change without test proof; no delivery
of what cannot be verified on the pinned toolchain.

Landed and proven:

- `tls12/ccm.v`: one AES key expansion per record (cipher threaded
  through CBC-MAC/CTR/tag-mask) instead of one per 16-byte block
  (~2000 expansions/record before). Proven by `tls12` suite
  (35 s, incl. CCM KAT + loopback).
- `tls/client.v`: deleted dead `sg_tmp` ClientHello-groups recompute.
- `mlkem/mlkem.v`: `sample_cbd_eta` collapses four repeated
  eta dispatches. Proven by `mlkem` KAT suite.
- `pkcs12`: `hmac.equal` called directly; `verify_hmac` wrapper and
  the now-unused import removed. Proven by `pkcs12` suite.
- CI: `concurrency.cancel-in-progress`, per-job `timeout-minutes`,
  cache `restore-keys`, `.git` excluded from `.vmodules` copies,
  artifact names in `.gitignore`. Zero job-structure change, so nothing
  to re-prove beyond the next green board.
- Measured baselines: CLI 4,557,312 B default vs 3,847,633 B with
  `-prod` (−15.6%, behavior identical). CLI `-prod` guidance is in
  CONTRIBUTING.md.

Deliberately deferred (with reason):

- Per-epoch AEAD caching, roots/CRL caching, P-256/FFDHE param
  caching, transcript/flight copy reduction: all real wins from the
  audit, each needs its module suite green before/after. Queued as
  one-item-per-commit work.
- Test sharding (fast units vs slow loopbacks): YAML restructure,
  only provable by pushing. Queued.
- `pub`-surface shrinking (`mlkem` internals, `dtls12` timers):
  API break for downstream importers; decide with a version bump.
