# vtls roadmap and goals

## Goal

`vtls` is a pure-V TLS/PKI stack and a practical OpenSSL replacement
for the TLS/PKI subset: connect, serve, issue, verify, convert.
Everything is `-Wimpure-v` clean (no C interop in module code);
every claim is gated by tests, including live OpenSSL interop.

## Where it comes from

Extracted from `vlang/v` PR #32052 (`tls-final` @ `15ba1ef81f`) with
import paths rewritten (`crypto.x509` → `metif12.vtls.x509`, etc.) and
`x.crypto.mlkem` vendored as `mlkem/`. Sync procedure is in
CONTRIBUTING.md. Deliberately left behind: the legacy `net/dtls`
module (superseded by `dtls12`), QUIC test vectors (one fixture
vendored into `tls/testdata` with provenance noted below).

Fixture provenance: `tls/testdata/quiche_p256_handshake_server_cert.pem`
is copied from `vlib/net/quic/testdata/tls13_vectors/` (upstream V repo)
and used only to exercise EC public-key extraction.

## v1 (this repo)

- [x] Library: `tls` (1.3), `tls12` (1.2), `dtls12`, `x509`, `pkcs12`,
  `rsa`, `slh_dsa`, `mlkem`, `kat`, `toolkit`
- [x] CLI: `s_client s_server req x509 verify crl ocsp pkcs12 enc dgst
  rand speed` (full scope)
- [x] C ABI: `c/vtls.h` + `capi/` shim + `c/demo.c`, release artifacts
  (prebuilt libs + header + demo)
- [x] Docs: usage-v, usage-c, openssl-map, goals
- [x] CI: fmt/vet/test matrix + OpenSSL interop + C-lib release
- [x] VPM install verified (`v install --git https://github.com/metif12/vtls`
  resolves `metif12.vtls.*`); version tag `v0.1.0` pushed (triggers the
  C-lib release). Registry search listing is a manual step on
  vpm.vlang.io.

## CI hardening (from the first green-board runs)

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
- CI workflow carries the same stdin-EOF bug class: the interop step's
  bare `openssl s_server ... &` shares the step stdin, which runners
  don't guarantee open (ACCEPT then instant DONE, 0 accepts — flaked
  ubuntu+windows in run8 while the V suite was fully green). Now
  `sleep 30 | openssl s_server ... &` like the in-test wrapper.
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

## v1.1 (next)

- C API: TLS 1.2 + DTLS 1.2 bindings, mTLS parameters, keylog hook.
- `s_client`: interactive TTY mode (today it relays piped stdin).
- `req`: CSRs (`-new`, no `-x509`) and CA signing (`-CA` with a real CA).
- OCSP responder mode (`ocsp -index`, nonce handling).
- Fuzz corpus in CI (short) + nightly long fuzz.

## Non-goals (carried over)

3DES/RC4/export, MD5/SHA-1 chains, TLS < 1.2, ARIA/Camellia/SEED/IDEA,
Ed448, static-RSA key exchange, GOST/SM, full async state machine,
HSM/provider/PKCS#11, assembly acceleration, QUIC/ECH, CMS/S/MIME.
DTLS 1.2 stays anonymous-by-default unless the peer key is pinned.
CBC length-timing residual and socket write-timeout limits are
documented in usage-c.md.
