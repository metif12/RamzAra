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
- [ ] VPM publish (`v install metif12.vtls`) + version tag `v0.1.0`

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
