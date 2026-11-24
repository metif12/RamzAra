# Changelog

## Unreleased — PKI: PKCS#10 CSRs

- New: `x509.generate_csr` / `parse_csr_pem` / `parse_csr_der` /
  `verify_self`, `x509.encode_spki`, `toolkit.generate_csr`,
  `ramzara req -new` — CSRs for every key family (ECDSA, Ed25519,
  ML-DSA, SLH-DSA, RSA), self-signature verified at generation and
  cross-checked against `openssl req` both directions (including
  `openssl x509 -req` CA signing of our CSRs).
- Internal: `x509.parse_spki` factored out of certificate parsing so
  certs and CSRs accept exactly the same key shapes.

## v0.1.0 (unreleased)

Initial standalone release, extracted from the V project and
maintained here as a versioned package.

- Library: `tls` (TLS 1.3), `tls12` (TLS 1.2), `dtls12`, `x509`,
  `pkcs12`, `rsa`, `slh_dsa`, vendored `mlkem`, `kat`.
- Import paths rewritten to `metif12.ramzara.*`; testdata paths moved to
  `@VMODROOT`-relative package dirs; one QUIC EC fixture vendored into
  `tls/testdata` for the key-extraction test.
- New: `toolkit/` (keygen + self-signed certs for every family, TLS
  loopback-proven), `cmd/ramzara/` CLI (s_client, s_server, req, x509,
  verify, crl, ocsp, pkcs12, enc, dgst, rand, speed).
- New: `tls.listen_on(addr, cfg)` (the vendored `listen` binds
  loopback:0 only); `Conn.send_close_notify()` for clean EOF with
  strict peers (OpenSSL errors on a bare FIN).
- Fork fixes (deviations from upstream, all verified by execution):
  `rsa` validity dates are UTC-normalized like `x509` (wrong on
  non-UTC boxes); `Config.ca_cert`/`ca_cert_pem` are honored in trust
  resolution (documented upstream but unwired); SEC1 output carries the
  mandatory version INTEGER 1 (OpenSSL rejects the scalar there);
  SEC1 P-256 curve OID bytes corrected to 1.2.840.10045.3.1.7
  (OpenSSL 3.5 refused our keys as "unsupported"); serial numbers use
  minimal DER encoding via `normalize_serial_bytes`/`fresh_serial`
  (strip-then-mask failed our own parser ~1/500 certs) — the serial
  fix is also carried upstream, the SEC1 items are toolkit-only.
  (Follow-up: the standalone `rsa/cert_gen.v` copy kept the old
  strip-then-mask and now calls `x509.fresh_serial` instead.)
- CI: fmt gate, 3-OS test matrix, OpenSSL interop.
- C support removed (was: `capi/` + `c/ramzara.h` C ABI with demo
  client, `c/generated/` single-file C form, `c-api` CI job, C-lib
  release workflow). The package is pure V (library + CLI) only;
  no C sources, headers, or artifacts remain.
- Project renamed `vtls` → `RamzAra`: module/binary `ramzara`
  (`metif12.ramzara.*`, `v install metif12.ramzara`), CLI `cmd/ramzara/`,
  C API `ramzara_*` in `c/ramzara.h` / `c/ramzara.def` (`RamzAraConn`,
  `RamzAraListener`), libraries `libramzara.*` / `ramzara.dll`.
  No `vtls`-spelled symbols, paths, or install locations remain.
