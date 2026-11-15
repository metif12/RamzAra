# Changelog

## v0.1.0 (unreleased)

Initial standalone release, extracted from `vlang/v` PR #32052
(`tls-final` @ `15ba1ef81f`).

- Library: `tls` (TLS 1.3), `tls12` (TLS 1.2), `dtls12`, `x509`,
  `pkcs12`, `rsa`, `slh_dsa`, vendored `mlkem`, `kat`.
- Import paths rewritten to `metif12.vtls.*`; testdata paths moved to
  `@VMODROOT`-relative package dirs; one QUIC EC fixture vendored into
  `tls/testdata` for the key-extraction test.
- New: `toolkit/` (keygen + self-signed certs for every family, TLS
  loopback-proven), `cmd/vtls/` CLI (s_client, s_server, req, x509,
  verify, crl, ocsp, pkcs12, enc, dgst, rand, speed), `capi/` + `c/vtls.h`
  C ABI with demo client.
- New: `tls.listen_on(addr, cfg)` (the vendored `listen` binds
  loopback:0 only); `Conn.send_close_notify()` for clean EOF with
  strict peers (OpenSSL errors on a bare FIN).
- Fork fixes (deviations from upstream, all verified by execution):
  `rsa` validity dates are UTC-normalized like `x509` (wrong on
  non-UTC boxes); `Config.ca_cert`/`ca_cert_pem` are honored in trust
  resolution (documented upstream but unwired); SEC1 output carries the
  mandatory version INTEGER 1 (OpenSSL rejects the scalar there).
- CI: fmt gate, 3-OS test matrix, OpenSSL interop, C-lib release.
