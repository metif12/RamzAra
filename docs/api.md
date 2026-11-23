# RamzAra API reference

V library (`import metif12.ramzara.<module>`), C ABI (`c/ramzara.h`),
and CLI surface. Task guides live in `usage-v.md` (V), `usage-c.md`
(C) and `openssl-map.md` (CLI command map); per-module notes in
`tls/README.md`, `x509/README.md`, `mlkem/README.md`.

## V library

### `tls` — TLS 1.3

```v
import metif12.ramzara.tls
```

| item | shape | notes |
|---|---|---|
| `dial` | `dial(host string, port int, cfg Config) !&Conn` | client handshake on demand via `c.handshake()` |
| `listen` | `listen(cfg Config) !&Listener` | binds `127.0.0.1:0`; generates a ticket key when `cfg.ticket_key` is empty |
| `listen_on` | `listen_on(addr string, cfg Config) !&Listener` | binds `addr` (e.g. `127.0.0.1:4433`); the CLI uses this for `-accept` |
| `Listener.accept` | `accept() !&Conn` | runs the server handshake; closes the TCP conn on failure |
| `Listener.close` / `Listener.addr` | | |

`Conn` methods: `handshake()`, `read(mut buf)`, `write(data)`,
`write_string(s)`, `close()`, `shutdown()` (no `close_notify`),
`send_close_notify()`, `rekey()`, `request_client_auth_post()`,
`negotiated_cipher()`, `negotiated_alpn()`, `resumed()`,
`session_state() ?SessionState`, `exporter(label, context, len)`,
`ocsp_response()`, `is_closed()`, `read_timeout()`.

`Config` highlights: `server_name`, `alpn_protocols`, `ca_cert` /
`ca_cert_pem` / `ca_store`, `verify` (default true), `cert` / `key`
(+ `_pem` forms, server side), `client_cert` / `client_key` (mTLS),
`cipher_suites`, `pq_mode`, `ticket_key` / `ticket_keys`,
`resume_from ?SessionState`, `max_early_data` / `early_data` (0-RTT),
`verify_client`, `cert_map` (SNI), `psk_identity` / `psk_key`,
`request_ocsp`, `ocsp_response` (staple). `SessionState` carries
`ticket`, `psk`, `suite`, `created_unix`, `lifetime`, `age_add`,
`max_early_data`.

Timeouts (`tls/nonblock.v`): `dial_with_timeouts(host, port, cfg,
timeouts)`, `dial_async(host, port, tcfg) chan DialResult`
(`result() !&Conn`), `apply_timeouts` / `set_conn_timeouts`,
`conn_read_timeout` / `conn_write_timeout`, `is_timeout(err)`
(`net.err_timed_out_code`).

Suites: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 (server
preference). Groups: X25519, ECDHE P-256/P-384, FFDHE 2048/3072,
pure ML-KEM-768/1024, X25519MLKEM768 hybrid (`pq_mode`).

### `tls12` — TLS 1.2 (standalone, needs `-enable-globals`)

```v
import metif12.ramzara.tls12

mut c := tls12.dial('example.com', 443, tls12.Config{})!
c.handshake()!
```

| item | shape | notes |
|---|---|---|
| `dial` / `accept` | `dial(host, port, cfg) !&Conn`, `accept(tcp, cfg) !&Conn` | |
| `Conn` | `handshake`, `read`, `write`, `close`, `renegotiate` | |
| introspection | `cipher_suite() u16`, `cipher_suite_name()`, `session() Session`, `did_resume() bool`, `uses_ems()`, `uses_etm()` | |
| `Session` | `{ id, master, suite }` | client passes as `Config.resume` to abbreviate |
| `Config` | `server_name`, `skip_verify` (tests), `root_ders` (pinned DER CAs), `cert_der` / `chain_ders` / `key_der` (server, PKCS#8 DER), `cipher_suites`, `resume` | |

Suites: ECDHE RSA/ECDSA with AES-128-GCM, AES-128-CCM8,
AES-128-CBC-SHA256 (`suite_*` consts, `suite_name()`,
`suite_is_supported()`).

### `dtls12` — DTLS 1.2 + ECDHE over UDP

```v
import metif12.ramzara.dtls12

mut c := dtls12.dial('127.0.0.1:4444', dtls12.default_config())!
c.handshake()!
```

Default is **anonymous ECDHE** (passive confidentiality + forward
secrecy, no MITM protection). Pin the peer to authenticate: server
sets `ecdsa_sign_priv` (32-byte P-256 key), client sets
`ecdsa_sign_peer` (65-byte uncompressed point). `enable_cookie: true`
adds stateless HelloVerifyRequest cookies. Retransmit/backoff and
loss simulation (`drop_tx_first_n`, `drop_rx_first_n`) are in
`Config`; `default_config()` fills sane timeouts.

`dial(raddr, cfg)`, `bind(laddr, cfg)`, `listen(laddr, cfg)` →
`Listener.accept() !&Conn`; `Conn` has `handshake()`,
`is_handshake_done()`, `cipher_suite()`, `read`, `write`,
`write_string`, `close()`.

### `x509` — PKI: parse, verify, issue, revoke

```v
import metif12.ramzara.x509
```

- Parse: `parse_pem(text)`, `parse_der(der)`, `Certificate.check_host(name)`.
- Chain: `build_chain(leaf, intermediates, roots)` (longest valid path
  wins) + `verify_chain(chain, VerifyOptions{ hostname, at, crls, ocsp_resp })`
  with EKU/KU, name constraints, path length enforced per edge.
- Issue: `generate_self_signed` / `generate_ca_signed` (ECDSA),
  `..._ed25519`, `..._mldsa`, `..._slh_dsa` families;
  `fresh_serial()` (minimal DER encoding).
- CRL: `parse_crl_pem/der`, `verify_crl`, `make_crl`, `Crl.is_revoked`,
  `load_system_crls()`.
- OCSP: `parse_ocsp_response`, `make_ocsp_response`,
  `verify_ocsp_staple(resp_der, leaf_der, issuer_der)`.

See `x509/README.md` for parser/validation semantics.

### `pkcs12` — PFX parse/generate

```v
import metif12.ramzara.pkcs12

d := pkcs12.decode(data, password)!        // DecodedPfx
out := pkcs12.encode(key_der, certs, password, cfg)! // EncodeConfig
```

### `rsa` — keygen, codecs, self-signed certs

```v
import metif12.ramzara.rsa

key := rsa.generate_key(rsa.KeyGenOptions{ bits: 2048 })!
```

`sign_pss` / `verify_pss`, `sign_pkcs1_v15` / `verify_pkcs1_v15`,
`encrypt` / `decrypt`, PKCS#1/8 + SPKI DER codecs and PEM codecs
(`to_pem_*` / `*_from_pem`), `generate_self_signed(opts, key)`
(UTC-normalized dates, `x509.fresh_serial`). Byte-compatible with the
verification paths in `tls`; never imports `tls`.

### `slh_dsa` — SLH-DSA, all 12 FIPS 205 sets

`keygen(params)`, `sign(msg, ctx, sk)`, `sign_deterministic`,
`verify(msg, sig, ctx, pk)` (+ `keygen_internal`,
`sign_internal`, `verify_internal` for KAT/test use). End-to-end
coverage in `tls` (all `0x0917`–`0x091c` schemes) with loopback tests.

### `mlkem` — ML-KEM (FIPS 203), all three sets

`keygen()` / `encaps(ek)` / `decaps(dk, ct)` (ML-KEM-768) and the
variant-explicit `generate_keypair(variant)`, `encapsulate(pk)`,
`decapsulate(ct, sk)` for `ml_kem_512/768/1024`, plus K-PKE /
polynomial / NTT internals. See `mlkem/README.md`.

### `toolkit` — keygen + self-signed certs for the CLI and C API

```v
import metif12.ramzara.toolkit

g := toolkit.generate_self_signed('ec:p-256', 'localhost', [], 365, false)!
```

`parse_key_type(name)` accepts `rsa[:2048|:3072]`,
`ec:p-256|p-384|p-521`, `ed25519`, `ml-dsa-44|65|87`,
`slh-shake|sha2-<...>`; returns `Generated{ key_pem, cert_pem, cert }`.
`pem_encode(block_type, der)`, `cert_text(cert)` (powers `x509 -text`).

### `kat` — cross-primitive known-answer tests

Provenance-locked vectors (RFC 6979/8017/8439/5869/2202/7748, NIST
GCM/KEM/SLH-DSA vectors, OpenSSL cross-implementation oracles). No
library API; documents what every primitive is pinned against.

## C ABI (`c/ramzara.h`)

Stable, C89-compatible header over `capi/ramzara_c.v`
(`-shared -enable-globals`; Windows link adds
`-Wl,--export-all-symbols`, import lib via `c/ramzara.def`).

| symbol | notes |
|---|---|
| `RamzAraConn *ramzara_dial(host, port, server_name, ca_file, insecure)` | TLS 1.3 + handshake; NULL on failure, see `ramzara_last_error()` |
| `ramzara_read / ramzara_write / ramzara_close` | `0` = clean close, negative = error |
| `ramzara_cipher_name / ramzara_resumed` | suite name into caller buffer; resumption flag |
| `ramzara_listen(port, cert, key)` → `RamzAraListener *` / `ramzara_accept(l)` / `ramzara_listener_close(l)` | binds 127.0.0.1 |
| `ramzara_generate_self_signed(key_type, cn, key_out, cert_out, days)` | mirrors `ramzara req -x509` |
| `ramzara_verify(ca_bundle, leaf_pem, hostname, errbuf, errlen)` | `0` = chain verifies |
| `ramzara_cert_text(cert_pem, out, outlen)` | human-readable summary |
| `ramzara_last_error()` / `ramzara_version()` | thread-local detail / version string |

Limits (v1): TLS 1.3 only over C (V API also has `tls12`, `dtls12`);
no client-certificate (mTLS) parameters yet; all out-params are
caller-owned buffers with explicit lengths (except `last_error` /
`version`, valid until the next call on the same thread).

## CLI (`cmd/ramzara` → `ramzara <command>`)

| command | purpose | key flags |
|---|---|---|
| `s_client` | TLS client | `-connect h:p`, `-servername`, `-CAfile`, `-alpn`, `-tls1_2`, `-insecure`, `-reconnect n`, `-brief`, `-waitms` |
| `s_server` | TLS server | `-accept port`, `-cert`, `-key`, `-Verify [-CAfile]`, `-www`, `-naccept` |
| `req` | key + self-signed | `-newkey type`, `-keyout`, `-out`, `-subj /CN=`, `-dns`, `-days`, `-ca` |
| `x509` | print cert | `-in`, `-text`, `-subject`, `-issuer`, `-dates`, `-fingerprint [-sha1]` |
| `verify` | verify chain | `-CAfile bundle cert`, `-untrusted`, `-hostname`, `-crlfile`, `-ocsp` |
| `crl` | print CRL | `-in`, `-text` |
| `ocsp` | print/check staple | `-in`, `-text`, `-leaf`, `-issuer` |
| `pkcs12` | parse / create PFX | `-in -passin [-out]`; `-export -inkey -in [-certfile] -out -passout [-pbe aes256\|aes128\|3des\|rc2] [-name]` |
| `enc` | AEAD encrypt/decrypt | `-aes-128-gcm\|-aes-256-gcm\|-chacha20-poly1305 -e\|-d -K hex -iv hex [-aad] [-in] [-out]` |
| `dgst` | hash | `[-sha256\|-sha512\|-sha1] [file]` (stdin default) |
| `rand` | random bytes | `-hex\|-base64 n` |
| `speed` | benchmark | `[algos...] [-seconds n]` |

Full OpenSSL correspondence: `docs/openssl-map.md`.
