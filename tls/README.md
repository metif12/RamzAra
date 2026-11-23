# tls

Pure-V TLS 1.3 (RFC 8446) for TCP connections, the core of RamzAra.

```v
import metif12.ramzara.tls

mut c := tls.dial('example.com', 443, tls.Config{})!
c.handshake()!
c.write('GET / HTTP/1.0\r\n\r\n'.bytes())!
```

No C interop in module code (`-Wimpure-v` clean). Every behavior is
gated by tests, including live OpenSSL interop.

## Status

TLS 1.3 only. ECDSA P-256/P-384/P-521, Ed25519, ML-DSA-44/65/87 and RSA
leaves, with direct-root chain verification. Trust roots resolve on
every OS: explicit `ca_store`/`ca_cert`, then `SSL_CERT_FILE` /
`SSL_CERT_DIR`, then Unix bundle paths, then the embedded Mozilla
bundle (`cacert.pem`, also used on Windows). X25519, ECDHE P-256/P-384,
FFDHE 2048/3072, pure ML-KEM-768/1024 and hybrid X25519+ML-KEM-768 key
exchange (`pq_mode`). AES-128-GCM, AES-256-GCM (SHA-384 schedule) and
ChaCha20-Poly1305 record protection, negotiated by server preference.
Stateless session tickets with `psk_dhe_ke` resumption (ticket plus
external-PSK identities) and mTLS (`verify_client` + `client_cert` /
`client_key`), plus KeyUpdate, HelloRetryRequest, ALPN selection, SNI
certificates, post-handshake auth, exporters, SSLKEYLOGFILE, ticket
rotation, record fragmentation and OCSP stapling (transport); TLS 1.2
and DTLS live in the sibling `tls12` / `dtls12` modules.

## Client

```v
mut c := tls.dial(host, 443, tls.Config{
	server_name: 'example.com' // empty means the dialed host
	// ca_cert: '/path/bundle.pem', // or empty for platform roots
})!
c.handshake()!
```

Key `Config` fields: `server_name`, `alpn_protocols`, `ca_cert` /
`ca_cert_pem`, `ca_store`, `verify` (default true), `cipher_suites`
(default AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM),
`resume_from` / `SessionState` (resumption), `max_early_data` /
`early_data` (0-RTT), `client_cert` / `client_key` (mTLS),
`psk_identity` / `psk_key` (external PSK), `request_ocsp`,
`ticket_keys`, `ocsp_response`.

After the handshake: `c.negotiated_cipher()`,
`c.negotiated_alpn()`, `c.resumed()`, `c.session_state()`,
`c.exporter(label, context, len)`, `c.ocsp_response()`,
`c.rekey()`, `c.send_close_notify()`, `c.close()`.

## Server

```v
mut l := tls.listen(tls.Config{ cert: 'server.pem', key: 'key.pem' })!
for {
	mut conn := l.accept()!
	spawn handle(mut conn)
}
```

`cert` / `key` accept a file path or inline PEM; `cert_map` selects
credentials by SNI (unknown names fail closed). `listen_on(addr, cfg)`
binds a specific address (the CLI uses it for `-accept`).

## Session resumption and 0-RTT

The server sends one `NewSessionTicket` per connection: an
AES-256-GCM box holding the resumption master secret, so servers stay
stateless (the ticket key is generated per `Listener`). The client
captures the ticket on its next `read()` and passes it as
`Config.resume_from` on the next dial; a valid ticket resumes with
`psk_dhe_ke` and no certificate flight (`Conn.resumed()` reports it,
`Conn.session_state()` returns the ticket). Bad boxes, wrong suites,
stale age or bad binders fall back to a full handshake.

0-RTT: set `max_early_data` on both sides and `early_data` on the
client (resumption only; tampered records abort the handshake; a
server that rejects early data discards it and continues).

## Mutual TLS

Set `Config.verify_client` on the server and `Config.client_cert` /
`client_key` (PEM paths or bytes) on the client. Client certificates
verify against `ca_store` / system roots when `verify_chain` is set.
No `CertificateRequest` is sent on a resumed (PSK) handshake: the
ticket authenticates the peer. Post-handshake auth:
`Conn.request_client_auth_post()`.

## Timeouts and async I/O

Blocking by default. `nonblock.v` adds opt-in timeouts without
changing any existing API:

- `dial_with_timeouts(host, port, cfg, timeouts)` dials, handshakes and
  applies steady-state timeouts, closing the half-open connection on
  any failure. Timeout failures carry `net.err_timed_out_code`; use
  `is_timeout(err)` to detect them. The legacy
  `Conn.set_read_timeout` remains a no-op: use `apply_timeouts` /
  `set_conn_timeouts` and the `conn_read_timeout` /
  `conn_write_timeout` getters instead.
- `dial_async(host, port, tcfg)` runs the same dial in the background
  and delivers exactly one `DialResult` on the returned buffered
  channel.

## Protocol features (RFC 8446)

Beyond the v1 baseline this stack implements:

- KeyUpdate: `Conn.rekey()` rotates the sending traffic secret and
  sends `update_not_requested`. Receiving a KeyUpdate rotates the
  read secret; `update_requested` is answered with our own update.
- HelloRetryRequest: full cookie-less flight on both sides with the
  `message_hash` transcript. The server retries for its
  most-preferred group when the client shared none of its groups.
- ALPN: the server selects its first overlap from
  `Config.alpn_protocols`; `Conn.negotiated_alpn()` exposes it.
- SNI: `Config.cert_map` maps hostnames to credentials; the server
  selects on `server_name`, else the default credential (fail closed).
- External PSK: `Config.psk_identity` / `psk_key` is offered as an
  extra `psk_dhe_ke` identity; the server matches bytes in constant
  time and verifies that identity's binder.
- Post-handshake auth: `Conn.request_client_auth_post()` sends a
  post-handshake CertificateRequest; the client answers automatically
  on its next read. Traffic keys never change.
- Exporters: `Conn.exporter(label, context, len)` derives from the
  exporter master secret stored at handshake completion.
- SSLKEYLOGFILE: when set, `CLIENT_RANDOM <client_random_hex>
  <master_secret_hex>` lines are appended at handshake completion
  (best-effort, never fails the handshake). The CLI does not expose
  this; the library honors the environment variable directly.
- Ticket rotation: `Config.ticket_keys` seals with `[0]` and tries
  every key on open; `save_ticket_keys` / `load_ticket_keys`
  persist the raw 32-byte concat file (0600 where the OS allows).
- Fragmentation: handshake flights over 2^14 are chunked into
  multiple records on send and reassembled on receive (needed for
  large SLH-DSA flights); small flights keep the single-record fast
  path.
- OCSP: `Config.ocsp_response` (file or PEM bytes, opaque) is
  stapled as CertificateStatus when the client offers
  `status_request`; `Conn.ocsp_response()` returns the raw bytes.
  Transport only — verification lives in `x509.verify_ocsp_staple`.
- Defaults stay wire-identical: no new extensions are offered unless
  configured (the client always offers `status_request` so servers
  with a staple configured can answer; it is ignored otherwise).

## Scope and limitations (accepted non-goals)

- RSA *key generation* lives in the `rsa` module; test fixtures stay
  in `testdata/`.
- CCM suites (0x1304/0x1305) are not negotiated: no CCM primitive
  exists in the stdlib and no major peer offers them.
- Chain building verifies the leaf against roots via `x509`; the
  longest valid path wins (see `x509/README.md`).
- Signature hashes follow the algorithm OID exactly (no SHA-1/MD5
  anywhere); ML-DSA signs the raw TBS/content bytes with no pre-hash.

## Trust roots (`cacert.pem`)

`cacert.pem` is the Mozilla CA bundle as distributed by curl
(`https://curl.se/ca/cacert.pem`, MPL-2.0, extracted from Mozilla's
`certdata.txt`; this snapshot is dated 2026-11-05). It is embedded via
`$embed_file` and used as the last-resort trust source, which is what
makes default chain verification work on Windows and macOS with zero
C interop. To refresh it, download the current bundle over TLS,
confirm all 118+ certificates parse (`test_certstore_embedded_bundle`
pins the count — bump it deliberately), and re-run the `x509` and
`tls` suites.

## Fuzz corpus (`testdata/fuzz`)

Deterministic seeds for `tls/fuzz_test.v`
(`test_fuzz_corpus_no_panic`); see `testdata/fuzz/README.md`. Every
seed is exercised verbatim (must parse) and under single-byte
mutations (must fail closed, never panic).
