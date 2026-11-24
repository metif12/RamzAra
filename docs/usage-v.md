# RamzAra usage guide (V)

Full symbol reference: [`api.md`](api.md).

Install: `v install metif12.ramzara`, then `import metif12.ramzara.tls`
(or `tls12`, `dtls12`, `x509`, `pkcs12`, `rsa`, `slh_dsa`, `toolkit`).
Requires a V toolchain newer than 0.5.2 (needs `x.crypto.mlkem` in
stdlib); CI pins the exact commit.

## TLS 1.3 client

```v
import metif12.ramzara.tls

mut c := tls.dial('example.com', 443, tls.Config{
	server_name: 'example.com', // empty means the dialed host
	// ca_cert: '/path/bundle.pem', // or leave empty for platform roots
})!
c.handshake()!
c.write('GET / HTTP/1.0\r\n\r\n'.bytes())!
mut buf := []u8{len: 4096}
n := c.read(mut buf)!
println(buf[..n].bytestr())
c.close()!
```

Notes:

- `server_name` defaults to the dialed host when empty. Literal IPs never
  go into SNI (RFC 6066 section 3) and verify against IP SANs.
- Trust roots, in order: `Config.ca_store` / `ca_cert` / `ca_cert_pem`,
  `SSL_CERT_FILE`, `SSL_CERT_DIR`, Unix bundle paths, embedded Mozilla
  bundle (works on every OS, including Windows via the system store).
- `c.negotiated_cipher()`, `c.negotiated_alpn()`, `c.resumed()` report the
  session. `c.session_state()` + `Config.resume_from` resume it
  (`psk_dhe_ke`, single-use server tickets, replay cache).
- 0-RTT: set `max_early_data` on both sides and `early_data` on the client
  (resumption only; tampered records abort).
- mTLS: server sets `verify_client: true`; client sets `client_cert` /
  `client_key`. Post-handshake auth: `c.request_client_auth_post()`.
- Rekey mid-connection: `c.rekey()`. Traffic keying: `c.exporter(...)`.
- OCSP staples are opt-in: `Config{ request_ocsp: true }`, then read
  `c.ocsp_response()` and check it with `x509.verify_ocsp_staple`.
- Cipher default is server preference
  `[AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM]`; override with
  `cipher_suites`. PQ: `pq_mode: .hybrid_require` forces X25519MLKEM768.

## TLS 1.3 server

```v
mut l := tls.listen(tls.Config{ cert: 'server.pem', key: 'key.pem' })!
for {
	mut conn := l.accept()!
	spawn handle(mut conn)
}
```

`cert`/`key` accept a file path or inline PEM. `cert_map` selects
credentials by SNI (unknown names fail closed). `listen_on(addr, cfg)`
binds a specific address (the CLI uses it for `-accept`).

## TLS 1.2 (`tls12`)

Standalone module, no shared code with `tls`:

```v
import metif12.ramzara.tls12

mut c := tls12.dial('example.com', 443, tls12.Config{
	server_name: 'example.com', // empty means the dialed host
	root_ders:   roots,         // pinned DER CAs, or skip_verify: true
})!
c.handshake()!
println(c.cipher_suite_name()) // + c.did_resume() c.uses_ems() c.uses_etm()
```

Needs `-enable-globals` (in-memory session cache). Session resumption via
`Config.resume` + `Session`. Server side: `tls12.accept(tcp, cfg)` with
`cert_der`/`chain_ders`/`key_der` (PKCS#8 DER, RSA or P-256).

## DTLS 1.2 (`dtls12`)

```v
import metif12.ramzara.dtls12

mut c := dtls12.dial('127.0.0.1:4444', dtls12.default_config())!
c.handshake()!
```

Default is anonymous ECDHE (passive confidentiality + forward secrecy,
**no MITM protection**). Pin the peer to authenticate:
server sets `ecdsa_sign_priv` (32-byte P-256 key), client sets
`ecdsa_sign_peer` (65-byte uncompressed point). `enable_cookie: true`
adds stateless HelloVerifyRequest cookies. Loss simulation for tests:
`drop_tx_first_n` / `drop_rx_first_n`.

## PKI (`x509`)

```v
import metif12.ramzara.x509

leaf := x509.parse_pem(text)!
chain := x509.build_chain(leaf, intermediates, roots)!
x509.verify_chain(chain, x509.VerifyOptions{
	hostname: 'example.com',
	at:       time.now(),
	crls:     crls,        // optional
	ocsp_resp: staple,     // optional
})!
```

Generation (`generate_self_signed`, `generate_ca_signed`,
`generate_self_signed_ed25519/mldsa/slh_dsa`, `..._ca_signed_...`),
CRLs (`make_crl`, `parse_crl_pem/der`, `verify_crl`,
`is_revoked`, `load_system_crls`), OCSP (`make_ocsp_response`,
`parse_ocsp_response`, `verify_ocsp_staple`). Name constraints,
EKU/KU, and path length are enforced per edge; the longest valid path
wins; expiry of any chain certificate reports expired.

## PKCS#12, RSA, SLH-DSA, toolkit

- `pkcs12.decode(data, password)` / `pkcs12.encode(key_der, certs,
  password, cfg)`.
- `rsa.generate_key(KeyGenOptions{ bits: 2048 })`, PKCS#1/8 + SPKI
  codecs, self-signed certs.
- `slh_dsa.keygen(params)` for all 12 FIPS 205 sets.
- `toolkit.generate_self_signed(key_type, cn, dns, days, is_ca)`
  powers the CLI; `toolkit.cert_text(cert)` renders it.

## Limits

- Accepted residual: CBC length-timing in the TLS 1.2/CBC path.
- Socket-level write timeouts need a V standard library socket change
  upstream (`Conn.set_read_timeout` stays a no-op placeholder; use
  `apply_timeouts` / `set_conn_timeouts`).
