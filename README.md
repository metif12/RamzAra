# RamzAra — pure-V TLS/PKI stack and OpenSSL replacement

**RamzAra (رمزآرا)** is a Persian compound meaning *one who arranges, creates, or adorns symbols and codes*.

- **ramz (رمز):** Code, cipher, symbol, secret, or encoded meaning.
- **ārā (آرا):** An element meaning adorning, arranging, or embellishing, derived from **ārāstan (آراستن)**, the Persian verb meaning *to adorn, decorate, or put in order*.

Pronounced *ramz-ārā* (/ɾæmz.ɒːˈɾɒː/).

The name evokes the art of giving structure and expression to symbols, patterns, and encoded information. It represents the craft of turning abstract symbols and complex structures into something organized, meaningful, and elegant.

![CI](https://github.com/metif12/RamzAra/actions/workflows/ci.yml/badge.svg)
![license](https://img.shields.io/badge/license-MIT-blue)

> **Renamed:** this repo was previously `metif12/vtls` (module
> `metif12.vtls.*`, binary/API prefix `vtls`). Old GitHub links redirect,
> but reinstall and repoint imports: `v install metif12.ramzara`, then
> `import metif12.ramzara.*`.

Pure-V TLS 1.3, TLS 1.2, DTLS 1.2, x509 PKI, PKCS#12, RSA, SLH-DSA —
plus a `ramzara` CLI. Extracted from
the V project and maintained here as a versioned
[VPM](https://vlang.io) package.

- `-Wimpure-v` clean: no C interop anywhere in module code.
- Every behavior is gated by tests, including live OpenSSL interop.
- What it is not: 3DES/RC4/export, MD5/SHA-1 chains, TLS < 1.2,
  ARIA/Camellia/SEED, Ed448, static-RSA KEX, GOST/SM, QUIC/ECH,
  CMS/S/MIME (see ROADMAP.md).

## Install

```sh
v install metif12.ramzara
```

Requires a V toolchain newer than 0.5.2 (uses `x.crypto.mldsa`-era
stdlib APIs); CI builds V at the pinned commit (see `V_PIN`).

Manual install (or before the registry lists the package):

```sh
git clone https://github.com/metif12/RamzAra ~/.vmodules/metif12/ramzara
```

Note: `v install --git <url>` puts the repo at `~/.vmodules/ramzara`
(flat, no author segment); move it to `~/.vmodules/metif12/ramzara` so
`import metif12.ramzara.*` resolves.

## Use

```v
import metif12.ramzara.tls

mut c := tls.dial('example.com', 443, tls.Config{})!
c.handshake()!
c.write('GET / HTTP/1.0\r\n\r\n'.bytes())!
```

```sh
# issue + serve + fetch
ramzara req -newkey ec:p-256 -keyout key.pem -out cert.pem -subj /CN=localhost
ramzara s_server -accept 4433 -cert cert.pem -key key.pem &
printf hello | ramzara s_client -connect 127.0.0.1:4433 -CAfile cert.pem -brief
```

Guides: [`docs/usage-v.md`](docs/usage-v.md),
[`docs/openssl-map.md`](docs/openssl-map.md),
API: [`docs/api.md`](docs/api.md). Goals: [`ROADMAP.md`](ROADMAP.md).

## Layout

| path | contents |
|---|---|
| `tls/` | TLS 1.3 (client/server, resumption, 0-RTT, mTLS, tickets) |
| `tls12/` | TLS 1.2 standalone (needs `-enable-globals`) |
| `dtls12/` | DTLS 1.2 + ECDHE (anonymous by default; pin peer to authenticate) |
| `x509/` | chain building, EKU/KU/name-constraints, CRL, OCSP, generation |
| `pkcs12/` | PFX parse/generate |
| `rsa/` | RSA keygen, PKCS#1/8 + SPKI codecs, self-signed certs |
| `slh_dsa/` | SLH-DSA, all 12 FIPS 205 sets |
| `mlkem/` | vendored ML-KEM (stdlib newer than 0.5.2 also has it) |
| `kat/` | cross-primitive known-answer tests |
| `toolkit/` | keygen + self-signed certs for the CLI |
| `cmd/ramzara/` | `ramzara` CLI (OpenSSL replacement) |
| `docs/` | usage guides, OpenSSL map |

## Test

```sh
v -Wimpure-v -enable-globals -silent test tls/ tls12/ dtls12/ x509/ \
  pkcs12/ slh_dsa/ rsa/ kat/ mlkem/ toolkit/
```

## License

MIT — see LICENSE (same as the V project it was extracted from).
