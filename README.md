# vtls — pure-V TLS/PKI stack and OpenSSL replacement

![CI](https://github.com/metif12/vtls/actions/workflows/ci.yml/badge.svg)
![license](https://img.shields.io/badge/license-MIT-blue)

Pure-V TLS 1.3, TLS 1.2, DTLS 1.2, x509 PKI, PKCS#12, RSA, SLH-DSA —
plus a `vtls` CLI and a stable C library. Extracted from
[`vlang/v` PR #32052](https://github.com/vlang/v/pull/32052)
(`tls-final` @ `15ba1ef81f`) and maintained here as a versioned
[VPM](https://vlang.io) package.

- `-Wimpure-v` clean: no C interop anywhere in module code.
- Every behavior is gated by tests, including live OpenSSL interop.
- What it is not: 3DES/RC4/export, MD5/SHA-1 chains, TLS < 1.2,
  ARIA/Camellia/SEED, Ed448, static-RSA KEX, GOST/SM, QUIC/ECH,
  CMS/S/MIME (see ROADMAP.md).

## Install

```sh
v install metif12.vtls
```

Requires a V toolchain newer than 0.5.2 (uses `x.crypto.mldsa`-era
stdlib APIs); CI builds V at the pinned commit (see `V_PIN`).

## Use

```v
import metif12.vtls.tls

mut c := tls.dial('example.com', 443, tls.Config{})!
c.handshake()!
c.write('GET / HTTP/1.0\r\n\r\n'.bytes())!
```

```sh
# issue + serve + fetch
vtls req -newkey ec:p-256 -keyout key.pem -out cert.pem -subj /CN=localhost
vtls s_server -accept 4433 -cert cert.pem -key key.pem &
printf hello | vtls s_client -connect 127.0.0.1:4433 -CAfile cert.pem -brief
```

```c
#include "vtls.h"
VtlsConn *c = vtls_dial("example.com", 443, NULL, NULL, 0);
```

Guides: [`docs/usage-v.md`](docs/usage-v.md),
[`docs/usage-c.md`](docs/usage-c.md),
[`docs/openssl-map.md`](docs/openssl-map.md). Goals: [`ROADMAP.md`](ROADMAP.md).

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
| `toolkit/` | keygen + self-signed certs for the CLI and C API |
| `cmd/vtls/` | `vtls` CLI (OpenSSL replacement) |
| `capi/` + `c/` | C ABI shim + `vtls.h` + demo client |
| `docs/` | usage guides, OpenSSL map |

## Test

```sh
v -Wimpure-v -enable-globals -silent test tls/ tls12/ dtls12/ x509/ \
  pkcs12/ slh_dsa/ rsa/ kat/ mlkem/ toolkit/
```

## License

MIT — see LICENSE (same as the V project it was extracted from).
