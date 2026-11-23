# RamzAra usage guide (C)

Full symbol reference: [`api.md`](api.md) (C ABI section).

The C ABI is `c/ramzara.h` (stable, C89-compatible header). You link a
prebuilt library from the GitHub releases (`libramzara.so` / `ramzara.dll` /
`libramzara.dylib`) or amalgamation (see below). No V toolchain needed to
*use* the library — only to build it.

## Linking

```sh
# Linux
cc -o demo c/demo.c -L. -lramzara -I c
LD_LIBRARY_PATH=. ./demo example.com 443
```

On Windows, create the import library first (the release ships one;
this is how to regenerate it):

```sh
dlltool -d c/ramzara.def --dllname ramzara.dll -l libramzara.dll.a
gcc -o demo.exe c/demo.c -Ic -L. -lramzara
```

MSVC users: `lib /def:ramzara.def /out:ramzara.lib /machine:x64`, then link
`demo.obj` against `ramzara.lib`.

## Client

```c
#include "ramzara.h"

RamzAraConn *c = ramzara_dial("example.com", 443, NULL, NULL, 0);
if (!c) { fprintf(stderr, "%s\n", ramzara_last_error()); return 1; }
ramzara_write(c, (unsigned char *)req, len);
int n = ramzara_read(c, buf, sizeof buf);
ramzara_close(c);
```

- `server_name`: NULL/"" means `host`; IPs never enter SNI.
- `ca_file`: NULL/"" selects platform roots (system store on Windows,
  `SSL_CERT_FILE`/`SSL_CERT_DIR`, Unix bundles, embedded Mozilla).
- `insecure` nonzero skips verification (tests only).

## Server

```c
RamzAraListener *l = ramzara_listen(4433, "server.pem", "key.pem");
for (;;) {
	RamzAraConn *c = ramzara_accept(l);
	/* read/write/close */
}
```

## Key generation and verification

```c
ramzara_generate_self_signed("ec:p-256", "localhost", "key.pem", "cert.pem", 365);
char err[256];
if (ramzara_verify("ca.pem", "leaf.pem", "example.com", err, sizeof err) != 0)
	fprintf(stderr, "bad chain: %s\n", err);
```

Key types: `rsa[:2048|:3072]`, `ec:p-256|p-384|p-521`, `ed25519`,
`ml-dsa-44|65|87`, `slh-shake|sha2-128s|...|256f`.

## Artifacts

Each tag release ships `ramzara.h`, one prebuilt shared library per OS,
and `demo.c`. A single-file C amalgamation is future work (the V
`-shared` build does not emit a self-contained translation unit).
ABI rule: only C-compatible types cross the boundary; all out-params
are caller-owned buffers with explicit lengths (except
`ramzara_last_error()` / `ramzara_version()`, valid until the next call on
the same thread).

## Limits (v1)

- Client and server speak TLS 1.3. No TLS 1.2 / DTLS C API yet
  (V API exists: `tls12`, `dtls12`).
- DTLS 1.2 default is anonymous ECDHE (pin the peer key to authenticate).
- No client-certificate (mTLS) parameters in the C API yet; the V API
  supports it (`verify_client`, `client_cert`/`client_key`).
- Accepted residual: CBC length-timing in the 1.2/CBC path; socket-level
  write timeouts need a `vlib/net` change upstream.
