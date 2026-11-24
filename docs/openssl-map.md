# OpenSSL → ramzara command map

The `ramzara` CLI covers the TLS/PKI subset of OpenSSL (flags per
command: [`api.md`](api.md) CLI section). General-purpose
crypto outside TLS/PKI (ciphers for files, password hashing, CMS/SMIME)
is intentionally out of scope.

| openssl | ramzara | notes |
|---|---|---|
| `s_client -connect h:p` | `s_client -connect h:p` | + `-servername -CAfile -alpn -tls1_2 -insecure -reconnect -brief`; stdin relay, no interactive key renegotiation |
| `s_server -accept p` | `s_server -accept p -cert f -key f` | echo or `-www`; `-Verify [-CAfile]` for mTLS; `-naccept` |
| `req -x509 -newkey rsa:2048` | `req -newkey rsa:2048 -keyout k -out c` | types: rsa ec ed25519 ml-dsa-* slh-*; `-subj -dns -days -ca`; `-new` writes a PKCS#10 CSR instead |
| `x509 -in c -text` | `x509 -in c -text` | also `-subject -issuer -dates -fingerprint [-sha1]` |
| `verify -CAfile b c` | `verify -CAfile b c` | + `-untrusted -hostname -crlfile -ocsp` |
| `crl -in c -text` | `crl -in c -text` | PEM or DER |
| `ocsp -in r -text` | `ocsp -in r -text` | + `-leaf -issuer` staple check |
| `pkcs12 -in f` | `pkcs12 -in f -passin pw [-out p]` | writes `p.key.pem`, `p.N.cert.pem` |
| `pkcs12 -export ...` | `pkcs12 -export -inkey k -in c -out f -passout pw` | `-pbe aes256\|aes128\|3des\|rc2 -name -certfile` |
| `enc -aes-256-gcm -e` | `enc -aes-256-gcm -e -K hex -iv hex` | also aes-128-gcm, chacha20-poly1305; `-d -aad -in -out` |
| `dgst -sha256 f` | `dgst [-sha256\|-sha512\|-sha1] [f]` | stdin default |
| `rand -hex n` | `rand -hex n` | also `-base64` |
| `speed` | `speed [algos] [-seconds n]` | sha256, aes-gcm, chacha20, rand, mlkem-768, rsa |
| `s_time`, `sess_id`, `ciphers` | — | not planned (benchmark via `speed`; sessions via `-reconnect`) |
| `cms`, `smime`, `passwd`, `kdf` | — | out of scope, see ROADMAP |

Behavioral notes:

- Verification is on by default; `-insecure` maps to `-verify 0`-style flows.
- PKI failures are fail-closed with a reason on stderr and exit code 1.
- PEM inputs accept bundles; the first CERTIFICATE block is the leaf
  unless the command says otherwise.
