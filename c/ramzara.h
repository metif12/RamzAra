// ramzara.h — stable C ABI for the RamzAra pure-V TLS/PKI stack.
//
// Threading: no shared state; each RamzAraConn/RamzAraListener is independent.
// Error strings from ramzara_last_error() stay valid until the next ramzara call
// on the same thread. Handles are heap objects owned by the library:
// release connections/listeners with ramzara_close()/ramzara_listener_close().
// ramzara_close() closes the socket; handle memory itself is reclaimed by the
// library runtime.
#ifndef RAMZARA_H
#define RAMZARA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

// Opaque connection and listener handles.
typedef struct RamzAraConn RamzAraConn;
typedef struct RamzAraListener RamzAraListener;

// ramzara_dial opens a TLS 1.3 connection and runs the handshake.
//   host:        TCP hostname/IP (e.g. "example.com").
//   port:        TCP port.
//   server_name: SNI + certificate hostname; NULL or "" means `host`
//                (literal IPs never go into SNI, per RFC 6066 section 3).
//   ca_file:    PEM bundle path, or NULL/"" for the platform trust roots
//                (explicit store, SSL_CERT_FILE/DIR, Unix paths, embedded
//                Mozilla bundle).
//   insecure:   nonzero skips certificate verification (tests only).
// Returns NULL on failure; details via ramzara_last_error().
RamzAraConn *ramzara_dial(const char *host, int port, const char *server_name,
	const char *ca_file, int insecure);

// ramzara_read reads up to len bytes; returns bytes read, 0 on clean close,
// negative on error (see ramzara_last_error()).
int ramzara_read(RamzAraConn *c, unsigned char *buf, int len);

// ramzara_write writes exactly len bytes; returns len or negative on error.
int ramzara_write(RamzAraConn *c, const unsigned char *buf, int len);

// ramzara_close shuts the connection down and releases the socket.
void ramzara_close(RamzAraConn *c);

// ramzara_cipher_name writes the negotiated cipher suite name into out
// (truncated to outlen-1 chars); returns 0 on success.
int ramzara_cipher_name(RamzAraConn *c, char *out, int outlen);

// ramzara_resumed reports whether the connection resumed a previous session.
int ramzara_resumed(RamzAraConn *c);

// ramzara_listen binds 127.0.0.1:port with cert/key PEM files.
// Returns NULL on failure.
RamzAraListener *ramzara_listen(int port, const char *cert_file, const char *key_file);

// ramzara_accept runs one server handshake; NULL on failure.
RamzAraConn *ramzara_accept(RamzAraListener *l);

// ramzara_listener_close releases the listener socket.
void ramzara_listener_close(RamzAraListener *l);

// ramzara_generate_self_signed creates a key and self-signed certificate
// (mirrors `ramzara req -x509`):
//   key_type: "rsa[:2048|:3072]", "ec:p-256|p-384|p-521", "ed25519",
//             "ml-dsa-44|65|87", "slh-shake|sha2-128s|...|256f".
//   cn:       Common Name (also used as the single SAN when no IP/DNS is
//             configured; pass a DNS name to get a verifiable leaf).
// Writes PKCS#8/SEC1 PEM key + PEM certificate. Returns 0 on success.
int ramzara_generate_self_signed(const char *key_type, const char *cn,
	const char *key_out, const char *cert_out, int days);

// ramzara_verify checks a PEM leaf against a PEM CA bundle and hostname
// (empty hostname skips the name check). errbuf (errlen bytes) receives
// the failure reason; returns 0 when the chain verifies.
int ramzara_verify(const char *ca_bundle, const char *leaf_pem,
	const char *hostname, char *errbuf, int errlen);

// ramzara_cert_text renders a human-readable certificate summary into out
// (truncated to outlen-1 chars); returns 0 on success.
int ramzara_cert_text(const char *cert_pem, char *out, int outlen);

// ramzara_last_error returns the last failure detail (never NULL).
const char *ramzara_last_error(void);

// ramzara_version returns the library version string, e.g. "0.1.0".
const char *ramzara_version(void);

#ifdef __cplusplus
}
#endif

#endif // RAMZARA_H
