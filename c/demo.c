// demo.c — minimal HTTPS client against the ramzara shared library.
//
// Build (Linux/macOS):
//   v -shared -o libramzara.so capi/ramzara_c.v   # or .dylib on macOS
//   cc -o demo c/demo.c -L. -lramzara -I c
//   LD_LIBRARY_PATH=. ./demo example.com 443
//
// With a local test server (see .github/workflows/ci.yml `c-api` job):
//   openssl req -x509 -newkey rsa:2048 -keyout k.pem -out c.pem -days 1 \
//     -nodes -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1
//   openssl s_server -tls1_3 -www -accept 18445 -cert c.pem -key k.pem -naccept 1 &
//   LD_LIBRARY_PATH=. ./demo 127.0.0.1 18445 c.pem 0
//
// Build (Windows, MSVC prompt):
//   v -shared -o ramzara.dll capi/ramzara_c.v
//   cl c/demo.c /Ic ramzara.lib
//
// Usage: demo [host [port [cafile [insecure]]]]
//   cafile   PEM bundle path, or empty for platform roots.
//   insecure "1" skips certificate verification (tests only).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ramzara.h"

int main(int argc, char **argv) {
	const char *host = argc > 1 ? argv[1] : "example.com";
	int port = argc > 2 ? atoi(argv[2]) : 443;
	const char *cafile = argc > 3 ? argv[3] : NULL;
	if (cafile != NULL && cafile[0] == '\0')
		cafile = NULL;
	int insecure = argc > 4 ? atoi(argv[4]) : 0;

	RamzAraConn *c = ramzara_dial(host, port, NULL, cafile, insecure);
	if (!c) {
		fprintf(stderr, "dial failed: %s\n", ramzara_last_error());
		return 1;
	}
	char cipher[64];
	if (ramzara_cipher_name(c, cipher, sizeof(cipher)) == 0)
		printf("cipher: %s (resumed=%d)\n", cipher, ramzara_resumed(c));

	char req[256];
	snprintf(req, sizeof(req),
		"GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
	if (ramzara_write(c, (unsigned char *)req, (int)strlen(req)) < 0) {
		fprintf(stderr, "write failed: %s\n", ramzara_last_error());
		ramzara_close(c);
		return 1;
	}
	unsigned char buf[16384];
	for (;;) {
		int n = ramzara_read(c, buf, sizeof(buf));
		if (n <= 0)
			break;
		fwrite(buf, 1, (size_t)n, stdout);
	}
	ramzara_close(c);
	return 0;
}
