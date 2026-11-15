// demo.c — minimal HTTPS client against the vtls shared library.
//
// Build (Linux/macOS):
//   v -shared -o libvtls.so capi/vtls_c.v   # or .dylib on macOS
//   cc -o demo c/demo.c -L. -lvtls -I c
//   LD_LIBRARY_PATH=. ./demo example.com 443
//
// Build (Windows, MSVC prompt):
//   v -shared -o vtls.dll capi/vtls_c.v
//   cl c/demo.c /Ic vtls.lib
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vtls.h"

int main(int argc, char **argv) {
	const char *host = argc > 1 ? argv[1] : "example.com";
	int port = argc > 2 ? atoi(argv[2]) : 443;

	VtlsConn *c = vtls_dial(host, port, NULL, NULL, 0);
	if (!c) {
		fprintf(stderr, "dial failed: %s\n", vtls_last_error());
		return 1;
	}
	char cipher[64];
	if (vtls_cipher_name(c, cipher, sizeof(cipher)) == 0)
		printf("cipher: %s (resumed=%d)\n", cipher, vtls_resumed(c));

	char req[256];
	snprintf(req, sizeof(req),
		"GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
	if (vtls_write(c, (unsigned char *)req, (int)strlen(req)) < 0) {
		fprintf(stderr, "write failed: %s\n", vtls_last_error());
		vtls_close(c);
		return 1;
	}
	unsigned char buf[16384];
	for (;;) {
		int n = vtls_read(c, buf, sizeof(buf));
		if (n <= 0)
			break;
		fwrite(buf, 1, (size_t)n, stdout);
	}
	vtls_close(c);
	return 0;
}
