// ramzara_c.v — C ABI shim over the ramzara modules. Built with:
//   v -shared -o libramzara.so capi/ramzara_c.v        (Linux)
//   v -shared -o ramzara.dll capi/ramzara_c.v          (Windows)
//   v -shared -o libramzara.dylib capi/ramzara_c.v     (macOS)
// The public contract is c/ramzara.h; symbol names below must match it.
module main

import crypto.pem
import os
import metif12.ramzara.tls
import metif12.ramzara.toolkit
import metif12.ramzara.x509

__global (
	c_last_error  string
	c_err_buf     []u8
	c_version_buf []u8
)

fn set_err(msg string) {
	c_last_error = msg
	// Keep a private NUL-terminated copy: the returned pointer stays valid
	// until the next error on this thread.
	c_err_buf = msg.bytes()
	c_err_buf << u8(0)
}

// c_str converts a C string (NULL-safe) to a V string.
fn c_str(p &char) string {
	if p == unsafe { nil } {
		return ''
	}
	return unsafe { cstring_to_vstring(p) }
}

// copy_out copies msg into a caller buffer, NUL-terminated and truncated.
fn copy_out(msg string, out &char, outlen int) {
	if out == unsafe { nil } || outlen <= 0 {
		return
	}
	b := msg.bytes()
	mut n := b.len
	if n > outlen - 1 {
		n = outlen - 1
	}
	if n > 0 {
		unsafe { C.memcpy(out, b.data, n) }
	}
	unsafe { out[n] = 0 }
}

struct CVConn {
mut:
	conn &tls.Conn
}

struct CVListener {
mut:
	l &tls.Listener
}

@[export: 'ramzara_dial']
fn cramzara_dial(host &char, port int, server_name &char, ca_file &char, insecure int) &CVConn {
	h := c_str(host)
	mut cfg := tls.Config{
		server_name: c_str(server_name)
		verify:      insecure == 0
	}
	if cfg.server_name == '' {
		cfg.server_name = h
	}
	ca := c_str(ca_file)
	if ca != '' {
		cfg.ca_cert = ca
	}
	mut conn := tls.dial(h, port, cfg) or {
		set_err('dial: ${err}')
		return unsafe { nil }
	}
	conn.handshake() or {
		set_err('handshake: ${err}')
		conn.close() or {}
		return unsafe { nil }
	}
	return &CVConn{ conn: conn }
}

@[export: 'ramzara_read']
fn cramzara_read(c &CVConn, buf &u8, len int) int {
	if c == unsafe { nil } || buf == unsafe { nil } || len <= 0 {
		set_err('read: bad argument')
		return -1
	}
	mut tmp := []u8{len: len}
	n := c.conn.read(mut tmp) or {
		set_err('read: ${err}')
		return -1
	}
	if n > 0 {
		unsafe { C.memcpy(buf, tmp.data, n) }
	}
	return n
}

@[export: 'ramzara_write']
fn cramzara_write(c &CVConn, buf &u8, len int) int {
	if c == unsafe { nil } || buf == unsafe { nil } || len < 0 {
		set_err('write: bad argument')
		return -1
	}
	mut off := 0
	for off < len {
		seg := len - off
		mut chunk := []u8{len: seg}
		unsafe { C.memcpy(chunk.data, buf + off, seg) }
		n := c.conn.write(chunk) or {
			set_err('write: ${err}')
			return -1
		}
		off += n
	}
	return len
}

@[export: 'ramzara_close']
fn cramzara_close(c &CVConn) {
	if c == unsafe { nil } {
		return
	}
	c.conn.close() or {}
}

@[export: 'ramzara_cipher_name']
fn cramzara_cipher_name(c &CVConn, out &char, outlen int) int {
	if c == unsafe { nil } {
		set_err('cipher: bad handle')
		return -1
	}
	copy_out(c.conn.negotiated_cipher().str(), out, outlen)
	return 0
}

@[export: 'ramzara_resumed']
fn cramzara_resumed(c &CVConn) int {
	if c == unsafe { nil } {
		return 0
	}
	return if c.conn.resumed() { 1 } else { 0 }
}

@[export: 'ramzara_listen']
fn cramzara_listen(port int, cert_file &char, key_file &char) &CVListener {
	mut l := tls.listen_on('127.0.0.1:${port}', tls.Config{
		cert: c_str(cert_file)
		key:  c_str(key_file)
	}) or {
		set_err('listen: ${err}')
		return unsafe { nil }
	}
	return &CVListener{ l: l }
}

@[export: 'ramzara_accept']
fn cramzara_accept(l &CVListener) &CVConn {
	if l == unsafe { nil } {
		set_err('accept: bad handle')
		return unsafe { nil }
	}
	mut conn := l.l.accept() or {
		set_err('accept: ${err}')
		return unsafe { nil }
	}
	return &CVConn{ conn: conn }
}

@[export: 'ramzara_listener_close']
fn cramzara_listener_close(l &CVListener) {
	if l == unsafe { nil } {
		return
	}
	l.l.close() or {}
}

@[export: 'ramzara_generate_self_signed']
fn cramzara_generate_self_signed(key_type &char, cn &char, key_out &char, cert_out &char, days int) int {
	real_days := if days <= 0 { 365 } else { days }
	g := toolkit.generate_self_signed(c_str(key_type), c_str(cn), [], real_days,
		false) or {
		set_err('generate: ${err}')
		return -1
	}
	os.write_file(c_str(key_out), g.key_pem) or {
		set_err('generate: ${err}')
		return -1
	}
	os.write_file(c_str(cert_out), g.cert_pem) or {
		set_err('generate: ${err}')
		return -1
	}
	return 0
}

@[export: 'ramzara_verify']
fn cramzara_verify(ca_bundle &char, leaf_pem &char, hostname &char, errbuf &char, errlen int) int {
	cas := os.read_file(c_str(ca_bundle)) or {
		set_err('verify: ${err}')
		copy_out('verify: ${err}', errbuf, errlen)
		return -1
	}
	leaf_text := os.read_file(c_str(leaf_pem)) or {
		set_err('verify: ${err}')
		copy_out('verify: ${err}', errbuf, errlen)
		return -1
	}
	mut roots := []x509.Certificate{}
	for der in pem_cert_ders_of(cas) {
		roots << x509.parse_der(der) or {
			set_err('verify: bad CA cert: ${err}')
			copy_out('verify: bad CA cert: ${err}', errbuf, errlen)
			return -1
		}
	}
	leaf := x509.parse_pem(leaf_text) or {
		set_err('verify: bad leaf: ${err}')
		copy_out('verify: bad leaf: ${err}', errbuf, errlen)
		return -1
	}
	chain := x509.build_chain(leaf, [], roots) or {
		set_err('verify: untrusted: ${err}')
		copy_out('verify: untrusted: ${err}', errbuf, errlen)
		return -1
	}
	x509.verify_chain(chain, x509.VerifyOptions{ hostname: c_str(hostname) }) or {
		set_err('verify: ${err}')
		copy_out('verify: ${err}', errbuf, errlen)
		return -1
	}
	return 0
}

// pem_cert_ders_of decodes every CERTIFICATE block in a PEM bundle.
fn pem_cert_ders_of(text string) [][]u8 {
	mut out := [][]u8{}
	mut rest := text
	for {
		block, next := pem.decode(rest) or { break }
		rest = next
		if block.block_type == 'CERTIFICATE' {
			out << block.data
		}
		if rest.trim_space() == '' {
			break
		}
	}
	return out
}

@[export: 'ramzara_cert_text']
fn cramzara_cert_text(cert_pem &char, out &char, outlen int) int {
	cert := x509.parse_pem(c_str(cert_pem)) or {
		set_err('cert_text: ${err}')
		return -1
	}
	copy_out(toolkit.cert_text(cert), out, outlen)
	return 0
}

@[export: 'ramzara_last_error']
fn cramzara_last_error() &char {
	if c_err_buf.len == 0 {
		c_err_buf = 'no error'.bytes()
		c_err_buf << u8(0)
	}
	return &char(c_err_buf.data)
}

@[export: 'ramzara_version']
fn cramzara_version() &char {
	if c_version_buf.len == 0 {
		c_version_buf = '0.1.0'.bytes()
		c_version_buf << u8(0)
	}
	return &char(c_version_buf.data)
}
