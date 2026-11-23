// s_client and s_server: TLS connection testing and serving.
module main

import os
import time
import metif12.ramzara.tls
import metif12.ramzara.tls12

fn cmd_s_client(args []string) {
	connect := flag_value(args, 'connect')
	if connect == '' {
		die('s_client: -connect host:port is required')
	}
	host := connect.all_before_last(':')
	port := connect.all_after_last(':').int()
	if port <= 0 {
		die('s_client: bad port in -connect ${connect}')
	}
	servername := flag_value(args, 'servername')
	name := if servername != '' { servername } else { host }
	brief := has_flag(args, 'brief')
	if has_flag(args, 'tls1_2') {
		s_client_tls12(args, host, port, name, brief)
		return
	}
	mut cfg := tls.Config{
		server_name: name
		verify:      !has_flag(args, 'insecure')
	}
	cafile := flag_value(args, 'CAfile')
	if cafile != '' {
		cfg.ca_cert = cafile
	}
	alpn := flag_value(args, 'alpn')
	if alpn != '' {
		cfg.alpn_protocols = alpn.split(',')
	}
	if has_flag(args, 'keylog') {
		eprintln('ramzara: s_client: -keylog is not supported by the pure-V stack (no SSLKEYLOGFILE hook in v1)')
	}
	mut c := tls.dial(host, port, cfg) or { die('s_client: dial: ${err}') }
	c.handshake() or { die('s_client: handshake: ${err}') }
	if !brief {
		println('cipher: ${c.negotiated_cipher()}')
		println('alpn: ${c.negotiated_alpn()}')
		println('resumed: ${c.resumed()}')
	}
	// Non-interactive relay: the library has no TCP half-close (its
	// shutdown closes the socket), so the client writes the payload, then
	// reads the reply for -waitms before closing. The close unblocks the
	// reader; anything the server echoed in the window is printed.
	payload := read_all_stdin()
	if payload.len > 0 {
		c.write(payload) or { die('s_client: write: ${err}') }
	}
	waitms := flag_value(args, 'waitms').int()
	grace := if waitms > 0 { waitms } else { 1500 }
	if payload.len > 0 {
		ch := chan []u8{cap: 64}
		spawn pump_reader_tls13(mut c, ch)
		time.sleep(grace * time.millisecond)
		c.send_close_notify() or {}
		c.close() or {}
		drain_and_print(ch)
	} else {
		c.close() or {}
	}
	reconnect := flag_value(args, 'reconnect')
	if reconnect != '' {
		st := c.session_state() or { die('s_client: -reconnect needs a resumable session') }
		n := reconnect.int()
		for i in 0 .. n {
			mut cfg2 := cfg
			cfg2.resume_from = st
			mut c2 := tls.dial(host, port, cfg2) or {
				die('s_client: reconnect dial: ${err}')
			}
			c2.handshake() or { die('s_client: reconnect handshake: ${err}') }
			println('reconnect ${i + 1}: resumed=${c2.resumed()}')
			c2.close() or {}
		}
	}
}

// s_client_tls12 runs the same probe over TLS 1.2.
fn s_client_tls12(args []string, host string, port int, name string, brief bool) {
	skip := has_flag(args, 'insecure')
	cafile := flag_value(args, 'CAfile')
	mut root_ders := [][]u8{}
	if cafile != '' && !skip {
		root_ders = pem_cert_ders(os.read_file(cafile) or {
			die('s_client: cannot read -CAfile: ${err}')
		})
		if root_ders.len == 0 {
			die('s_client: -CAfile holds no certificates')
		}
	}
	cfg := tls12.Config{
		server_name: name
		skip_verify: skip
		root_ders:   root_ders
	}
	mut c := tls12.dial(host, port, cfg) or { die('s_client: dial: ${err}') }
	c.handshake() or { die('s_client: handshake: ${err}') }
	if !brief {
		println('cipher: ${c.cipher_suite_name()}')
		println('resumed: ${c.did_resume()}')
		println('ems: ${c.uses_ems()} etm: ${c.uses_etm()}')
	}
	payload := read_all_stdin()
	if payload.len > 0 {
		c.write(payload) or { die('s_client: write: ${err}') }
	}
	waitms := flag_value(args, 'waitms').int()
	grace := if waitms > 0 { waitms } else { 1500 }
	if payload.len > 0 {
		ch := chan []u8{cap: 64}
		spawn pump_reader_tls12(mut c, ch)
		time.sleep(grace * time.millisecond)
		c.close() or {}
		drain_and_print(ch)
	} else {
		c.close() or {}
	}
}

fn cmd_s_server(args []string) {
	port := flag_value(args, 'accept')
	if port == '' {
		die('s_server: -accept port is required')
	}
	certf := flag_value(args, 'cert')
	keyf := flag_value(args, 'key')
	if certf == '' || keyf == '' {
		die('s_server: -cert and -key are required')
	}
	mut cfg := tls.Config{
		cert: certf
		key:  keyf
	}
	if has_flag(args, 'Verify') {
		cfg.verify_client = true
		cafile := flag_value(args, 'CAfile')
		if cafile != '' {
			cfg.ca_cert = cafile
		}
	}
	www := has_flag(args, 'www')
	naccept := flag_value(args, 'naccept').int()
	mut l := tls.listen_on('127.0.0.1:${port}', cfg) or {
		die('s_server: listen: ${err}')
	}
	eprintln('ramzara: s_server listening on 127.0.0.1:${port}')
	mut served := 0
	for {
		if naccept > 0 && served >= naccept {
			break
		}
		mut conn := l.accept() or {
			eprintln('ramzara: s_server: accept: ${err}')
			continue
		}
		served++
		if www {
			serve_www(mut conn)
		} else {
			echo_conn(mut conn)
		}
		// Clean EOF for strict peers (OpenSSL errors on a bare FIN).
		conn.send_close_notify() or {}
		conn.close() or {}
	}
	l.close() or {}
}

// echo_conn relays bytes back until the peer closes.
fn echo_conn(mut conn tls.Conn) {
	for {
		mut chunk := []u8{len: 16384}
		n := conn.read(mut chunk) or { break }
		if n == 0 {
			break
		}
		conn.write(chunk[..n]) or { break }
	}
}

// serve_www answers one HTTP request with a fixed status page.
fn serve_www(mut conn tls.Conn) {
	mut req := []u8{}
	for req.len < 8192 {
		mut chunk := []u8{len: 1024}
		n := conn.read(mut chunk) or { break }
		if n == 0 {
			break
		}
		req << chunk[..n]
		if req.bytestr().contains('\r\n\r\n') {
			break
		}
	}
	body := 'ramzara s_server status page\ncipher: ${conn.negotiated_cipher()}\n'
	head := 'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${body.len}\r\nConnection: close\r\n\r\n'
	conn.write((head + body).bytes()) or {}
}

// pump_reader_tls13 streams server bytes into ch until the connection
// errors; an empty chunk is the end sentinel.
fn pump_reader_tls13(mut c tls.Conn, ch chan []u8) {
	for {
		mut chunk := []u8{len: 16384}
		n := c.read(mut chunk) or { break }
		if n <= 0 {
			break
		}
		ch <- chunk[..n]
	}
	ch <- []u8{}
}

// pump_reader_tls12 is pump_reader_tls13 for TLS 1.2 connections.
fn pump_reader_tls12(mut c tls12.Conn, ch chan []u8) {
	for {
		mut chunk := []u8{len: 16384}
		n := c.read(mut chunk) or { break }
		if n <= 0 {
			break
		}
		ch <- chunk[..n]
	}
	ch <- []u8{}
}

// drain_and_print prints chunks until the end sentinel.
fn drain_and_print(ch chan []u8) {
	mut out := os.stdout()
	for {
		chunk := <-ch
		if chunk.len == 0 {
			break
		}
		out.write(chunk) or { break }
	}
}

// read_all_stdin slurps stdin (binary-safe).
fn read_all_stdin() []u8 {
	mut sin := os.stdin()
	mut out := []u8{}
	for {
		mut chunk := []u8{len: 65536}
		n := sin.read(mut chunk) or { break }
		if n <= 0 {
			break
		}
		out << chunk[..n]
	}
	return out
}
