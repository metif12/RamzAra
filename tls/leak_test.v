// leak_test.v — memory-stability gate for the -gc none project.
//
// Runs N verified loopback sessions against one listener and asserts
// resident memory does not grow without bound. Under the default GC
// this passes (the runtime reclaims); under -gc none every handshake's
// allocations leak and it must fail. The -gc none port is done when
// this test passes with -gc none — until then it is the conversion's
// failing-then-passing gate.
module tls

import crypto.pem
import metif12.ramzara.x509
import os

// Sessions measured per run (plus warmup, unmeasured).
const leak_sessions = 40

// Warmup sessions: lets the GC heap, ticket keys and replay cache
// reach steady state before the first sample.
const leak_warmup_sessions = 5

// Max RSS growth (KiB) allowed across leak_sessions. Calibrated on a
// quiet Linux runner; CI load inflates this, so the bound is generous
// on purpose — it catches leaks (unbounded growth), not jitters.
const leak_max_growth_kb = 8192

// leak_rss_kb returns the process resident set in KiB (Linux only).
fn leak_rss_kb() !int {
	$if linux {
		status := os.read_file('/proc/self/status')!
		for line in status.split_into_lines() {
			if line.starts_with('VmRSS:') {
				return line.fields()[1].int()
			}
		}
		return error('leak gate: no VmRSS line in /proc/self/status')
	} $else {
		return error('leak gate: Linux-only RSS accounting')
	}
}

// leak_echo_once runs one verified ping/pong session against l.
fn leak_echo_once(mut l Listener, store CertStore, port int) ! {
	done := chan string{cap: 1}
	spawn fn (mut l Listener, done chan string) {
		mut conn := l.accept() or {
			done <- 'accept err: ${err}'
			return
		}
		defer {
			conn.close() or {}
		}
		mut buf := []u8{len: 4}
		n := conn.read(mut buf) or {
			done <- 'read err: ${err}'
			return
		}
		if n > 0 {
			conn.write(buf[..n]) or {
				done <- 'write err: ${err}'
				return
			}
		}
		done <- 'ok'
	}(mut l, done)
	mut c := dial('127.0.0.1', port, Config{
		server_name:  'localhost'
		verify:       true
		verify_chain: true
		ca_store:     store
	}) or { return error('leak gate: dial: ${err}') }
	c.handshake() or { return error('leak gate: handshake: ${err}') }
	c.write('ping'.bytes()) or { return error('leak gate: write: ${err}') }
	mut buf := []u8{len: 4}
	n := c.read(mut buf) or { return error('leak gate: read: ${err}') }
	if buf[..n] != 'ping'.bytes() {
		return error('leak gate: echo mismatch')
	}
	c.close() or { return error('leak gate: close: ${err}') }
	server_out := <-done
	if server_out != 'ok' {
		return error('leak gate: server: ${server_out}')
	}
}

fn test_loopback_memory_stable() ! {
	$if !linux {
		println('skip leak gate: Linux-only RSS accounting')
		return
	}
	td := os.join_path(@VMODROOT, 'tls/testdata')
	mut l := listen(Config{
		cert: os.join_path(td, 'rsa_leaf_cert.pem')
		key:  os.join_path(td, 'rsa_leaf_pkcs8_key.pem')
	}) or { return error('leak gate: listen: ${err}') }
	defer {
		l.close() or {}
	}
	port := int(l.addr() or { return error('leak gate: addr: ${err}') }.port() or {
		return error('leak gate: port: ${err}')
	})
	ca_txt := os.read_file(os.join_path(td, 'rsa_ca_cert.pem')) or {
		return error('leak gate: ca read: ${err}')
	}
	ca_block, _ := pem.decode(ca_txt) or { return error('leak gate: ca pem') }
	if ca_block.block_type != 'CERTIFICATE' {
		return error('leak gate: ca block')
	}
	ca_cert := x509.parse_der(ca_block.data) or {
		return error('leak gate: ca parse: ${err}')
	}
	ca_store := CertStore{
		roots: [ca_cert]
	}
	for _ in 0 .. leak_warmup_sessions {
		leak_echo_once(mut l, ca_store, port)!
	}
	before := leak_rss_kb()!
	for _ in 0 .. leak_sessions {
		leak_echo_once(mut l, ca_store, port)!
	}
	after := leak_rss_kb()!
	growth := after - before
	assert growth <= leak_max_growth_kb, 'leak gate: RSS grew ${growth} KiB over ${leak_sessions} sessions (max ${leak_max_growth_kb})'
}
