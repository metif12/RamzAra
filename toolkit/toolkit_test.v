// Every generated format must parse back and verify: key PEM blocks
// decode with the right type, certificates parse and cover their names,
// and each key family completes a real TLS 1.3 loopback (which proves the
// emitted keys are accepted by the TLS credential loader).
module toolkit

import crypto.pem
import metif12.vtls.tls
import metif12.vtls.x509

fn check_pair(key_type string, want_key_block string) ! {
	g := generate_self_signed(key_type, 'localhost', [], 30, false)!
	assert g.key_pem.len > 0
	assert g.cert_pem.len > 0
	kb, _ := pem.decode(g.key_pem) or { panic('no key pem for ${key_type}') }
	assert kb.block_type == want_key_block, 'key block for ${key_type}: ${kb.block_type}'
	cb, _ := pem.decode(g.cert_pem) or { panic('no cert pem for ${key_type}') }
	assert cb.block_type == 'CERTIFICATE'
	cert := x509.parse_der(cb.data)!
	cert.check_host('localhost')!
}

fn test_toolkit_pem_roundtrip_fast() ! {
	check_pair('rsa:2048', 'PRIVATE KEY')!
	check_pair('ec:p-256', 'EC PRIVATE KEY')!
	check_pair('ec:p-384', 'EC PRIVATE KEY')!
	check_pair('ec:p-521', 'EC PRIVATE KEY')!
	check_pair('ed25519', 'PRIVATE KEY')!
	check_pair('ml-dsa-44', 'PRIVATE KEY')!
	check_pair('ml-dsa-65', 'PRIVATE KEY')!
	check_pair('ml-dsa-87', 'PRIVATE KEY')!
	check_pair('slh-shake-128s', 'PRIVATE KEY')!
	check_pair('slh-sha2-128s', 'PRIVATE KEY')!
}

fn test_toolkit_aliases() ! {
	assert parse_key_type('RSA')! == .rsa_2048
	assert parse_key_type('rsa:3072')! == .rsa_3072
	assert parse_key_type('P-256')! == .ecdsa_p256
	assert parse_key_type('secp384r1')! == .ecdsa_p384
	assert parse_key_type('P-521')! == .ecdsa_p521
	assert parse_key_type('ed')! == .ed25519
	assert parse_key_type('ml-dsa-87')! == .mldsa_87
	assert parse_key_type('slh-shake-256f')! == .slh_shake_256f
	if _ := parse_key_type('des') {
		assert false, 'unknown key type must fail'
	} else {
		assert err.msg().contains('unknown key type')
	}
}

// loopback_echo runs one TLS 1.3 echo round with generated credentials.
fn loopback_echo(key_type string) ! {
	g := generate_self_signed(key_type, 'localhost', [], 30, false)!
	mut l := tls.listen(tls.Config{
		cert: g.cert_pem
		key:  g.key_pem
	})!
	port := l.addr()!.port()!
	done := chan string{cap: 1}
	spawn fn (mut l tls.Listener, done chan string) {
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
		conn.write(buf[..n]) or {
			done <- 'write err: ${err}'
			return
		}
		done <- 'ok'
	}(mut l, done)
	mut c := tls.dial('127.0.0.1', port, tls.Config{
		server_name: 'localhost'
		ca_store:    tls.CertStore{
			roots: [g.cert]
		}
	})!
	c.handshake()!
	c.write('ping'.bytes())!
	mut buf := []u8{len: 4}
	n := c.read(mut buf)!
	assert buf[..n] == 'ping'.bytes()
	c.close()!
	assert <-done == 'ok'
	l.close()!
}

fn test_toolkit_loopback_rsa() ! {
	loopback_echo('rsa:2048')!
}

fn test_toolkit_loopback_ecdsa() ! {
	loopback_echo('ec:p-256')!
}

fn test_toolkit_loopback_ed25519() ! {
	loopback_echo('ed25519')!
}

fn test_toolkit_loopback_mldsa() ! {
	loopback_echo('ml-dsa-65')!
}

fn test_toolkit_loopback_slh() ! {
	loopback_echo('slh-shake-128s')!
}

fn test_toolkit_cert_text() ! {
	g := generate_self_signed('ec:p-256', 'example.com', ['example.com', 'www.example.com'],
		30, false)!
	t := cert_text(g.cert)
	assert t.contains('example.com')
	assert t.contains('SigAlg')
	assert t.contains('SHA256')
}
