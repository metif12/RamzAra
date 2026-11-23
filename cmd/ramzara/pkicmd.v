// req, x509, verify, crl, ocsp, pkcs12: certificate and store tooling.
module main

import crypto.pem
import crypto.sha1
import crypto.sha256
import encoding.hex
import os
import time
import metif12.ramzara.pkcs12
import metif12.ramzara.toolkit
import metif12.ramzara.x509

// pem_cert_ders decodes every CERTIFICATE block in a PEM bundle.
fn pem_cert_ders(text string) [][]u8 {
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

// cert_file_der reads a certificate file as DER (PEM or raw DER).
fn cert_file_der(path string) ![]u8 {
	text := os.read_file(path)!
	ders := pem_cert_ders(text)
	if ders.len > 0 {
		return ders[0]
	}
	return os.read_bytes(path)!
}

// dn_text renders a DN map in short form.
fn dn_text(m map[string]string) string {
	if m.len == 0 {
		return '(empty)'
	}
	mut parts := []string{}
	for oid, val in m {
		short := match oid {
			'2.5.4.3' { 'CN' }
			'2.5.4.10' { 'O' }
			'2.5.4.11' { 'OU' }
			'2.5.4.6' { 'C' }
			'2.5.4.8' { 'ST' }
			'2.5.4.7' { 'L' }
			else { oid }
		}
		parts << '${short}=${val}'
	}
	return parts.join(', ')
}

// secure_write_key writes a private key file with owner-only permissions
// where the OS supports it.
fn secure_write_key(path string, data string) ! {
	os.write_file(path, data)!
	$if unix {
		os.chmod(path, 0o600) or { eprintln('ramzara: warning: cannot chmod ${path}: ${err}') }
	}
}

fn cmd_req(args []string) {
	key_type := flag_value(args, 'newkey')
	kt := if key_type == '' { 'rsa:2048' } else { key_type }
	keyout := flag_value(args, 'keyout')
	out := flag_value(args, 'out')
	if keyout == '' || out == '' {
		die('req: -keyout and -out are required')
	}
	subj := flag_value(args, 'subj')
	cn := parse_subj_cn(subj)
	dns_flag := flag_value(args, 'dns')
	mut dns := []string{}
	if dns_flag != '' {
		dns = dns_flag.split(',')
	}
	days := flag_value(args, 'days').int()
	real_days := if days <= 0 { 365 } else { days }
	g := toolkit.generate_self_signed(kt, cn, dns, real_days, has_flag(args, 'ca')) or {
		die('req: ${err}')
	}
	secure_write_key(keyout, g.key_pem) or { die('req: cannot write ${keyout}: ${err}') }
	os.write_file(out, g.cert_pem) or { die('req: cannot write ${out}: ${err}') }
	println('key:  ${keyout}')
	println('cert: ${out}')
	println(toolkit.cert_text(g.cert))
}

// parse_subj_cn extracts the CN from `/CN=name/...` or a bare name.
fn parse_subj_cn(subj string) string {
	if subj == '' {
		return 'localhost'
	}
	if !subj.starts_with('/') {
		return subj
	}
	for part in subj.split('/') {
		if part.starts_with('CN=') {
			return part[3..]
		}
	}
	return 'localhost'
}

fn cmd_x509(args []string) {
	inp := flag_value(args, 'in')
	if inp == '' {
		die('x509: -in cert is required')
	}
	der := cert_file_der(inp) or { die('x509: ${err}') }
	cert := x509.parse_der(der) or { die('x509: parse: ${err}') }
	if has_flag(args, 'text') {
		println(toolkit.cert_text(cert))
		return
	}
	if has_flag(args, 'subject') {
		println('subject=${dn_text(cert.subject)}')
	}
	if has_flag(args, 'issuer') {
		println('issuer=${dn_text(cert.issuer)}')
	}
	if has_flag(args, 'dates') {
		println('notBefore=${cert.not_before}')
		println('notAfter=${cert.not_after}')
	}
	if has_flag(args, 'fingerprint') {
		if has_flag(args, 'sha1') {
			println(hex.encode(sha1.sum(cert.raw)))
		} else {
			println(hex.encode(sha256.sum(cert.raw)))
		}
	}
	if !has_flag(args, 'subject') && !has_flag(args, 'issuer') && !has_flag(args, 'dates')
		&& !has_flag(args, 'fingerprint') {
		println('subject=${dn_text(cert.subject)}')
		println('issuer=${dn_text(cert.issuer)}')
	}
}

fn cmd_verify(args []string) {
	cafile := flag_value(args, 'CAfile')
	if cafile == '' {
		die('verify: -CAfile bundle is required')
	}
	pos := rest_args(args, ['CAfile', 'untrusted', 'hostname', 'crlfile', 'ocsp'])
	if pos.len == 0 {
		die('verify: a certificate file is required')
	}
	roots := pem_cert_ders(os.read_file(cafile) or { die('verify: ${err}') }).map(x509.parse_der(it) or {
		die('verify: bad CA cert: ${err}')
	})
	mut intermediates := []x509.Certificate{}
	untrusted := flag_value(args, 'untrusted')
	if untrusted != '' {
		for f in untrusted.split(',') {
			for der in pem_cert_ders(os.read_file(f.trim_space()) or {
				die('verify: ${err}')
			}) {
				intermediates << x509.parse_der(der) or { die('verify: bad chain cert: ${err}') }
			}
		}
	}
	leaf := x509.parse_der(cert_file_der(pos[0]) or { die('verify: ${err}') }) or {
		die('verify: bad leaf: ${err}')
	}
	chain := x509.build_chain(leaf, intermediates, roots) or {
		die('verify: ${pos[0]}: untrusted: ${err}')
	}
	mut opts := x509.VerifyOptions{
		at: time.now()
	}
	hostname := flag_value(args, 'hostname')
	if hostname != '' {
		opts.hostname = hostname
	}
	crlfile := flag_value(args, 'crlfile')
	if crlfile != '' {
		raw := os.read_file(crlfile) or { die('verify: ${err}') }
		if block, _ := pem.decode(raw) {
			opts.crls << x509.parse_crl_pem(raw) or { die('verify: bad CRL: ${err}') }
			_ = block
		} else {
			opts.crls << x509.parse_crl_der(os.read_bytes(crlfile) or {
				die('verify: ${err}')
			}) or { die('verify: bad CRL: ${err}') }
		}
	}
	ocsp := flag_value(args, 'ocsp')
	if ocsp != '' {
		opts.ocsp_resp = os.read_bytes(ocsp) or { die('verify: ${err}') }
	}
	x509.verify_chain(chain, opts) or { die('verify: ${pos[0]}: ${err}') }
	println('${pos[0]}: OK (${dn_text(leaf.subject)})')
}

fn cmd_crl(args []string) {
	inp := flag_value(args, 'in')
	if inp == '' {
		die('crl: -in file is required')
	}
	raw := os.read_file(inp) or { die('crl: ${err}') }
	crl := if _, _ := pem.decode(raw) {
		x509.parse_crl_pem(raw) or { die('crl: ${err}') }
	} else {
		x509.parse_crl_der(os.read_bytes(inp) or { die('crl: ${err}') }) or {
			die('crl: ${err}')
		}
	}
	println('issuer: ${dn_text(crl.issuer)}')
	println('thisUpdate: ${crl.this_update}')
	if crl.has_next_update {
		println('nextUpdate: ${crl.next_update}')
	}
	println('revoked: ${crl.revoked.len}')
	if has_flag(args, 'text') {
		for e in crl.revoked {
			println('  serial=${hex.encode(e.serial)} date=${e.revoked_at}')
		}
	}
}

fn cmd_ocsp(args []string) {
	inp := flag_value(args, 'in')
	if inp == '' {
		die('ocsp: -in response is required')
	}
	der := os.read_bytes(inp) or { die('ocsp: ${err}') }
	resp := x509.parse_ocsp_response(der) or { die('ocsp: ${err}') }
	leaf := flag_value(args, 'leaf')
	issuer := flag_value(args, 'issuer')
	if leaf != '' && issuer != '' {
		leaf_der := cert_file_der(leaf) or { die('ocsp: ${err}') }
		issuer_der := cert_file_der(issuer) or { die('ocsp: ${err}') }
		x509.verify_ocsp_staple(der, leaf_der, issuer_der) or {
			die('ocsp: staple invalid: ${err}')
		}
		println('ocsp: staple verifies against issuer')
	}
	println('producedAt: ${resp.produced_at}')
	println('responses: ${resp.responses.len}')
	if has_flag(args, 'text') {
		for s in resp.responses {
			println('  serial=${hex.encode(s.serial)} status=${s.status} thisUpdate=${s.this_update}')
		}
	}
}

fn cmd_pkcs12(args []string) {
	if has_flag(args, 'export') {
		pkcs12_export(args)
		return
	}
	inp := flag_value(args, 'in')
	if inp == '' {
		die('pkcs12: -in file is required')
	}
	pw := flag_value(args, 'passin')
	out := flag_value(args, 'out')
	prefix := if out == '' { 'ramzara-out' } else { out }
	data := os.read_bytes(inp) or { die('pkcs12: ${err}') }
	dec := pkcs12.decode(data, pw) or { die('pkcs12: ${err}') }
	secure_write_key('${prefix}.key.pem', pem.Block{
		block_type: 'PRIVATE KEY'
		data:       dec.key_der
	}.encode(pem.EncodeConfig{}) or { die('pkcs12: ${err}') }) or { die('pkcs12: ${err}') }
	for i, cert in dec.certs {
		os.write_file('${prefix}.${i}.cert.pem', pem.Block{
			block_type: 'CERTIFICATE'
			data:       cert
		}.encode(pem.EncodeConfig{}) or { die('pkcs12: ${err}') }) or { die('pkcs12: ${err}') }
	}
	println('key: ${prefix}.key.pem')
	println('certs: ${dec.certs.len}')
	if dec.friendly_names.len > 0 {
		println('names: ${dec.friendly_names.join(', ')}')
	}
}

// pkcs12_export builds a .p12 from PEM inputs.
fn pkcs12_export(args []string) {
	inkey := flag_value(args, 'inkey')
	incert := flag_value(args, 'in')
	out := flag_value(args, 'out')
	if inkey == '' || incert == '' || out == '' {
		die('pkcs12: -export needs -inkey, -in and -out')
	}
	key_text := os.read_file(inkey) or { die('pkcs12: ${err}') }
	key_block, _ := pem.decode(key_text) or { die('pkcs12: no PEM key in ${inkey}') }
	if key_block.block_type != 'PRIVATE KEY' {
		die('pkcs12: -inkey must be PKCS#8 PEM')
	}
	mut certs := pem_cert_ders(os.read_file(incert) or { die('pkcs12: ${err}') })
	if certs.len == 0 {
		die('pkcs12: no certificates in ${incert}')
	}
	chainf := flag_value(args, 'certfile')
	if chainf != '' {
		for f in chainf.split(',') {
			certs << pem_cert_ders(os.read_file(f.trim_space()) or {
				die('pkcs12: ${err}')
			})
		}
	}
	pbe := match flag_value(args, 'pbe') {
		'', 'aes256' { pkcs12.PbeKind.pbes2_aes256_sha256 }
		'aes128' { pkcs12.PbeKind.pbes2_aes128_sha256 }
		'3des' { pkcs12.PbeKind.pbe_sha1_3des }
		'rc2' { pkcs12.PbeKind.pbe_sha1_rc2_40 }
		else { die('pkcs12: unknown -pbe (aes256|aes128|3des|rc2)') }
	}
	name := flag_value(args, 'name')
	cfg := pkcs12.EncodeConfig{
		key_pbe:       pbe
		cert_pbe:      pbe
		friendly_name: if name == '' { 'v-pkcs12' } else { name }
	}
	pw := flag_value(args, 'passout')
	blob := pkcs12.encode(key_block.data, certs, pw, cfg) or {
		die('pkcs12: encode: ${err}')
	}
	os.write_bytes(out, blob) or { die('pkcs12: ${err}') }
	println('wrote ${out} (${blob.len} bytes, ${certs.len} certs)')
}
