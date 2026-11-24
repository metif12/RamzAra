module x509

import crypto.ecdsa
import crypto.pem
import encoding.base64
import os
import time
import x.crypto.mldsa

// openssl_bin locates an OpenSSL CLI: PATH first, then the common Windows
// install path. Returns '' when unavailable; callers must skip gracefully.
fn openssl_bin() string {
	res := os.exec(['openssl', 'version'])
	if res.exit_code == 0 {
		return 'openssl'
	}
	win := 'C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe'
	res2 := os.exec([win, 'version'])
	if res2.exit_code == 0 {
		return win
	}
	return ''
}

fn test_our_der_parses_under_openssl() {
	bin := openssl_bin()
	if bin == '' {
		return
	}
	key, priv := ecdsa.generate_key(ecdsa.CurveOptions{}) or { panic('keygen: ${err}') }
	_ = key
	now := time.now()
	opts := CertGenOptions{
		common_name: 'crosscheck.example.com'
		dns_names:   ['crosscheck.example.com']
		not_before:  now
		not_after:   now.add_days(30)
	}
	_, der := generate_self_signed(opts, priv) or { panic('gen: ${err}') }
	tmp := os.temp_dir() + '/tls_cc_self.der'
	os.write_file_array(tmp, der) or { panic('write') }
	defer {
		os.rm(tmp) or {}
	}
	res := os.exec([bin, 'x509', '-inform', 'DER', '-in', tmp, '-text', '-noout'])
	assert res.exit_code == 0
	assert res.output.contains('crosscheck.example.com')
}

fn test_our_ca_signed_der_parses_under_openssl() {
	bin := openssl_bin()
	if bin == '' {
		return
	}
	ca_key, ca_priv := ecdsa.generate_key(ecdsa.CurveOptions{}) or { panic('ca keygen: ${err}') }
	_ = ca_key
	leaf_key, leaf_priv := ecdsa.generate_key(ecdsa.CurveOptions{}) or { panic('leaf keygen: ${err}') }
	_ = leaf_key
	now := time.now()
	ca_opts := CertGenOptions{
		common_name: 'Test CA'
		not_before:  now
		not_after:   now.add_days(3650)
	}
	ca_cert, _ := generate_self_signed(ca_opts, ca_priv) or { panic('ca gen: ${err}') }
	leaf_opts := CertGenOptions{
		common_name: 'leaf.example.com'
		dns_names:   ['leaf.example.com']
		not_before:  now
		not_after:   now.add_days(365)
	}
	_, leaf_der := generate_ca_signed(leaf_opts, leaf_priv, &ca_cert, ca_priv) or {
		panic('leaf gen: ${err}')
	}
	tmp := os.temp_dir() + '/tls_cc_leaf.der'
	os.write_file_array(tmp, leaf_der) or { panic('write') }
	defer {
		os.rm(tmp) or {}
	}
	res := os.exec([bin, 'x509', '-inform', 'DER', '-in', tmp, '-text', '-noout'])
	assert res.exit_code == 0
	assert res.output.contains('leaf.example.com')
}

fn test_openssl_cert_parses_under_v() {
	bin := openssl_bin()
	if bin == '' {
		return
	}
	dir := os.temp_dir()
	keyf := dir + '/tls_ossl_key.pem'
	certf := dir + '/tls_ossl_cert.pem'
	defer {
		os.rm(keyf) or {}
		os.rm(certf) or {}
	}
	gen := os.exec([bin, 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
		'-keyout', keyf, '-out', certf, '-days', '2', '-nodes', '-subj', '/CN=ossl-interop.example.com',
		'-addext', 'subjectAltName=DNS:ossl-interop.example.com'])
	assert gen.exit_code == 0
	pem_text := os.read_file(certf) or { panic('read cert') }
	assert pem_text.contains('BEGIN CERTIFICATE')
	block, _ := pem.decode(pem_text) or { panic('pem decode') }
	cert := parse_der(block.data) or { panic('parse openssl cert: ${err}') }
	cert.check_host('ossl-interop.example.com') or { panic('host mismatch') }
	cert.check_host('other.example.com') or { return }
	panic('expected hostname mismatch')
}

// test_our_csr_parses_and_verifies_under_openssl checks a V-generated
// CSR parses under openssl and its self-signature verifies there.
fn test_our_csr_parses_and_verifies_under_openssl() {
	bin := openssl_bin()
	if bin == '' {
		return
	}
	_, priv := ecdsa.generate_key(ecdsa.CurveOptions{}) or { panic('keygen: ${err}') }
	point := priv.public_key() or { panic('pubkey: ${err}') }.bytes() or { panic('point: ${err}') }
	spki := encode_spki(EcdsaP256PublicKey{ point: point }) or { panic('spki: ${err}') }
	signer := CertSigner{
		kind:       .ecdsa
		ecdsa_priv: priv
	}
	opts := CsrOptions{
		common_name: 'csr-crosscheck.example.com'
		dns_names:   ['csr-crosscheck.example.com', 'www.csr-crosscheck.example.com']
	}
	csr, der := generate_csr(opts, spki, signer) or { panic('gen: ${err}') }
	tmp := os.temp_dir() + '/ramzara_csr_self.pem'
	os.write_file_array(tmp, pem_block('CERTIFICATE REQUEST', der)) or { panic('write: ${err}') }
	defer {
		os.rm(tmp) or {}
	}
	res := os.exec([bin, 'req', '-in', tmp, '-text', '-noout'])
	assert res.exit_code == 0, 'openssl req -text failed: ${res.output}'
	assert res.output.contains('csr-crosscheck.example.com')
	ver := os.exec([bin, 'req', '-in', tmp, '-noout', '-verify'])
	assert ver.exit_code == 0, 'openssl req -verify failed: ${ver.output}'
	assert ver.output.contains('verify OK')
	_ = csr
}

// test_openssl_csr_parses_and_verifies_in_ramzara checks an
// openssl-generated RSA CSR parses here and its self-signature
// verifies. This also covers the RSA path, which x509 unit tests
// cannot generate natively (the rsa module lives above x509).
fn test_openssl_csr_parses_and_verifies_in_ramzara() {
	bin := openssl_bin()
	if bin == '' {
		return
	}
	dir := os.temp_dir()
	keyf := dir + '/ramzara_csr_ossl_key.pem'
	csrf := dir + '/ramzara_csr_ossl.csr'
	defer {
		os.rm(keyf) or {}
		os.rm(csrf) or {}
	}
	gen := os.exec([bin, 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyf, '-out',
		csrf, '-subj', '/CN=openssl.example.com', '-addext',
		'subjectAltName=DNS:openssl.example.com,DNS:www.openssl.example.com'])
	assert gen.exit_code == 0, 'openssl req -new failed: ${gen.output}'
	text := os.read_file(csrf) or { panic('read csr: ${err}') }
	csr := parse_csr_pem(text) or { panic('parse csr: ${err}') }
	assert csr.common_name == 'openssl.example.com'
	assert 'openssl.example.com' in csr.dns_names
	csr.verify_self() or { panic('verify csr: ${err}') }
}

// test_openssl_signs_our_csr proves a real CA flow end to end: openssl
// signs our CSR, and the issued leaf verifies here against the CA.
fn test_openssl_signs_our_csr() {
	bin := openssl_bin()
	if bin == '' {
		return
	}
	_, priv := ecdsa.generate_key(ecdsa.CurveOptions{}) or { panic('keygen: ${err}') }
	point := priv.public_key() or { panic('pubkey: ${err}') }.bytes() or { panic('point: ${err}') }
	spki := encode_spki(EcdsaP256PublicKey{ point: point }) or { panic('spki: ${err}') }
	signer := CertSigner{
		kind:       .ecdsa
		ecdsa_priv: priv
	}
	opts := CsrOptions{
		common_name: 'leaf.example.com'
		dns_names:   ['leaf.example.com']
	}
	_, csr_der := generate_csr(opts, spki, signer) or { panic('gen: ${err}') }
	dir := os.temp_dir()
	csrf := dir + '/ramzara_ca_csr.pem'
	caf := dir + '/ramzara_ca_cert.pem'
	cak := dir + '/ramzara_ca_key.pem'
	leaff := dir + '/ramzara_ca_leaf.pem'
	defer {
		os.rm(csrf) or {}
		os.rm(caf) or {}
		os.rm(cak) or {}
		os.rm(leaff) or {}
		os.rm(dir + '/ramzara_ca_cert.srl') or {}
	}
	os.write_file_array(csrf, pem_block('CERTIFICATE REQUEST', csr_der)) or { panic('write csr: ${err}') }
	mkca := os.exec([bin, 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
		'-keyout', cak, '-out', caf, '-days', '30', '-nodes', '-subj', '/CN=ramzara-test-ca'])
	assert mkca.exit_code == 0, 'openssl req -x509 failed: ${mkca.output}'
	sign := os.exec([bin, 'x509', '-req', '-in', csrf, '-CA', caf, '-CAkey', cak, '-CAcreateserial',
		'-out', leaff, '-days', '30'])
	assert sign.exit_code == 0, 'openssl x509 -req failed: ${sign.output}'
	leaf_pem := os.read_file(leaff) or { panic('read leaf: ${err}') }
	leaf := parse_pem(leaf_pem) or { panic('parse leaf: ${err}') }
	assert leaf.common_name() == 'leaf.example.com'
	ca_pem := os.read_file(caf) or { panic('read ca: ${err}') }
	ca := parse_pem(ca_pem) or { panic('parse ca: ${err}') }
	chain := build_chain(leaf, [], [ca]) or { panic('chain: ${err}') }
	verify_chain(chain, VerifyOptions{ hostname: 'leaf.example.com' }) or {
		panic('verify: ${err}')
	}
}

// pem_block wraps DER in a PEM text block (local copy: test files must
// stay self-contained because `v test -run-only` compiles only files
// with matching test names).
fn pem_block(block_type string, der []u8) []u8 {
	mut out := '-----BEGIN ${block_type}-----\n'.bytes()
	b64 := csr_pem_b64(der)
	mut i := 0
	for i < b64.len {
		end := if i + 64 < b64.len { i + 64 } else { b64.len }
		out << b64[i..end].bytes()
		out << '\n'.bytes()
		i = end
	}
	out << '-----END ${block_type}-----\n'.bytes()
	return out
}

// csr_pem_b64 base64-encodes DER for PEM output.
fn csr_pem_b64(der []u8) string {
	return base64.encode(der)
}

// Skips without openssl; the same key material is covered without skips by
// test_sig_vgen_mldsa_chains and test_sig_mldsa_chain in tls.
fn test_our_mldsa_der_parses_under_openssl() {
	bin := openssl_bin()
	if bin == '' {
		return
	}
	kinds := [mldsa.Kind.ml_dsa_44, .ml_dsa_65, .ml_dsa_87]
	for kind in kinds {
		priv := mldsa.PrivateKey.generate(kind) or { panic('keygen: ${err}') }
		now := time.now()
		_, der := generate_self_signed_mldsa(CertGenOptions{
			common_name: 'mldsa-crosscheck.example.com'
			dns_names:   ['mldsa-crosscheck.example.com']
			not_before:  now
			not_after:   now.add_days(30)
		}, priv, kind) or { panic('gen: ${err}') }
		tmp := os.temp_dir() + '/tls_mldsa_self.der'
		os.write_file_array(tmp, der) or { panic('write') }
		defer {
			os.rm(tmp) or {}
		}
		res := os.exec([bin, 'x509', '-inform', 'DER', '-in', tmp, '-text', '-noout'])
		assert res.exit_code == 0
		assert res.output.contains('ML-DSA')
		assert res.output.contains('mldsa-crosscheck.example.com')
	}
}

// test_our_mldsa_ca_signed_verifies_under_openssl checks V-generated ML-DSA
// CA/leaf pairs verify under openssl for every variant.
// Skips without openssl; V-side verification of the same shapes is covered
// without skips by test_sig_mldsa_chain in tls.
fn test_our_mldsa_ca_signed_verifies_under_openssl() {
	bin := openssl_bin()
	if bin == '' {
		return
	}
	kinds := [mldsa.Kind.ml_dsa_44, .ml_dsa_65, .ml_dsa_87]
	for kind in kinds {
		ca_priv := mldsa.PrivateKey.generate(kind) or { panic('ca keygen: ${err}') }
		now := time.now()
		ca_cert, ca_der := generate_self_signed_mldsa(CertGenOptions{
			common_name: 'Test ML-DSA CA'
			not_before:  now.add_days(-1)
			not_after:   now.add_days(3650)
			is_ca:       true
		}, ca_priv, kind) or { panic('ca gen: ${err}') }
		leaf_priv := mldsa.PrivateKey.generate(kind) or { panic('leaf keygen: ${err}') }
		leaf_cert, leaf_der := generate_ca_signed_mldsa(CertGenOptions{
			common_name: 'leaf.example.com'
			dns_names:   ['leaf.example.com']
			not_before:  now.add_days(-1)
			not_after:   now.add_days(30)
		}, leaf_priv, kind, &ca_cert, ca_priv, kind) or { panic('leaf gen') }
		_ = leaf_cert
		dir := os.temp_dir()
		ca_pem := dir + '/tls_mldsa_ca.pem'
		leaf_pem := dir + '/tls_mldsa_leaf.pem'
		ca_text := pem.Block{
			block_type: 'CERTIFICATE'
			data:       ca_der
		}.encode(pem.EncodeConfig{}) or { panic('pem encode') }
		leaf_text := pem.Block{
			block_type: 'CERTIFICATE'
			data:       leaf_der
		}.encode(pem.EncodeConfig{}) or { panic('pem encode') }
		os.write_file(ca_pem, ca_text) or { panic('write ca') }
		os.write_file(leaf_pem, leaf_text) or { panic('write leaf') }
		defer {
			os.rm(ca_pem) or {}
			os.rm(leaf_pem) or {}
		}
		res := os.exec([bin, 'verify', '-CAfile', ca_pem, leaf_pem])
		assert res.exit_code == 0, 'openssl verify failed: ${res.output}'
	}
}
