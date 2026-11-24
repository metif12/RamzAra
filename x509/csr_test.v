module x509

import crypto.ecdsa
import crypto.ed25519
import encoding.base64
import metif12.ramzara.slh_dsa
import x.crypto.mldsa

// csr_test_key_ecdsa generates a P-256 key and its SPKI + signer pair.
fn csr_test_key_ecdsa() !(CertSigner, []u8) {
	_, priv := ecdsa.generate_key(ecdsa.CurveOptions{})!
	point := priv.public_key()!.bytes()!
	spki := encode_spki(EcdsaP256PublicKey{ point: point })!
	signer := CertSigner{
		kind:       .ecdsa
		ecdsa_priv: priv
	}
	return signer, spki
}

fn test_csr_ecdsa_roundtrip() {
	signer, spki := csr_test_key_ecdsa()!
	opts := CsrOptions{
		common_name: 'csr.example.com'
		dns_names:   ['csr.example.com', 'www.csr.example.com']
	}
	csr, der := generate_csr(opts, spki, signer)!
	assert der.len > 0
	parsed := parse_csr_der(der)!
	assert parsed.common_name == 'csr.example.com'
	assert parsed.dns_names == ['csr.example.com', 'www.csr.example.com']
	assert parsed.spki == spki
	assert parsed.signature == csr.signature
	assert parsed.tbs == csr.tbs
	parsed.verify_self()!
}

fn test_csr_pem_roundtrip() {
	signer, spki := csr_test_key_ecdsa()!
	opts := CsrOptions{
		common_name: 'pem.example.com'
	}
	_, der := generate_csr(opts, spki, signer)!
	block := '-----BEGIN CERTIFICATE REQUEST-----\n' + encode_pem_body(der) + '-----END CERTIFICATE REQUEST-----\n'
	parsed := parse_csr_pem(block)!
	assert parsed.common_name == 'pem.example.com'
	parsed.verify_self()!
}

// encode_pem_body base64-encodes DER with 64-char lines (test helper;
// production PEM writing lives in toolkit.pem_encode).
fn encode_pem_body(der []u8) string {
	b64 := base64.encode(der)
	mut out := ''
	for i := 0; i < b64.len; i += 64 {
		end := if i + 64 < b64.len { i + 64 } else { b64.len }
		out += b64[i..end] + '\n'
	}
	return out
}

fn test_csr_no_san_no_cn() {
	signer, spki := csr_test_key_ecdsa()!
	opts := CsrOptions{}
	parsed, _ := generate_csr(opts, spki, signer)!
	assert parsed.common_name == ''
	assert parsed.dns_names.len == 0
	parsed.verify_self()!
}

fn test_csr_tampered_signature_fails() {
	signer, spki := csr_test_key_ecdsa()!
	opts := CsrOptions{
		common_name: 'tamper.example.com'
	}
	csr, _ := generate_csr(opts, spki, signer)!
	mut bad_sig := csr.signature.clone()
	bad_sig[0] ^= 0x80
	mut bad := csr
	bad.signature = bad_sig
	if _ := bad.verify_self() {
		assert false, 'tampered CSR signature must fail'
	}
}

fn test_csr_tampered_tbs_fails() {
	signer, spki := csr_test_key_ecdsa()!
	opts := CsrOptions{
		common_name: 'tamper.example.com'
	}
	csr, _ := generate_csr(opts, spki, signer)!
	mut bad_tbs := csr.tbs.clone()
	bad_tbs[bad_tbs.len - 1] ^= 0x01
	mut bad := csr
	bad.tbs = bad_tbs
	if _ := bad.verify_self() {
		assert false, 'tampered CSR TBS must fail'
	}
}

fn test_csr_wrong_version_rejected() {
	signer, spki := csr_test_key_ecdsa()!
	opts := CsrOptions{
		common_name: 'version.example.com'
	}
	_, der := generate_csr(opts, spki, signer)!
	// walk to the version INTEGER inside CertificationRequestInfo and
	// flip 0 -> 1: outer SEQ, CRI SEQ, then the INTEGER TLV.
	outer := expect_tag(der, 0, 0x30, 'csr')!
	cri_tlv, _ := split_tlv(outer, 0)!
	cri := expect_tag(cri_tlv, 0, 0x30, 'cri')!
	ver_tlv, _ := split_tlv(cri, 0)!
	mut bad := der.clone()
	// version TLV sits at: outer header + cri header; its last content
	// byte is the INTEGER value.
	outer_hl := der.len - outer.len
	cri_hl := (cri_tlv.len - cri.len)
	ver_pos := outer_hl + cri_hl + ver_tlv.len - 1
	bad[ver_pos] = 1
	if _ := parse_csr_der(bad) {
		assert false, 'CSR version 1 must be rejected'
	}
}

fn test_csr_wrong_key_fails() {
	signer_a, _ := csr_test_key_ecdsa()!
	_, spki_b := csr_test_key_ecdsa()!
	opts := CsrOptions{
		common_name: 'mismatch.example.com'
	}
	// sign TBS-for-B with key A: build manually to force the mismatch
	csr_b, _ := generate_csr(opts, spki_b, signer_a)!
	// signature was made by A over B's TBS: self-verify with B's key fails
	if _ := csr_b.verify_self() {
		assert false, 'cross-key CSR signature must fail'
	}
}

fn test_csr_ed25519_roundtrip() {
	_, priv := ed25519.generate_key() or { panic('ed keygen: ${err}') }
	raw := priv.public_key()
	spki := encode_spki(Ed25519PublicKey{ raw: raw })!
	signer := CertSigner{
		kind:    .ed25519
		ed_priv: priv
	}
	opts := CsrOptions{
		common_name: 'ed.example.com'
	}
	parsed, der := generate_csr(opts, spki, signer)!
	assert parsed.common_name == 'ed.example.com'
	// PEM shape check
	block := '-----BEGIN CERTIFICATE REQUEST-----\n' + encode_pem_body(der) + '-----END CERTIFICATE REQUEST-----\n'
	parsed2 := parse_csr_pem(block)!
	parsed2.verify_self()!
	parsed.verify_self()!
}

fn test_csr_mldsa_roundtrip() {
	priv := mldsa.PrivateKey.generate(.ml_dsa_44)!
	raw := priv.public_key().bytes()
	spki := encode_spki(MlDsa44PublicKey{ raw: raw })!
	signer := CertSigner{
		kind:       .mldsa
		mldsa_priv: priv
		mldsa_kind: .ml_dsa_44
	}
	opts := CsrOptions{
		common_name: 'mldsa.example.com'
		dns_names:   ['mldsa.example.com']
	}
	parsed, _ := generate_csr(opts, spki, signer)!
	parsed.verify_self()!
}

fn test_csr_slh_dsa_roundtrip() {
	priv, _ := slh_dsa.keygen(.shake_128s)!
	raw := priv.public_key().bytes()
	spki := encode_spki(SlhDsaShake128sPublicKey{ raw: raw })!
	signer := CertSigner{
		kind:       .slh_dsa
		slh_priv:   priv
		slh_params: .shake_128s
	}
	opts := CsrOptions{
		common_name: 'slh.example.com'
	}
	parsed, _ := generate_csr(opts, spki, signer)!
	parsed.verify_self()!
}
