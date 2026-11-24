module x509

import crypto.ecdsa
import crypto.ed25519
import crypto.pem
import crypto.sha256
import crypto.sha512
import crypto.subtle
import math.big
import metif12.ramzara.slh_dsa
import x.crypto.mldsa

// PKCS#10 CertificationRequest (RFC 2986) generation, parsing and
// self-signature verification. A CSR carries the subject name, the
// subject public key and requested extensions (SAN only for now),
// signed by the subject key itself; a CA later turns it into a
// certificate after its own verification.

// oid_extension_request identifies the CSR attributes entry that
// carries requested extensions (RFC 2986 §5.4 / RFC 5272 §3.1).
const oid_extension_request = '1.2.840.113549.1.9.14'

// CsrOptions selects the subject identity of a generated CSR.
pub struct CsrOptions {
pub:
	common_name string
	dns_names   []string
	ip_names    [][]u8
}

// Csr is a parsed PKCS#10 CertificationRequest.
pub struct Csr {
pub mut:
	raw         []u8 // full CertificationRequest DER
	tbs         []u8 // CertificationRequestInfo DER (the signed bytes)
	common_name string
	dns_names   []string
	ip_names    [][]u8
	spki        []u8 // subjectPublicKeyInfo DER
	sig_alg     []u8 // signatureAlgorithm SEQ content (OID TLV + params)
	sig_alg_oid string
	signature   []u8
}

// csr_subject_name builds a CN-only RDNSequence, the same shape the
// certificate generators emit.
fn csr_subject_name(cn string) []u8 {
	mut content := []u8{}
	if cn.len > 0 {
		mut cn_attr_content := []u8{}
		for b in encode_oid('2.5.4.3') { cn_attr_content << b }
		for b in der_utf8(cn) { cn_attr_content << b }
		cn_attr := der_seq(cn_attr_content)
		set_content := der_set(cn_attr)
		for b in set_content { content << b }
	}
	return der_seq(content)
}

// csr_requested_attributes builds the [0] attributes entry: an
// extensionRequest attribute carrying a SAN extension when DNS/IP
// names are requested, otherwise an empty context element.
// OpenSSL emits the same shape (`openssl req -text` shows
// "Requested Extensions"), so round-trips stay parseable on both sides.
fn csr_requested_attributes(dns_names []string, ip_names [][]u8) []u8 {
	if dns_names.len == 0 && ip_names.len == 0 {
		return der_ctx(0, []u8{})
	}
	mut attr_content := []u8{}
	for b in encode_oid(oid_extension_request) { attr_content << b }
	mut exts := []u8{}
	for b in san_ext(dns_names, ip_names) { exts << b }
	attr_content << der_set(der_seq(exts))
	return der_ctx(0, der_seq(attr_content))
}

// sig_alg_id wraps a signature-algorithm OID the way the certificate
// generators do: bare OID, except RSA which carries NULL parameters
// (required by RFC 8017 / expected by OpenSSL).
fn csr_sig_alg_id(sig_alg_oid string, is_rsa bool) []u8 {
	mut content := []u8{}
	for b in encode_oid(sig_alg_oid) { content << b }
	if is_rsa {
		for b in der_tlv(0x05, []u8{}) { content << b }
	}
	return der_seq(content)
}

// generate_csr builds and self-signs a PKCS#10 request for spki.
// signer must match the subject key; sign_tbs selects the signature
// scheme (and its OID) per key type. The result is parsed back
// before returning, so a malformed encoding fails here, not at the CA.
pub fn generate_csr(opts CsrOptions, spki []u8, signer CertSigner) !(Csr, []u8) {
	check_ip_names(opts.ip_names)!
	version := der_int([u8(0)])
	subject := csr_subject_name(opts.common_name)
	attrs := csr_requested_attributes(opts.dns_names, opts.ip_names)
	mut tbs_content := []u8{}
	for b in version { tbs_content << b }
	for b in subject { tbs_content << b }
	for b in spki { tbs_content << b }
	for b in attrs { tbs_content << b }
	tbs_der := der_seq(tbs_content)
	sig, sig_alg_oid := sign_tbs(signer, tbs_der)!
	is_rsa := signer.kind == .rsa
	sig_alg_id := csr_sig_alg_id(sig_alg_oid, is_rsa)
	bsig := der_bitstr(sig)
	mut csr_content := []u8{}
	for b in tbs_der { csr_content << b }
	for b in sig_alg_id { csr_content << b }
	for b in bsig { csr_content << b }
	csr_der := der_seq(csr_content)
	csr := parse_csr_der(csr_der)!
	return csr, csr_der
}

// parse_csr_pem reads the first CERTIFICATE REQUEST block of PEM text.
pub fn parse_csr_pem(pem_text string) !Csr {
	mut rest := pem_text
	for {
		block, next := pem.decode(rest) or { return error('x509: no CERTIFICATE REQUEST PEM block found') }
		if block.block_type == 'CERTIFICATE REQUEST' {
			return parse_csr_der(block.data)
		}
		if next.trim_space() == '' {
			return error('x509: no CERTIFICATE REQUEST PEM block found')
		}
		rest = next
	}
}

// parse_csr_der parses one complete DER-encoded CertificationRequest
// without verifying it (use verify_self for the self-signature).
pub fn parse_csr_der(der []u8) !Csr {
	if der.len == 0 || der.len > 65536 {
		return error('x509: bad CSR length')
	}
	total := tlv_total_len(der, 0)!
	if total != der.len {
		return error('x509: trailing CSR data')
	}
	outer := expect_tag(der, 0, 0x30, 'CertificationRequest')!
	mut pos := 0
	tbs_tlv, after_tbs := split_tlv(outer, pos)!
	pos = after_tbs
	tbs_content := expect_tag(tbs_tlv, 0, 0x30, 'CertificationRequestInfo')!
	mut tpos := 0
	version_content := expect_tag(tbs_content, tpos, 0x02, 'CSR version')!
	if version_content.len != 1 || version_content[0] != 0 {
		return error('x509: unsupported CSR version')
	}
	tpos = skip_tlv(tbs_content, tpos)!
	name_content := expect_tag(tbs_content[tpos..], 0, 0x30, 'CSR subject')!
	tpos += tlv_total_len(tbs_content, tpos)!
	attrs_map := parse_name(name_content)!
	spki_tlv, after_spki := split_tlv(tbs_content, tpos)!
	tpos = after_spki
	cn := attrs_map[oid_common_name] or { '' }
	// attributes [0] is optional; when present it may carry the
	// extensionRequest attribute with requested extensions.
	mut dns_names := []string{}
	mut ip_names := [][]u8{}
	if tpos < tbs_content.len {
		if tbs_content[tpos] != 0xa0 {
			return error('x509: expected CSR attributes [0]')
		}
		attrs_len := tlv_total_len(tbs_content, tpos)!
		attrs_outer := expect_tag(tbs_content[tpos..], 0, 0xa0, 'CSR attributes')!
		mut apos := 0
		for apos < attrs_outer.len {
			attr_tlv, next_attr := split_tlv(attrs_outer, apos)!
			apos = next_attr
			attr := expect_tag(attr_tlv, 0, 0x30, 'CSR attribute')!
			attr_oid, oid_len := der_oid(attr) or { return err }
			if attr_oid != oid_extension_request {
				continue
			}
			vals, _ := split_tlv(attr, oid_len)!
			values := expect_tag(vals, 0, 0x31, 'attribute values')!
			// The extensionRequest attribute carries a single
			// Extensions SEQUENCE in the SET (the shape OpenSSL
			// emits); its items are full Extension SEQUENCES.
			exts_seq, after_exts := split_tlv(values, 0)!
			if after_exts != values.len {
				return error('x509: trailing CSR attribute data')
			}
			exts := expect_tag(exts_seq, 0, 0x30, 'requested extensions')!
			mut epos := 0
			for epos < exts.len {
				ext_tlv, next_ext := split_tlv(exts, epos)!
				epos = next_ext
				ext := expect_tag(ext_tlv, 0, 0x30, 'requested extension')!
				ext_oid, ext_oid_len := der_oid(ext) or { return err }
				if ext_oid != oid_san {
					continue
				}
				rest_ext := ext[ext_oid_len..]
				// optional critical BOOLEAN, then extnValue OCTET STRING
				mut ipos := 0
				if rest_ext.len > 0 && rest_ext[0] == 0x01 {
					ipos = skip_tlv(rest_ext, 0)!
				}
				octets := expect_tag(rest_ext[ipos..], 0, 0x04, 'extension value')!
				d, ips := parse_san(octets)!
				dns_names << d
				ip_names << ips
			}
		}
		if apos != attrs_outer.len {
			return error('x509: trailing CSR attribute data')
		}
		tpos += attrs_len
	}
	if tpos != tbs_content.len {
		return error('x509: trailing CSR info data')
	}
	// signatureAlgorithm + signature BIT STRING follow the TBS element
	sig_alg_tlv, after_alg := split_tlv(outer, pos)!
	pos = after_alg
	// sig_alg holds the signatureAlgorithm SEQUENCE content (OID TLV
	// plus any parameters), matching what the verify.v helpers expect.
	sig_alg := expect_tag(sig_alg_tlv, 0, 0x30, 'CSR signatureAlgorithm')!
	sig_alg_oid, _ := der_oid(sig_alg) or { return err }
	sig_tlv, after_sig := split_tlv(outer, pos)!
	pos = after_sig
	sig_bs := expect_tag(sig_tlv, 0, 0x03, 'CSR signature')!
	if sig_bs.len < 1 || sig_bs[0] != 0 {
		return error('x509: bad CSR signature padding')
	}
	if pos != outer.len {
		return error('x509: trailing CSR data')
	}
	// exact TBS bytes for signature verification
	tbs_start := der.len - outer.len
	tbs_end := tbs_start + tlv_total_len(outer, 0)!
	return Csr{
		raw:         der.clone()
		tbs:         der[tbs_start..tbs_end].clone()
		common_name: cn
		dns_names:   dns_names
		ip_names:    ip_names
		spki:        spki_tlv.clone()
		sig_alg:     sig_alg.clone()
		sig_alg_oid: sig_alg_oid
		signature:   sig_bs[1..].clone()
	}
}

// verify_self verifies the CSR self-signature against the subject key
// in its own SPKI. The signature OID must agree with the key type
// (ECDSA scheme with the matching curve, RSA PKCS#1 v1.5, Ed25519,
// ML-DSA or SLH-DSA variant); anything else fails closed.
pub fn (c &Csr) verify_self() ! {
	spki_content := expect_tag(c.spki, 0, 0x30, 'csr spki')!
	pk := parse_spki(spki_content)!
	match c.sig_alg_oid {
		'1.2.840.10045.4.3.2', '1.2.840.10045.4.3.3', '1.2.840.10045.4.3.4' {
			point := match pk {
				EcdsaP256PublicKey {
					if c.sig_alg_oid != '1.2.840.10045.4.3.2' {
						return error('x509: ECDSA sigAlg/key mismatch')
					}
					pk.point
				}
				EcdsaP384PublicKey {
					if c.sig_alg_oid != '1.2.840.10045.4.3.3' {
						return error('x509: ECDSA sigAlg/key mismatch')
					}
					pk.point
				}
				EcdsaP521PublicKey {
					if c.sig_alg_oid != '1.2.840.10045.4.3.4' {
						return error('x509: ECDSA sigAlg/key mismatch')
					}
					pk.point
				}
				else {
					return error('x509: ECDSA sigAlg/key mismatch')
				}
			}
			epk := ecdsa.PublicKey.from_uncompressed_bytes(point)!
			ok := epk.verify(c.tbs, c.signature) or { return error('x509: bad CSR ECDSA signature') }
			if !ok {
				return error('x509: bad CSR ECDSA signature')
			}
		}
		'1.2.840.113549.1.1.11', '1.2.840.113549.1.1.12', '1.2.840.113549.1.1.13' {
			rsa_pk := match pk {
				RsaPublicKey { pk }
				else { return error('x509: RSA sigAlg/key mismatch') }
			}
			h := match c.sig_alg_oid {
				'1.2.840.113549.1.1.11' { RsaCrlHash.sha256 }
				'1.2.840.113549.1.1.12' { RsaCrlHash.sha384 }
				else { RsaCrlHash.sha512 }
			}
			digest := match h {
				.sha256 { sha256.sum256(c.tbs) }
				.sha384 { sha512.sum384(c.tbs) }
				.sha512 { sha512.sum512(c.tbs) }
			}
			n, e := rsa_pub_numbers(rsa_pk.der)!
			k := (n.bit_len() + 7) / 8
			if c.signature.len != k {
				return error('x509: bad CSR RSA signature length')
			}
			s_int := big.integer_from_bytes(c.signature)
			m_int := s_int.mod_pow(e, n)
			em := rsa_int_to_bytes(m_int, k)!
			expected := rsa_pkcs1_expected(digest, h, k)!
			if subtle.constant_time_compare(em, expected) != 1 {
				return error('x509: bad CSR RSA signature')
			}
		}
		oid_ed25519 {
			ed_pk := match pk {
				Ed25519PublicKey { pk }
				else { return error('x509: Ed25519 sigAlg/key mismatch') }
			}
			ok := ed25519.verify(ed_pk.raw, c.tbs, c.signature) or {
				return error('x509: bad CSR Ed25519 signature')
			}
			if !ok {
				return error('x509: bad CSR Ed25519 signature')
			}
		}
		oid_mldsa_44, oid_mldsa_65, oid_mldsa_87 {
			kind := mldsa_kind_from_sigalg(c.sig_alg)!
			raw := match pk {
				MlDsa44PublicKey {
					if kind != .ml_dsa_44 {
						return error('x509: ML-DSA sigAlg/key mismatch')
					}
					pk.raw
				}
				MlDsa65PublicKey {
					if kind != .ml_dsa_65 {
						return error('x509: ML-DSA sigAlg/key mismatch')
					}
					pk.raw
				}
				MlDsa87PublicKey {
					if kind != .ml_dsa_87 {
						return error('x509: ML-DSA sigAlg/key mismatch')
					}
					pk.raw
				}
				else {
					return error('x509: ML-DSA sigAlg/key mismatch')
				}
			}
			mpk := mldsa.PublicKey.from_bytes(raw, kind)!
			ok := mpk.verify(c.tbs, c.signature, mldsa.SignerOpts{}) or {
				return error('x509: bad CSR ML-DSA signature')
			}
			if !ok {
				return error('x509: bad CSR ML-DSA signature')
			}
		}
		else {
			params := slh_dsa_params_from_sigalg(c.sig_alg) or {
				return error('x509: unsupported CSR signature algorithm')
			}
			// any SLH-DSA variant key is accepted here; parse_spki
			// already length-checked the raw key for its own set and
			// the OID selects the verification parameter set.
			raw := match pk {
				SlhDsaSha2128sPublicKey { pk.raw }
				SlhDsaSha2128fPublicKey { pk.raw }
				SlhDsaSha2192sPublicKey { pk.raw }
				SlhDsaSha2192fPublicKey { pk.raw }
				SlhDsaSha2256sPublicKey { pk.raw }
				SlhDsaSha2256fPublicKey { pk.raw }
				SlhDsaShake128sPublicKey { pk.raw }
				SlhDsaShake128fPublicKey { pk.raw }
				SlhDsaShake192sPublicKey { pk.raw }
				SlhDsaShake192fPublicKey { pk.raw }
				SlhDsaShake256sPublicKey { pk.raw }
				SlhDsaShake256fPublicKey { pk.raw }
				else { return error('x509: SLH-DSA sigAlg/key mismatch') }
			}
			spk := slh_dsa.public_key_from_bytes(params, raw) or {
				return error('x509: bad CSR SLH-DSA public key')
			}
			if !slh_dsa.verify(c.tbs, c.signature, [], spk) {
				return error('x509: bad CSR SLH-DSA signature')
			}
		}
	}
}
