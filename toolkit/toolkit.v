// toolkit generates keys and self-signed certificates using only the ramzara
// modules and the V standard library. The `ramzara` CLI is a thin wrapper
// around this module, so every emitted format is covered by toolkit tests,
// including a real TLS 1.3 loopback per key family (which proves the
// generated keys are accepted by the TLS credential loader).
module toolkit

import crypto.ecdsa
import crypto.ed25519
import crypto.pem
import crypto.sha256
import encoding.hex
import time
import x.crypto.mldsa
import metif12.ramzara.rsa
import metif12.ramzara.slh_dsa
import metif12.ramzara.x509

// KeyType selects the key algorithm for generation.
pub enum KeyType {
	rsa_2048
	rsa_3072
	ecdsa_p256
	ecdsa_p384
	ecdsa_p521
	ed25519
	mldsa_44
	mldsa_65
	mldsa_87
	slh_shake_128s
	slh_shake_128f
	slh_shake_192s
	slh_shake_192f
	slh_shake_256s
	slh_shake_256f
	slh_sha2_128s
	slh_sha2_128f
	slh_sha2_192s
	slh_sha2_192f
	slh_sha2_256s
	slh_sha2_256f
}

// parse_key_type maps a user-facing name (openssl-style or plain) to a KeyType.
pub fn parse_key_type(name string) !KeyType {
	return match name.to_lower() {
		'rsa', 'rsa2048', 'rsa:2048', 'rsa_2048' { .rsa_2048 }
		'rsa3072', 'rsa:3072', 'rsa_3072' { .rsa_3072 }
		'ec', 'ecdsa', 'p256', 'p-256', 'prime256v1', 'ec:p-256' { .ecdsa_p256 }
		'p384', 'p-384', 'secp384r1', 'ec:p-384' { .ecdsa_p384 }
		'p521', 'p-521', 'secp521r1', 'ec:p-521' { .ecdsa_p521 }
		'ed25519', 'ed' { .ed25519 }
		'mldsa44', 'ml-dsa-44', 'mldsa:44' { .mldsa_44 }
		'mldsa65', 'ml-dsa-65', 'mldsa:65' { .mldsa_65 }
		'mldsa87', 'ml-dsa-87', 'mldsa:87' { .mldsa_87 }
		'shake128s', 'slh-shake-128s', 'slh_shake_128s' { .slh_shake_128s }
		'shake128f', 'slh-shake-128f', 'slh_shake_128f' { .slh_shake_128f }
		'shake192s', 'slh-shake-192s', 'slh_shake_192s' { .slh_shake_192s }
		'shake192f', 'slh-shake-192f', 'slh_shake_192f' { .slh_shake_192f }
		'shake256s', 'slh-shake-256s', 'slh_shake_256s' { .slh_shake_256s }
		'shake256f', 'slh-shake-256f', 'slh_shake_256f' { .slh_shake_256f }
		'sha2128s', 'slh-sha2-128s', 'slh_sha2_128s' { .slh_sha2_128s }
		'sha2128f', 'slh-sha2-128f', 'slh_sha2_128f' { .slh_sha2_128f }
		'sha2192s', 'slh-sha2-192s', 'slh_sha2_192s' { .slh_sha2_192s }
		'sha2192f', 'slh-sha2-192f', 'slh_sha2_192f' { .slh_sha2_192f }
		'sha2256s', 'slh-sha2-256s', 'slh_sha2_256s' { .slh_sha2_256s }
		'sha2256f', 'slh-sha2-256f', 'slh_sha2_256f' { .slh_sha2_256f }
		else { return error('toolkit: unknown key type `${name}`') }
	}
}

// Generated is a generated key + self-signed certificate pair.
pub struct Generated {
pub:
	key_pem  string
	cert_pem string
	cert     x509.Certificate
}

// generate_self_signed creates a key of the named type and a self-signed
// certificate for `cn` (added to the SAN list when `dns` is empty).
// It mirrors `openssl req -x509`: CA certs get keyCertSign/crlSign usage,
// leaves get digitalSignature/keyEncipherment plus serverAuth EKU.
pub fn generate_self_signed(key_type string, cn string, dns []string, days int, is_ca bool) !Generated {
	kt := parse_key_type(key_type)!
	mut sans := dns.clone()
	if sans.len == 0 && cn != '' {
		sans << cn
	}
	now := time.now()
	mut ku := x509.ku_digital_signature | x509.ku_key_encipherment
	mut eku := [x509.oid_eku_server_auth]
	if is_ca {
		ku = x509.ku_digital_signature | x509.ku_key_cert_sign | x509.ku_crl_sign
		eku = []string{}
	}
	opts := x509.CertGenOptions{
		common_name:   cn
		dns_names:     sans
		not_before:    now
		not_after:     now.add_days(days)
		is_ca:         is_ca
		has_key_usage: true
		key_usage:     ku
		ext_key_usage: eku
	}
	match kt {
		.rsa_2048, .rsa_3072 {
			bits := if kt == .rsa_2048 { 2048 } else { 3072 }
			key := rsa.generate_key(rsa.KeyGenOptions{ bits: bits })!
			cert, cert_der := rsa.generate_self_signed(opts, key)!
			key_pem := key.to_pem_pkcs8()!
			return finish_pair(cert, cert_der, key_pem)!
		}
		.ecdsa_p256, .ecdsa_p384, .ecdsa_p521 {
			nid := match kt {
				.ecdsa_p256 { ecdsa.Nid.prime256v1 }
				.ecdsa_p384 { ecdsa.Nid.secp384r1 }
				else { ecdsa.Nid.secp521r1 }
			}
			_, priv := ecdsa.generate_key(ecdsa.CurveOptions{ nid: nid }) or {
				return err
			}
			cert, cert_der := x509.generate_self_signed(opts, priv)!
			scalar := priv.bytes()!
			key_pem := pem_encode('EC PRIVATE KEY', sec1_der(scalar, ec_curve_oid(kt)))!
			return finish_pair(cert, cert_der, key_pem)!
		}
		.ed25519 {
			_, priv := ed25519.generate_key() or { return err }
			cert, cert_der := x509.generate_self_signed_ed25519(opts, priv)!
			key_pem := pem_encode('PRIVATE KEY', pkcs8_der(oid_ed25519(), priv.seed()))!
			return finish_pair(cert, cert_der, key_pem)!
		}
		.mldsa_44, .mldsa_65, .mldsa_87 {
			kind := match kt {
				.mldsa_44 { mldsa.Kind.ml_dsa_44 }
				.mldsa_65 { mldsa.Kind.ml_dsa_65 }
				else { mldsa.Kind.ml_dsa_87 }
			}
			priv := mldsa.PrivateKey.generate(kind)!
			cert, cert_der := x509.generate_self_signed_mldsa(opts, priv, kind)!
			key_pem := pem_encode('PRIVATE KEY', pkcs8_der(mldsa_oid(kind), priv.seed()))!
			return finish_pair(cert, cert_der, key_pem)!
		}
		else {
			params := slh_params(kt)
			priv, _ := slh_dsa.keygen(params)!
			cert, cert_der := x509.generate_self_signed_slh_dsa(opts, priv, params)!
			key_pem := pem_encode('PRIVATE KEY', pkcs8_der(slh_oid(params), priv.bytes()))!
			return finish_pair(cert, cert_der, key_pem)!
		}
	}
}

// CsrPair bundles a generated private key with its self-signed CSR.
pub struct CsrPair {
pub:
	key_pem string
	csr_pem string
	csr     x509.Csr
}

// generate_csr creates a key of the named type and a PKCS#10
// certification request for `cn` (added to the SAN list when `dns`
// is empty). It mirrors `openssl req -new`: the key stays local,
// the CSR goes to the CA. The CSR self-signature is verified before
// returning, so a malformed request fails here, not at the CA.
pub fn generate_csr(key_type string, cn string, dns []string) !CsrPair {
	kt := parse_key_type(key_type)!
	mut sans := dns.clone()
	if sans.len == 0 && cn != '' {
		sans << cn
	}
	opts := x509.CsrOptions{
		common_name: cn
		dns_names:   sans
	}
	match kt {
		.rsa_2048, .rsa_3072 {
			bits := if kt == .rsa_2048 { 2048 } else { 3072 }
			key := rsa.generate_key(rsa.KeyGenOptions{ bits: bits })!
			pubkey := x509.RsaPublicKey{
				der: key.public_key().to_pkcs1_der()
			}
			signer := x509.CertSigner{
				kind:  .rsa
				rsa_n: key.n
				rsa_e: key.e
				rsa_d: key.d
			}
			spki := x509.encode_spki(pubkey)!
			csr, csr_der := x509.generate_csr(opts, spki, signer)!
			key_pem := key.to_pem_pkcs8()!
			return finish_csr_pair(csr, csr_der, key_pem)!
		}
		.ecdsa_p256, .ecdsa_p384, .ecdsa_p521 {
			nid := match kt {
				.ecdsa_p256 { ecdsa.Nid.prime256v1 }
				.ecdsa_p384 { ecdsa.Nid.secp384r1 }
				else { ecdsa.Nid.secp521r1 }
			}
			_, priv := ecdsa.generate_key(ecdsa.CurveOptions{ nid: nid }) or {
				return err
			}
			point := priv.public_key()!.bytes()!
			pubkey := match kt {
				.ecdsa_p256 { x509.PublicKey(x509.EcdsaP256PublicKey{ point: point }) }
				.ecdsa_p384 { x509.PublicKey(x509.EcdsaP384PublicKey{ point: point }) }
				else { x509.PublicKey(x509.EcdsaP521PublicKey{ point: point }) }
			}
			signer := x509.CertSigner{
				kind:       .ecdsa
				ecdsa_priv: priv
			}
			spki := x509.encode_spki(pubkey)!
			csr, csr_der := x509.generate_csr(opts, spki, signer)!
			scalar := priv.bytes()!
			key_pem := pem_encode('EC PRIVATE KEY', sec1_der(scalar, ec_curve_oid(kt)))!
			return finish_csr_pair(csr, csr_der, key_pem)!
		}
		.ed25519 {
			_, priv := ed25519.generate_key() or { return err }
			pubkey := x509.PublicKey(x509.Ed25519PublicKey{ raw: priv.public_key() })
			signer := x509.CertSigner{
				kind:    .ed25519
				ed_priv: priv
			}
			spki := x509.encode_spki(pubkey)!
			csr, csr_der := x509.generate_csr(opts, spki, signer)!
			key_pem := pem_encode('PRIVATE KEY', pkcs8_der(oid_ed25519(), priv.seed()))!
			return finish_csr_pair(csr, csr_der, key_pem)!
		}
		.mldsa_44, .mldsa_65, .mldsa_87 {
			kind := match kt {
				.mldsa_44 { mldsa.Kind.ml_dsa_44 }
				.mldsa_65 { mldsa.Kind.ml_dsa_65 }
				else { mldsa.Kind.ml_dsa_87 }
			}
			priv := mldsa.PrivateKey.generate(kind)!
			raw := priv.public_key().bytes()
			pubkey := match kt {
				.mldsa_44 { x509.PublicKey(x509.MlDsa44PublicKey{ raw: raw }) }
				.mldsa_65 { x509.PublicKey(x509.MlDsa65PublicKey{ raw: raw }) }
				else { x509.PublicKey(x509.MlDsa87PublicKey{ raw: raw }) }
			}
			signer := x509.CertSigner{
				kind:       .mldsa
				mldsa_priv: priv
				mldsa_kind: kind
			}
			spki := x509.encode_spki(pubkey)!
			csr, csr_der := x509.generate_csr(opts, spki, signer)!
			key_pem := pem_encode('PRIVATE KEY', pkcs8_der(mldsa_oid(kind), priv.seed()))!
			return finish_csr_pair(csr, csr_der, key_pem)!
		}
		else {
			params := slh_params(kt)
			priv, _ := slh_dsa.keygen(params)!
			raw := priv.public_key().bytes()
			pubkey := match kt {
				.slh_shake_128s { x509.PublicKey(x509.SlhDsaShake128sPublicKey{ raw: raw }) }
				.slh_shake_128f { x509.PublicKey(x509.SlhDsaShake128fPublicKey{ raw: raw }) }
				.slh_shake_192s { x509.PublicKey(x509.SlhDsaShake192sPublicKey{ raw: raw }) }
				.slh_shake_192f { x509.PublicKey(x509.SlhDsaShake192fPublicKey{ raw: raw }) }
				.slh_shake_256s { x509.PublicKey(x509.SlhDsaShake256sPublicKey{ raw: raw }) }
				.slh_shake_256f { x509.PublicKey(x509.SlhDsaShake256fPublicKey{ raw: raw }) }
				.slh_sha2_128s { x509.PublicKey(x509.SlhDsaSha2128sPublicKey{ raw: raw }) }
				.slh_sha2_128f { x509.PublicKey(x509.SlhDsaSha2128fPublicKey{ raw: raw }) }
				.slh_sha2_192s { x509.PublicKey(x509.SlhDsaSha2192sPublicKey{ raw: raw }) }
				.slh_sha2_192f { x509.PublicKey(x509.SlhDsaSha2192fPublicKey{ raw: raw }) }
				.slh_sha2_256s { x509.PublicKey(x509.SlhDsaSha2256sPublicKey{ raw: raw }) }
				else { x509.PublicKey(x509.SlhDsaSha2256fPublicKey{ raw: raw }) }
			}
			signer := x509.CertSigner{
				kind:       .slh_dsa
				slh_priv:   priv
				slh_params: params
			}
			spki := x509.encode_spki(pubkey)!
			csr, csr_der := x509.generate_csr(opts, spki, signer)!
			key_pem := pem_encode('PRIVATE KEY', pkcs8_der(slh_oid(params), priv.bytes()))!
			return finish_csr_pair(csr, csr_der, key_pem)!
		}
	}
}

// finish_csr_pair encodes the CSR DER as PEM and bundles the pair.
fn finish_csr_pair(csr x509.Csr, csr_der []u8, key_pem string) !CsrPair {
	csr_pem := pem_encode('CERTIFICATE REQUEST', csr_der)!
	return CsrPair{
		key_pem: key_pem
		csr_pem: csr_pem
		csr:     csr
	}
}

// finish_pair encodes the certificate DER as PEM and bundles the pair.
fn finish_pair(cert x509.Certificate, cert_der []u8, key_pem string) !Generated {
	cert_pem := pem_encode('CERTIFICATE', cert_der)!
	return Generated{
		key_pem:  key_pem
		cert_pem: cert_pem
		cert:     cert
	}
}

// slh_params maps the SLH-DSA KeyType variants to parameter sets.
fn slh_params(kt KeyType) slh_dsa.ParameterSet {
	return match kt {
		.slh_shake_128s { .shake_128s }
		.slh_shake_128f { .shake_128f }
		.slh_shake_192s { .shake_192s }
		.slh_shake_192f { .shake_192f }
		.slh_shake_256s { .shake_256s }
		.slh_shake_256f { .shake_256f }
		.slh_sha2_128s { .sha2_128s }
		.slh_sha2_128f { .sha2_128f }
		.slh_sha2_192s { .sha2_192s }
		.slh_sha2_192f { .sha2_192f }
		.slh_sha2_256s { .sha2_256s }
		else { .sha2_256f }
	}
}

// ec_curve_oid returns the DER content bytes of the named-curve OID.
fn ec_curve_oid(kt KeyType) []u8 {
	return match kt {
		.ecdsa_p384 { [u8(0x2b), 0x81, 0x04, 0x00, 0x22] }
		.ecdsa_p521 { [u8(0x2b), 0x81, 0x04, 0x00, 0x23] }
		// prime256v1 (1.2.840.10045.3.1.7): 1.2 -> 0x2a, 840 -> 86 48,
		// 10045 -> ce 3d. (A previous revision emitted the 1.3.132
		// prefix here, which OpenSSL rejects as an unknown curve.)
		else { [u8(0x2a), 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] }
	}
}

// oid_ed25519 returns the DER content bytes of id-Ed25519.
fn oid_ed25519() []u8 {
	return [u8(0x2b), 0x65, 0x70]
}

// mldsa_oid returns the DER content bytes of the ML-DSA variant OID.
fn mldsa_oid(kind mldsa.Kind) []u8 {
	tail := match kind {
		.ml_dsa_44 { u8(0x11) }
		.ml_dsa_65 { u8(0x12) }
		else { u8(0x13) }
	}
	return [u8(0x60), 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, tail]
}

// slh_oid returns the DER content bytes of the SLH-DSA parameter-set OID
// (same table the TLS stack verifies against).
fn slh_oid(params slh_dsa.ParameterSet) []u8 {
	tail := match params {
		.sha2_128s { u8(0x14) }
		.sha2_128f { u8(0x15) }
		.sha2_192s { u8(0x16) }
		.sha2_192f { u8(0x17) }
		.sha2_256s { u8(0x18) }
		.sha2_256f { u8(0x19) }
		.shake_128s { u8(0x1a) }
		.shake_128f { u8(0x1b) }
		.shake_192s { u8(0x1c) }
		.shake_192f { u8(0x1d) }
		.shake_256s { u8(0x1e) }
		.shake_256f { u8(0x1f) }
	}
	return [u8(0x60), 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, tail]
}

// der_len encodes a DER length.
fn der_len(n int) []u8 {
	if n < 0x80 {
		return [u8(n)]
	}
	mut v := n
	mut rev := []u8{}
	for v > 0 {
		rev << u8(v & 0xff)
		v >>= 8
	}
	mut out := [u8(0x80 | rev.len)]
	for i := rev.len - 1; i >= 0; i-- {
		out << rev[i]
	}
	return out
}

// der_tlv wraps content in a tag-length-value triple.
fn der_tlv(tag u8, content []u8) []u8 {
	mut out := [tag]
	out << der_len(content.len)
	out << content
	return out
}

// der_oid wraps raw OID content bytes in an OID TLV.
fn der_oid(content []u8) []u8 {
	return der_tlv(0x06, content)
}

// sec1_der builds a SEC1 ECPrivateKey for a raw scalar and curve OID.
fn sec1_der(scalar []u8, curve_oid []u8) []u8 {
	mut body := der_tlv(0x02, [u8(1)])
	body << der_tlv(0x04, scalar)
	mut oid_wrap := [u8(0xa0)]
	oid_tlv := der_oid(curve_oid)
	oid_wrap << der_len(oid_tlv.len)
	oid_wrap << oid_tlv
	body << oid_wrap
	return der_tlv(0x30, body)
}

// pkcs8_der builds a PKCS#8 PrivateKeyInfo with a parameters-less
// single-OID AlgorithmIdentifier (exactly what the TLS loader accepts).
fn pkcs8_der(alg_oid []u8, private_octets []u8) []u8 {
	mut body := der_tlv(0x02, [u8(0)])
	body << der_tlv(0x30, der_oid(alg_oid))
	body << der_tlv(0x04, private_octets)
	return der_tlv(0x30, body)
}

// pem_encode wraps DER bytes in a PEM block.
pub fn pem_encode(block_type string, der []u8) !string {
	return pem.Block{
		block_type: block_type
		data:       der
	}.encode(pem.EncodeConfig{})!
}

// cert_text renders a human-readable summary of a certificate
// (used by `ramzara x509 -text`).
pub fn cert_text(c x509.Certificate) string {
	mut b := []u8{}
	b << 'Subject: ${name_text(c.subject)}\n'.bytes()
	b << 'Issuer:  ${name_text(c.issuer)}\n'.bytes()
	b << 'Serial:  ${hex.encode(c.serial)}\n'.bytes()
	b << 'Valid:   ${c.not_before} .. ${c.not_after}\n'.bytes()
	if c.dns_names.len > 0 {
		b << 'SAN DNS: ${c.dns_names.join(', ')}\n'.bytes()
	}
	if c.ip_addresses.len > 0 {
		mut ips := []string{}
		for ip in c.ip_addresses {
			ips << hex.encode(ip)
		}
		b << 'SAN IP:  ${ips.join(', ')}\n'.bytes()
	}
	b << 'CA:      ${c.is_ca}\n'.bytes()
	if c.has_key_usage {
		b << 'KU:      0x${c.key_usage:04x}\n'.bytes()
	}
	if c.ext_key_usage.len > 0 {
		b << 'EKU:     ${c.ext_key_usage.join(', ')}\n'.bytes()
	}
	b << 'SigAlg:  ${c.sig_alg_oid}\n'.bytes()
	b << 'SHA256:  ${hex.encode(sha256.sum(c.raw))}\n'.bytes()
	return b.bytestr()
}

// name_text renders a DN map in short form.
fn name_text(m map[string]string) string {
	if m.len == 0 {
		return '(empty)'
	}
	mut parts := []string{}
	for oid, val in m {
		parts << '${short_name(oid)}=${val}'
	}
	return parts.join(', ')
}

// short_name maps common DN OIDs to abbreviations.
fn short_name(oid string) string {
	return match oid {
		'2.5.4.3' { 'CN' }
		'2.5.4.10' { 'O' }
		'2.5.4.11' { 'OU' }
		'2.5.4.6' { 'C' }
		'2.5.4.8' { 'ST' }
		'2.5.4.7' { 'L' }
		else { oid }
	}
}
