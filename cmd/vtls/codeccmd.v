// enc, dgst, rand, speed: symmetric ciphers, digests, randomness, benchmarks.
module main

import crypto.aes
import crypto.rand
import crypto.sha1
import crypto.sha256
import crypto.sha512
import encoding.base64
import encoding.hex
import os
import time
import x.crypto.chacha20
import x.crypto.chacha20poly1305
import metif12.vtls.mlkem
import metif12.vtls.rsa

fn cmd_enc(args []string) {
	want_gcm128 := has_flag(args, 'aes-128-gcm')
	want_gcm256 := has_flag(args, 'aes-256-gcm')
	want_chacha := has_flag(args, 'chacha20-poly1305')
	mut nalg := 0
	if want_gcm128 {
		nalg++
	}
	if want_gcm256 {
		nalg++
	}
	if want_chacha {
		nalg++
	}
	if nalg != 1 {
		die('enc: exactly one of -aes-128-gcm, -aes-256-gcm, -chacha20-poly1305')
	}
	enc_mode := has_flag(args, 'e')
	dec_mode := has_flag(args, 'd')
	if enc_mode == dec_mode {
		die('enc: exactly one of -e, -d')
	}
	key := hex.decode(flag_value(args, 'K')) or { die('enc: bad -K hex: ${err}') }
	nonce := hex.decode(flag_value(args, 'iv')) or { die('enc: bad -iv hex: ${err}') }
	aad_flag := flag_value(args, 'aad')
	aad := if aad_flag == '' {
		[]u8{}
	} else {
		hex.decode(aad_flag) or {
			die('enc: bad -aad hex: ${err}')
		}
	}
	if want_gcm128 && key.len != 16 {
		die('enc: aes-128 needs a 16-byte -K')
	}
	if want_gcm256 && key.len != 32 {
		die('enc: aes-256 needs a 32-byte -K')
	}
	if nonce.len != 12 {
		die('enc: nonce (-iv) must be 12 bytes')
	}
	input := if flag_value(args, 'in') != '' {
		os.read_bytes(flag_value(args, 'in')) or { die('enc: ${err}') }
	} else {
		read_all_stdin()
	}
	out := if want_chacha {
		if enc_mode {
			chacha20poly1305.encrypt(input, key, nonce, aad, chacha20.Options{}) or {
				die('enc: ${err}')
			}
		} else {
			chacha20poly1305.decrypt(input, key, nonce, aad, chacha20.Options{}) or {
				die('enc: ${err}')
			}
		}
	} else {
		g := aes.new_aes_gcm(key) or { die('enc: ${err}') }
		if enc_mode {
			g.encrypt(input, nonce, aad) or { die('enc: ${err}') }
		} else {
			g.decrypt(input, nonce, aad) or { die('enc: ${err}') }
		}
	}
	outf := flag_value(args, 'out')
	if outf != '' {
		os.write_bytes(outf, out) or { die('enc: ${err}') }
		return
	}
	mut stdout := os.stdout()
	stdout.write(out) or { die('enc: ${err}') }
}

fn cmd_dgst(args []string) {
	algo := if has_flag(args, 'sha512') {
		'sha512'
	} else if has_flag(args, 'sha1') {
		'sha1'
	} else {
		'sha256'
	}
	pos := rest_args(args, []string{})
	data := if pos.len > 0 {
		os.read_bytes(pos[0]) or { die('dgst: ${err}') }
	} else {
		read_all_stdin()
	}
	digest := match algo {
		'sha512' { sha512.sum512(data) }
		'sha1' { sha1.sum(data) }
		else { sha256.sum(data) }
	}
	name := if pos.len > 0 { '  ${pos[0]}' } else { '' }
	println('${algo.to_upper()}${name} = ${hex.encode(digest)}')
}

fn cmd_rand(args []string) {
	n := flag_value(args, 'hex').int()
	b64 := flag_value(args, 'base64').int()
	count := if n > 0 {
		n
	} else if b64 > 0 {
		b64
	} else {
		die('rand: -hex n or -base64 n')
	}
	buf := rand.bytes(count) or { die('rand: ${err}') }
	if n > 0 {
		println(hex.encode(buf))
	} else {
		println(base64.encode(buf))
	}
}

fn cmd_speed(args []string) {
	secs := flag_value(args, 'seconds').int()
	budget_ms := if secs > 0 { i64(secs) * 1000 } else { i64(1000) }
	algos := rest_args(args, ['seconds'])
	run_all := algos.len == 0
	if run_all || 'sha256' in algos {
		msg := []u8{len: 1024, init: 0x61}
		ops := bench_ms(budget_ms, fn [msg] () {
			_ = sha256.sum(msg)
		})
		println('sha256-1k: ${ops} ops in budget (${ops * 1024 / 1024} MiB equivalent/s scaled)')
	}
	if run_all || 'aes-128-gcm' in algos {
		g := aes.new_aes_gcm([]u8{len: 16}) or { die('speed: ${err}') }
		pt := []u8{len: 1024, init: 0x61}
		nonce := []u8{len: 12}
		ops := bench_ms(budget_ms, fn [g, pt, nonce] () {
			_ = g.encrypt(pt, nonce, []u8{}) or { return }
		})
		println('aes-128-gcm-1k: ${ops} ops')
	}
	if run_all || 'aes-256-gcm' in algos {
		g := aes.new_aes_gcm([]u8{len: 32}) or { die('speed: ${err}') }
		pt := []u8{len: 1024, init: 0x61}
		nonce := []u8{len: 12}
		ops := bench_ms(budget_ms, fn [g, pt, nonce] () {
			_ = g.encrypt(pt, nonce, []u8{}) or { return }
		})
		println('aes-256-gcm-1k: ${ops} ops')
	}
	if run_all || 'chacha20-poly1305' in algos {
		key := []u8{len: 32}
		nonce := []u8{len: 12}
		pt := []u8{len: 1024, init: 0x61}
		ops := bench_ms(budget_ms, fn [key, nonce, pt] () {
			_ = chacha20poly1305.encrypt(pt, key, nonce, []u8{}, chacha20.Options{}) or {
				return
			}
		})
		println('chacha20-poly1305-1k: ${ops} ops')
	}
	if run_all || 'rand' in algos {
		ops := bench_ms(budget_ms, fn () {
			_ = rand.bytes(32) or { return }
		})
		println('rand-32: ${ops} ops')
	}
	if run_all || 'mlkem-768' in algos {
		ops := bench_ms(budget_ms, fn () {
			pk, _ := mlkem.generate_keypair(.ml_kem_768) or { return }
			ct, _ := mlkem.encapsulate(pk) or { return }
			_ = ct
		})
		println('mlkem-768-encaps: ${ops} ops')
	}
	if run_all || 'rsa-2048' in algos {
		key := rsa.generate_key(rsa.KeyGenOptions{ bits: 1024 }) or {
			die('speed: ${err}')
		}
		digest := sha256.sum('speed benchmark message'.bytes())
		ops := bench_ms(budget_ms, fn [key, digest] () {
			sig := key.sign_pkcs1_v15(digest, .sha256) or { return }
			key.public_key().verify_pkcs1_v15(digest, sig, .sha256) or { return }
		})
		println('rsa-1024-sign+verify: ${ops} ops (1024-bit keeps the default run short)')
	}
}

// bench_ms runs f for up to budget_ms milliseconds and returns iterations.
fn bench_ms(budget_ms i64, f fn ()) i64 {
	start := time.now().unix_milli()
	mut ops := i64(0)
	for {
		f()
		ops++
		if ops % 16 == 0 && time.now().unix_milli() - start >= budget_ms {
			break
		}
	}
	return ops
}
