// RamzAra — pure-V TLS/PKI stack and OpenSSL replacement.
// Usage: ramzara <command> [options]
//
// Network:    s_client  s_server
// PKI:        req  x509  verify  crl  ocsp  pkcs12
// Codecs:     enc  dgst  rand  speed
module main

import os

fn main() {
	args := os.args[1..]
	if args.len == 0 {
		usage()
		exit(1)
	}
	cmd := args[0]
	rest := args[1..]
	match cmd {
		's_client' { cmd_s_client(rest) }
		's_server' { cmd_s_server(rest) }
		'req' { cmd_req(rest) }
		'x509' { cmd_x509(rest) }
		'verify' { cmd_verify(rest) }
		'crl' { cmd_crl(rest) }
		'ocsp' { cmd_ocsp(rest) }
		'pkcs12' { cmd_pkcs12(rest) }
		'enc' { cmd_enc(rest) }
		'dgst' { cmd_dgst(rest) }
		'rand' { cmd_rand(rest) }
		'speed' { cmd_speed(rest) }
		'help', '-h', '--help' { usage() }
		else {
			eprintln('ramzara: unknown command `${cmd}`')
			usage()
			exit(1)
		}
	}
}

fn usage() {
	println('usage: ramzara <command> [options]\n')
	println('  s_client -connect host:port [-servername name] [-CAfile f] [-alpn l]')
	println('           [-tls1_2] [-insecure] [-keylog f] [-reconnect n] [-brief] [-waitms ms]')
	println('  s_server -accept port -cert f -key f [-Verify [-CAfile f]] [-www] [-naccept n]')
	println('  req -newkey type -keyout f -out f [-subj /CN=name] [-dns a,b]')
	println('      [-days n] [-ca]')
	println('      types: rsa[:2048|:3072] ec:p-256|p-384|p-521 ed25519')
	println('             ml-dsa-44|65|87 slh-shake|sha2-128s|128f|192s|192f|256s|256f')
	println('  x509 -in cert [-text] [-subject] [-issuer] [-dates] [-fingerprint]')
	println('  verify -CAfile bundle cert [-untrusted chain] [-hostname name]')
	println('         [-crlfile crl] [-ocsp resp]')
	println('  crl -in crl [-text]')
	println('  ocsp -in resp [-text] [-leaf cert -issuer cert]')
	println('  pkcs12 -in file -passin pw [-out prefix]')
	println('  pkcs12 -export -inkey key -in cert [-certfile chain] -out file -passout pw')
	println('         [-pbe aes256|aes128|3des|rc2] [-name friendly]')
	println('  enc -aes-128-gcm|-aes-256-gcm|-chacha20-poly1305 -e|-d -K hex -iv hex')
	println('      [-in f] [-out f] [-aad hex]')
	println('  dgst [-sha256|-sha512|-sha1] [file]')
	println('  rand -hex|-base64 n')
	println('  speed [algo ...] [-seconds n]')
}

// flag_value returns the value of `-name value` or `-name=value`, else ''.
fn flag_value(args []string, name string) string {
	for i, a in args {
		if a == '-${name}' {
			if i + 1 < args.len {
				return args[i + 1]
			}
			return ''
		}
		if a.starts_with('-${name}=') {
			return a[name.len + 2..]
		}
	}
	return ''
}

// has_flag reports whether the bare `-name` flag is present.
fn has_flag(args []string, name string) bool {
	for a in args {
		if a == '-${name}' {
			return true
		}
	}
	return false
}

// rest_args returns positional (non-flag) arguments. Flags listed in
// value_flags consume the following token; other flags stand alone.
fn rest_args(args []string, value_flags []string) []string {
	mut out := []string{}
	mut i := 0
	for i < args.len {
		a := args[i]
		if a.starts_with('-') {
			if a.contains('=') {
				i++
				continue
			}
			name := a[1..]
			if name in value_flags {
				i += 2
				continue
			}
			i++
			continue
		}
		out << a
		i++
	}
	return out
}

@[noreturn]
fn die(msg string) {
	eprintln('ramzara: ${msg}')
	exit(1)
}
