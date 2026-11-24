# Security policy

## Supported versions

RamzAra is pre-1.0. Security fixes land on `master` and are noted in
CHANGELOG.md; there are no maintained release branches yet. Once
versioned releases begin, only the latest minor release will receive
security fixes.

## Reporting a vulnerability

Do **not** open a public issue for a suspected vulnerability. Use
GitHub's private vulnerability reporting on the repository's Security
tab (Advisories → New draft advisory), including:

- what you believe is vulnerable (module, function, protocol flow),
- how to reproduce it (commands, test vectors, or a minimal program),
- your assessment of impact (e.g. handshake bypass, key recovery,
  denial of service, memory-safety).

We aim to acknowledge reports within 7 days and to ship a fix or a
mitigation plan within 30 days, crediting the reporter unless they
prefer otherwise.

## Scope

In scope: the V library (`tls`, `tls12`, `dtls12`, `x509`, `pkcs12`,
`rsa`, `slh_dsa`, `mlkem`, `kat`, `toolkit`), the `ramzara` CLI, and
the CI workflows that gate them.

Out of scope: denial of service through resource exhaustion on
untrusted networks (documented limits apply — see `docs/usage-v.md`),
and vulnerabilities in the V toolchain or standard library itself
(report those upstream to `vlang/v`).

## Hardening already in place

- `-Wimpure-v` clean: no C interop anywhere in module code.
- Memory-stability gate (`tls/leak_test.v`) runs verified loopbacks
  and fails on unbounded RSS growth.
- Fuzz-shape corpus (`tls/testdata/fuzz`) with fail-closed parsing
  requirements.
- Constant-time audit report in `tls/constant_time_audit_report.md`.
