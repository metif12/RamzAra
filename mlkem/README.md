# mlkem

Pure-V ML-KEM (FIPS 203) post-quantum key encapsulation, vendored from
`x.crypto.mlkem` so the package builds on any V toolchain (stdlib newer
than 0.5.2 ships its own copy).

All three parameter sets: `ml_kem_512`, `ml_kem_768`, `ml_kem_1024`.

```v
import metif12.ramzara.mlkem

ek, dk := mlkem.keygen()! // ML-KEM-768
ct, ss1 := mlkem.encaps(ek)!
ss2 := mlkem.decaps(dk, ct)!
assert ss1 == ss2
```

Variant-explicit form: `generate_keypair(variant)`, `encapsulate(pk)`,
`decapsulate(ct, sk)`. Lower-level K-PKE / polynomial / NTT helpers are
also public (`kpke_keygen/encrypt/decrypt`, `ntt`, `sample_cbd2/3`).

Used by `tls` for pure `ML-KEM-768/1024` groups and the hybrid
`X25519MLKEM768` key exchange. Correctness is pinned by KAT tests
(`mlkem_kat_test.v`, `mlkem_variants_test.v`, `mlkem_kpke_test.v`,
`mlkem_ntt_test.v`) plus harsh differential tests.
