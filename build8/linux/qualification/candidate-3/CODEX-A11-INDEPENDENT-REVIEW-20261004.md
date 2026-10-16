# Independent A11 RSA review and representative-bound regression

Reviewed parent 81f3696 + 12c68c1 and final range fix c85033a (local import 5f5f683). This is public synthetic software evidence. The parser remains in test support at this source identity; promotion requires the separate executable witness/admission review. Production physical host entry remains disabled until its launch dependency is satisfied.

**Major before promotion, resolved:** consensus/tests/support/x509_syntax.rs previously checked exact signature width, then invoked rsa 0.9.10 generic PSS verification. That dependency's src/pss.rs:126-138 omits the s < n check; algorithms/rsa.rs:21-22 computes modular exponentiation. Its typed verify_digest at pss.rs:153 has the missing check. A same-width s+n therefore verifies the same encoded PSS message as s. This is alternate RSA representative acceptance, not an arbitrary-message forgery. Strict DER and exact TBS alone do not reject the alternate signature integer.

Regressions at endorsement_rsa_x509.rs:83-120 use only the explicitly public fixture. Both first verify canonical s < n over the exact message, then construct same-width s+n >= n. SHA-256 exhibits this at counter 1, SHA-384 at counter 0; both signatures are 256 bytes. Pre-fix bda2545 compiles and fails both refusal assertions (0 passed, 2 failed, 3 filtered, exit 101). Final x509_syntax.rs:480-485 rejects the out-of-range integer before key verification. The same fixture/message/signature hashes pass after the fix. Full successor RSA and X.509 checks pass 5 + 14 = 19 tests, no failed/ignored/filtered tests. Width, exact hash/TBS, wrong algorithm/key family, corrupted signature/CRL, revocation, trust-root digest, PSS hash/MGF/salt/default parameters and strict DER controls remain exercised.

Dependency review independently matched all 10 pinned archive checksums against consensus/Cargo.lock and all 418 archive files against extracted registry source; details in rsa-closure-independent.json. Read num-bigint-dig build.rs (fixed cfg), num-traits build.rs (autocfg compile-only total_cmp probe), libm build.rs/configure.rs (target/feature configuration), and autocfg probe implementation (configured Rust compiler, library/LLVM-IR output under OUT_DIR, no probe binary execution). No new Cargo feature is introduced; rsa remains a pinned dev dependency at this identity. The public n/d/p/q fixture and deterministic test RNG are labelled synthetic and confer no production signing authority. This is local checksum/source review, not remote provenance attestation.

No additional concrete bypass was found in the reviewed algorithm pairing/parameter/key-bound code. Coverage remains a public 2048-bit fixture; this result does not establish manufacturer trust, physical activation, larger-key performance, hardware execution, offline retention, or production readiness. The regression must follow the parser if moved into executable code; do not transfer this test result silently across a later source change.

Closed logs and SHA-256: D:/Mutiny/build8-targets/hyg3/takeover-20261004/successor-focused-evidence-index.json. Prior failed/partial evidence is preserved. Exact commands:

```text
cargo test --manifest-path consensus/Cargo.toml --offline --locked --test endorsement_rsa_x509 pss_same_width_representative -- --test-threads=1 --nocapture
cargo test --manifest-path consensus/Cargo.toml --offline --locked --test endorsement_rsa_x509 --test endorsement_x509 -- --test-threads=1 --nocapture
```
