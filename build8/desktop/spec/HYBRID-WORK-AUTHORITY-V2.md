# Hybrid mining work authority V2

Candidate implemented; canonical runtime and miner activation remain IN_PROGRESS.

The coordinator uses an independent Node-role key (role 6), suite
`MUTINY-NODE-HYBRID-ED448-FNDSA1024-V1`, with both Ed448 and the pinned FN-DSA-1024
required. It is not a wallet, release, Continuity, Worker or transport-session
key. Ordinary node work authorization gives no physical eligibility or quorum
weight; a cloud coordinator remains weight zero. No production key was generated.

The node descriptor uses the existing eight-field non-wallet descriptor codec,
with exact role, suite, profile and positive generation. Its work-authority ID
is SHA256(`MUTINY-BUILD8-NODE-AUTHORITY-IDENTITY-V2` || 00 || descriptor).
This is a generation-specific coordinator authorization commitment; it does not
silently replace the separate logical NodeID or the physical TPM identity.

Unsigned authority is canonical CBOR `[2, work_fields_bytes, node_descriptor]`.
`work_fields_bytes` retains the existing eighteen-field deterministic work field
codec, including its internal version 1. Reusing those field encodings does not
accept V1 signatures. The signed envelope is `[2, unsigned_bytes, Ed448Signature114,
FNDSASignature1280]`, bounded to 8 KiB. Unknown/trailing/noncanonical encodings
reject. Its signature-independent authority ID is
SHA256(`MUTINY-BUILD8-HYBRID-WORK-AUTHORITY-ID-V2` || 00 || unsigned_bytes).
Both constituents sign the same SHA512 intent under
`MUTINY-BUILD8-NODE-WORK-AUTHORIZATION-V2` || 00.

The trusted parent supplies the exact coordinator descriptor and WorkContext.
Verification checks network, Genesis, protocol fingerprint, parent, next height,
license, Worker, target, assignment generation, increasing ticket sequence, nonce
range, timestamp/MTP and mining epoch before accepting both signatures. The
existing WorkHeader and SHA256d work byte format remain unchanged; its authority
commitment contains the V2 authority ID. PoW, state execution, licensed assignment
and finality are still separate mandatory checks.

Tests reject both missing/mutated signature halves, wrong role, wrong descriptor
generation, V1 envelopes, replayed tickets, context changes, nonce violations,
all truncated encodings and trailing bytes. Python independently reproduces the
codec/commitments and Ed448 verification; the pristine C implementation verifies
the FN-DSA intent and mutations. The public fixture is 3,690 bytes. Evidence:
`hybrid-work-authority-rust-v1.log`, `hybrid-work-authority-python-v1.json`,
`hybrid-work-authority-c-v1.log`, and `hybrid-work-field-regression-v1.log`.

Remaining: canonical V2 license/coordinator assignment, node-local encrypted
custody and public binding, miner verification and bounded transport integration,
complete block/runtime migration, final domain/fingerprint commitment. There is
no automatic V1/V2 negotiation and this module is not production activated.

## Embedded component evidence

`miner/work_v2.c` is a bounded allocation-free parser/verifier. It checks the
exact pinned coordinator commitment, public-key encodings, both signatures and
the miner's expected work context. Its caller supplies FN-DSA workspace (at least
4,127 bytes); overlapping input/context/output/workspace ranges reject. Node-side
historical MTP, canonical assignment execution and finality remain independent
requirements; the miner parser does not claim to perform full-node validation.

Native testing rejects every truncation and one-bit mutation at each of the
3,690 wire byte positions, context substitution, replay, short workspace, hash
failure and output aliasing. Actual Xtensa compilation with warnings as errors
reports a 656-byte verifier frame, excluding callees. The ROM RAM test on pinned
Miner 1 at 80 MHz measured 424.068 ms per valid hybrid authorization and a
6,496-byte written watermark in a 16 KiB reserved stack. All three positive
samples and targeted negative cases passed; guards and hash-context accounting
remained intact. A written watermark is not proof of maximum stack-pointer depth.

Evidence: `miner-hybrid-work-c-v1.log`, `work-v2-esp32-objects-v1/result.json`,
`esp32-hybrid-work-ram-v1/report.json` and its post-probe public status report.
The previous pending public identity was unchanged after reset. No flash, NVS,
RF or COM4 action occurred. FreeRTOS scheduling/watchdog integration, production
task stack and the complete Wi-Fi mining runtime still need qualification.
