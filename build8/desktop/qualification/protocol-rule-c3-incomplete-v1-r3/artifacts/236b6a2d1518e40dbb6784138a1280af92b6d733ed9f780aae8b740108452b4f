# Miner Enrollment V2 integration candidate

Status: IN_PROGRESS, pre-Genesis. This codec implements the approved fresh
Ed448 Worker and BOTH_REQUIRED hybrid owner model. It does not authorize device
cutover, seal the ProtocolFingerprint, or qualify persistent identity handling.

All arrays below use deterministic minimal CBOR, definite lengths, no tags,
trailing data, implicit defaults or alternate suites. NetworkID is 0x4d555401.
Worker suite is the exact text `MUTINY-WORKER-ED448-V1`. Public Worker keys are
57-byte strict Ed448 keys; Worker signatures are 114 bytes over a 64-byte intent
using raw Ed448, empty context, no Ed448ph.

The unsigned binding is the 16-element array:

1. version = 2
2. NetworkID
3. GenesisID (32 bytes)
4. ProtocolFingerprint (32 bytes)
5. LicenseID (32 bytes)
6. OwnerAuthDescriptorID (32 bytes)
7. owner authorization generation (positive u64)
8. Worker suite text
9. Worker public key (57 bytes)
10. WorkerID (32 bytes)
11. coordinator NodeID/profile commitment (32 bytes)
12. configuration generation (positive u64)
13. physical device MAC (6 bytes, public association metadata, never entropy)
14. assignment generation (positive u64)
15. effective MiningEpoch (u64)
16. valid-until canonical height (u64; zero means no expiry)

Unsigned encoding is bounded at 512 bytes. The signed envelope is a four-element
array of byte strings: unsigned bytes, owner Ed448 signature (114), owner
FN-DSA-1024 signature (1280), Worker possession signature (114). Envelope bound
is 2048 bytes. The authoritative owner descriptor is resolved separately from
trusted supervised/parent state; it is not supplied as self-declared authority
inside this envelope.

OwnerAuthDescriptorID = SHA-256 of ASCII
`MUTINY-BUILD8-OWNER-AUTH-DESCRIPTOR-V2`, one NUL byte, then the complete canonical
wallet-owner descriptor from the shared crypto core. That descriptor binds
network, owner role, generation, exact wallet hybrid suite and pinned FN-DSA
profile, Ed448 public key and FN-DSA public key. BOTH_REQUIRED is the only
acceptance policy for that exact suite. Descriptor generation must match the
binding; neither a recovery nor release descriptor is accepted. The current
wallet descriptor is the nine-field numeric-suite/numeric-policy codec in
WALLET-HYBRID-TRANSACTION-V2.md; the superseded eight-field candidate is rejected.

WorkerID = SHA-256 of ASCII `MUTINY-BUILD8-WORKER-ID-V2`, one NUL byte, then CBOR
`[2, NetworkID, GenesisID, LicenseID, WorkerSuiteText, WorkerPublicKey]`.
This preserves the existing 32-byte consensus identity width and introduces an
explicit V2 domain. It does not silently change the protocol hash-width model.

The owner intent is SHA-512 of ASCII
`MUTINY-BUILD8-MINER-ENROLLMENT-OWNER-V2`, one NUL byte, then unsigned binding
bytes. Both owner algorithms sign this same intent. Worker possession uses the
same construction with `MUTINY-BUILD8-WORKER-POSSESSION-V2`. The Worker signs the
complete binding, not only its public key or WorkerID. Neither domain authorizes
transactions, firmware releases, Continuity votes or arbitrary host messages.

Validation compares the complete binding to independently trusted expected
context, rederives both public commitments, validates exact suites/keys, and
verifies all three signatures. Genesis additionally requires assignment and
configuration generation 1, effective epoch 0 and no expiry. Later reassignment
must use the ordinary canonical state transition's generation and timing rules;
this verifier alone cannot grant state-transition authority.

Rust and independent allocation-free C implementations reject V1 and malformed
encodings. Python independently checks canonical bytes, identities, intents and
both Ed448 signatures; FN-DSA is cross-verified by the pinned Rust and C sources.
The fixtures are synthetic and contain public material only. Final Worker keys
must still be generated on device from qualified hardware entropy after the
final network context is locked. Crash-safe storage, anti-downgrade state,
firmware integration and fleet cutover remain separate mandatory gates.

## Activation storage integration candidate

`miner/enrollment_v2_store.c` provides a bounded public activation layer. Its
caller must first restore the immutable device-private V2 candidate and supply
that candidate's expected binding and owner descriptor. Calls must be serialized
across the entire read/validate/commit sequence. This layer never receives or
exports the Worker seed, and it cannot substitute for private-candidate storage.

Activation validates the incoming signed binding, durably writes the complete
binding record, reads it back, repeats all signature/context checks, then commits
a separate 40-byte activation marker. The marker is `B8V2ACT` plus byte 1 followed
by SHA-256 of `MUTINY-BUILD8-ENROLLMENT-ACTIVATION-V2`, NUL, and complete signed
enrollment bytes. Only a matching marker plus a fully verified binding restores
ACTIVE. An absent marker is PENDING; malformed committed state is FAULT. Neither
condition enables mining or selects V1. An existing different binding is never
silently overwritten. Repeating the exact completed activation is idempotent.

The native fault-injection backend tests every possible write prefix, failures
before writes, completed writes followed by lost acknowledgements, corrupted
committed bytes, wrong context and attempted legacy activation. These establish
the application selection behavior, not physical flash durability or resistance
to malicious flash erasure. No miner flash was modified by these tests.

The intended device backend must commit each key before reporting success and
propagate storage errors without erase/reinitialization fallback. ESP-IDF 5.5.5
documents NVS power-loss recovery, with possible loss of the pair being written;
it also documents that unencrypted NVS can be altered with physical flash access.
Those properties require explicit integration and capacity/power qualification:
[NVS documentation](https://docs.espressif.com/projects/esp-idf/en/v5.5.5/esp32/api-reference/storage/nvs_flash.html).

## Device-private candidate integration

`worker_v2_candidate.c` generates a separate 57-byte Ed448 seed through a trusted
device-local entropy callback. It never imports the V1 seed. The private record
contains its explicit format, seed, complete unsigned binding, owner descriptor,
Worker possession proof and a damage-detection digest. The digest is not a claim
of encrypted or physically tamper-resistant storage. Every load derives the
public key again and verifies the complete candidate and possession proof.

The candidate is committed and read back before public enrollment material is
returned. An existing valid candidate is reused only for identical context;
read errors, malformed records and context changes never trigger fresh key
generation or overwrite. Failed operations wipe local seed-containing buffers
and clear public output. There is no erase, private export or V1 import API.
Constant-byte and constant-word RNG output are rejected as catastrophic faults;
these checks do not establish entropy quality by themselves.

The ESP-IDF adapter uses a dedicated V2 namespace and mutex. It enables the
manufacturer's non-RF entropy source only before RF/ADC/I2S startup and disables
it immediately after the fill. The peripheral-start latch uses the same mutex;
the application may start those subsystems only after successfully latching.
NVS initialization errors fail without erasure. This source compiles against the
real ESP-IDF headers but is not linked into the installed V1 application.
[RNG prerequisites](https://docs.espressif.com/projects/esp-idf/en/v5.5.5/esp32/api-reference/system/random.html).

The native synthetic tests cover entropy failure/stuck output, every truncated
or single-byte-corrupted private record, interrupted commit/readback and exact
reboot recovery, plus the complete owner-authorized activation path. A RAM-only
probe ran the same portable candidate and activation code on Miner 1 using
explicit public test entropy bytes 0..56 and RAM-backed storage. It did not call
the hardware RNG or NVS. Preparation took 1.146 seconds and the repeated-check
activation sequence 2.358 seconds at 80 MHz. Written-stack high-water was 12,144
bytes of a reserved 16 KiB stack with intact guards. This measurement is for the
tested path, not all-input or FreeRTOS qualification. Runtime integration must
use a dedicated stack with additional measured margin; the legacy main task's
stack must not be assumed sufficient.

## Storage bounds

Under the current numeric descriptor, maximum Genesis sizes are 313 bytes
unsigned binding, 1911 bytes owner descriptor, 1832 bytes signed wire enrollment,
and 2439 bytes private record. Widening all four additional context integers
(configuration generation, assignment generation, effective epoch and expiry)
to u64 maxima gives 345, 1864 and 2471 bytes respectively for unsigned binding,
signed wire enrollment and private record. Buffer capacities are not padding.
The maximum release-policy codec size remains 5632 bytes.

The candidate local public-binding record is exactly 1523 bytes: the eight-byte
marker `42 38 56 32 42 4e 44 02`, followed by the three unchanged canonical
signature byte strings (116, 1283 and 116 bytes, including their CBOR headers).
It omits only the unsigned body already stored in the immutable private
candidate. Restoration reconstructs the exact four-item canonical wire array
using that candidate's expected unsigned bytes. All owner hybrid signatures,
Worker possession, exact context and activation-marker checks then run over the
full original wire binding. The activation marker still hashes the full wire
bytes. This is storage deduplication, not a weaker enrollment authorization or a
new network codec. Wrong expected context fails validation; old local storage
formats are refused rather than silently migrated. Private records and seeds
are unchanged.

Espressif's offline NVS generator fits the modeled identity, one current policy,
and either a second policy or a pending release into the existing 24 KiB NVS
partition with its reserved free page. Concurrent rotation plus pending release
does not fit. The firmware must serialize those maintenance operations and
qualify cleanup/reclaim behavior; it must not increase the partition or erase
old identity to hide the constraint. A 1024-byte system-storage allowance in the
model is an assumption requiring runtime validation. The generator result is
not a garbage-collection or physical power-cut test.

The current RAM-backed test executes pinned ESP-IDF storage/garbage-collection
code with a 2471-byte private candidate, 1523-byte stored public binding, both
5632-byte policy slots, a 73-byte parked observation checkpoint, preserved legacy
records and the modeled 1024-byte system allowance. Ordinary accounting first
parks its fully acknowledged checkpoint under maintenance ownership; it cannot
discard pending work. The maintenance owner keeps mining/session authority
retired until update or policy rotation and retired-policy cleanup finish.
The independent cryptographic tests verify complete binding reconstruction;
storage-only fault tests use dummy public payloads and do not confer authority.
Physical usage, power loss, final owner-task sequencing and stack/watchdog
qualification remain required.
