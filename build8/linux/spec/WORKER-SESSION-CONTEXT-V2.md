# Worker V2 handshake context candidate

This context/transcript codec and its host handshake are under qualification.
They cannot issue work or activate firmware. The handshake returns opaque
confirmed key material and supports bounded encrypted host frames; device key
custody and runtime integration remain in progress. Historical V1 Ed25519 sessions
are not a fallback.

The candidate uses the repository's X448 + ML-KEM-1024 ephemeral profile. Worker
identity remains the V2 enrollment's Ed448 key; coordinator identity is the pinned
hybrid Node descriptor. Authentication uses separate Worker and Node signing
domains and verifies the full transcript, followed by directional key
confirmation. This does not claim PQ Worker identity authentication. The
authentication components verify
Node signatures under `MUTINY-BUILD8-NODE-WORKER-SESSION-V2` (Ed448 and FN-DSA
both required) and Worker signatures under
`MUTINY-BUILD8-WORKER-SESSION-POSSESSION-V2` (the enrolled Ed448 key). Each signs
SHA-512(domain || zero delimiter || 64-byte transcript digest). Neither component
alone establishes traffic keys or confirms peer possession of the ephemeral
secrets; the separate handshake below supplies those steps.

The caller supplies a previously verified and currently active canonical V2
License/Worker binding, plus an independently trusted Node descriptor. The codec
requires the descriptor's existing Node-authority identity hash to equal the
binding's coordinator field. A descriptor received from an unauthenticated peer
is not a trust source. Its generation is committed by the descriptor bytes.

ContextID is SHA-512 over the ASCII domain
`MUTINY-BUILD8-WORKER-SESSION-CONTEXT-V2`, a zero delimiter, and:

1. version u8 = 2, candidate suite u8 = 1;
2. NetworkID u32 big endian;
3. canonical unsigned binding length u16 big endian and exact binding bytes;
4. Node descriptor length u16 big endian and exact descriptor bytes.

The binding is bounded at 512 bytes and descriptor at 2,048 bytes. Committing the
complete binding includes owner authority/generation, Worker public key/identity,
coordinator, configuration and assignment generations, device MAC, activation
epoch and inclusion-deadline height. Parent churn does not inherently invalidate
a session; the application must recheck active canonical authority. The deadline
height (`valid_until_height`) is not a session expiry (amendment WP-Q17 below).

Hello is exactly 1,722 bytes: version 2, suite 1, ContextID 64 bytes, Worker nonce
32 bytes, Worker X448 public key 56 bytes, Worker ML-KEM-1024 public key 1,568
bytes. Response body is exactly 1,656 bytes: coordinator nonce 32 bytes,
coordinator X448 public key 56 bytes, ML-KEM ciphertext 1,568 bytes. These are
public handshake inputs; private keys never enter the codec.

Transcript is SHA-512 over domain
`MUTINY-BUILD8-WORKER-SESSION-TRANSCRIPT-V2`, a zero delimiter, exact Hello and
exact response body. Fixed lengths prevent concatenation ambiguity. Unknown
version/suite, wrong context, trailing/short bytes, zero nonces and reflected
nonces reject. Structural nonzero X448 checks do not replace real agreement and
all-zero shared-secret rejection. KEM validation and implicit-rejection handling
belong to the actual primitive/Finished path; this codec claims neither.

The host handshake uses a 60-second monotonic lifetime from local start,
checked around expensive operations. This is a bounded qualification setting,
not final ESP32 latency qualification. The 600-second LoRa handshake lifetime is
not inherited. Scheduler, admission capacity and hardware deadlines still need
integration. No production gate or final ProtocolFingerprint is enabled.

Evidence: `worker-session-context-v3.json` covers three Rust tests and independent
Python preimage reproduction. `worker-session-auth-v1.json` covers Worker
signatures through Rust/C and independent Python Ed448 verification. The current
hybrid domain matrix in `hybrid-domain-matrix-v3.json` covers all 25 Node/wallet/
release/Continuity/transport enum domains with 25 positives and 600 rejected
transplants per path (Rust, Python Ed448 and pristine C FN-DSA). Worker Ed448-only
authentication is deliberately tested separately from that hybrid matrix.

`worker_handshake_v2` combines the actual pinned X448 agreement and ML-KEM-1024
encapsulation/decapsulation outputs. HKDF-SHA-512 uses the transcript digest as
salt, X448 shared secret (56 bytes) followed by KEM secret (32 bytes) as input,
and `MUTINY-BUILD8-WORKER-SESSION-KEYS-V2` plus a zero delimiter as info. Its
104 bytes split into Worker transmit key 32, Node transmit key 32, Worker nonce
prefix 4, Node nonce prefix 4 and SessionID 32. Directional ownership is reversed
at the Node. Secrets use the existing zeroizing custody wrappers and KDF closure.

Node response appends Ed448 114 bytes and FN-DSA 1,280 bytes to the response body
(3,050 bytes total). Worker authenticates the Node before calling its device-local
signer. The Worker finish contains Ed448 114 bytes plus a 16-byte Finished tag.
Node verifies both before returning its own 16-byte Finished tag. Worker must
verify that tag before obtaining confirmed material. The signer adapter has no
seed export or generic-domain signing method; its output is reverified.

Finished uses ChaCha20-Poly1305 with empty plaintext, directional key, and nonce
prefix4 || zero64. Associated data is
`MUTINY-BUILD8-WORKER-SESSION-FINISHED-V2` || zero delimiter || sender u8
(Worker 0, Node 1) || transcript64. Nonce sequence zero is reserved for this
single Finished in each direction; future traffic must begin at one. Pending
states are consumed on success or failure and are neither cloneable nor
serializable. No retry or session resumption reuses ephemeral keys.

`worker-handshake-windows-v1.json` records seven context/authentication/handshake
tests and independent Python reproduction of the fixed public HKDF/Finished
vector. Real handshake secrets are not exported. This is component evidence;
complete runtime and physical-device qualification remain open.

The host frame candidate converts confirmed material into a channel within
60 seconds of confirmation and rechecks the supplied current canonical binding
at conversion and every send/receive. The caller must obtain that state from its
trusted actor, never from the incoming packet. Each frame has version u8 = 2,
sender u8 (Worker 0, Node 1), SessionID 32 bytes, sequence u64 big endian, and
plaintext length u16 big endian, then ciphertext and its 16-byte Poly1305 tag.
Payload length is 1..16,384 bytes; maximum frame is 16,444 bytes. This holds the
bounded 8-KiB signed work envelope plus application framing without changing
consensus object bounds.

Each direction starts sequence at one and requires the exact next sequence over
ordered TCP. Nonce is directional prefix4 || sequence u64BE. AAD is
`MUTINY-BUILD8-WORKER-SESSION-FRAME-V2` || zero delimiter || exact 44-byte header.
Limits are 1,048,576 frames and 64 MiB of plaintext per direction, and one hour
from handshake confirmation. Exhaustion, expiry, authority mismatch or invalid
inbound frames close the channel and explicitly clear both traffic key buffers.
No resume, clone or serialization API restores old sequence/key state. A fresh
handshake is required. This transport authentication never establishes PoW,
licenses, receipt settlement, or canonical finality.

Windows V2 qualification includes ten tests with actual synthetic handshakes
and frame mutation/replay/boundary cases. Linux V1's six passing sanitizer tests
cover the earlier handshake snapshot only; the frame-inclusive Linux V2 run is
tracked separately. These distinctions must be preserved in qualification.

## Embedded frame qualification V1

The Linux V2 host handshake/frame snapshot passed ten tests. The embedded C frame candidate passed three Windows tests and three Linux tests with C ASAN/UBSAN/leak detection (Rust harness uninstrumented). Exact C wire bytes agree with the Rust and independent Python public vectors. ESP32 Xtensa 14.2.0 compilation passes with warnings as errors; seal/open each use a 400-byte static stack frame, excluding callees, interrupts and RTOS overhead. This is component evidence, not an installed application or physical runtime qualification. Reports: `qualification/worker-handshake-linux-v2.json`, `qualification/worker-session-frames-v1.json`, `qualification/worker-frame-c-windows-v1.json`, `qualification/worker-frame-c-linux-v1.json`, `qualification/worker-frames-esp32-v1/report.json`.

## Device-private session signing candidate V1

`build8_v2_candidate_sign_session` restores the private candidate, compares its exact unsigned binding to trusted current authority, and requires ACTIVE storage with genuine dual owner and Worker verification. It signs only the session possession domain and post-verifies the signature. No entropy, storage write or private export occurs. Pending, damaged, unavailable, mismatched or expired authority fails with cleared signature output. The enclosing trusted handshake must authenticate the pinned Node response first; this signing adapter does not itself authenticate a Node or establish shared keys. The current private/public persistence remains the initial Genesis-binding candidate; later assignment migration is not qualified by these tests.

Windows and Linux pass four enrollment/private-custody tests; Linux instruments C with ASAN/UBSAN/leak detection, while Rust is uninstrumented. An independent Ed448 implementation verifies the session signature and rejects the enrollment domain and mutated transcripts. ESP32 compilation passes for the signer and NVS adapters. The signer frame is 6,176 bytes excluding callees and task overhead. NVS adapters hold the maintenance and enrollment mutexes throughout the operation; runtime mutex qualification remains separate.

Evidence: `qualification/worker-private-session-windows-v1.json`, `qualification/worker-private-session-linux-v1.json`, `qualification/worker-private-session-esp32-v1/report.json`, `qualification/update-v2-esp32-objects-v10/result.json`.

## Embedded Node authentication candidate V1

The allocation-free C context/Node verifier agrees with the host context and transcript and requires both Ed448 and FN-DSA over the dedicated Node session domain. It parses a canonical Node descriptor and requires the enrollment-pinned coordinator identity. Wrong role/context, noncanonical encoding, reflected or zero nonces, malformed sizes, partial signatures and mutated public inputs fail. Python independently reproduces hashes and verifies Ed448. Linux passes two tests with C ASAN/UBSAN/leaks (Rust uninstrumented). ESP32 compilation passes; Node verification and context functions have 3,664-byte and 2,640-byte static frames, respectively, excluding nested callees and RTOS overhead. The first compile attempt rejected an unused static helper in the unmodified upstream FN-DSA header; V2 marks that pinned include as a system header. Project warnings remain errors. No cryptographic source was changed to suppress the warning.

The separate mutex contract probe passes with actual adapter functions and a sentinel signer under a modeled scheduler. It establishes busy/failure lock and output behavior, not cryptographic verification, real NVS storage or RTOS scheduling.

Evidence: `qualification/worker-session-guard-v1.json`, `qualification/worker-node-auth-windows-v1.json`, `qualification/worker-node-auth-linux-v1.json`, `qualification/worker-node-auth-esp32-v2/report.json`.

## Embedded fixed-pool KDF candidate V1

The isolated HKDF-SHA512 component pins Mbed TLS commit `068ff080b369adfac81509f9b57b2afabaf82dc5`. One explicit custody patch clears the HMAC finish temporary on success and error; the hash/HMAC/HKDF mathematics are unchanged. Namespace isolation prevents accidental link selection against the separate public-hash implementation. Two fixed 256-byte slots replace general allocation under a nonblocking atomic guard. Output is the exact 104-byte Worker schedule; it confers no authentication or channel authority.

Windows and Linux tests compare 128 synthetic cases to independent Rust HKDF, inject four allocation failures and execute 1,024 concurrent attempts. Calls either return their correct output or cleared busy output, with the pool cleared afterward. Linux instruments C with ASAN/UBSAN/leaks; Rust is uninstrumented. ESP32 compile and relocatable symbol isolation pass, with no OS allocator or test-control symbols. The wrapper static frame is 144 bytes, excluding nested calls and RTOS overhead. Whole-device erasure, compiler register copies and complete runtime qualification are not established.

Evidence: `qualification/worker-kdf-c-windows-v2.json`, `qualification/worker-kdf-c-linux-v2.json`, `qualification/worker-kdf-esp32-v1/report.json`, `qualification/worker-kdf-symbols-v1.json`, `qualification/worker-kdf-source-review-v1.json`.

## Embedded Finished candidate V1

The C Finished primitive matches independent Python ChaCha20-Poly1305 for both Worker and Node directions using deliberately public constant KDF inputs. It uses the dedicated Finished domain, sender discriminator, exact transcript and directional prefix with reserved sequence zero. Partial/oversized tags, wrong direction, changed transcript, key, prefix or tag fail. Windows and Linux pass the combined four-test frame/Finished probe; Linux instruments C with ASAN/UBSAN/leaks, Rust uninstrumented. ESP32 compilation passes. This primitive does not activate a session: the complete handshake must first authenticate both parties and enforce expiry/current authority.

Evidence: `qualification/worker-finished-c-windows-v1.json`, `qualification/worker-finished-c-linux-v1.json`, `qualification/worker-finished-esp32-v1/report.json`.

## Combined C Worker and idle cleanup qualification

The bounded caller-owned C pending object now interoperates with the actual Rust Node using synthetic, genuinely owner-authorized enrollment. It validates current local authority and the pinned Node hybrid signature before deriving traffic keys or producing the device-private Worker signature. Both Finished messages are required before channel initialization. Failed authentication, replay, changed authority, expiry and clock rollback consume pending state. This does not grant application work authority by itself.

The owning task must call the pending expiry entry point even without incoming data; its deadline is 60 seconds inclusive. Confirmed channels likewise require an idle timer with independently recomputed current authority; one hour inclusive, clock rollback or invalid current authority clears traffic keys. Disconnect and maintenance must clear immediately. These are single-owner APIs; concurrent calls are forbidden. Actual RTOS scheduling and NVS integration remain unqualified.

Windows and Linux pass four combined handshake tests. Separate current frame/Finished tests pass five tests including confirmed idle cleanup. Linux instruments C with ASAN/UBSAN/leak detection; Rust is uninstrumented. ESP32 object compilation passes, not a whole-image/resource qualification. The combined source snapshot precedes the additive confirmed-channel timer; its separate evidence is preserved. Failed Linux harness attempts remain recorded: archive link order and an over-restrictive test filter were corrected, not classified as passes.

Evidence: `qualification/worker-pending-windows-v2.json`, `qualification/worker-pending-linux-v2.json`, `qualification/worker-pending-esp32-v3/report.json`, `qualification/worker-idle-c-windows-v1.json`, `qualification/worker-idle-c-linux-v2.json`, `qualification/worker-frames-esp32-v2/report.json`.

## NVS serialization and combined resource gate

The NVS integration adapters supply their own internal stores, reject caller-supplied store pointers and hold the maintenance and enrollment mutexes throughout each complete handshake flight. Busy/failure consumes pending state. They require one task to own the pending/channel memory and disjoint buffers; outputs are usable only on success. Final confirmation takes a fresh empty channel. Entropy and clock callbacks are trusted platform inputs and still need deployment qualification.

The actual wrappers pass the five-test Windows synthetic cryptographic integration suite, including public/private read faults, real hybrid Node verification, Worker signing, both Finished messages and encrypted traffic. The synthetic NVS bridge aborts on writes or device RNG access. This is not a real NVS/FreeRTOS qualification. The separate sanitizer mutex contract checks contention, ownership, all three flight dispatches and backend-injection rejection with a sentinel crypto implementation. Linux integrated results are tracked separately.

The pinned portable ML-KEM decapsulation compiler graph reports a 29,072-byte known direct-call stack path, before caller/RTOS/external overhead. The earlier public RAM KAT measured 29,088 touched bytes in 40,960 bytes. The enrollment-only 24 KiB allocation must not be reused as the handshake task budget. A final budget must include the complete caller chain, register-window/ABI effects, external calls, interrupt/task overhead and measured margin. Neither this static analysis nor that historical standalone measurement qualifies the final task.

Evidence: `qualification/worker-handshake-guard-v1.json`, `qualification/update-v2-esp32-objects-v11/result.json`, `qualification/worker-pending-windows-v3.json`, `qualification/worker-mlkem-stack-analysis-v1.json`.

## Current NVS and native closure evidence

The five-test actual NVS-wrapper/synthetic storage integration also passes on Linux with C ASAN/UBSAN/leak detection; Rust remains uninstrumented. The source manifest contains 1,520 files and remains unchanged throughout that run. Both platforms now cover the combined crypto path through the adapters.

All 34 native crypto translation units compile together for ESP32 and link into one relocatable object. With the explicit public handshake/enrollment/frame/hash roots retained, live relocation analysis finds only compiler integer helpers and standard memory/string functions unresolved. It finds no reachable allocator or diagnostic-print reference. The first symbol-table-only audit flagged unused undefined entries retained by the relocatable linker; V2 checks relocations and removed helper definitions, with both reports retained.

The combined known direct-call frame sums are 19,488 bytes for begin, 29,264 for accept and 12,224 for final confirmation. These are partial compiler path sums, not a total task bound. Hash/storage/entropy/clock callbacks, NVS adapter frames, ABI effects and RTOS/interrupt overhead still require explicit analysis and final measurement.

Evidence: `qualification/worker-pending-linux-v3.json`, `qualification/worker-crypto-closure-esp32-v1/report.json`, `qualification/worker-crypto-reachable-v2.json`, `qualification/worker-crypto-stack-analysis-v1.json`.

## Bounded owner-task connection controller

The candidate controller uses the actual NVS handshake adapters, bounded receiver and traffic channel. It does not create a task, start radio or open a socket. One task must own its storage and invoke its monotonic timer even during idle periods. Disconnect, maintenance and canonical revocation must be delivered to that owner for immediate close; production delivery is still unqualified.

Partial outgoing writes retain an explicit offset. Incoming phase changes occur only after a whole outgoing handshake message is reported sent and the appropriate cryptographic step succeeds. Node Finished is mandatory before confirmation. Coalesced input reports a consumed prefix; the caller handles the event before feeding the remainder. The receiver never grants authority by itself.

After confirmation, one bounded encrypted frame may be queued. BUSY preserves it and does not advance sequence state. Both wire buffers require 16,444 bytes; the previous handshake-only 1,722-byte transmit allocation is insufficient for this controller. The caller separately owns and clears decrypted plaintext after typed-message validation. Encrypted transport does not authorize work by itself.

The nine-test synthetic integration exercises real owner enrollment and Node/Worker crypto through actual adapters, maximum 16 KiB outbound traffic, backpressure and partial writes, receive coalescing, expiry/disconnect cleanup, storage faults and nested-authority alias rejection. Reports contain exact source snapshots and platform status. The ESP32 check is compilation only. None of these results qualifies socket/RTOS scheduling, hardware entropy, physical storage or the complete task memory/watchdog budget.

Current evidence is maintained in `qualification/SECURITY-HARDENING-PROGRESS.json`, component `worker_connection_controller_v2`.

## Mining lifecycle guard candidate

The same owner task must guard mining requests, nonce issuance and solution handling with the actual confirmed connection. The candidate guard retires work on disconnect, expiry, maintenance or authority loss while retaining RUN intent, accounting and the ticket floor. A clock rollback relative to mining observations latches a fault and closes the connection; advancing time later does not clear it. The return value establishes only session liveness, not permission to hash. Signed work, nonce, deadline, RUN and accounting checks remain mandatory.

The work context must already match independently authenticated enrollment and canonical parent/job state. This candidate does not establish that linkage or rewrite context from a received work offer. Socket/task scheduling, event delivery and platform entropy remain unqualified. The nine-test V9 integration uses synthetic mining control state, real handshake cryptography and modeled NVS/mutexes; it is not a full signed-work end-to-end qualification. Linux instruments C, not Rust. ESP32 V17 is compile-only. Exact evidence is in the progress component `worker_runtime_guard_v2`.

## Explicit work identity linkage and runtime entropy candidate

The V10 candidate adds `build8_worker_runtime_binding_v2` at session confirmation and before authority/work-context changes. It derives WorkerID with the existing canonical identity codec, compares the mining binding fields, and reconstructs the exact ContextID against the confirmed session. This supersedes the earlier guard-only caller assumption for identity linkage. It does not authenticate canonical parent/job state or initialize mining context from an offer. The cheap timer guard remains mandatory between events. Mismatch closes the session and retires work, retaining RUN, accounting and ticket floor. Ten Windows/Linux tests include 13 mismatch cases and independent Rust/C WorkerID agreement; mining state remains modeled.

The runtime entropy candidate requires original ESP32, Wi-Fi enabled, power management/Bluetooth/RNG bypass disabled, connected station mode, power saving off, and the local maintenance mutex held across the draw. All radio/power lifecycle changes must be serialized through that same mutex by the final application. It checks prerequisites before and after drawing and clears failed output. It never enables SAR alongside radio and has no software fallback. Repeating-pattern checks are catastrophic failure checks only. No hardware entropy quality is inferred from them.

The [pinned SDK RNG documentation](https://docs.espressif.com/projects/esp-idf/en/v5.5.5/esp32/api-reference/system/random.html) requires an active physical source and notes that RF sleep can remove that source. SDK headers/source and candidate configuration are hash-pinned in the qualification evidence. The 28 mocked fault cases and six-case target build matrix qualify prerequisite enforcement only. Real RF/PHY lifecycle, physical entropy, RTOS concurrency, memory/stack and watchdog qualification remain open. No radio, firmware or production identity was changed.

## Read-only runtime closure and signed-work integration

The current session adapters provide read-only private/public backend tables. Identity preparation and enrollment activation retain their separate maintenance paths; the session table cannot invoke their write or pre-radio SAR callbacks. The retained ESP32 runtime component link has no NVS set/commit, SAR control, allocator or diagnostic relocations. SDK drivers and runtime implementations are outside this component link.

V12 integrates real dual-signed work over the confirmed encrypted session with actual C work validation and mining control. A valid AEAD frame carrying a damaged work signature fails work admission. A valid signed envelope with independently pinned synthetic parent/job context issues both inclusive nonces and enters pending accounting through the solution-retirement API. This does not claim a PoW solution, certified finality, live canonical-state proof or final socket/application qualification. Earlier modeled-state-only evidence remains historical.

The extended compiler graph includes controller/NVS adapters. Its receive path sum is 29,728 bytes; binding linkage is 4,400 bytes. These are partial, condition-insensitive sums, can include infeasible phase-dispatch paths, and omit unresolved callback/driver/RTOS overhead. They do not determine a safe task allocation. Final linked stack, static RAM, timing and watchdog measurement remain required.

## Bounded owner stream and socket candidate

The candidate `worker_stream_v2` preserves coalesced bytes across handshake/application events, performs at most one nonblocking1024-byte I/O operation and one receive event per call, and checks trusted monotonic time before and after I/O and verification. Once confirmed, receive service alternates with an occupied transmit queue, including would-block writes. Caller scheduling between calls remains mandatory. Transport plaintext still requires independent typed-work validation and canonical authority; confirmation still requires the runtime identity-binding guard.

The `worker_socket_io_v2` adapter accepts only an already-connected nonblocking stream descriptor. It neither connects nor changes flags; the owner retains descriptor lifetime. It maps would-block/interruption to deferred service and EOF/fatal errors to closure. The owner must retire/clear stream and mining state before closing the descriptor and must not reassign it during a callback. No automatic reconnect or identity fallback exists.

V15 passes11 Windows tests and12 Linux tests; Linux adds a real local socketpair C Worker/Rust Node handshake with authenticated traffic in both directions and EOF cleanup. Mocked I/O covers short writes, fragmented response, coalesced frames, backpressure, invalid callback counts and expiry/clock failure. The earlier transmit-priority adapter fails the retained inbound-starvation negative control. Linux instruments C with ASAN/UBSAN/leak checks; Rust is uninstrumented.

ESP32 compile/relocatable-link and reachable-call checks pass. The stream step adds a112-byte compiler frame; its longest known component path is29840 bytes, excluding unresolved callbacks, SDK drivers and RTOS/interrupt overhead. This is not a safe task-stack allocation. FreeRTOS ownership, maintenance/revocation events, canonical-authority delivery, complete application/link/resource and physical qualification remain open. The default V1 application fence is unchanged.
## Encrypted Node custody candidate

The Node handshake accepts a restricted `NodeSessionSigner`: it validates the
current context and signs only the existing Node Worker-session transcript.
`WorkerSessionSigner` binds an unlocked encrypted physical Node key or software
coordinator key to a canonical parent, License, Worker and trusted timestamp.
It exports no private material and accepts no caller-selected signing domain.

The canonical lookup uses the authenticated current snapshot and ordinary
work timestamp/assignment rules, including activation of due assignments.
Physical custody additionally checks current Node-control authority; software
custody requires the existing software-only coordinator rule. The adapter
rechecks authority before and after signing. The handshake independently verifies
both returned signature halves and checks authority again before releasing its
response. Its lifetime starts before custody callbacks.

This is a component integration, not an installed network endpoint. The actor
must supply trusted current time, discard adapters on parent/time/assignment
change, and revalidate authority before finishing/activating a session and every
traffic operation. A previously confirmed transport session cannot authorize
work by itself. Existing typed work signatures, liveness, request deadlines and
canonical execution checks remain mandatory. No new consensus rule, signature
domain, Node eligibility, key provisioning or production activation is introduced.
## Canonical Node channel gate

`CanonicalWorkerChannel` consumes a confirmed Node endpoint and releases the
Node Finished tag only after current canonical activation succeeds. It checks
the expected parent, active License/Worker assignment, Node descriptor, nonzero
height, epoch at least the effective epoch and trusted local clock before and after
frame operations; the binding's deadline height is not checked (amendment WP-Q17).
An ordinary parent change can preserve a still-valid binding. A rotated Node
descriptor, reassignment, License sale, invalid clock, replay or authentication
failure retires the channel permanently. Post-decryption rejection erases
undispatched plaintext.

The owner must also call the idle check and must derive parent and clock inputs
from its trusted runtime. The gate does not launch a listener, authenticate a
new physical machine, authorize mining work or replace typed message validation.
Queued and partly written output still needs the carrier's current-authority and
original application-deadline checks before each delivery attempt.

Qualification is recorded in `worker-current-channel-v1.json`: Windows and Linux
exercise both encrypted custody roles, bidirectional frames and post-decryption
clock failures. Extended Windows tests retain live channels across canonical
physical key rotation and software reassignment. The Linux snapshot predates
that final test-only extension; the component source hashes match. Linux C has
ASAN/UBSAN/leak instrumentation; Rust is uninstrumented. This remains a candidate
component and does not close the production application or hardware gates.
## Bounded Node carrier

The Node carrier owns an already confirmed channel and one nonblocking socket.
It retains one bounded receive frame and one queued outgoing frame, performs at
most one read or write of4096 bytes per step, and alternates incoming service
with queued output. The ESP32 peer retains its separate1024-byte step bound.
The caller must own the socket exclusively, including any descriptor aliases.

Partial progress never extends the five-second frame/output deadline. Outgoing
frames are additionally limited by the original trusted application deadline;
mining work must retain its request, epoch and liveness limits. Clock/authority
and deadline checks run around I/O and after decryption before plaintext release.
Failure closes the connection and erases undispatched plaintext and traffic keys.

`worker-carrier-v1.json` records Windows11 and Linux16 integrated tests plus
Linux33 transport tests. Admission4 and recovery1 tests also pass after removal
of a duplicate state reconstruction inside the same authenticated read transaction.
The earlier blocked-output test correctly expired after delivering one incoming
message; the retained diagnostic is not a cryptographic verification failure.
Maximum16KiB input took1725ms on Windows and3544ms on instrumented Linux with six
reads. These observations are not worst-case registry/load or hardware guarantees.

## Bounded socket handshake owner

`worker-handshake-io-v1.json` records the candidate's Windows 11 integrated
tests and Linux 16 integrated plus 33 transport tests. Both encrypted custody
roles complete partial Hello/response/Finished exchanges and then encrypted
traffic. Malformed input, damaged confirmation, EOF, invalid I/O counts,
stale authority, exact deadline expiry and nested clock rollback fail closed.
Linux C has ASAN/UBSAN/leak instrumentation; Rust is uninstrumented.

The owner performs at most one bounded nonblocking I/O call per step. The total
60-second lifetime includes the full confirmation write; progress cannot renew
it. The socket and traffic channel transfer only after confirmation completes.
Nested channel validation preserves the original clock history. The retained
first failure was a reusable Vec reset that erased its length; the corrected
reset erases the initialized slice without changing the next phase's bounds.

The pending budget is a local resource policy, independent of consensus
membership and reputation. Operators must supply finite positive pending and
attempt limits. A permit is reserved before untrusted input, accepts a single
public routing claim, and is retained while handshake resources remain owned.
An expired permit does not free capacity until released. Failed claims cannot
be retried to grow the Worker attempt map, and dropping a permit does not refund
attempts. Claimed Worker identity is only a routing hint; the canonical custody
and cryptographic handshake remain authoritative.

The admitted handshake inherits the reservation's original deadline, including
time spent routing. Confirmed connections still require a separately bounded
runtime owner. Public context routing, typed mining dispatch, task scheduling
and complete production/resource qualification remain open.

## Public routing and confirmed connection ownership candidates

The public router reads exactly the first 66 Hello bytes, at most one
nonblocking read per step, under a pending permit reserved before input. Its
finite table maps the version/suite/context identifier to an expected License
and Worker. The routing snapshot does not authenticate either identity. The
encrypted custody path checks fresh canonical state and the exact context again;
the prefix is preserved for ordinary transcript validation. Unknown contexts
and malformed prefixes close without signing. Route-table refresh belongs to
the owning runtime and cannot relax these checks.

Confirmed connection admission rechecks the canonical channel and uses a
separate finite local ownership limit. A newer authenticated connection can
replace the current local token for its Worker only when capacity is available.
The old token remains counted until its socket, buffers and outstanding
plaintext are retired. Releasing an old token cannot remove its replacement.
Operators wanting overlap during reconnect must provide capacity for both;
the limit is never exceeded temporarily to permit replacement.

Each connection permits only one outstanding opaque received-message object.
While it is held, subsequent steps perform idle validity checks without reading
more payload. Dispatch checks the exact registry and connection token, then
fresh canonical channel authority. The owning runtime must hold its canonical
actor while performing bounded typed dispatch. Replacement and dispatch are
serialized by the local registry lock; dispatch callbacks cannot do socket I/O
or reenter that registry. A message received before replacement does not retain
dispatch authority afterward. Dropping pending plaintext erases it before
releasing its shared capacity reservation, including after socket closure.

These are candidate components. The production listener/task, typed mining
payloads, durable hybrid observation receipts, work-deadline propagation and
whole-application qualification remain required. Operational receipt messages
must not be confused with settlement proofs or finality certificates.
## Typed host dispatch candidate

The confirmed connection derives the expected Genesis, ProtocolFingerprint,
License and Worker scope from its validated channel. Typed dispatch accepts
bounded canonical Worker status, work request and result messages. It rejects
Node-direction messages and never calls the historical Ed25519 receipt verifier.
Syntactic decoding grants no PoW acceptance or accounting credit. Historical
work validation, durable accounting and retained candidate delivery are separate
required steps. Windows 29 and Linux 34 integrated tests are recorded in
`worker-typed-dispatch-v1.json`; full runtime/hardware qualification remains open.

## Hybrid work-offer payload

Inside the confirmed channel, a Node work offer is exactly: type 5 (one byte),
version 2 (one byte), request nonce (32 bytes), MiningEpoch (u64 BE), remaining
lifetime in milliseconds (u64 BE), authority length (u16 BE), followed by that
many canonical hybrid WorkAuthorityV2 bytes. Authority length is 1..8192;
the total payload is at most 8244 bytes. No trailing bytes are accepted.

The context is not installed from this packet. The device already holds its
independently authenticated work context and validates both Node signatures,
authority identity, parent, target, assignment, ticket, epoch and identity scope
against that context. The request nonce must match its outstanding request.
Lifetime is positive, capped at 60 seconds and measured from device request
start; verification completion must still precede the deadline.

The Node encodes authority bytes before its final publication checks, then
patches only the fixed lifetime bytes after checking current request, epoch and
quorum lifetime. The owner must queue immediately under the original local
deadline. Holding a prepared packet does not extend authority. This payload
does not admit the historical V1 work signature or peer-supplied parent state.

The independent public vector is `hybrid-work-offer-public-v1.json`; Rust and
actual C tests use the same vector. Final application integration remains gated.

## Amendment WP-Q17 (Build 8 candidate 3, 2026-10-04): the deadline height is not a session expiry; the sale gate

Integration copy; identity in `spec/imports/WORKER-SESSION-CONTEXT-V2.md.identity.txt`. Above this heading
only two passages changed: the binding paragraph (former wording "activation epoch and expiry height. Parent
churn does not inherently invalidate a session; the application must recheck active canonical authority and
expiry.") and the Canonical Node channel gate paragraph (former wording "height/epoch validity" and "A rotated
Node descriptor, reassignment, invalid clock, replay or authentication failure retires the channel
permanently."). Authority: Order Q17; P-LANE-DESIGN-V1 11.2 (b); P-LANE-DESIGN-AMENDMENTS-V1 AM-7. Evidence:
Windows-host software tests only (NATIVE-PASS-offline-TEST-VALUE); the C file was compiled by MSVC for the Rust
tests, not for the ESP32 and not on a device; nothing here ran on Linux.

1. `valid_until_height` is the INCLUSION deadline of the Worker-assignment operation in consensus
   (`consensus/src/license_assignment_v2.rs`, `Assignment::verify_next_epoch`: inclusion height H must be at
   most `valid_until_height`), and consensus cannot schedule the value 0 there, so every post-Genesis binding
   carries a deadline while its assignment stays canonical and mining-valid after it. Neither side of the
   Worker channel ends a session at that height any longer: Rust `transport-v2/src/worker_context_v2.rs`
   `Context::matches_current` and embedded C `transport-v2/embedded/worker_frame_v2.c` `live()` require a
   nonzero height, an epoch at least the effective epoch and the exact current authority (Rust: binding and
   Node descriptor equality; C: the current ContextID, which commits the complete binding and the Node
   descriptor); both keep their one-hour channel lifetime and clock checks. Tests:
   `valid_until_height_does_not_end_active_session`,
   `worker_context_binds_every_active_assignment_field_and_node_generation` (worker_context_v2.rs);
   `c_and_rust_keep_an_active_session_past_valid_until_height_and_close_on_authority_change`,
   `idle_channel_timer_erases_keys_on_expiry_or_authority_loss`,
   `mbedtls_worker_lifecycle_counter_and_alias_boundaries_fail_closed` (worker_frames_c_tests.rs). A stale
   sequence (reassignment or sale), another owner or another owner generation still ends the session at the
   first check on both sides, before and after the deadline height
   (`valid_until_height_does_not_end_active_session` and the C/Rust agreement test).
2. C interface: `b8_worker_channel_init` keeps its signature and still records its last argument `until`; the
   value never ends the channel, so a caller may pass the binding's `valid_until_height` or 0 with the same
   effect. The firmware caller of `b8_worker_channel_init` is outside this repository and must not rely on
   `until` for any expiry. Firmware sources outside this repository (the untracked `miner/` tree of the original
   checkout, not imported here) apply the same expiry clause in `miner/worker_handshake_v2.c:55` (sha256
   789c161878f0297cc1aa130f46faeedf24e6f77beeea42efede9aad830cdd58f), `miner/worker_v2_candidate.c:74`
   (de9a95c884a6f11c459d6a2cff3302a665da45a644041b62be4efdd911d4bc2c) and
   `miner/idf/main/worker_runtime_guard_v2.c:17`
   (7e04c6e2d351811c041c22fba07c0e00a8f50fdebc0a8558a47c75559cc4c566); any import of that firmware must remove
   it the same way. They were neither changed nor tested here.
3. Sale gate (Order Q17: an old owner's session must not retain rights because a desktop has not refreshed).
   A License sale detaches the active Worker in the canonical state of the sale's block. From the first
   canonical-state check after that block is committed, `CanonicalStore::current_worker_session` and
   `current_work_context` (`consensus/src/canonical_store_v2.rs` 1013-1062) refuse the old Worker with
   StaleSequence; the node's `CanonicalWorkerChannel::check` (`node/src/worker_current_channel_v2.rs` 137-156)
   re-reads that state before and after every frame operation and on the idle tick, and closes the channel for
   good on failure. Consensus-level test: `sale_without_pending_assignment_detaches_the_worker_and_its_sessions_lose_rights`
   (`consensus/tests/license_sale_assignment_v1.rs`). A node test with a LIVE channel through a sale is not part
   of this amendment (P-LANE-DESIGN-V1 14.11 assigns it to WP-NODE).
