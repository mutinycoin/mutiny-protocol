# Admission activation under the existing parent quorum

Status: adopted for implementation and software TEST on 2026-10-05. The recorded
activation-only source passed 22 modeled controls and normal Node compilation.
The integrated A2 outer-carrier successor is awaiting native verification.
No production eligibility, actual TPM result, sealed Genesis,
physical uniqueness qualification or fleet enrollment is claimed.

The immutable RuleManifest entry `AdmissionActivationParentQuorumV1` equals
`activation_attestation_v1::rule_commitment()`. Its semantic commitment and this
normative document belong in a reviewed successor ProtocolFingerprint. Existing
manifests, Genesis identifiers, old certificate meanings and frozen candidate
snapshots remain unchanged. An unsupported value is rejected. There is no local
flag that selects this rule in lieu of authenticated immutable parameters.

An existing valid parent certificate retains its existing strict weighted
quorum, signer eligibility, BOTH_REQUIRED hybrid signature, money, age,
reputation, penalties, locks, reservations and timing rules. For this successor,
an honest signer also independently performs fresh private credential activation
for every new accepted admission/binding in the exact block it signs. Historical
replay authenticates this explicit quorum attestation and all existing native
public evidence; it does not perform live activation or consult private caches,
elapsed time or an external service. This is the existing honest-quorum trust
model, not publicly verifiable proof that an individual TPM command occurred.

Native full successful execution classifies Join (15), HardwareRotate (16),
ContinuityKeyRotate (21), and the separate prepared Recovery replacement.
Recovery may accompany an empty operation body. Kind 21 verifies and accepts a
complete new hybrid binding/consensus descriptor on the same hardware. Kind 22
NodeKeyRotate changes the current Node descriptor using existing binding and
new Node possession; it accepts no new AK/profile/full admission binding and
adds no activation requirement by itself. Ordinary monetary, wallet, trade,
bond, worker-assignment, freshness and liveness operations acquire no such
requirement. The exact whole block/body is nevertheless in any required scope.

Under the authenticated A2 successor, kinds 15 and 16 use the exact public V3
carrier selected by the committed parent parameters. Native full execution must
first authenticate that carrier, its included witness and its inner signed V2
authorization. The receipt retains the outer operation wire identity; the
accepted Binding is decoded from the exact inner signed bytes. Neither a
structurally parsed carrier nor an operation prefix establishes acceptance.
The whole body in the scope uses the shared authenticated-parent capacity
implementation, including the single reserved A2 item and legacy projection.
Historical or unmarked bodies retain their prior encoding and limits.

The opaque executed scope binds NetworkID, GenesisID, ProtocolFingerprint,
canonical parent and height, full header, BlockHash, exact full body, ordered
accepted positions, operation wire identities and complete binding bytes. Those
binding bytes contain the exact AK public material/profile and both hybrid
authorization/possession proofs. Public witness material must additionally
verify each mandatory qualified EK class against that receipt. A single EK hash,
same-AK association, public return record or witness signature does not establish
cross-class physical-lineage equivalence. Genuine class profiles, relationships
and canonical registry inputs remain required independently of this gate.

The private workflow obtains each independent 32-byte secret directly from the
existing crypto OS CSPRNG and uses a trusted configured MakeCredential adapter
with the exact native EK public area and AK Name. It retains only domain-separated
secret commitments. Every private returned value must match exactly once for
every admission/class, in order, under independently current context before and
after preparation/completion. Returned buffers are owned and zeroized; adapter
and private-channel receive buffers must also be protected/erased. Private raw
values, challenges and encrypted enrollment exchanges never enter logs, the
repository, public witnesses or the counter snapshot.

A finite positive caller-selected LOCAL verifier lifetime and trusted elapsed
continuity are mandatory, with checked deadline arithmetic and exclusive expiry.
No default number, new consensus window or BFT deadline extension is supplied.
Missing configuration, expiry, unavailable or backward elapsed time refuses fresh
signing. Loss of elapsed continuity cancels local private state and requires a
new process/attempt. Each new round/phase fresh signature consumes an exact
signer-bound capability. Wrong context, partial result, failed attempt and
restart confer no signing authority. The actor's existing precommit timer starts
after signing and cannot substitute for prior challenge freshness.

Before any new reservation/reducer/counter mutation, CounterVoter and its actor
check the actual block selected by the lock-aware reducer. At the lowest unsigned
completion boundary the capability is consumed again immediately before the
private custody call. The custody call takes a nonconstructible exact-message,
signer permit; the normal encrypted backend refuses raw unpermitted signing.
Elapsed and canonical-current checks after private work can refuse output;
already performed private work or bytes already sent cannot be retracted. A
failure after durable mutation retains existing halted/poisoned safety behavior
and the unfinished reservation. Pure missing/expired activation before mutation
does not halt, reserve, sign NIL, reset locks or fabricate timeout.

Selected successor snapshots use local format 4 to persist only authenticated
PUBLIC native classification per slot: unknown, no admission, or required exact
scope commitment. It is atomic with the existing counter-protected reservation
and locks. No private success/expiry cache is persisted. Unsigned required slots
need fresh activation after restart even when the old qualified-clock marker is
set. Unknown old unsigned slots require native revalidation. Ordinary unsigned
slots retain their existing clock behavior. Exact completely signed durable
retransmissions use the existing stored dual signature and require no renewed
activation; no new signature or altered decision is produced.

The normal workflow refuses Production-class material and has no registered
production MakeCredential adapter. Production enablement requires independently
reviewed actual activation mechanism, private transport, all class profiles/
alias relationships, canonical current/revocation provider, trusted elapsed
provider and explicit local deployment freshness configuration. Software TEST
models prove only the local protocol/gate mechanics they actually exercise.
