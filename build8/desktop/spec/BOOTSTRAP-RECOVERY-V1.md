# Bootstrap recovery and irreversible activation V1

Authority: ARCHITECT-BLOCKER-RESOLUTIONS-V1.txt, SHA-256
804500f20c008a31124d4123ab67ff8d7bec741f115086a3ae6ca815e5752f5b.
This resolution supersedes conflicting earlier draft language. Implementation
status: canonical recovery codec and pure transition tests exist; durable node
integration and real physical admission verification remain pre-Genesis gates.

Genesis commits a distinct Ed25519 BootstrapRecoveryAuthority public key. Desktop
derives it with established BIP39/SLIP-0010 at m/44'/1297437697'/0'/1'/0', with
empty BIP39 passphrase as for the existing wallet. Owner spending uses role 0;
recovery uses hardened role 1. Seeds and private keys remain inside Desktop.
Public identity export does not grant any node the recovery signing key.

## Canonical certificate

Deterministic CBOR body, exactly 19 array entries in this order:

`[1, NetworkID, GenesisID, ProtocolFingerprint, height, tip, StateRoot,
registry_root, recovery_sequence, lineage, old_generation, new_node,
new_hardware_commitment, new_attestation_commitment, new_voting_key,
operation=1, reason=1, supervised_loss_commitment, attestation_policy_version=1]`.

NetworkID is u32; height, sequence and generation are u64. IDs, roots and
commitments are 32-byte strings. The voting key is a compressed 33-byte P-256
public key whose validity, possession and TPM binding must pass admission.
Generation u64::MAX is invalid; replacement generation is old_generation+1.
Operation 1 means replacement of permanently lost physical bootstrap hardware;
reason 1 means supervised permanent hardware loss. No other operations/reasons
are accepted. The envelope is `[body_bstr, Ed25519_signature_64_bstr]`, <=4096
bytes. Definite lengths, shortest encodings, exact field counts and no trailing
bytes are mandatory; decode/re-encode must reproduce the input exactly.

Sign SHA-256(ASCII `MUTINY-BUILD8-BOOTSTRAP-RECOVERY-V1` || NUL || body).
The supervised loss commitment hashes the canonical sorted unique array of
`[lineage_32_bstr,generation_u64]` pairs using the separate domain
`MUTINY-BUILD8-SUPERVISED-HARDWARE-LOSS-V1` plus NUL. Its evidence is an explicit
supervised ceremony, never an inference from elapsed time or silent nodes.

Acceptance requires bootstrap mode and recovery enabled; exact current network,
Genesis, fingerprint, canonical anchor and registry; increasing sequence; valid
committed recovery-authority signature; no conflicting accepted recovery or
existing valid ordinary finality decision; the identified old hardware generation;
insufficient surviving old-set weight for strict >2/3; and fresh, fully verified
physical admission of a distinct replacement. A caller-provided boolean or mock
admission result is not a production verifier or evidence of global finality.

The transition changes only the lost registry generation and recovery metadata.
Preserve lineage, P/A/S, bond amounts/ages, and penalties; reset H to zero and
replace physical identity, TPM voting key and attestation. Do not change UTXOs,
issuance, PoW, economics, network, Genesis or historical blocks. Historical roots
remain historical; the replacement registry and recovery sequence must be
atomically committed as the active recovery state before any resumed vote.
Crash-safe integration and registry commitment vectors are still required.

## Irreversible decentralized activation

Ordinary old-set consensus must certify activation with at least four qualified
independent physical voters and strictly >2/3 of original committed weight
remaining after removal of each individual voter. Set
CONTINUITY_DECENTRALIZED_ACTIVE=true and bootstrap_recovery_enabled=false
atomically and irreversibly. All later recovery certificates are invalid. No
owner, operator, wallet seed, software update or ordinary governance can restore
this authority. If legitimate old-set authority is permanently unavailable after
activation, the chain remains halted. There is no denominator renormalization.

Concentration metrics are recomputed at each committed state. Mode stays
DECENTRALIZED if later concentration fails redundancy; expose the failed Survival
status without restoring bootstrap recovery. During one-voter bootstrap display
BOOTSTRAP_CENTRALIZED, physical voters 1, Survival redundancy NO, recovery ENABLED.

## Weight and qualification evidence

Only physically qualified Genesis members receive provisional voting weight 1.
The first certified ContinuityPeriod boundary replaces it with the direct score,
e.g. 1007, never 1008. Cloud/vTPM remains zero; later joiners get no fictitious
history. S reset, effective bond withdrawal and H reset may lower total score.
There is no global monotonicity promise, cap, normalization or high-water clamp.

The public recovery fixture is qualification/recovery-vector-v1.json and is
independently checked by verify_recovery_vector.py. Its known test seed and mock
physical evidence are never production authority. Twelve Rust tests and eight
Python model tests currently cover resolved policy cases; they do not substitute
for complete node, crash, partition, physical TPM or Genesis qualification.
