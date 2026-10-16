# Protocol rules and fingerprint candidate

RuleManifestV1 is deterministic CBOR `[1, NetworkID,
[[artifactNameBytes, artifactSHA256], ...]]`. Names are nonempty ASCII graphic
bytes, at most 128 bytes, unique and strictly ascending. There are 1..512 entries,
hashes are exactly 32 bytes, and the complete manifest is bounded at 128 KiB.
ProtocolFingerprint is H(MUTINY-BUILD8-PROTOCOL-FINGERPRINT-V1, manifestBytes).
The fingerprint itself is never an artifact input.

The candidate commits the normative rule documents, domain definitions,
consensus parameter definitions, and reference implementation artifacts. UTF-8
text artifacts normalize CRLF to LF before hashing; JSON rule artifacts use
sorted keys and compact separators. Content-addressed copies retain the exact
bytes. Reference implementation commitments identify a fixed rule definition;
an independently implemented conforming node uses that same locked manifest,
not a fingerprint of its own executable or compiler output.

Genesis descriptors, GenesisID, GenesisBlockHash, owner identities, WorkerIDs,
assignments, admitted hardware instances, ceremony timestamps, certificates,
private files, and mined work are excluded. They instantiate these rules and
are committed separately by Genesis/canonical state. An InitialPoWTarget value
is a Genesis parameter; its derivation and enforcement rules are committed by
the manifest.

The candidate is pre-Genesis and cannot by itself authorize launch, physical
admission, wallet signing, or sealing. It must be regenerated if rule artifacts
change before the ceremony freezes it. Historical candidate snapshots remain
immutable. A finalized network must not silently replace its locked manifest.
