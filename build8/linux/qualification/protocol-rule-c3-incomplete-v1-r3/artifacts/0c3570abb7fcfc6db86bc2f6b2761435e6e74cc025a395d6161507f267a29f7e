# Authenticated recovery catch-up

RecoveryEnvelopeV1 is canonical CBOR `[1, recoveryCertificateBytes,
[[lineage32,generation],...], recoveryMaterialBytes]`, bounded at 256 KiB.
The certificate is at most 4 KiB; native RecoveryMaterial is at most 16 KiB.
There are 1..1,024 strictly sorted unique loss entries. Their existing signed
supervised-hardware-loss commitment must match the recovery certificate.
This is transport of existing authorization, not a new recovery or vote domain.

`get_recovery(height)` returns the public envelope for that exact canonical
height, or null if no recovery was committed there. Historical records are
checked against the stored base block. Legacy recovery lacking native admission
material is not relayed as a qualifying physical recovery.

`submit_recovery` accepts only an envelope for the local finalized tip. It calls
the existing native recovery transition: pinned recovery authority signature,
exact network/Genesis/fingerprint and parent state, committed loss set,
insufficient surviving quorum, active recovery policy, native physical admission
and replacement possession must all pass. Duplicate identical records are
idempotent; conflicting or malformed records fail without mutation. No network
request initializes, resets or repairs a TPM counter journal.

Catch-up fetches recovery at the current local tip before requesting its
successor, including height zero, then after each accepted block. Every block
still undergoes full ordinary execution/certificate validation. Withheld recovery
material cannot make an otherwise invalid successor acceptable. An older peer
cannot replace the local state with a recovery for an already superseded parent.

Desktop uses the same validated catch-up dependency. All material is public;
wallet private keys and TPM private material are outside this transport.
Physical signing custody remains bound to its admitted generation. Recovery
does not silently convert an old key/journal into replacement custody; the
supervised replacement ceremony must establish the new custody explicitly.
