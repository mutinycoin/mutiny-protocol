# WalletKeyRotateV1 candidate

Implemented under qualification, not activated in canonical execution. This
implements the Architect's current-authorization plus new-control requirement.
Authenticated wallet-record lookup, transaction/License owner resolution,
checkpoint records and atomic block execution must be integrated before lock.

Unsigned body is minimal definite-length CBOR:

`[1, NetworkID, GenesisID32, ProtocolFingerprint32, authority_record_id32,
current_descriptor_bytes, proposed_descriptor_bytes, created_height,
expiry_height]`.

Both descriptors are exact WalletAuthDescriptorV1 owner-role descriptors.
Proposed generation equals checked current generation + 1. Both key halves
change. Only explicitly implemented wallet suites are accepted; unknown future
suites require an explicit protocol upgrade, never dynamic fallback. The
validity interval uses the existing 10,080-height transaction horizon.

Wire is `[1, unsigned_body_bytes, current_Ed448_signature114,
current_FNDSA_signature1280, proposed_Ed448_signature114,
proposed_FNDSA_signature1280]`, bounded to 16KiB.

Current authorization signs SHA512 of
`MUTINY-BUILD8-WALLET-KEY-ROTATE-V1 || 00 || unsigned_body`.
Proposed proof of control signs SHA512 of
`MUTINY-BUILD8-WALLET-KEY-ROTATE-POSSESSION-V1 || 00 || unsigned_body`.
Both constituents are required independently for each role. This prevents
copying an old authorization into the possession slot or using a transaction,
release or Continuity signature as rotation authority.

Rotation identity is SHA256 of
`MUTINY-BUILD8-WALLET-ROTATION-ID-V1 || 00 || unsigned_body`; randomized signature
representations do not change operation identity. Exact signed bytes remain
committed in the enclosing canonical body.

Verification requires the locally authenticated current descriptor and authority
record ID, exact network-generation/fingerprint context and inclusion height.
Caller-supplied peer descriptors are not a trust source. The resulting private
VerifiedRotation can compare-and-replace only that exact current descriptor;
replay and two competing replacements cannot both apply. Signature generation
also publishes neither changed signature until both signing operations succeed.

The typed WalletBook now commits authority transitions and retained historical
addresses; see WALLET-AUTHORITY-STATE-V1.md. Hybrid transfer verification requires
that explicit book, and old-address coins resolve to its current descriptor.
No UTXO is moved or rewritten. Node admission/block execution and Desktop must
still be migrated before the operation is active on the network.

Qualification uses public BIP39 vectors only. Rust tests cover four required
signature halves, domains, wrong context/role/generation, overflow, expiry,
replay, competing replacements and every wire truncation. Independent Python
reproduces the codec/identity/intents and both Ed448 signatures; pristine C
verifies both FN-DSA signatures and negative mutations. Public wire is 6,726
bytes. These are component results, not completed runtime qualification.

---

## Amendment A1 (candidate 3, Lane P work package WP-R, 2026-10-04)

Status: PROPOSED-UNFROZEN; Windows-host software evidence only. Authority: Order P2; design
`qualification/candidate-3/P-LANE-DESIGN-V1.md` 3.1 and 3.7.

The standalone `WalletKeyRotateV1` object above can no longer reach a block: its only carrier, the
`[2,21,rotation,transfer]` wrapper, is retired and fails decoding (`old_rotate_wrapper_rejected`). A
wallet authority changes in canonical execution only through the funded wallet-rotation bundle
(`spec/FUNDED-WALLET-ROTATION-V1.md`, amendment A1), whose old key signs
`[MUTINY-BUILD8-FUNDED-ROTATION-AUTHORIZE-V2, commitment]` under the same WalletRotate domain and whose
new key signs `[MUTINY-BUILD8-FUNDED-ROTATION-POSSESSION-V2, commitment]` under the same
WalletRotatePossession domain. Those role payloads are CBOR arrays of two byte strings, while the
unsigned body above is an array of nine, so no signature over one can verify as the other. The
generation, key-half and WalletOwner-role rules of lines 14-17 apply unchanged to the bundle's
descriptors. The state transition is the crate-private `WalletBook::apply_verified_rotation`
(compare-and-replace, new address record, capacity), reachable in canonical execution only from the
verified bundle (`only_the_verified_bundle_rotates_a_wallet_authority`). The standalone type and
`WalletBook::apply` remain as a non-consensus helper for test fixtures and for the Treasury ceremony's
authorized-plan modelling (`treasury_rehearsal_v1`); they create no canonical authority.
