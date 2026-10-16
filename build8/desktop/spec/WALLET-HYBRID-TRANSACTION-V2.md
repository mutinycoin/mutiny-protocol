# Wallet hybrid descriptor and transfer candidate

Status: IN_PROGRESS, pre-Genesis. These codecs supersede the provisional wallet
descriptor component. They are not yet activated by the canonical runtime;
wallet rotation and runtime/ceremony migration remain required gates. There is
no V1/Ed25519 compatibility branch in the V2 descriptor/transfer decoder.

WalletCryptoSuiteID=1 maps exactly to
`MUTINY-WALLET-HYBRID-ED448-FNDSA1024-V1`. PolicyID=1 means BOTH_REQUIRED. All
other suite/policy numbers fail closed. WalletAuthDescriptorV1 is the minimal
definite-length nine-field CBOR array:

`[1, NetworkID, role, authorization_generation, 1, 1, pinned_profile_text,
Ed448_public57, FNDSA1024_public1793]`.

Role1 is owner, role2 recovery; generation is a positive u64. The profile is
`MUTINY-FNDSA1024-PORNIN-20260722-V1`. Recovery keys do not authorize transfers.
The preceding eight-field text-suite descriptor was a qualification candidate
only and is rejected. Historical evidence using it is retained as historical.
Other shared crypto roles retain their separate eight-field descriptors.

AddressID is SHA256(`MUTINY-BUILD8-HYBRID-ADDRESS-V1` || NUL || complete canonical
owner descriptor). OwnerAuthDescriptorID for enrollment uses the separate
`MUTINY-BUILD8-OWNER-AUTH-DESCRIPTOR-V2` domain over these same complete bytes.
Both public keys, numeric suite/policy, role, network, generation and profile are
committed. No old owner wallet or hardware identity is silently migrated.

HybridTransferV2 is minimal definite-length CBOR:

`[2, NetworkID, GenesisID32, ProtocolFingerprint32, created_height,
expiry_height, fee_atoms, inputs, outputs]`.

Each signed input is `[prior_TxID32, output_index_u32, descriptor_bytes,
Ed448_signature114, FNDSA_signature1280]`. Unsigned intent inputs omit both
signatures. Each output is `[AddressID32, atoms_u64]`. Every signature binds
CBOR `[unsigned_transfer_bytes, input_index_u32]` through the shared SHA512
`MUTINY-BUILD8-WALLET-TRANSACTION-INTENT-V1` domain. Both algorithms sign the same
64-byte intent. This binds all inputs, outputs, amounts, explicit fee, validity,
network, Genesis, fingerprint, descriptor generation and authorization policy.

TxID is SHA256(`MUTINY-BUILD8-HYBRID-TRANSFER-ID-V2` || NUL || unsigned transfer).
FN-DSA signature randomness does not create a different economic transaction.
The containing canonical block still commits to the exact signed body bytes.

Existing bounds remain: 16KiB complete signed transaction; 1..128 inputs and
outputs, subject also to the byte bound; no duplicate outpoint; positive output
amounts and a nonzero output AddressID; expiry range at most10080 canonical heights;
coinbase maturity100.
Checked accounting requires input value minus output value equal the explicit
fee and fee at least signed byte length. Input ownership now resolves through an
explicit authenticated WalletBook. Unregistered generation-one addresses use
direct descriptor-derived ownership; registered addresses use the exact current
descriptor. See WALLET-AUTHORITY-STATE-V1.md and FUNDED-WALLET-ROTATION-V1.md for
explicit atomic rotation. No generation change is inferred from a peer claim.

Candidate-3 amendment (Order of 4 October 2026, decision P3; Lane P design P-LANE-DESIGN-V1
section 4.1 row 1): an output AddressID of 32 zero bytes is not a destination. The codec refuses
it with `TxError::Bounds` when encoding, when computing the TxID or a signing intent, and when
decoding, so such a transfer can be neither signed through the codec nor admitted nor executed;
it is never treated as a burn. The positive-amount rule is unchanged. Test:
`consensus/tests/zero_destinations_v1.rs` `transfer_zero_owner_rejected` (a crafted, genuinely
signed zero-owner transfer in a certified block is refused by the canonical store's commit; the
store stays byte-identical).

Current evidence: numeric descriptor rejection tests, new clean isolated wallet
restore evidence v2, Rust hybrid transaction negatives, independent Python
canonical/intent/Ed448 verification and separate pristine C FN-DSA verification.
The synthetic one-input/one-output transaction is3465 bytes. Encrypted object
transport carries these exact bytes and runs local hybrid verification after
reassembly. Radio use, final settlement proof and final production activation
are not claimed.
