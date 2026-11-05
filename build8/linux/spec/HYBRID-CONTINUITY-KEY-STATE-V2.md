# Hybrid Continuity admission key state V2

Status: candidate implementation; production execution remains gated.

The authenticated state now has a typed hybrid Continuity key book. A new entry
requires the non-forgeable VerifiedAdmission result of the full admission
validator: current canonical owner WalletBook, exact policy and supervised
challenge, both owner signatures, both Continuity possession signatures, certified
native TPM key, and matching quote. The token retains GenesisID and
ProtocolFingerprint so it cannot be inserted into another network generation.
Public insertion revalidates against the current policy, expected ceremony inputs
and WalletBook; callers cannot insert a cached token after authority changes.

Each canonical record is CBOR [2, 50, NetworkID, owner_descriptor_bytes,
AdmissionV2_bytes]. Its key is SHA-256 of ASCII
MUTINY-BUILD8-CONTINUITY-KEY-STATE-V2, one zero byte, and the 32-byte NodeID.
The record retains the original public authorization and native evidence. The
maximum record length is 18,464 bytes. The book is bounded by the existing
1,024-node Continuity registry limit. Every entry must share GenesisID and
ProtocolFingerprint. Node identity, either software public-key half, native TPM
identity key and hardware identity cannot be duplicated in this initial book.

Insertion is atomic and cannot replace a NodeID. Hardware migration and software
key rotation require their own authorized transitions; they cannot be implemented
as another insertion. No new authority to rotate keys is introduced here.

State reconstruction checks an independently pinned whole-state root and then
checks exact encoding, record key, context consistency, retained dual signatures,
native key certification and challenged quote. It does not treat a self-provided
root or an embedded owner descriptor as admission authority. Original owner-policy
eligibility is established by replay of the accepted historical transition or by
the trusted checkpoint, not by the record in isolation. Later owner rotation does
not invalidate that accepted historical evidence; it does invalidate new requests
under the retired owner key through the normal admission validator.

Tag 50 is reserved even when malformed. These records cannot be hidden as opaque
protocol records, bypass typed validation, or be imported under an unrelated key.
No private keys appear in the records.

This book does not grant voting weight. The complete canonical membership,
reputation, revocation, freshness and rotation integration is still required.
Both legacy and hybrid transfer execution reject a state containing these records
until that integration is implemented. The production launch gate remains closed.

Qualification: hybrid-continuity-key-state-v1.log passes three tests covering
cross-context insertion, checkpoint round trip, wrong roots/keys, corrupt retained
signatures, malformed reserved tags, duplicate identity rejection without mutation,
preservation across owner rotation, and execution fencing. Fixtures use synthetic
software TPM evidence and do not claim physical qualification.

The candidate HeightAuthority::from_state projection accepts a finalized parent
anchor and its independently verified StateRoot. It verifies the full root and
accounting height, then derives weights from the committed physical registry's
existing reputation formula. Every physical member must match its retained hybrid
admission's network generation, hardware generation, hardware identity, native TPM
key and profile commitment. Missing/orphaned records fail. Cloud entries cannot
carry hybrid Continuity key records or voting weight. Admitted zero-weight members
remain identifiable without gaining quorum authority.

The projected membership root is SHA-256 over ASCII
MUTINY-BUILD8-HYBRID-CONTINUITY-MEMBERSHIP-V2, a zero byte, and canonical CBOR
[2, existing_physical_membership_root, key_book_StateRootV2]. Reputation and native
attestation roots retain their existing deterministic codecs. This commits the
software key bindings into every hybrid decision without changing the reputation
formula. The old physical/history record codec is a candidate bridge only; its
legacy recovery authority does not become an authorized hybrid recovery path.

hybrid-state-authority-v2.log passes four targeted tests, including stale-owner
insertion, checkpoint projection, mismatch rejection, cloud exclusion and zero
weight. hybrid-state-authority-v1.log additionally covers the five durable hybrid
voter tests. The independent Python model reproduces the exact StateRoot and all
three authority roots and rejects seven hostile record/metadata variants in
hybrid-continuity-key-state-python-v2.json. Retained admission bytes exactly match
the separately verified Python/native-TPM/Ed448 and pristine-C FN-DSA public fixture.

Current projection additionally requires the complete Node binding/control record for every physical member and validates pending transitions against parent height. Missing controls no longer have a test-fixture compatibility path into HeightAuthority. hybrid-parent-full-controls-v1.log passes three targeted groups; hybrid-parent-control-temporal-v1.log covers pending-exit boundaries and the rolling lifecycle. The new public fixture is hybrid-continuity-key-state-public-v2.json; hybrid-continuity-key-state-python-v4.json independently reproduces its roots with complete controls and rejects eleven mutations. Earlier key-only projection fixtures are historical component evidence, not valid current voting authority.
