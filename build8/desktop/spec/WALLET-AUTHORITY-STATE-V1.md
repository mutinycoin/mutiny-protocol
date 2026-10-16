# Wallet authority state candidate

WalletBook is now a typed component of execution State and StateRootV2 checkpoint
reconstruction. Node transaction admission and block execution remain on the
older runtime path pending explicit migration. No final Genesis is generated.

The authority ID is the initial generation-one WalletAuthDescriptor AddressID.
Registration records that descriptor and its initial address. A validated
WalletKeyRotateV1 compare-and-replaces the current descriptor and adds the new
descriptor-derived AddressID. Every older descriptor/address remains committed
as historical state. There is one current descriptor per authority; old keys do
not retain spending authority. Rotation does not rewrite UTXOs, amounts or their
AddressIDs. Later receipts to an old address resolve to the current descriptor.

Hybrid transfer verification now requires an explicit authenticated WalletBook.
For registered addresses the input descriptor must exactly match the current
record. An unregistered address permits direct generation-one ownership only.
An unregistered generation-two descriptor cannot claim that state transition
occurred. Callers must obtain the book from authenticated parent/candidate state,
not an untrusted peer's assertion or an empty placeholder.

Current record is canonical CBOR `[1,30,authority_id32,current_descriptor_bytes]`.
Its key is SHA256(`MUTINY-BUILD8-WALLET-AUTHORITY-STATE-V1 || 00 || authority_id`).
Historical address record is `[1,31,authority_id32,descriptor_bytes]`, keyed by
SHA256(`MUTINY-BUILD8-WALLET-ADDRESS-STATE-V1 || 00 || descriptor_AddressID`).
Records are at most 4KiB, within existing record bounds. The existing ten-million
total authenticated-state-record ceiling also counts these records.

Checkpoint reconstruction checks canonical encoding, descriptor role/suite,
record keys, initial address identity, one retained descriptor per generation,
contiguous generations 1 through current and current-address correspondence.
Reserved record types cannot be hidden as opaque protocol records even when a
key or descriptor is malformed. Overall StateRoot must match the caller's
independently authenticated root; records alone do not prove historical owner
authorization.

Rust tests exercise failed-transition atomicity, old-key rejection, new-key
authorization over unchanged old-address coins, replay, typed state roundtrip,
missing records and wrong record keys. Python independently reproduces the
record keys and full StateRootV2, including inclusion proofs.

Fee-bearing rotation and exact transaction ordering now use the explicit
candidate execution path in FUNDED-WALLET-ROTATION-V1.md. Remaining integration
includes node admission/Work V2, License/other owner-operation resolution,
authenticated wallet lookup proofs and Desktop lifecycle. The typed state
component does not silently activate a network listener or replace runtime checks.
