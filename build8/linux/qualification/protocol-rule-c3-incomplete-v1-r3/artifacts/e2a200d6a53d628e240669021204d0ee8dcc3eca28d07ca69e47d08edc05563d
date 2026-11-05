# Complete Genesis inputs and initial state

GenesisParametersV1 is canonical CBOR
`[1, 2, InitialPoWTarget32, RuleManifestV1_bytes]`. The second field selects
StateRoot V2. The complete object is at most 64 KiB. InitialPoWTarget is nonzero
and must equal the independently qualified active fleet target. RuleManifestV1
commits the complete fixed consensus parameter definitions and rules; its
fingerprint must equal the descriptor fingerprint and the independently locked
manifest. An embedded manifest is not its own trust root. No instance identity
is a manifest input. Earlier mining-only parameter arrays are fixture-only.

The initial physical admission input is canonical CBOR
`[1, owner_Ed25519_public32, node_authentication_Ed25519_public32,
endorsement_root_SHA256_32, TpmProfile_bytes]`, at most 16 KiB. Exactly one such
input appears in the approved initial topology, for the physical Linux Node A.
The node key is distinct from the wallet owner and recovery keys. Native
certified-key properties and a nonzero supervised trust commitment are required.
This input contains no GenesisID, NodeID, Worker, assignment or final state root.
Vultr's peer configuration gives it no entry in the weighted physical registry.

The descriptor owner AddressID must derive from the input owner public key.
Descriptor generation nonce and timestamp are nonzero. The descriptor otherwise
uses the existing GenesisDescriptorV1 codec and domain. These checks precede
durable identity freeze. Worker enrollment remains strictly after GenesisID.

After enrollment, the initial-state constructor validates all twelve ordinary
owner/Worker-signed BindWorker records against that frozen descriptor. It verifies
an ApprovedProfile under the owner admission policy for that exact network
generation, fingerprint and endorsement root; its profile must exactly match
the pre-state input. A fresh nonzero supervised nonce and native TPM quote bind
the existing GenesisPhysicalAttestation challenge to GenesisID, NodeID and the
physical generation. The quote does not depend on GenesisBlockHash.

NodeID follows the ordinary derivation from GenesisID and node authentication
public key. Initial lineage equals NodeID, hardware generation is zero as in
ordinary admission, all history counters and penalties start at zero, and the
approved provisional bootstrap voting weight is one. The current key, owner,
admission policy/profile, membership control and Genesis freshness record enter
the authenticated state. Freshness covers slots 1 through 60 inclusive.

The parameter record is stored unchanged at
`H(MUTINY-BUILD8-GENESIS-PARAMETERS-KEY-V1, empty)`. Its record bytes are the
GenesisParametersV1 bytes above. It is immutable under existing transitions.
Initial state has no coins, bonds, penalties, participation history, pending
assignments or caller-supplied extra records. The initial registry retains the
approved bootstrap recovery authority. Its transient verification anchor is not
serialized into state, so it creates no GenesisBlockHash cycle.

Construction is deterministic and does not seal or launch Genesis. The production
loader must reconstruct this complete state and compare exact records, root and
height-zero block bytes to the independently reproduced sealed artifact. A file
hash alone cannot replace profile, binding or native quote verification. The
actual physical qualification, final rule lock and independent ceremony gates
remain mandatory; software-generated native-wire tests satisfy none of them.
