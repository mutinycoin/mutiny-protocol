//! Owner-authorized bond funding, unbond request and matured withdrawal.
use crate::{
    Error, Hash, NETWORK_ID, Result,
    anchors::FinalizedAnchor,
    bonds::{BondLot, LotStatus, MINIMUM_ATOMS},
    domain_hash,
    execution::State,
    transactions::{Coin, OutPoint, Output, address},
};
use ed25519_dalek::{Signature, VerifyingKey};
use minicbor::{Decoder, Encoder};
fn hash(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
    d.bytes()?
        .try_into()
        .map_err(|_| minicbor::decode::Error::message("hash"))
}
fn context(parent: &FinalizedAnchor, g: Hash, f: Hash, h: u64, a: Hash) -> Result<()> {
    parent.validate_context(g, f)?;
    if parent.height.checked_add(1) != Some(h) || parent.id() != a {
        return Err(Error::WrongAnchor);
    }
    Ok(())
}
fn signature(key: Hash, digest: Hash, sig: [u8; 64]) -> Result<()> {
    VerifyingKey::from_bytes(&key)
        .map_err(|_| Error::BadSignature)?
        .verify_strict(&digest, &Signature::from_bytes(&sig))
        .map_err(|_| Error::BadSignature)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondCreate {
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub height: u64,
    pub parent_anchor: Hash,
    pub node: Hash,
    pub generation: u64,
    pub nonce: Hash,
    pub funding: OutPoint,
    pub owner: Hash,
    pub signature: [u8; 64],
}
impl BondCreate {
    fn bytes(&self, signed: bool) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(if signed { 14 } else { 13 })
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(18)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .u64(self.height)
            .unwrap()
            .bytes(&self.parent_anchor)
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .u64(self.generation)
            .unwrap()
            .bytes(&self.nonce)
            .unwrap()
            .bytes(&self.funding.transaction)
            .unwrap()
            .u32(self.funding.index)
            .unwrap()
            .bytes(&self.owner)
            .unwrap();
        if signed {
            e.bytes(&self.signature).unwrap();
        }
        e.into_writer()
    }
    pub fn encode(&self) -> Vec<u8> {
        self.bytes(true)
    }
    pub fn signing_digest(&self) -> Hash {
        domain_hash(b"MUTINY-BUILD8-BOND-CREATE-V1", &self.bytes(false))
    }
    pub fn lot_id(&self) -> Hash {
        let mut e = Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .u8(1)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .bytes(&self.owner)
            .unwrap()
            .bytes(&self.nonce)
            .unwrap();
        domain_hash(b"MUTINY-BUILD8-BOND-ID-V1", &e.into_writer())
    }
    pub fn escrow_address(&self) -> Hash {
        domain_hash(b"MUTINY-BUILD8-BOND-ESCROW-V1", &self.lot_id())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, 512)?;
        let mut d = Decoder::new(raw);
        let value = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("bond create");
            if d.array()? != Some(14) || d.u8()? != 1 || d.u8()? != 18 || d.u32()? != NETWORK_ID {
                return Err(bad());
            }
            Ok(Self {
                genesis: hash(&mut d)?,
                fingerprint: hash(&mut d)?,
                height: d.u64()?,
                parent_anchor: hash(&mut d)?,
                node: hash(&mut d)?,
                generation: d.u64()?,
                nonce: hash(&mut d)?,
                funding: OutPoint {
                    transaction: hash(&mut d)?,
                    index: d.u32()?,
                },
                owner: hash(&mut d)?,
                signature: d.bytes()?.try_into().map_err(|_| bad())?,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if value.encode() != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondCommand {
    pub kind: u8,
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub height: u64,
    pub parent_anchor: Hash,
    pub lot: Hash,
    pub sequence: u64,
    pub owner: Hash,
    pub signature: [u8; 64],
}
impl BondCommand {
    fn bytes(&self, signed: bool) -> Result<Vec<u8>> {
        if !matches!(self.kind, 19 | 20) {
            return Err(Error::WrongOperation);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(if signed { 11 } else { 10 })
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(self.kind)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .u64(self.height)
            .unwrap()
            .bytes(&self.parent_anchor)
            .unwrap()
            .bytes(&self.lot)
            .unwrap()
            .u64(self.sequence)
            .unwrap()
            .bytes(&self.owner)
            .unwrap();
        if signed {
            e.bytes(&self.signature).unwrap();
        }
        Ok(e.into_writer())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.bytes(true)
    }
    pub fn signing_digest(&self) -> Result<Hash> {
        Ok(domain_hash(
            if self.kind == 19 {
                b"MUTINY-BUILD8-BOND-UNBOND-V1"
            } else {
                b"MUTINY-BUILD8-BOND-WITHDRAW-V1"
            },
            &self.bytes(false)?,
        ))
    }
    pub fn payout_id(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-BOND-PAYOUT-ID-V1",
            &self.bytes(false)?,
        ))
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, 512)?;
        let mut d = Decoder::new(raw);
        let value = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("bond command");
            if d.array()? != Some(11) || d.u8()? != 1 {
                return Err(bad());
            }
            let kind = d.u8()?;
            if d.u32()? != NETWORK_ID {
                return Err(bad());
            }
            Ok(Self {
                kind,
                genesis: hash(&mut d)?,
                fingerprint: hash(&mut d)?,
                height: d.u64()?,
                parent_anchor: hash(&mut d)?,
                lot: hash(&mut d)?,
                sequence: d.u64()?,
                owner: hash(&mut d)?,
                signature: d.bytes()?.try_into().map_err(|_| bad())?,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
    pub fn validate(&self, parent: &FinalizedAnchor, lot: &BondLot) -> Result<()> {
        context(
            parent,
            self.genesis,
            self.fingerprint,
            self.height,
            self.parent_anchor,
        )?;
        if self.lot != lot.id || self.owner != lot.owner {
            return Err(Error::WrongAnchor);
        }
        signature(self.owner, self.signing_digest()?, self.signature)?;
        // Preflight against parent state even if same-block evidence burns it.
        let mut check = lot.clone();
        if self.kind == 19 {
            check.start_unbond(self.height, self.sequence)?;
        } else {
            check.withdraw(self.height, self.sequence)?;
        }
        Ok(())
    }
}
impl State {
    /// Call after ordinary transactions and objective evidence settlement. The
    /// parent authorizes commands; only surviving locked lots can be paid out.
    pub(crate) fn apply_bond_operations(
        &self,
        parent: &FinalizedAnchor,
        body: &crate::blocks::BlockBody,
        next: &mut State,
    ) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for raw in &body.operations {
            let kind = crate::blocks::operation_kind(raw)?;
            if kind == 18 {
                let create = BondCreate::decode(raw)?;
                context(
                    parent,
                    create.genesis,
                    create.fingerprint,
                    create.height,
                    create.parent_anchor,
                )?;
                let id = create.lot_id();
                if !seen.insert(id) || next.bonds.lots.contains_key(&id) {
                    return Err(Error::Duplicate);
                }
                let control = self
                    .membership
                    .controls
                    .get(&create.node)
                    .ok_or(Error::UnknownSigner)?;
                let old = self
                    .continuity
                    .as_ref()
                    .ok_or(Error::UnqualifiedPhysical)?
                    .members
                    .iter()
                    .find(|m| m.node == create.node)
                    .ok_or(Error::UnknownSigner)?;
                if control.owner != create.owner
                    || control.generation != create.generation
                    || old.generation != create.generation
                    || !old.physical
                    || !old.eligible
                {
                    return Err(Error::UnqualifiedPhysical);
                }
                if next.penalties.revoked(old.lineage)
                    || next
                        .membership
                        .retired
                        .values()
                        .any(|r| r.node == create.node && r.reason == 2)
                    || !next
                        .continuity
                        .as_ref()
                        .ok_or(Error::UnqualifiedPhysical)?
                        .members
                        .iter()
                        .any(|m| m.node == create.node && m.eligible && m.physical)
                {
                    return Err(Error::UnqualifiedPhysical);
                }
                // E5, defense in depth (no separate eligibility flag): in the Production class
                // the member's COMMITTED admission profile must still pass the admission rule.
                if self.admission_class()? == crate::provenance::AdmissionClass::Production {
                    let policy = self
                        .admission
                        .policy
                        .as_ref()
                        .ok_or(Error::UnqualifiedPhysical)?;
                    self.admission
                        .profiles
                        .get(&old.attestation)
                        .ok_or(Error::UnqualifiedPhysical)?
                        .verify(policy, crate::provenance::AdmissionClass::Production)?;
                }
                signature(create.owner, create.signing_digest(), create.signature)?;
                let coin = next.coins.get(&create.funding).ok_or(Error::WrongAnchor)?;
                if coin.created_height != body.height
                    || coin.coinbase
                    || coin.output.owner != create.escrow_address()
                    || coin.output.atoms < MINIMUM_ATOMS
                {
                    return Err(Error::WrongAnchor);
                }
                let lot = BondLot {
                    id,
                    node: create.node,
                    lineage: old.lineage,
                    owner: create.owner,
                    atoms: coin.output.atoms,
                    created_height: body.height,
                    sequence: 0,
                    unbond_height: None,
                    settled_height: None,
                    status: LotStatus::Active,
                    evidence: [0; 32],
                };
                next.bonds.lots.insert(id, lot);
                next.bonds.records()?;
                next.coins.remove(&create.funding);
            } else if matches!(kind, 19 | 20) {
                let command = BondCommand::decode(raw)?;
                if !seen.insert(command.lot) {
                    return Err(Error::Duplicate);
                }
                let parent_lot = self
                    .bonds
                    .lots
                    .get(&command.lot)
                    .ok_or(Error::WrongAnchor)?;
                command.validate(parent, parent_lot)?;
                let lot = next
                    .bonds
                    .lots
                    .get_mut(&command.lot)
                    .ok_or(Error::WrongAnchor)?;
                if lot.status == LotStatus::Burned {
                    continue;
                }
                if kind == 19 {
                    lot.start_unbond(command.height, command.sequence)?;
                } else {
                    let amount = lot.withdraw(command.height, command.sequence)?;
                    let coin = Coin {
                        output: Output {
                            owner: address(&command.owner),
                            atoms: amount,
                        },
                        created_height: command.height,
                        coinbase: false,
                    };
                    if next
                        .coins
                        .insert(
                            OutPoint {
                                transaction: command.payout_id()?,
                                index: 0,
                            },
                            coin,
                        )
                        .is_some()
                    {
                        return Err(Error::Duplicate);
                    }
                }
            }
        }
        if !next.bonds.lots.is_empty() {
            let registry = next.continuity.as_mut().ok_or(Error::UnqualifiedPhysical)?;
            for member in &mut registry.members {
                member.history.bonds = next.bonds.reputation_lots(member.lineage, body.height)?;
            }
        }
        next.bonds.records()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bonds::{BondBook, EVIDENCE_HEIGHTS, LOCK_HEIGHTS};
    use ed25519_dalek::{Signer, SigningKey};
    // TEST-VALUE simulator support (public seeds only), shared with the integration tests; declared
    // once at file scope in lib.rs (a #[path] in this inline module would not resolve on Linux).
    use crate::software_tpm;

    /// T6 (iii), E5 defense in depth: in the Production class a Bond create for a member whose
    /// COMMITTED profile is TEST-VALUE marked or carries no provenance is refused, although the
    /// member's physical and eligible flags were set directly (no admission path can produce such
    /// a Production-class state; this exercises the bond-time recheck itself). The same state
    /// without the Production declaration funds the bond (Legacy/Test behaviour unchanged), and so
    /// does the T14 limit profile in the Production class (authority attestation is the anchor).
    #[test]
    fn production_class_bond_create_rechecks_the_members_committed_profile() {
        use crate::{
            membership::NodeControl,
            recovery::{Anchor, ContinuityState, Member},
            transactions::{Coin, OutPoint, Output},
        };
        let owner = SigningKey::from_bytes(&[61; 32]);
        let policy = software_tpm::fixture_policy();
        let run = |tpm: &software_tpm::TestTpm, production: bool| -> Result<()> {
            let root = software_tpm::test_value_endorsement_root();
            let commitment = tpm.profile().commitment().unwrap();
            let node = [5; 32];
            let mut state = State::default();
            state.admission.policy = Some(policy.clone());
            state
                .admission
                .profiles
                .insert(commitment, software_tpm::approve(&policy, root, tpm.profile()));
            if production {
                state.protocol_records.insert(
                    crate::genesis_inputs::parameters_key(),
                    software_tpm::production_parameters(&policy.endorsement_roots),
                );
            }
            state.continuity = Some(
                ContinuityState::bootstrap(
                    policy.genesis,
                    policy.fingerprint,
                    Anchor { height: 59, tip: [3; 32], state_root: [0; 32], registry_root: [0; 32] },
                    [20; 32],
                    vec![Member {
                        lineage: node,
                        node,
                        hardware: tpm.profile().hardware,
                        generation: 0,
                        voting_key: tpm.voting_point(),
                        attestation: commitment,
                        history: Default::default(),
                        physical: true,
                        eligible: true,
                        genesis_member: true,
                    }],
                )
                .unwrap(),
            );
            state.membership.controls.insert(
                node,
                NodeControl {
                    node,
                    generation: 0,
                    owner: owner.verifying_key().to_bytes(),
                    node_authentication: owner.verifying_key().to_bytes(),
                    sequence: 0,
                    exit_boundary: None,
                    admitted_height: 0,
                    admission_boundary: None,
                    hardware_since_height: 0,
                },
            );
            let parent = FinalizedAnchor {
                network: NETWORK_ID,
                genesis: policy.genesis,
                fingerprint: policy.fingerprint,
                height: 59,
                block: [3; 32],
            };
            let mut create = BondCreate {
                genesis: policy.genesis,
                fingerprint: policy.fingerprint,
                height: 60,
                parent_anchor: parent.id(),
                node,
                generation: 0,
                nonce: [7; 32],
                funding: OutPoint { transaction: [8; 32], index: 0 },
                owner: owner.verifying_key().to_bytes(),
                signature: [0; 64],
            };
            create.signature = owner.sign(&create.signing_digest()).to_bytes();
            let mut next = state.clone();
            next.coins.insert(
                create.funding.clone(),
                Coin {
                    output: Output { owner: create.escrow_address(), atoms: MINIMUM_ATOMS },
                    created_height: 60,
                    coinbase: false,
                },
            );
            let body = crate::blocks::BlockBody {
                height: 60,
                reward_owner: [9; 32],
                fees: 0,
                transactions: vec![],
                operations: vec![create.encode()],
            };
            state.apply_bond_operations(&parent, &body, &mut next)?;
            assert_eq!(next.bonds.lots.len(), 1);
            Ok(())
        };
        let marked = software_tpm::TestTpm::new();
        let unproven = software_tpm::TestTpm::stripped(software_tpm::Strip::Both);
        let limit = software_tpm::TestTpm::stripped(software_tpm::Strip::ConsistentProvenance(
            software_tpm::test_value_endorsement_root(),
        ));
        run(&marked, false).unwrap();
        run(&unproven, false).unwrap();
        assert!(run(&marked, true).is_err(), "marked committed profile");
        assert!(run(&unproven, true).is_err(), "provenance-less committed profile");
        run(&limit, true).unwrap();
    }

    /// T6 (iii) for the V2 hybrid stack, E5 defense in depth (`bond_create_v3.rs` V6, the checks of
    /// the retired `apply_bond_creates_v2` unchanged; candidate 3 retired kind 18 and this test now
    /// funds a kind-24 BondCreate, Lane P design 2.4): in the Production class a V2 Bond create for a member whose
    /// COMMITTED hybrid binding carries a TEST-VALUE marked or provenance-less profile is refused.
    /// The binding is injected under the Legacy/Test rule: no admission path produces it in a
    /// Production-class state, and such a state has no StateRoot, so the full V2 executor already
    /// stops at the parent root; this exercises the bond-time recheck itself. Without the
    /// Production declaration the same bond is funded, and so is the T14 limit binding in the
    /// Production class (authority attestation is the anchor).
    #[test]
    fn production_class_v2_bond_create_rechecks_the_members_committed_binding() {
        use crate::{
            admission_v2::{Admission, Expected, Policy},
            bond_create_v3::{BondError, FundedBondCreate, UnsignedBondCreate, apply_bond_creates_v3},
            node_admission_v2::{Binding, node_id},
            op_envelope_v1::Envelope,
            provenance::AdmissionClass,
            recovery::{Anchor, ContinuityState, Member},
            transactions::{Coin, OutPoint, Output},
        };
        use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
        let root = software_tpm::test_value_endorsement_root();
        let run = |tpm: &software_tpm::TestTpm, production: bool| -> std::result::Result<(), BondError> {
            let owner =
                HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner).unwrap();
            let policy = Policy {
                genesis: [1; 32],
                fingerprint: [2; 32],
                owner_descriptor: owner.public().descriptor(1).unwrap(),
                endorsement_roots: [root].into(),
            };
            let mut state = State::default();
            state.wallets.register(&policy.owner_descriptor).unwrap();
            state.admission_policy_v2 = Some(crate::admission_policy_v2::Record::new(policy.clone()).unwrap());
            let continuity = HybridKey::generate(Role::Continuity).unwrap();
            let node_key = HybridKey::generate(Role::Node).unwrap();
            let node_descriptor = node_key.public().descriptor(1).unwrap();
            let zero = HybridSignature { ed448: [0; 114], fndsa: [0; 1280] };
            let mut binding = Binding {
                node_signer: None,
                admission: Admission {
                    genesis: policy.genesis,
                    fingerprint: policy.fingerprint,
                    node: node_id(policy.genesis, &node_descriptor).unwrap(),
                    hardware_generation: 1,
                    key_generation: 1,
                    continuity_descriptor: continuity.public().descriptor(1).unwrap(),
                    profile: tpm.profile().encode().unwrap(),
                    endorsement_root: root,
                    owner: owner.public().address_id(1).unwrap(),
                    supervised_nonce: [5; 32],
                    quote: vec![],
                    possession: zero.clone(),
                    authorization: zero.clone(),
                },
                node_descriptor,
                possession: zero,
            };
            binding.admission.prove_continuity(&continuity).unwrap();
            binding.admission.quote = tpm.quote(binding.admission.challenge().unwrap());
            binding.admission.authorize(&owner, 1).unwrap();
            binding.sign(&node_key).unwrap();
            let node = binding.admission.node;
            let expected = Expected { node, hardware_generation: 1, key_generation: 1, supervised_nonce: [5; 32] };
            // Injected under the Legacy/Test rule: no admission path produces it in Production.
            (state.membership_v2, state.continuity_keys_v2) = crate::membership_v2::Book::genesis(
                &binding,
                &policy,
                &expected,
                &state.wallets,
                AdmissionClass::LegacyTest,
            )
            .unwrap();
            state.continuity = Some(
                ContinuityState::bootstrap(
                    policy.genesis,
                    policy.fingerprint,
                    Anchor { height: 0, tip: [19; 32], state_root: [0; 32], registry_root: [0; 32] },
                    [20; 32],
                    vec![Member {
                        lineage: node,
                        node,
                        hardware: tpm.profile().hardware,
                        generation: 1,
                        voting_key: tpm.voting_point(),
                        attestation: tpm.profile().commitment().unwrap(),
                        history: Default::default(),
                        physical: true,
                        eligible: true,
                        genesis_member: true,
                    }],
                )
                .unwrap(),
            );
            if production {
                state.protocol_records.insert(
                    crate::genesis_inputs::parameters_key(),
                    software_tpm::production_parameters(&policy.endorsement_roots),
                );
                assert_eq!(state.admission_class().unwrap(), AdmissionClass::Production);
            }
            let parent = FinalizedAnchor {
                network: NETWORK_ID,
                genesis: policy.genesis,
                fingerprint: policy.fingerprint,
                height: 5,
                block: [8; 32],
            };
            // The owner's own coin, created before the inclusion height 6, funds the lot.
            let funding = OutPoint { transaction: [90; 32], index: 0 };
            state.coins.insert(
                funding.clone(),
                Coin {
                    output: Output { owner: owner.public().address_id(1).unwrap(), atoms: MINIMUM_ATOMS + 20_000 },
                    created_height: 5,
                    coinbase: false,
                },
            );
            let unsigned = UnsignedBondCreate {
                genesis: policy.genesis,
                fingerprint: policy.fingerprint,
                envelope: Envelope {
                    first_height: 6,
                    last_height: 6,
                    reference_height: parent.height,
                    reference_block: parent.block,
                    preconditions: vec![],
                },
                owner: owner.public().address_id(1).unwrap(),
                owner_descriptor: owner.public().descriptor(1).unwrap(),
                node,
                node_generation: 1,
                nonce: [91; 32],
                principal: MINIMUM_ATOMS,
                fee: 20_000,
                inputs: vec![funding],
                change: None,
            };
            assert!(unsigned.signed_len().unwrap() <= 20_000);
            let create = FundedBondCreate::sign(unsigned, &owner).unwrap();
            let mut next = state.clone();
            apply_bond_creates_v3(&state, &parent, &Default::default(), &[create], &mut next)?;
            assert_eq!(next.bonds_v2.lots.len(), 1);
            Ok(())
        };
        let marked = software_tpm::TestTpm::new();
        let unproven = software_tpm::TestTpm::stripped(software_tpm::Strip::Both);
        let limit = software_tpm::TestTpm::stripped(software_tpm::Strip::ConsistentProvenance(root));
        run(&marked, false).unwrap();
        run(&unproven, false).unwrap();
        assert!(
            matches!(run(&marked, true), Err(BondError::Eligibility(_))),
            "marked committed binding funded a bond"
        );
        assert!(
            matches!(run(&unproven, true), Err(BondError::Eligibility(_))),
            "provenance-less committed binding funded a bond"
        );
        run(&limit, true).unwrap();
    }

    fn fixture(height: u64, kind: u8) -> (FinalizedAnchor, BondLot, BondCommand) {
        let owner = SigningKey::from_bytes(&[61; 32]);
        let parent = FinalizedAnchor {
            network: NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            height: height - 1,
            block: [3; 32],
        };
        let lot = BondLot {
            id: [4; 32],
            node: [5; 32],
            lineage: [5; 32],
            owner: owner.verifying_key().to_bytes(),
            atoms: MINIMUM_ATOMS,
            created_height: 60,
            sequence: 0,
            unbond_height: None,
            settled_height: None,
            status: LotStatus::Active,
            evidence: [0; 32],
        };
        let mut command = BondCommand {
            kind,
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            height,
            parent_anchor: parent.id(),
            lot: lot.id,
            sequence: 1,
            owner: lot.owner,
            signature: [0; 64],
        };
        command.signature = owner.sign(&command.signing_digest().unwrap()).to_bytes();
        (parent, lot, command)
    }
    #[test]
    fn owner_command_replay_context_sequence_and_maturity_are_all_checked() {
        let (parent, lot, command) = fixture(60 + LOCK_HEIGHTS, 19);
        command.validate(&parent, &lot).unwrap();
        assert_eq!(
            BondCommand::decode(&command.encode().unwrap()).unwrap(),
            command
        );
        for index in 0..8 {
            let mut bad = command.clone();
            match index {
                0 => bad.genesis[0] ^= 1,
                1 => bad.fingerprint[0] ^= 1,
                2 => bad.parent_anchor[0] ^= 1,
                3 => bad.height += 1,
                4 => bad.sequence += 1,
                5 => bad.lot[0] ^= 1,
                6 => bad.owner = SigningKey::from_bytes(&[62; 32]).verifying_key().to_bytes(),
                _ => bad.signature[0] ^= 1,
            }
            assert!(bad.validate(&parent, &lot).is_err());
        }
        // Restart Order sec.4: the notice may overlap the minimum holding
        // duration, so an early notice is valid; one at or before lock start is not.
        let (early_parent, early_lot, early) = fixture(59 + LOCK_HEIGHTS, 19);
        early.validate(&early_parent, &early_lot).unwrap();
        let (start_parent, start_lot, at_start) = fixture(60, 19);
        assert!(at_start.validate(&start_parent, &start_lot).is_err());
        let mut requested = lot.clone();
        requested
            .start_unbond(command.height, command.sequence)
            .unwrap();
        assert!(command.validate(&parent, &requested).is_err());
        let mut noncanonical = command.encode().unwrap();
        noncanonical.push(0);
        assert!(BondCommand::decode(&noncanonical).is_err());
    }
    #[test]
    fn early_notice_withdrawal_waits_for_the_minimum_holding_floor() {
        // B = 60; notice at U = 61; withdrawal needs W >= B + 259,200.
        let floor = 60 + LOCK_HEIGHTS;
        let sign = |c: &mut BondCommand| {
            c.signature = SigningKey::from_bytes(&[61; 32])
                .sign(&c.signing_digest().unwrap())
                .to_bytes();
        };
        let (_, mut lot, _) = fixture(61, 19);
        lot.start_unbond(61, 1).unwrap();
        let (parent, _, mut early) = fixture(floor - 1, 20);
        early.sequence = 2;
        sign(&mut early);
        assert!(early.validate(&parent, &lot).is_err());
        let (parent, _, mut ok) = fixture(floor, 20);
        ok.sequence = 2;
        sign(&mut ok);
        ok.validate(&parent, &lot).unwrap();
    }
    #[test]
    fn withdrawal_uses_parent_authorization_but_never_pays_same_block_burn() {
        let u = 60 + LOCK_HEIGHTS;
        let h = u + EVIDENCE_HEIGHTS;
        let (parent, mut lot, mut command) = fixture(h, 20);
        lot.start_unbond(u, 1).unwrap();
        command.sequence = 2;
        command.signature = SigningKey::from_bytes(&[61; 32])
            .sign(&command.signing_digest().unwrap())
            .to_bytes();
        command.validate(&parent, &lot).unwrap();
        let body = crate::blocks::BlockBody {
            height: h,
            reward_owner: [0; 32],
            fees: 0,
            transactions: vec![],
            operations: vec![command.encode().unwrap()],
        };
        // A registry is needed only for the post-state Q projection. Empty is
        // deliberate in this settlement unit fixture, not a certifiable chain.
        let mut state = State {
            bonds: BondBook {
                lots: [(lot.id, lot)].into_iter().collect(),
            },
            continuity: Some(
                crate::recovery::ContinuityState::bootstrap(
                    parent.genesis,
                    parent.fingerprint,
                    crate::recovery::Anchor {
                        height: parent.height,
                        tip: parent.block,
                        state_root: [0; 32],
                        registry_root: [0; 32],
                    },
                    command.owner,
                    vec![],
                )
                .unwrap(),
            ),
            ..Default::default()
        };
        let original = state.clone();
        let mut paid = state.clone();
        state
            .apply_bond_operations(&parent, &body, &mut paid)
            .unwrap();
        assert_eq!(
            paid.coins.values().map(|c| c.output.atoms).sum::<u64>(),
            MINIMUM_ATOMS
        );
        assert_eq!(paid.bonds.lots[&command.lot].status, LotStatus::Withdrawn);
        assert_eq!(
            paid.coins.values().next().unwrap().output.owner,
            address(&command.owner)
        );
        state.bonds.burn_exposed([5; 32], u, h, [9; 32]).unwrap();
        original
            .apply_bond_operations(&parent, &body, &mut state)
            .unwrap();
        assert!(state.coins.is_empty());
        assert_eq!(state.bonds.lots[&command.lot].status, LotStatus::Burned);
        assert_eq!(
            original.bonds.lots[&command.lot].status,
            LotStatus::Unbonding
        );
        let mut invalid_body = body;
        let mut invalid_command = command;
        invalid_command.signature[0] ^= 1;
        invalid_body.operations = vec![invalid_command.encode().unwrap()];
        // A burn must not let an invalid withdrawal authorization pass.
        assert!(
            original
                .apply_bond_operations(&parent, &invalid_body, &mut state)
                .is_err()
        );
    }
}
