//! Durable local production of parent ACKs and rolling physical refreshes.
//! Participation custody is separate from weighted BFT-voter eligibility.
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    canonical_store::CanonicalStore,
    freshness::{AttestationRefresh, PhysicalAttestationVerifier, PhysicalMember},
    participation::{ParentMember, ParticipationAck},
};
use rusqlite::{Connection, OptionalExtension, params};
use std::{collections::BTreeMap, path::Path};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Participation producer: {e:?}")
}
/// Implement with exclusive admitted physical-TPM custody. These purpose-bound
/// methods cannot request a BFT vote or replace a counter-backed voter journal.
pub trait ParticipationSigner {
    fn public_key(&self) -> [u8; 33];
    fn acknowledgement(&mut self, ack: &ParticipationAck) -> Result<[u8; 64]>;
    fn refresh_quote(&mut self, refresh: &AttestationRefresh) -> Result<Vec<u8>>;
}
pub struct Producer {
    db: Connection,
    genesis: Hash,
    fingerprint: Hash,
    node: Hash,
}
impl Producer {
    pub fn open(path: &Path, genesis: Hash, fingerprint: Hash, node: Hash) -> Result<Self> {
        let mut db = Connection::open(path).map_err(err)?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(err)?;
        db.execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;
          CREATE TABLE IF NOT EXISTS participation_context(id INTEGER PRIMARY KEY CHECK(id=1),binding BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS participation_pending(id INTEGER PRIMARY KEY CHECK(id=1),basis BLOB NOT NULL,ack BLOB,refresh BLOB);").map_err(err)?;
        let binding = [genesis.as_slice(), fingerprint.as_slice(), node.as_slice()].concat();
        let t = db.transaction().map_err(err)?;
        let old:Option<Vec<u8>>=t.query_row("SELECT CASE WHEN length(binding)=96 THEN binding END FROM participation_context WHERE id=1",[],|r|r.get(0)).optional().map_err(err)?;
        if let Some(old) = old {
            if old != binding {
                return Err("Participation context mismatch".into());
            }
        } else {
            t.execute("INSERT INTO participation_context VALUES(1,?1)", [binding])
                .map_err(err)?;
        }
        t.commit().map_err(err)?;
        Ok(Self {
            db,
            genesis,
            fingerprint,
            node,
        })
    }
    /// At most two bounded public operations are cached. Repeated calls/restart
    /// return the same signature bytes; only canonical publication earns credit.
    pub fn produce<V: PhysicalAttestationVerifier>(
        &mut self,
        chain: &mut CanonicalStore,
        signer: &mut impl ParticipationSigner,
        physical: &BTreeMap<Hash, PhysicalMember>,
        verifier: &V,
    ) -> Result<Vec<Vec<u8>>> {
        if chain.integrity_halted().map_err(err)? {
            return Err("Canonical integrity halt".into());
        }
        let (tip, state) = chain.load_effective().map_err(err)?;
        let (parent, _) = chain.execution_parent(tip.height).map_err(err)?;
        if (parent.genesis, parent.fingerprint) != (self.genesis, self.fingerprint) {
            return Err("Canonical participation context mismatch".into());
        }
        let anchor = FinalizedAnchor {
            network: NETWORK_ID,
            genesis: self.genesis,
            fingerprint: self.fingerprint,
            height: tip.height,
            block: tip.block,
        };
        self.produce_parent(&anchor, &state, signer, physical, verifier)
    }
    fn produce_parent<V: PhysicalAttestationVerifier>(
        &mut self,
        anchor: &FinalizedAnchor,
        state: &mutiny_consensus_v8::execution::State,
        signer: &mut impl ParticipationSigner,
        physical: &BTreeMap<Hash, PhysicalMember>,
        verifier: &V,
    ) -> Result<Vec<Vec<u8>>> {
        anchor
            .validate_context(self.genesis, self.fingerprint)
            .map_err(err)?;
        let member = state
            .continuity
            .as_ref()
            .ok_or("Registry absent")?
            .members
            .iter()
            .find(|m| m.node == self.node)
            .ok_or("Node not admitted")?;
        if !member.physical
            || !member.eligible
            || state.penalties.revoked(member.lineage)
            || member.voting_key != signer.public_key()
        {
            return Err("Ineligible participation custody".into());
        }
        let profile = physical
            .get(&self.node)
            .ok_or("Qualified physical profile absent")?;
        if profile.node != self.node
            || profile.generation != member.generation
            || profile.continuity_key != member.voting_key
            || profile.hardware != member.hardware
            || profile.admission_commitment != member.attestation
        {
            return Err("Physical profile differs from canonical registry".into());
        }
        let height = anchor.height.checked_add(1).ok_or("Height exhausted")?;
        let projected = ParentMember {
            node: self.node,
            generation: member.generation,
            key: member.voting_key,
            admitted: true,
            physical: true,
            revoked: false,
            freshness: state.accounting.freshness.get(&self.node).cloned(),
        };
        let eligible = projected
            .freshness
            .as_ref()
            .is_some_and(|f| f.eligible(self.node, member.generation, member.voting_key, height));
        // A ten-height local scheduling margin, not a consensus freshness rule.
        let needs_refresh = !eligible
            || projected
                .freshness
                .as_ref()
                .and_then(|f| f.committed_height.checked_add(60))
                .and_then(|last| last.checked_sub(height))
                .is_none_or(|remaining| remaining <= 10);
        let basis = [
            anchor.encode(),
            state.root().map_err(err)?.to_vec(),
            member.voting_key.to_vec(),
        ]
        .concat();
        let malformed:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM participation_pending WHERE length(basis)>256 OR (ack IS NOT NULL AND length(ack)>16384) OR (refresh IS NOT NULL AND length(refresh)>16384))",[],|r|r.get(0)).map_err(err)?;
        if malformed {
            return Err("Participation cache record bound".into());
        }
        type Cached = (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>);
        let cached:Option<Cached>=self.db.query_row("SELECT CASE WHEN length(basis)<=256 THEN basis END,CASE WHEN length(ack)<=16384 THEN ack END,CASE WHEN length(refresh)<=16384 THEN refresh END FROM participation_pending WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(err)?;
        if let Some((old, ack, refresh)) = cached {
            if old == basis {
                if ack.is_some() != eligible || refresh.is_some() != needs_refresh {
                    return Err("Participation cache shape mismatch".into());
                }
                let mut result = Vec::new();
                if let Some(raw) = ack {
                    let ack = ParticipationAck::decode(&raw).map_err(err)?;
                    ack.verify(&anchor, &projected).map_err(err)?;
                    result.push(raw);
                }
                if let Some(raw) = refresh {
                    let refresh = AttestationRefresh::decode(&raw).map_err(err)?;
                    refresh.validate(&anchor, profile, verifier).map_err(err)?;
                    result.push(raw);
                }
                return Ok(result);
            }
        }
        let ack = if eligible {
            let mut ack = ParticipationAck {
                network: NETWORK_ID,
                genesis: self.genesis,
                fingerprint: self.fingerprint,
                node: self.node,
                height,
                parent: anchor.id(),
                generation: member.generation,
                signature: [0; 64],
            };
            ack.signature = signer.acknowledgement(&ack)?;
            ack.verify(&anchor, &projected).map_err(err)?;
            Some(ack.encode())
        } else {
            None
        };
        let refresh = if needs_refresh {
            let mut refresh = AttestationRefresh {
                network: NETWORK_ID,
                genesis: self.genesis,
                fingerprint: self.fingerprint,
                node: self.node,
                generation: member.generation,
                height,
                parent_anchor: anchor.id(),
                evidence: vec![],
            };
            refresh.evidence = signer.refresh_quote(&refresh)?;
            refresh.validate(&anchor, profile, verifier).map_err(err)?;
            Some(refresh.encode().map_err(err)?)
        } else {
            None
        };
        // No operation is returned before this FULL transaction commits.
        let t = self.db.transaction().map_err(err)?;
        t.execute(
            "INSERT OR REPLACE INTO participation_pending VALUES(1,?1,?2,?3)",
            params![basis, ack, refresh],
        )
        .map_err(err)?;
        t.commit().map_err(err)?;
        Ok(ack.into_iter().chain(refresh).collect())
    }
}
#[cfg(test)]
#[path = "participation_producer_tests.rs"]
mod tests;
