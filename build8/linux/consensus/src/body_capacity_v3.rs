//! Store-issued canonical parent capacity. Structural parsing never selects a rule.
use crate::{Error, Hash, Result, anchors::FinalizedAnchor, blocks::BlockBody, execution::State};

pub const MAX_ORDINARY_ITEM_BYTES: usize = 16_384;
pub const MAX_LEGACY_BODY_BYTES: usize = 65_536;
pub const MAX_ITEMS: usize = 4_096;
pub const MAX_OVERSIZED_A2_ITEMS: usize = 1;
pub const MAX_A2_OPERATION_BYTES: usize = 196_608;
pub const MAX_BODY_BYTES: usize = 262_150;
pub const MAX_ENVELOPE_BYTES: usize = 1_942_044;
pub const MAX_PROPOSAL_BYTES: usize = 270_871;

/// Cannot be constructed from peer state, a fingerprint, or a caller enable flag.
/// Historical capabilities permit verification, never old-height signing.
#[derive(Clone, Debug)]
pub struct BodyCapacity {
    parent: FinalizedAnchor,
    parent_state_root: Hash,
    a2: bool,
}
impl BodyCapacity {
    /// The canonical store authenticates the state/root and parent in one snapshot.
    /// Internal native execution paths already accept authenticated parent state.
    pub(crate) fn from_authenticated_parent(
        state: &State,
        parent: FinalizedAnchor,
        root: Hash,
    ) -> Result<Self> {
        if state.root().map_err(|_| Error::WrongAnchor)? != root {
            return Err(Error::WrongAnchor);
        }
        Self::selected(state, parent, root)
    }
    /// ParentContext is private and validates canonical roots or carries a fully verified
    /// recovery projection. Its canonical root must never be replaced by a projected root.
    pub(crate) fn from_parent_context(
        context: crate::parent_context_v2::ParentContext<'_>,
    ) -> Result<Self> {
        Self::selected(context.state(), context.parent().clone(), context.root())
    }
    fn selected(state: &State, parent: FinalizedAnchor, root: Hash) -> Result<Self> {
        let parameters = state
            .protocol_records
            .get(&crate::genesis_v2::parameters_key())
            .map(|raw| crate::genesis_v2::Parameters::decode(raw).map_err(|_| Error::Codec))
            .transpose()?;
        let a2 = parameters
            .as_ref()
            .map(crate::endorsement_revocation_v1::enabled)
            .transpose()?
            .unwrap_or(false);
        if parameters
            .as_ref()
            .map(|p| p.fingerprint().map_err(|_| Error::WrongFingerprint))
            .transpose()?
            .is_some_and(|fingerprint| fingerprint != parent.fingerprint)
        {
            return Err(Error::WrongFingerprint);
        }
        Ok(Self {
            parent,
            parent_state_root: root,
            a2,
        })
    }
    pub fn parent(&self) -> &FinalizedAnchor {
        &self.parent
    }
    pub fn parent_state_root(&self) -> Hash {
        self.parent_state_root
    }
    pub fn allows_a2(&self) -> bool {
        self.a2
    }
    pub fn body_limit(&self) -> usize {
        if self.a2 {
            MAX_BODY_BYTES
        } else {
            MAX_LEGACY_BODY_BYTES
        }
    }
    pub fn envelope_limit(&self) -> usize {
        if self.a2 {
            MAX_ENVELOPE_BYTES
        } else {
            crate::block_envelope_v2::MAX_ENVELOPE_BYTES
        }
    }
    pub fn proposal_limit(&self) -> usize {
        if self.a2 { MAX_PROPOSAL_BYTES } else { 74_257 }
    }
    /// Exact typed codec selection only. Full native execution authenticates the evidence.
    pub fn supported_a2_operation(&self, raw: &[u8]) -> Result<u8> {
        if !self.a2 {
            return Err(Error::WrongFingerprint);
        }
        supported_a2_operation(raw)
    }
    pub fn encode(&self, body: &BlockBody) -> Result<Vec<u8>> {
        if self.parent.height.checked_add(1) != Some(body.height) {
            return Err(Error::WrongAnchor);
        }
        // Cheap borrowed bounds precede typed parsing, body cloning and encoding.
        // A candidate at this preflight boundary still needs every exact/native check.
        let oversized = self.preflight_raw(body)?;
        if !self.a2 {
            return body.encode();
        }
        if let Some(index) = oversized {
            self.supported_a2_operation(&body.operations[index])?;
        }
        let mut projection = body.clone();
        if let Some(index) = oversized {
            projection.operations.remove(index);
        }
        // Re-encode the exact remaining fields/order; no estimated raw-size shortcut.
        projection.encode()?;
        let ordinary_raw = projection
            .transactions
            .iter()
            .chain(projection.operations.iter())
            .try_fold(0usize, |n, r| n.checked_add(r.len()))
            .ok_or(Error::Capacity)?;
        if ordinary_raw > MAX_LEGACY_BODY_BYTES {
            return Err(Error::Capacity);
        }
        body.encode_with_reserved_a2(oversized)
    }
    fn preflight_raw(&self, body: &BlockBody) -> Result<Option<usize>> {
        self.preflight_lists(&body.transactions, &body.operations)
    }
    /// Cheap borrowed-list rejection for native assemblers across crates before any body clone.
    /// Structural quotas do not authenticate a carrier or replace exact encoding/execution.
    pub fn preflight_lists(
        &self, transactions: &[Vec<u8>], operations: &[Vec<u8>],
    ) -> Result<Option<usize>> {
        if transactions.len().checked_add(operations.len())
            .is_none_or(|n| n > MAX_ITEMS)
        {
            return Err(Error::Capacity);
        }
        if transactions.iter().any(|raw| raw.len() > MAX_ORDINARY_ITEM_BYTES)
            || operations.iter().any(|raw| raw.len() > if self.a2 {
                MAX_A2_OPERATION_BYTES
            } else { MAX_ORDINARY_ITEM_BYTES })
        {
            return Err(Error::Oversize);
        }
        let raw_limit = if self.a2 {
            MAX_LEGACY_BODY_BYTES + MAX_A2_OPERATION_BYTES
        } else { MAX_LEGACY_BODY_BYTES };
        if transactions.iter().chain(operations.iter())
            .try_fold(0usize, |n, raw| n.checked_add(raw.len()))
            .is_none_or(|n| n > raw_limit)
        {
            return Err(Error::Capacity);
        }
        let mut oversized = None;
        let mut ordinary_raw = transactions.iter()
            .try_fold(0usize, |n, raw| n.checked_add(raw.len()))
            .ok_or(Error::Capacity)?;
        for (index, raw) in operations.iter().enumerate() {
            if raw.len() > MAX_ORDINARY_ITEM_BYTES {
                if oversized.replace(index).is_some() { return Err(Error::Capacity); }
            } else {
                ordinary_raw = ordinary_raw.checked_add(raw.len()).ok_or(Error::Capacity)?;
            }
        }
        if ordinary_raw > MAX_LEGACY_BODY_BYTES { return Err(Error::Capacity); }
        Ok(oversized)
    }
    pub fn decode(&self, raw: &[u8]) -> Result<BlockBody> {
        if !self.a2 {
            let body = BlockBody::decode(raw)?;
            self.encode(&body)?;
            return Ok(body);
        }
        self.authorize(UntrustedA2Candidate::decode(raw)?)
    }
    pub fn authorize(&self, candidate: UntrustedA2Candidate) -> Result<BlockBody> {
        if self.encode(&candidate.body)? != candidate.exact {
            return Err(Error::NonCanonical);
        }
        Ok(candidate.body)
    }
    pub fn root(&self, body: &BlockBody) -> Result<Hash> {
        Ok(crate::domain_hash(
            b"MUTINY-BUILD8-BODY-V1",
            &self.encode(body)?,
        ))
    }
    /// A2 OP identity shares existing lifecycle identity semantics; TX tag25 is separate.
    pub fn operation_id(&self, raw: &[u8]) -> crate::operation_index_v2::Result<(u8, Hash)> {
        let kind = self
            .supported_a2_operation(raw)
            .map_err(|_| crate::operation_index_v2::IndexError::Codec)?;
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(2).unwrap().u8(kind).unwrap().bytes(raw).unwrap();
        Ok((
            kind,
            crate::domain_hash(
                crate::operation_index_v2::LIFECYCLE_ID_DOMAIN,
                &e.into_writer(),
            ),
        ))
    }
}

/// Canonical exact body bytes bounded for ingress. Contains no authenticated rule.
#[derive(Debug)]
pub struct UntrustedA2Candidate {
    body: BlockBody,
    exact: Vec<u8>,
}
impl UntrustedA2Candidate {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let body = BlockBody::decode_untrusted_a2(raw)?;
        Ok(Self {
            body,
            exact: raw.to_vec(),
        })
    }
    pub fn body(&self) -> &BlockBody {
        &self.body
    }
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
}
fn supported_a2_operation(raw: &[u8]) -> Result<u8> {
    if raw.len() > MAX_A2_OPERATION_BYTES {
        return Err(Error::Oversize);
    }
    let mut d = minicbor::Decoder::new(raw);
    let count = d.array().map_err(|_| Error::Codec)?;
    let version = d.u8().map_err(|_| Error::Codec)?;
    let kind = d.u8().map_err(|_| Error::Codec)?;
    match (version, kind, count) {
        (3, 15 | 16, Some(4)) => Ok(crate::admission_public_v3::Carrier::decode(raw)?.kind()),
        (2, 25, Some(5)) => {
            crate::endorsement_revocation_v1::Operation::decode(raw)?;
            Ok(25)
        }
        _ => Err(Error::WrongOperation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endorsement_revocation_v1::{Context,Evidence,Operation,Target,TargetClass,TargetScope};
    // Structural-only TEST capability. Public code cannot construct this private selector.
    // The public report payload below is not authenticated revocation evidence.
    fn capacity(a2: bool) -> BodyCapacity {
        BodyCapacity { parent:FinalizedAnchor {network:crate::NETWORK_ID,genesis:[1;32],fingerprint:[2;32],height:9,block:[3;32]}, parent_state_root:[4;32],a2 }
    }
    fn operation(size: usize, identity: u8) -> Vec<u8> {
        Operation { context:Context {genesis:[1;32],fingerprint:[2;32],parent_height:9,parent_block:[3;32],parent_state:[4;32],height:10,timestamp:1000},
            target:Target {class:TargetClass::Root,scope:TargetScope::Certificate,identity:[identity;32]},
            evidence:Evidence::Judgment {reason:b"PUBLIC SYNTHETIC SIZE-ONLY REPORT; NOT AUTHENTICATED".to_vec(),evidence:vec![vec![b'x';size]]} }.encode().unwrap()
    }
    fn body(operations:Vec<Vec<u8>>) -> BlockBody {
        BlockBody {height:10,reward_owner:[5;32],fees:0,transactions:vec![],operations}
    }
    #[test]
    fn candidate_rule_description_matches_independent_canonical_recomputation() {
        // Independently encoded unsigned canonical CBOR array29/version2, then SHA256
        // of unchanged rule domain || 00 || exact description. No fingerprint self-input.
        // This pins candidate order/bounds; it does not freeze or enable Production.
        let expected:Hash=hex::decode("167728892abc12847e8354d1d86fb2981145d2ae80a56831a019eed0e384b887")
            .unwrap().try_into().unwrap();
        assert_eq!(crate::endorsement_revocation_v1::rule_commitment(),expected);
    }
    #[test]
    fn raw_preflight_refuses_before_typed_parse_or_projection_allocation() {
        let cap = capacity(true);
        // Deliberately malformed byte strings isolate allocation preflight; neither
        // accepted raw bounds nor this TEST selector confer any evidence authority.
        let mut exact = body(vec![vec![0; MAX_A2_OPERATION_BYTES]]);
        exact.transactions = vec![vec![0; MAX_ORDINARY_ITEM_BYTES]; 4];
        assert_eq!(cap.preflight_raw(&exact), Ok(Some(0)));
        assert!(cap.encode(&exact).is_err()); // malformed typed inner remains refused
        exact.operations.push(vec![0]);
        assert_eq!(cap.preflight_raw(&exact), Err(Error::Capacity));
        assert_eq!(cap.encode(&exact), Err(Error::Capacity));
        let bad_ordinary = body(vec![vec![0; 14_000]; 5]);
        assert_eq!(cap.encode(&bad_ordinary), Err(Error::Capacity));
        let bad_count = body(vec![vec![]; MAX_ITEMS + 1]);
        assert_eq!(cap.encode(&bad_count), Err(Error::Capacity));
        let bad_size = body(vec![vec![0; MAX_A2_OPERATION_BYTES + 1]]);
        assert_eq!(cap.encode(&bad_size), Err(Error::Oversize));
        assert_eq!(capacity(false).encode(&body(vec![vec![0; 20_000]])), Err(Error::Oversize));
    }
    #[test]
    fn reserve_is_exact_typed_and_rule_selected_with_legacy_unchanged() {
        let large=body(vec![operation(100_000,6)]);let cap=capacity(true);
        assert!(large.encode().is_err());assert!(capacity(false).encode(&large).is_err());
        let raw=cap.encode(&large).unwrap();
        assert_eq!(cap.decode(&raw).unwrap(),large);
        assert_eq!(UntrustedA2Candidate::decode(&raw).unwrap().body(),&large);
        assert!(capacity(false).decode(&raw).is_err());
        assert_eq!(cap.root(&large).unwrap(),crate::domain_hash(b"MUTINY-BUILD8-BODY-V1",&raw));
        let small=body(vec![operation(8,6)]);
        assert_eq!(cap.encode(&small).unwrap(),small.encode().unwrap());
        assert_eq!(cap.operation_id(&small.operations[0]).unwrap().0,25);
        // OP arity5 cannot decode as FundedRotation TX tag25 arity7; kind23 is untouched.
        assert!(crate::hybrid_transaction_v2::Transaction::decode(&small.operations[0]).is_err());
        let mut wrong=small.operations[0].clone();wrong[3]=23;wrong.remove(2);
        assert!(cap.supported_a2_operation(&wrong).is_err());
    }
    #[test]
    fn second_oversized_item_and_other_namespaces_cannot_use_unused_reserve() {
        let cap=capacity(true);let two=body(vec![operation(20_000,6),operation(20_000,7)]);
        let before=two.clone();assert_eq!(cap.encode(&two),Err(Error::Capacity));assert_eq!(two,before);
        let mut tx=body(vec![]);tx.transactions.push(operation(20_000,6));
        assert_eq!(cap.encode(&tx),Err(Error::Oversize));
        let mut e=minicbor::Encoder::new(Vec::new());e.bytes(&vec![0;20_000]).unwrap();
        assert!(cap.encode(&body(vec![e.into_writer()])).is_err());
        assert_eq!(cap.encode(&BlockBody {height:11,..body(vec![])}),Err(Error::WrongAnchor));
    }
    #[test]
    fn structural_maximum_plus_one_trailing_and_total_count_refuse() {
        let cap=capacity(true);let encoded=cap.encode(&body(vec![operation(100_000,6)])).unwrap();
        let mut trailing=encoded;trailing.push(0);
        assert!(cap.decode(&trailing).is_err());
        assert!(UntrustedA2Candidate::decode(&vec![0;MAX_BODY_BYTES+1]).is_err());
        let too_many=body(vec![operation(8,6);MAX_ITEMS+1]);
        assert_eq!(cap.encode(&too_many),Err(Error::Capacity));
        assert_eq!(MAX_LEGACY_BODY_BYTES+MAX_A2_OPERATION_BYTES+5+1,MAX_BODY_BYTES);
        assert!(MAX_ENVELOPE_BYTES<2_097_152);
        assert_eq!(MAX_PROPOSAL_BYTES,512+8192+MAX_BODY_BYTES+17);
    }

    // Canonical malformed small operations below isolate structural budgets.
    // They NEVER represent accepted evidence or native/canonical admissions.
    fn syntax_item(index: u32, bytes: usize) -> Vec<u8> {
        let mut e=minicbor::Encoder::new(Vec::new());
        e.array(5).unwrap().u8(2).unwrap().u8(25).unwrap()
            .u32(index).unwrap().bytes(&vec![b'x';bytes]).unwrap().null().unwrap();
        e.into_writer()
    }
    #[test]
    fn structural_projection_array_widths_and_inclusive_item_count() {
        let cap=capacity(true);let large=operation(100_000,6);
        for ordinary_count in [22usize,23,254,255,4095] {
            let mut ordinary:Vec<_>=(0..ordinary_count).map(|i|syntax_item(i as u32,0)).collect();
            let projection=body(ordinary.clone());let projected=projection.encode().unwrap();
            ordinary.insert(ordinary_count/2,large.clone());let full=body(ordinary);
            let encoded=cap.encode(&full).unwrap();
            assert_eq!(cap.decode(&encoded).unwrap(),full);
            assert_eq!(encoded.len()-projected.len()-large.len()-5,
                usize::from(matches!(ordinary_count,23|255)));
            assert_eq!(full.operations.len(),ordinary_count+1);
        }
        let too_many=body((0..4096).map(|i|syntax_item(i,0))
            .chain(std::iter::once(large)).collect());
        assert_eq!(cap.encode(&too_many),Err(Error::Capacity));
    }
    #[test]
    fn structural_encoded_projection_exact_limit_and_one_byte_over() {
        let cap=capacity(true);
        let mut projection=body((0..4).map(|i|syntax_item(i,16_360)).collect());
        let initial=projection.encode().unwrap().len();
        assert!(initial<MAX_LEGACY_BODY_BYTES);
        let extra=MAX_LEGACY_BODY_BYTES-initial;
        projection.operations[3]=syntax_item(3,16_360+extra);
        assert!(projection.operations.iter().all(|raw|raw.len()<=MAX_ORDINARY_ITEM_BYTES));
        assert_eq!(projection.encode().unwrap().len(),MAX_LEGACY_BODY_BYTES);
        let mut full=projection.clone();full.operations.insert(2,operation(100_000,6));
        let raw=cap.encode(&full).unwrap();assert_eq!(cap.decode(&raw).unwrap(),full);
        let mut over=projection.clone();over.operations[3]=syntax_item(3,16_361+extra);
        assert_eq!(over.encode(),Err(Error::Oversize));
        over.operations.insert(2,operation(100_000,6));
        let before=over.clone();assert_eq!(cap.encode(&over),Err(Error::Oversize));
        assert_eq!(over,before);
    }
}
