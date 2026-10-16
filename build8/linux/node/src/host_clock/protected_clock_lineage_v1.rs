//! Pure, documentary C4 storage contract. No native owner, authentication,
//! trusted observation, restart capability or production factory is implemented.
//! A normal Node must never use these decoded bytes as clock authority.
//! The future isolated owner makes Commit only from its own live authenticated
//! acquisition/engine; its Node IPC must not accept caller calibration records.
#![allow(dead_code)]

use mutiny_consensus_v8::holdover_clock_v1::{PersistedAnchor,ProtectedCheckpoint};
use sha2::{Digest, Sha256};

type Hash = [u8; 32];
const MAGIC: &[u8; 8] = b"MCLC4D01";
const SCOPE_LEN: usize = 4 * 32;
const BINDING_LEN: usize = 5 * 32;
const REQUEST_MAX: usize = 8 + 1 + BINDING_LEN + PersistedAnchor::LEN;
const HEADER_LEN: usize = 8 + SCOPE_LEN + 8 + 8 + 1 + 2;
/// Local artifact bound derived from fixed fields, not a consensus quota/TTL.
pub(super) const SNAPSHOT_MAX: usize = HEADER_LEN + REQUEST_MAX;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Length, Canonical, Anchor, Scope, Binding, Sequence, Exhausted, Regression,
    Pending, Frozen, NoRecord, CrossBootUnsupported, IntentNotReadBack,
    Readback, AmbiguousBefore, ForeignCurrent, Operation, Conflict,
}
type Result<T> = std::result::Result<T, Error>;

/// Exact documentary context; construction is not acceptance or authentication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Scope {
    genesis: Hash, network: Hash, rule: Hash, lineage: Hash,
}
impl Scope {
    pub(super) fn selected_document(genesis:Hash,network:Hash,rule:Hash,lineage:Hash)->Self {
        Self{genesis,network,rule,lineage}
    }
    fn encode(&self, out: &mut Vec<u8>) {
        for value in [&self.genesis, &self.network, &self.rule, &self.lineage] {
            out.extend_from_slice(value);
        }
    }
    pub(super) fn journal_context(&self)->Hash {
        let mut raw=Vec::with_capacity(SCOPE_LEN);self.encode(&mut raw);
        let mut hash=Sha256::new();hash.update(b"MCLC4-JOURNAL-CONTEXT-1");hash.update(raw);hash.finalize().into()
    }
    fn decode(cursor: &mut Cursor<'_>) -> Result<Self> {
        Ok(Self {genesis:cursor.hash()?, network:cursor.hash()?,
            rule:cursor.hash()?, lineage:cursor.hash()?})
    }
}

/// Exact accepted deployment/evidence/current-code/provider/profile preimages
/// must be validated by the genuine owner adapter, which does not yet exist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Binding {
    deployment: Hash, qualification: Hash, code_configuration: Hash,
    provider_context: Hash, profile: Hash,
}
impl Binding {
    pub(super) fn selected_document(deployment:Hash,qualification:Hash,
        code_configuration:Hash,provider_context:Hash,profile:Hash)->Self {
        Self{deployment,qualification,code_configuration,provider_context,profile}
    }
    pub(super) fn deployment(&self)->Hash {self.deployment}
    pub(super) fn profile(&self)->Hash {self.profile}
    fn encode(&self, out: &mut Vec<u8>) {
        for value in [&self.deployment, &self.qualification, &self.code_configuration,
            &self.provider_context, &self.profile] {out.extend_from_slice(value);}
    }
    fn decode(cursor: &mut Cursor<'_>) -> Result<Self> {
        Ok(Self {deployment:cursor.hash()?, qualification:cursor.hash()?,
            code_configuration:cursor.hash()?, provider_context:cursor.hash()?,
            profile:cursor.hash()?})
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Record {binding: Binding, anchor: PersistedAnchor}
/// Private owner-only compact deployment binding. The deployment digest is
/// the selected record's canonical commitment, including code/configuration
/// and profile. Qualification/provider remain explicit. A decoded compact
/// record is documentary: it cannot issue that selected-record authority.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactRecord {
    deployment: Hash, qualification: Hash, provider_context: Hash,
    anchor: PersistedAnchor,
}
/// The canonical deployment commitment already binds exact qualification,
/// provider and profile. Compacting those redundant digests leaves room for
/// complete engine gap/leap memory while retaining the established 579 bound.
#[derive(Clone,Debug,PartialEq,Eq)]
pub(super) struct ProtectedRecord {
    deployment:Hash,checkpoint:ProtectedCheckpoint,leap:[u8;27],
}
impl ProtectedRecord {
    const LEN:usize=32+ProtectedCheckpoint::LEN+27;
    fn selected(binding:&Binding,checkpoint:ProtectedCheckpoint,leap:[u8;27])->Result<Self> {
        if checkpoint.anchor().params.id()!=binding.profile {return Err(Error::Binding);}
        let memory=super::leap_policy::LeapMemory::from_protected_document(&leap).map_err(|_|Error::Canonical)?;
        if checkpoint.anchor().leap.policy!=super::leap_policy::POLICY_VERSION
            || memory.view(Some(checkpoint.anchor().lower_ms))!=checkpoint.anchor().leap.view {return Err(Error::Binding);}
        Ok(Self{deployment:binding.deployment,checkpoint,leap})
    }
    fn decode(raw:&[u8])->Result<Self> {
        if raw.len()!=Self::LEN {return Err(Error::Length);}
        let deployment=raw[..32].try_into().map_err(|_|Error::Length)?;
        let checkpoint=ProtectedCheckpoint::decode(&raw[32..32+ProtectedCheckpoint::LEN]).map_err(|_|Error::Anchor)?;
        let leap:[u8;27]=raw[32+ProtectedCheckpoint::LEN..].try_into().map_err(|_|Error::Length)?;
        super::leap_policy::LeapMemory::from_protected_document(&leap).map_err(|_|Error::Canonical)?;
        let record=Self{deployment,checkpoint,leap};if record.encode()!=raw {return Err(Error::Canonical);}Ok(record)
    }
    fn encode(&self)->Vec<u8> {
        let mut raw=Vec::with_capacity(Self::LEN);raw.extend_from_slice(&self.deployment);
        raw.extend_from_slice(&self.checkpoint.encode());raw.extend_from_slice(&self.leap);raw
    }
    pub(super) fn checkpoint(&self)->&ProtectedCheckpoint {&self.checkpoint}
    pub(super) fn leap_memory(&self)->&[u8;27] {&self.leap}
    fn matches(&self,binding:&Binding)->bool {
        self.deployment==binding.deployment && self.checkpoint.anchor().params.id()==binding.profile
    }
}
const _:()=assert!(64+ProtectedRecord::LEN<=BINDING_LEN+PersistedAnchor::LEN);
impl CompactRecord {
    fn selected(binding: &Binding, anchor: PersistedAnchor) -> Result<Self> {
        if anchor.params.id() != binding.profile {return Err(Error::Binding);}
        Ok(Self {deployment:binding.deployment, qualification:binding.qualification,
            provider_context:binding.provider_context, anchor})
    }
    fn matches(&self, binding:&Binding)->bool {
        self.deployment == binding.deployment && self.qualification == binding.qualification
            && self.provider_context == binding.provider_context
            && self.anchor.params.id() == binding.profile
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Operation {identity: Hash, content: Hash}
impl Operation {
    /// Content must be the exact authenticated request commitment, including
    /// opcode/context/expected sequence. This constructor authenticates nothing.
    pub(super) fn authenticated_document(identity:Hash, content:Hash)->Result<Self> {
        if identity == [0;32] || content == [0;32] {return Err(Error::Operation);}
        Ok(Self {identity,content})
    }
    pub(super) fn identity(&self)->Hash {self.identity}
    pub(super) fn content(&self)->Hash {self.content}
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Action {
    Commit(Record), Invalidate {floor: u64},
    ClientCommit {operation:Operation, record:CompactRecord},
    ClientInvalidate {operation:Operation, floor:u64},
    ProtectedCommit(ProtectedRecord),
    ProtectedClientCommit{operation:Operation,record:ProtectedRecord},
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Request {expected_sequence: u64, action: Action}
impl Request {
    pub(super) fn from_protected_engine(expected_sequence:u64,binding:&Binding,
        checkpoint:ProtectedCheckpoint,leap:[u8;27],operation:Option<Operation>)->Result<Self> {
        let record=ProtectedRecord::selected(binding,checkpoint,leap)?;
        let action=match operation {Some(operation)=>Action::ProtectedClientCommit{operation,record},None=>Action::ProtectedCommit(record)};
        Self::decode(&Self{expected_sequence,action}.encode())
    }
    /// Only an owner-held live engine may supply this anchor. It is local
    /// bookkeeping, never a Node IPC constructor or an authentication issuer.
    pub(super) fn from_engine(expected_sequence:u64,binding:Binding,
        anchor:PersistedAnchor)->Result<Self> {
        let request=Self{expected_sequence,action:Action::Commit(Record{binding,anchor})};
        Self::decode(&request.encode())
    }
    pub(super) fn invalidate_engine_floor(expected_sequence:u64,floor:u64)->Self {
        Self{expected_sequence,action:Action::Invalidate{floor}}
    }
    pub(super) fn from_engine_for_operation(expected_sequence:u64,binding:&Binding,
        anchor:PersistedAnchor,operation:Operation)->Result<Self> {
        let record=CompactRecord::selected(binding,anchor)?;
        let request=Self{expected_sequence,action:Action::ClientCommit{operation,record}};
        Self::decode(&request.encode())
    }
    pub(super) fn invalidate_operation_floor(expected_sequence:u64,floor:u64,
        operation:Operation)->Result<Self> {
        let request=Self{expected_sequence,action:Action::ClientInvalidate{operation,floor}};
        Self::decode(&request.encode())
    }
    pub(super) fn operation(&self)->Option<&Operation> {
        match &self.action {
            Action::ClientCommit{operation,..}|Action::ClientInvalidate{operation,..}
                |Action::ProtectedClientCommit{operation,..}=>Some(operation),
            _=>None,
        }
    }
    /// Raw decoding is documentary only. There is no caller-authentication bit.
    pub(super) fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > REQUEST_MAX {return Err(Error::Length);}
        let mut cursor = Cursor::new(raw);
        let expected_sequence = cursor.u64()?;
        let action = match cursor.byte()? {
            0 => Action::Invalidate {floor:cursor.u64()?},
            1 => {
                let binding = Binding::decode(&mut cursor)?;
                let bytes = cursor.take(PersistedAnchor::LEN)?;
                let anchor = PersistedAnchor::decode(bytes).map_err(|_| Error::Anchor)?;
                if anchor.encode() != bytes || anchor.params.id() != binding.profile {
                    return Err(Error::Canonical);
                }
                let sequence = expected_sequence.checked_add(1).ok_or(Error::Exhausted)?;
                if anchor.sequence != sequence {return Err(Error::Sequence);}
                Action::Commit(Record {binding, anchor})
            }
            2 => {
                let operation=Operation::authenticated_document(cursor.hash()?,cursor.hash()?)?;
                let deployment=cursor.hash()?;
                let qualification=cursor.hash()?;
                let provider_context=cursor.hash()?;
                let bytes=cursor.take(PersistedAnchor::LEN)?;
                let anchor=PersistedAnchor::decode(bytes).map_err(|_|Error::Anchor)?;
                if anchor.encode()!=bytes {return Err(Error::Canonical);}
                if expected_sequence.checked_add(1)!=Some(anchor.sequence) {return Err(Error::Sequence);}
                Action::ClientCommit{operation,record:CompactRecord{deployment,qualification,provider_context,anchor}}
            }
            3 => {
                let operation=Operation::authenticated_document(cursor.hash()?,cursor.hash()?)?;
                Action::ClientInvalidate{operation,floor:cursor.u64()?}
            }
            tag @ (4|5)=> {
                let operation=if tag==5 {Some(Operation::authenticated_document(cursor.hash()?,cursor.hash()?)?)}else{None};
                let record=ProtectedRecord::decode(cursor.take(ProtectedRecord::LEN)?)?;
                if expected_sequence.checked_add(1)!=Some(record.checkpoint.anchor().sequence) {return Err(Error::Sequence);}
                match operation {Some(operation)=>Action::ProtectedClientCommit{operation,record},None=>Action::ProtectedCommit(record)}
            }
            _ => return Err(Error::Canonical),
        };
        cursor.end()?;
        let request = Self {expected_sequence, action};
        if request.encode() != raw {return Err(Error::Canonical);}
        Ok(request)
    }
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(REQUEST_MAX);
        out.extend_from_slice(&self.expected_sequence.to_be_bytes());
        match &self.action {
            Action::Invalidate {floor} => {out.push(0); out.extend_from_slice(&floor.to_be_bytes());}
            Action::Commit(record) => {
                out.push(1); record.binding.encode(&mut out);
                out.extend_from_slice(&record.anchor.encode());
            }
            Action::ClientCommit{operation,record} => {
                out.push(2);out.extend_from_slice(&operation.identity);out.extend_from_slice(&operation.content);
                for value in [&record.deployment,&record.qualification,&record.provider_context] {
                    out.extend_from_slice(value);
                }
                out.extend_from_slice(&record.anchor.encode());
            }
            Action::ClientInvalidate{operation,floor} => {
                out.push(3);out.extend_from_slice(&operation.identity);out.extend_from_slice(&operation.content);
                out.extend_from_slice(&floor.to_be_bytes());
            }
            Action::ProtectedCommit(record)=>{out.push(4);out.extend_from_slice(&record.encode());}
            Action::ProtectedClientCommit{operation,record}=>{
                out.push(5);out.extend_from_slice(&operation.identity);out.extend_from_slice(&operation.content);
                out.extend_from_slice(&record.encode());
            }
        }
        out
    }
    fn floor(&self) -> u64 {
        match &self.action {Action::Invalidate {floor} => *floor,
            Action::Commit(record) => record.anchor.high_water_ms,
            Action::ClientCommit{record,..}=>record.anchor.high_water_ms,
            Action::ClientInvalidate{floor,..}=>*floor,
            Action::ProtectedCommit(record)|Action::ProtectedClientCommit{record,..}=>record.checkpoint.anchor().high_water_ms}
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {Initial, Intent, Final}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    scope: Scope, sequence: u64, floor: u64, phase: Phase, request: Option<Request>,
}
impl Snapshot {
    /// Native production startup must refuse a missing file, not invoke this.
    /// Only the separately installed owner may establish an initial lineage.
    fn initial_document(scope: Scope) -> Self {
        Self {scope, sequence:0, floor:0, phase:Phase::Initial, request:None}
    }
    pub(super) fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() < HEADER_LEN || raw.len() > SNAPSHOT_MAX {return Err(Error::Length);}
        let mut cursor = Cursor::new(raw);
        if cursor.take(MAGIC.len())? != MAGIC {return Err(Error::Canonical);}
        let scope = Scope::decode(&mut cursor)?;
        let sequence = cursor.u64()?;
        let floor = cursor.u64()?;
        let phase = match cursor.byte()? {
            0 => Phase::Initial, 1 => Phase::Intent, 2 => Phase::Final,
            _ => return Err(Error::Canonical),
        };
        let length = cursor.u16()? as usize;
        if length > REQUEST_MAX {return Err(Error::Length);}
        let request = if length == 0 {None} else {Some(Request::decode(cursor.take(length)?)?)};
        cursor.end()?;
        match (&phase, &request) {
            (Phase::Initial, None) if sequence == 0 && floor == 0 => (),
            (Phase::Intent | Phase::Final, Some(request)) => {
                if request.expected_sequence.checked_add(1) != Some(sequence)
                    || request.floor() != floor {return Err(Error::Canonical);}
            }
            _ => return Err(Error::Canonical),
        }
        let snapshot = Self {scope, sequence, floor, phase, request};
        if snapshot.encode() != raw {return Err(Error::Canonical);}
        Ok(snapshot)
    }
    pub(super) fn encode(&self) -> Vec<u8> {
        let request = self.request.as_ref().map(Request::encode).unwrap_or_default();
        let mut out = Vec::with_capacity(HEADER_LEN + request.len());
        out.extend_from_slice(MAGIC); self.scope.encode(&mut out);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.floor.to_be_bytes());
        out.push(match self.phase {Phase::Initial => 0, Phase::Intent => 1, Phase::Final => 2});
        // Request has only fixed-sized variants, far below u16::MAX.
        out.extend_from_slice(&(request.len() as u16).to_be_bytes());
        out.extend_from_slice(&request); out
    }
    /// Exact-content commitment only: an unkeyed digest never authenticates.
    pub(super) fn content_digest(&self) -> Hash {Sha256::digest(self.encode()).into()}
    pub(super) fn sequence(&self) -> u64 {self.sequence}
    pub(super) fn floor(&self) -> u64 {self.floor}
}

#[derive(Clone, Debug)]
pub(super) struct Plan {before: Snapshot, intent: Snapshot, after: Snapshot}
impl Plan {
    pub(super) fn before(&self) -> Vec<u8> {self.before.encode()}
    pub(super) fn intent(&self) -> Vec<u8> {self.intent.encode()}
    pub(super) fn completion(&self) -> Vec<u8> {self.after.encode()}
}
pub(super) enum Begin {Plan(Plan), ExactLastRetry(Snapshot)}
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Reconcile {IntentRetained, CompletionObserved}

/// Pure bookkeeping only; no method returns a TimeBasis/qualified capability.
/// Durable intent is spent before completion. Unknown outcomes remain frozen.
pub(super) struct DocumentaryEngine {
    head: Snapshot, plan: Option<Plan>, intent_read_back: bool, frozen: bool,
}
impl DocumentaryEngine {
    pub(super) fn from_document(expected: &Scope, raw: &[u8]) -> Result<Self> {
        let head = Snapshot::decode(raw)?;
        if &head.scope != expected {return Err(Error::Scope);}
        // A pending crash cannot be auto-completed or rolled back at startup.
        let frozen = head.phase == Phase::Intent;
        Ok(Self {head, plan:None, intent_read_back:false, frozen})
    }
    pub(super) fn begin(&mut self, request: Request) -> Result<Begin> {
        if self.frozen || self.plan.is_some() {return Err(Error::Frozen);}
        if let (Some(previous),Some(requested))=(self.head.request.as_ref().and_then(Request::operation),request.operation()) {
            if previous.identity==requested.identity && previous.content!=requested.content {
                return Err(Error::Conflict);
            }
        }
        if self.head.phase == Phase::Final && self.head.request.as_ref() == Some(&request) {
            return Ok(Begin::ExactLastRetry(self.head.clone()));
        }
        if request.expected_sequence != self.head.sequence {return Err(Error::Sequence);}
        let sequence = self.head.sequence.checked_add(1).ok_or(Error::Exhausted)?;
        if request.floor() < self.head.floor {return Err(Error::Regression);}
        // Revalidate even an internal request, before state mutation.
        Request::decode(&request.encode())?;
        let intent = Snapshot {scope:self.head.scope.clone(), sequence,
            floor:request.floor(), phase:Phase::Intent, request:Some(request)};
        let after = Snapshot {phase:Phase::Final, ..intent.clone()};
        let plan = Plan {before:self.head.clone(), intent, after};
        self.frozen = true;
        self.intent_read_back = false;
        self.plan = Some(plan.clone());
        Ok(Begin::Plan(plan))
    }
    pub(super) fn intent_readback(&mut self, raw: &[u8]) -> Result<()> {
        self.intent_read_back=false;
        let plan = self.plan.as_ref().ok_or(Error::Pending)?;
        if raw != plan.intent() {self.frozen=true; return Err(Error::Readback);}
        Snapshot::decode(raw)?;
        self.intent_read_back = true;
        Ok(())
    }
    pub(super) fn completion_readback(&mut self, raw: &[u8]) -> Result<()> {
        if !self.intent_read_back {return Err(Error::IntentNotReadBack);}
        // An attempted readback consumes the observed ordering prerequisite.
        // A refused/unknown result requires exact intent reconciliation first.
        self.intent_read_back=false;
        let plan = self.plan.as_ref().ok_or(Error::Pending)?;
        if raw != plan.completion() {self.frozen=true; return Err(Error::Readback);}
        Snapshot::decode(raw)?;
        self.head = plan.after.clone(); self.plan=None;
        self.intent_read_back=false; self.frozen=false;
        Ok(())
    }
    /// Call before returning any native commit/sync/readback/identity error.
    /// The real clock service must revoke its consumers independently (C5).
    pub(super) fn unknown(&mut self) {self.frozen=true; self.intent_read_back=false;}
    /// Stop-only reconstruction of the exact retained FINAL head. This never
    /// resolves or discards an outstanding plan, and grants no qualification.
    /// The native owner must still compare this exact head with held storage
    /// and the append-only journal before writing ONLY an invalidation.
    pub(super) fn stopped_final(&self)->bool {
        self.plan.is_none() && self.head.phase==Phase::Final
            && matches!(self.head.request.as_ref().map(|r|&r.action),Some(Action::Invalidate{..}))
    }
    pub(super) fn retained_scope(&self)->Scope {self.head.scope.clone()}
    pub(super) fn for_stop_invalidation(&self)->Result<Self> {
        if self.plan.is_some() || self.head.phase!=Phase::Final{return Err(Error::Frozen);}
        Self::from_document(&self.head.scope,&self.head.encode())
    }
    pub(super) fn reconcile_document(&mut self, raw: &[u8]) -> Result<Reconcile> {
        self.frozen=true; self.intent_read_back=false;
        let observed = Snapshot::decode(raw)?;
        if observed.scope != self.head.scope {return Err(Error::Scope);}
        let plan = self.plan.as_ref().ok_or(Error::Pending)?;
        if raw == plan.completion() {
            self.head = plan.after.clone(); self.plan=None; self.frozen=false;
            return Ok(Reconcile::CompletionObserved);
        }
        if raw == plan.intent() {self.intent_read_back=true; return Ok(Reconcile::IntentRetained);}
        if raw == plan.before() {return Err(Error::AmbiguousBefore);}
        Err(Error::ForeignCurrent)
    }
    /// A same-boot *document* for existing diagnostic assess_restart only.
    /// No authentication or qualified continuity is implied by matching fields.
    pub(super) fn same_boot_document(&self, expected: &Binding, boot: u128)
        -> Result<&PersistedAnchor> {
        if self.frozen || self.head.phase != Phase::Final {return Err(Error::Frozen);}
        let anchor=match &self.head.request {
            Some(Request{action:Action::Commit(record),..})=>{
                if &record.binding!=expected {return Err(Error::Binding);}&record.anchor
            },
            Some(Request{action:Action::ClientCommit{record,..},..})=>{
                if !record.matches(expected) {return Err(Error::Binding);}&record.anchor
            },
            _=>return Err(Error::NoRecord),
        };
        if anchor.at.boot_id != boot {return Err(Error::CrossBootUnsupported);}
        Ok(anchor)
    }
    /// Complete protected checkpoint only. Legacy records remain documentary
    /// and cannot gain restart authority through this accessor.
    pub(super) fn protected_record(&self,expected:&Binding)->Result<Option<&ProtectedRecord>> {
        if self.frozen || self.head.phase!=Phase::Final {return Err(Error::Frozen);}
        let record=match &self.head.request {
            Some(Request{action:Action::ProtectedCommit(record),..})
                |Some(Request{action:Action::ProtectedClientCommit{record,..},..})=>record,
            _=>return Ok(None),
        };
        if !record.matches(expected){return Err(Error::Binding);}Ok(Some(record))
    }
    /// Only the latest durable operation is retained in this bounded head.
    /// Full arbitrary-ID retry requires the separate retained operation journal;
    /// this method must not be presented as that journal or a qualified reply.
    pub(super) fn latest_operation_document(&self,operation:&Operation)->Result<Option<(u64,u64)>> {
        if self.frozen || self.plan.is_some() {return Err(Error::Frozen);}
        let Some(previous)=self.head.request.as_ref().and_then(Request::operation) else {return Ok(None);};
        if previous.identity!=operation.identity {return Ok(None);}
        if previous.content!=operation.content {return Err(Error::Conflict);}
        if self.head.phase!=Phase::Final {return Err(Error::Pending);}
        Ok(Some((self.head.sequence,self.head.floor)))
    }
    pub(super) fn frozen(&self) -> bool {self.frozen}
    /// Exact documentary before-image for the native adapter. Equality here
    /// does not certify current ownership, authentication, or qualification.
    pub(super) fn current_document(&self) -> Vec<u8> {self.head.encode()}
    pub(super) fn sequence(&self)->u64 {self.head.sequence}
    pub(super) fn floor(&self)->u64 {self.head.floor}
}

struct Cursor<'a> {raw: &'a [u8], offset: usize}
impl<'a> Cursor<'a> {
    fn new(raw: &'a [u8]) -> Self {Self {raw, offset:0}}
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(n).ok_or(Error::Length)?;
        let value = self.raw.get(self.offset..end).ok_or(Error::Length)?;
        self.offset=end; Ok(value)
    }
    fn byte(&mut self) -> Result<u8> {Ok(self.take(1)?[0])}
    fn u16(&mut self) -> Result<u16> {Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| Error::Length)?))}
    fn u64(&mut self) -> Result<u64> {Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| Error::Length)?))}
    fn hash(&mut self) -> Result<Hash> {self.take(32)?.try_into().map_err(|_| Error::Length)}
    fn end(&self) -> Result<()> {if self.offset==self.raw.len() {Ok(())} else {Err(Error::Canonical)}}
}

#[cfg(test)]
mod tests {
    use super::*;
    use mutiny_consensus_v8::holdover_clock_v1::{
        ClockProfile, ControlledElapsed, HoldoverClock, LeapView, SourceSample,
    };
    fn scope() -> Scope {Scope {genesis:[1;32],network:[2;32],rule:[3;32],lineage:[4;32]}}
    fn engine() -> DocumentaryEngine {
        let initial=Snapshot::initial_document(scope()).encode();
        DocumentaryEngine::from_document(&scope(),&initial).unwrap()
    }
    fn invalidate(seq:u64,floor:u64)->Request {Request {expected_sequence:seq,action:Action::Invalidate{floor}}}
    fn plan(engine:&mut DocumentaryEngine,request:Request)->Plan {
        match engine.begin(request).unwrap(){Begin::Plan(p)=>p,_=>panic!("new modeled plan required")}
    }
    fn complete(engine:&mut DocumentaryEngine,p:&Plan) {
        engine.intent_readback(&p.intent()).unwrap();engine.completion_readback(&p.completion()).unwrap();
    }
    /// Exact existing anchor_store.rs MODELED profile/input; no measured clock.
    fn commit(seq:u64)->Request {
        let params=ClockProfile {max_source_uncertainty_ms:248,max_calibration_half_width_ms:250,
            min_sources:1,max_faulty_sources:0,drift_bound_ppb:8680,max_holdover_ms:86_400_000,
            max_interval_half_width_ms:1000,max_suspend_gap_ms:50,confirm_calibrations:1};
        let elapsed=ControlledElapsed::start(5);
        let clock=HoldoverClock::new(params,elapsed.clone()).unwrap();
        clock.set_leap_view(LeapView::Clear {valid_until_ms:u64::MAX});
        clock.calibrate(&[SourceSample {source:"chrony-nts".into(),authenticated:true,
            utc_ms:1_790_899_300_000,uncertainty_ms:13,at:elapsed.now()}]).unwrap();
        let anchor=clock.persisted(seq+1,1).unwrap();
        let binding=Binding {deployment:[1;32],qualification:[2;32],code_configuration:[3;32],
            provider_context:[4;32],profile:anchor.params.id()};
        Request {expected_sequence:seq,action:Action::Commit(Record {binding,anchor})}
    }
    #[test] fn canonical_initial_and_invalidation_roundtrip() {
        let mut e=engine();let p=plan(&mut e,invalidate(0,10));
        for bytes in [p.before(),p.intent(),p.completion()]{assert_eq!(Snapshot::decode(&bytes).unwrap().encode(),bytes);}
    }
    #[test] fn canonical_length_tags_trailing_and_partial_refused() {
        let raw=Snapshot::initial_document(scope()).encode();
        for n in 0..raw.len(){assert!(Snapshot::decode(&raw[..n]).is_err());}
        let mut extra=raw.clone();extra.push(0);assert!(Snapshot::decode(&extra).is_err());
        let mut tag=raw;tag[8+SCOPE_LEN+16]=255;assert!(Snapshot::decode(&tag).is_err());
        assert!(Snapshot::decode(&vec![0;SNAPSHOT_MAX+1]).is_err());
    }
    #[test] fn reservation_freezes_and_completion_requires_intent_readback() {
        let mut e=engine();let p=plan(&mut e,invalidate(0,10));assert!(e.frozen());
        assert_eq!(e.completion_readback(&p.completion()),Err(Error::IntentNotReadBack));
        assert!(matches!(e.begin(invalidate(0,11)),Err(Error::Frozen)));complete(&mut e,&p);assert!(!e.frozen());
    }
    #[test] fn exact_last_retry_has_no_new_sequence_different_content_refuses() {
        let mut e=engine();let request=invalidate(0,10);let p=plan(&mut e,request.clone());complete(&mut e,&p);
        assert!(matches!(e.begin(request),Ok(Begin::ExactLastRetry(s)) if s.sequence()==1));
        assert!(matches!(e.begin(invalidate(0,11)),Err(Error::Sequence)));
    }
    #[test] fn lower_floor_preflight_does_not_change_current_document() {
        let mut e=engine();let p=plan(&mut e,invalidate(0,10));complete(&mut e,&p);let before=e.head.encode();
        assert!(matches!(e.begin(invalidate(1,9)),Err(Error::Regression)));assert_eq!(e.head.encode(),before);assert!(!e.frozen());
    }
    #[test] fn pending_startup_cannot_auto_finish_or_reset() {
        let mut e=engine();let p=plan(&mut e,invalidate(0,10));let mut reopened=DocumentaryEngine::from_document(&scope(),&p.intent()).unwrap();
        assert!(reopened.frozen());assert!(matches!(reopened.begin(invalidate(1,10)),Err(Error::Frozen)));
        assert_eq!(reopened.completion_readback(&p.completion()),Err(Error::IntentNotReadBack));
    }
    #[test] fn ambiguous_before_stays_frozen_without_deleting_intent() {
        let mut e=engine();let p=plan(&mut e,invalidate(0,10));e.unknown();
        assert_eq!(e.reconcile_document(&p.before()),Err(Error::AmbiguousBefore));assert!(e.frozen());assert!(e.plan.is_some());
    }
    #[test] fn lost_ack_exact_completion_reconciles_document_only() {
        let mut e=engine();let p=plan(&mut e,invalidate(0,10));e.unknown();
        assert_eq!(e.reconcile_document(&p.completion()),Ok(Reconcile::CompletionObserved));assert_eq!(e.head.floor(),10);
        assert!(matches!(&e.head.request.as_ref().unwrap().action,Action::Invalidate{..}));
    }
    #[test] fn partial_or_foreign_readback_keeps_unknown_state() {
        let mut e=engine();let p=plan(&mut e,invalidate(0,10));e.unknown();
        assert!(e.reconcile_document(&p.intent()[..HEADER_LEN]).is_err());assert!(e.frozen());
        let mut foreign=p.intent;foreign.scope.network=[99;32];
        assert_eq!(e.reconcile_document(&foreign.encode()),Err(Error::Scope));assert!(e.frozen());
    }
    #[test] fn sequence_exhaustion_refuses_before_mutation() {
        let head=Snapshot {scope:scope(),sequence:u64::MAX,floor:10,phase:Phase::Final,
            request:Some(invalidate(u64::MAX-1,10))};
        let mut e=DocumentaryEngine::from_document(&scope(),&head.encode()).unwrap();
        assert!(matches!(e.begin(invalidate(u64::MAX,10)),Err(Error::Exhausted)));assert!(!e.frozen());
    }
    #[test] fn foreign_current_scope_refused_and_invalidation_has_no_restart_record() {
        let raw=Snapshot::initial_document(scope()).encode();let mut wrong=scope();wrong.genesis=[99;32];
        assert!(matches!(DocumentaryEngine::from_document(&wrong,&raw),Err(Error::Scope)));
        let mut e=engine();let p=plan(&mut e,invalidate(0,10));complete(&mut e,&p);
        let binding=Binding {deployment:[1;32],qualification:[2;32],code_configuration:[3;32],provider_context:[4;32],profile:[5;32]};
        assert_eq!(e.same_boot_document(&binding,1),Err(Error::NoRecord));
    }
    #[test] fn same_boot_document_is_exact_binding_only_cross_boot_refuses() {
        let request=commit(0);let Action::Commit(record)=&request.action else {unreachable!()};
        let binding=record.binding.clone();let anchor=record.anchor.clone();
        let mut e=engine();let p=plan(&mut e,request);complete(&mut e,&p);
        assert_eq!(e.same_boot_document(&binding,5).unwrap(),&anchor);
        assert_eq!(e.same_boot_document(&binding,6),Err(Error::CrossBootUnsupported));
        for field in 0..5 {
            let mut wrong=binding.clone();
            match field {0=>wrong.deployment=[99;32],1=>wrong.qualification=[99;32],
                2=>wrong.code_configuration=[99;32],3=>wrong.provider_context=[99;32],
                _=>wrong.profile=[99;32]};
            assert_eq!(e.same_boot_document(&wrong,5),Err(Error::Binding));
        }
        e.unknown();assert_eq!(e.same_boot_document(&binding,5),Err(Error::Frozen));
    }
    #[test] fn commit_embedded_profile_sequence_and_anchor_integrity_refuse() {
        let request=commit(0);assert_eq!(Request::decode(&request.encode()).unwrap(),request);
        let mut wrong=request.clone();let Action::Commit(record)=&mut wrong.action else {unreachable!()};
        record.binding.profile=[99;32];assert_eq!(Request::decode(&wrong.encode()),Err(Error::Canonical));
        let mut wrong=request.clone();let Action::Commit(record)=&mut wrong.action else {unreachable!()};
        record.anchor.sequence=2;assert_eq!(Request::decode(&wrong.encode()),Err(Error::Sequence));
        let mut raw=request.encode();let n=raw.len()-1;raw[n]^=1;
        assert_eq!(Request::decode(&raw),Err(Error::Anchor));
    }
    #[test] fn failed_completion_consumes_ordering_prerequisite_until_reconciliation() {
        let mut e=engine();let p=plan(&mut e,invalidate(0,10));e.intent_readback(&p.intent()).unwrap();
        assert_eq!(e.completion_readback(&p.before()),Err(Error::Readback));assert!(e.frozen());
        assert_eq!(e.completion_readback(&p.completion()),Err(Error::IntentNotReadBack));
        assert_eq!(e.reconcile_document(&p.intent()),Ok(Reconcile::IntentRetained));
        e.completion_readback(&p.completion()).unwrap();assert_eq!(e.head.floor(),10);
    }
    #[test] fn bad_intent_revokes_previous_readback_prerequisite() {
        let mut e=engine();let p=plan(&mut e,invalidate(0,10));e.intent_readback(&p.intent()).unwrap();
        assert_eq!(e.intent_readback(&p.before()),Err(Error::Readback));
        assert_eq!(e.completion_readback(&p.completion()),Err(Error::IntentNotReadBack));assert!(e.frozen());
    }
}
