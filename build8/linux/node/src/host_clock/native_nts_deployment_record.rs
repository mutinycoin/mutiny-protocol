//! Bounded local deployment artifact verification, not a clock-approval issuer.
//! Ordinary code has no constructor for approved pins or native-context receipts.
//! Decoded configuration, hashes and matching context do not grant startup/votes.
//! Local installation selection/succession is adopted; genuine platform
//! measurement verification and authentic qualifying evidence remain unfinished.
use super::native_nts_backend::validate_profile;
use super::state_dir::ClockStateDir;
use mutiny_clock_native_nts_v1::{AcquisitionBounds, Config, Provider};
use mutiny_consensus_v8::holdover_clock_v1::ClockProfile;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

type Result<T> = std::result::Result<T, Error>;
const FORMAT: &str = "build8/native-nts/deployment-v1";
const MAX_BYTES: usize = 64 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Error { Bound, Json, Canonical, Schema, Configuration, MissingApproval,
    MissingContext, Digest, Context, Succession, Placement, MissingAcceptedInputs,
    MissingCurrentInputs, Genesis, GenesisScope, PlatformProfile, CurrentSoftware,
    Installation, MissingQualification, UnsupportedCurrentFacts, QualificationEncoding,
    QualificationScope, QualificationProvenance }

#[derive(Clone, Debug, PartialEq, Eq)]
enum AdmissionClass { LegacyTest, Production }

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DecodedRecord {
    canonical: Vec<u8>, profile: ClockProfile, acquisition: Config, class: AdmissionClass,
}
impl DecodedRecord {
    pub(super) fn profile(&self) -> &ClockProfile { &self.profile }
    pub(super) fn acquisition(&self) -> &Config { &self.acquisition }
    pub(super) fn canonical(&self) -> &[u8] { &self.canonical }
}

/// Immutable approved record pin. No normal factory, raw bytes constructor,
/// Deserialize, public feature or caller assertion grants this capability.
pub(super) struct ApprovedRecordPin { record: [u8; 32], context: [u8; 32] }
/// Independently verified native/configuration selection. The future issuer
/// must derive this from real inputs and adopted approval/succession semantics.
/// It cannot be manufactured from an untrusted record by ordinary callers.
pub(super) struct ExactNativeContext { expected: DecodedRecord }
pub(super) struct ValidatedRecord { record: DecodedRecord }
impl ValidatedRecord {
    pub(super) fn record(&self) -> &DecodedRecord { &self.record }
}

/// Exact deployment selection and its already-held C8/C12 storage owner.
/// Ordinary code has no constructor: an eventual issuer must authenticate the
/// anchor placement and existing cadence under the adopted selection contract.
/// A pathname or record digest alone is never such a capability. Not Clone.
pub(super) struct ApprovedNativePlacement {
    record: [u8; 32], state: ClockStateDir, cadence: Duration,
    selection: NativeSelectionGuard,
}

/// Moves the same protected installation into service lifetime. Not Clone.
/// This does not issue qualification: only the private installed-input pipeline
/// may provide an ordinary guard, after its separate mandatory receipt gates.
pub(super) struct NativeSelectionGuard { inner: SelectionInner }
enum SelectionInner {
    Installed {
        owner: super::installation_directory::InstallationDirectory,
        record: DecodedRecord,
        current: super::native_nts_current::CurrentSoftwareBoundary,
    },
    #[cfg(test)]
    Modeled {
        valid: std::sync::Arc<std::sync::atomic::AtomicBool>,
        released: std::sync::Arc<std::sync::atomic::AtomicBool>,
    },
}
pub(super) enum InstallationRetainedClose {
    Native(super::native_retained_close::RetainedCloseReport),
    Quarantined(std::mem::ManuallyDrop<super::installation_directory::InstallationDirectory>),
    #[cfg(test)]Modeled,
}
pub(super) struct SelectionRetainedClose {
    installation:InstallationRetainedClose,current:super::native_nts_current::CurrentRetainedClose,
}
impl SelectionRetainedClose {
    /// Explicit original retained descriptor closure only. No replacement,
    /// native qualification or closure of prior quarantined transient objects.
    pub(super) fn retained_handles_closed(&self)->bool {
        let installation=match &self.installation {InstallationRetainedClose::Native(r)=>r.retained_handles_closed(),
            InstallationRetainedClose::Quarantined(_)=>false,#[cfg(test)]InstallationRetainedClose::Modeled=>true};
        installation&&self.current.retained_handles_closed()
    }
}
impl NativeSelectionGuard {
    pub(super) fn close_retained(mut self)->std::result::Result<SelectionRetainedClose,std::mem::ManuallyDrop<Self>> {
        if self.recheck().is_err(){return Err(std::mem::ManuallyDrop::new(self));}
        // Self's Drop exists solely for the inherited private modeled-release
        // observer. Move its exact owned variant once, with no duplicate drop.
        let owned=std::mem::ManuallyDrop::new(self);
        let inner=unsafe{std::ptr::read(&owned.inner)};
        match inner {
            SelectionInner::Installed{owner,current,record:_}=>{
                let current=current.close_retained();
                let installation=match owner.close_retained(){Ok(r)=>InstallationRetainedClose::Native(r),
                    Err(owner)=>InstallationRetainedClose::Quarantined(std::mem::ManuallyDrop::new(owner))};
                Ok(SelectionRetainedClose{installation,current})
            },
            #[cfg(test)]SelectionInner::Modeled{valid,released}=>{
                valid.store(false,std::sync::atomic::Ordering::SeqCst);released.store(true,std::sync::atomic::Ordering::SeqCst);
                Ok(SelectionRetainedClose{installation:InstallationRetainedClose::Modeled,current:super::native_nts_current::CurrentRetainedClose::NoNativeObjects})
            },
        }
    }
    fn from_inputs(installed: &mut InstalledNativeInputs, current: &CurrentNativeInputs)
        -> Result<Self> {
        match installed.installation.take() {
            Some(owner) => Ok(Self { inner: SelectionInner::Installed { owner,
                record: installed.expected.clone(), current: current.current_software.clone() } }),
            // No nullable ordinary guard or caller-provided approval flag.
            #[cfg(test)]
            None if installed.expected.class == AdmissionClass::LegacyTest => Ok(Self::modeled()),
            None => Err(Error::MissingAcceptedInputs),
        }
    }
    #[cfg(test)]
    pub(super) fn modeled() -> Self {
        Self { inner: SelectionInner::Modeled {
            valid: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            released: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        } }
    }
    #[cfg(test)]
    pub(super) fn modeled_controls(&self) -> (
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        std::sync::Arc<std::sync::atomic::AtomicBool>) {
        match &self.inner {
            SelectionInner::Modeled {valid,released} => (valid.clone(),released.clone()),
            _ => panic!("modeled controls cannot inspect an installed owner"),
        }
    }
    pub(super) fn recheck(&mut self) -> std::result::Result<(),String> {
        match &mut self.inner {
            SelectionInner::Installed {owner,record,current} => {
                owner.recheck()?;
                current.recheck(record).map_err(|_| "native current software changed".to_owned())?;
                owner.recheck()
            },
            #[cfg(test)]
            SelectionInner::Modeled {valid,..} => {
                if valid.load(std::sync::atomic::Ordering::SeqCst) {Ok(())}
                else {Err("modeled selection retired".into())}
            },
        }
    }
}
impl Drop for NativeSelectionGuard {
    fn drop(&mut self) {
        #[cfg(test)]
        if let SelectionInner::Modeled {released,..} = &self.inner {
            released.store(true,std::sync::atomic::Ordering::SeqCst);
        }
    }
}
impl ApprovedNativePlacement {
    #[cfg(test)]
    fn modeled_test_value(record: &ValidatedRecord, state: ClockStateDir,
        cadence: Duration) -> Result<Self> {
        if record.record.class != AdmissionClass::LegacyTest
            || super::native_nts_service::validate_cadence(cadence).is_err() {
            return Err(Error::Placement);
        }
        Ok(Self { record: hash(record.record.canonical()), state, cadence,
            selection: NativeSelectionGuard::modeled() })
    }
    pub(super) fn into_parts(mut self, validated: ValidatedRecord)
        -> Result<(ClockProfile, Config, ClockStateDir, Duration, NativeSelectionGuard)> {
        if self.record != hash(validated.record.canonical()) {
            return Err(Error::Placement);
        }
        validate_profile(&validated.record.profile, &validated.record.acquisition)
            .map_err(|_| Error::Configuration)?;
        super::native_nts_service::validate_cadence(self.cadence)
            .map_err(|_| Error::Placement)?;
        // Final fresh software continuity gate before any backend restore.
        // Native capture is not a platform/deployment approval capability.
        self.selection.recheck().map_err(|_| Error::CurrentSoftware)?;
        // Move both same held owners; no path reopen or caller-derived context.
        Ok((validated.record.profile, validated.record.acquisition, self.state,
            self.cadence, self.selection))
    }
}

fn hash(bytes: &[u8]) -> [u8; 32] { Sha256::digest(bytes).into() }

/// Local installation succession preflight only. This does not install a pin,
/// qualify evidence, establish current facts, or open an anchor. Both complete
/// records must remain canonical and preserve the frozen protocol context.
/// The installed-input adapter must independently authorize the successor after
/// the old owner and all of its consumers have been revoked.
pub(super) fn require_successor(prior: &[u8], next: &[u8]) -> Result<()> {
    let prior = decode(prior)?;
    let next = decode(next)?;
    let p: Value = serde_json::from_slice(prior.canonical()).map_err(|_| Error::Json)?;
    let n: Value = serde_json::from_slice(next.canonical()).map_err(|_| Error::Json)?;
    let predecessor = hex::encode(hash(prior.canonical()));
    if n["succession"]["prior_record_sha256"].as_str() != Some(predecessor.as_str()) {
        return Err(Error::Succession);
    }
    for key in ["genesis_sha256", "network_sha256", "rule_sha256", "admission_class"] {
        if p["binding"][key] != n["binding"][key] { return Err(Error::GenesisScope); }
    }
    Ok(())
}

/// Independently accepted release/deployment selection, distinct from current
/// host observations. No raw-byte/public constructor or Deserialize. Ordinary
/// construction must retain the installation and pass the separate verifier;
/// its presently unavailable backend refuses rather than approving a hash.
pub(super) struct InstalledNativeInputs {
    genesis: crate::genesis_artifact_v2::TrustV2,
    expected: DecodedRecord,
    anchor: std::path::PathBuf,
    cadence: Duration,
    installation: Option<super::installation_directory::InstallationDirectory>,
}
/// Independently obtained current OS/boot/measurement/TLS/storage configuration
/// receipt. An installed record is not a current measurement. No ordinary issuer
/// is registered; the private software model cannot issue Production receipts.
pub(super) struct CurrentNativeInputs {
    expected: DecodedRecord,
    current_software: super::native_nts_current::CurrentSoftwareBoundary,
}

/// Own-Genesis trust is selected here by the existing binary-supported private
/// route, never by a caller's public Trust/VerifiedGenesis fields. The held
/// administrator descriptor pins exact artifact bytes; it does not choose the
/// compiled Approved manifest/class/target or qualify this clock.
struct AcceptedOwnGenesis {
    trust: crate::genesis_artifact_v2::TrustV2,
    verified: crate::genesis_artifact_v2::VerifiedGenesisV2,
}
fn accepted_own_genesis(selection:&mut super::native_nts_installation::InstalledSelection,
    own_genesis:&[u8])->Result<AcceptedOwnGenesis> {
    if own_genesis.is_empty() || own_genesis.len()>crate::genesis_artifact_v2::MAX_ARTIFACT {
        return Err(Error::Genesis);
    }
    selection.recheck().map_err(|_|Error::Installation)?;
    let descriptor=selection.descriptor();
    if hash(own_genesis)!=descriptor.genesis_artifact {return Err(Error::Genesis);}
    let trust=crate::genesis_artifact_v2::supported_trust_v2(
        descriptor.genesis_artifact,descriptor.genesis_block).map_err(|_|Error::Genesis)?;
    let verified=crate::genesis_artifact_v2::VerifiedGenesisV2::verify(own_genesis,&trust)
        .map_err(|_|Error::Genesis)?;
    check_own_genesis_scope(&descriptor.record,&verified)?;
    selection.recheck().map_err(|_|Error::Installation)?;
    Ok(AcceptedOwnGenesis {trust,verified})
}

/// Complete measurement verification over the same held public installation.
/// The accepted method policy, signed provenance and complete trace findings
/// are required; documentary matching alone never issues this capability.
struct QualificationVerifier;
struct QualifiedNativeInstallation {
    selection: super::native_nts_installation::InstalledSelection,
    genesis: AcceptedOwnGenesis,
}
impl QualificationVerifier {
    fn verify(self, mut selection:super::native_nts_installation::InstalledSelection,
        genesis:AcceptedOwnGenesis)->Result<QualifiedNativeInstallation> {
        selection.recheck().map_err(|_|Error::Installation)?;
        check_own_genesis_scope(&selection.descriptor().record,&genesis.verified)?;
        let evidence=super::native_nts_qualification::decode_and_bind(
            selection.exact_objects().2,&selection.descriptor().record,
            &selection.descriptor().anchor,selection.descriptor().cadence)?;
        selection.recheck().map_err(|_|Error::Installation)?;
        // This private normal path cannot use modeled findings or a caller
        // acceptance flag. The verifier consumes the exact held descriptor,
        // accepted issuer artifacts and complete retained measurement evidence.
        let findings=selection.verify_installed_methods(&evidence)?;
        findings.normal_qualification().map_err(|_|Error::MissingQualification)?;
        check_own_genesis_scope(&selection.descriptor().record,&genesis.verified)?;
        selection.recheck().map_err(|_|Error::Installation)?;
        Ok(QualifiedNativeInstallation {selection,genesis})
    }
}
fn installed_native_inputs(raw:&[u8],own_genesis:&[u8])->Result<InstalledNativeInputs> {
    let mut selection=super::native_nts_installation::InstalledSelection::read()
        .map_err(|_|Error::MissingAcceptedInputs)?;
    selection.require_requested_record(raw).map_err(|_|Error::Context)?;
    let genesis=accepted_own_genesis(&mut selection,own_genesis)?;
    // Missing or invalid selected methods, accepted issuer pins or authentic
    // complete evidence refuse here before any anchor is opened or restored.
    // Installation selection does not manufacture physical qualification.
    let qualified=QualificationVerifier.verify(selection,genesis)?;
    let QualifiedNativeInstallation {mut selection,genesis}=qualified;
    check_own_genesis_scope(&selection.descriptor().record,&genesis.verified)?;
    selection.recheck().map_err(|_|Error::Installation)?;
    let (descriptor,owner)=selection.into_parts();
    Ok(InstalledNativeInputs {genesis:genesis.trust,expected:descriptor.record,
        anchor:descriptor.anchor,cadence:descriptor.cadence,installation:Some(owner)})
}
fn current_native_inputs(installed:&mut InstalledNativeInputs)->Result<CurrentNativeInputs> {
    let owner=installed.installation.as_mut().ok_or(Error::MissingAcceptedInputs)?;
    let evidence=super::native_nts_qualification::decode_and_bind(owner.objects().2,
        &installed.expected,&installed.anchor,installed.cadence)?;
    let mut observed=super::native_nts_current::capture_current_bound(&installed.expected,
        evidence.current_contract()).map_err(|_|Error::UnsupportedCurrentFacts)?;
    observed.require_selected_loaded(&installed.expected).map_err(|_|Error::UnsupportedCurrentFacts)?;
    // Only the exact retained Linux release-v2 roster can pass here. The
    // installed record/qualification/current pipeline remains mandatory;
    // Windows loaded-code implementation is separately unfinished and refuses.
    // Mapped-file provenance is not private relocated-page or physical evidence.
    owner.recheck().map_err(|_|Error::Installation)?;
    Ok(CurrentNativeInputs{expected:installed.expected.clone(),current_software:observed})
}

/// Genuine ordinary dedicated-owner formation from the same fixed held
/// administrator selection. No raw descriptor/UID/path/acceptance argument,
/// fixture route, account setup, file creation or qualification fallback.
/// Missing measurement implementation still refuses before native state opens.
#[cfg(any(target_os="linux",windows))]
pub(super) fn open_installed_protected_owner(raw:&[u8],own_genesis:&[u8])
    ->Result<(super::protected_clock_owner::ProtectedClockOwner,
        super::native_nts_installation::OwnerPlacementDocument)> {
    open_installed_protected_owner_inner(raw,own_genesis,None,None).map(|(owner,placement,_)|(owner,placement))
}
/// Application scheduling receives ONLY the cadence from the same held and
/// fully verified installation. It is not a new timing/profile value.
#[cfg(any(target_os="linux",windows))]
pub(super) fn open_installed_protected_application(raw:&[u8],own_genesis:&[u8])
    ->Result<(super::protected_clock_owner::ProtectedClockOwner,Duration)> {
    open_installed_protected_owner_inner(raw,own_genesis,None,None).map(|(owner,_,cadence)|(owner,cadence))
}
/// Replacement proof is issued ONLY by the naturally joined/explicitly closed
/// predecessor application. The successor still passes every normal fixed
/// installation, own Genesis, qualification and current-code check.
#[cfg(any(target_os="linux",windows))]
pub(super) fn open_installed_protected_successor(raw:&[u8],own_genesis:&[u8],
    replacement:super::protected_clock_application::ProtectedClockReplacement)
    ->Result<(super::protected_clock_owner::ProtectedClockOwner,Duration)> {
    open_installed_protected_owner_inner(raw,own_genesis,None,Some(replacement.into_lineage()))
        .map(|(owner,_,cadence)|(owner,cadence))
}
/// Both channel ends independently traverse the exact installed qualification
/// and own-loaded-image path. No peer pathname, claimed image hash, raw UID or
/// network response can issue this authority. This is local consumer/owner
/// registration only; it makes no claim to measure the OTHER process's image.
#[cfg(target_os="linux")]
pub(super) fn issue_installed_channel(raw:&[u8],own_genesis:&[u8],
    role:super::protected_clock_unix_channel::ChannelRole)
    ->Result<super::protected_clock_unix_channel::InstalledChannelAuthority> {
    let mut selection=super::native_nts_installation::InstalledSelection::read()
        .map_err(|_|Error::MissingAcceptedInputs)?;
    selection.require_requested_record(raw).map_err(|_|Error::Context)?;
    let placement=selection.descriptor().protected_owner.clone().ok_or(Error::Placement)?;
    let genesis=accepted_own_genesis(&mut selection,own_genesis)?;
    let QualifiedNativeInstallation{mut selection,genesis}=QualificationVerifier.verify(selection,genesis)?;
    selection.recheck().map_err(|_|Error::Installation)?;
    let (descriptor,owner)=selection.into_parts();
    let mut installed=InstalledNativeInputs{genesis:genesis.trust,expected:descriptor.record,
        anchor:descriptor.anchor,cadence:descriptor.cadence,installation:Some(owner)};
    let current=current_native_inputs(&mut installed)?;
    let record=validate_installed_record(raw,own_genesis,&mut installed,&current)?;
    let mut guard=NativeSelectionGuard::from_inputs(&mut installed,&current)?;
    guard.recheck().map_err(|_|Error::CurrentSoftware)?;
    super::protected_clock_unix_channel::InstalledChannelAuthority::from_selected(record,guard,placement,role)
        .map_err(|_|Error::Placement)
}
/// Windows ordinary-build issuer. Missing physical evidence, authenticated
/// evidence verification, actual loaded-code receipt or held installation
/// refuses; no TEST Boolean or caller SID can manufacture this capability.
#[cfg(windows)]
pub(super) fn issue_installed_windows_channel(raw:&[u8],own_genesis:&[u8],
    role:super::protected_clock_windows_channel::ChannelRole)
    ->Result<super::protected_clock_windows_channel::InstalledWindowsAuthority> {
    let mut selection=super::native_nts_installation::InstalledSelection::read()
        .map_err(|_|Error::MissingAcceptedInputs)?;
    selection.require_requested_record(raw).map_err(|_|Error::Context)?;
    let placement=selection.descriptor().protected_owner.clone().ok_or(Error::Placement)?;
    placement.windows_principals().map_err(|_|Error::Placement)?;
    let genesis=accepted_own_genesis(&mut selection,own_genesis)?;
    let QualifiedNativeInstallation{mut selection,genesis}=QualificationVerifier.verify(selection,genesis)?;
    selection.recheck().map_err(|_|Error::Installation)?;
    let(descriptor,owner)=selection.into_parts();
    let mut installed=InstalledNativeInputs{expected:descriptor.record,genesis:genesis.trust,
        anchor:descriptor.anchor,cadence:descriptor.cadence,installation:Some(owner)};
    let current=current_native_inputs(&mut installed)?;
    let record=validate_installed_record(raw,own_genesis,&mut installed,&current)?;
    let mut guard=NativeSelectionGuard::from_inputs(&mut installed,&current)?;
    guard.recheck().map_err(|_|Error::CurrentSoftware)?;
    super::protected_clock_windows_channel::InstalledWindowsAuthority::from_selected(record,guard,placement,role)
        .map_err(|_|Error::Placement)
}
/// Exact authenticated installed recovery route; operation is a matching
/// documentary selector, never a caller's new calibration/admission command.
#[cfg(any(target_os="linux",windows))]
pub(super) fn reconcile_installed_protected_owner(raw:&[u8],own_genesis:&[u8],
    operation:super::protected_clock_lineage_v1::Operation)
    ->Result<(super::protected_clock_owner::ProtectedClockOwner,
        super::native_nts_installation::OwnerPlacementDocument)> {
    open_installed_protected_owner_inner(raw,own_genesis,Some(operation),None).map(|(owner,placement,_)|(owner,placement))
}
#[cfg(any(target_os="linux",windows))]
fn open_installed_protected_owner_inner(raw:&[u8],own_genesis:&[u8],
    reconciliation:Option<super::protected_clock_lineage_v1::Operation>,continuity:Option<super::protected_clock_owner::ClosedLineageContinuity>)
    ->Result<(super::protected_clock_owner::ProtectedClockOwner,
        super::native_nts_installation::OwnerPlacementDocument,Duration)> {
    let mut selection=super::native_nts_installation::InstalledSelection::read()
        .map_err(|_|Error::MissingAcceptedInputs)?;
    selection.require_requested_record(raw).map_err(|_|Error::Context)?;
    let placement=selection.descriptor().protected_owner.clone().ok_or(Error::Placement)?;
    let genesis=accepted_own_genesis(&mut selection,own_genesis)?;
    let QualifiedNativeInstallation{mut selection,genesis}=QualificationVerifier.verify(selection,genesis)?;
    selection.recheck().map_err(|_|Error::Installation)?;
    let (descriptor,owner)=selection.into_parts();
    let mut installed=InstalledNativeInputs{genesis:genesis.trust,expected:descriptor.record,
        anchor:descriptor.anchor,cadence:descriptor.cadence,installation:Some(owner)};
    let current=current_native_inputs(&mut installed)?;
    let record=validate_installed_record(raw,own_genesis,&mut installed,&current)?;
    let mut guard=NativeSelectionGuard::from_inputs(&mut installed,&current)?;
    guard.recheck().map_err(|_|Error::CurrentSoftware)?;
    if let Some(proof)=&continuity {
        proof.require_successor(raw,&placement).map_err(|_|Error::Context)?;
    }
    let io=placement.open_lineage().map_err(|_|Error::Placement)?;
    // Own the original writer and selection before the post-open current
    // bracket can refuse. Reuse the owner's constructor custody, not RAII
    // release on error/unwind. Each successful arm transfers exactly once.
    let mut construction=super::protected_clock_owner::ConstructingProtectedOwner::retain((guard,io));
    construction.get_mut().0.recheck().map_err(|_|Error::CurrentSoftware)?;
    let owner=match (reconciliation,continuity) {
        (Some(operation),None)=>{let(guard,io)=construction.publish();
            super::protected_clock_owner::ProtectedClockOwner::from_selected_reconciled(record,guard,io,placement.clone(),operation)},
        (None,Some(proof))=>{let(guard,io)=construction.publish();
            super::protected_clock_owner::ProtectedClockOwner::from_selected_successor(record,guard,io,placement.clone(),proof)},
        (None,None)=>{let(guard,io)=construction.publish();
            super::protected_clock_owner::ProtectedClockOwner::from_selected(record,guard,io,placement.clone())},
        (Some(_),Some(_))=>return Err(Error::Context),
    }.map_err(|_|Error::Placement)?;
    // Endpoint issuer/held native listener and replacement lifecycle remain
    // separate implementation work; returning a document is not IPC authority.
    Ok((owner,placement,installed.cadence))
}

/// Normal same-held-anchor route. It reads only the fixed protected installation
/// before the unavailable qualification/current gates, never the supplied anchor
/// or a caller-selected installation pathname. No task or restore precedes them.
pub(super) fn select_supported_native(record: &[u8], genesis: &[u8], state: ClockStateDir)
    -> Result<(ValidatedRecord, ApprovedNativePlacement)> {
    let mut installed=installed_native_inputs(record,genesis)?;
    let current=current_native_inputs(&mut installed)?;
    select_native_inputs(record,genesis,state,&mut installed,&current)
}

fn select_native_inputs(raw: &[u8], own_genesis: &[u8], state: ClockStateDir,
    installed: &mut InstalledNativeInputs, current: &CurrentNativeInputs)
    -> Result<(ValidatedRecord, ApprovedNativePlacement)> {
    let validated=validate_installed_record(raw,own_genesis,installed,current)?;
    if state.anchor_file()!=installed.anchor.as_path() { return Err(Error::Placement); }
    let selection=NativeSelectionGuard::from_inputs(installed,current)?;
    let placement=ApprovedNativePlacement {record:hash(raw),state,cadence:installed.cadence,
        selection};
    Ok((validated,placement))
}

fn validate_installed_record(raw:&[u8],own_genesis:&[u8],
    installed:&InstalledNativeInputs,current:&CurrentNativeInputs)->Result<ValidatedRecord> {
    // Full canonical bytes and existing validators, not nine numeric values or
    // an approval boolean. Current evidence is compared independently before any
    // persisted anchor reaches backend restore. No cached qualification used.
    let pin=ApprovedRecordPin {record:hash(installed.expected.canonical()),
        context:hash(current.expected.canonical())};
    let context=ExactNativeContext {expected:current.expected.clone()};
    let validated=validate(raw,Some(&pin),Some(&context))?;
    if validated.record!=installed.expected { return Err(Error::Context); }
    let verified=crate::genesis_artifact_v2::VerifiedGenesisV2::verify(own_genesis,
        &installed.genesis).map_err(|_|Error::Genesis)?;
    // Public VerifiedGenesisV2 fields are not accepted as caller authority: this
    // adapter itself reconstructs authenticated exact artifact bytes above.
    check_own_genesis_scope(validated.record(),&verified)?;
    super::native_nts_service::validate_cadence(installed.cadence)
        .map_err(|_|Error::Placement)?;
    Ok(validated)
}
/// Ordinary application route opens only the independently selected anchor,
/// once, after exact record/current/own-Genesis validation. No caller path.
pub(super) fn select_installed_native(raw:&[u8],own_genesis:&[u8])
    ->Result<(ValidatedRecord,ApprovedNativePlacement)> {
    select_installed_native_inner(raw,own_genesis,None)
}
pub(super) fn select_installed_native_replacement(raw:&[u8],own_genesis:&[u8],
    continuity:&super::anchor_store::ReplacementContinuity)
    ->Result<(ValidatedRecord,ApprovedNativePlacement)> {
    select_installed_native_inner(raw,own_genesis,Some(continuity))
}
fn select_installed_native_inner(raw:&[u8],own_genesis:&[u8],
    continuity:Option<&super::anchor_store::ReplacementContinuity>)
    ->Result<(ValidatedRecord,ApprovedNativePlacement)> {
    let mut installed=installed_native_inputs(raw,own_genesis)?;
    let current=current_native_inputs(&mut installed)?;
    let validated=validate_installed_record(raw,own_genesis,&mut installed,&current)?;
    let mut selection=NativeSelectionGuard::from_inputs(&mut installed,&current)?;
    selection.recheck().map_err(|_| Error::CurrentSoftware)?;
    // Check lineage before opening/creating anything at a selected new path.
    // Descriptor succession alone cannot reset the predecessor's clock floor.
    if let Some(continuity)=continuity {
        continuity.require_anchor(&installed.anchor).map_err(|_|Error::Placement)?;
    }
    let state=ClockStateDir::open(&installed.anchor).map_err(|_|Error::Placement)?;
    // These owners move directly into placement/backend/service. No duplicate open.
    Ok((validated,ApprovedNativePlacement {record:hash(raw),state,cadence:installed.cadence,
        selection}))
}

fn check_own_genesis_scope(record: &DecodedRecord,
    verified: &crate::genesis_artifact_v2::VerifiedGenesisV2) -> Result<()> {
    use mutiny_consensus_v8::genesis_v2::GenesisClass;
    let v:Value=serde_json::from_slice(record.canonical()).map_err(|_|Error::Json)?;
    let b=&v["binding"];
    let class=match verified.genesis.class {
        GenesisClass::TestValue=>AdmissionClass::LegacyTest,
        GenesisClass::Production=>AdmissionClass::Production,
    };
    // Local artifact contract proposed for review: native GenesisIdentity and
    // RuleFingerprint verbatim; SHA256 of the network u32 big-endian. This does
    // not introduce a consensus domain, carrier, StateRoot field or authority.
    if record.class!=class
        || digest(&b["genesis_sha256"])?!=verified.genesis.identity
        || digest(&b["rule_sha256"])?!=verified.genesis.fingerprint
        || digest(&b["network_sha256"])?!=hash(&verified.genesis.anchor().network.to_be_bytes()) {
        return Err(Error::GenesisScope);
    }
    let profile=digest(&b["platform_profile_sha256"])?;
    if !verified.inputs.parameters.pcr_profiles.profiles().any(|p|p.id()==profile) {
        return Err(Error::PlatformProfile);
    }
    // Host/platform_class/release/measurement and all fifteen context identities
    // are bound by the separate installed/current canonical receipts above.
    // PCR-set membership alone does not prove this host's current measurement.
    Ok(())
}

fn object<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>> {
    let map=value.as_object().ok_or(Error::Schema)?;
    if map.len()!=keys.len() || map.keys().any(|k| !keys.contains(&k.as_str())) {
        return Err(Error::Schema);
    }
    Ok(map)
}
fn integer(value: &Value) -> Result<u64> { value.as_u64().ok_or(Error::Schema) }
fn narrow(value: &Value) -> Result<u32> {
    u32::try_from(integer(value)?).map_err(|_| Error::Schema)
}
fn digest(value: &Value) -> Result<[u8; 32]> {
    let text=value.as_str().ok_or(Error::Schema)?;
    if text.len()!=64 || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(Error::Schema);
    }
    let mut out=[0;32];hex::decode_to_slice(text,&mut out).map_err(|_|Error::Schema)?;
    if out==[0;32] { return Err(Error::Schema); }
    Ok(out)
}
fn bounded_tree(value: &Value, depth: usize) -> Result<Value> {
    if depth>8 { return Err(Error::Bound); }
    match value {
        Value::Object(map) => {
            if map.len()>64 { return Err(Error::Bound); }
            // Explicit lexical insertion also remains canonical if another graph
            // ever enables serde_json/preserve_order. No ambient map order used.
            let mut keys:Vec<_>=map.keys().collect();keys.sort();let mut sorted=Map::new();
            for key in keys {
                if key.len()>128 { return Err(Error::Bound); }
                sorted.insert(key.clone(),bounded_tree(&map[key],depth+1)?);
            }
            Ok(Value::Object(sorted))
        }
        Value::Array(values) => {
            if values.len()>8 { return Err(Error::Bound); }
            Ok(Value::Array(values.iter().map(|v|bounded_tree(v,depth+1)).collect::<Result<_>>()?))
        }
        Value::String(text) => {
            if text.len()>1024 { return Err(Error::Bound); }
            Ok(value.clone())
        }
        Value::Number(number) if !number.is_u64() => Err(Error::Schema),
        _ => Ok(value.clone()),
    }
}
pub(super) fn canonical_tree(value:&Value)->Result<Value> {bounded_tree(value,0)}
fn profile(value: &Value) -> Result<ClockProfile> {
    let p=object(value,&["max_source_uncertainty_ms","max_calibration_half_width_ms",
        "min_sources","max_faulty_sources","drift_bound_ppb","max_holdover_ms",
        "max_interval_half_width_ms","max_suspend_gap_ms","confirm_calibrations"])?;
    Ok(ClockProfile {
        max_source_uncertainty_ms:integer(&p["max_source_uncertainty_ms"])?,
        max_calibration_half_width_ms:integer(&p["max_calibration_half_width_ms"])?,
        min_sources:narrow(&p["min_sources"])?,max_faulty_sources:narrow(&p["max_faulty_sources"])?,
        drift_bound_ppb:integer(&p["drift_bound_ppb"])?,max_holdover_ms:integer(&p["max_holdover_ms"])?,
        max_interval_half_width_ms:integer(&p["max_interval_half_width_ms"])?,
        max_suspend_gap_ms:integer(&p["max_suspend_gap_ms"])?,
        confirm_calibrations:narrow(&p["confirm_calibrations"])?,
    })
}
fn acquisition(value: &Value) -> Result<Config> {
    let a=object(value,&["providers","timeout_seconds","bounds"])?;
    let bounds=object(&a["bounds"],&["era_lower_posix_ns","era_upper_posix_ns",
        "era_context_sha256","maximum_sampling_span_ns","wall_timestamp_uncertainty_ns",
        "elapsed_drift_ppb","maximum_round_trip_ns","maximum_interval_uncertainty_ns"])?;
    digest(&bounds["era_context_sha256"])?;
    let bounds:AcquisitionBounds=serde_json::from_value(a["bounds"].clone()).map_err(|_|Error::Schema)?;
    let providers=a["providers"].as_array().ok_or(Error::Schema)?;
    if !(3..=8).contains(&providers.len()) { return Err(Error::Configuration); }
    let providers=providers.iter().map(|v| {
        let p=object(v,&["hostname","operator","key_establishment_port","no_smear_profile_evidence_sha256"])?;
        Ok(Provider {
            hostname:p["hostname"].as_str().ok_or(Error::Schema)?.to_owned(),
            operator:p["operator"].as_str().ok_or(Error::Schema)?.to_owned(),
            key_establishment_port:u16::try_from(integer(&p["key_establishment_port"])?).map_err(|_|Error::Schema)?,
            no_smear_profile_evidence_sha256:digest(&p["no_smear_profile_evidence_sha256"])?,
        })
    }).collect::<Result<Vec<_>>>()?;
    Ok(Config {providers,timeout_seconds:integer(&a["timeout_seconds"])?,bounds})
}

/// Decode and structure-check only. Canonical exact re-encoding rejects duplicate
/// keys (including duplicate-equal keys), alternate escapes, whitespace/numeric
/// spellings, unknown fields and omitted fields; no bytes are authority by itself.
pub(super) fn canonical_value(bytes:&[u8])->Result<Value> {
    if bytes.is_empty() || bytes.len()>MAX_BYTES { return Err(Error::Bound); }
    let parsed:Value=serde_json::from_slice(bytes).map_err(|_|Error::Json)?;
    let value=bounded_tree(&parsed,0)?;
    let canonical=serde_json::to_vec(&value).map_err(|_|Error::Json)?;
    if canonical!=bytes { return Err(Error::Canonical); }
    Ok(value)
}
pub(super) fn decode(bytes: &[u8]) -> Result<DecodedRecord> {
    let value=canonical_value(bytes)?;
    let canonical=bytes.to_vec();
    let root=object(&value,&["format","binding","profile","profile_id","acquisition","context","succession"])?;
    if root["format"].as_str()!=Some(FORMAT) { return Err(Error::Schema); }
    let binding=object(&root["binding"],&["genesis_sha256","network_sha256","rule_sha256",
        "admission_class","platform_class","platform_profile_sha256","host_sha256"])?;
    for name in ["genesis_sha256","network_sha256","rule_sha256","platform_profile_sha256","host_sha256"] {
        digest(&binding[name])?;
    }
    let class=match binding["admission_class"].as_str() {
        Some("LegacyTest")=>AdmissionClass::LegacyTest,
        Some("Production")=>AdmissionClass::Production,
        _=>return Err(Error::Schema),
    };
    integer(&binding["platform_class"])?;
    let fields=["tls_source_sha256","tls_trust_policy_sha256","tls_verification_clock_policy_sha256",
        "tls_revocation_policy_sha256","os_build_sha256","elapsed_abi_sha256","boot_abi_sha256",
        "measurement_sha256","leap_policy_sha256","storage_boundary_sha256","anchor_policy_sha256",
        "code_sha256","config_sha256","qualification_sha256","qualification_scope_sha256"];
    let context=object(&root["context"],&fields)?;
    for name in fields { digest(&context[name])?; }
    let succession=object(&root["succession"],&["prior_record_sha256","approval_succession_sha256"])?;
    if !succession["prior_record_sha256"].is_null() {digest(&succession["prior_record_sha256"])?;}
    digest(&succession["approval_succession_sha256"])?;
    let profile=profile(&root["profile"])?;
    if digest(&root["profile_id"])?!=profile.id() { return Err(Error::Configuration); }
    let acquisition=acquisition(&root["acquisition"])?;
    validate_profile(&profile,&acquisition).map_err(|_|Error::Configuration)?;
    Ok(DecodedRecord {canonical,profile,acquisition,class})
}

pub(super) fn validate(bytes: &[u8], approval: Option<&ApprovedRecordPin>,
    native: Option<&ExactNativeContext>) -> Result<ValidatedRecord> {
    let approval=approval.ok_or(Error::MissingApproval)?;
    let native=native.ok_or(Error::MissingContext)?;
    let record=decode(bytes)?;
    if hash(bytes)!=approval.record { return Err(Error::Digest); }
    if hash(native.expected.canonical())!=approval.context { return Err(Error::Context); }
    // Every actual selected configuration/context/succession byte is immutable
    // and independently compared, not just nine profile values or public hashes.
    if record!=native.expected { return Err(Error::Context); }
    Ok(ValidatedRecord {record})
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{native_nts_service::{AuthorizedNativeDeployment, NativeNtsService},
        state_dir::StorageError};
    use std::{path::PathBuf, sync::atomic::{AtomicU64, Ordering}};

    fn selected_anchor(name: &str) -> PathBuf {
        static NEXT: AtomicU64=AtomicU64::new(0);
        let root=PathBuf::from(std::env::var_os("BUILD8_NATIVE_NTS_TEST_ROOT")
            .expect("explicit protected public TEST fixture root required"));
        let metadata=std::fs::symlink_metadata(&root).expect("fixture root missing");
        assert!(root.is_absolute() && metadata.is_dir() && !metadata.file_type().is_symlink());
        let dir=root.join(format!("native-nts-selected-{name}-{}-{}",std::process::id(),
            NEXT.fetch_add(1,Ordering::Relaxed)));
        match std::fs::symlink_metadata(&dir) {
            Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},
            _=>panic!("new protected fixture leaf required"),
        }
        eprintln!("retained public TEST selected-placement fixture: {}",dir.display());
        dir.join("clock.anchor")
    }
    fn validated(v: &Value) -> ValidatedRecord {
        let (raw,pin,context)=model(v);
        validate(&raw,Some(&pin),Some(&context)).unwrap()
    }
    fn assert_locked(anchor: &std::path::Path) {
        assert!(matches!(ClockStateDir::open(anchor),Err(StorageError::Locked(_))));
    }
    fn sample() -> Value {
        // Existing DEVELOPMENT profile/bounds only; no hardware qualification.
        let p=ClockProfile {max_source_uncertainty_ms:248,max_calibration_half_width_ms:250,
            min_sources:3,max_faulty_sources:1,drift_bound_ppb:100_000,max_holdover_ms:10_000,
            max_interval_half_width_ms:1000,max_suspend_gap_ms:50,confirm_calibrations:1};
        let mut fields=Map::new();
        for (name,value) in [("max_source_uncertainty_ms",p.max_source_uncertainty_ms),
            ("max_calibration_half_width_ms",p.max_calibration_half_width_ms),("min_sources",p.min_sources as u64),
            ("max_faulty_sources",p.max_faulty_sources as u64),("drift_bound_ppb",p.drift_bound_ppb),
            ("max_holdover_ms",p.max_holdover_ms),("max_interval_half_width_ms",p.max_interval_half_width_ms),
            ("max_suspend_gap_ms",p.max_suspend_gap_ms),("confirm_calibrations",p.confirm_calibrations as u64)] {
            fields.insert(name.into(),value.into());
        }
        let mut context=Map::new();
        for name in ["tls_source_sha256","tls_trust_policy_sha256","tls_verification_clock_policy_sha256",
            "tls_revocation_policy_sha256","os_build_sha256","elapsed_abi_sha256","boot_abi_sha256",
            "measurement_sha256","leap_policy_sha256","storage_boundary_sha256","anchor_policy_sha256",
            "code_sha256","config_sha256","qualification_sha256","qualification_scope_sha256"] {
            context.insert(name.into(),"b".repeat(64).into());
        }
        serde_json::json!({"format":FORMAT,
            "binding":{"genesis_sha256":"1".repeat(64),"network_sha256":"2".repeat(64),
                "rule_sha256":"3".repeat(64),"admission_class":"LegacyTest","platform_class":90,
                "platform_profile_sha256":"4".repeat(64),"host_sha256":"5".repeat(64)},
            "profile":Value::Object(fields),"profile_id":hex::encode(p.id()),
            "acquisition":{"providers":(1..=3).map(|n|serde_json::json!({"hostname":format!("source{n}.invalid"),
                "operator":format!("Operator{n}"),"key_establishment_port":4460,
                "no_smear_profile_evidence_sha256":hex::encode([n as u8;32])})).collect::<Vec<_>>(),
                "timeout_seconds":10,"bounds":{"era_lower_posix_ns":1_577_836_800_000_000_000u64,
                    "era_upper_posix_ns":2_208_988_800_000_000_000u64,"era_context_sha256":"a".repeat(64),
                    "maximum_sampling_span_ns":250_000_000,"wall_timestamp_uncertainty_ns":1_000_000,
                    "elapsed_drift_ppb":100_000,"maximum_round_trip_ns":1_000_000_000u64,
                    "maximum_interval_uncertainty_ns":200_000_000}},
            "context":Value::Object(context),"succession":{"prior_record_sha256":null,
                "approval_succession_sha256":"c".repeat(64)}})
    }
    fn bytes(v:&Value)->Vec<u8> {serde_json::to_vec(&bounded_tree(v,0).unwrap()).unwrap()}
    #[test] fn local_successor_names_exact_prior_and_preserves_frozen_protocol_context() {
        let original=bytes(&sample());
        let mut next=sample();
        next["succession"]["prior_record_sha256"]=hex::encode(hash(&original)).into();
        next["context"]["qualification_sha256"]="d".repeat(64).into();
        assert_eq!(require_successor(&original,&bytes(&next)),Ok(()));
        for field in ["genesis_sha256","network_sha256","rule_sha256","admission_class"] {
            let mut changed=next.clone();
            changed["binding"][field]=if field=="admission_class" {
                "Production".into()
            }else{"e".repeat(64).into()};
            assert_eq!(require_successor(&original,&bytes(&changed)),Err(Error::GenesisScope));
        }
        for predecessor in [Value::Null,Value::String("e".repeat(64))] {
            let mut changed=next.clone();
            changed["succession"]["prior_record_sha256"]=predecessor;
            assert_eq!(require_successor(&original,&bytes(&changed)),Err(Error::Succession));
        }
        assert_eq!(require_successor(&original,&original),Err(Error::Succession));
    }
    #[test] fn local_successor_structural_preflight_does_not_grant_installation_authority() {
        let original=bytes(&sample());let mut next=sample();
        next["succession"]["prior_record_sha256"]=hex::encode(hash(&original)).into();
        let raw=bytes(&next);
        assert_eq!(require_successor(&original,&raw),Ok(()));
        let context=ExactNativeContext{expected:decode(&raw).unwrap()};
        assert!(matches!(validate(&raw,None,Some(&context)),Err(Error::MissingApproval)));
        let mut noncanonical=raw.clone();noncanonical.push(b' ');
        assert_eq!(require_successor(&original,&noncanonical),Err(Error::Canonical));
    }
    #[test] fn modeled_installation_descriptor_binds_complete_public_record_and_evidence() {
        use super::super::native_nts_installation::decode_descriptor;
        let evidence=b"PUBLIC MODELED MEASUREMENT: NO PHYSICAL QUALIFICATION";
        let mut value=sample();
        value["context"]["qualification_sha256"]=hex::encode(hash(evidence)).into();
        let deployment=bytes(&value);
        let anchor=std::env::current_dir().unwrap().join("public-unused-clock.anchor");
        let descriptor=serde_json::json!({
            "format":"build8/native-nts/installation-v1",
            "record_sha256":hex::encode(hash(&deployment)),
            "qualification_sha256":hex::encode(hash(evidence)),
            "genesis_artifact_sha256":"6".repeat(64),
            "genesis_block_sha256":"7".repeat(64),
            "anchor":anchor.to_str().unwrap(),"cadence_seconds":1});
        let raw=bytes(&descriptor);
        let selected=decode_descriptor(&raw,&deployment,evidence).unwrap();
        assert_eq!(selected.record.canonical(),deployment.as_slice());
        assert_eq!(selected.qualification,hash(evidence));
        assert_eq!(selected.anchor,anchor);
        assert_eq!(selected.cadence,Duration::from_secs(1));
        assert_eq!(selected.genesis_artifact,[0x66;32]);
        assert_eq!(selected.genesis_block,[0x77;32]);
        // This is structural TEST evidence only; no issuer is constructed.
        assert!(super::super::native_nts_qualification::decode_and_bind(evidence,
            &selected.record,&selected.anchor,selected.cadence).is_err());
        assert!(decode_descriptor(&raw,&deployment,b"SUBSTITUTED PUBLIC EVIDENCE").is_err());
        let mut altered=value.clone();altered["binding"]["host_sha256"]="e".repeat(64).into();
        assert!(decode_descriptor(&raw,&bytes(&altered),evidence).is_err());
        for field in ["unexpected","cadence_seconds","anchor","qualification_sha256"] {
            let mut bad=descriptor.clone();
            bad[field]=match field {
                "cadence_seconds"=>0.into(),"anchor"=>"relative.anchor".into(),
                "qualification_sha256"=>"e".repeat(64).into(),_=>true.into(),
            };
            assert!(decode_descriptor(&bytes(&bad),&deployment,evidence).is_err());
        }
        let mut whitespace=raw.clone();whitespace.push(b' ');
        assert!(decode_descriptor(&whitespace,&deployment,evidence).is_err());
        let duplicate=String::from_utf8(raw.clone()).unwrap().replacen("{","{\"format\":\"build8/native-nts/installation-v1\",",1);
        assert!(decode_descriptor(duplicate.as_bytes(),&deployment,evidence).is_err());
        assert!(decode_descriptor(&raw,&deployment,&vec![b'x';64*1024+1]).is_err());
    }
    fn model(v:&Value)->(Vec<u8>,ApprovedRecordPin,ExactNativeContext) {
        let raw=bytes(v);let expected=decode(&raw).unwrap();
        // Private explicitly modeled independent approval/native context. No
        // ordinary constructor or actual deployment authentication is supplied.
        let pin=ApprovedRecordPin {record:hash(&raw),context:hash(expected.canonical())};
        (raw,pin,ExactNativeContext {expected})
    }
    #[test] fn canonical_record_validates_only_under_explicit_modeled_context() {
        let (raw,pin,context)=model(&sample());
        let r=validate(&raw,Some(&pin),Some(&context)).unwrap();
        assert_eq!(r.record().profile(),context.expected.profile());
        assert_eq!(r.record().acquisition(),context.expected.acquisition());
    }
    #[test] fn missing_approval_and_missing_native_context_fail_closed() {
        let (raw,pin,context)=model(&sample());
        assert!(matches!(validate(&raw,None,Some(&context)),Err(Error::MissingApproval)));
        assert!(matches!(validate(&raw,Some(&pin),None),Err(Error::MissingContext)));
    }
    #[test] fn exact_record_digest_refuses_changed_bytes() {
        let (_,pin,context)=model(&sample());let mut v=sample();v["binding"]["host_sha256"]="d".repeat(64).into();
        assert!(matches!(validate(&bytes(&v),Some(&pin),Some(&context)),Err(Error::Digest)));
    }
    #[test] fn modeled_new_approval_cannot_override_independent_current_context() {
        let (_,_,context)=model(&sample());let mut v=sample();v["binding"]["network_sha256"]="d".repeat(64).into();
        let (raw,mut pin,_)=model(&v);pin.context=hash(context.expected.canonical());
        assert!(matches!(validate(&raw,Some(&pin),Some(&context)),Err(Error::Context)));
    }
    #[test] fn all_context_identities_and_succession_are_exact() {
        let (_,_,context)=model(&sample());
        let fields=sample()["context"].as_object().unwrap().keys().cloned().collect::<Vec<_>>();
        for name in fields {
            let mut v=sample();v["context"][name]="d".repeat(64).into();let (raw,mut pin,_)=model(&v);
            pin.context=hash(context.expected.canonical());
            assert!(matches!(validate(&raw,Some(&pin),Some(&context)),Err(Error::Context)));
        }
        let mut v=sample();v["succession"]["prior_record_sha256"]="d".repeat(64).into();let (raw,mut pin,_)=model(&v);
        pin.context=hash(context.expected.canonical());
        assert!(matches!(validate(&raw,Some(&pin),Some(&context)),Err(Error::Context)));
    }
    #[test] fn provider_order_era_class_and_rule_are_bound() {
        let (_,_,context)=model(&sample());
        for change in 0..4 {
            let mut v=sample();match change {
                0=>v["acquisition"]["providers"].as_array_mut().unwrap().swap(0,1),
                1=>v["acquisition"]["bounds"]["era_context_sha256"]="d".repeat(64).into(),
                2=>v["binding"]["admission_class"]="Production".into(),
                _=>v["binding"]["rule_sha256"]="d".repeat(64).into(),
            }
            let (raw,mut pin,_)=model(&v);pin.context=hash(context.expected.canonical());
            assert!(matches!(validate(&raw,Some(&pin),Some(&context)),Err(Error::Context)));
        }
    }
    #[test] fn whitespace_duplicate_equal_key_and_alternate_escape_refuse() {
        let raw=bytes(&sample());let s=String::from_utf8(raw.clone()).unwrap();
        assert!(decode(&[raw.as_slice(),b"\n"].concat()).is_err());
        let duplicate=s.replacen("\"format\":",&format!("\"format\":\"{FORMAT}\",\"format\":"),1);
        assert!(decode(duplicate.as_bytes()).is_err());
        assert!(decode(s.replace("source1.invalid","\\u0073ource1.invalid").as_bytes()).is_err());
    }
    #[test] fn unknown_missing_fields_and_profile_identity_refuse() {
        let mut v=sample();v["unknown"]=1.into();assert!(decode(&bytes(&v)).is_err());
        let mut v=sample();v.as_object_mut().unwrap().remove("context");assert!(decode(&bytes(&v)).is_err());
        let mut v=sample();v["profile"]["max_holdover_ms"]=9_000.into();
        assert!(matches!(decode(&bytes(&v)),Err(Error::Configuration)));
    }
    #[test] fn uppercase_zero_digest_float_negative_and_oversize_refuse() {
        for bad in ["A".repeat(64),"0".repeat(64)] {
            let mut v=sample();v["context"]["elapsed_abi_sha256"]=bad.into();assert!(decode(&bytes(&v)).is_err());
        }
        let mut v=sample();v["binding"]["platform_class"]=serde_json::json!(1.0);
        assert!(bounded_tree(&v,0).is_err());
        v["binding"]["platform_class"]=serde_json::json!(-1);assert!(bounded_tree(&v,0).is_err());
        assert_eq!(decode(&vec![b' ';MAX_BYTES+1]),Err(Error::Bound));
    }
    #[test] fn existing_profile_budget_and_provider_validation_remain_mandatory() {
        let mut v=sample();v["acquisition"]["providers"][1]["operator"]="Operator1".into();
        assert!(matches!(decode(&bytes(&v)),Err(Error::Configuration)));
        let mut v=sample();v["acquisition"]["bounds"]["elapsed_drift_ppb"]=1.into();
        assert!(matches!(decode(&bytes(&v)),Err(Error::Configuration)));
    }
    #[test] fn selected_record_holds_same_native_owner_through_deployment_and_service() {
        let anchor=selected_anchor("same-owner");
        let record=validated(&sample());
        let state=ClockStateDir::open(&anchor).unwrap();
        let placement=ApprovedNativePlacement::modeled_test_value(&record,state,
            Duration::from_secs(1)).unwrap();
        assert_locked(&anchor);
        let deployment=AuthorizedNativeDeployment::from_validated(record,placement).unwrap();
        assert_locked(&anchor);
        // Uses real protected storage and native elapsed software APIs, but no
        // acquisition or approval issuer. Cold startup cannot grant clock time.
        let service=NativeNtsService::start(deployment).unwrap();
        assert_locked(&anchor);
        let held=service.basis();
        assert_eq!(held.lower_bound_ms(),None);
        assert!(matches!(service.vote_clock().reading(),
            mutiny_consensus_v8::vote_clock_v1::ClockReading::Unqualified));
        service.stop_handle().stop();
        assert_eq!(held.lower_bound_ms(),None);
        assert_locked(&anchor);
        drop(service);
        assert_eq!(held.lower_bound_ms(),None);
        // Consumer Arcs carry no storage owner; only service owns the lock.
        let reopened=ClockStateDir::open(&anchor).unwrap();
        drop(reopened);
    }
    #[test] fn selected_placement_cannot_be_reused_with_another_validated_record() {
        let anchor=selected_anchor("wrong-record");
        let record=validated(&sample());
        let placement=ApprovedNativePlacement::modeled_test_value(&record,
            ClockStateDir::open(&anchor).unwrap(),Duration::from_secs(1)).unwrap();
        let mut changed=sample();changed["binding"]["host_sha256"]="d".repeat(64).into();
        assert!(AuthorizedNativeDeployment::from_validated(validated(&changed),placement).is_err());
        // Refused composition drops its owner without reading/writing an anchor.
        assert_eq!(std::fs::symlink_metadata(&anchor).unwrap_err().kind(),
            std::io::ErrorKind::NotFound);
        drop(ClockStateDir::open(&anchor).unwrap());
    }
    #[test] fn modeled_selection_cannot_issue_production_placement() {
        let anchor=selected_anchor("production-refusal");
        let mut value=sample();value["binding"]["admission_class"]="Production".into();
        let record=validated(&value);
        assert!(matches!(ApprovedNativePlacement::modeled_test_value(&record,
            ClockStateDir::open(&anchor).unwrap(),Duration::from_secs(1)),Err(Error::Placement)));
        assert_eq!(std::fs::symlink_metadata(&anchor).unwrap_err().kind(),
            std::io::ErrorKind::NotFound);
        drop(ClockStateDir::open(&anchor).unwrap());
    }
    #[test] fn selected_cadence_preserves_existing_finite_whole_second_contract() {
        let anchor=selected_anchor("cadence");let record=validated(&sample());
        for cadence in [Duration::ZERO,Duration::from_millis(1500),Duration::from_secs(3601)] {
            assert!(matches!(ApprovedNativePlacement::modeled_test_value(&record,
                ClockStateDir::open(&anchor).unwrap(),cadence),Err(Error::Placement)));
            assert_eq!(std::fs::symlink_metadata(&anchor).unwrap_err().kind(),
                std::io::ErrorKind::NotFound);
        }
        let selected=ApprovedNativePlacement::modeled_test_value(&record,
            ClockStateDir::open(&anchor).unwrap(),Duration::from_secs(3600)).unwrap();
        assert_locked(&anchor);drop(selected);
        drop(ClockStateDir::open(&anchor).unwrap());
    }

    fn native_genesis() -> (Vec<u8>,crate::genesis_artifact_v2::TrustV2,
        crate::genesis_artifact_v2::VerifiedGenesisV2) {
        use mutiny_consensus_v8::{genesis_v2::{Inputs,Enrollment,Approved,GenesisClass},
            protocol_manifest::RuleManifest};
        let f:Value=serde_json::from_str(include_str!(
            "../../../qualification/GENESIS-V2-TEST-VALUE-FIXTURE-V1.json")).unwrap();
        assert_eq!(f["TEST_VALUE"],true);
        let raw=|name:&str|hex::decode(f[name].as_str().unwrap()).unwrap();
        let inputs=Inputs::decode(&raw("inputs")).unwrap();
        let enrollment=Enrollment::decode(&raw("enrollment")).unwrap();
        let approved=Approved {manifest:RuleManifest::decode(&raw("approved_manifest")).unwrap(),
            class:GenesisClass::TestValue,initial_target:raw("initial_target").try_into().unwrap()};
        let (bytes,c)=crate::genesis_artifact_v2::freeze(&inputs,&enrollment,&approved).unwrap();
        let trust=crate::genesis_artifact_v2::TrustV2 {artifact_sha256:hash(&bytes),
            genesis_block_hash:c.block_hash,approved};
        let verified=crate::genesis_artifact_v2::VerifiedGenesisV2::verify(&bytes,&trust).unwrap();
        (bytes,trust,verified)
    }
    fn scoped_value(verified:&crate::genesis_artifact_v2::VerifiedGenesisV2)->Value {
        let mut value=sample();
        let b=&mut value["binding"];
        b["genesis_sha256"]=hex::encode(verified.genesis.identity).into();
        b["network_sha256"]=hex::encode(hash(&verified.genesis.anchor().network.to_be_bytes())).into();
        b["rule_sha256"]=hex::encode(verified.genesis.fingerprint).into();
        b["platform_profile_sha256"]=hex::encode(
            verified.inputs.parameters.pcr_profiles.profiles().next().unwrap().id()).into();
        value
    }
    fn modeled_current(installed:&InstalledNativeInputs)->Result<CurrentNativeInputs> {
        if installed.expected.class!=AdmissionClass::LegacyTest {return Err(Error::Context);}
        Ok(CurrentNativeInputs {expected:installed.expected.clone(),
            current_software:super::super::native_nts_current::CurrentSoftwareBoundary::Modeled})
    }
    #[test] fn normal_startup_missing_accepted_inputs_cannot_restore_anchor() {
        let anchor=selected_anchor("normal-missing-inputs");
        let state=ClockStateDir::open(&anchor).unwrap();
        let error=super::super::HostClock::start_native(b"untrusted-record",b"untrusted-genesis",state)
            .err().unwrap();
        // The real fixed installation may be absent, or present with a
        // different exact record. These are the only two pre-Genesis refusals
        // for this deliberately nonempty untrusted request; neither reads the
        // supplied anchor. Do not depend on host-wide installation absence.
        assert!(error.ends_with("MissingAcceptedInputs") || error.ends_with("Context"));
        assert_eq!(std::fs::symlink_metadata(&anchor).unwrap_err().kind(),
            std::io::ErrorKind::NotFound);
        drop(ClockStateDir::open(&anchor).unwrap());
    }
    #[test] fn reconstructed_genesis_class_network_rule_and_pcr_set_are_mandatory() {
        let (_,_,verified)=native_genesis();let value=scoped_value(&verified);
        check_own_genesis_scope(&decode(&bytes(&value)).unwrap(),&verified).unwrap();
        for name in ["genesis_sha256","network_sha256","rule_sha256","platform_profile_sha256"] {
            let mut changed=value.clone();changed["binding"][name]=hex::encode([0x7e;32]).into();
            let expected=if name=="platform_profile_sha256" {Error::PlatformProfile} else {Error::GenesisScope};
            assert_eq!(check_own_genesis_scope(&decode(&bytes(&changed)).unwrap(),&verified),Err(expected));
        }
        let mut changed=value;changed["binding"]["admission_class"]="Production".into();
        assert_eq!(check_own_genesis_scope(&decode(&bytes(&changed)).unwrap(),&verified),Err(Error::GenesisScope));
    }
    #[test] fn modeled_current_receipt_cannot_issue_production_or_override_release_context() {
        let (_,trust,verified)=native_genesis();let mut value=scoped_value(&verified);
        value["binding"]["admission_class"]="Production".into();
        let mut installed=InstalledNativeInputs {genesis:trust,expected:decode(&bytes(&value)).unwrap(),
            anchor:selected_anchor("modeled-production"),cadence:Duration::from_secs(1),installation:None};
        assert!(matches!(modeled_current(&installed),Err(Error::Context)));
    }
    #[test] fn selected_startup_reconstructs_exact_artifact_and_preserves_same_owner() {
        let (genesis,trust,verified)=native_genesis();let raw=bytes(&scoped_value(&verified));
        let anchor=selected_anchor("selected-normal-composition");
        let mut installed=InstalledNativeInputs {genesis:trust,expected:decode(&raw).unwrap(),
            anchor:anchor.clone(),cadence:Duration::from_secs(1),installation:None};
        let current=modeled_current(&installed).unwrap();
        let (record,placement)=select_native_inputs(&raw,&genesis,ClockStateDir::open(&anchor).unwrap(),
            &mut installed,&current).unwrap();
        assert_locked(&anchor);
        let service=NativeNtsService::start(AuthorizedNativeDeployment::from_validated(record,placement).unwrap()).unwrap();
        let held=service.basis();assert_eq!(held.lower_bound_ms(),None);assert_locked(&anchor);
        drop(service);assert_eq!(held.lower_bound_ms(),None);
        drop(ClockStateDir::open(&anchor).unwrap());
        let mut altered=genesis;altered.push(b'\n');
        assert!(matches!(select_native_inputs(&raw,&altered,ClockStateDir::open(&anchor).unwrap(),
            &mut installed,&current),Err(Error::Genesis)));
    }
    #[test] fn current_changed_context_and_wrong_held_owner_refuse_before_anchor_restore() {
        let (genesis,trust,verified)=native_genesis();let value=scoped_value(&verified);let raw=bytes(&value);
        let anchor=selected_anchor("current-context");let other=selected_anchor("wrong-owner");
        let mut installed=InstalledNativeInputs {genesis:trust,expected:decode(&raw).unwrap(),
            anchor:anchor.clone(),cadence:Duration::from_secs(1),installation:None};
        let current=modeled_current(&installed).unwrap();
        assert!(matches!(select_native_inputs(&raw,&genesis,ClockStateDir::open(&other).unwrap(),
            &mut installed,&current),Err(Error::Placement)));
        for name in value["context"].as_object().unwrap().keys() {
            let mut changed=value.clone();changed["context"][name]=hex::encode([0x7e;32]).into();
            let changed=CurrentNativeInputs {expected:decode(&bytes(&changed)).unwrap(),
                current_software:super::super::native_nts_current::CurrentSoftwareBoundary::Modeled};
            assert!(matches!(select_native_inputs(&raw,&genesis,ClockStateDir::open(&anchor).unwrap(),
                &mut installed,&changed),Err(Error::Context)));
        }
        for path in [&anchor,&other] {
            assert_eq!(std::fs::symlink_metadata(path).unwrap_err().kind(),std::io::ErrorKind::NotFound);
            drop(ClockStateDir::open(path).unwrap());
        }
    }

    // These controls only model documentary bytes/observations. They neither
    // run hardware experiments nor issue real qualification/current capabilities.
    fn qualification_model()->(Value,Vec<u8>,std::path::PathBuf,Duration) {
        let mut value=sample();
        let path=std::env::current_dir().unwrap().join("public-no-io-evidence.anchor");
        let cadence=Duration::from_secs(1);
        let evidence=super::super::native_nts_qualification::modeled_envelope(&mut value,&path,cadence);
        (value,evidence,path,cadence)
    }
    fn bind_modeled_evidence(value:&mut Value,evidence:&Value)->Vec<u8> {
        let raw=bytes(evidence);
        value["context"]["qualification_sha256"]=hex::encode(hash(&raw)).into();raw
    }
    #[test] fn modeled_canonical_evidence_references_never_grant_measurement_qualification() {
        let (value,raw,path,cadence)=qualification_model();
        let record=decode(&bytes(&value)).unwrap();
        let matched=super::super::native_nts_qualification::decode_and_bind(&raw,&record,&path,cadence).unwrap();
        assert_eq!(matched.verify_measurements(),Err(Error::MissingQualification));
    }
    #[test] fn modeled_evidence_rejects_duplicate_whitespace_oversize_and_alternate_encoding() {
        let (value,raw,path,cadence)=qualification_model();let record=decode(&bytes(&value)).unwrap();
        let verify=|raw:&[u8]|super::super::native_nts_qualification::decode_and_bind(raw,&record,&path,cadence).is_err();
        let mut trailing=raw.clone();trailing.push(b' ');assert!(verify(&trailing));
        let mut duplicate=b"{\"format\":\"build8/native-nts/qualification-evidence-v1\",".to_vec();
        duplicate.extend_from_slice(&raw[1..]);assert!(verify(&duplicate));
        assert!(verify(&[]));assert!(verify(&vec![b' ';MAX_BYTES+1]));
        let alternate=String::from_utf8(raw.clone()).unwrap().replace("qualification-evidence","qualification\\u002devidence");
        assert!(verify(alternate.as_bytes()));
    }
    #[test] fn modeled_evidence_exact_scope_rejects_all_context_and_protocol_substitutions() {
        let (value,raw,path,cadence)=qualification_model();
        for group in ["context","binding"] {
            for key in value[group].as_object().unwrap().keys() {
                let mut changed=value.clone();
                let original=&changed[group][key];
                if original.is_string() && original.as_str().unwrap().len()==64 {
                    changed[group][key]=hex::encode([0x77;32]).into();
                } else {continue;}
                let record=decode(&bytes(&changed)).unwrap();
                assert!(super::super::native_nts_qualification::decode_and_bind(&raw,&record,&path,cadence).is_err(),"{group}/{key}");
            }
        }
    }
    #[test] fn modeled_evidence_binds_anchor_cadence_and_preceding_selection() {
        let (mut value,raw,path,cadence)=qualification_model();let record=decode(&bytes(&value)).unwrap();
        for (anchor,cadence) in [(path.with_file_name("other.anchor"),cadence),(path.clone(),Duration::from_secs(2))] {
            assert!(super::super::native_nts_qualification::decode_and_bind(&raw,&record,&anchor,cadence).is_err());
        }
        value["succession"]["prior_record_sha256"]="77".repeat(32).into();
        let changed=decode(&bytes(&value)).unwrap();
        assert!(super::super::native_nts_qualification::decode_and_bind(&raw,&changed,&path,cadence).is_err());
    }
    #[test] fn modeled_evidence_requires_each_locked_measurement_obligation_and_no_pass_flag() {
        let (value,raw,path,cadence)=qualification_model();let base:Value=serde_json::from_slice(&raw).unwrap();
        for key in base["measurements"].as_object().unwrap().keys() {
            let mut envelope=base.clone();envelope["measurements"].as_object_mut().unwrap().remove(key);
            let mut deployment=value.clone();let raw=bind_modeled_evidence(&mut deployment,&envelope);
            assert!(super::super::native_nts_qualification::decode_and_bind(&raw,&decode(&bytes(&deployment)).unwrap(),&path,cadence).is_err());
        }
        for key in ["qualified","physical_pass","admin_approved"] {
            let mut envelope=base.clone();envelope[key]=true.into();
            let mut deployment=value.clone();let raw=bind_modeled_evidence(&mut deployment,&envelope);
            assert!(super::super::native_nts_qualification::decode_and_bind(&raw,&decode(&bytes(&deployment)).unwrap(),&path,cadence).is_err());
        }
    }
    #[test] fn modeled_evidence_requires_method_raw_environment_and_exact_measurement_digest() {
        let (value,raw,path,cadence)=qualification_model();let base:Value=serde_json::from_slice(&raw).unwrap();
        for key in ["report_sha256","method_sha256","raw_data_sha256","environment_sha256"] {
            for replacement in ["00".repeat(32),"77".repeat(32)] {
                let mut envelope=base.clone();envelope["measurements"]["frequency_error"][key]=replacement.into();
                let mut deployment=value.clone();let raw=bind_modeled_evidence(&mut deployment,&envelope);
                assert!(super::super::native_nts_qualification::decode_and_bind(&raw,&decode(&bytes(&deployment)).unwrap(),&path,cadence).is_err());
            }
        }
    }
    #[test] fn modeled_evidence_matches_each_ordered_provider_and_no_smear_binding() {
        let (value,raw,path,cadence)=qualification_model();let base:Value=serde_json::from_slice(&raw).unwrap();
        for fault in 0..4 {
            let mut envelope=base.clone();
            match fault {
                0=>{envelope["provider_records"].as_array_mut().unwrap().pop();},
                1=>envelope["provider_records"].as_array_mut().unwrap().swap(0,1),
                2=>envelope["provider_records"][0]["provider"]["operator"]="foreign".into(),
                _=>envelope["provider_records"][0]["provider"]["no_smear_profile_evidence_sha256"]="77".repeat(32).into(),
            }
            let mut deployment=value.clone();let raw=bind_modeled_evidence(&mut deployment,&envelope);
            assert!(super::super::native_nts_qualification::decode_and_bind(&raw,&decode(&bytes(&deployment)).unwrap(),&path,cadence).is_err());
        }
    }
    #[test] fn modeled_current_contract_requires_exact_diagnostic_os_boot_and_abi() {
        let (value,raw,path,cadence)=qualification_model();let record=decode(&bytes(&value)).unwrap();
        let envelope=super::super::native_nts_qualification::decode_and_bind(&raw,&record,&path,cadence).unwrap();
        let base=super::super::windows_boot::BootEnvironment {identifier_bytes:[1;16],firmware_type:2,boot_flags:0,os_build:26200};
        assert_eq!(envelope.current_contract().compare_windows_diagnostic(&base),Ok(()));
        for field in 0..3 {
            let mut changed=base.clone();match field {0=>changed.os_build+=1,1=>changed.firmware_type=1,_=>changed.boot_flags=1};
            assert_eq!(envelope.current_contract().compare_windows_diagnostic(&changed),Err(Error::UnsupportedCurrentFacts));
        }
        // Positive documentary/diagnostic match is explicitly not qualification.
        assert_eq!(envelope.verify_measurements(),Err(Error::MissingQualification));
    }

}
