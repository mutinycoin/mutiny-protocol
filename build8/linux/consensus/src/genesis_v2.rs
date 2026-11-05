//! PROPOSED / UNFROZEN (Lane A1; Order A9, A10 and the representation part of A1). V2 is the
//! Production Genesis implementation target (Order A9): this module defines the immutable V2
//! Genesis input record, its identity, the explicit constructor and the verifier. Design:
//! `qualification/candidate-3/A-GENESIS-V2-DESIGN.md`.
//!
//! * The production/test CLASS is one byte of the immutable inputs (inside the parameters record),
//!   therefore inside the GenesisID preimage. `construct` takes no class or profile argument; the
//!   verifier's expected class can only reject (Order A10). Nothing here reads a local flag, a file
//!   name, an environment variable or a Cargo feature.
//! * The rule manifest commits to the class, the endorsement-root SET and the accepted PCR-profile
//!   slot through three named entries; the parameters codec refuses a record whose manifest
//!   disagrees with its own fields, so the two cannot disagree.
//! * Endorsement roots are a SET of exact root-certificate DER SHA-256 values, each with versioned
//!   validation constraints (Order A1). Root values are an evidence input: nothing here supplies one.
//!   A Production-class record with an empty set, a placeholder or a TEST-VALUE root is refused (fail
//!   closed). Code cannot recognize an invented random-looking hash: the authority against invented
//!   roots is the independently approved manifest, which only the Architect can supply.
//! * Nothing here seals Genesis or opens a production gate. V1 (`genesis_inputs`) stays for
//!   test/replay only; its Production paths refuse (`Error::V1NotProductionGenesis`).
use crate::{
    Error, Hash, NETWORK_ID,
    admission_v2::{Expected, Policy},
    anchors::FinalizedAnchor,
    domain_hash,
    execution::{ExecutionError, State},
    license_assignment_v2::Assignment,
    licenses::LicenseRecord,
    node_admission_v2::Binding,
    protocol_manifest::RuleManifest,
    provenance::AdmissionClass,
    tpm::TpmProfile,
    treasury_v1::Treasury,
    ek_chain::{AnchorConstraints, RevocationMode, SignatureAlgorithm, TrustAnchor},
    endorsement_identity::IdentityClasses,
    pcr_profiles::{AcceptedPcrProfiles, PcrFailure},
};
use minicbor::{Decoder, Encoder, data::Type};
use mutiny_crypto_v2::{PublicKey, Role, enrollment::Binding as SupervisedBinding};
use std::collections::{BTreeMap, BTreeSet};

/// GenesisID V2 = H(IDENTITY_DOMAIN, canonical GenesisInputsV2 bytes).
pub const IDENTITY_DOMAIN: &[u8] = b"MUTINY-BUILD8-GENESIS-ID-V2";
/// GenesisBlockHash V2 = H(BLOCK_DOMAIN, GenesisBlockV2 bytes).
pub const BLOCK_DOMAIN: &[u8] = b"MUTINY-BUILD8-GENESIS-BLOCK-V2";
/// State key of the immutable GenesisParametersV2 record: H(PARAMETERS_KEY_DOMAIN, empty).
pub const PARAMETERS_KEY_DOMAIN: &[u8] = b"MUTINY-BUILD8-GENESIS-PARAMETERS-KEY-V2";
/// Rule-manifest commitment to the class byte.
pub const CLASS_DOMAIN: &[u8] = b"MUTINY-BUILD8-GENESIS-CLASS-V2";
/// Rule-manifest commitment to the complete endorsement-root set (roots, constraints, labels).
pub const ROOT_SET_DOMAIN: &[u8] = b"MUTINY-BUILD8-ENDORSEMENT-ROOT-SET-V2";
// The PCR-profile set and identity-class list commitments use Lane A2's domains
// (`pcr_profiles::ACCEPTED_PCR_PROFILES_DOMAIN`, `endorsement_identity::IDENTITY_CLASSES_DOMAIN`): one definition.
/// Public TEST-VALUE root derivation: root = H(TEST_VALUE_ROOT_DOMAIN, label). Names no certificate.
pub const TEST_VALUE_ROOT_DOMAIN: &[u8] = b"MUTINY-BUILD8-TEST-VALUE-ENDORSEMENT-ROOT-V2";
/// Rule-manifest entry names binding a V2 Genesis (each exactly once, each equal to the value the
/// parameters record's own fields produce).
pub const CLASS_ENTRY: &[u8] = b"genesis-class-v2";
pub const ROOT_SET_ENTRY: &[u8] = b"endorsement-root-set-v2";
pub const PCR_SET_ENTRY: &[u8] = b"accepted-pcr-profile-set-v1";
pub const IDENTITY_CLASSES_ENTRY: &[u8] = b"endorsement-identity-classes-v1";
/// Record tag of GenesisParametersV2 (unused by every other typed record).
pub const PARAMETERS_TAG: u8 = 64;
pub const MAX_ROOTS: usize = 1024;
pub const MAX_PCR_PROFILES: usize = 1024;
pub const MAX_EK_CLASSES: usize = 8;
pub const MAX_LABEL: usize = 64;
pub const MAX_DESCRIPTOR: usize = 2048;
pub const MAX_ROOT_SET: usize = 140 * 1024;
/// A state record is at most 256 KiB (`state_tree::MAX_RECORD`).
pub const MAX_PARAMETERS: usize = crate::state_tree::MAX_RECORD;
pub const MAX_INPUTS: usize = 288 * 1024;
pub const MAX_ENROLLMENT: usize = 128 * 1024;
/// The fixed number of Genesis Bootstrap Licenses (`blocks::genesis_license`).
pub const GENESIS_LICENSES: u64 = 12;

/// Precise reason a V2 Genesis input, enrollment or claimed artifact is refused. Tests assert these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenesisV2Error {
    /// Malformed CBOR, wrong arity or field type.
    Codec,
    /// Valid CBOR that is not the canonical encoding (including trailing bytes).
    NonCanonical,
    /// Over a size bound.
    Oversize,
    /// A record, set, slot or constraints version, or the parameters tag, that this code does not know.
    UnknownVersion,
    /// A network identifier other than this build's NETWORK_ID.
    WrongNetwork,
    /// A class byte other than 1 (Production) or 2 (TestValue).
    UnknownClass,
    /// A field that must be nonzero is zero (timestamp, nonce, target, purchase, supervised nonce).
    ZeroField,
    EmptyRootSet,
    TooManyRoots,
    /// Root entries not strictly ascending (a duplicate or an unsorted pair), at the byte level.
    RootOrder,
    ZeroRoot,
    /// Per-root constraints outside their codec (no signature algorithm or EK class, an unknown code, an
    /// invalid EK class, too many intermediates).
    BadConstraints,
    /// A TEST-VALUE label that is empty or too long.
    BadLabel,
    /// Production class: a root whose 32 bytes are all equal (never a SHA-256 of real DER).
    PlaceholderRoot,
    /// Production class: a labelled TEST-VALUE root or the known V1 TEST-VALUE root.
    TestValueRootInProduction,
    /// TestValue class: a root that is not the labelled public TEST-VALUE derivation.
    UnlabelledRootInTestValue,
    /// The accepted PCR-profile set refused by its own codec (`pcr_profiles::AcceptedPcrProfiles`).
    PcrSet(PcrFailure),
    /// Production class: a PCR profile whose digest bytes are all equal (a placeholder).
    PlaceholderPcrProfile,
    /// The identity-class list refused by its own codec (`endorsement_identity::IdentityClasses`).
    IdentityClasses,
    /// One of the three binding entries is absent from the rule manifest.
    ManifestEntryMissing,
    ManifestClassMismatch,
    ManifestRootSetMismatch,
    ManifestPcrSetMismatch,
    ManifestIdentityClassesMismatch,
    /// The V1 class representation (`physical-admission-trust-roots-v1`) in a V2 manifest.
    V1TrustRootsEntry,
    /// Explicit TEST-VALUE DER alias selector or binding refused.
    TestRootAliasPolicy,
    /// A descriptor with the wrong role or generation, or that does not decode.
    BadDescriptor,
    /// Recovery, admission-owner and Treasury descriptors share a key half.
    RoleAlias,
    /// The Treasury wallet shares a key half with the admission-policy owner (Order A8).
    TreasuryIsAdmissionOwner,
    TreasuryClassMismatch,
    /// The initial member's endorsement root is not in the frozen root set.
    MemberRootNotInSet,
    /// The initial member's TPM profile does not decode or lacks certified-key properties.
    BadMemberProfile,
    /// The enrollment's member binding does not carry the member input's exact profile and root.
    MemberBindingMismatch,
    /// Exactly twelve assignments and twelve supervised bindings are required.
    EnrollmentCount,
    /// An existing consensus component (admission, membership, Licenses, wallets) refused.
    Consensus(Error),
    /// The complete state refused for a non-codec reason.
    State,
    /// Verifier: the inputs' class differs from the independently expected class.
    ClassMismatch,
    /// Verifier: the inputs' rule manifest differs from the independently approved manifest.
    ManifestMismatch,
    /// Verifier: the inputs' initial target differs from the independently qualified target.
    TargetMismatch,
    IdentityMismatch,
    RecordsMismatch,
    StateRootMismatch,
    BlockMismatch,
}
impl From<Error> for GenesisV2Error {
    fn from(e: Error) -> Self {
        Self::Consensus(e)
    }
}
impl From<ExecutionError> for GenesisV2Error {
    fn from(e: ExecutionError) -> Self {
        match e {
            ExecutionError::Codec(e) => Self::Consensus(e),
            _ => Self::State,
        }
    }
}
pub type Result<T> = std::result::Result<T, GenesisV2Error>;
use GenesisV2Error as E;

fn canonical(raw: &[u8], limit: usize) -> Result<()> {
    crate::blocks::canonical(raw, limit).map_err(|e| match e {
        Error::NonCanonical => E::NonCanonical,
        Error::Oversize => E::Oversize,
        _ => E::Codec,
    })
}
fn codec<T>(r: std::result::Result<T, minicbor::decode::Error>) -> Result<T> {
    r.map_err(|_| E::Codec)
}
fn fixed32(d: &mut Decoder<'_>) -> Result<Hash> {
    codec(d.bytes())?.try_into().map_err(|_| E::Codec)
}
fn arity(d: &mut Decoder<'_>, n: u64) -> Result<()> {
    if codec(d.array())? != Some(n) {
        return Err(E::Codec);
    }
    Ok(())
}
fn version(d: &mut Decoder<'_>, expected: u8) -> Result<()> {
    if codec(d.u8())? != expected {
        return Err(E::UnknownVersion);
    }
    Ok(())
}
fn end(d: &Decoder<'_>, raw: &[u8], reencoded: Vec<u8>) -> Result<()> {
    if d.position() != raw.len() || reencoded != raw {
        return Err(E::NonCanonical);
    }
    Ok(())
}

/// The production/test class of a V2 chain. One byte of the immutable inputs; the same numbering as
/// `treasury_v1::Class`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum GenesisClass {
    Production = 1,
    TestValue = 2,
}
impl GenesisClass {
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            1 => Ok(Self::Production),
            2 => Ok(Self::TestValue),
            _ => Err(E::UnknownClass),
        }
    }
    pub fn byte(self) -> u8 {
        self as u8
    }
    /// The admission rule set of this class: Production applies the typed provenance rule and refuses
    /// TEST-VALUE material; TestValue applies the existing Legacy/Test rule.
    pub fn admission_class(self) -> AdmissionClass {
        match self {
            Self::Production => AdmissionClass::Production,
            Self::TestValue => AdmissionClass::LegacyTest,
        }
    }
    /// Value of the `genesis-class-v2` rule-manifest entry.
    pub fn commitment(self) -> Hash {
        domain_hash(CLASS_DOMAIN, &[self.byte()])
    }
}

/// Per-root validation constraints: Lane A2's `ek_chain::AnchorConstraints` is the single definition (the structure the
/// EK-chain procedure consumes); this is its Genesis codec, version 2:
/// `[2, max_intermediates, [signature_algorithm_code, ...], [[ek_class_tag, ek_class_size], ...], revocation_code]`,
/// both lists non-empty, strictly ascending. Codes: signature algorithms in `SignatureAlgorithm` declaration order from 1
/// (RsaPkcs1Sha256 1 .. EcdsaP384Sha384 6); revocation CrlRequired 1, NoCrlPublished 2. Every value is an explicit input.
fn signature_code(a: SignatureAlgorithm) -> u8 {
    match a {
        SignatureAlgorithm::RsaPkcs1Sha256 => 1,
        SignatureAlgorithm::RsaPkcs1Sha384 => 2,
        SignatureAlgorithm::RsaPssSha256 => 3,
        SignatureAlgorithm::RsaPssSha384 => 4,
        SignatureAlgorithm::EcdsaP256Sha256 => 5,
        SignatureAlgorithm::EcdsaP384Sha384 => 6,
    }
}
fn signature_from(code: u8) -> Result<SignatureAlgorithm> {
    Ok(match code {
        1 => SignatureAlgorithm::RsaPkcs1Sha256,
        2 => SignatureAlgorithm::RsaPkcs1Sha384,
        3 => SignatureAlgorithm::RsaPssSha256,
        4 => SignatureAlgorithm::RsaPssSha384,
        5 => SignatureAlgorithm::EcdsaP256Sha256,
        6 => SignatureAlgorithm::EcdsaP384Sha384,
        _ => return Err(E::BadConstraints),
    })
}
fn revocation_code(r: RevocationMode) -> u8 {
    match r {
        RevocationMode::CrlRequired => 1,
        RevocationMode::NoCrlPublished => 2,
    }
}
fn check_constraints(c: &AnchorConstraints) -> Result<()> {
    use crate::endorsement_identity::{ECC_TAG, RSA_BITS, RSA_TAG, TPM_ECC_NIST_P256, TPM_ECC_NIST_P384, TPM_ECC_NIST_P521};
    let class_ok = |(tag, size): &(u8, u16)| match *tag {
        RSA_TAG => RSA_BITS.contains(size),
        ECC_TAG => [TPM_ECC_NIST_P256, TPM_ECC_NIST_P384, TPM_ECC_NIST_P521].contains(size),
        _ => false,
    };
    if c.max_intermediates > crate::ek_chain::MAX_INTERMEDIATES
        || c.signature_algorithms.is_empty()
        || c.ek_classes.is_empty()
        || c.ek_classes.len() > MAX_EK_CLASSES
        || !c.ek_classes.iter().all(class_ok)
    {
        return Err(E::BadConstraints);
    }
    Ok(())
}
fn encode_constraints(c: &AnchorConstraints, e: &mut Encoder<Vec<u8>>) -> Result<()> {
    check_constraints(c)?;
    e.array(5).unwrap().u8(2).unwrap().u8(c.max_intermediates).unwrap();
    e.array(c.signature_algorithms.len() as u64).unwrap();
    for a in &c.signature_algorithms {
        e.u8(signature_code(*a)).unwrap();
    }
    e.array(c.ek_classes.len() as u64).unwrap();
    for (tag, size) in &c.ek_classes {
        e.array(2).unwrap().u8(*tag).unwrap().u16(*size).unwrap();
    }
    e.u8(revocation_code(c.revocation)).unwrap();
    Ok(())
}
/// Lists are read into sets; a duplicate or unsorted list is refused by the caller's re-encoding check.
fn decode_constraints(d: &mut Decoder<'_>) -> Result<AnchorConstraints> {
    arity(d, 5)?;
    version(d, 2)?;
    let max_intermediates = codec(d.u8())?;
    let n = codec(d.array())?.ok_or(E::Codec)?;
    if n == 0 || n > 6 {
        return Err(E::BadConstraints);
    }
    let mut signature_algorithms = std::collections::BTreeSet::new();
    for _ in 0..n {
        signature_algorithms.insert(signature_from(codec(d.u8())?)?);
    }
    let n = codec(d.array())?.ok_or(E::Codec)?;
    if n == 0 || n > MAX_EK_CLASSES as u64 {
        return Err(E::BadConstraints);
    }
    let mut ek_classes = std::collections::BTreeSet::new();
    for _ in 0..n {
        arity(d, 2)?;
        ek_classes.insert((codec(d.u8())?, codec(d.u16())?));
    }
    let revocation = match codec(d.u8())? {
        1 => RevocationMode::CrlRequired,
        2 => RevocationMode::NoCrlPublished,
        _ => return Err(E::BadConstraints),
    };
    let c = AnchorConstraints { max_intermediates, signature_algorithms, ek_classes, revocation };
    check_constraints(&c)?;
    Ok(c)
}

/// One committed root of the set. Production keys are exact DER hashes;
/// TEST-VALUE keys remain label-derived logical RootIDs, including when an
/// explicit selected parameter policy binds their labels to exact DER.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndorsementRoot {
    pub constraints: AnchorConstraints,
    /// Present only in the TestValue class, where the root must equal `test_value_root(label)`.
    pub test_value_label: Option<Vec<u8>>,
}

/// Public TEST-VALUE root derivation. This derivation alone authenticates no
/// certificate or manufacturer; an explicitly selected policy may bind DER.
pub fn test_value_root(label: &[u8]) -> Hash {
    domain_hash(TEST_VALUE_ROOT_DOMAIN, label)
}
/// The V1 TEST-VALUE root label of the software simulator fixtures; refused in the Production class.
fn v1_test_value_root() -> Hash {
    domain_hash(b"MUTINY-BUILD8-TEST-VALUE-ENDORSEMENT-ROOT-V1", &[])
}

/// `[1, [[root_id32, constraints, label_or_null], ...]]`, 1..1024 entries, strictly
/// ascending by root (so unique).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndorsementRootSet {
    pub roots: BTreeMap<Hash, EndorsementRoot>,
}
impl EndorsementRootSet {
    /// The root identifiers, as the V2 admission policy record carries them.
    pub fn hashes(&self) -> BTreeSet<Hash> {
        self.roots.keys().copied().collect()
    }
    /// Historical direct-root anchor view, retained byte-for-byte. Selected
    /// policies must use Parameters::witness_policy for authenticated DER anchors.
    pub fn anchors(&self) -> Vec<TrustAnchor> {
        self.roots.iter().map(|(root, e)| TrustAnchor { root_cert_der_sha256: *root, constraints: e.constraints.clone() }).collect()
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.roots.is_empty() {
            return Err(E::EmptyRootSet);
        }
        if self.roots.len() > MAX_ROOTS {
            return Err(E::TooManyRoots);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(2)
            .unwrap()
            .u8(1)
            .unwrap()
            .array(self.roots.len() as u64)
            .unwrap();
        for (root, entry) in &self.roots {
            if *root == [0; 32] {
                return Err(E::ZeroRoot);
            }
            e.array(3).unwrap().bytes(root).unwrap();
            encode_constraints(&entry.constraints, &mut e)?;
            match &entry.test_value_label {
                Some(label) => {
                    if label.is_empty() || label.len() > MAX_LABEL {
                        return Err(E::BadLabel);
                    }
                    e.bytes(label).unwrap();
                }
                None => {
                    e.null().unwrap();
                }
            }
        }
        let raw = e.into_writer();
        if raw.len() > MAX_ROOT_SET {
            return Err(E::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        canonical(raw, MAX_ROOT_SET)?;
        let mut d = Decoder::new(raw);
        arity(&mut d, 2)?;
        version(&mut d, 1)?;
        let n = codec(d.array())?.ok_or(E::Codec)?;
        if n == 0 {
            return Err(E::EmptyRootSet);
        }
        if n > MAX_ROOTS as u64 {
            return Err(E::TooManyRoots);
        }
        let mut roots = BTreeMap::new();
        let mut last: Option<Hash> = None;
        for _ in 0..n {
            arity(&mut d, 3)?;
            let root = fixed32(&mut d)?;
            if last.is_some_and(|l| l >= root) {
                return Err(E::RootOrder);
            }
            last = Some(root);
            let constraints = decode_constraints(&mut d)?;
            let test_value_label = if codec(d.datatype())? == Type::Null {
                codec(d.null())?;
                None
            } else {
                Some(codec(d.bytes())?.to_vec())
            };
            roots.insert(root, EndorsementRoot { constraints, test_value_label });
        }
        let set = Self { roots };
        end(&d, raw, set.encode()?)?;
        Ok(set)
    }
    /// Value of the `endorsement-root-set-v2` rule-manifest entry.
    pub fn commitment(&self) -> Result<Hash> {
        Ok(domain_hash(ROOT_SET_DOMAIN, &self.encode()?))
    }
}

/// Value of the `endorsement-identity-classes-v1` rule-manifest entry (Lane A2's domain).
pub fn identity_classes_commitment(classes: &IdentityClasses) -> Hash {
    domain_hash(crate::endorsement_identity::IDENTITY_CLASSES_DOMAIN, &classes.encode())
}
/// The four rule-manifest entries (name, value) that bind a V2 Genesis' class, root set, accepted PCR-profile set
/// (`AcceptedPcrProfiles::commitment`) and identity-class list, in the manifest's ascending name order.
pub fn binding_entries(
    class: GenesisClass,
    roots: &EndorsementRootSet,
    pcr_profiles: &AcceptedPcrProfiles,
    identity_classes: &IdentityClasses,
) -> Result<Vec<(Vec<u8>, Hash)>> {
    let mut entries = vec![
        (PCR_SET_ENTRY.to_vec(), pcr_profiles.commitment()),
        (ROOT_SET_ENTRY.to_vec(), roots.commitment()?),
        (CLASS_ENTRY.to_vec(), class.commitment()),
        (IDENTITY_CLASSES_ENTRY.to_vec(), identity_classes_commitment(identity_classes)),
    ];
    entries.sort();
    Ok(entries)
}

/// GenesisParametersV2, the state-resident immutable part of the inputs:
/// `[2, 64, NetworkID, class, InitialPoWTarget, RuleManifestV1 bytes, EndorsementRootSetV2 bytes,
/// AcceptedPcrProfiles bytes, IdentityClasses bytes]`. Stored verbatim at `parameters_key()`; written by no block operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub class: GenesisClass,
    pub initial_target: Hash,
    pub rules: RuleManifest,
    pub roots: EndorsementRootSet,
    /// Lane A2's accepted PCR-profile set (the structure `check_accepted` reads).
    pub pcr_profiles: AcceptedPcrProfiles,
    /// Lane A2's ordered identity-class list (class 1 is the primary `hardware` class).
    pub identity_classes: IdentityClasses,
}
impl Parameters {
    /// The manifest must carry each binding entry exactly once (its codec forbids duplicate names),
    /// each equal to the value this record's own fields produce, and must not carry the V1 class
    /// representation: so the record cannot exist with a manifest that disagrees with it.
    fn check_manifest(&self) -> Result<()> {
        let commitments = &self.rules.commitments;
        if commitments
            .iter()
            .any(|(name, _)| name.as_slice() == crate::provenance::TRUST_ROOTS_COMMITMENT)
        {
            return Err(E::V1TrustRootsEntry);
        }
        let expected = [
            (CLASS_ENTRY, self.class.commitment(), E::ManifestClassMismatch),
            (ROOT_SET_ENTRY, self.roots.commitment()?, E::ManifestRootSetMismatch),
            (PCR_SET_ENTRY, self.pcr_profiles.commitment(), E::ManifestPcrSetMismatch),
            (
                IDENTITY_CLASSES_ENTRY,
                identity_classes_commitment(&self.identity_classes),
                E::ManifestIdentityClassesMismatch,
            ),
        ];
        for (name, value, mismatch) in expected {
            let found = commitments
                .iter()
                .find(|(n, _)| n.as_slice() == name)
                .ok_or(E::ManifestEntryMissing)?;
            if found.1 != value {
                return Err(mismatch);
            }
        }
        crate::test_value_root_alias_v1::WitnessPolicy::from_parameters(self)
            .map_err(|_| E::TestRootAliasPolicy)?;
        Ok(())
    }
    /// Immutable class/anchor/identity policy from a structurally validated,
    /// binding-consistent parameter record. No caller-supplied alias map.
    pub fn witness_policy(&self) -> crate::Result<crate::test_value_root_alias_v1::WitnessPolicy> {
        self.encode().map_err(|_| Error::Codec)?;
        crate::test_value_root_alias_v1::WitnessPolicy::from_parameters(self)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.initial_target == [0; 32] {
            return Err(E::ZeroField);
        }
        let rules = self.rules.encode()?;
        let roots = self.roots.encode()?;
        let pcr_profiles = self.pcr_profiles.encode();
        let identity_classes = self.identity_classes.encode();
        self.check_manifest()?;
        let mut e = Encoder::new(Vec::new());
        e.array(9)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(PARAMETERS_TAG)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .u8(self.class.byte())
            .unwrap()
            .bytes(&self.initial_target)
            .unwrap()
            .bytes(&rules)
            .unwrap()
            .bytes(&roots)
            .unwrap()
            .bytes(&pcr_profiles)
            .unwrap()
            .bytes(&identity_classes)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_PARAMETERS {
            return Err(E::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        canonical(raw, MAX_PARAMETERS)?;
        let mut d = Decoder::new(raw);
        arity(&mut d, 9)?;
        version(&mut d, 2)?;
        version(&mut d, PARAMETERS_TAG)?;
        if codec(d.u32())? != NETWORK_ID {
            return Err(E::WrongNetwork);
        }
        let class = GenesisClass::from_byte(codec(d.u8())?)?;
        let initial_target = fixed32(&mut d)?;
        let rules = RuleManifest::decode(codec(d.bytes())?)?;
        let roots = EndorsementRootSet::decode(codec(d.bytes())?)?;
        let pcr_profiles = AcceptedPcrProfiles::decode(codec(d.bytes())?).map_err(E::PcrSet)?;
        let identity_classes =
            IdentityClasses::decode(codec(d.bytes())?).map_err(|_| E::IdentityClasses)?;
        let parameters = Self {
            class,
            initial_target,
            rules,
            roots,
            pcr_profiles,
            identity_classes,
        };
        end(&d, raw, parameters.encode()?)?;
        Ok(parameters)
    }
    /// ProtocolFingerprint of the embedded manifest (the existing RuleManifestV1 derivation).
    pub fn fingerprint(&self) -> Result<Hash> {
        Ok(self.rules.fingerprint()?)
    }
}
pub fn parameters_key() -> Hash {
    domain_hash(PARAMETERS_KEY_DOMAIN, &[])
}

/// The single initial physical member, pre-identity part: `[2, endorsement_root, TpmProfile bytes]`.
/// Its Node and Continuity keys are generated AFTER GenesisID (locked V2 order) and are therefore
/// not identity inputs; they arrive with the enrollment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberInput {
    pub endorsement_root: Hash,
    pub profile: Vec<u8>,
}
impl MemberInput {
    /// The decoded profile: canonical, nonzero hardware and trust manifest, valid certified-key
    /// properties.
    pub fn tpm_profile(&self) -> Result<TpmProfile> {
        let profile = TpmProfile::decode(&self.profile).map_err(|_| E::BadMemberProfile)?;
        if profile.hardware == [0; 32] || profile.admission_trust_manifest == [0; 32] {
            return Err(E::BadMemberProfile);
        }
        profile
            .verify_certified_key()
            .map_err(|_| E::BadMemberProfile)?;
        Ok(profile)
    }
    fn encode(&self) -> Result<Vec<u8>> {
        if self.profile.is_empty() || self.profile.len() > 8192 {
            return Err(E::BadMemberProfile);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&self.endorsement_root)
            .unwrap()
            .bytes(&self.profile)
            .unwrap();
        Ok(e.into_writer())
    }
    fn decode(raw: &[u8]) -> Result<Self> {
        canonical(raw, 9 * 1024)?;
        let mut d = Decoder::new(raw);
        arity(&mut d, 3)?;
        version(&mut d, 2)?;
        let member = Self {
            endorsement_root: fixed32(&mut d)?,
            profile: codec(d.bytes())?.to_vec(),
        };
        end(&d, raw, member.encode()?)?;
        Ok(member)
    }
}

/// GenesisInputsV2, the identity preimage: `[2, NetworkID, timestamp, nonce, parameters bytes,
/// admission_owner descriptor, member bytes, recovery descriptor, treasury record bytes, purchase]`.
/// The twelve Bootstrap Licenses are owned by the admission owner's generation-one AddressID, as V1
/// derives its descriptor owner from the input owner key (`genesis_inputs::validate_descriptor`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inputs {
    pub timestamp: u64,
    pub nonce: Hash,
    pub parameters: Parameters,
    /// Generation-one WalletOwner descriptor: the V2 admission-policy owner.
    pub admission_owner: Vec<u8>,
    pub member: MemberInput,
    /// Generation-one WalletRecovery descriptor: the immutable bootstrap recovery authority.
    pub recovery: Vec<u8>,
    /// The Genesis-authenticated Treasury identity (`treasury_v1`, reused unchanged).
    pub treasury: Treasury,
    /// Purchase commitment recorded as every Bootstrap License's issuance.
    pub purchase: Hash,
}
fn wallet_descriptor(raw: &[u8], role: Role) -> Result<PublicKey> {
    if raw.len() > MAX_DESCRIPTOR {
        return Err(E::BadDescriptor);
    }
    let (key, generation) = PublicKey::decode_descriptor(raw).map_err(|_| E::BadDescriptor)?;
    if key.role != role || generation != 1 {
        return Err(E::BadDescriptor);
    }
    Ok(key)
}
fn share_a_half(a: &PublicKey, b: &PublicKey) -> bool {
    a.ed448 == b.ed448 || a.fndsa == b.fndsa
}
impl Inputs {
    pub fn class(&self) -> GenesisClass {
        self.parameters.class
    }
    /// Owner of the twelve Bootstrap Licenses: the admission owner's generation-one AddressID.
    pub fn license_owner(&self) -> Result<Hash> {
        wallet_descriptor(&self.admission_owner, Role::WalletOwner)?
            .address_id(1)
            .map_err(|_| E::BadDescriptor)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.admission_owner.len() > MAX_DESCRIPTOR || self.recovery.len() > MAX_DESCRIPTOR {
            return Err(E::BadDescriptor);
        }
        let parameters = self.parameters.encode()?;
        let member = self.member.encode()?;
        let treasury = self.treasury.encode()?;
        let mut e = Encoder::new(Vec::new());
        e.array(10)
            .unwrap()
            .u8(2)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .u64(self.timestamp)
            .unwrap()
            .bytes(&self.nonce)
            .unwrap()
            .bytes(&parameters)
            .unwrap()
            .bytes(&self.admission_owner)
            .unwrap()
            .bytes(&member)
            .unwrap()
            .bytes(&self.recovery)
            .unwrap()
            .bytes(&treasury)
            .unwrap()
            .bytes(&self.purchase)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_INPUTS {
            return Err(E::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        canonical(raw, MAX_INPUTS)?;
        let mut d = Decoder::new(raw);
        arity(&mut d, 10)?;
        version(&mut d, 2)?;
        if codec(d.u32())? != NETWORK_ID {
            return Err(E::WrongNetwork);
        }
        let inputs = Self {
            timestamp: codec(d.u64())?,
            nonce: fixed32(&mut d)?,
            parameters: Parameters::decode(codec(d.bytes())?)?,
            admission_owner: codec(d.bytes())?.to_vec(),
            member: MemberInput::decode(codec(d.bytes())?)?,
            recovery: codec(d.bytes())?.to_vec(),
            treasury: Treasury::decode(codec(d.bytes())?)?,
            purchase: fixed32(&mut d)?,
        };
        end(&d, raw, inputs.encode()?)?;
        Ok(inputs)
    }
    /// Every input rule of the design (section 2), including the class-specific refusals. The class
    /// comes only from `self.parameters.class`.
    pub fn validate(&self) -> Result<()> {
        self.encode()?;
        if self.timestamp == 0 || self.nonce == [0; 32] || self.purchase == [0; 32] {
            return Err(E::ZeroField);
        }
        let owner = wallet_descriptor(&self.admission_owner, Role::WalletOwner)?;
        let recovery = wallet_descriptor(&self.recovery, Role::WalletRecovery)?;
        let treasury = wallet_descriptor(self.treasury.descriptor(), Role::WalletOwner)?;
        if share_a_half(&treasury, &owner) {
            return Err(E::TreasuryIsAdmissionOwner);
        }
        if share_a_half(&recovery, &owner) || share_a_half(&recovery, &treasury) {
            return Err(E::RoleAlias);
        }
        let roots = &self.parameters.roots.roots;
        if !roots.contains_key(&self.member.endorsement_root) {
            return Err(E::MemberRootNotInSet);
        }
        self.member.tpm_profile()?;
        match self.parameters.class {
            GenesisClass::Production => {
                for (root, entry) in roots {
                    if entry.test_value_label.is_some() || *root == v1_test_value_root() {
                        return Err(E::TestValueRootInProduction);
                    }
                    if root.iter().all(|b| *b == root[0]) {
                        return Err(E::PlaceholderRoot);
                    }
                }
                if self.parameters.pcr_profiles.profiles().any(|p| p.digest.iter().all(|b| *b == p.digest[0])) {
                    return Err(E::PlaceholderPcrProfile);
                }
                self.treasury
                    .require_production()
                    .map_err(|_| E::TreasuryClassMismatch)?;
                crate::endorsement_identity::check_class_coverage(
                    &self.member.tpm_profile()?, &self.parameters.identity_classes,
                )?;
            }
            GenesisClass::TestValue => {
                for (root, entry) in roots {
                    match &entry.test_value_label {
                        Some(label) if test_value_root(label) == *root => {}
                        _ => return Err(E::UnlabelledRootInTestValue),
                    }
                }
                self.treasury
                    .require_test()
                    .map_err(|_| E::TreasuryClassMismatch)?;
            }
        }
        Ok(())
    }
    /// GenesisID V2 = H(MUTINY-BUILD8-GENESIS-ID-V2, canonical input bytes); only for valid inputs.
    pub fn identity(&self) -> Result<Hash> {
        self.validate()?;
        Ok(domain_hash(IDENTITY_DOMAIN, &self.encode()?))
    }
}

/// Post-identity ceremony material: `[2, supervised_nonce, member_binding bytes, [12 assignment
/// bytes], [12 supervised enrollment binding bytes]]`. Every element binds the frozen GenesisID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrollment {
    pub supervised_nonce: Hash,
    pub member_binding: Binding,
    pub assignments: Vec<Assignment>,
    pub supervised: Vec<SupervisedBinding>,
}
impl Enrollment {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.supervised_nonce == [0; 32] {
            return Err(E::ZeroField);
        }
        if self.assignments.len() != GENESIS_LICENSES as usize
            || self.supervised.len() != GENESIS_LICENSES as usize
        {
            return Err(E::EnrollmentCount);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&self.supervised_nonce)
            .unwrap()
            .bytes(&self.member_binding.encode()?)
            .unwrap()
            .array(GENESIS_LICENSES)
            .unwrap();
        for assignment in &self.assignments {
            e.bytes(&assignment.encode()?).unwrap();
        }
        e.array(GENESIS_LICENSES).unwrap();
        for binding in &self.supervised {
            e.bytes(&binding.bytes().map_err(|_| E::Codec)?).unwrap();
        }
        let raw = e.into_writer();
        if raw.len() > MAX_ENROLLMENT {
            return Err(E::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        canonical(raw, MAX_ENROLLMENT)?;
        let mut d = Decoder::new(raw);
        arity(&mut d, 5)?;
        version(&mut d, 2)?;
        let supervised_nonce = fixed32(&mut d)?;
        let member_binding = Binding::decode(codec(d.bytes())?)?;
        if codec(d.array())? != Some(GENESIS_LICENSES) {
            return Err(E::EnrollmentCount);
        }
        let mut assignments = Vec::new();
        for _ in 0..GENESIS_LICENSES {
            assignments.push(Assignment::decode(codec(d.bytes())?)?);
        }
        if codec(d.array())? != Some(GENESIS_LICENSES) {
            return Err(E::EnrollmentCount);
        }
        let mut supervised = Vec::new();
        for _ in 0..GENESIS_LICENSES {
            supervised.push(SupervisedBinding::decode(codec(d.bytes())?).map_err(|_| E::Codec)?);
        }
        let enrollment = Self {
            supervised_nonce,
            member_binding,
            assignments,
            supervised,
        };
        end(&d, raw, enrollment.encode()?)?;
        Ok(enrollment)
    }
}

/// GenesisBlockV2 = `[2, NetworkID, GenesisID, ProtocolFingerprint, timestamp, InitialStateRoot]`.
pub fn block_bytes(identity: Hash, fingerprint: Hash, timestamp: u64, state_root: Hash) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(6)
        .unwrap()
        .u8(2)
        .unwrap()
        .u32(NETWORK_ID)
        .unwrap()
        .bytes(&identity)
        .unwrap()
        .bytes(&fingerprint)
        .unwrap()
        .u64(timestamp)
        .unwrap()
        .bytes(&state_root)
        .unwrap();
    e.into_writer()
}
pub fn block_hash(block: &[u8]) -> Hash {
    domain_hash(BLOCK_DOMAIN, block)
}

/// A constructed (never sealed) V2 Genesis.
#[derive(Clone, Debug)]
pub struct Constructed {
    pub identity: Hash,
    pub fingerprint: Hash,
    pub class: GenesisClass,
    pub state: State,
    pub root: Hash,
    pub block: Vec<u8>,
    pub block_hash: Hash,
    /// Mining-epoch origin (the input timestamp).
    pub t0: u64,
    pub target: Hash,
}
impl Constructed {
    /// The height-zero finalized anchor of this Genesis.
    pub fn anchor(&self) -> FinalizedAnchor {
        FinalizedAnchor {
            network: NETWORK_ID,
            genesis: self.identity,
            fingerprint: self.fingerprint,
            height: 0,
            block: self.block_hash,
        }
    }
    pub fn records(&self) -> Result<Vec<(Hash, Vec<u8>)>> {
        Ok(self.state.records()?)
    }
}

/// Explicit V2 Genesis constructor. The class comes only from the input bytes (no class, profile,
/// flag or environment argument exists). Every initial component is derived from the frozen inputs
/// and the post-identity enrollment through the existing V2 component constructors; the complete
/// state then passes every `State::records` backstop. Nothing is installed or sealed.
pub fn construct(inputs: &Inputs, enrollment: &Enrollment) -> Result<Constructed> {
    construct_internal(inputs, enrollment, None)
}
/// New A2-marked candidates require the exact available public admission witness.
/// This constructs unsealed bytes only and never establishes locality or activation.
pub fn construct_with_public_dependencies(inputs: &Inputs, enrollment: &Enrollment,
    bundle: &[u8]) -> Result<Constructed> {
    construct_internal(inputs, enrollment, Some(bundle))
}
fn construct_internal(inputs: &Inputs, enrollment: &Enrollment,
    bundle: Option<&[u8]>) -> Result<Constructed> {
    use crate::recovery::{Anchor, ContinuityState, Member};
    inputs.validate()?;
    enrollment.encode()?;
    let identity = inputs.identity()?;
    let fingerprint = inputs.parameters.fingerprint()?;
    let class = inputs.parameters.class;
    let profile = inputs.member.tpm_profile()?;
    let binding = &enrollment.member_binding;
    if binding.admission.profile != inputs.member.profile
        || binding.admission.endorsement_root != inputs.member.endorsement_root
    {
        return Err(E::MemberBindingMismatch);
    }
    let mut state = State::default();
    state.wallets.register(&inputs.admission_owner)?;
    let policy = Policy {
        genesis: identity,
        fingerprint,
        owner_descriptor: inputs.admission_owner.clone(),
        endorsement_roots: inputs.parameters.roots.hashes(),
    };
    let record = crate::admission_policy_v2::Record::new(policy.clone())?;
    let node = crate::node_admission_v2::node_id(identity, &binding.node_descriptor)?;
    let expected = Expected {
        node,
        hardware_generation: 1,
        key_generation: 1,
        supervised_nonce: enrollment.supervised_nonce,
    };
    let (membership, keys) = crate::membership_v2::Book::genesis(
        binding,
        &policy,
        &expected,
        &state.wallets,
        class.admission_class(),
    )?;
    let voting_key = crate::tpm::public_key(&profile.voting_public, false)?;
    let recovery = crate::recovery_genesis_input_v2::RecoveryInput::new(inputs.recovery.clone())?;
    let registry = ContinuityState::bootstrap(
        identity,
        fingerprint,
        Anchor {
            height: 0,
            tip: [0; 32],
            state_root: [0; 32],
            registry_root: [0; 32],
        },
        recovery.commitment(),
        vec![Member {
            lineage: node,
            node,
            hardware: profile.hardware,
            generation: 1,
            voting_key,
            attestation: profile.commitment()?,
            history: Default::default(),
            physical: true,
            eligible: true,
            genesis_member: true,
        }],
    )?;
    let license_owner = inputs.license_owner()?;
    let mut licenses = Vec::new();
    for index in 0..GENESIS_LICENSES {
        licenses.push(LicenseRecord {
            id: crate::blocks::genesis_license(identity, index)?,
            genesis: identity,
            owner: license_owner,
            issuance: inputs.purchase,
            index,
            issue_height: 0,
            active_worker: None,
            assignment_sequence: 0,
        });
    }
    state.licenses_v2 = crate::license_book_v2::Book::genesis(
        &enrollment.assignments,
        &enrollment.supervised,
        &licenses,
        &state.wallets,
        identity,
        fingerprint,
    )?;
    state.admission_policy_v2 = Some(record);
    state.membership_v2 = membership;
    state.continuity_keys_v2 = keys;
    state.continuity = Some(registry);
    state.recovery_authority_v2 = Some(crate::recovery_authority_v2::Authority {
        genesis: identity,
        fingerprint,
        descriptor: inputs.recovery.clone(),
    });
    state.dividends = crate::dividend_state_v1::DividendState::genesis(inputs.treasury.clone());
    // The Genesis member's rolling freshness record, derived like the V2 JOIN composition derives
    // its record (`continuity_lifecycle_v2`): the admission quote is the fresh supervised evidence.
    state.accounting.freshness.insert(
        node,
        crate::freshness::FreshnessRecord {
            node,
            generation: 1,
            key: voting_key,
            committed_height: 0,
            evidence_commitment: domain_hash(
                b"MUTINY-BUILD8-ATTESTATION-EVIDENCE-V1",
                &binding.admission.quote,
            ),
        },
    );
    state
        .protocol_records
        .insert(parameters_key(), inputs.parameters.encode()?);
    let a2 = crate::endorsement_revocation_v1::enabled(&inputs.parameters)?;
    match (a2, bundle) {
        (true, Some(bundle)) => {
            state.endorsement_dependencies_v1 = crate::endorsement_dependencies_v1::Book::genesis(
                &state, inputs, bundle)?;
        }
        (false, None) => {}
        // No silently incomplete index, local enable flag or legacy artifact upgrade.
        _ => return Err(E::State),
    }
    let root = state.root()?;
    // The committed state must yield exactly the input class (`State::admission_class`).
    if state.admission_class()? != class.admission_class() {
        return Err(E::State);
    }
    let block = block_bytes(identity, fingerprint, inputs.timestamp, root);
    let block_hash = block_hash(&block);
    Ok(Constructed {
        identity,
        fingerprint,
        class,
        state,
        root,
        block,
        block_hash,
        t0: inputs.timestamp,
        target: inputs.parameters.initial_target,
    })
}

/// Trust inputs of the verifier, obtained independently of the artifact being verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approved {
    /// The independently approved rule manifest (it commits to class, root set and PCR slot).
    pub manifest: RuleManifest,
    /// The class this verifier accepts. A Production verifier refuses every other class.
    pub class: GenesisClass,
    /// The independently qualified initial PoW target.
    pub initial_target: Hash,
}
/// What an artifact claims; every value is compared with the reconstruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claimed {
    pub genesis_id: Hash,
    pub records: Vec<(Hash, Vec<u8>)>,
    pub state_root: Hash,
    pub block: Vec<u8>,
    pub block_hash: Hash,
}

/// The inputs must match the independently approved class (checked first: a Production verifier
/// refuses every other class), rule manifest (exact canonical bytes) and initial target.
pub fn check_approved(inputs: &Inputs, approved: &Approved) -> Result<()> {
    if inputs.parameters.class != approved.class {
        return Err(E::ClassMismatch);
    }
    let approved_manifest = approved.manifest.encode().map_err(|_| E::ManifestMismatch)?;
    if inputs.parameters.rules.encode()? != approved_manifest {
        return Err(E::ManifestMismatch);
    }
    if inputs.parameters.initial_target != approved.initial_target {
        return Err(E::TargetMismatch);
    }
    Ok(())
}

/// Verifier: strict decoding, then the inputs must match the independently approved class, manifest
/// and target, then the complete Genesis is reconstructed and every claimed value (identity, each
/// record, StateRoot, block bytes and hash) must equal the reconstruction.
pub fn verify(
    inputs: &[u8],
    enrollment: &[u8],
    approved: &Approved,
    claimed: &Claimed,
) -> Result<Constructed> {
    let inputs = Inputs::decode(inputs)?;
    let enrollment = Enrollment::decode(enrollment)?;
    check_approved(&inputs, approved)?;
    let constructed = construct(&inputs, &enrollment)?;
    if claimed.genesis_id != constructed.identity {
        return Err(E::IdentityMismatch);
    }
    if claimed.records != constructed.records()? {
        return Err(E::RecordsMismatch);
    }
    if claimed.state_root != constructed.root {
        return Err(E::StateRootMismatch);
    }
    if claimed.block != constructed.block || claimed.block_hash != constructed.block_hash {
        return Err(E::BlockMismatch);
    }
    Ok(constructed)
}
/// Current A2 Genesis reconstruction. Independently approved inputs precede
/// trusting any public evidence. No physical-host check is relaxed by this verifier.
pub fn verify_with_public_dependencies(
    inputs: &[u8], enrollment: &[u8], approved: &Approved, claimed: &Claimed, bundle: &[u8],
) -> Result<Constructed> {
    let inputs = Inputs::decode(inputs)?;
    let enrollment = Enrollment::decode(enrollment)?;
    check_approved(&inputs, approved)?;
    let constructed = construct_with_public_dependencies(&inputs, &enrollment, bundle)?;
    if claimed.genesis_id != constructed.identity { return Err(E::IdentityMismatch); }
    if claimed.records != constructed.records()? { return Err(E::RecordsMismatch); }
    if claimed.state_root != constructed.root { return Err(E::StateRootMismatch); }
    if claimed.block != constructed.block || claimed.block_hash != constructed.block_hash { return Err(E::BlockMismatch); }
    Ok(constructed)
}

/// Class of a state that carries a GenesisParametersV2 record (`State::admission_class` consults
/// this first). Absent record: `None` (the V1 rule applies unchanged). Present: the V1 parameters
/// record and the V1 policy must be absent, the V2 policy present with exactly the record's root
/// hashes and manifest fingerprint, and the record must decode; otherwise an error, never a
/// fallback. Read only from committed state.
pub(crate) fn committed_class(state: &State) -> crate::Result<Option<AdmissionClass>> {
    let Some(raw) = state.protocol_records.get(&parameters_key()) else {
        return Ok(None);
    };
    if state
        .protocol_records
        .contains_key(&crate::genesis_inputs::parameters_key())
        || state.admission.policy.is_some()
    {
        return Err(Error::UnqualifiedPhysical);
    }
    let record = state
        .admission_policy_v2
        .as_ref()
        .ok_or(Error::UnqualifiedPhysical)?;
    let parameters = Parameters::decode(raw).map_err(|_| Error::Codec)?;
    let initial = record.initial();
    if initial.fingerprint != parameters.rules.fingerprint()? {
        return Err(Error::WrongFingerprint);
    }
    if initial.endorsement_roots != parameters.roots.hashes() {
        return Err(Error::UnqualifiedPhysical);
    }
    Ok(Some(parameters.class.admission_class()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn constraints() -> AnchorConstraints {
        // TEST-VALUE illustrative constraint values only.
        AnchorConstraints {
            max_intermediates: 1,
            signature_algorithms: [SignatureAlgorithm::EcdsaP256Sha256, SignatureAlgorithm::EcdsaP384Sha384].into(),
            ek_classes: [(crate::endorsement_identity::RSA_TAG, 2048), (crate::endorsement_identity::ECC_TAG, 3)].into(),
            revocation: RevocationMode::CrlRequired,
        }
    }
    fn set(labels: &[&str]) -> EndorsementRootSet {
        EndorsementRootSet {
            roots: labels
                .iter()
                .map(|l| {
                    (
                        test_value_root(l.as_bytes()),
                        EndorsementRoot {
                            constraints: constraints(),
                            test_value_label: Some(l.as_bytes().to_vec()),
                        },
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn class_byte_codec_and_admission_mapping() {
        assert_eq!(GenesisClass::from_byte(1), Ok(GenesisClass::Production));
        assert_eq!(GenesisClass::from_byte(2), Ok(GenesisClass::TestValue));
        for byte in [0u8, 3, 255] {
            assert_eq!(GenesisClass::from_byte(byte), Err(E::UnknownClass));
        }
        assert_eq!(GenesisClass::Production.admission_class(), AdmissionClass::Production);
        assert_eq!(GenesisClass::TestValue.admission_class(), AdmissionClass::LegacyTest);
        assert_ne!(GenesisClass::Production.commitment(), GenesisClass::TestValue.commitment());
        assert_eq!(GenesisClass::TestValue.commitment(), domain_hash(CLASS_DOMAIN, &[2]));
    }

    #[test]
    fn constraints_are_versioned_bounded_and_canonical() {
        let mut ok = Encoder::new(Vec::new());
        encode_constraints(&constraints(), &mut ok).unwrap();
        let raw = ok.into_writer();
        assert_eq!(decode_constraints(&mut Decoder::new(&raw)).unwrap(), constraints());
        let bad = |edit: &dyn Fn(&mut AnchorConstraints)| {
            let mut c = constraints();
            edit(&mut c);
            encode_constraints(&c, &mut Encoder::new(Vec::new()))
        };
        assert_eq!(bad(&|c| c.signature_algorithms.clear()), Err(E::BadConstraints));
        assert_eq!(bad(&|c| c.ek_classes.clear()), Err(E::BadConstraints));
        assert_eq!(bad(&|c| { c.ek_classes.insert((3, 2048)); }), Err(E::BadConstraints));
        assert_eq!(bad(&|c| { c.ek_classes.insert((crate::endorsement_identity::RSA_TAG, 1024)); }), Err(E::BadConstraints));
        assert_eq!(bad(&|c| c.max_intermediates = crate::ek_chain::MAX_INTERMEDIATES + 1), Err(E::BadConstraints));
        let mut wrong_version = raw.clone();
        assert_eq!(wrong_version[1], 2);
        wrong_version[1] = 1;
        assert_eq!(decode_constraints(&mut Decoder::new(&wrong_version)), Err(E::UnknownVersion));
        let mut unknown_code = raw.clone();
        let last = unknown_code.len() - 1;
        unknown_code[last] = 3;
        assert_eq!(decode_constraints(&mut Decoder::new(&unknown_code)), Err(E::BadConstraints));
    }

    #[test]
    fn root_set_rejects_empty_zero_and_bad_labels_and_round_trips() {
        let two = set(&["a", "b"]);
        let raw = two.encode().unwrap();
        assert_eq!(EndorsementRootSet::decode(&raw).unwrap(), two);
        assert_eq!(EndorsementRootSet { roots: BTreeMap::new() }.encode(), Err(E::EmptyRootSet));
        let mut zero = two.clone();
        zero.roots.insert([0; 32], EndorsementRoot { constraints: constraints(), test_value_label: None });
        assert_eq!(zero.encode(), Err(E::ZeroRoot));
        let mut long = two.clone();
        long.roots.values_mut().next().unwrap().test_value_label = Some(vec![b'x'; MAX_LABEL + 1]);
        assert_eq!(long.encode(), Err(E::BadLabel));
        let mut trailing = raw.clone();
        trailing.push(0);
        assert_eq!(EndorsementRootSet::decode(&trailing), Err(E::NonCanonical));
    }
}
