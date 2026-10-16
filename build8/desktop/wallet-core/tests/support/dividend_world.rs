// Deterministic synthetic chain state for dividend-claim tests (no blocks, no store).
//
// Genesis bootstrap Licenses are rebuilt from public License records through the PUBLIC
// `license_book_v2::Book::from_records`, the first award is produced by the PUBLIC
// `DividendState::advance`, and later account values or License statuses are written through the
// PUBLIC record codec `DividendState::from_records`. Nothing here needs, or may enable, the
// consensus `dividend-test-fixtures` feature. A synthetic state is not authenticated: it stands in
// for a verified state in tests that never touch a block.
// NATIVE, TEST-VALUE: public deterministic test keys only (BIP-39 test vectors and a labelled
// rehearsal key that is public by construction).
//
// Owned by phase 3 of the wallet plan.
#![allow(dead_code)]

use minicbor::Encoder;
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    blocks::genesis_license,
    dividend_claim_v1::{self, ClaimBody, ClaimError, SignedClaim},
    dividend_state_v1::DividendState,
    dividends_v1::{AWARD_PERIOD_EPOCHS, Account, CLAIM_WINDOW_EPOCHS},
    domain_hash,
    execution::State,
    license_book_v2::Book,
    license_status_v1,
    licenses::LicenseRecord,
    transactions::{Coin, OutPoint, Output},
    treasury_v1::{Class, Treasury},
    wallet_rotation_v1::Rotation,
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
use mutiny_wallet_core_v8::{ChainView, HeadInfo, SignerIdentity};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

pub const T0: u64 = 1000;
/// The first award epoch.
pub const P: u64 = AWARD_PERIOD_EPOCHS;
/// The claim window of an award, in epochs.
pub const W: u64 = CLAIM_WINDOW_EPOCHS;
pub const GENESIS: Hash = [1; 32];
pub const FINGERPRINT: Hash = [2; 32];
/// Head height of a fresh world.
pub const HEIGHT: u64 = 100;

/// The wallet under test, which owns every synthetic License (the all-"abandon" BIP-39 vector).
pub fn owner_key() -> HybridKey {
    HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner).unwrap()
}

/// The TEST-VALUE Treasury key (the all-"zoo" BIP-39 vector).
pub fn treasury_key() -> HybridKey {
    HybridKey::wallet_restore(&format!("{}vote", "zoo ".repeat(23)), Role::WalletOwner).unwrap()
}

/// Another wallet (a recipient, a buyer, a stranger).
pub fn other_key() -> HybridKey {
    HybridKey::wallet_restore(
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        Role::WalletOwner,
    )
    .unwrap()
}

/// The owner's next key after a rotation: a labelled rehearsal key (public by construction).
pub fn rotated_key() -> HybridKey {
    let phrase = mutiny_crypto_v2::rehearsal_keys_v1::label_phrase("wallet-p3-rotated-owner").unwrap();
    HybridKey::wallet_restore(&phrase, Role::WalletOwner).unwrap()
}

pub fn address(key: &HybridKey, generation: u64) -> Hash {
    key.public().address_id(generation).unwrap()
}

pub fn descriptor(key: &HybridKey, generation: u64) -> Vec<u8> {
    key.public().descriptor(generation).unwrap()
}

pub fn identity(key: &HybridKey) -> SignerIdentity {
    SignerIdentity::from_public(key.public(), 1, None).unwrap()
}

/// A Genesis bootstrap LicenseID of the synthetic chain.
/// The public identifiers of the owner and Treasury keys, derived once per test process (restoring
/// a hybrid key from its phrase is not free).
struct PublicIds {
    owner_address: Hash,
    owner_descriptor: Vec<u8>,
    treasury_address: Hash,
    treasury_descriptor: Vec<u8>,
}

fn ids() -> &'static PublicIds {
    static IDS: OnceLock<PublicIds> = OnceLock::new();
    IDS.get_or_init(|| {
        let (owner, treasury) = (owner_key(), treasury_key());
        PublicIds {
            owner_address: address(&owner, 1),
            owner_descriptor: descriptor(&owner, 1),
            treasury_address: address(&treasury, 1),
            treasury_descriptor: descriptor(&treasury, 1),
        }
    })
}

pub fn license_id(index: u64) -> Hash {
    genesis_license(GENESIS, index).unwrap()
}

/// A block timestamp inside `epoch`.
pub fn at_epoch(epoch: u64) -> u64 {
    T0 + 60 * epoch + 5
}

pub fn treasury_coin() -> OutPoint {
    OutPoint {
        transaction: [0xd1; 32],
        index: 0,
    }
}

/// Detached Genesis bootstrap License records (no Worker), keyed exactly as `Book::records` keys
/// them, read back through the public `Book::from_records`.
pub fn license_book(owners: &[(u64, Hash)]) -> Book {
    let mut records = BTreeMap::new();
    for (index, owner) in owners {
        let record = LicenseRecord {
            id: license_id(*index),
            genesis: GENESIS,
            owner: *owner,
            issuance: [8; 32],
            index: *index,
            issue_height: 0,
            active_worker: None,
            assignment_sequence: 0,
        };
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(40)
            .unwrap()
            .bytes(&record.encode())
            .unwrap();
        records.insert(
            domain_hash(b"MUTINY-BUILD8-LICENSE-STATE-KEY-V2", &record.id),
            e.into_writer(),
        );
    }
    Book::from_records(&records).expect("public License records")
}

fn header_key() -> Hash {
    domain_hash(b"MUTINY-BUILD8-DIVIDEND-LEDGER-STATE-KEY-V1", &[])
}

fn award_key(epoch: u64) -> Hash {
    domain_hash(
        b"MUTINY-BUILD8-DIVIDEND-AWARD-STATE-KEY-V1",
        &epoch.to_be_bytes(),
    )
}

pub struct ClaimWorld {
    pub state: State,
    pub anchor: FinalizedAnchor,
    pub reserved: BTreeSet<OutPoint>,
    pub timestamp: u64,
}

impl ClaimWorld {
    /// `licenses` Genesis bootstrap Licenses (indices 0 to `licenses - 1`) owned by the owner key's
    /// generation-one address, a TEST-VALUE Treasury holding `treasury_atoms` in one coin, and the
    /// first award (epoch P) processed. The head is at height 100, in epoch P + 10.
    pub fn new(licenses: u64, treasury_atoms: u64) -> Self {
        let owner = ids().owner_address;
        let owners: Vec<(u64, Hash)> = (0..licenses).map(|index| (index, owner)).collect();
        Self::with_owners(&owners, treasury_atoms)
    }

    /// The same with explicit owners per License index.
    pub fn with_owners(owners: &[(u64, Hash)], treasury_atoms: u64) -> Self {
        let mut state = State::default();
        state.wallets.register(&ids().owner_descriptor).unwrap();
        state.wallets.register(&ids().treasury_descriptor).unwrap();
        state.licenses_v2 = license_book(owners);
        state.coins.insert(
            treasury_coin(),
            Coin {
                output: Output {
                    owner: ids().treasury_address,
                    atoms: treasury_atoms,
                },
                created_height: 0,
                coinbase: false,
            },
        );
        state.dividends = DividendState::genesis(
            Treasury::new(Class::TestValue, ids().treasury_descriptor.clone()).unwrap(),
        );
        let triples: Vec<(Hash, Hash, Option<u64>)> = owners
            .iter()
            .map(|(index, owner)| (license_id(*index), *owner, Some(0)))
            .collect();
        state
            .dividends
            .advance(P, treasury_atoms, &triples)
            .expect("the first award");
        Self {
            state,
            anchor: FinalizedAnchor {
                network: NETWORK_ID,
                genesis: GENESIS,
                fingerprint: FINGERPRINT,
                height: HEIGHT,
                block: [3; 32],
            },
            reserved: BTreeSet::new(),
            timestamp: at_epoch(P + 10),
        }
    }

    /// A world without any Treasury record (dividends inactive) and the same Licenses.
    pub fn inactive(licenses: u64) -> Self {
        let mut world = Self::new(licenses, 1_200_000);
        world.state.dividends = DividendState::default();
        world
    }

    /// Put the head in `epoch` (heights and epochs are independent in a synthetic world).
    pub fn at(mut self, epoch: u64) -> Self {
        self.timestamp = at_epoch(epoch);
        self
    }

    pub fn head(&self) -> HeadInfo {
        // A synthetic state need not hash; the core never recomputes the root itself.
        let root = self.state.root().unwrap_or([0x77; 32]);
        HeadInfo::new(self.anchor.clone(), self.timestamp, T0, root).unwrap()
    }

    pub fn view(&self) -> ChainView<'_> {
        ChainView::new(self.head(), &self.state, &self.reserved)
    }

    /// The same state at a later head: `blocks` blocks and `epochs` epochs on.
    pub fn later(&self, blocks: u64, epochs: u64) -> Self {
        let mut next = Self {
            state: self.state.clone(),
            anchor: self.anchor.clone(),
            reserved: self.reserved.clone(),
            timestamp: self.timestamp + 60 * epochs,
        };
        next.anchor.height += blocks;
        next.anchor.block[0] ^= (blocks as u8) | 0x80;
        next
    }

    pub fn account(&self, award: u64, license: &Hash) -> Option<Account> {
        self.state.dividends.ledger().award(award)?.account(license)
    }

    /// Rewrite the dividend records (header and every award) through the public codec, after
    /// `edit` changed some accounts. The reserve is recomputed as the sum of what remains.
    fn rewrite(&mut self, edit: impl Fn(u64, &Hash, &mut Account), extra: &[(Hash, Vec<u8>)]) {
        let mut records = self.state.dividends.records().unwrap();
        let ledger = self.state.dividends.ledger();
        let mut reserved = 0u64;
        for award in ledger.awards_iter() {
            let mut accounts: Vec<(Hash, Account)> = award
                .accounts_iter()
                .map(|(license, account)| (*license, *account))
                .collect();
            for (license, account) in &mut accounts {
                edit(award.epoch(), license, account);
                reserved += account.remaining;
            }
            let mut e = Encoder::new(Vec::new());
            e.array(4)
                .unwrap()
                .u8(2)
                .unwrap()
                .u8(63)
                .unwrap()
                .u64(award.epoch())
                .unwrap()
                .array(accounts.len() as u64)
                .unwrap();
            for (license, account) in &accounts {
                e.array(4)
                    .unwrap()
                    .bytes(license)
                    .unwrap()
                    .u64(account.share)
                    .unwrap()
                    .u64(account.remaining)
                    .unwrap()
                    .u64(account.claims)
                    .unwrap();
            }
            records.insert(award_key(award.epoch()), e.into_writer());
        }
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(62)
            .unwrap()
            .u64(reserved)
            .unwrap()
            .u64(ledger.cursor())
            .unwrap();
        records.insert(header_key(), e.into_writer());
        for (key, raw) in extra {
            records.insert(*key, raw.clone());
        }
        self.state.dividends = DividendState::from_records(&records).expect("public dividend records");
    }

    /// As if claims had been applied: `remaining` and `claims` of one account (the share stays).
    pub fn set_account(&mut self, award: u64, license: Hash, remaining: u64, claims: u64) {
        self.rewrite(
            |epoch, id, account| {
                if epoch == award && *id == license {
                    account.remaining = remaining;
                    account.claims = claims;
                }
            },
            &[],
        );
    }

    /// Give a License a status entry: suspended until an epoch, or revoked (`None`). TEST-VALUE
    /// Treasuries only, exactly as consensus allows.
    pub fn set_status(&mut self, license: Hash, suspended_until: Option<u64>) {
        let (kind, until) = match suspended_until {
            Some(until) => (1u8, until),
            None => (2u8, 0u64),
        };
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(61)
            .unwrap()
            .bytes(&license)
            .unwrap()
            .u8(kind)
            .unwrap()
            .u64(until)
            .unwrap();
        let record = (license_status_v1::key(&license), e.into_writer());
        self.rewrite(|_, _, _| {}, &[record]);
    }

    /// Rotate the owner authority from the owner key (generation one) to the rotated key
    /// (generation two), exactly as consensus applies a verified rotation to the wallet book.
    pub fn rotate_owner(&mut self) {
        let zero = HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        };
        let mut rotation = Rotation {
            network: NETWORK_ID,
            genesis: GENESIS,
            fingerprint: FINGERPRINT,
            authority: address(&owner_key(), 1),
            current: descriptor(&owner_key(), 1),
            proposed: descriptor(&rotated_key(), 2),
            created_height: 1,
            expiry_height: self.anchor.height + 10,
            authorization: zero.clone(),
            possession: zero,
        };
        rotation.sign(&owner_key(), &rotated_key()).unwrap();
        self.state
            .wallets
            .apply(&rotation, GENESIS, FINGERPRINT, self.anchor.height)
            .unwrap();
    }

    /// A claim signed by hand through the public consensus API, valid for blocks 1 to 10,000.
    #[allow(clippy::too_many_arguments)]
    pub fn hand_claim(
        &self,
        key: &HybridKey,
        generation: u64,
        license: Hash,
        award: u64,
        amount: u64,
        sequence: u64,
        destination: Hash,
    ) -> Vec<u8> {
        sign_claim(
            claim_body(license, award, amount, sequence, destination),
            key,
            generation,
        )
    }

    /// Consensus' bounded admission of a claim for the next block, at the head's epoch.
    pub fn admit(&self, raw: &[u8]) -> Result<(), ClaimError> {
        let epoch = (self.timestamp - T0) / 60;
        dividend_claim_v1::admit(
            &self.state,
            raw,
            GENESIS,
            FINGERPRINT,
            self.anchor.height + 1,
            epoch,
        )
    }
}

/// A claim body on the synthetic chain, valid for blocks 1 to 10,000.
pub fn claim_body(
    license: Hash,
    award: u64,
    amount: u64,
    sequence: u64,
    destination: Hash,
) -> ClaimBody {
    ClaimBody {
        network: NETWORK_ID,
        genesis: GENESIS,
        fingerprint: FINGERPRINT,
        created_height: 1,
        expiry_height: 10_000,
        award_epoch: award,
        license,
        amount,
        destination,
        sequence,
    }
}

/// Sign a claim body by hand through the public consensus API.
pub fn sign_claim(body: ClaimBody, key: &HybridKey, generation: u64) -> Vec<u8> {
    SignedClaim::sign(body, descriptor(key, generation), key)
        .unwrap()
        .encode()
}

/// The same body with the zero signature placeholder (an unsigned proposal).
pub fn unsigned_claim(body: ClaimBody, descriptor: Vec<u8>) -> Vec<u8> {
    SignedClaim {
        body,
        descriptor,
        signature: HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    }
    .encode()
}

/// The consensus outcome of a claim as one short name (`"Ok"`, `"Context"`,
/// `"Dividend(Overdrawn)"`, ...).
pub fn outcome(result: &Result<(), ClaimError>) -> String {
    match result {
        Ok(()) => "Ok".to_string(),
        Err(error) => format!("{error:?}"),
    }
}

/// The wallet refusal codes that agree with each consensus outcome. The wallet is sometimes MORE
/// specific than consensus (an absent award is "expired" when its window has passed, "not reached"
/// when its epoch is ahead of the head, "not entitled" otherwise), never less.
pub fn agreeing_codes(consensus: &str) -> &'static [&'static str] {
    match consensus {
        "Inactive" => &["DIVIDEND_INACTIVE"],
        "Context" => &["WRONG_CONTEXT"],
        "Window" => &["INVALID_VALIDITY", "WINDOW_NOT_OPEN", "WINDOW_CLOSED"],
        "UnknownLicense" => &["NOT_ENTITLED"],
        "Dividend(ZeroAmount)" => &["INVALID_AMOUNT"],
        "Dividend(UnknownAward)" => &["NOT_ENTITLED", "AWARD_EXPIRED", "AWARD_NOT_YET_OPEN"],
        "Dividend(NotYetClaimable)" => &["AWARD_NOT_YET_OPEN"],
        "Dividend(Expired)" => &["AWARD_EXPIRED"],
        "Dividend(NotEntitled)" | "Dividend(WrongLicense)" => &["NOT_ENTITLED"],
        "Dividend(Revoked)" | "Dividend(Suspended)" => &["LICENSE_SUSPENDED_OR_REVOKED"],
        "Dividend(Replay)" | "Duplicate" => &["REPLAY"],
        "Dividend(Sequence)" => &["WRONG_SEQUENCE"],
        "Dividend(Overdrawn)" => &["OVERDRAWN"],
        "StaleOwner" => &["STALE_AUTHORITY", "NOT_REQUIRED_SIGNER"],
        "Signature" => &["VERIFICATION_FAILED"],
        "Backing" => &["RESERVE_BACKING_VIOLATION"],
        "Codec" => &["MALFORMED", "UNKNOWN_OPERATION"],
        _ => &[],
    }
}
