//! The request forms (phase 7): one per operation kind that has a wallet-core handler in this
//! build. A form checks only the SYNTAX of what the person typed (hexadecimal identifiers, decimal
//! MUT amounts, block heights and epochs) and produces an `OperationRequest`; every rule of the
//! operation is wallet-core's (and through it consensus'), applied when the controller plans the
//! request, and the review that follows is the generic one (`plan_review`). A form cannot make
//! anything reviewable that wallet-core would not plan.
//!
//! The Treasury profile is NOT selectable here. No form offers a Treasury kind, and a signing
//! identity carries `WalletProfile::Treasury` only while this machine's Treasury declaration (explicit
//! runtime configuration, checked by wallet-core's `profile::declare` against the verified chain at
//! every unlock and every new head) holds, never from a button. The wallet rotation is its own flow (two
//! keys and the clean restore of the new phrase; see the controller), not a plain form.
use crate::{
    payment::parse_amount,
    plan_review::{ReviewInput, ReviewPanel, ReviewScreen},
    wallet_controller_v2::{Controller, ReviewOutcome},
};
use eframe::egui;
#[path = "branded_ui.rs"]
mod branded_ui;
use mutiny_consensus_v8::Hash;
use mutiny_wallet_core_v8::{
    Blob, BondCreateRequest, BondUnbondRequest, BondWithdrawRequest, DividendClaimRequest,
    FiatLockRequest, FiatReleaseRequest, HashLockRequest, LicenseDvpRequest, OperationKind,
    OperationRequest, PaymentRequest, RefundRequest, WorkerAssignmentRequest,
    ops::implemented_kinds,
};

/// What a form produces.
#[derive(Debug)]
pub enum FormOutput {
    /// A request for the controller to plan; its review follows.
    Request(Box<OperationRequest>),
    /// A claim of this hash lock: the controller takes the preimage from its own sealed store.
    Claim(Hash),
    /// Typed above-consensus maker terms. The controller supplies current identity and chain.
    MakerOffer {
        terms: mutiny_consensus_v8::trading_offer_v2::OfferTerms,
        side: u8,
        destination: Hash,
        condition: Option<Hash>,
        max_fee: u64,
        validity: u64,
    },
}

/// The forms there are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormKind {
    WorkerAssignment,
    MakerOffer,
    Payment,
    DividendClaim,
    BondCreate,
    BondUnbond,
    BondWithdraw,
    HashLock,
    ConditionalClaim,
    ConditionalRefund,
    LicenseDvp,
    FiatLock,
    FiatRelease,
}

impl FormKind {
    pub const ALL: [FormKind; 13] = [
        Self::WorkerAssignment,
        Self::MakerOffer,
        Self::Payment,
        Self::DividendClaim,
        Self::BondCreate,
        Self::BondUnbond,
        Self::BondWithdraw,
        Self::HashLock,
        Self::ConditionalClaim,
        Self::ConditionalRefund,
        Self::LicenseDvp,
        Self::FiatLock,
        Self::FiatRelease,
    ];
    pub fn operation(self) -> OperationKind {
        match self {
            Self::WorkerAssignment => OperationKind::WorkerAssignment,
            Self::MakerOffer => OperationKind::MakerOffer,
            Self::Payment => OperationKind::Payment,
            Self::DividendClaim => OperationKind::DividendClaim,
            Self::BondCreate => OperationKind::BondCreate,
            Self::BondUnbond => OperationKind::BondUnbond,
            Self::BondWithdraw => OperationKind::BondWithdraw,
            Self::HashLock => OperationKind::HashLock,
            Self::ConditionalClaim => OperationKind::ConditionalClaim,
            Self::ConditionalRefund => OperationKind::ConditionalRefund,
            Self::LicenseDvp => OperationKind::LicenseDvp,
            Self::FiatLock => OperationKind::FiatLock,
            Self::FiatRelease => OperationKind::FiatRelease,
        }
    }
    /// The forms offered: kinds with a wallet-core handler in this build (never a Treasury kind).
    pub fn offered() -> Vec<FormKind> {
        let implemented = implemented_kinds();
        Self::ALL
            .into_iter()
            .filter(|kind| implemented.contains(&kind.operation()))
            .collect()
    }
}

/// A 32-byte identifier typed as 64 hexadecimal characters (surrounding spaces ignored).
pub fn parse_hash(field: &str, text: &str) -> Result<Hash, String> {
    let text = text.trim();
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{field}: enter 64 hexadecimal characters"));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(text, &mut out).map_err(|_| format!("{field}: invalid hexadecimal"))?;
    Ok(out)
}

/// A block height or epoch: decimal digits only.
pub fn parse_number(field: &str, text: &str) -> Result<u64, String> {
    let text = text.trim();
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{field}: enter a whole number"));
    }
    text.parse()
        .map_err(|_| format!("{field}: number too large"))
}

/// Imported bytes typed or pasted as hexadecimal (an offer), bounded.
pub fn parse_hex(field: &str, text: &str, max: usize) -> Result<Vec<u8>, String> {
    let text: String = text.split_whitespace().collect();
    let bytes = hex::decode(&text).map_err(|_| format!("{field}: invalid hexadecimal"))?;
    if bytes.is_empty() || bytes.len() > max {
        return Err(format!("{field}: between 1 and {max} bytes"));
    }
    Ok(bytes)
}

/// Largest imported offer accepted by a form (wallet-core bounds it again).
const MAX_OFFER_BYTES: usize = 64 * 1024;
/// Largest public wallet descriptor accepted by a form (wallet-core checks it against the book).
const MAX_DESCRIPTOR_BYTES: usize = 16 * 1024;

/// An optional 32-byte identifier: empty means not given.
fn optional_hash(field: &str, text: &str) -> Result<Option<Hash>, String> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    parse_hash(field, text).map(Some)
}

/// An optional counterparty descriptor (public data): empty means "read it from the verified
/// wallet book".
fn optional_descriptor(field: &str, text: &str) -> Result<Option<Blob>, String> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    parse_hex(field, text, MAX_DESCRIPTOR_BYTES).map(|bytes| Some(Blob::new(bytes)))
}

/// What the person typed, per field. One set of fields serves every form.
#[derive(Default)]
pub struct Forms {
    pub maker_terms: u8,
    pub maker_side: String,
    /// Public canonical binding and Worker possession; never a Worker secret.
    pub worker_binding: String,
    pub worker_proof: String,
    pub worker_node_descriptor: String,
    pub bitcoin_satoshis: String,
    pub bitcoin_network: String,
    pub max_fee: String,
    pub validity: String,
    /// Read from the locally verified chain by the controller, never chosen by this form.
    pub address_class: Option<mutiny_wallet_core_v8::ChainClass>,
    pub kind: Option<FormKind>,
    pub recipient: String,
    pub amount: String,
    pub license: String,
    pub award_epoch: String,
    pub destination: String,
    pub node: String,
    pub node_generation: String,
    pub lot: String,
    pub offer: String,
    pub condition: String,
    pub refund_height: String,
    pub trade: String,
    pub contract: String,
    pub lock: String,
    /// The buyer of a fiat lock.
    pub buyer: String,
    /// The payment-terms commitment of a fiat lock.
    pub payment_terms: String,
    /// The counterparty's current public descriptor (only for an address the wallet book cannot
    /// name: the seller of a License sale or fiat release, the buyer of a fiat lock).
    pub descriptor: String,
    pub error: Option<String>,
    /// Where the Review button was last drawn (tests click it).
    #[cfg(any(test, feature = "testvalue-window"))]
    pub(crate) review_button: Option<egui::Rect>,
    #[cfg(feature = "testvalue-window")]
    native_targets: Vec<(String, egui::Rect)>,
}

impl Forms {
    /// Show the form of `kind`. Another kind's form starts EMPTY: nothing typed for one operation
    /// (an address, an amount, a destination) carries over into another.
    pub fn select(&mut self, kind: FormKind) {
        if self.kind != Some(kind) {
            *self = Forms {
                kind: Some(kind),
                address_class: self.address_class,
                ..Default::default()
            };
        }
    }

    /// The output of the form of `kind`, or why the input is not acceptable.
    fn address(&self, field: &str, text: &str) -> Result<Hash, String> {
        let class = self
            .address_class
            .ok_or_else(|| "Verified chain class is unavailable".to_string())?;
        mutiny_wallet_core_v8::address_format::decode(text, class)
            .map_err(|e| format!("{field}: {}", e.code()))
    }
    fn optional_address(&self, field: &str, text: &str) -> Result<Option<Hash>, String> {
        if text.is_empty() {
            Ok(None)
        } else {
            self.address(field, text).map(Some)
        }
    }
    pub fn build(&self, kind: FormKind) -> Result<FormOutput, String> {
        if !FormKind::offered().contains(&kind) {
            return Err(format!(
                "{} is not available in this build",
                kind.operation().title()
            ));
        }
        let request = match kind {
            FormKind::WorkerAssignment => {
                OperationRequest::WorkerAssignment(WorkerAssignmentRequest::new(
                    Blob::new(parse_hex(
                        "Canonical public Worker Binding",
                        &self.worker_binding,
                        512,
                    )?),
                    Blob::new(parse_hex(
                        "Coordinator Node descriptor",
                        &self.worker_node_descriptor,
                        2048,
                    )?),
                    Blob::new(parse_hex(
                        "Ed448 Worker possession signature",
                        &self.worker_proof,
                        114,
                    )?),
                ))
            }
            FormKind::MakerOffer => {
                use mutiny_consensus_v8::{trading_offer_v2::OfferTerms, trading_v1::Strikes};
                let amount = Strikes(parse_amount(&self.amount)?);
                let side = u8::try_from(parse_number("Maker side", &self.maker_side)?)
                    .map_err(|_| "Maker side must be 0 or 1")?;
                if side > 1 {
                    return Err("Maker side must be 0 or 1".into());
                }
                let terms = match self.maker_terms {
                    0 => OfferTerms::HashLinked {
                        amount,
                        bitcoin_satoshis: parse_number(
                            "Bitcoin satoshi terms",
                            &self.bitcoin_satoshis,
                        )?,
                        bitcoin_network: u8::try_from(parse_number(
                            "Bitcoin network terms",
                            &self.bitcoin_network,
                        )?)
                        .map_err(|_| "Network terms out of range")?,
                    },
                    1 => OfferTerms::License {
                        license: parse_hash("License", &self.license)?,
                        generation: parse_number("License generation", &self.node_generation)?,
                        price: amount,
                    },
                    2 => OfferTerms::Fiat {
                        amount,
                        payment_terms: parse_hash("Payment terms", &self.payment_terms)?,
                    },
                    _ => return Err("Unknown maker terms".into()),
                };
                return Ok(FormOutput::MakerOffer {
                    terms,
                    side,
                    destination: self
                        .address("Maker receiving/change address", &self.destination)?,
                    condition: if self.maker_terms == 0 {
                        optional_hash("Condition", &self.condition)?
                    } else {
                        None
                    },
                    max_fee: parse_number("Maximum fee in STRIKES", &self.max_fee)?,
                    validity: parse_number("Validity blocks", &self.validity)?,
                });
            }
            FormKind::Payment => OperationRequest::Payment(PaymentRequest::new(
                self.address("Recipient", &self.recipient)?,
                parse_amount(&self.amount)?,
            )),
            FormKind::DividendClaim => OperationRequest::DividendClaim(DividendClaimRequest::new(
                parse_hash("License", &self.license)?,
                parse_number("Award epoch", &self.award_epoch)?,
                parse_amount(&self.amount)?,
                self.address("Destination", &self.destination)?,
            )),
            FormKind::BondCreate => {
                // A fresh nonce derives the lot identifier (OS randomness; never zero).
                let mut nonce = [0u8; 32];
                while nonce == [0u8; 32] {
                    mutiny_crypto_v2::fill_os_random(&mut nonce)
                        .map_err(|_| "Operating-system randomness is unavailable".to_string())?;
                }
                OperationRequest::BondCreate(BondCreateRequest::new(
                    parse_hash("Node", &self.node)?,
                    parse_number("Node generation", &self.node_generation)?,
                    parse_amount(&self.amount)?,
                    nonce,
                ))
            }
            FormKind::BondUnbond => {
                OperationRequest::BondUnbond(BondUnbondRequest::new(parse_hash("Lot", &self.lot)?))
            }
            FormKind::BondWithdraw => OperationRequest::BondWithdraw(BondWithdrawRequest::new(
                parse_hash("Lot", &self.lot)?,
            )),
            FormKind::HashLock => {
                let mut request = HashLockRequest::new(
                    Blob::new(parse_hex("Offer", &self.offer, MAX_OFFER_BYTES)?),
                    self.address("Recipient", &self.recipient)?,
                    parse_amount(&self.amount)?,
                    parse_hash("Condition", &self.condition)?,
                    parse_number("Refund height", &self.refund_height)?,
                );
                if !self.trade.trim().is_empty() {
                    request = request.with_trade(parse_hash("Trade", &self.trade)?);
                }
                if !self.contract.trim().is_empty() {
                    request = request.with_contract(parse_hash("Contract", &self.contract)?);
                }
                OperationRequest::HashLock(request)
            }
            FormKind::ConditionalClaim => {
                return Ok(FormOutput::Claim(parse_hash("Lock", &self.lock)?));
            }
            FormKind::ConditionalRefund => OperationRequest::ConditionalRefund(RefundRequest::new(
                parse_hash("Lock", &self.lock)?,
            )),
            FormKind::LicenseDvp => {
                // Consensus refuses a License sale whose TradeID or ContractHash is zero: both are
                // asked for (opaque commitments, Q8).
                let mut request = LicenseDvpRequest::new(
                    Blob::new(parse_hex("Offer", &self.offer, MAX_OFFER_BYTES)?),
                    parse_hash("License", &self.license)?,
                )
                .with_commitments(
                    parse_hash("Trade", &self.trade)?,
                    parse_hash("Contract", &self.contract)?,
                );
                if let Some(destination) =
                    self.optional_address("Payment destination", &self.destination)?
                {
                    request = request.with_payment_destination(destination);
                }
                if let Some(descriptor) =
                    optional_descriptor("Seller descriptor", &self.descriptor)?
                {
                    request = request.with_seller_descriptor(descriptor);
                }
                OperationRequest::LicenseDvp(request)
            }
            FormKind::FiatLock => {
                let mut request = FiatLockRequest::new(
                    Blob::new(parse_hex("Offer", &self.offer, MAX_OFFER_BYTES)?),
                    self.address("Buyer", &self.buyer)?,
                    parse_amount(&self.amount)?,
                    parse_hash("Payment terms", &self.payment_terms)?,
                );
                let trade = optional_hash("Trade", &self.trade)?;
                let contract = optional_hash("Contract", &self.contract)?;
                if trade.is_some() || contract.is_some() {
                    request = request
                        .with_commitments(trade.unwrap_or([0; 32]), contract.unwrap_or([0; 32]));
                }
                if let Some(descriptor) = optional_descriptor("Buyer descriptor", &self.descriptor)?
                {
                    request = request.with_buyer_descriptor(descriptor);
                }
                OperationRequest::FiatLock(request)
            }
            FormKind::FiatRelease => {
                let mut request = FiatReleaseRequest::new(parse_hash("Lock", &self.lock)?);
                if let Some(descriptor) =
                    optional_descriptor("Seller descriptor", &self.descriptor)?
                {
                    request = request.with_seller_descriptor(descriptor);
                }
                OperationRequest::FiatRelease(request)
            }
        };
        Ok(FormOutput::Request(Box::new(request)))
    }

    /// The form selector and the form of the selected kind; returns the output when the person
    /// asks for the review and the input is acceptable.
    pub fn show(&mut self, ui: &mut egui::Ui) -> Option<FormOutput> {
        self.show_scoped(ui, &FormKind::offered())
    }
    /// Native navigation filters presentation only. The offered-handler check remains in build.
    fn show_scoped(&mut self, ui: &mut egui::Ui, kinds: &[FormKind]) -> Option<FormOutput> {
        // A draft from another route must never render under a misleading operation group.
        if self.kind.is_some_and(|kind| !kinds.contains(&kind)) { self.kind = None; }
        #[cfg(feature = "testvalue-window")]
        self.native_targets.clear();
        ui.horizontal_wrapped(|ui| {
            for kind in FormKind::offered().into_iter().filter(|kind| kinds.contains(kind)) {
                let response =
                    ui.selectable_label(self.kind == Some(kind), kind.operation().title());
                #[cfg(feature = "testvalue-window")]
                self.native_targets
                    .push((format!("form:{}", kind.operation().title()), response.rect));
                if response.clicked() {
                    self.select(kind);
                }
            }
        });
        let kind = self.kind?;
        #[cfg(feature = "testvalue-window")]
        let targets = std::cell::RefCell::new(&mut self.native_targets);
        #[allow(unused_mut)]
        let mut field = |ui: &mut egui::Ui, label: &str, value: &mut String| {
            ui.vertical(|ui| {
                ui.label(label);
                let response = ui.add_sized(
                    [ui.available_width(), 48.0],
                    egui::TextEdit::singleline(value).desired_width(f32::INFINITY),
                );
                #[cfg(feature = "testvalue-window")]
                targets.borrow_mut().push((format!("field:{label}"), response.rect));
                #[cfg(not(feature = "testvalue-window"))]
                let _ = response;
            });
        };
        match kind {
            FormKind::WorkerAssignment => {
                ui.label("Import the exact public Worker binding and possession proof. The current License owner is resolved from this verified chain. No Worker secret or provisioning belongs here.");
                field(
                    ui,
                    "Canonical public Binding CBOR (hex)",
                    &mut self.worker_binding,
                );
                field(
                    ui,
                    "Coordinator Node descriptor (hex)",
                    &mut self.worker_node_descriptor,
                );
                field(
                    ui,
                    "Ed448 possession signature (114 bytes, hex)",
                    &mut self.worker_proof,
                );
                ui.label("The binding fixes one inclusion epoch and a last height. A missed epoch requires a fresh proof, review and signature.");
            }
            FormKind::MakerOffer => {
                ui.horizontal(|ui| {
                    for (code, label) in [(0, "Hash-linked"), (1, "License"), (2, "Fiat")] {
                        let response=ui.selectable_value(&mut self.maker_terms, code, label);
                        #[cfg(feature = "testvalue-window")]
                        targets.borrow_mut().push((format!("maker-terms:{label}"),response.rect));
                        #[cfg(not(feature = "testvalue-window"))]
                        let _=response;
                    }
                });
                field(
                    ui,
                    "Maker side (0 sender/seller; 1 recipient/buyer)",
                    &mut self.maker_side,
                );
                field(ui, "Amount/price (MUT)", &mut self.amount);
                field(
                    ui,
                    "Maker receiving/change checksummed address",
                    &mut self.destination,
                );
                field(ui, "Maximum settlement fee (STRIKES)", &mut self.max_fee);
                field(ui, "Finite validity (blocks)", &mut self.validity);
                match self.maker_terms {
                    0 => {
                        field(
                            ui,
                            "Bitcoin satoshi terms (metadata only)",
                            &mut self.bitcoin_satoshis,
                        );
                        field(
                            ui,
                            "Bitcoin network terms (metadata only)",
                            &mut self.bitcoin_network,
                        );
                        field(ui, "Condition SHA-256 (hex, optional)", &mut self.condition);
                    }
                    1 => {
                        field(ui, "License (hex)", &mut self.license);
                        field(ui, "License generation", &mut self.node_generation);
                    }
                    2 => {
                        field(
                            ui,
                            "Payment terms commitment (hex)",
                            &mut self.payment_terms,
                        );
                    }
                    _ => {}
                }
                ui.label("An offer is an exported witness. It reserves no funds and requires current maker authority at first canonical funding; rotation requires fresh review/signatures.");
            }
            FormKind::Payment => {
                field(ui, "Recipient checksummed address", &mut self.recipient);
                field(ui, "Amount (MUT)", &mut self.amount);
            }
            FormKind::DividendClaim => {
                field(ui, "License (hex)", &mut self.license);
                field(ui, "Award epoch", &mut self.award_epoch);
                field(ui, "Amount (MUT)", &mut self.amount);
                field(ui, "Pay to checksummed address", &mut self.destination);
            }
            FormKind::BondCreate => {
                field(ui, "Node (hex)", &mut self.node);
                field(ui, "Node generation", &mut self.node_generation);
                field(ui, "Principal (MUT)", &mut self.amount);
            }
            FormKind::BondUnbond | FormKind::BondWithdraw => {
                field(ui, "Lot (hex)", &mut self.lot);
            }
            FormKind::HashLock => {
                field(ui, "Maker offer (hex)", &mut self.offer);
                field(ui, "Recipient checksummed address", &mut self.recipient);
                field(ui, "Amount (MUT)", &mut self.amount);
                field(ui, "Condition (SHA-256, hex)", &mut self.condition);
                field(ui, "Refund height", &mut self.refund_height);
                field(ui, "Trade commitment (hex, optional)", &mut self.trade);
                field(
                    ui,
                    "Contract commitment (hex, optional)",
                    &mut self.contract,
                );
            }
            FormKind::ConditionalClaim | FormKind::ConditionalRefund => {
                field(ui, "Lock (hex)", &mut self.lock);
            }
            FormKind::LicenseDvp => {
                field(ui, "Maker offer (hex)", &mut self.offer);
                field(ui, "License (hex)", &mut self.license);
                field(ui, "Trade commitment (hex)", &mut self.trade);
                field(ui, "Contract commitment (hex)", &mut self.contract);
                field(
                    ui,
                    "Pay the price to (checksummed address, optional: seller)",
                    &mut self.destination,
                );
                field(
                    ui,
                    "Seller descriptor (hex, optional: only if the wallet book cannot name the seller)",
                    &mut self.descriptor,
                );
            }
            FormKind::FiatLock => {
                field(ui, "Maker offer (hex)", &mut self.offer);
                field(ui, "Buyer checksummed address", &mut self.buyer);
                field(ui, "Amount (MUT)", &mut self.amount);
                field(
                    ui,
                    "Payment terms commitment (hex)",
                    &mut self.payment_terms,
                );
                field(ui, "Trade commitment (hex, optional)", &mut self.trade);
                field(
                    ui,
                    "Contract commitment (hex, optional)",
                    &mut self.contract,
                );
                field(
                    ui,
                    "Buyer descriptor (hex, optional: only if the wallet book cannot name the buyer)",
                    &mut self.descriptor,
                );
            }
            FormKind::FiatRelease => {
                field(ui, "Fiat lock (hex)", &mut self.lock);
                field(
                    ui,
                    "Seller descriptor (hex, optional: only if the wallet book cannot name the seller)",
                    &mut self.descriptor,
                );
            }
        }
        if let Some(error) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, error);
        }
        let review = ui.button("Review");
        #[cfg(any(test, feature = "testvalue-window"))]
        {
            self.review_button = Some(review.rect);
        }
        #[cfg(feature = "testvalue-window")]
        self.native_targets
            .push(("button:Review".into(), review.rect));
        if review.clicked() {
            match self.build(kind) {
                Ok(output) => {
                    self.error = None;
                    return Some(output);
                }
                Err(error) => self.error = Some(error),
            }
        }
        None
    }
}

/// The wallet screens composed: a request form, then the generic review of the controller's plan,
/// then the outcome. Everything goes through the UI-free controller, which owns the key, the gate
/// and the queues; this widget only shows and forwards what the person did. The windowed shell
/// (which opens in test builds only while the production gate is closed) would hold one.
#[derive(Default)]
pub struct WalletUi {
    pub forms: Forms,
    panel: ReviewPanel,
    screen: Option<ReviewScreen>,
    pub message: Option<String>,
    branded: branded_ui::BrandedUi,
}

impl WalletUi {
    /// The wallet service's latest history line (B1 `Event::Sync`), shown on the overview beside the
    /// verified height; `None` when no history connection is attached.
    pub fn set_sync(&mut self, line: Option<String>) {
        self.branded.sync = line;
    }
    /// Previous native frame rectangles only: a rehearsal player must still generate actual
    /// egui input events and cannot directly synthesize controller review approvals.
    #[cfg(feature = "testvalue-window")]
    pub(crate) fn native_targets(&self) -> Vec<(String, egui::Rect)> {
        use crate::plan_review::Target;
        let mut targets = self.branded.targets.clone();
        if self.screen.is_some() {
            targets.extend(self.panel
                .targets
                .iter()
                .map(|(target, rect)| {
                    let key = match target {
                        Target::Destination(index) => format!("destination:{index}"),
                        Target::Ack(ack) => format!("ack:{ack:?}"),
                        Target::Phrase => "phrase".into(),
                        Target::Authorize => "button:Authorize".into(),
                        Target::Cancel => "button:Cancel".into(),
                    };
                    (key, *rect)
                })
                .collect::<Vec<_>>());
        } else {
            targets.extend(self.forms.native_targets.clone());
        }
        targets
    }
    /// Load the controller's actual review after a host-specific request (for example rotation).
    pub fn present_current(&mut self, wallet: &mut Controller) {
        match wallet.screen() {
            Ok(screen) => {
                self.screen = screen;
                if self.screen.is_none() { self.panel = ReviewPanel::default(); }
                self.message = None;
            }
            Err(error) => {
                self.screen = None;
                self.panel = ReviewPanel::default();
                self.message = Some(error);
            }
        }
    }
    pub fn show(&mut self, ui: &mut egui::Ui, wallet: &mut Controller) {
        self.show_scoped(ui, wallet, &FormKind::offered());
    }
    /// New native presentation seam; controller and review authority are unchanged.
    pub fn show_branded(&mut self, ui: &mut egui::Ui, wallet: &mut Controller) {
        if self.screen.is_some() { self.present_current(wallet); }
        #[cfg(feature = "testvalue-window")]
        { self.forms.native_targets.clear(); self.panel.targets.clear(); }
        let mut branded = std::mem::take(&mut self.branded);
        branded.show(ui, self, wallet);
        self.branded = branded;
    }
    /// The branded shell when no wallet can be opened; see `BrandedUi::show_unavailable`.
    pub fn show_branded_unavailable(&mut self, ui: &mut egui::Ui, rows: &[(&str, bool, String)]) {
        self.branded.show_unavailable(ui, rows);
    }
    fn discard_review(&mut self) {
        self.screen = None;
        self.panel = ReviewPanel::default();
        // Drop previous-frame targets whenever context or navigation invalidates their widgets.
        #[cfg(feature = "testvalue-window")]
        self.forms.native_targets.clear();
    }
    fn has_review(&self) -> bool { self.screen.is_some() }
    fn show_scoped(&mut self, ui: &mut egui::Ui, wallet: &mut Controller, kinds: &[FormKind]) {
        if self.screen.is_some() {
            self.present_current(wallet);
        }
        self.forms.address_class = wallet.with_view(|view| view.class()).ok();
        if let Some(message) = &self.message {
            ui.label(message);
            ui.separator();
        }
        if let Some(screen) = self.screen.clone() {
            for input in self.panel.show(ui, &screen) {
                self.apply(wallet, input);
            }
        } else if let Some(output) = self.forms.show_scoped(ui, kinds) {
            self.request(wallet, output);
        }
    }
    /// Plan what a form produced and put its review on screen (a claim takes its preimage from the
    /// controller's sealed preimage store).
    pub fn request(&mut self, wallet: &mut Controller, output: FormOutput) {
        let result = match output {
            FormOutput::MakerOffer {
                terms,
                side,
                destination,
                condition,
                max_fee,
                validity,
            } => (|| {
                let me = wallet
                    .signer_identity()
                    .ok_or("Unlock the wallet before creating a maker offer")?;
                let mut nonce = [0; 32];
                mutiny_crypto_v2::fill_os_random(&mut nonce)
                    .map_err(|_| "Offer nonce entropy unavailable")?;
                let body = wallet.with_view(|view| -> Result<_, String> {
                    if validity == 0 || validity > mutiny_consensus_v8::transactions::EXPIRY_HORIZON
                    {
                        return Err("Invalid finite offer window".into());
                    }
                    let maker_wallet = match &terms {
                        // A License's immutable owner address remains its settlement identity
                        // after rotation; core verifies this exact current descriptor for it.
                        mutiny_consensus_v8::trading_offer_v2::OfferTerms::License {
                            license,
                            ..
                        } if side == 0 => {
                            view.state()
                                .licenses_v2
                                .license(*license)
                                .ok_or("License does not exist on this chain")?
                                .owner
                        }
                        _ => me.address(),
                    };
                    let created = view.next_height().map_err(|e| e.to_string())?;
                    Ok(mutiny_consensus_v8::trading_offer_v2::OfferBody {
                        context: mutiny_consensus_v8::trading_v1::Context {
                            network: view.anchor().network,
                            genesis: view.anchor().genesis,
                            fingerprint: view.anchor().fingerprint,
                        },
                        maker_descriptor: me.descriptor().to_vec(),
                        maker_wallet,
                        maker_side: side,
                        nonce,
                        created,
                        expiry: created
                            .checked_add(validity)
                            .ok_or("Offer height overflow")?,
                        terms,
                        destination,
                        condition,
                        max_fee: mutiny_consensus_v8::trading_v1::Strikes(max_fee),
                    })
                })??;
                wallet.request(OperationRequest::MakerOffer(
                    mutiny_wallet_core_v8::MakerOfferRequest::new(Blob::new(
                        body.encode().map_err(|_| "Maker offer terms are invalid")?,
                    )),
                ))
            })(),
            FormOutput::Request(request) => wallet.request(*request),
            FormOutput::Claim(lock) => wallet
                .claim_request(lock)
                .and_then(|claim| wallet.request(OperationRequest::ConditionalClaim(claim))),
        };
        match result {
            Ok(screen) => {
                self.screen = Some(screen);
                self.message = None;
            }
            Err(error) => self.message = Some(error),
        }
    }
    fn apply(&mut self, wallet: &mut Controller, input: ReviewInput) {
        match wallet.review_input(input) {
            Ok(ReviewOutcome::Screen(screen)) => self.screen = Some(*screen),
            Ok(ReviewOutcome::Queued(queued)) => {
                self.screen = None;
                self.message = Some(if queued.complete {
                    format!(
                        "{}: signed and queued on this computer (not delivered, not settled): {}",
                        queued.kind.title(),
                        hex::encode(queued.id)
                    )
                } else {
                    format!(
                        "{}: this wallet's part is signed and queued on this computer; {} signature(s) are still missing: export the public partial for the other parties ({})",
                        queued.kind.title(),
                        queued.missing.len(),
                        hex::encode(queued.id)
                    )
                });
            }
            Ok(ReviewOutcome::Cancelled) => {
                self.screen = None;
                self.message = None;
            }
            Err(error) => {
                self.message = Some(error);
                self.screen = wallet.screen().ok().flatten();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::synthetic::descriptor;
    use crate::test_support::{
        BondWorld, conditional_kit,
        synthetic::{World, address, identity, key_a, key_b},
    };
    use mutiny_consensus_v8::trading_v1::{OfferBody, OfferTerms, SignedOffer, Strikes};
    use mutiny_wallet_core_v8::{Refusal, offers, plan};

    /// A maker offer signed by `maker` (the test plays the maker, Q7).
    fn signed_offer(
        maker: &mutiny_crypto_v2::HybridKey,
        anchor: &mutiny_consensus_v8::anchors::FinalizedAnchor,
        terms: OfferTerms,
        nonce: u8,
    ) -> Vec<u8> {
        let offer = SignedOffer::sign(
            OfferBody {
                context: conditional_kit::context_of(anchor),
                maker_descriptor: maker.public().descriptor(1).unwrap(),
                maker_wallet: maker.public().address_id(1).unwrap(),
                destination: maker.public().address_id(1).unwrap(),
                condition: None,
                max_fee: Strikes(100_000),
                nonce: [nonce; 32],
                created: 90,
                expiry: 200,
                maker_side: 0,
                terms,
            },
            maker,
        )
        .unwrap();
        offers::encode_offer(&offer).unwrap()
    }

    fn test_address(hash: Hash) -> String {
        mutiny_wallet_core_v8::address_format::encode(
            &hash,
            mutiny_wallet_core_v8::ChainClass::TestValue,
        )
    }

    fn request_of(output: FormOutput) -> OperationRequest {
        match output {
            FormOutput::Request(request) => *request,
            FormOutput::Claim(_) => panic!("a request was expected"),
            FormOutput::MakerOffer { .. } => panic!("a direct request was expected"),
        }
    }

    #[test]
    fn only_kinds_with_a_handler_are_offered_and_never_a_treasury_kind() {
        let offered = FormKind::offered();
        let implemented = implemented_kinds();
        assert!(!offered.is_empty());
        for kind in &offered {
            assert!(implemented.contains(&kind.operation()));
        }
        // Every implemented kind has a form here except the rotation (its own two-key flow) and the
        // Treasury kinds (never selectable from the UI, whether or not their handlers are merged).
        for kind in implemented {
            assert!(
                matches!(
                    kind,
                    OperationKind::WalletRotation
                        | OperationKind::TreasuryRotate
                        | OperationKind::TreasuryFreezeOffer
                ) || offered.iter().any(|form| form.operation() == kind),
                "{kind:?} has a handler but no form"
            );
        }
        for kind in [
            OperationKind::TreasuryRotate,
            OperationKind::TreasuryFreezeOffer,
        ] {
            assert!(!offered.iter().any(|form| form.operation() == kind));
        }
        // The rendered selector names exactly the offered kinds.
        let ctx = egui::Context::default();
        let mut forms = Forms::default();
        let output = ctx.run_ui(Default::default(), |ui| {
            assert!(forms.show(ui).is_none());
        });
        let mut texts = Vec::new();
        for clipped in &output.shapes {
            if let egui::Shape::Text(text) = &clipped.shape {
                texts.push(text.galley.text().to_string());
            }
        }
        output.drop_without_applying_deltas();
        for kind in OperationKind::ALL {
            let shown = texts.iter().any(|t| t == kind.title());
            assert_eq!(
                shown,
                offered.iter().any(|form| form.operation() == kind),
                "{kind:?}"
            );
        }
    }

    /// Nonshipping target capture: genuine egui clicks change only the maker terms
    /// selector; rendering/clicks do not create a review, sign or submit anything.
    #[cfg(feature = "testvalue-window")]
    #[test]
    fn maker_terms_native_targets_follow_actual_raw_widget_switches() {
        let mut forms = Forms::default();
        forms.kind = Some(FormKind::MakerOffer);
        forms.amount = "1".into();
        forms.destination = "unchanged public form text".into();
        let mut driver = crate::test_support::UiDriver::new();
        for _ in 0..3 {
            driver.frame(Vec::new(), |ui| assert!(forms.show(ui).is_none()));
        }
        let target = |forms: &Forms, name: &str| {
            let found = forms.native_targets.iter().filter(|(n, _)| n == name)
                .map(|(_, r)| *r).collect::<Vec<_>>();
            assert_eq!(found.len(), 1, "exact actual widget target {name}");
            let rect = found[0];
            assert!(rect.min.x.is_finite() && rect.min.y.is_finite()
                && rect.max.x.is_finite() && rect.max.y.is_finite()
                && rect.width() > 0.0 && rect.height() > 0.0);
            rect.center()
        };
        assert_eq!(forms.maker_terms, 0);
        target(&forms, "field:Bitcoin satoshi terms (metadata only)");
        for (code, label, field) in [
            (1, "License", "field:License (hex)"),
            (2, "Fiat", "field:Payment terms commitment (hex)"),
            (0, "Hash-linked", "field:Bitcoin satoshi terms (metadata only)"),
        ] {
            let pos = target(&forms, &format!("maker-terms:{label}"));
            driver.click(pos, |ui| assert!(forms.show(ui).is_none()));
            driver.frame(Vec::new(), |ui| assert!(forms.show(ui).is_none()));
            assert_eq!(forms.maker_terms, code, "actual selectable widget callback");
            target(&forms, field);
            target(&forms, "field:Amount/price (MUT)");
            target(&forms, "button:Review");
            assert_eq!(forms.amount, "1");
            assert_eq!(forms.destination, "unchanged public form text");
            assert!(forms.error.is_none());
        }
    }

    #[test]
    fn forms_check_syntax_and_build_exactly_the_typed_request() {
        let recipient = address(&key_b(), 1);
        let mut forms = Forms {
            address_class: Some(mutiny_wallet_core_v8::ChainClass::TestValue),
            recipient: test_address(recipient),
            amount: "0.01".into(),
            ..Default::default()
        };
        let OperationRequest::Payment(payment) =
            request_of(forms.build(FormKind::Payment).unwrap())
        else {
            panic!("payment expected");
        };
        assert_eq!(
            (payment.recipient, payment.amount_atoms),
            (recipient, 1_000_000)
        );
        for (recipient, amount) in [
            ("00", "1"),
            (&"zz".repeat(32)[..], "1"),
            (&hex::encode(recipient)[..], "1.000000001"),
            (&hex::encode(recipient)[..], "-1"),
            (&hex::encode(recipient)[..], ""),
        ] {
            forms.recipient = recipient.into();
            forms.amount = amount.into();
            assert!(
                forms.build(FormKind::Payment).is_err(),
                "{recipient} {amount}"
            );
        }
        // Bond creation: a fresh, non-zero nonce every time.
        let forms = Forms {
            address_class: Some(mutiny_wallet_core_v8::ChainClass::TestValue),
            node: hex::encode([7; 32]),
            node_generation: "1".into(),
            amount: "150".into(),
            ..Default::default()
        };
        let nonce = |forms: &Forms| match request_of(forms.build(FormKind::BondCreate).unwrap()) {
            OperationRequest::BondCreate(create) => {
                assert_eq!(
                    (create.node, create.node_generation, create.amount_atoms),
                    ([7; 32], 1, 15_000_000_000)
                );
                create.nonce
            }
            _ => panic!("bond creation expected"),
        };
        let (first, second) = (nonce(&forms), nonce(&forms));
        assert!(first != [0; 32] && first != second);
        // Claim: the lock only; the controller adds the preimage from its own store.
        let forms = Forms {
            address_class: Some(mutiny_wallet_core_v8::ChainClass::TestValue),
            lock: hex::encode([0x6c; 32]),
            ..Default::default()
        };
        assert!(matches!(
            forms.build(FormKind::ConditionalClaim).unwrap(),
            FormOutput::Claim(lock) if lock == [0x6c; 32]
        ));
        let OperationRequest::ConditionalRefund(refund) =
            request_of(forms.build(FormKind::ConditionalRefund).unwrap())
        else {
            panic!("refund expected");
        };
        assert_eq!(refund.lock, [0x6c; 32]);
        assert!(parse_number("x", "1e3").is_err() && parse_number("x", " 7 ").unwrap() == 7);
        // License sale: both commitments are required (consensus refuses zero ones), the payment
        // destination and the seller's descriptor are optional.
        let mut forms = Forms {
            address_class: Some(mutiny_wallet_core_v8::ChainClass::TestValue),
            offer: hex::encode([0xab; 40]),
            license: hex::encode([0x4c; 32]),
            trade: hex::encode([0x73; 32]),
            contract: hex::encode([0x74; 32]),
            ..Default::default()
        };
        let OperationRequest::LicenseDvp(sale) =
            request_of(forms.build(FormKind::LicenseDvp).unwrap())
        else {
            panic!("License sale expected");
        };
        assert_eq!(
            (
                sale.offer.as_slice(),
                sale.license,
                sale.trade,
                sale.contract
            ),
            (&[0xab; 40][..], [0x4c; 32], [0x73; 32], [0x74; 32])
        );
        assert!(sale.payment_destination.is_none() && sale.seller_descriptor.is_empty());
        forms.destination = test_address([0x5d; 32]);
        forms.descriptor = hex::encode([0x0d; 64]);
        let OperationRequest::LicenseDvp(sale) =
            request_of(forms.build(FormKind::LicenseDvp).unwrap())
        else {
            panic!("License sale expected");
        };
        assert_eq!(sale.payment_destination, Some([0x5d; 32]));
        assert_eq!(sale.seller_descriptor.as_slice(), &[0x0d; 64][..]);
        forms.contract.clear();
        assert!(
            forms.build(FormKind::LicenseDvp).is_err(),
            "the ContractHash is required"
        );
        // Fiat lock: the payment terms are required, the commitments optional.
        let mut forms = Forms {
            address_class: Some(mutiny_wallet_core_v8::ChainClass::TestValue),
            offer: hex::encode([0xab; 40]),
            buyer: test_address([0x42; 32]),
            amount: "0.02".into(),
            payment_terms: hex::encode([0x77; 32]),
            ..Default::default()
        };
        let OperationRequest::FiatLock(lock) = request_of(forms.build(FormKind::FiatLock).unwrap())
        else {
            panic!("fiat lock expected");
        };
        assert_eq!(
            (
                lock.buyer,
                lock.amount_atoms,
                lock.payment_terms,
                lock.trade,
                lock.contract
            ),
            ([0x42; 32], 2_000_000, [0x77; 32], [0; 32], [0; 32])
        );
        assert!(lock.buyer_descriptor.is_empty());
        forms.trade = hex::encode([0x73; 32]);
        let OperationRequest::FiatLock(lock) = request_of(forms.build(FormKind::FiatLock).unwrap())
        else {
            panic!("fiat lock expected");
        };
        assert_eq!((lock.trade, lock.contract), ([0x73; 32], [0; 32]));
        forms.payment_terms.clear();
        assert!(
            forms.build(FormKind::FiatLock).is_err(),
            "the payment terms are required"
        );
        // Fiat release: the lock; the seller's descriptor only when given, and then as hex.
        let mut forms = Forms {
            address_class: Some(mutiny_wallet_core_v8::ChainClass::TestValue),
            lock: hex::encode([0x6c; 32]),
            ..Default::default()
        };
        let OperationRequest::FiatRelease(release) =
            request_of(forms.build(FormKind::FiatRelease).unwrap())
        else {
            panic!("fiat release expected");
        };
        assert!(release.lock == [0x6c; 32] && release.seller_descriptor.is_empty());
        forms.descriptor = "zz".into();
        assert!(forms.build(FormKind::FiatRelease).is_err());
        // Another kind's form starts empty; selecting the form on screen again keeps what was typed.
        let mut forms = Forms::default();
        forms.select(FormKind::FiatRelease);
        forms.lock = hex::encode([0x6c; 32]);
        forms.descriptor = hex::encode([0x0d; 64]);
        forms.select(FormKind::FiatRelease);
        assert_eq!(forms.lock, hex::encode([0x6c; 32]));
        forms.select(FormKind::Payment);
        assert!(
            forms.kind == Some(FormKind::Payment)
                && forms.lock.is_empty()
                && forms.descriptor.is_empty()
        );
    }

    /// Each form's request reaches its own wallet-core handler: planned (and therefore reviewable)
    /// where the synthetic chain allows it, refused with that handler's own code where it does not.
    #[test]
    fn every_form_reaches_its_wallet_core_handler() {
        let me = identity(&key_a());
        // Payment.
        let mut world = World::with_wallets(100);
        world.coin(address(&key_a(), 1), 5_000_000, 1, false, 1, 0);
        let forms = Forms {
            address_class: Some(mutiny_wallet_core_v8::ChainClass::TestValue),
            recipient: test_address(address(&key_b(), 1)),
            amount: "0.01".into(),
            ..Default::default()
        };
        let planned = plan(
            &request_of(forms.build(FormKind::Payment).unwrap()),
            &world.view(),
            &me,
        )
        .unwrap();
        assert_eq!(planned.kind(), OperationKind::Payment);
        // Dividend claim on a chain without dividends: the dividend handler's own refusal.
        let forms = Forms {
            address_class: Some(mutiny_wallet_core_v8::ChainClass::TestValue),
            license: hex::encode([5; 32]),
            award_epoch: "1440".into(),
            amount: "1".into(),
            destination: test_address(me.address()),
            ..Default::default()
        };
        assert_eq!(
            plan(
                &request_of(forms.build(FormKind::DividendClaim).unwrap()),
                &world.view(),
                &me
            )
            .unwrap_err(),
            Refusal::DividendInactive
        );
        // Bond creation, unbond and withdrawal on the fixture node.
        let mut bonds = BondWorld::new(100);
        bonds.coin(me.address(), 30_000_000_000, 0x31);
        let forms = Forms {
            address_class: Some(mutiny_wallet_core_v8::ChainClass::TestValue),
            node: hex::encode(bonds.node()),
            node_generation: "1".into(),
            amount: "150".into(),
            ..Default::default()
        };
        let planned = plan(
            &request_of(forms.build(FormKind::BondCreate).unwrap()),
            &bonds.view(),
            &me,
        )
        .unwrap();
        assert_eq!(planned.kind(), OperationKind::BondCreate);
        let lot = bonds.active_lot(0x51, me.address(), 15_000_000_000, 10);
        let forms = Forms {
            address_class: Some(mutiny_wallet_core_v8::ChainClass::TestValue),
            lot: hex::encode(lot),
            ..Default::default()
        };
        let planned = plan(
            &request_of(forms.build(FormKind::BondUnbond).unwrap()),
            &bonds.view(),
            &me,
        )
        .unwrap();
        assert_eq!(planned.kind(), OperationKind::BondUnbond);
        assert!(
            matches!(
                plan(
                    &request_of(forms.build(FormKind::BondWithdraw).unwrap()),
                    &bonds.view(),
                    &me
                ),
                Err(Refusal::LotNotUnbonding("active"))
            ),
            "an Active lot is not withdrawn"
        );
        // Hash lock from an imported maker offer (the maker is played by the test, Q7).
        let maker = conditional_kit::maker_key();
        let offer = conditional_kit::signed_offer(
            &maker,
            conditional_kit::context_of(&world.anchor),
            90,
            200,
            1_000_000,
            1,
            1,
        );
        let forms = Forms {
            address_class: Some(mutiny_wallet_core_v8::ChainClass::TestValue),
            offer: hex::encode(conditional_kit::offer_bytes(&offer)),
            recipient: test_address(address(&key_b(), 1)),
            amount: "0.01".into(),
            condition: hex::encode([0x33; 32]),
            refund_height: "150".into(),
            ..Default::default()
        };
        let planned = plan(
            &request_of(forms.build(FormKind::HashLock).unwrap()),
            &world.view(),
            &me,
        )
        .unwrap();
        assert_eq!(planned.kind(), OperationKind::HashLock);
        // Refund of a lock that does not exist: the conditional handler's own refusal.
        let forms = Forms {
            address_class: Some(mutiny_wallet_core_v8::ChainClass::TestValue),
            lock: hex::encode([0x6c; 32]),
            ..Default::default()
        };
        assert_eq!(
            plan(
                &request_of(forms.build(FormKind::ConditionalRefund).unwrap()),
                &world.view(),
                &me
            )
            .unwrap_err(),
            Refusal::LockNotFound
        );
        // License sale of a License this chain does not have: the offer is imported and verified,
        // then the License handler refuses with its own reason.
        let forms = Forms {
            address_class: Some(mutiny_wallet_core_v8::ChainClass::TestValue),
            offer: hex::encode(signed_offer(
                &key_a(),
                &world.anchor,
                OfferTerms::License {
                    license: [0x4c; 32],
                    generation: 1,
                    price: Strikes(1_000_000),
                },
                0x31,
            )),
            license: hex::encode([0x4c; 32]),
            trade: hex::encode([0x73; 32]),
            contract: hex::encode([0x74; 32]),
            ..Default::default()
        };
        assert_eq!(
            plan(
                &request_of(forms.build(FormKind::LicenseDvp).unwrap()),
                &world.view(),
                &me
            )
            .unwrap_err(),
            Refusal::InvalidRequest("the License does not exist on this chain")
        );
        // Fiat lock: this wallet (the seller) funds it for the buyer, whose public descriptor the
        // form carries because the synthetic wallet book cannot name the buyer.
        let forms = Forms {
            address_class: Some(mutiny_wallet_core_v8::ChainClass::TestValue),
            offer: hex::encode(signed_offer(
                &key_a(),
                &world.anchor,
                OfferTerms::Fiat {
                    amount: Strikes(1_000_000),
                    payment_terms: [0x77; 32],
                },
                0x41,
            )),
            buyer: test_address(address(&key_b(), 1)),
            amount: "0.01".into(),
            payment_terms: hex::encode([0x77; 32]),
            descriptor: hex::encode(descriptor(&key_b(), 1)),
            ..Default::default()
        };
        let planned = plan(
            &request_of(forms.build(FormKind::FiatLock).unwrap()),
            &world.view(),
            &me,
        )
        .unwrap();
        assert_eq!(planned.kind(), OperationKind::FiatLock);
        // Fiat release of a lock that does not exist: the fiat handler's own refusal.
        let forms = Forms {
            address_class: Some(mutiny_wallet_core_v8::ChainClass::TestValue),
            lock: hex::encode([0x6c; 32]),
            ..Default::default()
        };
        assert!(matches!(
            plan(
                &request_of(forms.build(FormKind::FiatRelease).unwrap()),
                &world.view(),
                &me
            ),
            Err(Refusal::LockNotFound)
        ));
    }

    /// The composed screens through the real controller, driven by synthetic pointer and keyboard
    /// input: rendering alone requests and signs nothing; the payment form's Review plans and
    /// presents; the typed check, every acknowledgement and Authorize queue the payment durably.
    #[test]
    fn the_composed_screens_take_a_payment_from_its_form_to_the_queue() {
        use crate::{
            plan_review::Target,
            test_support::{TestDir, UiDriver},
            wallet_controller_v2::tests::{PASSWORD, fixture},
        };
        let base = TestDir::new("w7-wallet-ui");
        let (mut wallet, _, _) = fixture(&base);
        wallet.unlock(PASSWORD).unwrap();
        let mut screens = WalletUi::default();
        screens.forms.kind = Some(FormKind::Payment);
        screens.forms.recipient = wallet
            .with_view(|view| mutiny_wallet_core_v8::address_format::encode_for(&[94; 32], view))
            .unwrap();
        screens.forms.amount = "0.0005".into();
        let mut driver = UiDriver::new();
        for _ in 0..3 {
            driver.frame(Vec::new(), |ui| screens.show(ui, &mut wallet));
        }
        assert!(screens.screen.is_none() && screens.message.is_none());
        let pos = screens.forms.review_button.unwrap().center();
        driver.click(pos, |ui| screens.show(ui, &mut wallet));
        let screen = screens.screen.clone().expect("the review is on screen");
        assert_eq!(screen.review.kind(), OperationKind::Payment);
        driver.frame(Vec::new(), |ui| screens.show(ui, &mut wallet));
        let target = |screens: &WalletUi, target: Target| {
            screens
                .panel
                .targets
                .iter()
                .find(|(t, _)| *t == target)
                .unwrap()
                .1
                .center()
        };
        for index in screen.review.destinations_needing_check() {
            let typed = screen.review.destination_check_text(index);
            let pos = target(&screens, Target::Destination(index));
            driver.type_text(pos, &typed, |ui| screens.show(ui, &mut wallet));
        }
        for ack in screen.review.acknowledgements() {
            driver.frame(Vec::new(), |ui| screens.show(ui, &mut wallet));
            let pos = target(&screens, Target::Ack(*ack));
            driver.click(pos, |ui| screens.show(ui, &mut wallet));
        }
        driver.frame(Vec::new(), |ui| screens.show(ui, &mut wallet));
        assert!(
            screens.panel.authorize_enabled,
            "{:?}",
            screens.screen.as_ref().map(|s| &s.status)
        );
        assert!(wallet.pending_for_transport().unwrap().is_empty());
        let pos = target(&screens, Target::Authorize);
        driver.click(pos, |ui| screens.show(ui, &mut wallet));
        assert!(screens.screen.is_none());
        assert!(
            screens
                .message
                .as_deref()
                .unwrap()
                .contains("queued on this computer"),
            "{:?}",
            screens.message
        );
        assert_eq!(wallet.pending_for_transport().unwrap().len(), 1);
    }
}
