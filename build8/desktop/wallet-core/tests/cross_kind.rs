//! Cross-kind properties of the whole crate (phase 8, W5 self-review): every one of the sixteen
//! kinds has a handler; every reservation namespace a handler uses is registered, the namespaces
//! are distinct and each names one kind of resource (checked over every `resource_key` call site);
//! an approval never authorizes a plan of another kind, a signer never signs a kind it is not for,
//! and bytes of one kind labelled as another are refused; the two offer-import paths (phase 5A's
//! hash lock and phase 5B's offers, now one decoder) accept and reject the same bytes; the test-gate
//! items phase 8 added sit behind the non-shipping cfg. (That no two handlers recognise the same
//! bytes is checked for every kind on the real chain of `e2e_matrix.rs`.)
//! NATIVE, TEST-VALUE; public test keys; the maker is played by the test (Q7).
// Each kit includes the shared `support/flow.rs`; this file includes two kits and the flow.
#![allow(clippy::duplicate_mod)]
#[path = "support/conditional_kit.rs"]
mod ckit;
#[path = "support/flow.rs"]
mod flow;
#[path = "support/synthetic.rs"]
mod synthetic;
#[path = "support/trading_5b.rs"]
mod trading;

use mutiny_consensus_v8::{
    trading_v1::{Context as TradeContext, SignedOffer},
    transactions::OutPoint,
};
use mutiny_crypto_v2::{HybridKey, Role, rehearsal_keys_v1};
use mutiny_wallet_core_v8::{
    ops::{
        self, conditional,
        rotation::{self, RotationSigner},
    },
    outbox::RESOURCE_NAMESPACES,
    *,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use synthetic::{World, address, identity, key_a, key_b};

fn new_key(label: &str) -> HybridKey {
    let phrase = rehearsal_keys_v1::label_phrase(label).unwrap();
    HybridKey::wallet_restore(&phrase, Role::WalletOwner).unwrap()
}

fn source_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            source_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// A source file without its unit-test module (everything after `#[cfg(test)]` is test-only).
fn production_part(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap().replace('\r', "");
    match text.lines().position(|line| line == "#[cfg(test)]") {
        Some(at) => text.lines().take(at).collect::<Vec<_>>().join("\n"),
        None => text,
    }
}

#[test]
fn every_one_of_the_sixteen_kinds_has_a_handler() {
    assert_eq!(OperationKind::ALL.len(), 16);
    assert_eq!(OperationKind::MakerOffer.code(), 15);
    assert_eq!(OperationKind::WorkerAssignment.code(), 16);
    assert_eq!(OperationKind::ALL.into_iter().map(OperationKind::code)
        .collect::<BTreeSet<_>>().len(), 16, "no reused wallet-local kind code");
    assert_eq!(ops::implemented_kinds(), OperationKind::ALL.to_vec());
}

#[test]
fn every_reservation_namespace_is_registered_distinct_and_names_one_kind_of_resource() {
    // Distinct namespaces, distinct resources, distinct keys for one identifier.
    let names: BTreeSet<&str> = RESOURCE_NAMESPACES.iter().map(|(name, _)| *name).collect();
    assert_eq!(names.len(), RESOURCE_NAMESPACES.len(), "a namespace twice");
    let resources: BTreeSet<&str> = RESOURCE_NAMESPACES.iter().map(|(_, what)| *what).collect();
    assert_eq!(
        resources.len(),
        RESOURCE_NAMESPACES.len(),
        "a resource twice"
    );
    let keys: BTreeSet<OutPoint> = RESOURCE_NAMESPACES
        .iter()
        .map(|(name, _)| resource_key(name, &[7; 32]))
        .collect();
    assert_eq!(keys.len(), RESOURCE_NAMESPACES.len());
    assert!(keys.iter().all(|key| key.index == u32::MAX), "never a coin");

    // Every `resource_key` call of every handler passes a registered namespace constant, and every
    // registered namespace is used.
    let mut files = Vec::new();
    source_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let mut constants: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut arguments: Vec<(String, String)> = Vec::new();
    for file in &files {
        let name = file.file_name().unwrap().to_string_lossy().to_string();
        let code = production_part(file);
        for line in code.lines() {
            let line = line.trim_start();
            let line = line
                .strip_prefix("pub(crate) ")
                .or_else(|| line.strip_prefix("pub "))
                .unwrap_or(line);
            if let Some(rest) = line.strip_prefix("const ")
                && let Some((constant, value)) = rest.split_once(": &str = \"")
            {
                let value = value.trim_end_matches("\";").to_string();
                constants
                    .entry(constant.to_string())
                    .or_default()
                    .insert(value);
            }
        }
        for (at, _) in code.match_indices("resource_key(") {
            let line_start = code[..at].rfind('\n').map_or(0, |n| n + 1);
            let line = code[line_start..at].trim_start();
            if line.starts_with("//") || line.ends_with("fn ") {
                continue;
            }
            let rest = &code[at + "resource_key(".len()..];
            let argument: String = rest.chars().take_while(|c| *c != ',').collect();
            arguments.push((name.clone(), argument.trim().to_string()));
        }
    }
    assert!(arguments.len() >= 10, "{arguments:?}");
    let mut used = BTreeSet::new();
    for (file, argument) in &arguments {
        assert!(
            !argument.starts_with('"'),
            "{file}: a literal namespace {argument}"
        );
        let constant = argument.rsplit("::").next().unwrap();
        let values = constants
            .get(constant)
            .unwrap_or_else(|| panic!("{file}: {argument} is not a string constant"));
        assert_eq!(values.len(), 1, "{constant} has several values: {values:?}");
        let value = values.iter().next().unwrap();
        assert!(
            names.contains(value.as_str()),
            "{file}: namespace {value:?} is not registered in RESOURCE_NAMESPACES"
        );
        used.insert(value.clone());
    }
    assert_eq!(
        used,
        names.iter().map(|name| name.to_string()).collect(),
        "every registered namespace is used by a handler"
    );
}

/// Head 100: key A holds two coins; the plans of three kinds the tests below cross.
struct Scene {
    world: World,
    maker: HybridKey,
    offer: SignedOffer,
}

fn scene() -> Scene {
    let mut world = World::with_wallets(100);
    world.coin(address(&key_a(), 1), 5_000_000, 1, false, 1, 0);
    world.coin(address(&key_a(), 1), 3_000_000, 1, false, 2, 0);
    let maker = ckit::maker_key();
    let offer = ckit::signed_offer(
        &maker,
        ckit::context_of(&world.anchor),
        1,
        1000,
        1_000_000,
        1,
        6,
    );
    Scene {
        world,
        maker,
        offer,
    }
}

fn payment_request() -> OperationRequest {
    OperationRequest::Payment(PaymentRequest::new(address(&key_b(), 1), 1_000_000))
}

fn rotation_request() -> OperationRequest {
    let proposed = new_key("w8-cross-kind-new").public().descriptor(2).unwrap();
    OperationRequest::WalletRotation(
        RotationRequest::new(Blob::new(proposed.clone()), FeeSource::RotatingAuthority)
            .with_restore_verified(rotation::descriptor_fingerprint(&proposed)),
    )
}

fn lock_request(offer: &SignedOffer) -> OperationRequest {
    OperationRequest::HashLock(HashLockRequest::new(
        Blob::new(ckit::offer_bytes(offer)),
        address(&key_b(), 1),
        1_000_000,
        [9; 32],
        150,
    ))
}

#[test]
fn an_approval_never_authorizes_a_plan_of_another_kind_and_a_signer_signs_only_its_kinds() {
    let scene = scene();
    let view = scene.world.view();
    let me = identity(&key_a());
    let requests = [
        payment_request(),
        rotation_request(),
        lock_request(&scene.offer),
    ];
    let plans: Vec<OperationPlan> = requests
        .iter()
        .map(|request| plan(request, &view, &me).unwrap())
        .collect();
    let kinds: Vec<OperationKind> = plans.iter().map(OperationPlan::kind).collect();
    assert_eq!(
        kinds,
        [
            OperationKind::Payment,
            OperationKind::WalletRotation,
            OperationKind::HashLock
        ]
    );
    let key_signer = KeySigner::for_test(key_a()).unwrap();
    let rotation_signer =
        RotationSigner::for_test(key_a(), me.clone(), new_key("w8-cross-kind-new")).unwrap();
    // An approval given for one kind's review, presented with a plan of another kind, is refused
    // before anything is signed (the approval binds the kind, the digest and the scope).
    for (approved, plan_of) in [(0, 1), (0, 2), (1, 0), (1, 2), (2, 0), (2, 1)] {
        let approval = flow::approve(&review(&plans[approved], &view).unwrap(), &view);
        let refusal = if kinds[plan_of] == OperationKind::WalletRotation {
            rotation_signer
                .authorize(plans[plan_of].clone(), approval, &view)
                .unwrap_err()
        } else {
            key_signer
                .authorize(plans[plan_of].clone(), approval, &view)
                .unwrap_err()
        };
        assert_eq!(
            refusal,
            Refusal::PlanChanged,
            "{:?} approval, {:?} plan",
            kinds[approved],
            kinds[plan_of]
        );
    }
    // With its own approval: the one-key signer cannot sign a rotation (it holds no new key) and a
    // rotation session refuses every other kind.
    let own = |index: usize| flow::approve(&review(&plans[index], &view).unwrap(), &view);
    assert!(
        key_signer
            .authorize(plans[1].clone(), own(1), &view)
            .is_err()
    );
    for index in [0, 2] {
        assert_eq!(
            rotation_signer
                .authorize(plans[index].clone(), own(index), &view)
                .unwrap_err(),
            Refusal::InvalidRequest(rotation::REASON_SESSION_KIND)
        );
    }
    // Each signs its own kind.
    let payment = key_signer
        .authorize(plans[0].clone(), own(0), &view)
        .unwrap();
    let rotated = rotation_signer
        .authorize(plans[1].clone(), own(1), &view)
        .unwrap();
    let locked = key_signer
        .authorize(plans[2].clone(), own(2), &view)
        .unwrap();
    // Bytes of one kind labelled as another: refused by every outbox, whatever the label.
    for signed in [&payment, &rotated, &locked] {
        for label in OperationKind::ALL {
            if label == signed.kind() {
                continue;
            }
            let relabelled = match signed.clone() {
                SignedOperation::Complete {
                    id,
                    bytes,
                    validity,
                    reserved,
                    ..
                } => SignedOperation::Complete {
                    kind: label,
                    id,
                    bytes,
                    validity,
                    reserved,
                },
                SignedOperation::Partial {
                    id,
                    bytes,
                    missing,
                    validity,
                    reserved,
                    ..
                } => SignedOperation::Partial {
                    kind: label,
                    id,
                    bytes,
                    missing,
                    validity,
                    reserved,
                },
            };
            let mut outbox = MemoryOutbox::new();
            assert!(
                outbox.commit(&relabelled, &view).is_err(),
                "{:?} bytes labelled {label:?}",
                signed.kind()
            );
            assert!(outbox.records().unwrap().is_empty());
        }
        // The bytes themselves are recognised as their own kind only.
        assert_eq!(
            ops::recognizing_kinds_for_test(signed.bytes()),
            vec![signed.kind()]
        );
        assert_eq!(
            SignedOperation::import(signed.bytes(), &view)
                .unwrap()
                .kind(),
            signed.kind()
        );
    }
}

#[test]
fn the_hash_lock_and_the_offer_import_paths_accept_and_reject_the_same_bytes() {
    let scene = scene();
    let view = scene.world.view();
    let offer = &scene.offer;
    // Both current helpers export the same canonical SignedOffer. The former zero-fill
    // OfferProof import form is explicitly rejected below rather than treated as a second format.
    let container = trading::offer_bytes(offer);
    let proof_form = ckit::offer_bytes(offer);
    assert_eq!(container, proof_form);
    for raw in [&container, &proof_form] {
        let hashed = conditional::import_offer(raw, &view).unwrap();
        let imported = offers::import_offer(raw, &view).unwrap();
        assert_eq!((hashed.id, hashed.maker), (imported.id(), imported.maker()));
        assert_eq!(imported.signed_offer(), offer);
        assert_eq!(
            imported.encode(),
            container,
            "the canonical container either way"
        );
    }
    // Both helper exports plan the same hash lock (the plan holds the decoded offer).
    let me = identity(&key_a());
    let with = |raw: &[u8]| {
        OperationRequest::HashLock(HashLockRequest::new(
            Blob::new(raw.to_vec()),
            address(&key_b(), 1),
            1_000_000,
            [9; 32],
            150,
        ))
    };
    assert_eq!(
        plan(&with(&container), &view, &me).unwrap().objects(),
        plan(&with(&proof_form), &view, &me).unwrap().objects()
    );
    // Every truncation, extension and a dense set of bit flips of either form: one verdict.
    let verdict = |raw: &[u8]| {
        let hashed = conditional::import_offer(raw, &view).is_ok();
        let imported = offers::import_offer(raw, &view).is_ok();
        assert_eq!(
            hashed,
            imported,
            "the paths disagree on {} bytes",
            raw.len()
        );
        hashed
    };
    for form in [&container, &proof_form] {
        assert!(verdict(form));
        for cut in 0..form.len() {
            assert!(!verdict(&form[..cut]), "prefix {cut}");
        }
        for extra in [1usize, 2, 9] {
            let mut longer = form.clone();
            longer.extend(std::iter::repeat_n(0u8, extra));
            assert!(!verdict(&longer));
        }
        // Every bit of the header and the offer body; every bit of every 13th signature byte.
        for index in (0..form.len()).filter(|index| *index < 220 || index % 13 == 0) {
            for bit in 0..8 {
                let mut damaged = form.clone();
                damaged[index] ^= 1 << bit;
                assert!(!verdict(&damaged), "byte {index} bit {bit}");
            }
        }
    }
    // The obsolete zero-fill container, a filled proof, bare body and another chain
    // are refused by both paths. Preserve the original hostile-container coverage.
    let zero_fill = mutiny_consensus_v8::trading_v1::OfferProof {
        offer: offer.clone(), fill_signature: ckit::zero(),
    }.encode().unwrap();
    assert!(!verdict(&zero_fill));
    let filled = {
        let unsigned = plan(&with(&container), &view, &me).unwrap();
        ckit::fill_for(&unsigned.objects()[0].bytes, offer, &scene.maker)
    };
    assert!(!verdict(&filled));
    assert!(!verdict(&offer.body.encode().unwrap()));
    let foreign = ckit::signed_offer(
        &scene.maker,
        TradeContext {
            genesis: [9; 32],
            ..ckit::context_of(&scene.world.anchor)
        },
        1,
        1000,
        1_000_000,
        1,
        6,
    );
    for raw in [trading::offer_bytes(&foreign), ckit::offer_bytes(&foreign)] {
        assert!(!verdict(&raw));
    }
    // The ONE difference is the terms check of the hash-lock handler, which plans only hash-linked
    // offers (the sale and fiat handlers check their terms when they use the offer). Since W19 its
    // refusal is the one every planner gives for an offer of another kind (before:
    // OFFER_PROOF_INVALID).
    let license = trading::offer(
        &scene.maker,
        ckit::context_of(&scene.world.anchor),
        trading::license_terms([1; 32], 1, 5),
        1,
        1000,
        0,
        7,
    );
    for raw in [trading::offer_bytes(&license), ckit::offer_bytes(&license)] {
        assert_eq!(
            conditional::import_offer(&raw, &view).unwrap_err(),
            Refusal::InvalidRequest("the offer's terms are for another kind of operation")
        );
        assert!(offers::import_offer(&raw, &view).is_ok());
    }
    // Bytes in neither form: ONE refusal on every path since W19 (before, OFFER_PROOF_INVALID on the
    // hash-lock path and MALFORMED on the offers path).
    assert_eq!(
        conditional::import_offer(&container[..10], &view).unwrap_err(),
        offers::import_offer(&container[..10], &view).unwrap_err()
    );
    assert!(matches!(
        offers::import_offer(&container[..10], &view).unwrap_err(),
        Refusal::Malformed(_)
    ));
}

#[test]
fn the_test_gate_items_added_in_phase_8_are_behind_the_non_shipping_cfg() {
    const CFG: &str = "#[cfg(any(test, feature = \"test-value-signing\"))]";
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for (file, needle) in [
        ("ops/mod.rs", "pub fn recognizing_kinds_for_test("),
        ("outbox_sqlite.rs", "pub fn observe_replacement_for_test("),
    ] {
        let text = std::fs::read_to_string(src.join(file))
            .unwrap()
            .replace('\r', "");
        let lines: Vec<&str> = text.lines().collect();
        let at = lines
            .iter()
            .position(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("{needle} in {file}"));
        let mut guarded = false;
        for above in lines[..at].iter().rev() {
            let above = above.trim();
            if above == CFG {
                guarded = true;
                break;
            }
            if !(above.starts_with("//") || above.starts_with("#[")) {
                break;
            }
        }
        assert!(guarded, "{file}: {needle} without the non-shipping cfg");
    }
}
