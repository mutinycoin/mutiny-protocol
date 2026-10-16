//! Order W23: an opaque-commitment warning is a Caution that requires the Conditions
//! acknowledgement wherever it appears: `OPAQUE_COMMITMENTS` (the License sale, the fiat lock and
//! release) and `OPAQUE_TRADE_COMMITMENTS` (the hash lock, its claim and refund, the Treasury offer
//! freeze; a Notice without an acknowledgement before W23). Checked over the golden review texts
//! of every kind that carries one (the reviews the desktop draws line for line). A warning does not
//! replace concrete term validation, verified external-settlement evidence or the mandatory P5/P6
//! cryptographic commitments (docs/WALLET-OPERATIONS-V1.md). NATIVE, TEST-VALUE.
use std::path::Path;

#[test]
fn every_opaque_commitment_warning_is_a_caution_with_the_conditions_acknowledgement() {
    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    let mut carrying = Vec::new();
    for name in [
        "dvp_buyer_review.txt",
        "dvp_seller_review.txt",
        "hash_lock_review.txt",
        "hash_lock_recipient_review.txt",
        "claim_review.txt",
        "refund_review.txt",
        "treasury_freeze_review.txt",
    ] {
        let text = std::fs::read_to_string(golden.join(name))
            .unwrap()
            .replace('\r', "");
        let warnings: Vec<&str> = text
            .lines()
            // Warning lines only: the Conditions rows of the sale and the fiat lock also name the
            // commitments as opaque.
            .filter(|line| line.starts_with("! ") && line.contains("opaque commitments"))
            .collect();
        assert_eq!(warnings.len(), 1, "{name}: one opaque-commitment warning");
        assert!(
            warnings[0].starts_with("! Caution: "),
            "{name}: {}",
            warnings[0]
        );
        assert!(
            text.contains("* Required: I read the conditions and the timing"),
            "{name}: the Conditions acknowledgement"
        );
        carrying.push(name);
    }
    assert_eq!(carrying.len(), 7);
}
