use mutiny_consensus_v8::{Hash, proposer::*};
use primitive_types::U256;
use std::collections::BTreeMap;
#[test]
fn weighted_rounds_and_height_progression_do_not_depend_on_commit_proof_round() {
    let weights: BTreeMap<Hash, U256> = [
        ([1; 32], 1.into()),
        ([2; 32], 3.into()),
        ([3; 32], 0.into()),
    ]
    .into_iter()
    .collect();
    let schedule = ProposerSchedule::genesis(&weights).unwrap();
    let mut rounds = schedule.rounds();
    let mut selected = Vec::new();
    for _ in 0..8 {
        selected.push(rounds.advance().unwrap().1);
    }
    assert_eq!(
        selected,
        vec![
            [2; 32], [1; 32], [2; 32], [2; 32], [2; 32], [1; 32], [2; 32], [2; 32]
        ]
    );
    let observed_round_zero = schedule.clone();
    let observed_round_seven = schedule.clone();
    assert_eq!(
        observed_round_zero.next_height(&weights).unwrap(),
        observed_round_seven.next_height(&weights).unwrap()
    );
    let mut height = schedule.clone();
    let mut counts = BTreeMap::new();
    for _ in 0..400 {
        *counts
            .entry(height.rounds().advance().unwrap().1)
            .or_insert(0) += 1;
        height = height.next_height(&weights).unwrap();
    }
    assert_eq!(counts[&[1; 32]], 100);
    assert_eq!(counts[&[2; 32]], 300);
    assert!(!counts.contains_key(&[3; 32]));
    let changed = [
        ([1; 32], 100_000.into()),
        ([2; 32], 1.into()),
        ([4; 32], 1.into()),
    ]
    .into_iter()
    .collect();
    let changed = height.next_height(&changed).unwrap();
    let equal = [([2; 32], 1.into()), ([4; 32], 1.into())]
        .into_iter()
        .collect();
    let mut changed = changed.next_height(&equal).unwrap().rounds();
    let mut counts = BTreeMap::new();
    for _ in 0..20 {
        *counts.entry(changed.advance().unwrap().1).or_insert(0) += 1;
    }
    assert!(counts[&[2; 32]] >= 8 && counts[&[4; 32]] >= 8);
    assert!(ProposerSchedule::genesis(&BTreeMap::new()).is_err());
}
