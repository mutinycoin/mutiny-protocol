"""Pre-Genesis reference model of the Architect's exact amended formula.
No network, wallet, TPM, Genesis or real chain operations. Fail-closed u256 math.
"""
import json
from pathlib import Path

U64 = (1 << 64) - 1
U256 = (1 << 256) - 1
ATOMS = 100_000_000
PERIODS_PER_YEAR = 8_760  # Nominal 365-day years at one block/minute.


def checked(n):
    if not isinstance(n, int) or isinstance(n, bool) or not 0 <= n <= U256:
        raise OverflowError("u256 range")
    return n


def add(a, b):
    return checked(checked(a) + checked(b))


def mul(a, b):
    return checked(checked(a) * checked(b))


def score(p, a, s, h, lots=(), penalties=0):
    for counter in (p, a, s, h):
        if not isinstance(counter, int) or not 0 <= counter <= U64:
            raise ValueError("u64 counter")
    if s > p or h > p:
        raise ValueError("streak/hardware history exceeds participation")
    if len(lots) > 64:
        raise ValueError("too many lots")
    q = 0
    for atoms, age in lots:
        if not 0 <= atoms <= U64 or not 0 <= age <= U64:
            raise ValueError("u64 bond fields")
        q = add(q, mul(atoms, add(1, age)))
    gross = add(add(add(mul(1000, p), a), mul(4, s)), mul(2, h))
    gross = add(gross, q // 10_000_000_000)
    return max(0, gross - checked(penalties))


def quorum(weights, signed):
    if len(set(signed)) != len(signed) or any(i not in range(len(weights)) for i in signed):
        raise ValueError("duplicate/unknown signer")
    total = 0
    included = 0
    for i, w in enumerate(weights):
        total = add(total, w)
        if i in signed:
            included = add(included, w)
    return total > 0 and mul(3, included) > mul(2, total)


def effective_weight(history_score, physical, eligible, genesis_member, first_period_committed):
    checked(history_score)
    if not physical or not eligible:
        return 0
    if genesis_member and not first_period_committed:
        return 1
    return history_score


def public_metrics(weights, independent_physical_count, decentralized_activated):
    total = sum(weights)
    checked(total)
    losses = [quorum(weights, [j for j in range(len(weights)) if j != i])
              for i in range(len(weights))]
    ordered = sorted(weights, reverse=True)
    return dict(mode='DECENTRALIZED' if decentralized_activated else 'BOOTSTRAP_CENTRALIZED',
                bootstrap_recovery_enabled=not decentralized_activated,
                total_weight=total, largest_share_fraction=[max(weights, default=0), total],
                top_n_share_fractions=[[n, sum(ordered[:n]), total]
                                       for n in range(1, min(10, len(weights))+1)],
                survives_each_single_loss=losses,
                survival_redundancy_met=(independent_physical_count >= 4 and
                                         total > 0 and all(losses)))


def scenario(name, weights):
    total = sum(weights)
    return dict(name=name, weights=weights, total=total,
                largest_share_fraction=[max(weights, default=0), total],
                survives_each_single_loss=all(
                    quorum(weights, [j for j in range(len(weights)) if j != i])
                    for i in range(len(weights))))


def run():
    scenarios = []
    for year in (1, 5, 10):
        t = PERIODS_PER_YEAR * year
        old = score(t, t, t, t)
        newcomer = score(1, 1, 1, 1)
        scenarios += [
            scenario(f"{year}y_old_vs_100_new", [old] + [newcomer] * 100),
            scenario(f"{year}y_four_equal_unbonded", [old] * 4),
            scenario(f"{year}y_fresh_sybils_zero_history", [old] + [score(0, 0, 0, 0)] * 100),
            scenario(f"{year}y_admitted_sybils_one_qualified_period", [old] + [newcomer] * 100),
            scenario(f"{year}y_all_nominal_issued_supply_new_bond", [old] * 3 +
                     [score(1, 1, 1, 1, [(525_600 * year * ATOMS, 0)])]),
            scenario(f"{year}y_100mut_aged_bond", [old] * 3 +
                     [score(t, t, t, t, [(100 * ATOMS, t)])]),
            scenario(f"{year}y_supply_bound_aged_bond_stress", [old] * 3 +
                     [score(t, t, t, t, [(525_600 * year * ATOMS, t)])]),
        ]
    # All-supply aged from start is an adversarial upper bound, not a feasible
    # no-premine trajectory. Also model issuance arriving as 60 MUT each period.
    for year in (1, 5, 10):
        t = year * PERIODS_PER_YEAR
        # 120-MUT lots each two periods, consolidated only as an analytic bound;
        # 64 active lot cap and real ownership constrain an implementation further.
        m = t // 2
        q = 120 * ATOMS * m * m
        passive = score(t, t, t, t)
        bonded = passive + q // 10_000_000_000
        scenarios.append(scenario(f"{year}y_single_owner_all_rewards_analytic_bound",
                                  [passive] * 3 + [bonded]))
        # Realizable upper-concentration schedule: same owner earns all rewards,
        # deposits each completed batch in one of exactly 64 bond lots, never
        # withdraws, waits two periods for 100-block coinbase maturity. No premine
        # or bond-age reset/merging is assumed. Assess at t+2 periods.
        lots = []
        previous = 0
        for batch in range(1, 65):
            end = t * batch // 64
            lots.append(((end - previous) * 60 * ATOMS, t - end))
            previous = end
        tenure = t + 2
        baseline = score(tenure, tenure, tenure, tenure)
        scenarios.append(scenario(f"{year}y_all_rewards_64_lot_matured_schedule",
                                  [baseline] * 3 + [score(tenure, tenure, tenure, tenure, lots)]))
    examples = {
        "genesis_physical_effective_weight": effective_weight(0, True, True, True, False),
        "genesis_cloud_effective_weight": effective_weight(0, False, True, True, False),
        "postgenesis_joiner_effective_weight": effective_weight(0, True, True, False, False),
        "first_qualified_period_effective_weight": effective_weight(score(1, 1, 1, 1), True, True, True, True),
        "empty_bootstrap_weight": score(0, 0, 0, 0),
        "empty_bootstrap_can_commit": quorum([score(0, 0, 0, 0)], [0]),
        "before_missed_period": score(100, 100, 100, 100),
        "after_missed_period": score(100, 101, 0, 100),
        "before_withdrawal": score(5000, 5000, 5000, 5000, [(100 * ATOMS, 5000)]),
        "after_withdrawal": score(5000, 5000, 5000, 5000),
        "before_authorized_hardware_rotation": score(100, 100, 100, 100, [(100 * ATOMS, 100)], 50),
        "after_authorized_hardware_rotation": score(100, 100, 100, 0, [(100 * ATOMS, 100)], 50),
        "after_same_tpm_key_rotation": score(100, 100, 100, 100, [(100 * ATOMS, 100)], 50),
        "after_unauthorized_replacement": score(0, 0, 0, 0),
        "penalty_exceeds_gross": score(1, 1, 1, 1, penalties=U256),
        "lost_sole_voter_old_quorum": quorum([1007], []),
        "lost_equal_one_of_four_remaining_quorum": quorum([1007] * 4, [1, 2, 3]),
        "lost_exactly_one_third_remaining_quorum": quorum([1, 1, 1], [1, 2]),
        "before_join_old_denominator": quorum([1007], [0]),
        "after_three_joins_without_renormalization": quorum([1007, 1007, 1007, 1007], [0]),
        "voluntary_exit_certified_by_old_set": quorum([1007] * 4, [0, 1, 2]),
        "after_valid_exit_next_set_quorum": quorum([1007] * 3, [0, 1, 2]),
    }
    maximum = score(U64, U64, U64, U64, [(U64, U64)] * 64)
    checked(mul(3, mul(1024, maximum)))
    failures = 0
    for action in (lambda: add(U256, 1), lambda: mul(U256, 2),
                   lambda: score(U64 + 1, 0, 0, 0),
                   lambda: quorum([1, 1], [0, 0])):
        try:
            action()
        except (OverflowError, ValueError):
            failures += 1
    assert failures == 4
    assert examples["after_missed_period"] < examples["before_missed_period"]
    assert examples["after_withdrawal"] < examples["before_withdrawal"]
    assert examples["before_authorized_hardware_rotation"] - examples["after_authorized_hardware_rotation"] == 200
    return dict(schema="BUILD8-AMENDED-REPUTATION-ANALYSIS-V1",
                status="PASS_ARITHMETIC_WITH_ACCEPTED_CONCENTRATION", formula_changed=False,
                scenarios=scenarios, examples=examples,
                maximum_score_bits=maximum.bit_length(),
                maximum_quorum_comparison_bits=(3 * 1024 * maximum).bit_length(),
                fail_closed_negative_checks=failures,
                nominal_emission_mut_per_365day_year=525600,
                model_limits=["No real identities or bonds created", "No TPM/Sybil admission simulated as cryptographic proof",
                              "All-supply aged-bond case is an upper-bound stress case, not feasible issuance history",
                              "No certification or physical qualification is established by these arithmetic simulations"],
                resolved_by="ARCHITECT-BLOCKER-RESOLUTIONS-V1.txt",
                dynamic_metrics={"bootstrap": public_metrics([1],1,False),
                                 "four_equal": public_metrics([1007]*4,4,True),
                                 "later_concentration": public_metrics([7000,1000,1000,1000],4,True)},
                remaining_qualification=["physical TPM admission", "durable consensus integration",
                                         "complete canonical codec/negative vectors", "Genesis ceremony"])


if __name__ == "__main__":
    report = run()
    out = Path(__file__).with_name("reputation-results.json")
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "scenarios": len(report["scenarios"]),
                      "negative_checks": report["fail_closed_negative_checks"],
                      "examples": report["examples"],
                      "maximum_quorum_comparison_bits": report["maximum_quorum_comparison_bits"]}))
