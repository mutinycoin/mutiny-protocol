import unittest
from reputation_model import U64, U256, ATOMS, add, mul, score, quorum, run, effective_weight, public_metrics


class FormulaQualification(unittest.TestCase):
    def test_genesis_exception_is_replaced_and_physical_only(self):
        self.assertEqual(effective_weight(0,True,True,True,False),1)
        self.assertEqual(effective_weight(0,False,True,True,False),0)
        self.assertEqual(effective_weight(0,True,True,False,False),0)
        self.assertEqual(effective_weight(score(1,1,1,1),True,True,True,True),1007)

    def test_dynamic_survival_does_not_reenable_recovery(self):
        self.assertTrue(public_metrics([1007]*4,4,True)['survival_redundancy_met'])
        metric=public_metrics([7000,1000,1000,1000],4,True)
        self.assertFalse(metric['survival_redundancy_met'])
        self.assertFalse(metric['bootstrap_recovery_enabled'])
        self.assertEqual(metric['mode'],'DECENTRALIZED')
    def test_exact_direct_formula_no_hidden_baseline(self):
        self.assertEqual(score(0, 0, 0, 0), 0)
        self.assertEqual(score(1, 1, 1, 1), 1007)
        self.assertEqual(score(2, 2, 2, 2), 2014)

    def test_strict_threshold_and_unchanged_denominator(self):
        self.assertFalse(quorum([1, 1, 1], [0, 1]))
        self.assertTrue(quorum([1, 1, 1, 1], [0, 1, 2]))
        self.assertFalse(quorum([1007], []))
        self.assertFalse(quorum([0], [0]))

    def test_streak_and_bond_nonmonotonic_counterexamples(self):
        self.assertEqual(score(100, 100, 100, 100) - score(100, 101, 0, 100), 399)
        self.assertEqual(score(5000, 5000, 5000, 5000, [(100*ATOMS, 5000)])
                         - score(5000, 5000, 5000, 5000), 5001)

    def test_authorized_rotation_retains_history_and_bonds(self):
        before = score(100, 100, 100, 100, [(100*ATOMS, 100)], 50)
        after = score(100, 100, 100, 0, [(100*ATOMS, 100)], 50)
        self.assertEqual(before-after, 200)

    def test_fail_closed_ranges_and_signers(self):
        for f in (lambda: add(U256, 1), lambda: mul(U256, 2),
                  lambda: score(U64+1, 0, 0, 0), lambda: quorum([1], [0, 0])):
            with self.assertRaises((ValueError, OverflowError)):
                f()

    def test_report_is_deterministic_and_covers_requested_horizons(self):
        self.assertEqual(run(), run())
        report = run()
        self.assertEqual(len(report['scenarios']), 27)
        self.assertLess(report['maximum_quorum_comparison_bits'], 256)
        for year in (1, 5, 10):
            self.assertTrue(any(s['name'].startswith(f'{year}y_') for s in report['scenarios']))


if __name__ == '__main__':
    unittest.main()
