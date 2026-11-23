"""Model-agnostic attribution: exact decompositions across model families."""
import json
import math
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cloud_threat.core.attribution import builtin_profile, explain
from cloud_threat.core.evidence import RESOURCE_ROOT
from cloud_threat.core.scoring import FEATURES, score

SAMPLES = RESOURCE_ROOT / 'samples'
ALL = {'public_access': 1, 'unusual_region': 1, 'large_read': 1}


class AttributionTests(unittest.TestCase):
    def test_builtin_profile_matches_workspace_scoring(self):
        for bits in range(8):
            features = {name: (bits >> index) & 1 for index, name in enumerate(FEATURES)}
            result = explain(builtin_profile(), features)
            self.assertEqual(result['output'], score(features))
            self.assertTrue(result['complete'])

    def test_logistic_reports_log_odds_probability_and_intervals(self):
        model = json.loads((SAMPLES / 'model_logistic.json').read_text())
        result = explain(model, ALL)
        self.assertEqual(result['unit'], 'log_odds')
        self.assertAlmostEqual(result['output'], -4.0 + 2.1 + 1.3 + 1.9)
        self.assertAlmostEqual(result['probability'], 1 / (1 + math.exp(-result['output'])))
        top = result['contributions'][0]
        self.assertEqual(top['feature'], 'public_access')
        self.assertLess(top['lower'], top['contribution']); self.assertGreater(top['upper'], top['contribution'])

    def test_tree_ensemble_path_contributions_are_complete(self):
        model = json.loads((SAMPLES / 'model_tree.json').read_text())
        for bits in range(8):
            features = {name: (bits >> index) & 1 for index, name in enumerate(sorted(ALL))}
            result = explain(model, features)
            self.assertTrue(result['complete'], features)
        result = explain(model, ALL)
        contributions = {row['feature']: row['contribution'] for row in result['contributions']}
        self.assertAlmostEqual(result['baseline'], 0.30)
        self.assertAlmostEqual(result['output'], 1.05)
        self.assertAlmostEqual(contributions['public_access'], 0.40)
        self.assertAlmostEqual(contributions['unusual_region'], 0.20)
        self.assertAlmostEqual(contributions['large_read'], 0.15)

    def test_invalid_inputs_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Missing feature'):
            explain(builtin_profile(), {'public_access': 1})
        with self.assertRaises(ValueError):
            explain({'family': 'neural'}, ALL)
        with self.assertRaises(ValueError):
            explain(builtin_profile(), {**ALL, 'large_read': float('nan')})
        with self.assertRaisesRegex(ValueError, 'unknown feature'):
            explain({'family': 'tree_ensemble', 'features': ['a'], 'trees': [
                {'feature': 'b', 'threshold': 0, 'value': 0, 'left': {'leaf': 0}, 'right': {'leaf': 1}}]}, {'a': 1})


if __name__ == '__main__':
    unittest.main()
