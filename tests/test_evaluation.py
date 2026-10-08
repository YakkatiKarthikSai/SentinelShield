"""Tests for confusion-matrix and metric calculations."""

import unittest

from sentinelshield.evaluation import EvaluationResult, evaluate
from sentinelshield.engine import InspectionEngine


class EvaluationTests(unittest.TestCase):
    def test_controlled_dataset_results_are_repeatable(self) -> None:
        result = evaluate(InspectionEngine())
        self.assertEqual(6, result.true_positive)
        self.assertEqual(3, result.true_negative)
        self.assertEqual(0, result.false_positive)
        self.assertEqual(0, result.false_negative)
        self.assertEqual(1.0, result.f1_score)

    def test_zero_denominator_metrics_are_safe(self) -> None:
        result = EvaluationResult()
        self.assertEqual(0.0, result.precision)
        self.assertEqual(0.0, result.recall)
        self.assertEqual(0.0, result.f1_score)


if __name__ == "__main__":
    unittest.main()
