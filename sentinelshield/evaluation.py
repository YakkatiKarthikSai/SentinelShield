"""Repeatable, transparent evaluation for SentinelShield rule decisions."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from .dataset import EVALUATION_DATASET, LabelledRequest
from .engine import InspectionEngine


@dataclass(frozen=True)
class EvaluationResult:
    true_positive: int = 0
    true_negative: int = 0
    false_positive: int = 0
    false_negative: int = 0

    @property
    def precision(self) -> float:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else 0.0

    @property
    def f1_score(self) -> float:
        denominator = self.precision + self.recall
        return 2 * self.precision * self.recall / denominator if denominator else 0.0

    def to_dict(self) -> dict[str, float | int]:
        return {
            **asdict(self),
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1_score": round(self.f1_score, 3),
        }


def evaluate(
    engine: InspectionEngine, dataset: tuple[LabelledRequest, ...] = EVALUATION_DATASET
) -> EvaluationResult:
    """Compare allow/block decisions with the supplied sample labels."""

    counts = EvaluationResult()
    for sample in dataset:
        predicted_malicious = engine.inspect(sample.request).decision == "block"
        if sample.malicious and predicted_malicious:
            counts = EvaluationResult(counts.true_positive + 1, counts.true_negative, counts.false_positive, counts.false_negative)
        elif not sample.malicious and not predicted_malicious:
            counts = EvaluationResult(counts.true_positive, counts.true_negative + 1, counts.false_positive, counts.false_negative)
        elif not sample.malicious and predicted_malicious:
            counts = EvaluationResult(counts.true_positive, counts.true_negative, counts.false_positive + 1, counts.false_negative)
        else:
            counts = EvaluationResult(counts.true_positive, counts.true_negative, counts.false_positive, counts.false_negative + 1)
    return counts


def main() -> None:
    result = evaluate(InspectionEngine())
    print(json.dumps(result.to_dict(), indent=2))
    print("Controlled offline dataset only; this is not a claim of real-world detection accuracy.")


if __name__ == "__main__":
    main()
