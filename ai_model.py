"""Scoring utilities for enriched network telemetry."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional

if TYPE_CHECKING:  # pragma: no cover - imported only for typing
    from hf_model import HFPacketClassifier


@dataclass
class RuleBasedScorerConfig:
    high_entropy_threshold: float = 7.0
    high_density_threshold: float = 0.75
    large_payload_threshold: int = 1000
    large_port_gap_threshold: int = 40000
    broadcast_bonus: float = 0.2
    rotation_bonus: float = 0.4
    max_score: float = 1.0


@dataclass
class ScoreResult:
    score: float
    reasons: List[str]
    extra: Dict[str, Any]


class RuleBasedScorer:
    """Simple heuristic scorer to bootstrap AI-assisted detections."""

    def __init__(self, config: Optional[RuleBasedScorerConfig] = None) -> None:
        self.config = config or RuleBasedScorerConfig()

    def score(self, features: Dict[str, object]) -> ScoreResult:
        score = 0.0
        reasons: List[str] = []

        entropy = _safe_float(features.get("payload_entropy"))
        density = _safe_float(features.get("payload_density"))
        payload_size = _safe_float(features.get("payload_size"))
        port_gap = _safe_float(features.get("port_gap"))
        broadcast = bool(features.get("is_broadcast"))
        source_alert = bool(features.get("source_rotation_alert"))
        destination_alert = bool(features.get("destination_rotation_alert"))
        recent_source_ports = _safe_port_list(features.get("source_recent_ports"))

        if entropy >= self.config.high_entropy_threshold and density >= self.config.high_density_threshold:
            score += 0.3
            reasons.append("high-entropy-high-density payload")

        if payload_size >= self.config.large_payload_threshold:
            score += 0.3
            reasons.append("large payload size")

        if port_gap >= self.config.large_port_gap_threshold and len(recent_source_ports) >= 2:
            score += 0.2
            reasons.append("large port gap with high-port activity")

        if broadcast:
            score += self.config.broadcast_bonus
            reasons.append("broadcast traffic")

        if source_alert or destination_alert:
            score += self.config.rotation_bonus
            reasons.append("port rotation alert")

        if score > self.config.max_score:
            score = self.config.max_score

        return ScoreResult(
            score=score,
            reasons=reasons,
            extra={"rule": {"score": score, "reasons": reasons}},
        )


class HybridScorer:
    """Blend multiple scorers (rule-based, Hugging Face classifier, etc.)."""

    def __init__(
        self,
        rule_scorer: Optional[RuleBasedScorer] = None,
        hf_classifier: Optional["HFPacketClassifier"] = None,
        rule_weight: float = 0.5,
        hf_weight: float = 0.5,
    ) -> None:
        self.rule_scorer = rule_scorer
        self.hf_classifier = hf_classifier
        self.rule_weight = rule_weight if rule_scorer else 0.0
        self.hf_weight = hf_weight if hf_classifier else 0.0

    def score(self, features: Dict[str, object]) -> ScoreResult:
        total_score = 0.0
        total_weight = 0.0
        reasons: List[str] = []
        extra: Dict[str, Any] = {}

        if self.rule_scorer:
            rule_result = self.rule_scorer.score(features)
            total_score += self.rule_weight * rule_result.score
            total_weight += self.rule_weight
            reasons.extend(f"rule:{reason}" for reason in rule_result.reasons)
            extra["rule"] = {
                "score": rule_result.score,
                "reasons": rule_result.reasons,
            }

        if self.hf_classifier:
            hf_output = self.hf_classifier.predict(features)
            total_score += self.hf_weight * hf_output["score"]
            total_weight += self.hf_weight
            reasons.append(
                f"hf:{hf_output['label']} ({hf_output['score']:.2f})"
            )
            extra["huggingface"] = hf_output

        final_score = (total_score / total_weight) if total_weight else 0.0
        return ScoreResult(score=final_score, reasons=reasons, extra=extra)


def batch_score(scorer: RuleBasedScorer, records: Iterable[Dict[str, object]]) -> List[ScoreResult]:
    return [scorer.score(record) for record in records]


def _safe_float(value: object) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _safe_port_list(value: object) -> List[int]:
    if isinstance(value, list):
        return [int(port) for port in value if isinstance(port, (int, float))]
    return []
