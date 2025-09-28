"""Hugging Face packet classifier integration."""

from __future__ import annotations

from typing import Any, Dict, Optional


class HFPacketClassifier:
    """Wrapper around a Hugging Face text classifier for packet telemetry."""

    def __init__(
        self,
        model_name: str,
        positive_label: Optional[str] = None,
        device: Optional[str | int] = None,
        max_length: int = 256,
    ) -> None:
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline
        except ImportError as exc:  # pragma: no cover - exercised only when dependency missing
            raise RuntimeError(
                "transformers is required for Hugging Face scoring. Install it via 'pip install transformers'."
            ) from exc

        self.model_name = model_name
        self.max_length = max_length

        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(model_name)
        self._pipeline = pipeline(
            "text-classification",
            model=model,
            tokenizer=tokenizer,
            device=device,
        )

        if positive_label is None:
            # Default to the label with the highest index if not provided.
            labels = list(model.config.id2label.values())
            positive_label = labels[-1] if labels else "LABEL_1"
        self.positive_label = positive_label

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        text = self._render_features(features)
        outputs = self._pipeline(
            text,
            truncation=True,
            max_length=self.max_length,
            return_all_scores=True,
        )
        scores = {item["label"]: float(item["score"]) for item in outputs[0]}
        positive_score = scores.get(self.positive_label)
        if positive_score is None:
            # Fall back to the most probable label if the desired one is missing.
            label, positive_score = max(scores.items(), key=lambda kv: kv[1])
        else:
            label = max(scores, key=scores.get)

        return {
            "label": label,
            "score": float(positive_score),
            "scores": scores,
        }

    def _render_features(self, features: Dict[str, Any]) -> str:
        parts = [
            f"protocol={features.get('protocol', '')}",
            f"src_ip={features.get('src_ip', '')}",
            f"dst_ip={features.get('dst_ip', '')}",
            f"src_port={features.get('src_port', '')}",
            f"dst_port={features.get('dst_port', '')}",
            f"packet_length={features.get('packet_length', 0)}",
            f"payload_size={features.get('payload_size', 0)}",
            f"payload_entropy={features.get('payload_entropy', 0.0)}",
            f"payload_density={features.get('payload_density', 0.0)}",
            f"port_gap={features.get('port_gap', 0)}",
            f"broadcast={features.get('is_broadcast', False)}",
        ]

        source_ports = features.get("source_recent_ports")
        destination_ports = features.get("destination_recent_ports")
        if source_ports:
            parts.append(f"source_recent_ports={','.join(map(str, source_ports[-10:]))}")
        if destination_ports:
            parts.append(f"destination_recent_ports={','.join(map(str, destination_ports[-10:]))}")

        return " ".join(parts)
```}