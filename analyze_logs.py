"""Utility to transform monitored_traffic.jsonl into AI-friendly features and summaries."""

import argparse
import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from statistics import mean
from typing import Dict, Iterable, List, Sequence

NUMERIC_FIELDS = (
    "payload_size",
    "payload_entropy",
    "payload_density",
    "packet_length",
    "port_gap",
    "source_unique_port_count",
    "destination_unique_port_count",
    "ai_score",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze monitored network traffic logs, extract derived features, "
            "and optionally write them out as CSV for downstream AI pipelines."
        )
    )
    parser.add_argument(
        "input",
        type=Path,
        help="Path to monitored_traffic.jsonl (or similar JSONL file).",
    )
    parser.add_argument(
        "--csv-output",
        type=Path,
        default=None,
        help="Optional destination for a CSV file containing extracted features.",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print a human-friendly traffic summary to stdout.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optionally limit the number of records processed (useful for quick iterations).",
    )
    parser.add_argument(
        "--ai-threshold",
        type=float,
        default=0.7,
        help="Threshold for counting high AI scores in summaries (default: 0.7).",
    )
    return parser.parse_args()


def load_records(path: Path, limit: int | None = None) -> List[Dict[str, object]]:
    records: List[Dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            if limit is not None and index >= limit:
                break
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSON on line {index + 1}: {exc}") from exc
    return records


def _safe_number(value: object) -> float:
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _serialize_reasons(value: object) -> str:
    if isinstance(value, list):
        return ";".join(str(item) for item in value)
    if value is None:
        return ""
    return str(value)


def _serialize_mapping(value: object) -> str:
    if isinstance(value, dict):
        return json.dumps(value, separators=(",", ":"))
    if value is None:
        return ""
    return str(value)


def extract_features(record: Dict[str, object]) -> Dict[str, object]:
    timestamp_str = record.get("timestamp_utc")
    try:
        timestamp = datetime.fromisoformat(timestamp_str) if timestamp_str else None
    except ValueError:
        timestamp = None

    features: Dict[str, object] = {
        "timestamp_utc": timestamp_str,
        "protocol": record.get("protocol"),
        "src_ip": record.get("src_ip"),
        "dst_ip": record.get("dst_ip"),
        "src_port": record.get("src_port"),
        "dst_port": record.get("dst_port"),
        "payload_has_data": bool(record.get("payload_size", 0)),
        "port_gap": _safe_number(record.get("port_gap")),
        "payload_entropy": _safe_number(record.get("payload_entropy")),
        "payload_density": _safe_number(record.get("payload_density")),
        "source_unique_port_count": _safe_number(record.get("source_unique_port_count")),
        "destination_unique_port_count": _safe_number(record.get("destination_unique_port_count")),
        "source_rotation_alert": bool(record.get("source_rotation_alert", False)),
        "destination_rotation_alert": bool(record.get("destination_rotation_alert", False)),
        "is_broadcast": bool(record.get("is_broadcast", False)),
        "recent_source_ports": record.get("source_recent_ports", []),
        "recent_destination_ports": record.get("destination_recent_ports", []),
        "ai_score": _safe_number(record.get("ai_score")),
        "ai_threshold_exceeded": bool(record.get("ai_threshold_exceeded", False)),
        "ai_reasons": _serialize_reasons(record.get("ai_reasons")),
        "ai_details": _serialize_mapping(record.get("ai_details")),
    }

    if timestamp:
        features.update(
            {
                "hour": timestamp.hour,
                "weekday": timestamp.weekday(),
            }
        )

    payload_size = _safe_number(record.get("payload_size"))
    packet_length = _safe_number(record.get("packet_length"))
    features["payload_size"] = payload_size
    features["packet_length"] = packet_length
    features["payload_ratio"] = (
        payload_size / packet_length if packet_length else 0.0
    )

    return features


def summarize(records: Sequence[Dict[str, object]]) -> Dict[str, object]:
    data_records = [record for record in records if record.get("event") is None]

    protocol_counts = Counter(record.get("protocol") for record in data_records)
    source_counts = Counter(record.get("src_ip") for record in data_records)
    destination_counts = Counter(record.get("dst_ip") for record in data_records)

    numeric_stats: Dict[str, float] = {}
    for field in NUMERIC_FIELDS:
        values = [_safe_number(record.get(field)) for record in data_records if field in record]
        if values:
            numeric_stats[field + "_avg"] = mean(values)
            numeric_stats[field + "_max"] = max(values)
            numeric_stats[field + "_min"] = min(values)

    broadcast_total = sum(1 for record in data_records if record.get("is_broadcast"))
    rotation_total = sum(1 for record in data_records if record.get("source_rotation_alert") or record.get("destination_rotation_alert"))
    ai_alert_events = sum(1 for record in records if record.get("event") == "ai_score_alert")

    return {
        "total_records": len(data_records),
        "protocol_counts": protocol_counts,
        "top_sources": source_counts.most_common(5),
        "top_destinations": destination_counts.most_common(5),
        "numeric_stats": numeric_stats,
        "broadcast_packets": broadcast_total,
        "rotation_alerts": rotation_total,
        "ai_alert_events": ai_alert_events,
    }


def print_summary(summary: Dict[str, object]) -> None:
    print(f"Total records: {summary['total_records']}")
    print("Protocol counts:")
    for proto, count in summary["protocol_counts"].items():
        print(f"  {proto}: {count}")
    print("Top sources:")
    for ip, count in summary["top_sources"]:
        print(f"  {ip}: {count}")
    print("Top destinations:")
    for ip, count in summary["top_destinations"]:
        print(f"  {ip}: {count}")
    print("Broadcast packets:", summary["broadcast_packets"])
    print("Rotation alerts:", summary["rotation_alerts"])
    print("AI alert events:", summary["ai_alert_events"])
    if "ai_high_scores" in summary:
        print("AI high-score packets:", summary["ai_high_scores"])
    if summary["numeric_stats"]:
        print("Numeric field stats:")
        for field, value in summary["numeric_stats"].items():
            print(f"  {field}: {value:.4f}")


def write_csv(features: Iterable[Dict[str, object]], destination: Path) -> None:
    features = list(features)
    if not features:
        print("No features to write; skipping CSV export.")
        return
    fieldnames = sorted({key for feature in features for key in feature.keys()})
    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for feature in features:
            writer.writerow(feature)
    print(f"Wrote {len(features)} feature rows to {destination}")


def main() -> None:
    args = parse_args()
    records = load_records(args.input, limit=args.limit)
    if not records:
        print("No records found in input file.")
        return

    features = [extract_features(record) for record in records]

    if args.summary:
        summary = summarize(records)
        ai_high_scores = sum(
            1
            for record in records
            if record.get("event") is None and _safe_number(record.get("ai_score")) >= args.ai_threshold
        )
        summary["ai_high_scores"] = ai_high_scores
        print_summary(summary)

    if args.csv_output:
        write_csv(features, args.csv_output)
    else:
        print("Feature extraction complete (use --csv-output to persist results).")


if __name__ == "__main__":  # pragma: no cover
    main()
