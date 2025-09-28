import argparse
import json
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from ai_model import HybridScorer, RuleBasedScorer
from skype import (
    PortRotationTracker,
    TrafficMonitor,
    parse_port_range,
    shannon_entropy,
)


class ParsePortRangeTests(unittest.TestCase):
    def test_valid_range(self) -> None:
        self.assertEqual(parse_port_range("40000-60000"), (40000, 60000))

    def test_invalid_order_raises(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_port_range("60000-40000")

    def test_out_of_bounds_raises(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_port_range("0-100")
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_port_range("100-70000")


class PortRotationTrackerTests(unittest.TestCase):
    def test_alert_triggers_after_threshold(self) -> None:
        tracker = PortRotationTracker(alert_threshold=3, window_seconds=60, cooldown_seconds=10)

        now = time.time()
        _, alert1, _ = tracker.observe("1.1.1.1", 40000, now)
        self.assertFalse(alert1)
        _, alert2, _ = tracker.observe("1.1.1.1", 40001, now + 1)
        self.assertFalse(alert2)
        count3, alert3, _ = tracker.observe("1.1.1.1", 40002, now + 2)
        self.assertTrue(alert3)
        self.assertEqual(count3, 3)

        # Within cooldown window there should be no new alert
        _, alert4, _ = tracker.observe("1.1.1.1", 40003, now + 5)
        self.assertFalse(alert4)

        # After cooldown expires a new alert should trigger
        _, alert5, _ = tracker.observe("1.1.1.1", 40004, now + 15)
        self.assertTrue(alert5)

    def test_old_ports_evicted_after_window(self) -> None:
        tracker = PortRotationTracker(alert_threshold=10, window_seconds=5, cooldown_seconds=0)

        now = time.time()
        tracker.observe("2.2.2.2", 50000, now)
        tracker.observe("2.2.2.2", 50001, now + 1)
        count_after_eviction, _, ports_after_eviction = tracker.observe("2.2.2.2", 50002, now + 6)
        self.assertEqual(count_after_eviction, 2)
        self.assertListEqual(ports_after_eviction, [50001, 50002])

        count_final, _, ports_final = tracker.observe("2.2.2.2", 50003, now + 7)
        self.assertEqual(count_final, 2)
        self.assertListEqual(ports_final, [50002, 50003])


class ShannonEntropyTests(unittest.TestCase):
    def test_entropy_zero_for_uniform_bytes(self) -> None:
        self.assertEqual(shannon_entropy(b"\x00" * 32), 0.0)

    def test_entropy_increases_with_variability(self) -> None:
        diverse_bytes = bytes(range(32))
        self.assertGreater(shannon_entropy(diverse_bytes), 3.0)


class RuleBasedScorerTests(unittest.TestCase):
    def test_large_payload_increases_score(self) -> None:
        scorer = RuleBasedScorer()
        features = {
            "payload_entropy": 8.0,
            "payload_density": 0.9,
            "payload_size": 1500,
            "port_gap": 50000,
            "source_recent_ports": [50001, 50002],
        }
        result = scorer.score(features)
        self.assertGreaterEqual(result.score, 0.5)
        self.assertTrue(any("large payload" in reason for reason in result.reasons))

    def test_rotation_alert_bonus_applied(self) -> None:
        scorer = RuleBasedScorer()
        features = {
            "payload_entropy": 0.0,
            "payload_density": 0.0,
            "payload_size": 0,
            "port_gap": 0,
            "source_rotation_alert": True,
        }
        result = scorer.score(features)
        self.assertGreaterEqual(result.score, 0.4)
        self.assertIn("port rotation alert", result.reasons)


class HybridScorerTests(unittest.TestCase):
    class _StubHF:
        def predict(self, features: Dict[str, object]) -> Dict[str, object]:
            return {"label": "suspicious", "score": 0.9, "scores": {"benign": 0.1, "suspicious": 0.9}}

    def test_combines_rule_and_hf_scores(self) -> None:
        rule = RuleBasedScorer()
        hf = self._StubHF()
        scorer = HybridScorer(rule_scorer=rule, hf_classifier=hf, rule_weight=0.3, hf_weight=0.7)

        features = {
            "payload_entropy": 8.0,
            "payload_density": 0.9,
            "payload_size": 2000,
            "port_gap": 50000,
            "source_recent_ports": [50001, 50002],
        }

        result = scorer.score(features)
        self.assertGreater(result.score, 0.5)
        self.assertIn("huggingface", result.extra)
        self.assertIn("rule", result.extra)
        self.assertTrue(any(reason.startswith("hf:") for reason in result.reasons))


class TrafficMonitorTests(unittest.TestCase):
    def test_process_packet_logs_enriched_features(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir)
            monitor = TrafficMonitor(40000, 60000, output_dir)
            packet = (
                IP(src="10.0.0.1", dst="255.255.255.255")
                / UDP(sport=45000, dport=47809)
                / Raw(b"A" * 32)
            )

            try:
                monitor.process_packet(packet)
            finally:
                monitor.close()

            log_path = output_dir / "monitored_traffic.jsonl"
            self.assertTrue(log_path.exists())

            with log_path.open("r", encoding="utf-8") as handle:
                lines = [line.strip() for line in handle if line.strip()]

            self.assertEqual(len(lines), 1)
            record = json.loads(lines[0])

            self.assertIn("payload_entropy", record)
            self.assertGreaterEqual(record["payload_entropy"], 0.0)
            self.assertIn("payload_density", record)
            self.assertGreater(record["payload_density"], 0.0)
            self.assertTrue(record["source_high_port"])
            self.assertTrue(record["destination_high_port"])
            self.assertTrue(record["is_broadcast"])
            self.assertIn("source_recent_ports", record)
            self.assertIsInstance(record["source_recent_ports"], list)
            self.assertIn(45000, record["source_recent_ports"])
            self.assertIn("destination_recent_ports", record)
            self.assertTrue(record["destination_recent_ports"])  # UDP port logged

    def test_ai_scoring_emits_alert_record(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir)
            monitor = TrafficMonitor(
                40000,
                60000,
                output_dir,
                ai_scorer=RuleBasedScorer(),
                ai_threshold=0.5,
            )
            payload = bytes(range(256)) * 5  # 1280 bytes to trigger large payload rule
            packet = (
                IP(src="10.0.0.5", dst="255.255.255.255")
                / UDP(sport=50000, dport=47809)
                / Raw(payload)
            )

            try:
                monitor.process_packet(packet)
            finally:
                monitor.close()

            log_path = output_dir / "monitored_traffic.jsonl"
            with log_path.open("r", encoding="utf-8") as handle:
                entries = [json.loads(line) for line in handle if line.strip()]

            self.assertGreaterEqual(len(entries), 2)
            main_record = entries[0]
            self.assertIn("ai_score", main_record)
            self.assertTrue(main_record["ai_threshold_exceeded"])
            self.assertIn("ai_details", main_record)
            self.assertIn("rule", main_record["ai_details"])
            alert_records = [entry for entry in entries if entry.get("event") == "ai_score_alert"]
            self.assertTrue(alert_records)
            self.assertGreaterEqual(alert_records[0]["score"], 0.5)
            self.assertIn("details", alert_records[0])

    def test_hf_scorer_details_present(self) -> None:
        class StubHF:
            def predict(self, features: Dict[str, object]) -> Dict[str, object]:
                return {"label": "suspicious", "score": 0.9, "scores": {"benign": 0.1, "suspicious": 0.9}}

        with TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir)
            hybrid = HybridScorer(rule_scorer=None, hf_classifier=StubHF(), hf_weight=1.0, rule_weight=0.0)
            monitor = TrafficMonitor(
                40000,
                60000,
                output_dir,
                ai_scorer=hybrid,
                ai_threshold=0.5,
            )
            packet = (
                IP(src="10.0.0.8", dst="140.0.0.1")
                / TCP(sport=50001, dport=45000)
                / Raw(b"B" * 256)
            )

            try:
                monitor.process_packet(packet)
            finally:
                monitor.close()

            log_path = output_dir / "monitored_traffic.jsonl"
            with log_path.open("r", encoding="utf-8") as handle:
                entries = [json.loads(line) for line in handle if line.strip()]

            self.assertTrue(any(entry.get("event") == "ai_score_alert" for entry in entries))
            scored = next(entry for entry in entries if entry.get("ai_score") is not None)
            self.assertIn("huggingface", scored.get("ai_details", {}))


if __name__ == "__main__":
    unittest.main()
