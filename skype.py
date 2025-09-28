"""Network monitor to flag Skype-like traffic over rotating high ports.

This script uses scapy to sniff TCP/UDP packets within a configurable port range
(default 40000-60000). Metadata is logged to JSONL, packet payloads are persisted
per flow for later audio/signal analysis, and packets are mirrored to a PCAP file.
"""

import argparse
import base64
import json
import sys
import threading
import time
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone
from math import log2
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from scapy.all import IP, TCP, UDP, Raw, sniff
from scapy.utils import PcapWriter

from ai_model import HybridScorer, RuleBasedScorer, ScoreResult

DEFAULT_PORT_RANGE = "40000-60000"
DEFAULT_OUTPUT_DIR = "monitor_output"


def parse_port_range(port_range: str) -> Tuple[int, int]:
    """Return inclusive start/end ports from strings like "40000-60000"."""
    try:
        start_str, end_str = port_range.split("-", maxsplit=1)
        start = int(start_str)
        end = int(end_str)
        if start < 1 or end > 65535 or start > end:
            raise ValueError
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Port range must be formatted as start-end within 1-65535"
        ) from exc
    return start, end


def utc_timestamp() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(tz=timezone.utc).isoformat()


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits for the provided byte sequence."""
    if not data:
        return 0.0

    sample_count = len(data)
    freq: Dict[int, int] = {}
    for value in data:
        freq[value] = freq.get(value, 0) + 1

    entropy = 0.0
    for count in freq.values():
        probability = count / sample_count
        entropy -= probability * log2(probability)

    return entropy


class PortRotationTracker:
    """Track unique ports per IP to highlight rapid rotation patterns."""

    def __init__(
        self,
        alert_threshold: int = 10,
        window_seconds: int = 600,
        cooldown_seconds: int = 300,
        capacity: int = 100,
    ) -> None:
        self.alert_threshold = alert_threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.capacity = capacity
        self._history: defaultdict[str, OrderedDict[int, float]] = defaultdict(OrderedDict)
        self._last_alert_ts: Dict[str, float] = {}
        self._lock = threading.Lock()

    def observe(self, ip: str, port: int, now: float) -> Tuple[int, bool, list[int]]:
        """Record the port for an IP and decide if an alert should fire."""
        with self._lock:
            history = self._history[ip]
            stale_ports = [p for p, ts in history.items() if now - ts > self.window_seconds]
            for stale in stale_ports:
                history.pop(stale, None)
            history[port] = now
            history.move_to_end(port)
            while len(history) > self.capacity:
                history.popitem(last=False)

            unique_count = len(history)
            should_alert = False
            if unique_count >= self.alert_threshold:
                last_ts = self._last_alert_ts.get(ip, 0.0)
                if now - last_ts >= self.cooldown_seconds:
                    self._last_alert_ts[ip] = now
                    should_alert = True
            return unique_count, should_alert, list(history.keys())


class TrafficMonitor:
    """Sniff traffic, log metadata, and persist payloads for later inspection."""

    def __init__(
        self,
        port_start: int,
        port_end: int,
        output_dir: Path,
        interface: Optional[str] = None,
        pcap_path: Optional[Path] = None,
        ai_scorer: Optional[HybridScorer | RuleBasedScorer] = None,
        ai_threshold: float = 0.7,
    ) -> None:
        self.port_start = port_start
        self.port_end = port_end
        self.interface = interface
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.log_path = self.output_dir / "monitored_traffic.jsonl"
        self.payload_dir = self.output_dir / "payloads"
        self.payload_dir.mkdir(exist_ok=True)

        self._log_lock = threading.Lock()
        self._pcap_lock = threading.Lock()

        self.log_file = self.log_path.open("a", encoding="utf-8")

        pcap_destination = pcap_path or (self.output_dir / "captured_packets.pcap")
        try:
            self.pcap_writer = PcapWriter(str(pcap_destination), append=True, sync=True)
        except OSError as exc:
            print(f"[!] Failed to create PCAP writer at {pcap_destination}: {exc}", file=sys.stderr)
            self.pcap_writer = None

        self.rotation_tracker = PortRotationTracker()
        self.ai_scorer = ai_scorer
        self.ai_threshold = ai_threshold

    def close(self) -> None:
        """Flush and close resources."""
        with self._log_lock:
            self.log_file.flush()
            self.log_file.close()
        with self._pcap_lock:
            if self.pcap_writer is not None:
                self.pcap_writer.close()

    def _port_in_scope(self, port: int) -> bool:
        return self.port_start <= port <= self.port_end

    def _build_flow_path(
        self,
        proto: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> Path:
        left = (src_ip, src_port)
        right = (dst_ip, dst_port)
        if left <= right:
            canonical = (src_ip, src_port, dst_ip, dst_port)
        else:
            canonical = (dst_ip, dst_port, src_ip, src_port)
        safe_parts = [proto]
        for ip, port in (canonical[0:2], canonical[2:4]):
            safe_ip = ip.replace(":", "_").replace("/", "_")
            safe_parts.append(f"{safe_ip}-{port}")
        filename = "__".join(safe_parts) + ".raw"
        return self.payload_dir / filename

    def _persist_payload(
        self,
        proto: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        payload: bytes,
    ) -> Path:
        flow_path = self._build_flow_path(proto, src_ip, src_port, dst_ip, dst_port)
        with flow_path.open("ab") as handle:
            handle.write(payload)
        return flow_path

    def _log_record(self, record: Dict[str, object]) -> None:
        with self._log_lock:
            self.log_file.write(json.dumps(record) + "\n")
            self.log_file.flush()

    def _write_pcap(self, packet) -> None:
        if self.pcap_writer is None:
            return
        with self._pcap_lock:
            self.pcap_writer.write(packet)

    def process_packet(self, packet) -> None:
        if IP not in packet:
            return
        proto_layer = None
        proto_name = ""
        if TCP in packet:
            proto_layer = packet[TCP]
            proto_name = "TCP"
        elif UDP in packet:
            proto_layer = packet[UDP]
            proto_name = "UDP"
        else:
            return

        src_port = int(proto_layer.sport)
        dst_port = int(proto_layer.dport)
        if not (self._port_in_scope(src_port) or self._port_in_scope(dst_port)):
            return

        timestamp = utc_timestamp()
        epoch_now = time.time()
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        payload_bytes = bytes(packet[Raw].load) if Raw in packet else b""
        payload_size = len(payload_bytes)
        payload_preview = base64.b64encode(payload_bytes[:64]).decode("ascii") if payload_size else ""
        payload_entropy = shannon_entropy(payload_bytes)

        payload_path = None
        if payload_size:
            payload_path = str(
                self._persist_payload(proto_name, src_ip, src_port, dst_ip, dst_port, payload_bytes)
            )

        rotation_metrics: Dict[str, object] = {}
        alerts_to_emit: List[Tuple[str, str, int, List[int]]] = []
        for ip, port, direction in (
            (src_ip, src_port, "source"),
            (dst_ip, dst_port, "destination"),
        ):
            unique_count, alert, recent_ports = self.rotation_tracker.observe(ip, port, epoch_now)
            rotation_metrics[f"{direction}_unique_port_count"] = unique_count
            rotation_metrics[f"{direction}_recent_ports"] = recent_ports[-10:]
            rotation_metrics[f"{direction}_rotation_alert"] = alert
            if alert:
                alerts_to_emit.append((ip, direction, unique_count, recent_ports))

        packet_length = len(packet)
        payload_density = (payload_size / packet_length) if packet_length else 0.0
        port_gap = abs(src_port - dst_port)
        is_broadcast = dst_ip.endswith(".255") or dst_ip == "255.255.255.255"

        log_entry = {
            "timestamp_utc": timestamp,
            "protocol": proto_name,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "packet_length": packet_length,
            "payload_size": payload_size,
            "payload_preview_b64": payload_preview,
            "payload_file": payload_path,
            "payload_entropy": payload_entropy,
            "payload_density": payload_density,
            "port_gap": port_gap,
            "source_high_port": self._port_in_scope(src_port),
            "destination_high_port": self._port_in_scope(dst_port),
            "is_broadcast": is_broadcast,
        }
        log_entry.update(rotation_metrics)
        ai_result: Optional[ScoreResult] = None
        if self.ai_scorer is not None:
            ai_result = self.ai_scorer.score(log_entry)
            log_entry["ai_score"] = ai_result.score
            log_entry["ai_reasons"] = ai_result.reasons
            log_entry["ai_threshold_exceeded"] = ai_result.score >= self.ai_threshold
            if ai_result.extra:
                log_entry["ai_details"] = ai_result.extra
        self._log_record(log_entry)
        self._write_pcap(packet)
        for ip, direction, unique_count, recent_ports in alerts_to_emit:
            message = (
                f"[!] Port rotation alert for {ip} ({direction}). "
                f"Observed {unique_count} unique ports in {self.rotation_tracker.window_seconds}s."
            )
            alert_record = {
                "timestamp_utc": timestamp,
                "event": "port_rotation_alert",
                "ip": ip,
                "direction": direction,
                "unique_ports": unique_count,
                "recent_ports": recent_ports,
            }
            self._log_record(alert_record)
            print(message)

        if ai_result is not None and log_entry.get("ai_threshold_exceeded"):
            ai_message = (
                f"[!] AI score alert for {src_ip}->{dst_ip} ({proto_name}). "
                f"Score: {ai_result.score:.2f}"
            )
            ai_alert_record = {
                "timestamp_utc": timestamp,
                "event": "ai_score_alert",
                "score": ai_result.score,
                "reasons": ai_result.reasons,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
            }
            if ai_result.extra:
                ai_alert_record["details"] = ai_result.extra
            self._log_record(ai_alert_record)
            print(ai_message)

    def start(self, max_packets: int = 0, duration: int = 0) -> None:
        bpf_filter = f"(tcp or udp) and portrange {self.port_start}-{self.port_end}"
        sniff_kwargs: Dict[str, object] = {
            "filter": bpf_filter,
            "prn": self.process_packet,
            "store": False,
        }
        if self.interface:
            sniff_kwargs["iface"] = self.interface
        if max_packets:
            sniff_kwargs["count"] = max_packets
        if duration:
            sniff_kwargs["timeout"] = duration

        print(
            f"[*] Starting capture on ports {self.port_start}-{self.port_end}. "
            "Press CTRL+C to stop."
        )
        try:
            sniff(**sniff_kwargs)
        except KeyboardInterrupt:
            print("\n[*] Capture interrupted by user.")
        finally:
            self.close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Monitor high-port Skype-like traffic and persist payloads for analysis.",
    )
    parser.add_argument(
        "--ports",
        default=DEFAULT_PORT_RANGE,
        type=parse_port_range,
        help="Port range to monitor in start-end form (default: 40000-60000).",
    )
    parser.add_argument(
        "--interface",
        "-i",
        default=None,
        help="Network interface name for sniffing (default: scapy default).",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        type=Path,
        help="Directory for logs, payloads, and PCAP output (default: monitor_output).",
    )
    parser.add_argument(
        "--pcap",
        type=Path,
        default=None,
        help="Optional path for the PCAP file (default inside output directory).",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=0,
        help="Optional limit on total packets to capture (0 = unlimited).",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=0,
        help="Optional capture timeout in seconds (0 = run until interrupted).",
    )
    parser.add_argument(
        "--enable-ai-scoring",
        action="store_true",
        help="Enable rule-based AI scoring and alerting for each packet.",
    )
    parser.add_argument(
        "--ai-threshold",
        type=float,
        default=0.7,
        help="Threshold for emitting AI score alerts (default: 0.7).",
    )
    parser.add_argument(
        "--disable-rule-scorer",
        action="store_true",
        help="Disable the heuristic rule-based scorer when AI scoring is enabled.",
    )
    parser.add_argument(
        "--rule-weight",
        type=float,
        default=0.5,
        help="Weight assigned to the rule-based scorer when combining scores (default: 0.5).",
    )
    parser.add_argument(
        "--hf-model",
        type=str,
        default=None,
        help="Optional Hugging Face model identifier for packet classification (e.g. user/model).",
    )
    parser.add_argument(
        "--hf-positive-label",
        type=str,
        default=None,
        help="Label treated as the positive/suspicious class for the Hugging Face model.",
    )
    parser.add_argument(
        "--hf-weight",
        type=float,
        default=0.5,
        help="Weight assigned to the Hugging Face classifier when combining scores (default: 0.5).",
    )
    parser.add_argument(
        "--hf-max-length",
        type=int,
        default=256,
        help="Maximum token length for Hugging Face model inputs (default: 256).",
    )
    parser.add_argument(
        "--hf-device",
        type=str,
        default=None,
        help="Device for Hugging Face inference (e.g. cpu, cuda:0).",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    port_start, port_end = args.ports
    enable_ai = args.enable_ai_scoring or args.hf_model is not None
    ai_scorer: Optional[HybridScorer | RuleBasedScorer] = None
    if enable_ai:
        rule_component: Optional[RuleBasedScorer] = None
        hf_component = None
        if not args.disable_rule_scorer:
            rule_component = RuleBasedScorer()

        if args.hf_model:
            hf_device_raw = args.hf_device
            hf_device: Optional[int | str] = None
            if isinstance(hf_device_raw, str):
                lowered = hf_device_raw.lower()
                if lowered == "cpu":
                    hf_device = -1
                elif lowered.startswith("cuda"):
                    if ":" in lowered:
                        index = lowered.split(":", 1)[1]
                        hf_device = int(index) if index.isdigit() else hf_device_raw
                    else:
                        hf_device = 0
                elif hf_device_raw.isdigit():
                    hf_device = int(hf_device_raw)
                else:
                    hf_device = hf_device_raw
            else:
                hf_device = hf_device_raw
            try:
                from hf_model import HFPacketClassifier

                hf_component = HFPacketClassifier(
                    model_name=args.hf_model,
                    positive_label=args.hf_positive_label,
                    device=hf_device,
                    max_length=args.hf_max_length,
                )
            except RuntimeError as exc:
                print(f"[!] Failed to initialise Hugging Face model: {exc}", file=sys.stderr)

        if rule_component or hf_component:
            ai_scorer = HybridScorer(
                rule_scorer=rule_component,
                hf_classifier=hf_component,
                rule_weight=args.rule_weight,
                hf_weight=args.hf_weight,
            )

    monitor = TrafficMonitor(
        port_start=port_start,
        port_end=port_end,
        output_dir=args.output_dir,
        interface=args.interface,
        pcap_path=args.pcap,
        ai_scorer=ai_scorer,
        ai_threshold=args.ai_threshold,
    )
    monitor.start(max_packets=args.max_packets, duration=args.duration)


if __name__ == "__main__":
    main()
