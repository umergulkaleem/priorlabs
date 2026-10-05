"""Real network capture, flow reconstruction, and live IDS inference."""

from __future__ import annotations

import json
import math
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .ids_agent import IDSAgentError, IDSInvestigator


LIVE_STATE_PATH = Path("results/live_state.json")


def discover_interfaces() -> list[dict[str, str]]:
    """Return usable interfaces visible to Scapy on this host."""
    try:
        from scapy.all import conf, get_if_addr, get_if_list
    except ImportError as error:
        raise IDSAgentError("Live capture requires the 'scapy' package.") from error

    interfaces = []
    for name in get_if_list():
        try:
            address = get_if_addr(name)
        except Exception:
            continue
        if not address or address == "0.0.0.0" or address.startswith("169.254.") or address == "127.0.0.1":
            continue
        details = conf.ifaces.get(name)
        friendly_name = str(getattr(details, "name", "") or name)
        interfaces.append({
            "name": str(name),
            "display_name": friendly_name,
            "ip_address": str(address),
            "status": "Available",
        })
    if not interfaces:
        raise IDSAgentError(
            "No usable network interfaces were found. Install Npcap on Windows or grant capture permissions."
        )
    return interfaces


@dataclass
class _Flow:
    flow_id: int
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str
    started: float
    last_seen: float
    packet_count: int = 0
    byte_count: int = 0
    forward_packets: int = 0
    backward_packets: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    packet_lengths: list[int] = field(default_factory=list)
    forward_lengths: list[int] = field(default_factory=list)
    backward_lengths: list[int] = field(default_factory=list)
    packet_times: list[float] = field(default_factory=list)
    tcp_flags: defaultdict[str, int] = field(default_factory=lambda: defaultdict(int))

    def update(self, timestamp: float, length: int, forward: bool, flags: list[str]) -> None:
        self.last_seen = timestamp
        self.packet_count += 1
        self.byte_count += length
        self.packet_lengths.append(length)
        self.packet_times.append(timestamp)
        if forward:
            self.forward_packets += 1
            self.forward_bytes += length
            self.forward_lengths.append(length)
        else:
            self.backward_packets += 1
            self.backward_bytes += length
            self.backward_lengths.append(length)
        for flag in flags:
            self.tcp_flags[flag] += 1


def _mean(values: list[float]) -> float:
    return float(sum(values) / len(values)) if values else 0.0


def _std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = _mean(values)
    return float(math.sqrt(sum((value - mean) ** 2 for value in values) / len(values)))


def flow_features(flow: _Flow) -> dict[str, float]:
    """Map observable flow statistics to the CICIDS numeric schema.

    Values that require payload inspection or TCP state unavailable in a
    capture are explicitly represented as zero, never fabricated.
    """
    duration_us = max(0.0, flow.last_seen - flow.started) * 1_000_000
    packet_lengths = [float(value) for value in flow.packet_lengths]
    fwd = [float(value) for value in flow.forward_lengths]
    bwd = [float(value) for value in flow.backward_lengths]
    iats = [
        (flow.packet_times[index] - flow.packet_times[index - 1]) * 1_000_000
        for index in range(1, len(flow.packet_times))
    ]
    fwd_iats = [
        (flow.packet_times[index] - flow.packet_times[index - 1]) * 1_000_000
        for index in range(1, len(flow.packet_times))
    ]
    packets_per_second = flow.packet_count / max(flow.last_seen - flow.started, 1e-6)
    bytes_per_second = flow.byte_count / max(flow.last_seen - flow.started, 1e-6)
    flags = flow.tcp_flags
    features: dict[str, float] = {
        "Destination Port": float(flow.destination_port),
        "Flow Duration": duration_us,
        "Total Fwd Packets": float(flow.forward_packets),
        "Total Backward Packets": float(flow.backward_packets),
        "Total Length of Fwd Packets": float(flow.forward_bytes),
        "Total Length of Bwd Packets": float(flow.backward_bytes),
        "Fwd Packet Length Max": max(fwd, default=0.0),
        "Fwd Packet Length Min": min(fwd, default=0.0),
        "Fwd Packet Length Mean": _mean(fwd),
        "Fwd Packet Length Std": _std(fwd),
        "Bwd Packet Length Max": max(bwd, default=0.0),
        "Bwd Packet Length Min": min(bwd, default=0.0),
        "Bwd Packet Length Mean": _mean(bwd),
        "Bwd Packet Length Std": _std(bwd),
        "Flow Bytes/s": bytes_per_second,
        "Flow Packets/s": packets_per_second,
        "Flow IAT Mean": _mean(iats),
        "Flow IAT Std": _std(iats),
        "Flow IAT Max": max(iats, default=0.0),
        "Flow IAT Min": min(iats, default=0.0),
        "Fwd IAT Total": sum(fwd_iats),
        "Fwd IAT Mean": _mean(fwd_iats),
        "Fwd IAT Std": _std(fwd_iats),
        "Fwd IAT Max": max(fwd_iats, default=0.0),
        "Fwd IAT Min": min(fwd_iats, default=0.0),
        "Bwd IAT Total": 0.0,
        "Bwd IAT Mean": 0.0,
        "Bwd IAT Std": 0.0,
        "Bwd IAT Max": 0.0,
        "Bwd IAT Min": 0.0,
        "Fwd Header Length": float(flow.forward_packets * 20),
        "Fwd Header Length.1": float(flow.forward_packets * 20),
        "Bwd Header Length": float(flow.backward_packets * 20),
        "Fwd Packets/s": flow.forward_packets / max(flow.last_seen - flow.started, 1e-6),
        "Bwd Packets/s": flow.backward_packets / max(flow.last_seen - flow.started, 1e-6),
        "Min Packet Length": min(packet_lengths, default=0.0),
        "Max Packet Length": max(packet_lengths, default=0.0),
        "Packet Length Mean": _mean(packet_lengths),
        "Packet Length Std": _std(packet_lengths),
        "Packet Length Variance": _std(packet_lengths) ** 2,
        "FIN Flag Count": float(flags["F"]),
        "SYN Flag Count": float(flags["S"]),
        "RST Flag Count": float(flags["R"]),
        "PSH Flag Count": float(flags["P"]),
        "ACK Flag Count": float(flags["A"]),
        "URG Flag Count": float(flags["U"]),
        "Average Packet Size": _mean(packet_lengths),
        "Avg Fwd Segment Size": _mean(fwd),
        "Avg Bwd Segment Size": _mean(bwd),
        "Down/Up Ratio": flow.backward_packets / max(flow.forward_packets, 1),
        "Subflow Fwd Packets": float(flow.forward_packets),
        "Subflow Fwd Bytes": float(flow.forward_bytes),
        "Subflow Bwd Packets": float(flow.backward_packets),
        "Subflow Bwd Bytes": float(flow.backward_bytes),
        "act_data_pkt_fwd": float(flow.forward_packets),
        "min_seg_size_forward": min(fwd, default=0.0),
        "Active Mean": duration_us,
        "Active Std": 0.0,
        "Active Max": duration_us,
        "Active Min": duration_us,
        "Idle Mean": 0.0,
        "Idle Std": 0.0,
        "Idle Max": 0.0,
        "Idle Min": 0.0,
    }
    # These CICIDS columns need payload/window/bulk inspection not exposed by
    # this lightweight flow collector. Zero is an explicit unavailable value.
    for name in (
        "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
        "CWE Flag Count", "ECE Flag Count", "Fwd Avg Bytes/Bulk",
        "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk",
        "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Init_Win_bytes_forward",
        "Init_Win_bytes_backward",
    ):
        features.setdefault(name, 0.0)
    return features


class LiveNetworkMonitor:
    """Threaded real-packet monitor shared by the UI and persisted MCP state."""

    def __init__(self, agent: IDSInvestigator, state_path: Path = LIVE_STATE_PATH) -> None:
        self.agent = agent
        self.state_path = state_path
        self._lock = threading.RLock()
        self._write_lock = threading.Lock()
        self._sniffer: Any = None
        self._flows: dict[tuple[Any, ...], _Flow] = {}
        self._completed: list[dict[str, Any]] = []
        self._active_interface: str | None = None
        self._packets = 0
        self._next_flow_id = 1
        self._last_error: str | None = None
        self._last_state_write = 0.0
        self._live_predictions_used = 0
        self._window_generation = 0

    @property
    def monitoring(self) -> bool:
        return self._sniffer is not None

    def start(self, interface: str) -> None:
        if self.monitoring:
            return
        if self.agent.state is None:
            raise IDSAgentError("Train the TabPFN model in Dataset Analysis before starting live monitoring.")
        try:
            from scapy.all import AsyncSniffer
            self._sniffer = AsyncSniffer(iface=interface, prn=self._packet_callback, store=False)
            self._sniffer.start()
        except Exception as error:
            self._sniffer = None
            raise IDSAgentError(
                "Unable to capture packets. The application may lack permission for this interface "
                "or Npcap/libpcap may not be installed."
            ) from error
        self._active_interface = interface
        self._last_error = None
        self._live_predictions_used = 0
        self._write_state()

    def stop(self) -> None:
        with self._lock:
            sniffer, self._sniffer = self._sniffer, None
            self._window_generation += 1
            self._flows.clear()
        if sniffer is not None:
            threading.Thread(
                target=self._stop_sniffer,
                args=(sniffer,),
                name="live-network-stop",
                daemon=True,
            ).start()
        self._write_state()

    def _stop_sniffer(self, sniffer: Any) -> None:
        try:
            sniffer.stop()
        except Exception as error:
            with self._lock:
                self._last_error = f"Capture stopped with an error: {error}"
            self._write_state()

    def clear(self) -> None:
        """Start a fresh live window without retraining or changing capture."""
        with self._lock:
            self._flows.clear()
            self._completed.clear()
            self._packets = 0
            self._next_flow_id = 1
            self._last_error = None
            self._live_predictions_used = 0
            self._window_generation += 1
        self._write_state()

    def _packet_callback(self, packet: Any) -> None:
        try:
            from scapy.layers.inet import IP, TCP, UDP
            if not packet.haslayer(IP):
                return
            ip = packet[IP]
            protocol_layer = packet.getlayer(TCP) or packet.getlayer(UDP)
            protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else str(ip.proto)
            source_port = int(getattr(protocol_layer, "sport", 0))
            destination_port = int(getattr(protocol_layer, "dport", 0))
            endpoint_a = (str(ip.src), source_port)
            endpoint_b = (str(ip.dst), destination_port)
            ordered = tuple(sorted((endpoint_a, endpoint_b)))
            key = (protocol, ordered[0], ordered[1])
            timestamp = float(getattr(packet, "time", time.time()))
            with self._lock:
                if self._sniffer is None:
                    return
                self._packets += 1
                flow = self._flows.get(key)
                if flow is None:
                    flow = _Flow(
                        flow_id=self._next_flow_id,
                        source_ip=str(ip.src),
                        source_port=source_port,
                        destination_ip=str(ip.dst),
                        destination_port=destination_port,
                        protocol=protocol,
                        started=timestamp,
                        last_seen=timestamp,
                    )
                    self._next_flow_id += 1
                    self._flows[key] = flow
                forward = (str(ip.src), source_port) == (flow.source_ip, flow.source_port)
                flags = list(str(getattr(packet[TCP], "flags", ""))) if packet.haslayer(TCP) else []
                flow.update(timestamp, len(packet), forward, flags)
                expired = self._expire_flows(timestamp)
                should_write = time.monotonic() - self._last_state_write >= 0.5
                generation = self._window_generation
            for expired_flow in expired:
                self._complete_flow(expired_flow, generation)
            if should_write:
                self._write_state()
        except Exception as error:
            self._last_error = f"Packet processing failed: {error}"

    def _expire_flows(self, now: float) -> list[_Flow]:
        expired: list[_Flow] = []
        for key, flow in list(self._flows.items()):
            if now - flow.last_seen >= 5 or flow.packet_count >= 100:
                expired.append(flow)
                del self._flows[key]
        return expired

    def _complete_flow(self, flow: _Flow, generation: int) -> None:
        features = flow_features(flow)
        record = dict(features)
        try:
            self._live_predictions_used += 1
            prediction = self.agent.predict([record])[0]
            error = None
        except IDSAgentError as caught:
            prediction = None
            error = str(caught)
        result = {
            "flow_id": flow.flow_id,
            "source": f"{flow.source_ip}:{flow.source_port}",
            "destination": f"{flow.destination_ip}:{flow.destination_port}",
            "source_ip": flow.source_ip,
            "destination_ip": flow.destination_ip,
            "source_port": flow.source_port,
            "destination_port": flow.destination_port,
            "protocol": flow.protocol,
            "started_at": datetime.fromtimestamp(flow.started, timezone.utc).isoformat(),
            "last_seen_at": datetime.fromtimestamp(flow.last_seen, timezone.utc).isoformat(),
            "duration_seconds": round(flow.last_seen - flow.started, 6),
            "packet_count": flow.packet_count,
            "bytes": flow.byte_count,
            "features": features,
            "prediction": prediction,
            "error": error,
        }
        with self._lock:
            if generation != self._window_generation:
                return
            self._completed.append(result)
            self._completed = self._completed[-500:]

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            analyzed = [item for item in self._completed if item["prediction"] is not None]
            alerts = [item for item in analyzed if item["prediction"]["is_attack"]]
            active_flows = [
                {
                    "flow_id": flow.flow_id,
                    "source": f"{flow.source_ip}:{flow.source_port}",
                    "destination": f"{flow.destination_ip}:{flow.destination_port}",
                    "protocol": flow.protocol,
                    "packet_count": flow.packet_count,
                    "bytes": flow.byte_count,
                    "active": True,
                }
                for flow in self._flows.values()
            ]
            return {
                "monitoring": self.monitoring,
                "interface": self._active_interface,
                "packets_captured": self._packets,
                "flows_detected": len(self._completed) + len(self._flows),
                "flows_analyzed": len(analyzed),
                "suspicious_flows": len(alerts),
                "live_predictions_used": self._live_predictions_used,
                "last_error": self._last_error,
                "flows": list(reversed(self._completed[-100:])),
                "active_flows": active_flows,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }

    def _write_state(self) -> None:
        with self._write_lock:
            self.state_path.parent.mkdir(exist_ok=True)
            temporary = self.state_path.with_name(
                f".{self.state_path.name}.{threading.get_ident()}.tmp"
            )
            temporary.write_text(json.dumps(self.snapshot(), default=str), encoding="utf-8")
            temporary.replace(self.state_path)
            self._last_state_write = time.monotonic()


def read_live_state(path: Path = LIVE_STATE_PATH) -> dict[str, Any]:
    if not path.is_file():
        return {
            "monitoring": False, "interface": None, "packets_captured": 0,
            "flows_detected": 0, "flows_analyzed": 0, "suspicious_flows": 0,
            "live_predictions_used": 0,
            "flows": [], "active_flows": [], "last_error": None,
        }
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise IDSAgentError(f"Could not read live monitoring state: {error}") from error


def live_flow(state: dict[str, Any], flow_id: int) -> dict[str, Any]:
    for flow in state.get("flows", []):
        if int(flow.get("flow_id", -1)) == flow_id:
            return flow
    raise IDSAgentError(f"Live flow {flow_id} was not found.")
