"""
Backend service for real-time 5-second flow aggregation, temporal network state management,
and PyTorch LSTM Attack Forecasting.
"""

import os
import sys
import time
import math
import logging
import statistics
import numpy as np
from collections import deque
from datetime import datetime
from typing import Dict, Any, List, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from inference.forecast import ForecastEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

HIGH_RISK_PORTS = {21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080, 8443}


def extract_27_flow_features(packets_in_window: List[Any], interval_duration: float = 5.0) -> List[float]:
    """
    Extracts the exact 27 canonical flow/traffic features expected by the trained LSTM model
    from a list of packet dicts or raw Scapy Packet objects collected during a 5-second observation interval.
    Matches feature_config.json schema exactly.
    """
    if not packets_in_window:
        return [0.0] * 27

    # Standardize input list to dictionary format
    normalized_packets = []
    for p in packets_in_window:
        if isinstance(p, dict):
            normalized_packets.append(p)
        else:
            # Raw Scapy packet conversion
            size = len(p)
            src_ip, dst_ip = "", ""
            proto = "OTHER"
            src_port, dst_port = 0, 0
            syn, ack, fin = 0, 0, 0
            try:
                if hasattr(p, 'haslayer'):
                    if p.haslayer('IP'):
                        src_ip = getattr(p['IP'], 'src', '')
                        dst_ip = getattr(p['IP'], 'dst', '')
                    elif p.haslayer('IPv6'):
                        src_ip = getattr(p['IPv6'], 'src', '')
                        dst_ip = getattr(p['IPv6'], 'dst', '')
                    if p.haslayer('TCP'):
                        proto = "TCP"
                        src_port = getattr(p['TCP'], 'sport', 0)
                        dst_port = getattr(p['TCP'], 'dport', 0)
                        flags = str(getattr(p['TCP'], 'flags', ''))
                        if 'S' in flags: syn = 1
                        if 'A' in flags: ack = 1
                        if 'F' in flags: fin = 1
                    elif p.haslayer('UDP'):
                        proto = "UDP"
                        src_port = getattr(p['UDP'], 'sport', 0)
                        dst_port = getattr(p['UDP'], 'dport', 0)
            except Exception:
                pass
            normalized_packets.append({
                "size_bytes": size,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "protocol": proto,
                "src_port": src_port,
                "dst_port": dst_port,
                "flag_syn": syn,
                "flag_ack": ack,
                "flag_fin": fin
            })

    packets_in_window = normalized_packets

    tot_pkts = len(packets_in_window)
    sizes = [float(p.get("size_bytes", 64)) for p in packets_in_window]
    total_bytes = sum(sizes)

    # Classify forward (outgoing/local) vs backward (incoming) traffic based on local network pattern
    fwd_pkts = []
    bwd_pkts = []

    for p in packets_in_window:
        src = str(p.get("source_ip", ""))
        # Treat private IP or empty/proxy as forward (local host initiated)
        if not src or src.startswith("10.") or src.startswith("192.168.") or src.startswith("172.") or src == "127.0.0.1":
            fwd_pkts.append(p)
        else:
            bwd_pkts.append(p)

    tot_fwd_cnt = float(len(fwd_pkts)) if fwd_pkts else float(tot_pkts)
    tot_bwd_cnt = float(len(bwd_pkts)) if bwd_pkts else 0.0

    fwd_sizes = [float(p.get("size_bytes", 64)) for p in fwd_pkts] if fwd_pkts else sizes
    bwd_sizes = [float(p.get("size_bytes", 64)) for p in bwd_pkts] if bwd_pkts else [0.0]

    totlen_fwd = sum(fwd_sizes)
    totlen_bwd = sum(bwd_sizes)

    fwd_pkt_len_max = max(fwd_sizes) if fwd_sizes else 0.0
    fwd_pkt_len_mean = statistics.mean(fwd_sizes) if fwd_sizes else 0.0

    bwd_pkt_len_max = max(bwd_sizes) if bwd_sizes else 0.0
    bwd_pkt_len_mean = statistics.mean(bwd_sizes) if bwd_sizes else 0.0

    flow_duration = max(interval_duration, 0.001)
    flow_byts_s = total_bytes / flow_duration
    flow_pkts_s = tot_pkts / flow_duration

    # Parse timestamps for inter-arrival times (IAT)
    timestamps = []
    for p in packets_in_window:
        ts = p.get("timestamp")
        if isinstance(ts, (int, float)):
            timestamps.append(float(ts))
        elif isinstance(ts, str):
            try:
                timestamps.append(datetime.fromisoformat(ts).timestamp())
            except Exception:
                pass

    if len(timestamps) >= 2:
        timestamps.sort()
        iats = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
        flow_iat_mean = statistics.mean(iats)
        flow_iat_std = statistics.stdev(iats) if len(iats) >= 2 else 0.0
    else:
        flow_iat_mean = 0.001
        flow_iat_std = 0.0

    fwd_iat_mean = flow_iat_mean
    bwd_iat_mean = flow_iat_mean / 2.0 if tot_bwd_cnt > 0 else 0.0

    # TCP flags counting
    syn_cnt = 0.0
    ack_cnt = 0.0
    rst_cnt = 0.0
    fin_cnt = 0.0
    psh_cnt = 0.0

    tcp_count = 0
    udp_count = 0
    high_risk_port_active = 0.0

    for p in packets_in_window:
        flags = p.get("flags", []) or []
        if isinstance(flags, str):
            flags = [flags]

        flags_upper = [str(f).upper() for f in flags]
        if any("SYN" in f for f in flags_upper):
            syn_cnt += 1.0
        if any("ACK" in f for f in flags_upper):
            ack_cnt += 1.0
        if any("RST" in f for f in flags_upper):
            rst_cnt += 1.0
        if any("FIN" in f for f in flags_upper):
            fin_cnt += 1.0
        if any("PSH" in f for f in flags_upper):
            psh_cnt += 1.0

        proto = str(p.get("protocol", "")).upper()
        if proto == "TCP":
            tcp_count += 1
        elif proto == "UDP":
            udp_count += 1

        dport = p.get("dest_port")
        if dport and int(dport) in HIGH_RISK_PORTS:
            high_risk_port_active = 1.0

    pkt_len_mean = statistics.mean(sizes) if sizes else 0.0
    pkt_len_std = statistics.stdev(sizes) if len(sizes) >= 2 else 0.0

    down_up_ratio = tot_bwd_cnt / max(tot_fwd_cnt, 1.0)
    protocol_tcp = 1.0 if tcp_count >= udp_count else 0.0
    protocol_udp = 1.0 if udp_count > tcp_count else 0.0
    fwd_bwd_bytes_ratio = totlen_fwd / max(totlen_bwd, 1.0)

    # Return canonical 27-feature array
    return [
        flow_duration,
        tot_fwd_cnt,
        tot_bwd_cnt,
        totlen_fwd,
        totlen_bwd,
        fwd_pkt_len_max,
        fwd_pkt_len_mean,
        bwd_pkt_len_max,
        bwd_pkt_len_mean,
        flow_byts_s,
        flow_pkts_s,
        flow_iat_mean,
        flow_iat_std,
        fwd_iat_mean,
        bwd_iat_mean,
        syn_cnt,
        ack_cnt,
        rst_cnt,
        fin_cnt,
        psh_cnt,
        pkt_len_mean,
        pkt_len_std,
        down_up_ratio,
        protocol_tcp,
        protocol_udp,
        high_risk_port_active,
        fwd_bwd_bytes_ratio,
    ]


class ForecastService:
    def __init__(self, window_size: int = 30, interval_seconds: float = 5.0):
        self.engine = ForecastEngine()
        self.window_size = window_size
        self.interval_seconds = interval_seconds
        
        # Deque of 5-second network state feature vectors (maximum 30)
        self.state_history: deque = deque(maxlen=window_size)
        self.last_bucket_time: float = time.time()
        self.current_bucket_packets: List[Dict[str, Any]] = []
        
        # Mode indicator: "live" or "simulation"
        self.mode = "live"

    def process_live_packets(self, packets: List[Dict[str, Any]]) -> None:
        """
        Groups live captured packets into 5-second observation buckets,
        extracts 27 flow features per bucket, and updates chronological state_history.
        """
        self.mode = "live"
        now = time.time()

        # Check if 5-second bucket interval has elapsed
        if now - self.last_bucket_time >= self.interval_seconds:
            window_packets = []
            if packets:
                for p in packets:
                    ts = p.get("timestamp")
                    if ts:
                        try:
                            if isinstance(ts, (int, float)):
                                p_time = float(ts)
                            else:
                                p_time = datetime.fromisoformat(ts).timestamp()
                            if p_time >= self.last_bucket_time:
                                window_packets.append(p)
                        except Exception:
                            window_packets.append(p)
                    else:
                        window_packets.append(p)

            # Extract 27-feature state for this 5-second window
            features = extract_27_flow_features(window_packets, self.interval_seconds)
            self.state_history.append(features)
            
            # Reset bucket for next 5 seconds
            self.current_bucket_packets = []
            self.last_bucket_time = now

    def add_packet_features(self, packet_data: Any) -> None:
        """
        Appends packet snapshot or 27-feature vector to state_history.
        """
        self.mode = "live"
        if isinstance(packet_data, list) and len(packet_data) == 27:
            self.state_history.append([float(x) for x in packet_data])
        elif isinstance(packet_data, dict):
            features = extract_27_flow_features([packet_data], self.interval_seconds)
            self.state_history.append(features)


    def get_forecast(self, packets: Optional[List[Dict[str, Any]]] = None, custom_window: Optional[List[List[float]]] = None) -> Dict[str, Any]:
        """
        Returns PyTorch LSTM forecast for current computer traffic or simulation window.
        Returns status='collecting' with progress if < 30 states exist in Live Mode.
        """
        # Scenario A: Simulation / Custom Window passed
        if custom_window and len(custom_window) >= self.window_size:
            seq = np.array(custom_window[-self.window_size:], dtype=np.float32)
            result = self.engine.forecast(seq)
            return {
                "status": "success",
                "mode": "simulation",
                "collected_states": self.window_size,
                "required_states": self.window_size,
                **result
            }

        # Scenario B: Live Traffic processing
        if packets is not None:
            self.process_live_packets(packets)

        if not self.engine.model:
            return {
                "status": "error",
                "mode": self.mode,
                "collected_states": len(self.state_history),
                "required_states": self.window_size,
                "message": "AI model unavailable",
                "error": "PyTorch LSTM model artifact (world_model.pth) or scaler.pkl could not be loaded."
            }

        if len(self.state_history) == 0:
            return {
                "status": "no_data",
                "mode": self.mode,
                "collected_states": 0,
                "required_states": self.window_size,
                "message": "No live traffic data available",
                "current_probability": None,
                "forecast": [],
                "predicted_stage": "Awaiting Traffic",
                "stage_confidence": 0.0,
                "top_features": []
            }

        if len(self.state_history) < self.window_size:
            count = len(self.state_history)
            return {
                "status": "collecting",
                "mode": self.mode,
                "collected_states": count,
                "required_states": self.window_size,
                "message": f"Collecting traffic history: {count}/{self.window_size} states",
                "current_probability": None,
                "forecast": [],
                "predicted_stage": f"Collecting Data ({count}/{self.window_size})",
                "stage_confidence": round(count / self.window_size, 2),
                "top_features": []
            }

        # Full 30-state history available -> Run PyTorch LSTM Inference
        seq = np.array(list(self.state_history), dtype=np.float32)
        result = self.engine.forecast(seq)

        return {
            "status": "success",
            "mode": self.mode,
            "collected_states": self.window_size,
            "required_states": self.window_size,
            **result
        }
