"""
Flow Manager Service
Handles grouping of packets into bidirectional network flows
"""

import hashlib
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional
from collections import defaultdict
from app.models.schemas import Flow

class FlowManager:
    def __init__(self, timeout_seconds: int = 60):
        self.active_flows: Dict[str, Flow] = {}
        self.closed_flows: List[Flow] = []
        self.timeout_seconds = timeout_seconds
        # Track last seen time for each flow for timeout cleanup
        self.last_seen: Dict[str, datetime] = {}

    def _get_flow_key(self, src_ip: str, src_port: Optional[int], dst_ip: str, dst_port: Optional[int], protocol: str) -> Tuple[Any, ...]:
        """
        Normalize the 5-tuple to ensure bidirectionality.
        A -> B and B -> A map to the same flow.
        """
        # Use 0 for missing ports (e.g. ICMP)
        p1 = (src_ip, src_port or 0)
        p2 = (dst_ip, dst_port or 0)

        # Sort the endpoints lexicographically to create a consistent key
        if p1 < p2:
            return (src_ip, src_port or 0, dst_ip, dst_port or 0, protocol)
        else:
            return (dst_ip, dst_port or 0, src_ip, src_port or 0, protocol)

    def _generate_flow_id(self, flow_key: Tuple) -> str:
        """Generate a unique hash for the normalized flow key."""
        key_str = ":".join(map(str, flow_key))
        return hashlib.sha256(key_str.encode()).hexdigest()[:16]

    def update_flow(self, packet_info: Dict[str, Any]) -> Flow:
        """
        Update existing flow or create a new one based on packet information.
        """
        # 1. Extract 5-tuple and normalize
        src_ip = packet_info.get("source_ip")
        dst_ip = packet_info.get("dest_ip")
        src_port = packet_info.get("source_port")
        dst_port = packet_info.get("dest_port")
        protocol = packet_info.get("protocol", "Unknown")
        timestamp_str = packet_info.get("timestamp")
        size = packet_info.get("size_bytes", 0)

        if not src_ip or not dst_ip:
            # Cannot group packets without IP addresses
            return None

        # Parse timestamp
        try:
            timestamp = datetime.fromisoformat(timestamp_str) if timestamp_str else datetime.now()
        except ValueError:
            timestamp = datetime.now()

        flow_key = self._get_flow_key(src_ip, src_port, dst_ip, dst_port, protocol)
        flow_id = self._generate_flow_id(flow_key)

        # 2. Update/Create Flow
        if flow_id not in self.active_flows:
            # New Flow
            # For new flows, we set the normalized source/dest as defined by _get_flow_key
            norm_src_ip, norm_src_port, norm_dst_ip, norm_dst_port, norm_proto = flow_key

            flow = Flow(
                flow_id=flow_id,
                timestamp=timestamp,
                source_ip=norm_src_ip,
                source_port=norm_src_port,
                dest_ip=norm_dst_ip,
                dest_port=norm_dst_port,
                protocol=norm_proto,
                start_time=timestamp,
                end_time=timestamp,
                total_packets=0,
                total_bytes=0,
                packets_forward=0,
                bytes_forward=0,
                packets_backward=0,
                bytes_backward=0,
                duration=0.0,
                avg_packet_size=0.0,
                status="active"
            )
            self.active_flows[flow_id] = flow
        else:
            flow = self.active_flows[flow_id]
            flow.end_time = timestamp
            flow.duration = (flow.end_time - flow.start_time).total_seconds()

        # 3. Update Directional Statistics
        # Check if this packet is moving from normalized source to normalized dest
        # We must compare against the normalized a-priori source/dest
        is_forward = (src_ip == flow.source_ip and (src_port or 0) == flow.source_port)

        if is_forward:
            flow.packets_forward += 1
            flow.bytes_forward += size
        else:
            flow.packets_backward += 1
            flow.bytes_backward += size

        flow.total_packets += 1
        flow.total_bytes += size
        flow.avg_packet_size = flow.total_bytes / flow.total_packets if flow.total_packets > 0 else 0

        # Update last seen for timeout tracking
        self.last_seen[flow_id] = timestamp

        return flow

    def cleanup_expired_flows(self) -> List[Flow]:
        """
        Move flows that haven't seen activity for timeout_seconds to closed_flows.
        """
        now = datetime.now()
        expired_ids = []

        for flow_id, last_time in self.last_seen.items():
            if (now - last_time).total_seconds() > self.timeout_seconds:
                expired_ids.append(flow_id)

        closed_this_run = []
        for fid in expired_ids:
            flow = self.active_flows.pop(fid, None)
            if flow:
                flow.status = "closed"
                self.closed_flows.append(flow)
                closed_this_run.append(flow)
            self.last_seen.pop(fid, None)

        return closed_this_run

    def get_active_flows(self) -> List[Flow]:
        """Return all currently active flows."""
        return list(self.active_flows.values())

    def get_closed_flows(self) -> List[Flow]:
        """Return all flows that have been closed."""
        return self.closed_flows

    def reset(self):
        """Clear all flow data."""
        self.active_flows.clear()
        self.closed_flows.clear()
        self.last_seen.clear()
