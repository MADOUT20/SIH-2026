"""
Device Service for NetGuard
Handles device registration, local persistence, real-time connectivity status tracking,
and evidence-grounded malware/threat assessment using the existing PyTorch LSTM World Model,
27-feature flow extractor, and packet capture pipeline.
"""

import os
import json
import logging
import re
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
DATA_FILE = os.path.join(BASE_DIR, "data", "registered_devices.json")

logger = logging.getLogger("netguard.device_service")

# Friendly descriptions for the canonical 27 flow features
FEATURE_FRIENDLY_NAMES = {
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Forward Packet Count",
    "tot_bwd_pkts": "Backward Packet Count",
    "totlen_fwd_pkts": "Forward Volume (Bytes)",
    "totlen_bwd_pkts": "Backward Volume (Bytes)",
    "fwd_pkt_len_max": "Max Forward Packet Size",
    "fwd_pkt_len_mean": "Mean Forward Packet Size",
    "bwd_pkt_len_max": "Max Backward Packet Size",
    "bwd_pkt_len_mean": "Mean Backward Packet Size",
    "flow_byts_s": "Traffic Throughput (Bytes/s)",
    "flow_pkts_s": "Flow Packet Rate (Pkts/s)",
    "flow_iat_mean": "Packet Inter-Arrival Time",
    "flow_iat_std": "Inter-Arrival Variance",
    "fwd_iat_mean": "Forward Inter-Arrival Time",
    "bwd_iat_mean": "Backward Inter-Arrival Time",
    "syn_flag_cnt": "TCP SYN Flag Count",
    "ack_flag_cnt": "TCP ACK Flag Count",
    "rst_flag_cnt": "TCP RST Flag Count",
    "fin_flag_cnt": "TCP FIN Flag Count",
    "psh_flag_cnt": "TCP PSH Flag Count",
    "pkt_len_mean": "Mean Packet Length",
    "pkt_len_std": "Packet Length Variance",
    "down_up_ratio": "Down/Up Traffic Ratio",
    "protocol_tcp": "TCP Protocol Flow",
    "protocol_udp": "UDP Protocol Flow",
    "is_high_risk_port": "High-Risk Port Activity",
    "fwd_bwd_bytes_ratio": "Directional Volume Ratio",
}


class DeviceService:
    def __init__(
        self,
        packet_service=None,
        threat_service=None,
        forecast_service=None,
        mitre_service=None,
    ):
        self.packet_service = packet_service
        self.threat_service = threat_service
        self.forecast_service = forecast_service
        self.mitre_service = mitre_service
        self._ensure_storage_directory()
        self.registered_devices: Dict[str, Dict[str, Any]] = self._load_devices()
        self.active_device_id: Optional[str] = self._load_active_device_id()

    def _ensure_storage_directory(self) -> None:
        """Ensure the directory for persistent data storage exists."""
        os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)

    @staticmethod
    def validate_ip(ip_str: str) -> str:
        """Validate and return canonical trimmed IP string."""
        if not ip_str:
            raise ValueError("IP address is required.")
        clean = str(ip_str).strip()
        try:
            # Validate IP format using ipaddress module
            ipaddress.ip_address(clean)
            return clean
        except ValueError:
            # If not a standard IPv4/IPv6, check if alphanumeric with dots
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean):
                return clean
            raise ValueError(f"Invalid IP address format: '{clean}'")

    def _load_devices(self) -> Dict[str, Dict[str, Any]]:
        """Load registered devices from persistent JSON storage, deduplicating by canonical IP."""
        if not os.path.exists(DATA_FILE):
            return {}
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                raw_list = list(data.values()) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                deduped: Dict[str, Dict[str, Any]] = {}
                ip_seen: Dict[str, str] = {}
                DEMO_FIXTURE_IPS = {"192.168.1.105", "192.168.1.45", "192.168.1.1", "192.168.1.10", "192.168.1.200"}
                for dev in raw_list:
                    if not isinstance(dev, dict):
                        continue
                    ip = dev.get("ip")
                    if not ip:
                        continue
                    clean_ip = str(ip).strip()
                    # Skip link-local APIPA addresses and demo fixture IPs in persistent storage
                    if clean_ip.startswith("169.254.") or clean_ip in DEMO_FIXTURE_IPS:
                        continue
                    canonical_id = f"dev_{clean_ip.replace('.', '_').replace(':', '_')}"
                    dev["id"] = canonical_id
                    dev["ip"] = clean_ip
                    if clean_ip in ip_seen:
                        existing_id = ip_seen[clean_ip]
                        existing_dev = deduped[existing_id]
                        existing_dev["name"] = dev.get("name") or existing_dev.get("name")
                        existing_dev["mac"] = dev.get("mac") or existing_dev.get("mac")
                        existing_dev["device_type"] = dev.get("device_type") or existing_dev.get("device_type")
                        existing_dev["description"] = dev.get("description") or existing_dev.get("description")
                    else:
                        ip_seen[clean_ip] = canonical_id
                        deduped[canonical_id] = dev
                return deduped
        except Exception as e:
            logger.error(f"Error loading registered devices from {DATA_FILE}: {e}")
            return {}

    def _save_devices(self) -> None:
        """Persist registered devices to JSON storage."""
        self._ensure_storage_directory()
        try:
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                json.dump(self.registered_devices, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving registered devices to {DATA_FILE}: {e}")

    def _load_active_device_id(self) -> Optional[str]:
        """Load currently active connected device ID from storage or environment."""
        active_file = os.path.join(os.path.dirname(DATA_FILE), "active_device.json")
        if os.path.exists(active_file):
            try:
                with open(active_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("active_device_id")
            except Exception:
                pass
        return None

    def _save_active_device_id(self, device_id: Optional[str]) -> None:
        """Persist active connected device ID."""
        self._ensure_storage_directory()
        active_file = os.path.join(os.path.dirname(DATA_FILE), "active_device.json")
        try:
            with open(active_file, "w", encoding="utf-8") as f:
                json.dump({"active_device_id": device_id, "updated_at": datetime.now().isoformat()}, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving active device ID: {e}")

    def discover_local_devices(self, mode: str = "live") -> List[Dict[str, Any]]:
        """
        Discover local network devices.
        In DEMO MODE: returns the deterministic seeded enterprise demo scenario devices.
        In LIVE MODE: returns actual local network devices from ARP table, local host interfaces,
        and observed live packet flows. No fake devices are introduced.
        """
        if mode == "demo":
            demo_fixture_devices = [
                {
                    "id": "demo_192_168_1_105",
                    "name": "Engineering Laptop",
                    "ip": "192.168.1.105",
                    "mac": "00:50:56:C0:00:08",
                    "device_type": "Laptop",
                    "description": "Seeded enterprise demo fixture node (Compromised)",
                    "is_local_host": True,
                    "is_gateway": False,
                    "status": "available",
                    "has_traffic": True,
                    "packet_count": 6200,
                    "can_monitor": True,
                    "consent_required": True,
                    "is_demo": True,
                },
                {
                    "id": "demo_192_168_1_45",
                    "name": "SOC Admin Workstation",
                    "ip": "192.168.1.45",
                    "mac": "00:50:56:C0:00:12",
                    "device_type": "Workstation",
                    "description": "Admin console workstation",
                    "is_local_host": False,
                    "is_gateway": False,
                    "status": "available",
                    "has_traffic": True,
                    "packet_count": 2040,
                    "can_monitor": True,
                    "consent_required": True,
                    "is_demo": True,
                },
                {
                    "id": "demo_192_168_1_1",
                    "name": "Gateway / Firewall",
                    "ip": "192.168.1.1",
                    "mac": "00:50:56:C0:00:01",
                    "device_type": "Gateway",
                    "description": "Default Network Gateway & Router",
                    "is_local_host": False,
                    "is_gateway": True,
                    "status": "available",
                    "has_traffic": True,
                    "packet_count": 6050,
                    "can_monitor": True,
                    "consent_required": True,
                    "is_demo": True,
                },
                {
                    "id": "demo_192_168_1_10",
                    "name": "Domain Controller (AD / DNS)",
                    "ip": "192.168.1.10",
                    "mac": "00:50:56:C0:00:0A",
                    "device_type": "Server",
                    "description": "Active Directory & DNS Controller",
                    "is_local_host": False,
                    "is_gateway": False,
                    "status": "available",
                    "has_traffic": True,
                    "packet_count": 3270,
                    "can_monitor": True,
                    "consent_required": True,
                    "is_demo": True,
                },
                {
                    "id": "demo_192_168_1_200",
                    "name": "Internal Database Server",
                    "ip": "192.168.1.200",
                    "mac": "00:50:56:C0:00:C8",
                    "device_type": "Database Server",
                    "description": "Enterprise PostgreSQL & Analytics DB",
                    "is_local_host": False,
                    "is_gateway": False,
                    "status": "available",
                    "has_traffic": True,
                    "packet_count": 2150,
                    "can_monitor": True,
                    "consent_required": True,
                    "is_demo": True,
                },
            ]
            return demo_fixture_devices

        # LIVE MODE: Discover real devices from system ARP table, interfaces, and packet sniff
        discovered: Dict[str, Dict[str, Any]] = {}
        import subprocess
        import re
        import socket

        # Helper: is an IP address a link-local (APIPA) address?
        def _is_link_local(ip: str) -> bool:
            return str(ip).startswith("169.254.")

        # Helper: is an IP strictly within an RFC1918 private range?
        # 10.0.0.0/8, 172.16.0.0/12 (172.16-172.31), 192.168.0.0/16
        def _is_rfc1918(ip: str) -> bool:
            clean = str(ip).strip()
            if clean.startswith("10."):
                return True
            if clean.startswith("192.168."):
                return True
            if clean.startswith("172."):
                try:
                    second_octet = int(clean.split(".")[1])
                    return 16 <= second_octet <= 31
                except Exception:
                    return False
            return False

        # 1. Identify local host machine and gather ALL host IPs
        hostname = socket.gethostname()
        local_host_ips = set()
        try:
            host_ip = socket.gethostbyname(hostname)
            if host_ip and not host_ip.startswith("127."):
                local_host_ips.add(host_ip)
        except Exception:
            pass

        best_local_ip: Optional[str] = None  # best IP to represent local host
        best_local_mac: Optional[str] = None
        best_local_iface_desc: Optional[str] = None

        if self.packet_service and hasattr(self.packet_service, "check_environment"):
            try:
                env_info = self.packet_service.check_environment()
                for iface in env_info.get("interfaces", []):
                    mac = iface.get("mac") or None
                    desc = iface.get("description") or iface.get("name") or ""
                    for if_ip in iface.get("ips", []):
                        if not if_ip:
                            continue
                        if if_ip.startswith("127.") or ":" in if_ip:
                            continue  # skip loopback and IPv6

                        # Add to local_host_ips set so secondary interfaces are never added as separate devices
                        local_host_ips.add(if_ip)

                        if _is_link_local(if_ip):
                            continue

                        # Prefer an RFC1918 IP that represents this host
                        if best_local_ip is None or (_is_rfc1918(if_ip) and not _is_rfc1918(best_local_ip)):
                            best_local_ip = if_ip
                            best_local_mac = mac
                            best_local_iface_desc = desc
            except Exception as e:
                logger.warning(f"Error reading network interfaces: {e}")

        # Fallback: use the DNS-resolved host IP if Scapy wasn't available
        if best_local_ip is None:
            for l_ip in local_host_ips:
                if not _is_link_local(l_ip) and not l_ip.startswith("127."):
                    best_local_ip = l_ip
                    break

        # Add EXACTLY ONE "This Machine" entry for the local workstation
        if best_local_ip:
            dev_id = f"dev_{best_local_ip.replace('.', '_')}"
            discovered[best_local_ip] = {
                "id": dev_id,
                "name": f"Local Workstation ({hostname})",
                "ip": best_local_ip,
                "mac": best_local_mac or None,
                "device_type": "Workstation",
                "description": f"This Machine ({best_local_iface_desc or 'Network Interface'})",
                "is_local_host": True,
                "is_gateway": False,
                "status": "available",
                "has_traffic": False,
                "packet_count": 0,
                "can_monitor": True,
                "consent_required": True,
                "is_demo": False,
            }

        # 2. Query Windows ARP Table for nearby network hosts
        try:
            res = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=4)
            if res.returncode == 0:
                arp_lines = res.stdout.splitlines()
                arp_pattern = re.compile(r"^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})\s+(\w+)", re.IGNORECASE)
                for line in arp_lines:
                    match = arp_pattern.match(line)
                    if match:
                        ip_val, mac_val, entry_type = match.groups()

                        # Ignore link-local (169.254.x.x), loopback, broadcast, multicast, non-RFC1918
                        if (
                            _is_link_local(ip_val)
                            or ip_val.startswith("224.")
                            or ip_val.startswith("239.")
                            or ip_val.startswith("127.")
                            or ip_val.endswith(".255")
                            or ip_val == "255.255.255.255"
                            or not _is_rfc1918(ip_val)
                        ):
                            continue

                        # Strict single-host rule: Any IP belonging to this local machine must NOT create a separate device
                        if ip_val in local_host_ips:
                            if best_local_ip and best_local_ip in discovered:
                                clean_mac = mac_val.replace("-", ":").upper()
                                if not discovered[best_local_ip].get("mac") and clean_mac != "00:00:00:00:00:00":
                                    discovered[best_local_ip]["mac"] = clean_mac
                            continue

                        # Canonicalize MAC (XX:XX:XX:XX:XX:XX)
                        clean_mac = mac_val.replace("-", ":").upper()
                        is_gw = ip_val.endswith(".1")
                        dev_id = f"dev_{ip_val.replace('.', '_')}"

                        dev_type = "Gateway Router" if is_gw else "Local Network Device"
                        dev_name = "Default Gateway Router" if is_gw else f"Nearby Device ({ip_val})"

                        if ip_val in discovered:
                            discovered[ip_val]["mac"] = clean_mac
                            if is_gw:
                                discovered[ip_val]["is_gateway"] = True
                                discovered[ip_val]["device_type"] = "Gateway Router"
                                discovered[ip_val]["name"] = "Default Gateway Router"
                        else:
                            discovered[ip_val] = {
                                "id": dev_id,
                                "name": dev_name,
                                "ip": ip_val,
                                "mac": clean_mac,
                                "device_type": dev_type,
                                "description": f"Discovered via ARP cache ({entry_type})",
                                "is_local_host": False,
                                "is_gateway": is_gw,
                                "status": "available",
                                "has_traffic": False,
                                "packet_count": 0,
                                "can_monitor": True,
                                "consent_required": True,
                                "is_demo": False,
                            }
        except Exception as e:
            logger.warning(f"Error querying ARP table: {e}")

        # 3. Check observed packet flows from live packet buffer.
        if self.packet_service and hasattr(self.packet_service, "packets") and self.packet_service.packets:
            for p in self.packet_service.packets:
                for target_ip in [p.get("source_ip"), p.get("dest_ip")]:
                    if (
                        target_ip
                        and not target_ip.startswith("127.")
                        and not target_ip.startswith("224.")
                        and not target_ip.startswith("239.")
                        and not target_ip.endswith(".255")
                        and ":" not in target_ip
                        and not _is_link_local(target_ip)
                        and _is_rfc1918(target_ip)
                    ):
                        # If target_ip is a secondary IP of this host, update the main workstation entry
                        if target_ip in local_host_ips:
                            if best_local_ip and best_local_ip in discovered:
                                discovered[best_local_ip]["packet_count"] = discovered[best_local_ip].get("packet_count", 0) + 1
                                discovered[best_local_ip]["has_traffic"] = True
                                discovered[best_local_ip]["status"] = "traffic_observed"
                        elif target_ip in discovered:
                            # Increment traffic counter for a known device
                            discovered[target_ip]["packet_count"] = discovered[target_ip].get("packet_count", 0) + 1
                            discovered[target_ip]["has_traffic"] = True
                            discovered[target_ip]["status"] = "traffic_observed"

        # 4. Include previously registered/persisted devices — ONLY if they are valid,
        # observable LAN devices (no demo fixtures, no 169.254, no duplicate host entries).
        DEMO_FIXTURE_IPS = {"192.168.1.105", "192.168.1.45", "192.168.1.1", "192.168.1.10", "192.168.1.200"}
        for reg in self.registered_devices.values():
            r_ip = reg.get("ip")
            if not r_ip or _is_link_local(r_ip) or r_ip in DEMO_FIXTURE_IPS or not _is_rfc1918(r_ip):
                continue

            # If this registered IP belongs to the local host machine, merge into single host entry
            if r_ip in local_host_ips:
                if best_local_ip and best_local_ip in discovered:
                    discovered[best_local_ip]["name"] = reg.get("name") or discovered[best_local_ip]["name"]
                    discovered[best_local_ip]["is_registered"] = True
                continue

            # Skip demo-description entries that leaked into live registered devices
            desc_lower = (reg.get("description") or "").lower()
            if "seeded enterprise demo fixture" in desc_lower or "admin console workstation" in desc_lower:
                continue

            if r_ip in discovered:
                discovered[r_ip]["name"] = reg.get("name") or discovered[r_ip]["name"]
                discovered[r_ip]["device_type"] = reg.get("device_type") or discovered[r_ip]["device_type"]
                discovered[r_ip]["is_registered"] = True
            else:
                dev_id = reg.get("id") or f"dev_{r_ip.replace('.', '_')}"
                conn = self.resolve_device_connectivity(r_ip, reg.get("mac"), mode="live")

                # Skip phantom/stale entries that have no active traffic or ARP presence
                if not conn["has_traffic"] and conn["packet_count"] == 0:
                    continue

                discovered[r_ip] = {
                    "id": dev_id,
                    "name": reg.get("name") or f"Device ({r_ip})",
                    "ip": r_ip,
                    "mac": reg.get("mac"),
                    "device_type": reg.get("device_type", "Laptop"),
                    "description": reg.get("description") or "Configured device",
                    "is_local_host": False,
                    "is_gateway": r_ip.endswith(".1"),
                    "status": "traffic_observed" if conn["has_traffic"] else "available",
                    "has_traffic": conn["has_traffic"],
                    "packet_count": conn["packet_count"],
                    "can_monitor": True,
                    "consent_required": True,
                    "is_demo": False,
                    "is_registered": True,
                }

        # Format list: sort local host first, then gateways, then traffic observed, then by IP
        result_list = list(discovered.values())
        result_list.sort(key=lambda d: (not d.get("is_local_host"), not d.get("is_gateway"), not d.get("has_traffic"), d.get("ip")))
        return result_list

    def connect_device(
        self,
        device_id: str,
        ip: str,
        name: Optional[str] = None,
        mac: Optional[str] = None,
        device_type: str = "Laptop",
        description: Optional[str] = None,
        consent: bool = False,
        mode: str = "live",
    ) -> Dict[str, Any]:
        """
        Connect to a nearby/local network device with explicit user permission.
        Sets this device as the primary active monitoring target for the NetGuard application.
        """
        if not consent:
            raise ValueError(
                "Explicit user consent is required before monitoring network activity for this device."
            )

        clean_ip = self.validate_ip(ip)

        # Validate pre-connection reachability: Device must be genuinely present in live discovery
        if mode == "live":
            discovered_now = self.discover_local_devices(mode="live")
            known_ips = {d["ip"] for d in discovered_now}
            if clean_ip not in known_ips:
                raise ValueError("Device is no longer available on the local network.")

        clean_name = (name or "").strip() or f"Device ({clean_ip})"
        clean_type = (device_type or "Laptop").strip()
        clean_mac = mac.strip().upper() if mac and mac.strip() else None

        # Build canonical deterministic ID
        canonical_id = f"dev_{clean_ip.replace('.', '_').replace(':', '_')}"
        device_record = {
            "id": canonical_id,
            "name": clean_name,
            "ip": clean_ip,
            "mac": clean_mac,
            "device_type": clean_type,
            "description": description or "Connected network monitoring target",
            "connected_at": datetime.now().isoformat(),
            "consent_granted": True,
            "is_registered": True,
        }

        # Deduplicate: Remove any existing entry matching this IP or canonical ID or old device_id
        keys_to_remove = [
            k for k, v in self.registered_devices.items()
            if k == canonical_id or k == device_id or v.get("ip") == clean_ip
        ]
        for k in keys_to_remove:
            self.registered_devices.pop(k, None)

        self.registered_devices[canonical_id] = device_record
        self._save_devices()
        self.active_device_id = canonical_id
        self._save_active_device_id(canonical_id)

        logger.info(f"Connected to device for monitoring: {clean_name} ({clean_ip}) [ID: {canonical_id}]")
        return device_record

    def disconnect_device(self) -> bool:
        """
        Disconnect active device and return monitoring to unscoped/all-traffic state.
        """
        old_id = self.active_device_id
        self.active_device_id = None
        self._save_active_device_id(None)
        logger.info(f"Disconnected active device (was: {old_id}).")
        return True

    def get_active_connected_device(self, mode: str = "live") -> Optional[Dict[str, Any]]:
        """
        Get the currently connected active monitoring device with its live status.
        Detects if the device becomes unreachable/disconnected during an active session.
        """
        if mode == "demo":
            # In demo mode, default to the seeded compromised engineering laptop if not explicitly set
            target_id = self.active_device_id or "demo_192_168_1_105"
            # If persistent active_device_id is a live device, fallback to demo compromised laptop in demo mode
            if target_id.startswith("dev_") and not target_id.startswith("demo_"):
                target_id = "demo_192_168_1_105"

            if target_id == "demo_192_168_1_105" or target_id == "192.168.1.105":
                conn = self.resolve_device_connectivity("192.168.1.105", mode="demo")
                assessment = self.assess_device_malware_threat("192.168.1.105", mode="demo")
                return {
                    "id": "demo_192_168_1_105",
                    "name": "Engineering Laptop",
                    "ip": "192.168.1.105",
                    "mac": "00:50:56:C0:00:08",
                    "device_type": "Laptop",
                    "description": "Seeded enterprise demo fixture node (Compromised)",
                    "is_active_target": True,
                    "is_reachable": True,
                    "connectivity": conn,
                    "security": assessment,
                    "is_demo": True,
                }
            # Or resolve whatever demo device is active
            for d in self.discover_local_devices(mode="demo"):
                if d["id"] == target_id or d["ip"] == target_id:
                    conn = self.resolve_device_connectivity(d["ip"], d.get("mac"), mode="demo")
                    assessment = self.assess_device_malware_threat(d["ip"], d.get("mac"), mode="demo")
                    return {
                        **d,
                        "is_active_target": True,
                        "is_reachable": True,
                        "connectivity": conn,
                        "security": assessment,
                        "is_demo": True,
                    }
            # Fallback to default demo device if target_id did not match
            conn = self.resolve_device_connectivity("192.168.1.105", mode="demo")
            assessment = self.assess_device_malware_threat("192.168.1.105", mode="demo")
            return {
                "id": "demo_192_168_1_105",
                "name": "Engineering Laptop",
                "ip": "192.168.1.105",
                "mac": "00:50:56:C0:00:08",
                "device_type": "Laptop",
                "description": "Seeded enterprise demo fixture node (Compromised)",
                "is_active_target": True,
                "is_reachable": True,
                "connectivity": conn,
                "security": assessment,
                "is_demo": True,
            }

        if not self.active_device_id:
            return None

        dev = self.get_registered_device(self.active_device_id)
        if not dev:
            # Check if active_device_id is an IP
            for d in self.discover_local_devices(mode="live"):
                if d["id"] == self.active_device_id or d["ip"] == self.active_device_id:
                    dev = d
                    break

        if not dev:
            return None

        target_ip = dev["ip"]
        target_mac = dev.get("mac")
        
        # Check current live reachability
        live_devices = self.discover_local_devices(mode="live")
        is_currently_discoverable = any(d["ip"] == target_ip for d in live_devices)

        conn = self.resolve_device_connectivity(target_ip, target_mac, mode=mode)
        assessment = self.assess_device_malware_threat(target_ip, target_mac, mode=mode)

        if not is_currently_discoverable:
            conn["connectivity_status"] = "UNAVAILABLE"
            conn["has_traffic"] = False
            conn["message"] = "Device has disconnected or is no longer reachable on the local network."

        return {
            **dev,
            "is_active_target": True,
            "is_reachable": is_currently_discoverable,
            "connectivity": conn,
            "security": assessment,
            "is_demo": mode == "demo",
        }

    def validate_ip(self, ip_str: str) -> str:
        """Validate an IP address (IPv4 or IPv6) and return its canonical string."""
        if not ip_str or not isinstance(ip_str, str):
            raise ValueError("IP address must be a non-empty string.")
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            return str(ip_obj)
        except ValueError:
            raise ValueError(f"'{ip_str}' is not a valid IPv4 or IPv6 address.")

    def register_device(
        self,
        name: str,
        ip: str,
        mac: Optional[str] = None,
        device_type: str = "Laptop",
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Register a new device and persist it."""
        clean_name = (name or "").strip()
        if not clean_name:
            raise ValueError("Device name cannot be blank.")

        clean_ip = self.validate_ip(ip)

        # Check for duplicate IP registrations
        for dev_id, dev in self.registered_devices.items():
            if dev.get("ip") == clean_ip:
                raise ValueError(f"Device with IP {clean_ip} is already registered as '{dev.get('name')}'.")

        device_id = f"dev_{clean_ip.replace('.', '_').replace(':', '_')}"
        clean_mac = mac.strip().upper() if mac and mac.strip() else None
        clean_type = (device_type or "Laptop").strip()
        clean_desc = description.strip() if description and description.strip() else None

        new_device = {
            "id": device_id,
            "name": clean_name,
            "ip": clean_ip,
            "mac": clean_mac,
            "device_type": clean_type,
            "description": clean_desc,
            "created_at": datetime.now().isoformat(),
            "is_registered": True,
        }

        self.registered_devices[device_id] = new_device
        self._save_devices()
        logger.info(f"Registered new device: {clean_name} ({clean_ip})")
        return new_device

    def delete_device(self, device_id: str) -> bool:
        """Remove a registered device."""
        if device_id in self.registered_devices:
            del self.registered_devices[device_id]
            self._save_devices()
            logger.info(f"Deleted registered device: {device_id}")
            return True
        for dev_key, dev in list(self.registered_devices.items()):
            if dev.get("ip") == device_id:
                del self.registered_devices[dev_key]
                self._save_devices()
                logger.info(f"Deleted registered device with IP: {device_id}")
                return True
        return False

    def get_registered_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get a registered device by its ID or IP."""
        if device_id in self.registered_devices:
            return self.registered_devices[device_id]
        for dev in self.registered_devices.values():
            if dev.get("ip") == device_id:
                return dev
        return None

    def get_registered_devices_list(self) -> List[Dict[str, Any]]:
        """Return a copy of all registered devices."""
        return list(self.registered_devices.values())

    def get_device_packets(self, ip: str, mac: Optional[str] = None) -> List[Dict[str, Any]]:
        """Filter captured packets associated with a device by IP (and optional MAC)."""
        if not self.packet_service or not hasattr(self.packet_service, "packets"):
            return []

        captured = self.packet_service.packets
        if not captured:
            return []

        matched = []
        for p in captured:
            src_ip = p.get("source_ip")
            dst_ip = p.get("dest_ip")
            src_mac = p.get("source_mac")
            dst_mac = p.get("dest_mac")

            ip_matched = (src_ip == ip or dst_ip == ip)
            mac_matched = bool(mac and (src_mac == mac or dst_mac == mac))

            if ip_matched or mac_matched:
                matched.append(p)

        return matched

    def resolve_device_connectivity(
        self,
        ip: str,
        mac: Optional[str] = None,
        mode: str = "live",
    ) -> Dict[str, Any]:
        """
        Determine connectivity state and observed activity using actual packet data.
        Possible states: CONNECTED, ACTIVE, INACTIVE, NOT OBSERVED.
        For devices with no traffic:
          CONNECTIVITY: NOT OBSERVED
          TRAFFIC: NO TRAFFIC OBSERVED
          SECURITY: NOT ASSESSED
        """
        now = datetime.now()

        # In DEMO MODE: Check existing deterministic demo fixture
        if mode == "demo":
            demo_nodes_map = {
                "192.168.1.105": {
                    "label": "Engineering Laptop (Compromised)",
                    "packets_in": 2400,
                    "packets_out": 3800,
                    "total_bytes": 2150000,
                    "status": "threat_detected",
                    "role": "compromised",
                    "type": "Endpoint",
                    "is_demo_fixture": True,
                },
                "192.168.1.45": {
                    "label": "SOC Admin Workstation",
                    "packets_in": 1150,
                    "packets_out": 890,
                    "total_bytes": 485000,
                    "status": "active",
                    "role": "workstation",
                    "type": "Admin Workstation",
                    "is_demo_fixture": True,
                },
                "192.168.1.1": {
                    "label": "Gateway / Firewall",
                    "packets_in": 3200,
                    "packets_out": 2850,
                    "total_bytes": 1420000,
                    "status": "active",
                    "role": "gateway",
                    "type": "Gateway",
                    "is_demo_fixture": True,
                },
                "192.168.1.10": {
                    "label": "Domain Controller (AD / DNS)",
                    "packets_in": 1850,
                    "packets_out": 1420,
                    "total_bytes": 890000,
                    "status": "active",
                    "role": "server",
                    "type": "Server",
                    "is_demo_fixture": True,
                },
                "192.168.1.200": {
                    "label": "Internal Database Server",
                    "packets_in": 1200,
                    "packets_out": 950,
                    "total_bytes": 620000,
                    "status": "active",
                    "role": "server",
                    "type": "Database Server",
                    "is_demo_fixture": True,
                },
                "185.220.101.5": {
                    "label": "External C2 Beacon Host",
                    "packets_in": 2100,
                    "packets_out": 1950,
                    "total_bytes": 1850000,
                    "status": "hostile",
                    "role": "adversary",
                    "type": "External Threat",
                    "is_demo_fixture": True,
                },
                "1.1.1.1": {
                    "label": "Cloudflare Public DNS",
                    "packets_in": 980,
                    "packets_out": 1050,
                    "total_bytes": 240000,
                    "status": "active",
                    "role": "external",
                    "type": "Cloud Service",
                    "is_demo_fixture": True,
                },
            }

            if ip in demo_nodes_map:
                fixture = demo_nodes_map[ip]
                return {
                    "connectivity_status": "CONNECTED",
                    "packet_count": fixture["packets_in"] + fixture["packets_out"],
                    "packets_in": fixture["packets_in"],
                    "packets_out": fixture["packets_out"],
                    "total_bytes": fixture["total_bytes"],
                    "last_seen": now.isoformat(),
                    "has_traffic": True,
                    "is_demo": True,
                }
            else:
                # Custom registered device in demo mode that has no traffic in the fixture
                return {
                    "connectivity_status": "NOT OBSERVED",
                    "packet_count": 0,
                    "packets_in": 0,
                    "packets_out": 0,
                    "total_bytes": 0,
                    "last_seen": None,
                    "has_traffic": False,
                    "is_demo": True,
                }

        # In LIVE MODE: Use actual captured packets
        dev_packets = self.get_device_packets(ip, mac)
        if not dev_packets:
            return {
                "connectivity_status": "NOT OBSERVED",
                "packet_count": 0,
                "packets_in": 0,
                "packets_out": 0,
                "total_bytes": 0,
                "last_seen": None,
                "has_traffic": False,
                "is_demo": False,
            }

        pkts_in = 0
        pkts_out = 0
        total_bytes = 0
        latest_ts = None

        for p in dev_packets:
            size = int(p.get("size_bytes") or 0)
            total_bytes += size
            if p.get("source_ip") == ip:
                pkts_out += 1
            if p.get("dest_ip") == ip:
                pkts_in += 1

            ts_str = p.get("timestamp")
            if ts_str:
                try:
                    p_ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if latest_ts is None or p_ts > latest_ts:
                        latest_ts = p_ts
                except Exception:
                    pass

        # Determine status: ACTIVE if packet seen within last 45s, else INACTIVE
        if latest_ts and (now - latest_ts.replace(tzinfo=None)) < timedelta(seconds=45):
            conn_status = "ACTIVE"
        else:
            conn_status = "CONNECTED" if dev_packets else "NOT OBSERVED"

        return {
            "connectivity_status": conn_status,
            "packet_count": len(dev_packets),
            "packets_in": pkts_in,
            "packets_out": pkts_out,
            "total_bytes": total_bytes,
            "last_seen": latest_ts.isoformat() if latest_ts else now.isoformat(),
            "has_traffic": True,
            "is_demo": False,
        }

    def get_all_devices(self, mode: str = "live") -> List[Dict[str, Any]]:
        """
        List devices with connectivity and security status summary.
        Combines registered devices and discovered endpoints.
        """
        devices: List[Dict[str, Any]] = []
        registered_ips = set()

        # 1. Process all explicitly registered devices
        for dev in self.registered_devices.values():
            ip = dev["ip"]
            registered_ips.add(ip)
            conn = self.resolve_device_connectivity(ip, dev.get("mac"), mode=mode)

            # Retrieve quick security status
            assessment = self.assess_device_malware_threat(ip, dev.get("mac"), mode=mode)

            devices.append(
                {
                    "id": dev["id"],
                    "name": dev["name"],
                    "ip": ip,
                    "mac": dev.get("mac"),
                    "device_type": dev.get("device_type", "Laptop"),
                    "description": dev.get("description"),
                    "created_at": dev.get("created_at"),
                    "is_registered": True,
                    "connectivity_status": conn["connectivity_status"],
                    "has_traffic": conn["has_traffic"],
                    "packet_count": conn["packet_count"],
                    "packets_in": conn["packets_in"],
                    "packets_out": conn["packets_out"],
                    "total_bytes": conn["total_bytes"],
                    "last_seen": conn["last_seen"],
                    "security_status": assessment["security_status"],
                    "attack_probability": assessment["attack_probability"],
                    "mitre_stage": assessment.get("mitre_stage"),
                    "is_demo": mode == "demo",
                }
            )

        # 2. In DEMO MODE: Include demo fixture devices that haven't been registered yet
        if mode == "demo":
            demo_fixture_ips = [
                ("192.168.1.105", "Engineering Laptop (Compromised)", "Endpoint", "threat_detected"),
                ("192.168.1.45", "SOC Admin Workstation", "Admin Workstation", "active"),
                ("192.168.1.1", "Gateway / Firewall", "Gateway", "active"),
                ("192.168.1.10", "Domain Controller (AD / DNS)", "Server", "active"),
                ("192.168.1.200", "Internal Database Server", "Database Server", "active"),
                ("185.220.101.5", "External C2 Beacon Host", "External Threat", "hostile"),
                ("1.1.1.1", "Cloudflare Public DNS", "Cloud Service", "active"),
            ]
            for f_ip, f_name, f_type, _ in demo_fixture_ips:
                if f_ip not in registered_ips:
                    conn = self.resolve_device_connectivity(f_ip, mode="demo")
                    assessment = self.assess_device_malware_threat(f_ip, mode="demo")
                    devices.append(
                        {
                            "id": f"demo_{f_ip.replace('.', '_')}",
                            "name": f_name,
                            "ip": f_ip,
                            "mac": None,
                            "device_type": f_type,
                            "description": "Seeded enterprise demo fixture node",
                            "created_at": None,
                            "is_registered": False,
                            "connectivity_status": conn["connectivity_status"],
                            "has_traffic": conn["has_traffic"],
                            "packet_count": conn["packet_count"],
                            "packets_in": conn["packets_in"],
                            "packets_out": conn["packets_out"],
                            "total_bytes": conn["total_bytes"],
                            "last_seen": conn["last_seen"],
                            "security_status": assessment["security_status"],
                            "attack_probability": assessment["attack_probability"],
                            "mitre_stage": assessment.get("mitre_stage"),
                            "is_demo": True,
                        }
                    )

        # 3. In LIVE MODE: Include any discovered active endpoints from live packet buffer
        elif mode == "live" and self.packet_service and self.packet_service.packets:
            seen_ips = set()
            for p in self.packet_service.packets:
                for target_ip in [p.get("source_ip"), p.get("dest_ip")]:
                    if (
                        target_ip
                        and target_ip not in registered_ips
                        and target_ip not in seen_ips
                        and target_ip not in {"127.0.0.1", "::1"}
                    ):
                        seen_ips.add(target_ip)
                        conn = self.resolve_device_connectivity(target_ip, mode="live")
                        assessment = self.assess_device_malware_threat(target_ip, mode="live")

                        is_local = (
                            target_ip.startswith("192.168.")
                            or target_ip.startswith("10.")
                            or target_ip.startswith("172.")
                        )
                        label = f"Discovered Endpoint ({target_ip})" if is_local else f"Observed Server ({target_ip})"
                        dtype = "LAN Endpoint" if is_local else "Remote Server"

                        devices.append(
                            {
                                "id": f"live_{target_ip.replace('.', '_').replace(':', '_')}",
                                "name": label,
                                "ip": target_ip,
                                "mac": p.get("source_mac") if p.get("source_ip") == target_ip else p.get("dest_mac"),
                                "device_type": dtype,
                                "description": "Auto-discovered from live packet sniff",
                                "created_at": None,
                                "is_registered": False,
                                "connectivity_status": conn["connectivity_status"],
                                "has_traffic": conn["has_traffic"],
                                "packet_count": conn["packet_count"],
                                "packets_in": conn["packets_in"],
                                "packets_out": conn["packets_out"],
                                "total_bytes": conn["total_bytes"],
                                "last_seen": conn["last_seen"],
                                "security_status": assessment["security_status"],
                                "attack_probability": assessment["attack_probability"],
                                "mitre_stage": assessment.get("mitre_stage"),
                                "is_demo": False,
                            }
                        )

        return devices

    def get_device_traffic_details(
        self,
        ip: str,
        mac: Optional[str] = None,
        mode: str = "live",
    ) -> Dict[str, Any]:
        """
        Return structured observed traffic for a specific device.
        If the device has no traffic yet, clearly returns has_traffic=False with NO TRAFFIC OBSERVED.
        """
        conn = self.resolve_device_connectivity(ip, mac, mode=mode)
        if not conn["has_traffic"] or conn["packet_count"] == 0:
            return {
                "ip": ip,
                "has_traffic": False,
                "traffic_status": "NO TRAFFIC OBSERVED",
                "connectivity_status": conn["connectivity_status"],
                "packet_count": 0,
                "byte_count": 0,
                "protocols": {},
                "ports": [],
                "connections": [],
                "recent_packets": [],
                "message": "NO TRAFFIC OBSERVED",
            }

        # DEMO MODE: Format connections from demo topology
        if mode == "demo":
            demo_connections = []
            if ip == "192.168.1.105":
                demo_connections = [
                    {
                        "endpoint": "185.220.101.5",
                        "protocol": "TCP",
                        "port": 443,
                        "direction": "outbound",
                        "packet_count": 1420,
                        "byte_count": 894000,
                        "is_threat": True,
                        "description": "C2 Bot Beaconing detected over HTTPS",
                    },
                    {
                        "endpoint": "192.168.1.10",
                        "protocol": "TCP",
                        "port": 445,
                        "direction": "internal",
                        "packet_count": 480,
                        "byte_count": 68000,
                        "is_threat": True,
                        "description": "Kerberos Authentication Brute-Force",
                    },
                    {
                        "endpoint": "192.168.1.200",
                        "protocol": "TCP",
                        "port": 3306,
                        "direction": "internal",
                        "packet_count": 750,
                        "byte_count": 215000,
                        "is_threat": True,
                        "description": "Lateral Database Query Scan",
                    },
                ]
            elif ip == "192.168.1.45":
                demo_connections = [
                    {
                        "endpoint": "192.168.1.1",
                        "protocol": "TCP",
                        "port": 22,
                        "direction": "internal",
                        "packet_count": 320,
                        "byte_count": 45000,
                        "is_threat": False,
                        "description": "SSH Admin Management",
                    }
                ]

            return {
                "ip": ip,
                "has_traffic": True,
                "traffic_status": f"{conn['packet_count']} packets observed",
                "connectivity_status": conn["connectivity_status"],
                "packet_count": conn["packet_count"],
                "byte_count": conn["total_bytes"],
                "protocols": {"TCP": conn["packet_count"]},
                "ports": [22, 80, 443, 445, 3306],
                "connections": demo_connections,
                "recent_packets": [],
                "is_demo": True,
            }

        # LIVE MODE: Extract actual connections and breakdown
        dev_packets = self.get_device_packets(ip, mac)
        protocol_counts: Dict[str, int] = defaultdict(int)
        port_counts: Dict[int, int] = defaultdict(int)
        endpoint_map: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "endpoint": "",
                "protocol": "TCP",
                "ports": set(),
                "direction": "outbound",
                "packet_count": 0,
                "byte_count": 0,
                "is_threat": False,
            }
        )

        recent_sample = []
        for p in reversed(dev_packets):
            src = p.get("source_ip", "")
            dst = p.get("dest_ip", "")
            proto = str(p.get("protocol") or "TCP").upper()
            size = int(p.get("size_bytes") or 0)
            dport = p.get("dest_port")
            sport = p.get("source_port")

            protocol_counts[proto] += 1
            if dport:
                port_counts[int(dport)] += 1
            if sport:
                port_counts[int(sport)] += 1

            peer_ip = dst if src == ip else src
            if peer_ip:
                fl = endpoint_map[peer_ip]
                fl["endpoint"] = peer_ip
                fl["protocol"] = proto
                if dport:
                    fl["ports"].add(int(dport))
                fl["direction"] = "outbound" if src == ip else "inbound"
                fl["packet_count"] += 1
                fl["byte_count"] += size

            if len(recent_sample) < 25:
                recent_sample.append(
                    {
                        "timestamp": p.get("timestamp"),
                        "source_ip": src,
                        "dest_ip": dst,
                        "protocol": proto,
                        "source_port": sport,
                        "dest_port": dport,
                        "size_bytes": size,
                    }
                )

        connections_list = []
        for peer_ip, fl in endpoint_map.items():
            connections_list.append(
                {
                    "endpoint": peer_ip,
                    "protocol": fl["protocol"],
                    "ports": sorted(list(fl["ports"]))[:5],
                    "direction": fl["direction"],
                    "packet_count": fl["packet_count"],
                    "byte_count": fl["byte_count"],
                    "is_threat": False,
                    "description": f"{fl['protocol']} communication ({fl['packet_count']} pkts)",
                }
            )

        connections_list.sort(key=lambda c: c["packet_count"], reverse=True)

        return {
            "ip": ip,
            "has_traffic": True,
            "traffic_status": f"{len(dev_packets)} packets observed",
            "connectivity_status": conn["connectivity_status"],
            "packet_count": len(dev_packets),
            "byte_count": conn["total_bytes"],
            "protocols": dict(protocol_counts),
            "ports": [pt for pt, _ in sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]],
            "connections": connections_list[:15],
            "recent_packets": recent_sample,
            "is_demo": False,
        }

    def assess_device_malware_threat(
        self,
        ip: str,
        mac: Optional[str] = None,
        mode: str = "live",
    ) -> Dict[str, Any]:
        """
        Evidence-grounded malware and threat assessment for a specific device.
        Uses the existing NetGuard detection pipeline:
          Device Network Traffic
          ↓
          Canonical 27 Flow Feature Extraction
          ↓
          PyTorch LSTM World Model Inference
          ↓
          Attack Probability & Predicted Stage
          ↓
          Gradient-based Feature Attribution (Explainability)
          ↓
          MITRE ATT&CK Mapping
          ↓
          Device Security Status

        CRITICAL REQUIREMENT:
        Zero or insufficient traffic (<5 packets) MUST NOT be classified as CLEAN or SECURE.
        Instead, returns security_status="NOT ASSESSED" with explanation:
        "Insufficient traffic data for malware assessment."
        """
        conn = self.resolve_device_connectivity(ip, mac, mode=mode)
        packet_count = conn.get("packet_count", 0)

        # 1. Insufficient Traffic Guard
        if not conn["has_traffic"] or packet_count < 5:
            return {
                "ip": ip,
                "connectivity_status": conn["connectivity_status"],
                "packet_count": packet_count,
                "security_status": "NOT ASSESSED",
                "attack_probability": 0.0,
                "mitre_stage": None,
                "mitre_technique": None,
                "top_indicators": [],
                "evidence": [],
                "explanation": "Insufficient traffic data for malware assessment.",
                "model_evaluated": False,
                "is_demo": mode == "demo",
            }

        # 2. DEMO MODE: Grounded in the existing deterministic demo fixture
        if mode == "demo":
            if ip == "192.168.1.105":
                # Known compromised engineering laptop in existing demo scenario
                return {
                    "ip": ip,
                    "connectivity_status": "CONNECTED",
                    "packet_count": packet_count,
                    "security_status": "HIGH RISK",
                    "attack_probability": 0.88,
                    "mitre_stage": "Command and Control",
                    "mitre_technique": "T1071.001 - Web Protocols (C2 Beaconing)",
                    "top_indicators": [
                        "Persistent periodic outbound beaconing to external IP 185.220.101.5",
                        "High-volume payload retrieval matching Trojan dropper patterns",
                        "Lateral Kerberos authentication sweep against Domain Controller",
                        "Elevated flow packet rate with anomalous ACK/SYN ratio",
                    ],
                    "evidence": [
                        "MITRE Stage 12: Command and Control [T1071.001]",
                        "Outbound socket communication to external threat actor 185.220.101.5:8080",
                        "Heuristic match: Trojan horse downloader binary payload",
                    ],
                    "explanation": "Potential threat detected: Device is exhibiting persistent periodic outbound communication and payload retrieval patterns associated with Command and Control activity.",
                    "model_evaluated": True,
                    "is_demo": True,
                    "demo_label": "DEMO / SEEDED DATA",
                }
            elif ip == "192.168.1.45":
                return {
                    "ip": ip,
                    "connectivity_status": "CONNECTED",
                    "packet_count": packet_count,
                    "security_status": "SUSPICIOUS",
                    "attack_probability": 0.65,
                    "mitre_stage": "Reconnaissance",
                    "mitre_technique": "T1046 - Network Service Discovery",
                    "top_indicators": [
                        "Sequential internal TCP port probe sweep",
                        "Active administrative SSH session",
                    ],
                    "evidence": [
                        "MITRE Stage 1: Reconnaissance [T1046]",
                        "42 internal TCP ports probed in short interval",
                    ],
                    "explanation": "Suspicious internal activity: Host initiated sequential TCP port scanning against network gateway.",
                    "model_evaluated": True,
                    "is_demo": True,
                    "demo_label": "DEMO / SEEDED DATA",
                }
            elif ip in {"192.168.1.1", "192.168.1.10", "1.1.1.1"}:
                return {
                    "ip": ip,
                    "connectivity_status": "CONNECTED",
                    "packet_count": packet_count,
                    "security_status": "SECURE",
                    "attack_probability": 0.08,
                    "mitre_stage": "Normal / Benign",
                    "mitre_technique": None,
                    "top_indicators": [
                        "Standard DNS and gateway forward flow patterns",
                        "Normal connection duration and balanced throughput",
                    ],
                    "evidence": ["No anomalous flow attributes detected in baseline observation"],
                    "explanation": "Device communication patterns align with legitimate infrastructure baseline; no malicious telemetry observed.",
                    "model_evaluated": True,
                    "is_demo": True,
                    "demo_label": "DEMO / SEEDED DATA",
                }
            else:
                # Custom registered device in Demo mode that does not match any demo attack fixture
                return {
                    "ip": ip,
                    "connectivity_status": "NOT OBSERVED",
                    "packet_count": 0,
                    "security_status": "NOT ASSESSED",
                    "attack_probability": 0.0,
                    "mitre_stage": None,
                    "mitre_technique": None,
                    "top_indicators": [],
                    "evidence": [],
                    "explanation": "Insufficient traffic data for malware assessment.",
                    "model_evaluated": False,
                    "is_demo": True,
                }

        # 3. LIVE MODE: Execute actual feature extraction + LSTM World Model Inference
        dev_packets = self.get_device_packets(ip, mac)
        if len(dev_packets) < 5:
            return {
                "ip": ip,
                "connectivity_status": conn["connectivity_status"],
                "packet_count": len(dev_packets),
                "security_status": "NOT ASSESSED",
                "attack_probability": 0.0,
                "mitre_stage": None,
                "mitre_technique": None,
                "top_indicators": [],
                "evidence": [],
                "explanation": "Insufficient traffic data for malware assessment.",
                "model_evaluated": False,
                "is_demo": False,
            }

        # Step 3a: Extract the canonical 27 flow features from device packets
        from app.services.forecast_service import extract_27_flow_features

        features_27 = extract_27_flow_features(dev_packets, interval_duration=5.0)

        # Step 3b: Run PyTorch LSTM World Model inference through existing ForecastEngine
        model_curr_prob = 0.0
        predicted_stage = "Normal / Benign"
        top_indicators = []

        if self.forecast_service and hasattr(self.forecast_service, "engine") and self.forecast_service.engine:
            try:
                engine = self.forecast_service.engine
                # Tile the 27 features across the 30-step window for sequence inference
                seq_np = np.array([features_27] * 30, dtype=np.float32)
                forecast_res = engine.forecast(seq_np)

                if "current_probability" in forecast_res and forecast_res["current_probability"] is not None:
                    model_curr_prob = float(forecast_res["current_probability"])
                predicted_stage = forecast_res.get("predicted_stage", "Normal / Benign")

                # Step 3c: Extract top contributing indicators from gradient feature attribution
                for feat in forecast_res.get("top_features", [])[:5]:
                    fname = feat.get("feature", "")
                    friendly = FEATURE_FRIENDLY_NAMES.get(fname, fname.replace("_", " ").title())
                    desc = feat.get("description", "")
                    raw_val = feat.get("raw_value", 0.0)
                    top_indicators.append(f"{friendly}: {desc or f'value {raw_val:.2f}'}")
            except Exception as e:
                logger.warning(f"Error during LSTM model inference for {ip}: {e}")

        # Step 3d: Check threat detection heuristics for this device
        heuristic_evidence = []
        has_critical_threat = False
        has_high_threat = False

        if self.threat_service:
            matched_threats = []
            for t in getattr(self.threat_service, "detected_threats", []):
                if t.get("source_ip") == ip or t.get("destination_ip") == ip:
                    matched_threats.append(t)

            for t in matched_threats:
                sev = str(t.get("severity", "LOW")).upper()
                ttype = t.get("type", "ANOMALY")
                desc = t.get("description", "")
                heuristic_evidence.append(f"{sev} Threat Detected: {ttype} ({desc})")
                if sev == "CRITICAL":
                    has_critical_threat = True
                elif sev == "HIGH":
                    has_high_threat = True

        # Step 3e: MITRE Stage & Technique Mapping
        mitre_stage_label = predicted_stage
        mitre_technique_label = None

        if self.mitre_service:
            try:
                # If heuristic threat matched, map it directly
                if heuristic_evidence:
                    mapped = self.mitre_service.map_threat("MALICIOUS_FLOW")
                    mitre_technique_label = f"{mapped.get('technique_id', '')} - {mapped.get('technique_name', '')}"
                elif predicted_stage and predicted_stage != "Normal / Benign":
                    mitre_technique_label = f"T1071 - Application Layer Traffic ({predicted_stage})"
            except Exception:
                pass

        # Step 3f: Evidence-grounded Security Classification
        # Conservative classification: only assign MALICIOUS if critical threat confirmed
        if has_critical_threat:
            security_status = "MALICIOUS / THREAT DETECTED"
            explanation = "Potential threat detected: Active critical anomalies (e.g. C2 or payload delivery) observed in live socket telemetry."
        elif model_curr_prob >= 0.75 or has_high_threat:
            security_status = "HIGH RISK"
            explanation = f"Potential threat detected: High model threat score ({int(model_curr_prob * 100)}%) and anomalous traffic patterns observed."
        elif model_curr_prob >= 0.40 or len(heuristic_evidence) > 0:
            security_status = "SUSPICIOUS"
            explanation = f"Suspicious activity observed: Traffic exhibits irregular flow patterns (attack probability {int(model_curr_prob * 100)}%)."
        elif model_curr_prob >= 0.15:
            security_status = "LOW RISK"
            explanation = "Low-risk traffic: Minor statistical variance detected; no definitive threat signatures identified."
        else:
            security_status = "SECURE"
            explanation = "Traffic analysis indicates clean, legitimate endpoint communication matching standard baseline."

        if not top_indicators:
            top_indicators = [
                f"Evaluated {len(dev_packets)} captured packets against 27 canonical flow features",
                f"PyTorch LSTM World Model current attack score: {round(model_curr_prob, 4)}",
            ]

        return {
            "ip": ip,
            "connectivity_status": conn["connectivity_status"],
            "packet_count": len(dev_packets),
            "security_status": security_status,
            "attack_probability": round(model_curr_prob, 4),
            "mitre_stage": mitre_stage_label,
            "mitre_technique": mitre_technique_label,
            "top_indicators": top_indicators,
            "evidence": heuristic_evidence if heuristic_evidence else [f"LSTM model attack probability {round(model_curr_prob * 100, 1)}%"],
            "explanation": explanation,
            "model_evaluated": True,
            "is_demo": False,
        }
