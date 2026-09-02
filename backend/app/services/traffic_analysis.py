"""
Traffic Analysis Service
Analyzes network traffic patterns and provides insights
"""

from typing import Dict, List, Any, Optional
from collections import defaultdict
from datetime import datetime, timedelta
import statistics

class TrafficAnalysisService:
    def __init__(self):
        self.traffic_data: List[Dict[str, Any]] = []
        self.max_history = 500
    
    async def get_traffic_summary(self, packets: List[Dict[str, Any]], time_range: str = "24h") -> Dict[str, Any]:
        """
        Get traffic summary for specified time range
        """
        # This service is mostly a dashboard summarizer. It does not decide
        # whether traffic is malicious; it prepares chart-friendly aggregates.
        if not packets:
            return {
                "total_packets": 0,
                "total_bytes": 0,
                "average_packet_size": 0,
                "packets_per_second": 0,
                "time_range": time_range,
                "summary": "No traffic data available"
            }
        
        total_packets = len(packets)
        total_bytes = sum(p.get("size_bytes", 0) for p in packets)
        avg_size = total_bytes / total_packets if total_packets > 0 else 0
        pps = total_packets  # Simplified for current session
        
        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "average_packet_size": round(avg_size, 2),
            "packets_per_second": pps,
            "time_range": time_range,
            "timestamp": datetime.now().isoformat()
        }
    
    async def analyze_by_protocol(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Break down traffic by protocol
        """
        protocol_stats = defaultdict(lambda: {"count": 0, "bytes": 0, "percentage": 0})
        
        if not packets:
            return {"protocols": {}, "total": 0}
        
        total_packets = len(packets)
        total_bytes = sum(p.get("size_bytes", 0) for p in packets)
        
        for packet in packets:
            protocol = packet.get("protocol", "Unknown")
            size = packet.get("size_bytes", 0)
            
            protocol_stats[protocol]["count"] += 1
            protocol_stats[protocol]["bytes"] += size
        
        # Calculate percentages
        for protocol in protocol_stats:
            protocol_stats[protocol]["percentage"] = round(
                (protocol_stats[protocol]["count"] / total_packets * 100), 2
            )
        
        return {
            "protocols": dict(protocol_stats),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "timestamp": datetime.now().isoformat()
        }
    
    async def analyze_by_port(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze traffic by destination ports
        """
        port_stats = defaultdict(lambda: {"count": 0, "protocol": "Unknown"})
        
        if not packets:
            return {"ports": {}, "total": 0}
        
        for packet in packets:
            dest_port = packet.get("dest_port")
            protocol = packet.get("protocol", "Unknown")
            
            if dest_port:
                port_stats[dest_port]["count"] += 1
                port_stats[dest_port]["protocol"] = protocol
        
        # Sort by traffic count and get top 20
        top_ports = dict(
            sorted(port_stats.items(), key=lambda x: x[1]["count"], reverse=True)[:20]
        )
        
        return {
            "top_ports": top_ports,
            "total_unique_ports": len(port_stats),
            "timestamp": datetime.now().isoformat()
        }
    
    async def analyze_by_application(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Classify traffic by application/port type
        """
        # This is a lightweight port-to-application mapping, so it is useful for
        # visualization but not meant to be a deep protocol fingerprinting engine.
        port_to_app = {
            80: "HTTP", 443: "HTTPS", 53: "DNS", 25: "SMTP",
            110: "POP3", 143: "IMAP", 3306: "MySQL", 5432: "PostgreSQL",
            6379: "Redis", 27017: "MongoDB", 22: "SSH", 23: "Telnet",
            21: "FTP", 69: "TFTP", 123: "NTP", 161: "SNMP",
            3389: "RDP", 445: "SMB", 139: "NetBIOS", 8080: "HTTP-Alt"
        }
        
        app_traffic = defaultdict(lambda: {"packets": 0, "bytes": 0, "ports": set()})
        unknown_count = 0
        unknown_bytes = 0
        
        if not packets:
            return {"applications": {}, "total": 0}
        
        for packet in packets:
            dest_port = packet.get("dest_port", 0)
            size = packet.get("size_bytes", 0)
            
            if dest_port in port_to_app:
                app = port_to_app[dest_port]
                app_traffic[app]["packets"] += 1
                app_traffic[app]["bytes"] += size
                app_traffic[app]["ports"].add(dest_port)
            else:
                unknown_count += 1
                unknown_bytes += size
        
        # Convert sets to lists for JSON serialization
        result = {
            "applications": {},
            "unknown": {
                "packets": unknown_count,
                "bytes": unknown_bytes
            },
            "timestamp": datetime.now().isoformat()
        }
        
        for app, stats in app_traffic.items():
            result["applications"][app] = {
                "packets": stats["packets"],
                "bytes": stats["bytes"],
                "ports": sorted(list(stats["ports"]))
            }
        
        return result
    
    async def get_geographic_distribution(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Get traffic distribution by geographic location (simplified IP-based)
        """
        # IP ranges for common regions (simplified)
        ip_regions = {
            "8.8.": "USA (Google)",
            "1.1.": "USA (Cloudflare)",
            "192.168.": "Local Network",
            "10.0.": "Local Network",
            "172.16.": "Local Network",
        }
        
        region_traffic = defaultdict(lambda: {"packets": 0, "bytes": 0})
        
        if not packets:
            return {"regions": {}, "total": 0}
        
        for packet in packets:
            dest_ip = packet.get("dest_ip", "Unknown")
            size = packet.get("size_bytes", 0)
            region = "Other"
            
            for prefix, region_name in ip_regions.items():
                if dest_ip.startswith(prefix):
                    region = region_name
                    break
            
            region_traffic[region]["packets"] += 1
            region_traffic[region]["bytes"] += size
        
        return {
            "regions": dict(region_traffic),
            "timestamp": datetime.now().isoformat(),
            "note": "Geographic distribution based on IP prefix (simplified)"
        }
    
    async def predict_bandwidth_requirements(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Predict future bandwidth requirements based on current trends
        """
        if not packets:
            return {
                "prediction": "Insufficient data",
                "current_bandwidth_mbps": 0,
                "projected_bandwidth_mbps": 0
            }
        
        total_bytes = sum(p.get("size_bytes", 0) for p in packets)
        current_bandwidth_mbps = (total_bytes * 8) / 1_000_000  # Convert to Mbps
        
        # Simple linear projection
        avg_packet_size = total_bytes / len(packets) if packets else 0
        growth_factor = 1.15  # Assume 15% growth
        projected_bandwidth = current_bandwidth_mbps * growth_factor
        
        # Capacity recommendations
        if projected_bandwidth < 10:
            recommendation = "Current bandwidth is sufficient"
        elif projected_bandwidth < 100:
            recommendation = "Consider 100 Mbps connection"
        elif projected_bandwidth < 1000:
            recommendation = "Consider 1 Gbps connection"
        else:
            recommendation = "Consider enterprise/multi-Gbps solution"
        
        return {
            "current_bandwidth_mbps": round(current_bandwidth_mbps, 2),
            "projected_bandwidth_mbps": round(projected_bandwidth, 2),
            "growth_assumption": f"{(growth_factor - 1) * 100:.0f}%",
            "recommendation": recommendation,
            "average_packet_size_bytes": round(avg_packet_size, 2),
            "timestamp": datetime.now().isoformat()
        }
    
    async def analyze_connection_patterns(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze source-destination connection patterns
        """
        if not packets:
            return {
                "unique_sources": 0,
                "unique_destinations": 0,
                "unique_connections": 0,
                "most_active": []
            }
        
        connections = defaultdict(lambda: {"packets": 0, "bytes": 0})
        sources = set()
        destinations = set()
        
        for packet in packets:
            src_ip = packet.get("source_ip")
            dst_ip = packet.get("dest_ip")
            size = packet.get("size_bytes", 0)
            
            if src_ip and dst_ip:
                sources.add(src_ip)
                destinations.add(dst_ip)
                
                connection_key = f"{src_ip} -> {dst_ip}"
                connections[connection_key]["packets"] += 1
                connections[connection_key]["bytes"] += size
        
        # Get top connections
        top_connections = sorted(
            connections.items(),
            key=lambda x: x[1]["packets"],
            reverse=True
        )[:10]
        
        most_active = [
            {
                "connection": conn[0],
                "packets": conn[1]["packets"],
                "bytes": conn[1]["bytes"]
            }
            for conn in top_connections
        ]
        
        return {
            "unique_sources": len(sources),
            "unique_destinations": len(destinations),
            "unique_connections": len(connections),
            "most_active": most_active,
            "timestamp": datetime.now().isoformat()
        }
    
    def store_traffic_sample(self, sample: Dict[str, Any]) -> None:
        """Store traffic sample for historical analysis"""
        self.traffic_data.append({
            "timestamp": datetime.now().isoformat(),
            **sample
        })
        
        # Independent helper: keeps the in-memory history bounded so dashboard
        # sampling does not grow forever during long runs.
        if len(self.traffic_data) > self.max_history:
            self.traffic_data.pop(0)

    async def get_network_topology(
        self, packets: List[Dict[str, Any]], mode: str = "live"
    ) -> Dict[str, Any]:
        """
        Build connected device topology and packet flow links.
        In Live Mode: extracts actual devices and flows from captured Npcap packets.
        In Demo Mode: returns deterministic demonstration topology fixtures.
        """
        now_str = datetime.now().isoformat()

        if mode == "demo":
            nodes = [
                {
                    "id": "192.168.1.1",
                    "ip": "192.168.1.1",
                    "label": "Gateway / Firewall",
                    "role": "gateway",
                    "type": "Gateway",
                    "status": "active",
                    "packets_in": 3200,
                    "packets_out": 2850,
                    "total_bytes": 1420000,
                    "protocols": ["TCP", "UDP", "ICMP"],
                    "ports": [22, 53, 80, 443],
                    "is_local": True,
                    "threat_level": "CLEAN",
                },
                {
                    "id": "192.168.1.45",
                    "ip": "192.168.1.45",
                    "label": "SOC Admin Workstation",
                    "role": "workstation",
                    "type": "Admin Workstation",
                    "status": "active",
                    "packets_in": 1150,
                    "packets_out": 890,
                    "total_bytes": 485000,
                    "protocols": ["TCP", "SSH"],
                    "ports": [22, 443],
                    "is_local": True,
                    "threat_level": "CLEAN",
                },
                {
                    "id": "192.168.1.105",
                    "ip": "192.168.1.105",
                    "label": "Engineering Laptop (Compromised)",
                    "role": "compromised",
                    "type": "Endpoint",
                    "status": "threat_detected",
                    "packets_in": 2400,
                    "packets_out": 3800,
                    "total_bytes": 2150000,
                    "protocols": ["TCP", "HTTP", "SMB"],
                    "ports": [80, 443, 445, 3306],
                    "is_local": True,
                    "threat_level": "CRITICAL",
                },
                {
                    "id": "192.168.1.10",
                    "ip": "192.168.1.10",
                    "label": "Domain Controller (AD / DNS)",
                    "role": "server",
                    "type": "Server",
                    "status": "active",
                    "packets_in": 1850,
                    "packets_out": 1420,
                    "total_bytes": 890000,
                    "protocols": ["TCP", "UDP"],
                    "ports": [53, 88, 389, 445],
                    "is_local": True,
                    "threat_level": "MEDIUM",
                },
                {
                    "id": "192.168.1.200",
                    "ip": "192.168.1.200",
                    "label": "Internal Database Server",
                    "role": "server",
                    "type": "Database Server",
                    "status": "active",
                    "packets_in": 1200,
                    "packets_out": 950,
                    "total_bytes": 620000,
                    "protocols": ["TCP"],
                    "ports": [3306, 5432],
                    "is_local": True,
                    "threat_level": "HIGH",
                },
                {
                    "id": "185.220.101.5",
                    "ip": "185.220.101.5",
                    "label": "External C2 Beacon Host",
                    "role": "adversary",
                    "type": "External Threat",
                    "status": "hostile",
                    "packets_in": 2100,
                    "packets_out": 1950,
                    "total_bytes": 1850000,
                    "protocols": ["TCP"],
                    "ports": [443, 8080],
                    "is_local": False,
                    "threat_level": "CRITICAL",
                },
                {
                    "id": "1.1.1.1",
                    "ip": "1.1.1.1",
                    "label": "Cloudflare Public DNS",
                    "role": "external",
                    "type": "Cloud Service",
                    "status": "active",
                    "packets_in": 980,
                    "packets_out": 1050,
                    "total_bytes": 240000,
                    "protocols": ["UDP"],
                    "ports": [53],
                    "is_local": False,
                    "threat_level": "CLEAN",
                },
            ]

            links = [
                {
                    "id": "192.168.1.105->185.220.101.5",
                    "source": "192.168.1.105",
                    "target": "185.220.101.5",
                    "protocol": "TCP",
                    "ports": [443, 8080],
                    "packet_count": 1420,
                    "byte_count": 894000,
                    "direction": "outbound",
                    "status": "active",
                    "is_threat": True,
                    "threat_description": "C2 Bot Beaconing detected over HTTPS",
                },
                {
                    "id": "192.168.1.45->192.168.1.1",
                    "source": "192.168.1.45",
                    "target": "192.168.1.1",
                    "protocol": "TCP",
                    "ports": [22],
                    "packet_count": 320,
                    "byte_count": 45000,
                    "direction": "internal",
                    "status": "active",
                    "is_threat": False,
                    "threat_description": "SSH Admin Management",
                },
                {
                    "id": "192.168.1.105->192.168.1.10",
                    "source": "192.168.1.105",
                    "target": "192.168.1.10",
                    "protocol": "TCP",
                    "ports": [88, 445],
                    "packet_count": 480,
                    "byte_count": 68000,
                    "direction": "internal",
                    "status": "active",
                    "is_threat": True,
                    "threat_description": "Kerberos Authentication Brute-Force",
                },
                {
                    "id": "192.168.1.105->192.168.1.200",
                    "source": "192.168.1.105",
                    "target": "192.168.1.200",
                    "protocol": "TCP",
                    "ports": [3306],
                    "packet_count": 750,
                    "byte_count": 215000,
                    "direction": "internal",
                    "status": "active",
                    "is_threat": True,
                    "threat_description": "Lateral Database Query Scan",
                },
                {
                    "id": "192.168.1.1->1.1.1.1",
                    "source": "192.168.1.1",
                    "target": "1.1.1.1",
                    "protocol": "UDP",
                    "ports": [53],
                    "packet_count": 2100,
                    "byte_count": 198000,
                    "direction": "outbound",
                    "status": "active",
                    "is_threat": False,
                    "threat_description": "DNS Query Forwarding",
                },
            ]

            return {
                "status": "success",
                "mode": "demo",
                "is_demo": True,
                "origin": "DEMO NETWORK TOPOLOGY (DETERMINISTIC DATA)",
                "total_devices": len(nodes),
                "total_connections": len(links),
                "nodes": nodes,
                "links": links,
                "timestamp": now_str,
            }

        # ===== LIVE MODE: Parse real packets =====
        if not packets:
            return {
                "status": "success",
                "mode": "live",
                "is_demo": False,
                "origin": "LIVE NPCAP NETWORK TOPOLOGY",
                "total_devices": 0,
                "total_connections": 0,
                "nodes": [],
                "links": [],
                "timestamp": now_str,
                "message": "No live packets captured yet. Start traffic capture to discover network devices.",
            }

        # Collect host system IPs and names for accurate endpoint classification
        host_ips = set()
        host_name = "Laptop"
        try:
            import socket
            host_name = socket.gethostname()
            host_ips.add(socket.gethostbyname(host_name))
        except Exception:
            pass

        gateway_ip = None
        try:
            from scapy.all import conf
            route = conf.route.route("1.1.1.1")
            if route and len(route) >= 2 and route[1]:
                gateway_ip = str(route[1])
            for iface in conf.ifaces.values():
                if hasattr(iface, "ips") and iface.ips:
                    for ip in iface.ips:
                        if ip:
                            host_ips.add(str(ip))
                if hasattr(iface, "ip") and iface.ip:
                    host_ips.add(str(iface.ip))
        except Exception:
            pass
        host_ips.update({"127.0.0.1", "::1"})

        device_stats: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "packets_in": 0,
                "packets_out": 0,
                "bytes_in": 0,
                "bytes_out": 0,
                "protocols": defaultdict(int),
                "ports": defaultdict(int),
                "first_seen": None,
                "last_seen": None,
            }
        )

        flow_map: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "packet_count": 0,
                "byte_count": 0,
                "protocols": defaultdict(int),
                "ports": defaultdict(int),
                "last_seen": None,
            }
        )

        ip_to_domain: Dict[str, str] = {}

        def is_private_ip(ip_str: Optional[str]) -> bool:
            if not ip_str:
                return False
            if ip_str in host_ips or ip_str == "127.0.0.1" or ip_str == "::1":
                return True
            if ip_str.startswith("10.") or ip_str.startswith("192.168.") or ip_str.startswith("169.254."):
                return True
            octets = ip_str.split(".")
            if len(octets) >= 2 and octets[0] == "172":
                try:
                    sec = int(octets[1])
                    return 16 <= sec <= 31
                except ValueError:
                    return False
            return False

        for p in packets:
            src = p.get("source_ip")
            dst = p.get("dest_ip")
            size = int(p.get("size_bytes") or 0)
            proto = str(p.get("protocol") or "TCP").upper()
            sport = p.get("source_port")
            dport = p.get("dest_port")
            ts = p.get("timestamp") or now_str
            obs_host = p.get("observed_host")
            dns_q = p.get("dns_query")

            if dst:
                if obs_host:
                    ip_to_domain[dst] = obs_host
                elif dns_q and dst not in ip_to_domain:
                    ip_to_domain[dst] = dns_q
            if src and dns_q and src not in ip_to_domain:
                ip_to_domain[src] = dns_q

            if src:
                st = device_stats[src]
                st["packets_out"] += 1
                st["bytes_out"] += size
                st["protocols"][proto] += 1
                if sport:
                    st["ports"][int(sport)] += 1
                if not st["first_seen"]:
                    st["first_seen"] = ts
                st["last_seen"] = ts

            if dst:
                st = device_stats[dst]
                st["packets_in"] += 1
                st["bytes_in"] += size
                st["protocols"][proto] += 1
                if dport:
                    st["ports"][int(dport)] += 1
                if not st["first_seen"]:
                    st["first_seen"] = ts
                st["last_seen"] = ts

            if src and dst and src != dst:
                key = f"{src}->{dst}"
                fl = flow_map[key]
                fl["packet_count"] += 1
                fl["byte_count"] += size
                fl["protocols"][proto] += 1
                if dport:
                    fl["ports"][int(dport)] += 1
                fl["last_seen"] = ts

        # Build live node list
        nodes = []
        for ip, stats in device_stats.items():
            is_local = is_private_ip(ip) or (ip in host_ips)
            is_host = (ip in host_ips)
            is_gateway = (ip == gateway_ip) or (is_local and ip.endswith(".1") and not is_host)
            is_dns = (stats["ports"].get(53, 0) > 0) or ip in {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"}

            if is_host:
                role = "workstation"
                label = f"Laptop ({host_name})"
                device_type = "Host Device (This Machine)"
            elif is_gateway:
                role = "gateway"
                label = f"Default Gateway ({ip})"
                device_type = "Gateway / Router"
            elif is_dns:
                role = "dns"
                dns_name = "Cloudflare DNS" if "1.1.1.1" in ip else ("Google DNS" if "8.8.8.8" in ip else "DNS Resolver")
                label = f"{dns_name} ({ip})"
                device_type = "DNS Name Server"
            elif is_local:
                role = "workstation"
                label = f"LAN Device ({ip})"
                device_type = "Local Network Endpoint"
            else:
                role = "external"
                domain = ip_to_domain.get(ip)
                label = f"{domain}" if domain else f"External Server ({ip})"
                device_type = "External Web Service" if (stats["ports"].get(443, 0) > 0 or stats["ports"].get(80, 0) > 0) else "Remote Cloud Host"

            top_protocols = sorted(
                stats["protocols"].keys(),
                key=lambda pr: stats["protocols"][pr],
                reverse=True,
            )[:3]
            top_ports = sorted(
                stats["ports"].keys(),
                key=lambda pt: stats["ports"][pt],
                reverse=True,
            )[:5]

            nodes.append(
                {
                    "id": ip,
                    "ip": ip,
                    "label": label,
                    "role": role,
                    "type": device_type,
                    "status": "active",
                    "packets_in": stats["packets_in"],
                    "packets_out": stats["packets_out"],
                    "total_bytes": stats["bytes_in"] + stats["bytes_out"],
                    "protocols": top_protocols,
                    "ports": top_ports,
                    "is_local": is_local,
                    "threat_level": "CLEAN",
                }
            )

        # Sort nodes: Local host and Gateway first, then by total traffic volume
        def node_sort_key(node):
            if node["role"] == "workstation" and "Laptop" in node["label"]:
                return (0, -(node["packets_in"] + node["packets_out"]))
            if node["role"] == "gateway":
                return (1, -(node["packets_in"] + node["packets_out"]))
            if node["role"] == "dns":
                return (2, -(node["packets_in"] + node["packets_out"]))
            return (3, -(node["packets_in"] + node["packets_out"]))

        nodes.sort(key=node_sort_key)
        # Limit nodes to top 25 active devices to preserve graph clarity
        nodes = nodes[:25]
        active_node_ids = {n["id"] for n in nodes}

        # Build live link list
        links = []
        for flow_key, fstats in flow_map.items():
            src, dst = flow_key.split("->")
            # Only include links between rendered active nodes
            if src not in active_node_ids or dst not in active_node_ids:
                continue

            top_proto = (
                max(fstats["protocols"], key=fstats["protocols"].get)
                if fstats["protocols"]
                else "TCP"
            )
            top_ports = sorted(
                fstats["ports"].keys(),
                key=lambda pt: fstats["ports"][pt],
                reverse=True,
            )[:4]

            src_local = is_private_ip(src)
            dst_local = is_private_ip(dst)
            if src_local and not dst_local:
                direction = "outbound"
            elif not src_local and dst_local:
                direction = "inbound"
            else:
                direction = "internal"

            reverse_key = f"{dst}->{src}"
            has_reverse = reverse_key in flow_map

            links.append(
                {
                    "id": flow_key,
                    "source": src,
                    "target": dst,
                    "protocol": top_proto,
                    "ports": top_ports,
                    "packet_count": fstats["packet_count"],
                    "byte_count": fstats["byte_count"],
                    "direction": direction,
                    "has_reverse_flow": has_reverse,
                    "status": "active",
                    "recent_activity": fstats["last_seen"],
                    "is_threat": False,
                    "threat_description": f"{top_proto} traffic ({fstats['packet_count']} pkts)",
                }
            )

        return {
            "status": "success",
            "mode": "live",
            "is_demo": False,
            "origin": "LIVE NPCAP NETWORK TOPOLOGY",
            "total_devices": len(nodes),
            "total_connections": len(links),
            "nodes": nodes,
            "links": links,
            "timestamp": now_str,
        }
