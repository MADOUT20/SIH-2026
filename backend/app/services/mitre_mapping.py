"""
MITRE ATT&CK Mapping & Threat Intelligence Service for NetGuard
Provides structured mapping of real-time network threats, packet anomalies,
and website/URL visits to MITRE ATT&CK tactics, technique IDs, and 14-stage kill-chain taxonomy.
"""

from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import re
import math
from urllib.parse import urlsplit

# Complete Enterprise MITRE ATT&CK Tactics Taxonomy (Stages 1 through 14)
MITRE_TACTICS = {
    "TA0043": {
        "id": "TA0043",
        "name": "Reconnaissance",
        "stage_number": 1,
        "description": "Adversary is trying to gather information they can use to plan future operations.",
        "color": "#38bdf8",  # sky-400
    },
    "TA0042": {
        "id": "TA0042",
        "name": "Resource Development",
        "stage_number": 2,
        "description": "Adversary is trying to establish resources they can use to support operations.",
        "color": "#60a5fa",  # blue-400
    },
    "TA0001": {
        "id": "TA0001",
        "name": "Initial Access",
        "stage_number": 3,
        "description": "Adversary is trying to get into your network through entry vectors like phishing or exposed services.",
        "color": "#818cf8",  # indigo-400
    },
    "TA0002": {
        "id": "TA0002",
        "name": "Execution",
        "stage_number": 4,
        "description": "Adversary is trying to run malicious code or trojan payloads on network endpoints.",
        "color": "#a78bfa",  # violet-400
    },
    "TA0003": {
        "id": "TA0003",
        "name": "Persistence",
        "stage_number": 5,
        "description": "Adversary is trying to maintain their foothold across restarts and credential rotations.",
        "color": "#c084fc",  # purple-400
    },
    "TA0004": {
        "id": "TA0004",
        "name": "Privilege Escalation",
        "stage_number": 6,
        "description": "Adversary is trying to gain higher-level permissions like SYSTEM or root.",
        "color": "#e879f9",  # fuchsia-400
    },
    "TA0005": {
        "id": "TA0005",
        "name": "Defense Evasion",
        "stage_number": 7,
        "description": "Adversary is trying to avoid being detected by security filters, firewalls, or proxies.",
        "color": "#f472b6",  # pink-400
    },
    "TA0006": {
        "id": "TA0006",
        "name": "Credential Access",
        "stage_number": 8,
        "description": "Adversary is trying to steal credentials like account names and passwords.",
        "color": "#fb7185",  # rose-400
    },
    "TA0007": {
        "id": "TA0007",
        "name": "Discovery",
        "stage_number": 9,
        "description": "Adversary is trying to observe the system and internal network topology.",
        "color": "#fb923c",  # orange-400
    },
    "TA0008": {
        "id": "TA0008",
        "name": "Lateral Movement",
        "stage_number": 10,
        "description": "Adversary is trying to move through your environment to reach target assets.",
        "color": "#facc15",  # yellow-400
    },
    "TA0009": {
        "id": "TA0009",
        "name": "Collection",
        "stage_number": 11,
        "description": "Adversary is trying to gather data of interest to their goal.",
        "color": "#a3e635",  # lime-400
    },
    "TA0011": {
        "id": "TA0011",
        "name": "Command and Control",
        "stage_number": 12,
        "description": "Adversary is communicating with systems under their control outside the network.",
        "color": "#4ade80",  # green-400
    },
    "TA0010": {
        "id": "TA0010",
        "name": "Exfiltration",
        "stage_number": 13,
        "description": "Adversary is trying to steal data by transmitting it to external locations.",
        "color": "#2dd4bf",  # teal-400
    },
    "TA0040": {
        "id": "TA0040",
        "name": "Impact",
        "stage_number": 14,
        "description": "Adversary is trying to manipulate, interrupt, or destroy your network systems and data.",
        "color": "#ef4444",  # red-500
    },
}

# Mapping of NetGuard Threat & Packet Alert Types to MITRE ATT&CK Techniques
THREAT_TYPE_MITRE_MAP: Dict[str, Dict[str, Any]] = {
    # --- TROJAN & MALICIOUS EXECUTION (Stage 4: Execution) ---
    "TROJAN": {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_id": "T1204.002",
        "technique_name": "User Execution: Malicious File",
        "sub_technique": "Malicious Executable / Dropper",
        "stage_number": 4,
        "category": "Trojan Horse / Dropper",
        "description": "Attempt to deliver or execute Trojan horse payloads disguised as legitimate software or media.",
        "mitigation": "Block payload URLs at proxy boundary; restrict executable downloads; endpoint EDR inspection.",
        "reference_url": "https://attack.mitre.org/techniques/T1204/002/",
    },
    "TROJAN_DOWNLOAD": {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_id": "T1204.002",
        "technique_name": "User Execution: Malicious File",
        "sub_technique": "Ingress Tool Transfer (T1105)",
        "stage_number": 4,
        "category": "Trojan Horse / Dropper",
        "description": "Inbound file transfer containing suspected Trojan executable or malicious script delivery.",
        "mitigation": "Terminate TCP stream; isolate downloading host; inspect file hash in sandbox.",
        "reference_url": "https://attack.mitre.org/techniques/T1204/002/",
    },
    "MALWARE": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "sub_technique": "Malicious Web Asset",
        "stage_number": 3,
        "secondary_tactic": {
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1204",
            "technique_name": "User Execution",
        },
        "category": "Malware Distribution",
        "description": "Access to a known malware distribution hub or drive-by compromise landing page.",
        "mitigation": "DNS sinkholing; enforce strict HTTP proxy block list; browser isolation.",
        "reference_url": "https://attack.mitre.org/techniques/T1189/",
    },
    "MALWARE_SITE_VISIT": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "sub_technique": "Spearphishing Link (T1566.002)",
        "stage_number": 3,
        "secondary_tactic": {
            "tactic_id": "TA0011",
            "tactic_name": "Command and Control",
            "technique_id": "T1071.001",
            "technique_name": "Application Layer Protocol: Web Protocols",
        },
        "category": "Malicious Website Visit",
        "description": "Connection initiated to a confirmed malicious site, C2 beacon, or exploit landing host.",
        "mitigation": "Automated DNS sinkholing; host-based domain blocking in NetGuard proxy.",
        "reference_url": "https://attack.mitre.org/techniques/T1189/",
    },
    "PHISHING": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1566.002",
        "technique_name": "Phishing: Spearphishing Link",
        "sub_technique": "Credential Harvesting Link",
        "stage_number": 3,
        "category": "Phishing Vector",
        "description": "Navigating to a deceptive domain designed to harvest credentials or session tokens.",
        "mitigation": "Block malicious URL; revoke recently entered credentials; enforce multi-factor authentication.",
        "reference_url": "https://attack.mitre.org/techniques/T1566/002/",
    },
    "PHISHING_WEBSITE": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1566.002",
        "technique_name": "Phishing: Spearphishing Link",
        "sub_technique": "Credential Harvesting Link",
        "stage_number": 3,
        "category": "Phishing Vector",
        "description": "Web traffic visiting a counterfeit credential-harvesting or banking phishing website.",
        "mitigation": "Block malicious URL; revoke recently entered credentials; enforce multi-factor authentication.",
        "reference_url": "https://attack.mitre.org/techniques/T1566/002/",
    },
    "RANSOMWARE": {
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "sub_technique": "Ransomware Key Exchange",
        "stage_number": 14,
        "category": "Ransomware Activity",
        "description": "Communication with known ransomware infrastructure or automated encryption key distribution servers.",
        "mitigation": "Immediately isolate host from local network; revoke active SMB shares; trigger backup restoration.",
        "reference_url": "https://attack.mitre.org/techniques/T1486/",
    },
    "C2_COMMUNICATION": {
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "sub_technique": "C2 Heartbeat",
        "stage_number": 12,
        "category": "Command & Control",
        "description": "Periodic or structured beacon traffic communicating with an external attacker-controlled C2 node.",
        "mitigation": "Block remote IP/domain; terminate process establishing socket connection; inspect host memory.",
        "reference_url": "https://attack.mitre.org/techniques/T1071/001/",
    },
    "SPYWARE": {
        "tactic_id": "TA0009",
        "tactic_name": "Collection",
        "technique_id": "T1056.001",
        "technique_name": "Input Capture: Keylogging",
        "sub_technique": "Screen & Keystroke Harvesting",
        "stage_number": 11,
        "category": "Spyware / Infostealer",
        "description": "Outbound transmission of captured telemetry, keystrokes, browser passwords, or clipboard buffers.",
        "mitigation": "Isolate affected workstation; scan with antimalware; force password rotation across all services.",
        "reference_url": "https://attack.mitre.org/techniques/T1056/001/",
    },
    "EXPLOIT_KIT": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "sub_technique": "Browser Vulnerability Exploit",
        "stage_number": 3,
        "category": "Exploit Kit",
        "description": "Automated delivery of zero-day or memory corruption exploits via weaponized web pages.",
        "mitigation": "Keep browser engines patched; enable OS memory protections (ASLR/DEP); isolate browsing.",
        "reference_url": "https://attack.mitre.org/techniques/T1203/",
    },
    "CRYPTOMINING": {
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "technique_id": "T1496",
        "technique_name": "Resource Hijacking",
        "sub_technique": "Network Mining Pool Traffic (Stratum)",
        "stage_number": 14,
        "category": "Cryptojacking",
        "description": "Connections to cryptocurrency mining pools utilizing network compute and power resources unauthorized.",
        "mitigation": "Block mining pool ports (3333, 4444, 14444) and domain lists at gateway.",
        "reference_url": "https://attack.mitre.org/techniques/T1496/",
    },
    "BEACONING": {
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "sub_technique": "Regular Interval Heartbeat",
        "stage_number": 12,
        "category": "C2 Beaconing",
        "description": "Rhythmic low-jitter HTTP/HTTPS outbound traffic indicating automated botnet check-ins.",
        "mitigation": "Trace process establishing recurrent TCP sessions; block destination IP subnet.",
        "reference_url": "https://attack.mitre.org/techniques/T1071/001/",
    },
    "SUSPICIOUS_BEACON": {
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "sub_technique": "Regular Interval Heartbeat",
        "stage_number": 12,
        "category": "C2 Beaconing",
        "description": "Rhythmic low-jitter HTTP/HTTPS outbound traffic indicating automated botnet check-ins.",
        "mitigation": "Trace process establishing recurrent TCP sessions; block destination IP subnet.",
        "reference_url": "https://attack.mitre.org/techniques/T1071/001/",
    },
    "SEQUENTIAL_PORT_PROBE": {
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "technique_id": "T1595.001",
        "technique_name": "Active Scanning: Port Scanning",
        "sub_technique": "Port Scanning",
        "stage_number": 1,
        "category": "Reconnaissance",
        "description": "Sequential or broad TCP/UDP port probing to discover open network services and vulnerabilities.",
        "mitigation": "Filter ingress probe traffic at perimeter firewall; rate-limit SYN packets.",
        "reference_url": "https://attack.mitre.org/techniques/T1595/001/",
    },
    "PORT_SCAN": {
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "sub_technique": "Service Scan",
        "stage_number": 9,
        "category": "Discovery",
        "description": "Probing hosts to determine remote operating services and potential exploit surfaces.",
        "mitigation": "Segment internal network segments; deploy port knocking / zero-trust access control.",
        "reference_url": "https://attack.mitre.org/techniques/T1046/",
    },
    "SUSPICIOUS_PACKET_BURST": {
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "sub_technique": "Direct Network Flood",
        "stage_number": 14,
        "category": "Denial of Service",
        "description": "High-velocity packet volume anomaly designed to degrade service bandwidth or exhaust sockets.",
        "mitigation": "Enforce adaptive PPS throttling and TCP SYN-cookies on ingress routes.",
        "reference_url": "https://attack.mitre.org/techniques/T1498/",
    },
    "DDOS": {
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "technique_id": "T1498.001",
        "technique_name": "Network Denial of Service: Direct Network Flood",
        "sub_technique": "Direct Network Flood",
        "stage_number": 14,
        "category": "Denial of Service",
        "description": "Coordinated multi-source packet flooding targeting internal network infrastructure.",
        "mitigation": "Upstream ISP blackholing; automatic IP rate-limiting thresholds.",
        "reference_url": "https://attack.mitre.org/techniques/T1498/001/",
    },
    "DNS_TUNNELING": {
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "technique_id": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS",
        "sub_technique": "DNS Protocol Tunneling",
        "stage_number": 12,
        "category": "C2 / Exfiltration",
        "description": "Encapsulating non-DNS command/exfiltration payloads inside encoded DNS request queries.",
        "mitigation": "Inspect DNS payload entropy; enforce authoritative DNS proxy inspection.",
        "reference_url": "https://attack.mitre.org/techniques/T1071/004/",
    },
    "DATA_EXFILTRATION": {
        "tactic_id": "TA0010",
        "tactic_name": "Exfiltration",
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "sub_technique": "Encrypted Exfiltration",
        "stage_number": 13,
        "category": "Data Exfiltration",
        "description": "Anomalously large outbound payload transfers transmitted to untrusted external endpoints.",
        "mitigation": "DLP egress inspection; byte threshold alerting and session termination.",
        "reference_url": "https://attack.mitre.org/techniques/T1041/",
    },
    "BRUTE_FORCE": {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "sub_technique": "Password Guessing",
        "stage_number": 8,
        "category": "Credential Access",
        "description": "Rapid repetitive authentication requests attempting to compromise administrative or service accounts.",
        "mitigation": "Account lockout policies; IP-based connection throttling after repeated failures.",
        "reference_url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "UNENCRYPTED_SENSITIVE_TRAFFIC": {
        "tactic_id": "TA0009",
        "tactic_name": "Collection",
        "technique_id": "T1040",
        "technique_name": "Network Sniffing",
        "sub_technique": "Cleartext Inspection",
        "stage_number": 11,
        "category": "Information Gathering",
        "description": "Transmitting sensitive protocol data in cleartext (e.g. HTTP, Telnet, FTP) vulnerable to eavesdropping.",
        "mitigation": "Enforce mandatory TLS 1.3 / HTTPS-only transit policies across the local network.",
        "reference_url": "https://attack.mitre.org/techniques/T1040/",
    },
}

DEFAULT_MITRE_MAPPING = {
    "tactic_id": "TA0007",
    "tactic_name": "Discovery",
    "technique_id": "T1046",
    "technique_name": "Network Service Discovery",
    "sub_technique": "Network Traffic Anomaly",
    "stage_number": 9,
    "category": "Network Anomaly",
    "description": "Network traffic behavior exhibiting anomalous patterns requiring behavioral analysis.",
    "mitigation": "Baseline normal network flows and flag protocol deviations.",
    "reference_url": "https://attack.mitre.org/techniques/T1046/",
}

# High-Risk Suspicious Keywords in Domains/URLs for Heuristic Threat Detection
SUSPICIOUS_DOMAIN_KEYWORDS = {
    "trojan": ("TROJAN", "CRITICAL", "Trojan Payload Delivery Vector"),
    "malware": ("MALWARE", "CRITICAL", "Malware Dropper / Distribution"),
    "ransom": ("RANSOMWARE", "CRITICAL", "Ransomware Encryption Command Node"),
    "lockbit": ("RANSOMWARE", "CRITICAL", "Ransomware Campaign Endpoint"),
    "payload": ("TROJAN_DOWNLOAD", "HIGH", "Malicious Binary Payload Host"),
    "stealer": ("SPYWARE", "CRITICAL", "Infostealer / Keylogger Exfiltration"),
    "keylogger": ("SPYWARE", "HIGH", "Keystroke Harvesting Endpoint"),
    "phish": ("PHISHING", "HIGH", "Deceptive Phishing Credential Portal"),
    "secure-login": ("PHISHING", "MEDIUM", "Suspected Credential Harvester"),
    "account-verify": ("PHISHING", "MEDIUM", "Impersonated Authentication Portal"),
    "banking-update": ("PHISHING", "HIGH", "Banking Phishing Scheme"),
    "exploit": ("EXPLOIT_KIT", "CRITICAL", "Browser Exploit Kit"),
    "c2": ("C2_COMMUNICATION", "CRITICAL", "Command & Control Node"),
    "botnet": ("C2_COMMUNICATION", "CRITICAL", "Botnet Master Controller"),
    "miner": ("CRYPTOMINING", "MEDIUM", "Cryptocurrency Mining Pool"),
    "coinhive": ("CRYPTOMINING", "HIGH", "Cryptojacking Web Script"),
    "darkweb": ("MALWARE", "HIGH", "Darknet Associated Dropper"),
    "crack": ("TROJAN", "HIGH", "Trojanized Software Crack"),
    "keygen": ("TROJAN", "HIGH", "Trojanized Key Generator"),
    "eicar": ("MALWARE", "HIGH", "Standard Antimalware Test Target (EICAR)"),
    "wicar": ("EXPLOIT_KIT", "HIGH", "Web Exploitation Test Target (WICAR)"),
}

HIGH_RISK_TLDS = {".xyz", ".top", ".cc", ".su", ".pw", ".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".download", ".work"}


class MitreMappingService:
    """Service providing MITRE ATT&CK classification, website scanning, and kill-chain stage tracking."""

    @staticmethod
    def get_taxonomy() -> Dict[str, Any]:
        """Return the complete ATT&CK matrix tactics and technique definitions."""
        return {
            "tactics": MITRE_TACTICS,
            "techniques": THREAT_TYPE_MITRE_MAP,
            "total_tactics": len(MITRE_TACTICS),
            "total_mapped_techniques": len(THREAT_TYPE_MITRE_MAP),
            "framework_version": "v15.1",
        }

    @staticmethod
    def map_threat(threat_type: str, threat_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Map a threat finding to its MITRE ATT&CK tactic, technique, and stage.
        """
        threat_key = str(threat_type).upper().strip().replace(" ", "_").replace("-", "_")
        mapping = THREAT_TYPE_MITRE_MAP.get(threat_key, DEFAULT_MITRE_MAPPING)

        tactic_info = MITRE_TACTICS.get(mapping["tactic_id"], {})
        stage_num = mapping["stage_number"]
        tactic_name = mapping["tactic_name"]

        result = {
            "threat_type": threat_type,
            "tactic_id": mapping["tactic_id"],
            "tactic_name": tactic_name,
            "technique_id": mapping["technique_id"],
            "technique_name": mapping["technique_name"],
            "sub_technique": mapping.get("sub_technique"),
            "stage_number": stage_num,
            "stage_name": tactic_name,
            "stage_label": f"Stage {stage_num}: {tactic_name}",
            "stage_description": tactic_info.get("description", ""),
            "color": tactic_info.get("color", "#94a3b8"),
            "category": mapping.get("category", "Network Threat"),
            "description": mapping["description"],
            "mitigation": mapping["mitigation"],
            "reference_url": mapping["reference_url"],
            "secondary_tactic": mapping.get("secondary_tactic"),
        }

        # Enhance with runtime threat context if provided
        if threat_data:
            result["threat_id"] = threat_data.get("id")
            result["source_ip"] = threat_data.get("source_ip")
            result["severity"] = threat_data.get("severity")
            result["timestamp"] = threat_data.get("timestamp")
            result["destination_host"] = threat_data.get("destination_host")

        return result

    @staticmethod
    def infer_attack_stage_from_packet(packet_info: Dict[str, Any], is_malicious: bool = False) -> Dict[str, Any]:
        """
        Derive the exact MITRE ATT&CK stage for ML prediction inspection.
        """
        alerts = packet_info.get("security_alerts", [])
        if alerts:
            return MitreMappingService.map_threat(alerts[0])

        dest_port = packet_info.get("dest_port")
        protocol = str(packet_info.get("protocol", "")).upper()
        flags = packet_info.get("flags", [])
        size = packet_info.get("size_bytes", 0)
        dns_query = packet_info.get("dns_query")
        observed_host = packet_info.get("observed_host")

        # Check DNS queries / host for keyword indicators
        target_str = f"{dns_query or ''} {observed_host or ''}".lower()
        for kw, (t_type, _, _) in SUSPICIOUS_DOMAIN_KEYWORDS.items():
            if kw in target_str:
                return MitreMappingService.map_threat(t_type)

        if protocol == "TCP" and "SYN" in flags and "ACK" not in flags:
            return MitreMappingService.map_threat("SEQUENTIAL_PORT_PROBE")

        if size > 15000:
            return MitreMappingService.map_threat("DATA_EXFILTRATION")

        if dest_port in {4444, 5555, 6666, 7777, 31337, 1337}:
            return MitreMappingService.map_threat("C2_COMMUNICATION")

        if dest_port in {80, 8080}:
            return MitreMappingService.map_threat("UNENCRYPTED_SENSITIVE_TRAFFIC")

        if dest_port == 443 or observed_host:
            if is_malicious:
                return MitreMappingService.map_threat("TROJAN")
            return MitreMappingService.map_threat("MALICIOUS_SITE_VISIT")

        if protocol == "UDP" and (dest_port == 53 or dns_query):
            return MitreMappingService.map_threat("DNS_TUNNELING")

        return MitreMappingService.map_threat("DEFAULT")

    @staticmethod
    def scan_website_threat(url_or_domain: str) -> Dict[str, Any]:
        """
        Multi-signal heuristic website threat scanner (offline capable).
        Evaluates subtle & minor suspicious indicators, domain characteristics,
        URL/path anomalies, and known attack patterns.
        Distinguishes: Clean, Low Risk, Medium Risk, High Risk, Critical.
        """
        raw_input = (url_or_domain or "").strip()
        if not raw_input:
            return {
                "url": "",
                "domain": "",
                "is_malicious": False,
                "threat_type": "BENIGN_SAFE",
                "threat_category": "Normal / Safe Website",
                "severity": "SAFE",
                "risk_level": "Clean",
                "threat_score": 0.0,
                "confidence_percent": 100,
                "contributing_signals": [],
                "mitre_mapping": MitreMappingService.map_threat("BENIGN"),
                "warning": {"title": "No URL Provided", "headline": "Enter a valid URL to scan."},
                "evidence": ["No input provided"],
                "scan_timestamp": datetime.now().isoformat(),
                "engine": "NetGuard Multi-Signal Heuristic Analyzer (Offline Capable)",
            }

        # Normalize URL / Domain
        target = raw_input
        if not target.startswith("http://") and not target.startswith("https://"):
            target = f"https://{target}"

        try:
            parsed = urlsplit(target)
            raw_host = (parsed.hostname or raw_input).lower().rstrip(".")
            domain = raw_host
            path = parsed.path.lower()
            query = parsed.query.lower()
            port = parsed.port
            full_target = f"{domain}{path}"
        except Exception:
            domain = raw_input.lower().split("/")[0]
            path = ""
            query = ""
            port = None
            full_target = domain

        # Known legitimate domains whitelist to avoid false positives
        KNOWN_CLEAN_DOMAINS = {
            "google.com", "www.google.com", "github.com", "microsoft.com", "apple.com",
            "amazon.com", "wikipedia.org", "cloudflare.com", "stackoverflow.com",
            "youtube.com", "linkedin.com", "twitter.com", "x.com", "reddit.com",
            "netflix.com", "zoom.us", "gov.in", "nic.in", "ac.in", "edu"
        }

        # Check if domain matches legitimate authority (and has no malicious executable download attached)
        is_whitelisted = any(domain == cd or domain.endswith(f".{cd}") for cd in KNOWN_CLEAN_DOMAINS)
        has_dangerous_extension = any(path.endswith(ext) for ext in [".exe", ".scr", ".vbs", ".bat", ".apk", ".dll", ".ps1", ".hta", ".iso", ".msi"])

        if is_whitelisted and not has_dangerous_extension:
            mitre_info = MitreMappingService.map_threat("BENIGN")
            return {
                "url": target,
                "domain": domain,
                "path": path,
                "is_malicious": False,
                "threat_type": "BENIGN_SAFE",
                "threat_category": "Verified Trusted Website",
                "severity": "SAFE",
                "risk_level": "Clean",
                "threat_score": 0.02,
                "confidence_percent": 99,
                "contributing_signals": [
                    {
                        "name": "Verified Authority",
                        "category": "Domain Trust",
                        "severity": "CLEAN",
                        "weight": -0.5,
                        "description": f"Domain '{domain}' matches verified trusted internet services authority.",
                    }
                ],
                "mitre_mapping": {
                    **mitre_info,
                    "stage_label": f"Stage {mitre_info['stage_number']}: {mitre_info['tactic_name']}",
                },
                "warning": {
                    "title": "✅ CLEAN / TRUSTED DESTINATION",
                    "headline": f"Website '{domain}' is a verified legitimate service with zero threat indicators.",
                    "recommendation": "Standard network communication permitted. No defensive action needed.",
                    "prevention_steps": ["NetGuard background packet inspection remains active."],
                    "badge_severity": "SAFE",
                },
                "evidence": [
                    f"Domain matches verified legitimate service authority ({domain})",
                    "Valid standard URL structure with no executable payload path",
                ],
                "scan_timestamp": datetime.now().isoformat(),
                "engine": "NetGuard Multi-Signal Heuristic Analyzer (Offline Capable)",
            }

        signals: List[Dict[str, Any]] = []
        evidence: List[str] = []
        score_accum = 0.0

        # --- Signal 1: Dangerous Executable / Trojan Payload Extensions ---
        dangerous_exts = {
            ".exe": ("Executable binary payload", 0.85),
            ".scr": ("Windows screensaver executable payload", 0.90),
            ".vbs": ("VBScript payload", 0.80),
            ".bat": ("Batch script execution file", 0.75),
            ".apk": ("Android application package dropper", 0.80),
            ".dll": ("Dynamic link library payload", 0.85),
            ".ps1": ("PowerShell script dropper", 0.85),
            ".hta": ("HTML application executable payload", 0.90),
            ".iso": ("Disk image container payload", 0.80),
            ".msi": ("Windows installer binary package", 0.80),
        }
        matched_ext = None
        for ext, (ext_desc, ext_weight) in dangerous_exts.items():
            if path.endswith(ext):
                matched_ext = ext
                score_accum += ext_weight
                signals.append({
                    "name": "Dangerous Executable Extension",
                    "category": "Payload Vector",
                    "severity": "CRITICAL",
                    "weight": ext_weight,
                    "description": f"Direct link to executable payload with extension '{ext}' ({ext_desc}).",
                })
                evidence.append(f"Direct executable file download link with high-risk extension: '{ext}'")
                break

        # Check for deceptive double extensions (e.g. invoice.pdf.exe)
        if re.search(r"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.(exe|scr|vbs|bat|ps1|hta|iso)$", path):
            score_accum += 0.90
            signals.append({
                "name": "Deceptive Double Extension",
                "category": "Malware Obfuscation",
                "severity": "CRITICAL",
                "weight": 0.90,
                "description": "Double file extension pattern detected (e.g., disguising executable as document or image).",
            })
            evidence.append("Deceptive double file extension disguising executable payload as a document")

        # --- Signal 2: Known Malicious Signature Keywords ---
        matched_keyword = None
        for kw, (mapped_type, assigned_sev, cat_label) in SUSPICIOUS_DOMAIN_KEYWORDS.items():
            if kw in full_target:
                matched_keyword = kw
                weight = 0.70 if assigned_sev == "CRITICAL" else (0.50 if assigned_sev == "HIGH" else 0.35)
                score_accum += weight
                signals.append({
                    "name": f"Known Attack Keyword '{kw}'",
                    "category": "Signature Detection",
                    "severity": assigned_sev,
                    "weight": weight,
                    "description": f"Target contains malicious keyword '{kw}' ({cat_label}).",
                })
                evidence.append(f"Contains attack keyword pattern: '{kw}' in hostname or path")
                break

        # --- Signal 3: Phishing Patterns & Deceptive Brand Impersonation ---
        PHISH_BRANDS = ["paypal", "microsoft", "google", "apple", "netflix", "amazon", "chase", "bankofamerica", "binance", "metamask", "coinbase", "facebook", "instagram"]
        PHISH_AUTH_TERMS = ["login", "signin", "verify", "secure", "account", "update", "banking", "billing", "recovery", "support", "auth", "credential", "portal"]

        domain_no_tld = domain.split(".")[0] if "." in domain else domain
        has_brand = any(b in domain for b in PHISH_BRANDS)
        has_auth = any(a in domain for a in PHISH_AUTH_TERMS) or any(a in path for a in PHISH_AUTH_TERMS)

        if has_brand and has_auth and not is_whitelisted:
            score_accum += 0.65
            signals.append({
                "name": "Brand Credential Phishing Pattern",
                "category": "Phishing Vector",
                "severity": "HIGH",
                "weight": 0.65,
                "description": "Deceptive combination of major consumer brand and credential authentication keywords on untrusted domain.",
            })
            evidence.append("Deceptive credential-harvesting pattern: brand name combined with authentication keywords")

        # Check for typosquatting / homoglyph patterns (e.g. paypa1, micros0ft, g00gle)
        homoglyphs = ["paypa1", "micros0ft", "g00gle", "faceb00k", "netf1ix", "amaz0n", "sec-login", "apple-id-verify"]
        if any(hg in domain for hg in homoglyphs):
            score_accum += 0.70
            signals.append({
                "name": "Typosquatting Homoglyph Substitution",
                "category": "Phishing Vector",
                "severity": "HIGH",
                "weight": 0.70,
                "description": "Domain employs character substitution / typosquatting to mimic trusted brands.",
            })
            evidence.append("Typosquatting / homoglyph character substitution detected mimicking legitimate brand")

        # --- Signal 4: High-Risk and Abused TLDs ---
        matched_tld = None
        for tld in HIGH_RISK_TLDS:
            if domain.endswith(tld):
                matched_tld = tld
                score_accum += 0.30
                signals.append({
                    "name": f"High-Risk TLD '{tld}'",
                    "category": "Domain Characteristics",
                    "severity": "MEDIUM",
                    "weight": 0.30,
                    "description": f"Domain registered under frequently abused TLD extension: '{tld}'.",
                })
                evidence.append(f"Domain registered under high-risk TLD extension: '{tld}'")
                break

        # --- Signal 5: URL & Path Anomalies ---
        # 5a. Raw IP-literal address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            score_accum += 0.35
            signals.append({
                "name": "Direct IP-Literal Host",
                "category": "Network Anomaly",
                "severity": "MEDIUM",
                "weight": 0.35,
                "description": f"Direct raw IP-literal address ({domain}) accessed without DNS domain validation.",
            })
            evidence.append(f"Direct raw IP-literal address accessed ({domain}) bypassing standard DNS trust validation")

        # 5b. Embedded '@' symbol in URL
        if "@" in target:
            score_accum += 0.40
            signals.append({
                "name": "Embedded URL Authority Deception ('@')",
                "category": "URL Anomaly",
                "severity": "HIGH",
                "weight": 0.40,
                "description": "URL contains '@' symbol, a common browser spoofing technique to mislead destination authority.",
            })
            evidence.append("URL contains embedded '@' symbol indicating authority deception attempt")

        # 5c. Non-standard port
        if port and port not in {80, 443}:
            score_accum += 0.20
            signals.append({
                "name": f"Non-Standard Port :{port}",
                "category": "Network Anomaly",
                "severity": "LOW",
                "weight": 0.20,
                "description": f"Web traffic directed to unusual non-standard port :{port}.",
            })
            evidence.append(f"Service running on non-standard port: :{port}")

        # 5d. Path traversal or command injection patterns
        if any(pt in f"{path}?{query}" for pt in ["../", "..\\", "%2e%2e", "cmd=", "exec=", "eval=", "system="]):
            score_accum += 0.50
            signals.append({
                "name": "Path Traversal / Command Injection Signature",
                "category": "Exploitation Anomaly",
                "severity": "HIGH",
                "weight": 0.50,
                "description": "Path or query parameters contain directory traversal or remote command injection tokens.",
            })
            evidence.append("Path or query parameters contain directory traversal or command injection patterns")

        # 5e. Suspicious redirection parameter
        if any(rp in query for rp in ["redirect=", "redirect_to=", "url=http", "dest=http", "return_url="]):
            score_accum += 0.20
            signals.append({
                "name": "Open Redirect / Redirection Parameter",
                "category": "URL Anomaly",
                "severity": "LOW",
                "weight": 0.20,
                "description": "URL contains open redirect parameter frequently abused in phishing delivery chains.",
            })
            evidence.append("Contains open redirection parameter query string")

        # --- Signal 6: Domain Structure, Entropy & Obfuscation ---
        # 6a. Shannon entropy on domain name (DGA detection)
        if len(domain_no_tld) > 9:
            chars = list(domain_no_tld)
            prob = [float(chars.count(c)) / len(chars) for c in set(chars)]
            entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
            if entropy > 3.65:
                score_accum += 0.35
                signals.append({
                    "name": f"High Domain Entropy ({entropy:.2f} bits)",
                    "category": "Domain Characteristics",
                    "severity": "MEDIUM",
                    "weight": 0.35,
                    "description": f"Shannon entropy ({entropy:.2f} bits) exceeds natural language thresholds, indicating algorithmic generation (DGA).",
                })
                evidence.append(f"High domain entropy detected ({entropy:.2f} bits) indicating algorithmic generation (DGA)")

        # 6b. Deep subdomain nesting (e.g. a.b.c.d.domain.com)
        subdomain_count = len(domain.split(".")) - 2
        if subdomain_count >= 3:
            score_accum += 0.25
            signals.append({
                "name": f"Deep Subdomain Nesting ({subdomain_count} levels)",
                "category": "Domain Characteristics",
                "severity": "LOW",
                "weight": 0.25,
                "description": f"Domain contains {subdomain_count} levels of subdomains, a pattern used to hide actual registrars.",
            })
            evidence.append(f"Deep subdomain nesting detected ({subdomain_count} levels)")

        # 6c. Excessive hyphens or numeric density
        hyphen_count = domain.count("-")
        digit_count = sum(c.isdigit() for c in domain)
        if hyphen_count >= 3 or (len(domain) > 8 and digit_count / len(domain) > 0.4):
            score_accum += 0.20
            signals.append({
                "name": "Excessive Hyphens / Numeric Density",
                "category": "Domain Characteristics",
                "severity": "LOW",
                "weight": 0.20,
                "description": f"Domain has {hyphen_count} hyphens and {digit_count} digits, typical of disposable lure domains.",
            })
            evidence.append(f"Domain structure has unusual hyphen or numeric density ({hyphen_count} hyphens, {digit_count} digits)")

        # 6d. Punycode / IDN Homograph attack
        if "xn--" in domain:
            score_accum += 0.40
            signals.append({
                "name": "Punycode IDN Encoded Domain",
                "category": "Obfuscation",
                "severity": "HIGH",
                "weight": 0.40,
                "description": "Internationalized domain name (Punycode 'xn--') detected, which can deceive visual inspection.",
            })
            evidence.append("Punycode (xn--) internationalized domain pattern detected")

        # Final Score and Risk Level Classification
        clamped_score = min(0.99, max(0.02, score_accum)) if signals else 0.05

        if clamped_score >= 0.90:
            risk_level = "Critical"
            severity = "CRITICAL"
            is_malicious = True
            threat_type = "TROJAN_DOWNLOAD" if matched_ext else "MALWARE"
            threat_category = "Critical Malicious / Payload Vector"
            confidence = 96
        elif clamped_score >= 0.70:
            risk_level = "High Risk"
            severity = "HIGH"
            is_malicious = True
            threat_type = "PHISHING" if has_brand or "phish" in full_target else "MALWARE_SITE_VISIT"
            threat_category = "High-Risk Deceptive / Phishing Host"
            confidence = 88
        elif clamped_score >= 0.40:
            risk_level = "Medium Risk"
            severity = "MEDIUM"
            is_malicious = True
            threat_type = "MALWARE_SITE_VISIT"
            threat_category = "Suspicious Domain / Anomaly Detected"
            confidence = 74
        elif clamped_score >= 0.15:
            risk_level = "Low Risk"
            severity = "LOW"
            is_malicious = False
            threat_type = "BENIGN_SAFE"
            threat_category = "Low-Risk Minor Anomaly"
            confidence = 80
        else:
            risk_level = "Clean"
            severity = "SAFE"
            is_malicious = False
            threat_type = "BENIGN_SAFE"
            threat_category = "Normal / Clean Website"
            confidence = 95

        # Map to MITRE
        mitre_info = MitreMappingService.map_threat(threat_type if is_malicious else "BENIGN")

        if is_malicious:
            warning_title = f"⚠️ {risk_level.upper()} SECURITY WARNING"
            headline = f"Potential threat vector identified on '{domain}' with risk score {clamped_score:.2f}."
            recommendation = "NetGuard recommends restricting access or enforcing proxy domain block."
            prevention_steps = [
                f"Block domain '{domain}' across local network and proxy rules.",
                "Verify host identity before entering credentials or submitting forms.",
                f"Review MITRE technique {mitre_info['technique_id']} ({mitre_info['technique_name']}) mitigations.",
            ]
        else:
            warning_title = "✅ SAFE / BENIGN DESTINATION" if risk_level == "Clean" else "ℹ️ LOW RISK ADVISORY"
            headline = f"Website '{domain}' exhibits normal network characteristics (Score: {clamped_score:.2f})."
            recommendation = "No critical malware or high-risk threat indicators observed."
            prevention_steps = ["Standard NetGuard packet monitoring remains active."]
            if not evidence:
                evidence.append("Host matches standard legitimate domain structure with low entropy and valid scheme")

        return {
            "url": target,
            "domain": domain,
            "path": path,
            "is_malicious": is_malicious,
            "threat_type": threat_type,
            "threat_category": threat_category,
            "severity": severity,
            "risk_level": risk_level,
            "threat_score": round(clamped_score, 2),
            "confidence_percent": confidence,
            "contributing_signals": signals,
            "mitre_mapping": {
                **mitre_info,
                "stage_label": f"Stage {mitre_info['stage_number']}: {mitre_info['tactic_name']}",
            },
            "warning": {
                "title": warning_title,
                "headline": headline,
                "recommendation": recommendation,
                "prevention_steps": prevention_steps,
                "badge_severity": severity,
            },
            "evidence": evidence,
            "scan_timestamp": datetime.now().isoformat(),
            "offline_capable": True,
            "engine": "NetGuard Multi-Signal Heuristic Analyzer (Offline Capable)",
        }

    @staticmethod
    def build_attack_chain_summary(threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Group threats into the MITRE ATT&CK kill-chain progression across all 14 stages.
        """
        stages_hit: Dict[int, Dict[str, Any]] = {}
        for tactic in MITRE_TACTICS.values():
            stages_hit[tactic["stage_number"]] = {
                "stage_number": tactic["stage_number"],
                "tactic_id": tactic["id"],
                "tactic_name": tactic["name"],
                "stage_label": f"Stage {tactic['stage_number']}: {tactic['name']}",
                "description": tactic["description"],
                "color": tactic["color"],
                "count": 0,
                "threats": [],
            }

        for threat in threats:
            threat_type = threat.get("type", "")
            mapping = MitreMappingService.map_threat(threat_type, threat)
            stage_num = mapping["stage_number"]
            if stage_num in stages_hit:
                stages_hit[stage_num]["count"] += 1
                stages_hit[stage_num]["threats"].append({
                    "id": threat.get("id"),
                    "type": threat_type,
                    "technique_id": mapping["technique_id"],
                    "technique_name": mapping["technique_name"],
                    "stage_name": mapping["stage_name"],
                    "stage_number": stage_num,
                    "severity": threat.get("severity", "MEDIUM"),
                    "source_ip": threat.get("source_ip"),
                    "destination_host": threat.get("destination_host"),
                    "timestamp": threat.get("timestamp"),
                })

        active_stages = [stage for stage in stages_hit.values() if stage["count"] > 0]
        active_stages.sort(key=lambda x: x["stage_number"])

        # Calculate kill-chain progression percentage (e.g. highest stage number reached out of 14)
        highest_stage = max([s["stage_number"] for s in active_stages], default=0)
        progression_percent = round((highest_stage / 14.0) * 100, 1) if highest_stage > 0 else 0

        return {
            "total_active_stages": len(active_stages),
            "highest_stage_number": highest_stage,
            "progression_percent": progression_percent,
            "progression": active_stages,
            "all_stages": sorted(list(stages_hit.values()), key=lambda x: x["stage_number"]),
            "timestamp": datetime.now().isoformat(),
        }
