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
        Evaluate any website or URL for Malware, Trojan, Phishing, Ransomware, or C2 threats.
        Returns complete MITRE ATT&CK stage mapping, safety warning, and response recommendation.
        """
        raw_input = (url_or_domain or "").strip()
        if not raw_input:
            return {
                "url": "",
                "domain": "",
                "is_malicious": False,
                "threat_type": "BENIGN_SAFE",
                "severity": "SAFE",
                "threat_score": 0.0,
                "confidence_percent": 100,
                "mitre_mapping": MitreMappingService.map_threat("BENIGN"),
                "warning": {"title": "No URL Provided", "headline": "Enter a valid URL to scan."},
            }

        # Normalize URL / Domain
        target = raw_input
        if not target.startswith("http://") and not target.startswith("https://"):
            target = f"https://{target}"

        try:
            parsed = urlsplit(target)
            domain = (parsed.hostname or raw_input).lower().rstrip(".")
            path = parsed.path.lower()
            full_target = f"{domain}{path}"
        except Exception:
            domain = raw_input.lower()
            path = ""
            full_target = domain

        evidence = []
        is_malicious = False
        threat_type = "BENIGN_SAFE"
        threat_category = "Normal / Safe Website"
        severity = "SAFE"
        threat_score = 0.05
        confidence = 94

        # 1. Check known keyword signatures
        matched_keyword = None
        for kw, (mapped_type, assigned_sev, cat_label) in SUSPICIOUS_DOMAIN_KEYWORDS.items():
            if kw in full_target:
                matched_keyword = kw
                threat_type = mapped_type
                severity = assigned_sev
                threat_category = cat_label
                is_malicious = True
                threat_score = 0.96 if severity == "CRITICAL" else (0.88 if severity == "HIGH" else 0.72)
                confidence = int(threat_score * 100)
                evidence.append(f"Contains high-confidence malicious signature pattern: '{kw}' in hostname or path")
                break

        # 2. Check high-risk TLDs
        for tld in HIGH_RISK_TLDS:
            if domain.endswith(tld):
                evidence.append(f"Domain registered under high-risk TLD extension: '{tld}'")
                if not is_malicious:
                    threat_type = "MALWARE_SITE_VISIT"
                    severity = "MEDIUM"
                    threat_category = "Suspicious Unverified TLD Host"
                    is_malicious = True
                    threat_score = 0.65
                    confidence = 78
                else:
                    threat_score = min(0.99, threat_score + 0.05)
                break

        # 3. Calculate Shannon entropy for domain name (DGA / Obfuscated Detection)
        domain_name_part = domain.split(".")[0] if "." in domain else domain
        if len(domain_name_part) > 10:
            prob = [float(domain_name_part.count(c)) / len(domain_name_part) for c in dict.fromkeys(list(domain_name_part))]
            entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
            if entropy > 3.6:
                evidence.append(f"High domain entropy detected ({entropy:.2f} bits) indicating algorithmic generation (DGA)")
                if not is_malicious:
                    threat_type = "C2_COMMUNICATION"
                    severity = "HIGH"
                    threat_category = "Algorithmically Generated C2 Domain (DGA)"
                    is_malicious = True
                    threat_score = 0.84
                    confidence = 88
                else:
                    threat_score = min(0.99, threat_score + 0.04)

        # 4. Check for IP-literal address visits (uncommon for legitimate consumer sites)
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            evidence.append(f"Direct raw IP-literal address accessed ({domain}) bypassing standard DNS trust validation")
            if not is_malicious:
                threat_type = "MALWARE_SITE_VISIT"
                severity = "MEDIUM"
                threat_category = "Direct IP Connection / Unresolved Host"
                is_malicious = True
                threat_score = 0.60
                confidence = 75

        # 5. Check for dangerous file extensions in path (.exe, .scr, .vbs, .bat, .apk, .dll)
        dangerous_exts = [".exe", ".scr", ".vbs", ".bat", ".apk", ".dll", ".ps1", ".hta", ".iso"]
        for ext in dangerous_exts:
            if path.endswith(ext):
                evidence.append(f"Direct executable file download link detected with dangerous extension: '{ext}'")
                threat_type = "TROJAN_DOWNLOAD"
                severity = "CRITICAL"
                threat_category = "Direct Trojan Executable Dropper"
                is_malicious = True
                threat_score = 0.98
                confidence = 98
                break

        # Map to MITRE ATT&CK Taxonomy
        mitre_info = MitreMappingService.map_threat(threat_type if is_malicious else "MALICIOUS_SITE_VISIT")

        # Build Safety Warning Payload
        if is_malicious:
            warning_title = f"⚠️ MALWARE / {threat_category.upper()} WARNING"
            if "TROJAN" in threat_type:
                headline = f"CRITICAL WARNING: Trojan Payload Vector Detected on '{domain}'!"
                recommendation = "Do not visit or download files from this website. NetGuard has automatically engaged browser shield isolation."
            elif "PHISHING" in threat_type:
                headline = f"PHISHING WARNING: Deceptive Credential Stealer Target '{domain}'!"
                recommendation = "Never enter personal credentials, passwords, or card numbers on this website."
            elif "RANSOMWARE" in threat_type:
                headline = f"CRITICAL THREAT: Ransomware Infrastructure Endpoint '{domain}'!"
                recommendation = "Immediate network block enforced to prevent file encryption payloads."
            else:
                headline = f"SECURITY ALERT: Malicious Website Threat Identified on '{domain}'!"
                recommendation = "NetGuard recommended action: enforce instant domain block."

            prevention_steps = [
                f"Block domain '{domain}' across all local network connections and proxy routes.",
                f"Inspect active browser tabs and terminate ongoing socket streams.",
                f"Review MITRE technique {mitre_info['technique_id']} ({mitre_info['technique_name']}) mitigations.",
            ]
        else:
            warning_title = "✅ SAFE / VERIFIED DESTINATION"
            headline = f"Website '{domain}' exhibits standard benign network characteristics."
            recommendation = "No known malware, trojan, or phishing indicators were found."
            prevention_steps = ["Standard NetGuard packet inspection remains active in the background."]
            evidence.append("Host matches standard legitimate domain structure with low entropy and valid scheme")

        return {
            "url": target,
            "domain": domain,
            "path": path,
            "is_malicious": is_malicious,
            "threat_type": threat_type,
            "threat_category": threat_category,
            "severity": severity,
            "threat_score": round(threat_score, 2),
            "confidence_percent": confidence,
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
