import unittest
import asyncio
from app.services.mitre_mapping import MitreMappingService, MITRE_TACTICS, THREAT_TYPE_MITRE_MAP
from app.services.threat_detection import ThreatDetectionService
from app.services.ml_benchmark import MLBenchmarkService


class TestMitreAndScanner(unittest.TestCase):
    def setUp(self):
        self.mitre = MitreMappingService()
        self.threat_service = ThreatDetectionService()
        self.ml_service = MLBenchmarkService()

    def test_mitre_taxonomy_has_14_stages(self):
        taxonomy = self.mitre.get_taxonomy()
        tactics = taxonomy.get("tactics", {})
        self.assertEqual(len(tactics), 14)
        self.assertIn("TA0043", tactics)  # Stage 1: Reconnaissance
        self.assertIn("TA0001", tactics)  # Stage 3: Initial Access
        self.assertIn("TA0002", tactics)  # Stage 4: Execution
        self.assertIn("TA0011", tactics)  # Stage 12: Command and Control
        self.assertIn("TA0040", tactics)  # Stage 14: Impact

    def test_trojan_threat_mapping(self):
        mapping = self.mitre.map_threat("TROJAN")
        self.assertEqual(mapping["stage_number"], 4)
        self.assertEqual(mapping["tactic_name"], "Execution")
        self.assertEqual(mapping["technique_id"], "T1204.002")
        self.assertIn("Stage 4: Execution", mapping["stage_label"])

    def test_malware_threat_mapping(self):
        mapping = self.mitre.map_threat("MALWARE")
        self.assertEqual(mapping["stage_number"], 3)
        self.assertEqual(mapping["tactic_name"], "Initial Access")
        self.assertEqual(mapping["technique_id"], "T1189")

    def test_phishing_threat_mapping(self):
        mapping = self.mitre.map_threat("PHISHING")
        self.assertEqual(mapping["stage_number"], 3)
        self.assertEqual(mapping["tactic_name"], "Initial Access")
        self.assertEqual(mapping["technique_id"], "T1566.002")

    def test_ransomware_threat_mapping(self):
        mapping = self.mitre.map_threat("RANSOMWARE")
        self.assertEqual(mapping["stage_number"], 14)
        self.assertEqual(mapping["tactic_name"], "Impact")
        self.assertEqual(mapping["technique_id"], "T1486")

    def test_c2_threat_mapping(self):
        mapping = self.mitre.map_threat("C2_COMMUNICATION")
        self.assertEqual(mapping["stage_number"], 12)
        self.assertEqual(mapping["tactic_name"], "Command and Control")
        self.assertEqual(mapping["technique_id"], "T1071.001")

    def test_website_threat_scanner_trojan_detection(self):
        result = self.mitre.scan_website_threat("http://malware-download-trojan.com/trojan.exe")
        self.assertTrue(result["is_malicious"])
        self.assertIn("TROJAN", result["threat_type"])
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertEqual(result["mitre_mapping"]["stage_number"], 4)
        self.assertEqual(result["mitre_mapping"]["stage_name"], "Execution")
        self.assertIn("CRITICAL WARNING", result["warning"]["headline"])

    def test_website_threat_scanner_phishing_detection(self):
        result = self.mitre.scan_website_threat("https://secure-login-bank-verify.xyz/account")
        self.assertTrue(result["is_malicious"])
        self.assertEqual(result["threat_type"], "PHISHING")
        self.assertEqual(result["mitre_mapping"]["stage_number"], 3)
        self.assertEqual(result["mitre_mapping"]["stage_name"], "Initial Access")

    def test_website_threat_scanner_safe_detection(self):
        result = self.mitre.scan_website_threat("https://github.com")
        self.assertFalse(result["is_malicious"])
        self.assertEqual(result["severity"], "SAFE")
        self.assertEqual(result["threat_type"], "BENIGN_SAFE")

    def test_ml_prediction_contains_real_attack_stage(self):
        packet = {
            "size_bytes": 22000,
            "dest_port": 4444,
            "protocol": "TCP",
            "flags": ["PSH", "ACK"],
            "security_alerts": ["TROJAN"],
        }
        pred = self.ml_service.predict_packet(packet)
        self.assertIn("mitre_attack_stage", pred)
        self.assertIn("Stage 4: Execution", pred["mitre_attack_stage"])
        self.assertEqual(pred["mitre_stage_name"], "Execution")
        self.assertEqual(pred["mitre_stage_number"], 4)
        self.assertIn("logistic_regression", pred)
        self.assertIn("ai_ensemble", pred)
        self.assertEqual(pred["logistic_regression"]["prediction"], "MALICIOUS")
        self.assertEqual(pred["ai_ensemble"]["prediction"], "MALICIOUS")

    def test_attack_chain_summary_progression(self):
        threats = [
            {"id": "t1", "type": "SEQUENTIAL_PORT_PROBE", "severity": "MEDIUM", "source_ip": "192.168.1.5"},
            {"id": "t2", "type": "TROJAN", "severity": "CRITICAL", "source_ip": "192.168.1.10", "destination_host": "trojan.cc"},
            {"id": "t3", "type": "DATA_EXFILTRATION", "severity": "HIGH", "source_ip": "192.168.1.15"},
        ]
        chain = self.mitre.build_attack_chain_summary(threats)
        self.assertEqual(chain["total_active_stages"], 3)
        self.assertEqual(chain["highest_stage_number"], 13)
        self.assertGreater(chain["progression_percent"], 0)
        self.assertEqual(len(chain["all_stages"]), 14)


if __name__ == "__main__":
    unittest.main()
