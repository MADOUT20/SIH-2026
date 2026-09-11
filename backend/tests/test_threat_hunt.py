import unittest
from datetime import datetime, timedelta
from app.services.threat_detection import ThreatDetectionService


class TestThreatHunt(unittest.IsolatedAsyncioTestCase):
    async def test_hunt_live_threats_prefers_confirmed_detection(self):
        service = ThreatDetectionService()
        start = datetime(2026, 3, 26, 12, 0, 0)

        packets = [
            {
                "timestamp": (start + timedelta(seconds=index)).isoformat(),
                "source_ip": "192.168.1.10",
                "dest_ip": "8.8.8.8",
                "protocol": "TCP",
                "dest_port": 8443,
                "size_bytes": 15_000,
            }
            for index in range(12)
        ]

        result = await service.hunt_live_threats(packets, {})

        self.assertGreaterEqual(result["confirmed_findings"], 1)
        self.assertIsNotNone(result["best_finding"])
        self.assertEqual(result["best_finding"]["classification"], "confirmed")
        self.assertEqual(result["best_finding"]["type"], "DATA_EXFILTRATION")

    async def test_hunt_live_threats_returns_dns_lead_when_alert_threshold_not_met(self):
        service = ThreatDetectionService()
        start = datetime(2026, 3, 26, 12, 5, 0)

        packets = [
            {
                "timestamp": (start + timedelta(seconds=index)).isoformat(),
                "source_ip": "192.168.1.15",
                "dest_ip": "192.168.1.1",
                "protocol": "UDP",
                "dest_port": 53,
                "size_bytes": 120,
                "dns_query": query,
            }
            for index, query in enumerate(
                [
                    "abcdefghijklmnopqrstuvwx123456.example.com",
                    "mnopqrstuvwxabcdefghijkl123456.example.com",
                ]
            )
        ]

        result = await service.hunt_live_threats(packets, {})

        self.assertEqual(result["confirmed_findings"], 0)
        self.assertGreaterEqual(result["suspicious_leads"], 1)
        self.assertIsNotNone(result["best_finding"])
        self.assertEqual(result["best_finding"]["classification"], "lead")
        self.assertEqual(result["best_finding"]["type"], "SUSPICIOUS_DNS_LEAD")


if __name__ == "__main__":
    unittest.main()
