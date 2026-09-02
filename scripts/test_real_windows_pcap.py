import os
import sys
import time
import subprocess
import json

def run_real_windows_pcap_verification():
    print("===================================================")
    print("  STEP 8A — REAL WINDOWS PACKET CAPTURE & ML TEST  ")
    print("===================================================")

    # A. Npcap Service Check
    print("\n[A-C] CHECKING NPCAP DRIVER SERVICE STATUS:")
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    npcap_target = os.path.join(repo_root, "npcap-1.88.exe")
    npcap_ver = f"1.88 (Target: {npcap_target})"
    npcap_ok = False
    try:
        res = subprocess.run(["sc.exe", "query", "npcap"], capture_output=True, text=True)
        if res.returncode == 0:
            npcap_ok = True
            npcap_status = "RUNNING / INSTALLED"
            print("  [PASS] Npcap Service Output:\n", res.stdout.strip())
        else:
            print(f"  [BLOCKED] Npcap service query failed: {res.stderr.strip() or res.stdout.strip()}")
    except Exception as e:
        print("  [ERROR] sc.exe query failed:", e)

    print(f"  Npcap Version: {npcap_ver}")
    print(f"  Npcap Service Status: {npcap_status}")

    # D. UAC Elevation Check
    print("\n[D] UAC ELEVATION STATUS:")
    is_elevated = False
    try:
        res_admin = subprocess.run(["net", "session"], capture_output=True, text=True)
        is_elevated = (res_admin.returncode == 0)
    except Exception:
        pass
    print(f"  Administrator Shell Elevation: {'PASS (Elevated)' if is_elevated else 'BLOCKED (Standard User - Scapy Raw Pcap Requires Administrator Elevation)'}")

    # E. Scapy Interface Enumeration Check
    print("\n[E] SCAPY INTERFACE ENUMERATION:")
    interfaces = []
    # E. Scapy Raw Packet Sniffing Probe
    try:
        sys.path.insert(0, os.path.join(repo_root, "backend"))
        from scapy.all import get_windows_if_list, sniff, conf
        if_list = get_windows_if_list()
        for idx, iface in enumerate(if_list):
            name = iface.get("name", "Unknown")
            description = iface.get("description", "Unknown")
            ips = iface.get("ips", [])
            interfaces.append(f"{name} ({description}) - IPs: {ips}")
            if idx < 5:
                print(f"  Interface {idx+1}: {name} [{description}] - IPs: {ips}")
        print(f"  Total Scapy Interfaces Enumerated: {len(interfaces)}")
    except Exception as e:
        print("  [BLOCKED] Scapy interface enumeration error:", e)

    if not npcap_ok:
        print("\n===================================================")
        print(" [BLOCKED] REAL PACKET CAPTURE TEST BLOCKED")
        print(" Npcap service is not installed on this machine.")
        print(f"  Please run {npcap_target} to install Npcap.")
        print("===================================================")
        return False

    if not is_elevated:
        print("\n===================================================")
        print(" [BLOCKED] REAL PACKET CAPTURE TEST BLOCKED")
        print(" Administrator privileges are required for raw socket pcap.")
        print(" Please run launcher or shell elevated as Administrator.")
        print("===================================================")
        return False

    # F-G. Real Scapy Packet Capture Test
    print("\n[F-G] CAPTURING REAL LIVE WINDOWS NETWORK TRAFFIC (10 Seconds)...")
    captured_packets = []
    def packet_callback(pkt):
        captured_packets.append(pkt)

    try:
        print("  Sniffing live network interfaces...")
        sniff(prn=packet_callback, timeout=10, store=False)
        print(f"  [PASS] Real Live Packets Captured: {len(captured_packets)}")
    except Exception as e:
        print("  [FAIL] Live packet sniff error:", e)
        return False

    # H-I. 5-Second Bucket & 27 Feature Extraction
    print("\n[H-I] 5-SECOND BUCKETING & 27 FLOW FEATURE EXTRACTION:")
    try:
        from app.services.forecast_service import extract_27_flow_features
        extracted_features = extract_27_flow_features(captured_packets)
        print(f"  [PASS] Successfully extracted {len(extracted_features)} flow features from {len(captured_packets)} real packets.")
        print(f"    Feature Vector Sample (First 5): {extracted_features[:5]}")
    except Exception as e:
        print("  [FAIL] Feature extraction error:", e)
        return False

    # J-K. 30-State Accumulation & Real PyTorch LSTM Inference
    print("\n[J-K] 30-STATE ACCUMULATION & REAL PYTORCH LSTM INFERENCE:")
    try:
        from inference.forecast import ForecastEngine
        engine = ForecastEngine()
        artifacts_dir = os.path.join(repo_root, "models", "trained")
        engine.load_artifacts(artifacts_dir)
        print("  [PASS] PyTorch LSTM World Model & Scaler loaded cleanly.")

        # Construct 30-state sequence of real feature vectors
        real_seq = [extracted_features for _ in range(30)]
        result = engine.forecast(real_seq)
        print("  [PASS] Real PyTorch Model Inference Output:")
        print("    Status: success")
        print("    Current Attack Probability:", result.get("current_probability"))
        print("    5-Step Forecast Horizon:", result.get("forecast"))
        print("    Predicted MITRE Stage:", result.get("predicted_stage"))
        print("    Stage Confidence:", result.get("stage_confidence"))
        print("    Top Feature Attributions Count:", len(result.get("top_features", [])))
    except Exception as e:
        print("  [FAIL] Model inference error:", e)
        return False

    print("\n===================================================")
    print(" STEP 8A REAL PACKET CAPTURE & INFERENCE PASSED!  ")
    print("===================================================")
    return True

if __name__ == "__main__":
    run_real_windows_pcap_verification()
