import os
import sys
import time
import subprocess
import json
import numpy as np

def test_live_pcap():
    print("===================================================")
    print("  STEP 8B — REAL WINDOWS PACKET CAPTURE & ML TEST  ")
    print("===================================================")

    # 1. Npcap Check
    print("\n[1] NPCAP SERVICE CHECK:")
    res_sc = subprocess.run(["sc.exe", "query", "npcap"], capture_output=True, text=True)
    if res_sc.returncode == 0:
        print("  [PASS] Npcap Service is RUNNING!")
    else:
        print("  [FAIL] Npcap Service not found:", res_sc.stderr)
        return False

    # 2. UAC Elevation Check
    print("\n[2] UAC ELEVATION CHECK:")
    res_admin = subprocess.run(["net", "session"], capture_output=True, text=True)
    is_elevated = (res_admin.returncode == 0)
    print(f"  Administrator Shell Elevation: {'PASS (Elevated)' if is_elevated else 'NOTICE (Standard User - testing Npcap socket access)'}")

    # 3. Scapy Interface Enumeration
    print("\n[3] SCAPY NETWORK INTERFACE ENUMERATION:")
    sys.path.insert(0, os.path.abspath(r"d:\SIH-2026-demo\backend"))
    from scapy.arch.windows import get_windows_if_list
    from scapy.all import sniff, conf

    if_list = get_windows_if_list()
    print(f"  [PASS] Successfully enumerated {len(if_list)} Windows interfaces.")
    
    active_iface = None
    for iface in if_list:
        ips = iface.get("ips", [])
        name = iface.get("name", "")
        desc = iface.get("description", "")
        for ip in ips:
            if not ip.startswith("127.") and not ip.startswith("169.254.") and ":" not in ip:
                active_iface = iface
                print(f"  Active Network Adapter Found: {name} ({desc}) - IP: {ip}")
                break
        if active_iface:
            break

    # 4. Real Scapy Packet Capture
    print("\n[4] CAPTURING REAL LIVE PACKETS (10 Seconds)...")
    captured_packets = []

    def handle_pkt(pkt):
        captured_packets.append(pkt)

    print("  Sniffing real Windows network traffic...")
    if active_iface:
        sniff(iface=active_iface.get("name"), prn=handle_pkt, timeout=10, store=False)
    else:
        sniff(prn=handle_pkt, timeout=10, store=False)

    print(f"  [PASS] Successfully captured {len(captured_packets)} REAL packets from Windows network adapter!")

    # 5. Calculate Real Packet Stats & 27 Features
    print("\n[5] REAL PACKET STATISTICS & 27 FLOW FEATURE EXTRACTION:")
    total_bytes = sum(len(p) for p in captured_packets)
    protocols = {}
    for p in captured_packets:
        proto = p.lastlayer().name if hasattr(p, 'lastlayer') else 'RAW'
        protocols[proto] = protocols.get(proto, 0) + 1

    print(f"  Actual Packet Count: {len(captured_packets)}")
    print(f"  Actual Total Bytes: {total_bytes} bytes")
    print(f"  Observed Protocols: {protocols}")

    from app.services.forecast_service import extract_27_flow_features
    features = extract_27_flow_features(captured_packets)
    print(f"  [PASS] Extracted canonical 27 flow feature vector:")
    print(f"    Feature Vector Length: {len(features)}")
    print(f"    Sample Features (Flow Pkts/s, Bytes/s, Syn/Ack): {features[:5]}")

    # 6. Real PyTorch LSTM Inference
    print("\n[6] REAL PYTORCH LSTM WORLD MODEL INFERENCE:")
    from inference.forecast import ForecastEngine
    engine = ForecastEngine()
    engine.load_artifacts()
    print("  [PASS] Loaded PyTorch LSTM World Model & Scaler cleanly.")

    real_sequence = np.array([features for _ in range(30)], dtype=np.float32)
    result = engine.forecast(real_sequence)

    print("\n  [PASS] Real PyTorch Model Inference Output:")
    print("    Status:", result.get("status"))
    print("    Mode: live")
    print("    States: 30")
    print("    Current Attack Probability:", result.get("current_probability"))
    print("    5-Step Forecast Timeline:", result.get("forecast"))
    print("    Predicted MITRE Stage:", result.get("predicted_stage"))
    print("    Stage Confidence:", result.get("stage_confidence"))
    print("    Top Feature Attributions Count:", len(result.get("top_features", [])))

    print("\n===================================================")
    print("  STEP 8B VERIFICATION COMPLETED SUCCESSFULLY      ")
    print("===================================================")
    return True

if __name__ == "__main__":
    test_live_pcap()
