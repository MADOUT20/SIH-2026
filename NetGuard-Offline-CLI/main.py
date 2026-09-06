#!/usr/bin/env python3
import argparse
import os
import sys
import numpy as np
import pandas as pd
from core.engine import ForecastEngine
from core.pcap_parser import extract_flows_from_pcap
from core.csv_parser import map_dataframe_to_27_canonical

def print_header(text):
    print("\n" + "="*60)
    print(f" {text} ")
    print("="*60)

def main():
    parser = argparse.ArgumentParser(description="NetGuard Offline AI Attack Forecaster")
    parser.add_argument("--file", type=str, required=True, help="Path to PCAP or CSV network traffic file")
    args = parser.parse_args()

    file_path = args.file
    if not os.path.exists(file_path):
        print(f"Error: File not found at {file_path}")
        sys.exit(1)

    ext = os.path.splitext(file_path)[1].lower()
    print(f"\n[*] Analyzing file: {os.path.basename(file_path)}")
    print(f"[*] Detected format: {ext[1:].upper()}")

    # 1. Feature Extraction
    try:
        if ext in {".pcap", ".pcapng"}:
            df = extract_flows_from_pcap(file_path)
            if df is None or df.empty:
                print("Error: Could not extract flows from PCAP.")
                sys.exit(1)

            # Ensure all canonical columns exist
            canonical_cols = [
                'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts', 'totlen_fwd_pkts', 'totlen_bwd_pkts',
                'fwd_pkt_len_max', 'fwd_pkt_len_mean', 'bwd_pkt_len_max', 'bwd_pkt_len_mean',
                'flow_byts_s', 'flow_pkts_s', 'flow_iat_mean', 'flow_iat_std', 'fwd_iat_mean',
                'bwd_iat_mean', 'syn_flag_cnt', 'ack_flag_cnt', 'rst_flag_cnt', 'fin_flag_cnt',
                'psh_flag_cnt', 'pkt_len_mean', 'pkt_len_std', 'down_up_ratio', 'protocol_tcp',
                'protocol_udp', 'is_high_risk_port', 'fwd_bwd_bytes_ratio'
            ]
            # PCAP parser doesn't compute everything by default, we pad here
            for col in canonical_cols:
                if col not in df.columns:
                    df[col] = 0.0
            features_list = df[canonical_cols].fillna(0.0).values.tolist()

        elif ext == ".csv" or ext == ".parquet":
            if ext == ".csv":
                df_raw = pd.read_csv(file_path)
            else:
                df_raw = pd.read_parquet(file_path)

            if df_raw.empty:
                print(f"Error: {ext[1:].upper()} file is empty.")
                sys.exit(1)
            df = map_dataframe_to_27_canonical(df_raw)
            features_list = df.values.tolist()
        else:
            print(f"Error: Unsupported file extension {ext}. Use .pcap, .csv, or .parquet")
            sys.exit(1)
    except Exception as e:
        print(f"Error during feature extraction: {e}")
        sys.exit(1)

    # 2. Window Generation (Model expects 30 states)
    arr = np.array(features_list, dtype=np.float32)
    if len(arr) < 30:
        pad = np.tile(arr[-1:], (30 - len(arr), 1)) if len(arr) > 0 else np.zeros((30, 27), dtype=np.float32)
        window = np.vstack([arr, pad])
    else:
        window = arr[-30:]

    # 3. AI Inference
    try:
        engine = ForecastEngine()
        result = engine.forecast(window)
    except Exception as e:
        print(f"Error during AI inference: {e}")
        sys.exit(1)

    # 4. Formatted Output
    print_header("NETGUARD AI ATTACK FORECAST")

    print(f"\n[+] CURRENT STATUS")
    print(f"    Attack Probability: {result['current_probability']*100:.2f}%")
    print(f"    Predicted Stage:    {result['predicted_stage']}")
    print(f"    Stage Confidence:  {result['stage_confidence']*100:.2f}%")

    print_header("PROBABILITY TIMELINE (Next 5 Steps)")
    for step in result['forecast']:
        bar = "█" * int(step['probability'] * 20)
        print(f"    Step {step['step']}: {step['probability']*100:5.2f}% | {bar}")

    print_header("TOP CONTRIBUTING FEATURES (Explainability)")
    for i, feat in enumerate(result['top_features'], 1):
        print(f"    {i}. {feat['feature']:<20} | Impact: {feat['direction']} | Importance: {feat['importance']:.4f}")
        print(f"       Description: {feat['description']}")

    print("\n" + "="*60)
    print(" Analysis Complete. System running fully offline.")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
