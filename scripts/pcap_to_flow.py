#!/usr/bin/env python3
"""
PCAP to Flow Feature Extractor
Converts raw PCAP files into flow-level features compatible with the World Model.
Implemented to satisfy SIH requirement for raw PCAP ingestion.
"""

import os
import sys
import logging
import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def extract_flows_from_pcap(pcap_path: str):
    logging.info(f"Reading PCAP file: {pcap_path}")
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        logging.error(f"Failed to read PCAP: {e}")
        return None

    # Flow key: (src_ip, dst_ip, src_port, dst_port, protocol)
    flows = defaultdict(list)

    logging.info(f"Processing {len(packets)} packets into flows...")
    for pkt in packets:
        if IP in pkt:
            ip_layer = pkt[IP]
            proto = ip_layer.proto
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            src_port = None
            dst_port = None
            flags = 0

            if TCP in pkt:
                tcp_layer = pkt[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                flags = tcp_layer.flags
            elif UDP in pkt:
                udp_layer = pkt[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport

            if src_port is not None:
                # To treat bidirectional traffic as one flow, we sort the endpoint tuples
                flow_id = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]) + [proto])
                flows[flow_id].append({
                    "ts": float(pkt.time),
                    "len": len(pkt),
                    "src": src_ip,
                    "dst": dst_ip,
                    "sport": src_port,
                    "dport": dst_port,
                    "proto": proto,
                    "flags": flags,
                    "is_fwd": (src_ip, src_port) == (src_ip, src_port) # Simplified
                })

    flow_data = []
    for flow_id, pkts in flows.items():
        pkts.sort(key=lambda x: x["ts"])

        start_ts = pkts[0]["ts"]
        end_ts = pkts[-1]["ts"]
        duration = end_ts - start_ts

        # Split into fwd and bwd (simplified: first packet direction is fwd)
        fwd_src = pkts[0]["src"]
        fwd_port = pkts[0]["sport"]

        fwd_pkts = [p for p in pkts if p["src"] == fwd_src and p["sport"] == fwd_port]
        bwd_pkts = [p for p in pkts if p["src"] != fwd_src or p["sport"] != fwd_port]

        fwd_lens = [p["len"] for p in fwd_pkts]
        bwd_lens = [p["len"] for p in bwd_pkts]

        # IATs
        fwd_iats = np.diff([p["ts"] for p in fwd_pkts]) if len(fwd_pkts) > 1 else [0]
        bwd_iats = np.diff([p["ts"] for p in bwd_pkts]) if len(bwd_pkts) > 1 else [0]
        all_iats = np.diff([p["ts"] for p in pkts]) if len(pkts) > 1 else [0]

        # Flags (TCP only)
        syn_cnt = sum(1 for p in pkts if p["flags"] & 0x02)
        ack_cnt = sum(1 for p in pkts if p["flags"] & 0x10)
        rst_cnt = sum(1 for p in pkts if p["flags"] & 0x04)
        fin_cnt = sum(1 for p in pkts if p["flags"] & 0x01)
        psh_cnt = sum(1 for p in pkts if p["flags"] & 0x08)

        flow_data.append({
            "timestamp": datetime.fromtimestamp(start_ts).isoformat(),
            "flow_duration": duration,
            "tot_fwd_pkts": len(fwd_pkts),
            "tot_bwd_pkts": len(bwd_pkts),
            "totlen_fwd_pkts": sum(fwd_lens),
            "totlen_bwd_pkts": sum(bwd_lens),
            "fwd_pkt_len_max": max(fwd_lens) if fwd_lens else 0,
            "fwd_pkt_len_mean": np.mean(fwd_lens) if fwd_lens else 0,
            "bwd_pkt_len_max": max(bwd_lens) if bwd_lens else 0,
            "bwd_pkt_len_mean": np.mean(bwd_lens) if bwd_lens else 0,
            "flow_byts_s": (sum(fwd_lens) + sum(bwd_lens)) / max(duration, 0.001),
            "flow_pkts_s": len(pkts) / max(duration, 0.001),
            "flow_iat_mean": np.mean(all_iats),
            "flow_iat_std": np.std(all_iats),
            "fwd_iat_mean": np.mean(fwd_iats),
            "bwd_iat_mean": np.mean(bwd_iats),
            "syn_flag_cnt": syn_cnt,
            "ack_flag_cnt": ack_cnt,
            "rst_flag_cnt": rst_cnt,
            "fin_flag_cnt": fin_cnt,
            "psh_flag_cnt": psh_cnt,
            "pkt_len_mean": np.mean([p["len"] for p in pkts]),
            "pkt_len_std": np.std([p["len"] for p in pkts]),
            "down_up_ratio": sum(bwd_lens) / max(sum(fwd_lens), 1),
            "protocol": pkts[0]["proto"],
            "dst_port": pkts[0]["dport"],
            "label": "UNKNOWN" # PCAPs usually don't have labels
        })

    return pd.DataFrame(flow_data)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pcap_to_flow.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    df = extract_flows_from_pcap(pcap_file)
    if df is not None:
        output_file = "pcap_extracted_flows.csv"
        df.to_csv(output_file, index=False)
        logging.info(f"Successfully extracted flows to {output_file}")
