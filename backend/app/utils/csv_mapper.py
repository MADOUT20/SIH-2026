"""
Robust CSV Flow Record Normalizer & Column Mapper for NetGuard.
Maps headers from CIC-IDS2018, CTU-13 (Argus/NetFlow), CICIDS2017, CICDDoS2019,
Bot-IoT, TON-IoT, and UNSW-NB15 datasets into NetGuard's 27 canonical features.
"""

import pandas as pd
import numpy as np
from typing import List, Dict, Any

HIGH_RISK_PORTS = {21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080, 8443}

CANONICAL_27_COLUMNS = [
    'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts', 'totlen_fwd_pkts', 'totlen_bwd_pkts',
    'fwd_pkt_len_max', 'fwd_pkt_len_mean', 'bwd_pkt_len_max', 'bwd_pkt_len_mean',
    'flow_byts_s', 'flow_pkts_s', 'flow_iat_mean', 'flow_iat_std', 'fwd_iat_mean',
    'bwd_iat_mean', 'syn_flag_cnt', 'ack_flag_cnt', 'rst_flag_cnt', 'fin_flag_cnt',
    'psh_flag_cnt', 'pkt_len_mean', 'pkt_len_std', 'down_up_ratio', 'protocol_tcp',
    'protocol_udp', 'is_high_risk_port', 'fwd_bwd_bytes_ratio'
]

# Column alias dictionary mapping lowercase stripped names to canonical names
COLUMN_ALIASES = {
    # Flow duration
    "flow_duration": "flow_duration", "flow duration": "flow_duration", "duration": "flow_duration", "dur": "flow_duration",
    # Total Fwd Packets
    "tot_fwd_pkts": "tot_fwd_pkts", "total fwd packets": "tot_fwd_pkts", "total_fwd_packets": "tot_fwd_pkts", "fwd_pkts": "tot_fwd_pkts", "spkts": "tot_fwd_pkts", "srcpkts": "tot_fwd_pkts", "src_pkts": "tot_fwd_pkts",
    # Total Bwd Packets
    "tot_bwd_pkts": "tot_bwd_pkts", "total backward packets": "tot_bwd_pkts", "total_bwd_packets": "tot_bwd_pkts", "bwd_pkts": "tot_bwd_pkts", "dpkts": "tot_bwd_pkts", "dstpkts": "tot_bwd_pkts", "dst_pkts": "tot_bwd_pkts",
    # Fwd Bytes
    "totlen_fwd_pkts": "totlen_fwd_pkts", "total length of fwd packets": "totlen_fwd_pkts", "subflow_fwd_bytes": "totlen_fwd_pkts", "sbytes": "totlen_fwd_pkts", "stotbytes": "totlen_fwd_pkts", "src_bytes": "totlen_fwd_pkts",
    # Bwd Bytes
    "totlen_bwd_pkts": "totlen_bwd_pkts", "total length of bwd packets": "totlen_bwd_pkts", "subflow_bwd_bytes": "totlen_bwd_pkts", "dbytes": "totlen_bwd_pkts", "dtotbytes": "totlen_bwd_pkts", "dst_bytes": "totlen_bwd_pkts",
    # Fwd Pkt Len Max
    "fwd_pkt_len_max": "fwd_pkt_len_max", "fwd packet length max": "fwd_pkt_len_max", "fwd_packet_length_max": "fwd_pkt_len_max",
    # Fwd Pkt Len Mean
    "fwd_pkt_len_mean": "fwd_pkt_len_mean", "fwd packet length mean": "fwd_pkt_len_mean", "fwd_packet_length_mean": "fwd_pkt_len_mean", "smean": "fwd_pkt_len_mean",
    # Bwd Pkt Len Max
    "bwd_pkt_len_max": "bwd_pkt_len_max", "bwd packet length max": "bwd_pkt_len_max", "bwd_packet_length_max": "bwd_pkt_len_max",
    # Bwd Pkt Len Mean
    "bwd_pkt_len_mean": "bwd_pkt_len_mean", "bwd packet length mean": "bwd_pkt_len_mean", "bwd_packet_length_mean": "bwd_pkt_len_mean", "dmean": "bwd_pkt_len_mean",
    # Rates
    "flow_byts_s": "flow_byts_s", "flow bytes/s": "flow_byts_s", "flow_bytes_s": "flow_byts_s", "rate": "flow_byts_s", "sload": "flow_byts_s",
    "flow_pkts_s": "flow_pkts_s", "flow packets/s": "flow_pkts_s", "flow_packets_s": "flow_pkts_s", "srate": "flow_pkts_s",
    # IATs
    "flow_iat_mean": "flow_iat_mean", "flow iat mean": "flow_iat_mean", "sinpkt": "flow_iat_mean", "mean": "flow_iat_mean",
    "flow_iat_std": "flow_iat_std", "flow iat std": "flow_iat_std", "stddev": "flow_iat_std",
    "fwd_iat_mean": "fwd_iat_mean", "fwd iat mean": "fwd_iat_mean",
    "bwd_iat_mean": "bwd_iat_mean", "bwd iat mean": "bwd_iat_mean", "dinpkt": "bwd_iat_mean",
    # Flags
    "syn_flag_cnt": "syn_flag_cnt", "syn flag count": "syn_flag_cnt", "syn_flag": "syn_flag_cnt", "synack": "syn_flag_cnt",
    "ack_flag_cnt": "ack_flag_cnt", "ack flag count": "ack_flag_cnt", "ack_flag": "ack_flag_cnt", "ackdat": "ack_flag_cnt",
    "rst_flag_cnt": "rst_flag_cnt", "rst flag count": "rst_flag_cnt", "rst_flag": "rst_flag_cnt",
    "fin_flag_cnt": "fin_flag_cnt", "fin flag count": "fin_flag_cnt", "fin_flag": "fin_flag_cnt",
    "psh_flag_cnt": "psh_flag_cnt", "psh flag count": "psh_flag_cnt", "psh_flag": "psh_flag_cnt", "fwd_psh_flags": "psh_flag_cnt",
    # Packet length stats
    "pkt_len_mean": "pkt_len_mean", "packet length mean": "pkt_len_mean", "packet_length_mean": "pkt_len_mean",
    "pkt_len_std": "pkt_len_std", "packet length std": "pkt_len_std", "packet_length_std": "pkt_len_std",
    # Protocol / Port
    "protocol": "protocol", "proto": "protocol",
    "dst_port": "dst_port", "destination port": "dst_port", "destination_port": "dst_port", "dport": "dst_port", "sport": "sport"
}

def map_dataframe_to_27_canonical(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalizes any dataset CSV (CIC-IDS2018, CTU-13, CICIDS2017, CICDDoS2019, Bot-IoT, TON-IoT, UNSW-NB15)
    into NetGuard's 27 canonical flow features.
    """
    df_clean = df.copy()
    
    # Rename columns based on alias mapping
    new_cols = {}
    for col in df_clean.columns:
        col_lower = str(col).strip().lower()
        if col_lower in COLUMN_ALIASES:
            new_cols[col] = COLUMN_ALIASES[col_lower]
            
    df_clean.rename(columns=new_cols, inplace=True)
    
    # Calculate protocol_tcp and protocol_udp if 'protocol' or 'proto' exists
    if 'protocol' in df_clean.columns:
        proto_vals = df_clean['protocol'].astype(str).str.upper()
        df_clean['protocol_tcp'] = proto_vals.apply(lambda x: 1.0 if '6' in x or 'TCP' in x else 0.0)
        df_clean['protocol_udp'] = proto_vals.apply(lambda x: 1.0 if '17' in x or 'UDP' in x else 0.0)
    else:
        if 'protocol_tcp' not in df_clean.columns: df_clean['protocol_tcp'] = 1.0
        if 'protocol_udp' not in df_clean.columns: df_clean['protocol_udp'] = 0.0
        
    # Calculate is_high_risk_port
    if 'dst_port' in df_clean.columns:
        df_clean['is_high_risk_port'] = df_clean['dst_port'].apply(
            lambda p: 1.0 if pd.notnull(p) and int(float(p)) in HIGH_RISK_PORTS else 0.0
        )
    elif 'sport' in df_clean.columns:
        df_clean['is_high_risk_port'] = df_clean['sport'].apply(
            lambda p: 1.0 if pd.notnull(p) and int(float(p)) in HIGH_RISK_PORTS else 0.0
        )
    else:
        if 'is_high_risk_port' not in df_clean.columns: df_clean['is_high_risk_port'] = 0.0
        
    # Fill missing canonical columns with 0.0
    for col in CANONICAL_27_COLUMNS:
        if col not in df_clean.columns:
            if col == 'down_up_ratio':
                tot_fwd = df_clean.get('tot_fwd_pkts', pd.Series([1]*len(df_clean))).replace(0, 1)
                tot_bwd = df_clean.get('tot_bwd_pkts', pd.Series([0]*len(df_clean)))
                df_clean['down_up_ratio'] = tot_bwd / tot_fwd
            elif col == 'fwd_bwd_bytes_ratio':
                len_fwd = df_clean.get('totlen_fwd_pkts', pd.Series([1]*len(df_clean)))
                len_bwd = df_clean.get('totlen_bwd_pkts', pd.Series([1]*len(df_clean))).replace(0, 1)
                df_clean['fwd_bwd_bytes_ratio'] = len_fwd / len_bwd
            else:
                df_clean[col] = 0.0

    return df_clean[CANONICAL_27_COLUMNS].fillna(0.0).astype(float)
