#!/usr/bin/env python3
"""
STEP 3 — CHRONOLOGICAL NETWORK STATE WINDOW GENERATOR

Generates temporal sequences X[t-29] ... X[t] for multi-step attack forecasting.
WINDOW_SIZE = 30
PREDICTION_HORIZON = 5
STATE_INTERVAL_SECONDS = 5

Aggregates raw flow records into chronological state vectors including:
- Packet counts & rates
- Byte volume & ratios
- Flow durations
- SYN, ACK, RST, FIN, PSH flag counts
- High-risk port ratios & protocol distribution
- Packet length statistics (mean, max, std)
- Flow IAT statistics (mean, std)
- Forward / Backward traffic ratios
"""

import os
import logging
import numpy as np
import pandas as pd
from typing import Tuple, List, Dict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

WINDOW_SIZE = 30
PREDICTION_HORIZON = 5
STATE_INTERVAL_SECONDS = 5

# Canonical features selected from CIC-IDS2018 for temporal forecasting
FEATURE_COLUMNS = [
    "flow_duration",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "totlen_fwd_pkts",
    "totlen_bwd_pkts",
    "fwd_pkt_len_max",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_max",
    "bwd_pkt_len_mean",
    "flow_byts_s",
    "flow_pkts_s",
    "flow_iat_mean",
    "flow_iat_std",
    "fwd_iat_mean",
    "bwd_iat_mean",
    "syn_flag_cnt",
    "ack_flag_cnt",
    "rst_flag_cnt",
    "fin_flag_cnt",
    "psh_flag_cnt",
    "pkt_len_mean",
    "pkt_len_std",
    "down_up_ratio",
    "protocol_tcp",
    "protocol_udp",
    "is_high_risk_port",
    "fwd_bwd_bytes_ratio"
]


def extract_flow_features(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[str]]:
    """Transforms raw flow DataFrame into normalized feature matrix and target arrays (row-by-row fallback)."""
    df = df.copy()

    def get_col(candidates, default=0.0):
        for c in candidates:
            if c in df.columns:
                return pd.to_numeric(df[c], errors="coerce").fillna(default).values
        return np.full(len(df), default)

    flow_duration = get_col(["flow_duration", "duration"])
    tot_fwd_pkts = get_col(["tot_fwd_pkts", "total_fwd_packets", "fwd_pkts"])
    tot_bwd_pkts = get_col(["tot_bwd_pkts", "total_bwd_packets", "bwd_pkts"])
    totlen_fwd_pkts = get_col(["totlen_fwd_pkts", "subflow_fwd_bytes"])
    totlen_bwd_pkts = get_col(["totlen_bwd_pkts", "subflow_bwd_bytes"])

    fwd_pkt_len_max = get_col(["fwd_pkt_len_max", "fwd_packet_length_max"])
    fwd_pkt_len_mean = get_col(["fwd_pkt_len_mean", "fwd_packet_length_mean"])
    bwd_pkt_len_max = get_col(["bwd_pkt_len_max", "bwd_packet_length_max"])
    bwd_pkt_len_mean = get_col(["bwd_pkt_len_mean", "bwd_packet_length_mean"])

    flow_byts_s = get_col(["flow_byts_s", "flow_bytes_s"])
    flow_pkts_s = get_col(["flow_pkts_s", "flow_packets_s"])
    flow_iat_mean = get_col(["flow_iat_mean"])
    flow_iat_std = get_col(["flow_iat_std"])
    fwd_iat_mean = get_col(["fwd_iat_mean", "fwd_iat_tot"])
    bwd_iat_mean = get_col(["bwd_iat_mean", "bwd_iat_tot"])

    syn_flag_cnt = get_col(["syn_flag_cnt", "fwd_psh_flags"])
    ack_flag_cnt = get_col(["ack_flag_cnt"])
    rst_flag_cnt = get_col(["rst_flag_cnt"])
    fin_flag_cnt = get_col(["fin_flag_cnt"])
    psh_flag_cnt = get_col(["psh_flag_cnt"])

    pkt_len_mean = get_col(["pkt_len_mean", "packet_length_mean"])
    pkt_len_std = get_col(["pkt_len_std", "packet_length_std"])
    down_up_ratio = get_col(["down_up_ratio"])

    protocol = get_col(["protocol"])
    protocol_tcp = (protocol == 6).astype(float)
    protocol_udp = (protocol == 17).astype(float)

    dst_port = get_col(["dst_port", "destination_port"])
    high_risk_ports = {21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080, 8443}
    is_high_risk_port = np.array([1.0 if int(p) in high_risk_ports else 0.0 for p in dst_port])

    fwd_bwd_bytes_ratio = np.where(totlen_bwd_pkts > 0, totlen_fwd_pkts / np.maximum(totlen_bwd_pkts, 1.0), totlen_fwd_pkts)

    feature_matrix = np.column_stack([
        flow_duration,
        tot_fwd_pkts,
        tot_bwd_pkts,
        totlen_fwd_pkts,
        totlen_bwd_pkts,
        fwd_pkt_len_max,
        fwd_pkt_len_mean,
        bwd_pkt_len_max,
        bwd_pkt_len_mean,
        flow_byts_s,
        flow_pkts_s,
        flow_iat_mean,
        flow_iat_std,
        fwd_iat_mean,
        bwd_iat_mean,
        syn_flag_cnt,
        ack_flag_cnt,
        rst_flag_cnt,
        fin_flag_cnt,
        psh_flag_cnt,
        pkt_len_mean,
        pkt_len_std,
        down_up_ratio,
        protocol_tcp,
        protocol_udp,
        is_high_risk_port,
        fwd_bwd_bytes_ratio
    ])

    if "is_attack" in df.columns:
        is_attack = df["is_attack"].values.astype(float)
    else:
        is_attack = (df["label"].astype(str).str.upper() != "BENIGN").values.astype(float)

    if "stage_num" in df.columns:
        stage_num = df["stage_num"].values.astype(int)
    else:
        stage_num = np.zeros(len(df), dtype=int)

    return feature_matrix, is_attack, stage_num, FEATURE_COLUMNS


def aggregate_time_windows(df: pd.DataFrame, interval_seconds: int = STATE_INTERVAL_SECONDS) -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[str]]:
    """
    Aggregates flow records chronologically into time buckets (e.g. 5 seconds per bucket).
    Each time bucket becomes one 27-dimensional network state vector.
    """
    df = df.copy()
    if "timestamp" not in df.columns or len(df) == 0:
        return extract_flow_features(df)

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"]).sort_values("timestamp").reset_index(drop=True)

    if len(df) == 0:
        return extract_flow_features(df)

    freq_str = f"{interval_seconds}s"
    df["time_bucket"] = df["timestamp"].dt.floor(freq_str)

    def get_val(df_in, candidates, default=0.0):
        for c in candidates:
            if c in df_in.columns:
                return pd.to_numeric(df_in[c], errors="coerce").fillna(default)
        return pd.Series(default, index=df_in.index)

    df["_flow_dur"] = get_val(df, ["flow_duration", "duration"])
    df["_tot_fwd_pkts"] = get_val(df, ["tot_fwd_pkts", "total_fwd_packets", "fwd_pkts"])
    df["_tot_bwd_pkts"] = get_val(df, ["tot_bwd_pkts", "total_bwd_packets", "bwd_pkts"])
    df["_totlen_fwd_pkts"] = get_val(df, ["totlen_fwd_pkts", "subflow_fwd_bytes"])
    df["_totlen_bwd_pkts"] = get_val(df, ["totlen_bwd_pkts", "subflow_bwd_bytes"])
    df["_fwd_pkt_len_max"] = get_val(df, ["fwd_pkt_len_max", "fwd_packet_length_max"])
    df["_fwd_pkt_len_mean"] = get_val(df, ["fwd_pkt_len_mean", "fwd_packet_length_mean"])
    df["_bwd_pkt_len_max"] = get_val(df, ["bwd_pkt_len_max", "bwd_packet_length_max"])
    df["_bwd_pkt_len_mean"] = get_val(df, ["bwd_pkt_len_mean", "bwd_packet_length_mean"])
    df["_flow_byts_s"] = get_val(df, ["flow_byts_s", "flow_bytes_s"])
    df["_flow_pkts_s"] = get_val(df, ["flow_pkts_s", "flow_packets_s"])
    df["_flow_iat_mean"] = get_val(df, ["flow_iat_mean"])
    df["_flow_iat_std"] = get_val(df, ["flow_iat_std"])
    df["_fwd_iat_mean"] = get_val(df, ["fwd_iat_mean", "fwd_iat_tot"])
    df["_bwd_iat_mean"] = get_val(df, ["bwd_iat_mean", "bwd_iat_tot"])
    df["_syn_flag_cnt"] = get_val(df, ["syn_flag_cnt", "fwd_psh_flags"])
    df["_ack_flag_cnt"] = get_val(df, ["ack_flag_cnt"])
    df["_rst_flag_cnt"] = get_val(df, ["rst_flag_cnt"])
    df["_fin_flag_cnt"] = get_val(df, ["fin_flag_cnt"])
    df["_psh_flag_cnt"] = get_val(df, ["psh_flag_cnt"])
    df["_pkt_len_mean"] = get_val(df, ["pkt_len_mean", "packet_length_mean"])
    df["_pkt_len_std"] = get_val(df, ["pkt_len_std", "packet_length_std"])
    df["_down_up_ratio"] = get_val(df, ["down_up_ratio"])

    proto = get_val(df, ["protocol"])
    df["_protocol_tcp"] = (proto == 6).astype(float)
    df["_protocol_udp"] = (proto == 17).astype(float)

    dst_port = get_val(df, ["dst_port", "destination_port"])
    high_risk_ports = {21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080, 8443}
    df["_is_high_risk_port"] = dst_port.apply(lambda p: 1.0 if int(p) in high_risk_ports else 0.0)

    if "is_attack" in df.columns:
        df["_is_attack"] = pd.to_numeric(df["is_attack"], errors="coerce").fillna(0.0).astype(float)
    else:
        df["_is_attack"] = (df["label"].astype(str).str.upper() != "BENIGN").astype(float)

    if "stage_num" in df.columns:
        df["_stage_num"] = pd.to_numeric(df["stage_num"], errors="coerce").fillna(0).astype(int)
    else:
        df["_stage_num"] = 0

    grouped = df.groupby("time_bucket", sort=True)

    bucket_features = []
    bucket_is_attack = []
    bucket_stage_num = []

    for bucket_time, group in grouped:
        flow_dur = group["_flow_dur"].mean()
        tot_fwd_pkts = group["_tot_fwd_pkts"].sum()
        tot_bwd_pkts = group["_tot_bwd_pkts"].sum()
        totlen_fwd_pkts = group["_totlen_fwd_pkts"].sum()
        totlen_bwd_pkts = group["_totlen_bwd_pkts"].sum()
        fwd_pkt_len_max = group["_fwd_pkt_len_max"].max()
        fwd_pkt_len_mean = group["_fwd_pkt_len_mean"].mean()
        bwd_pkt_len_max = group["_bwd_pkt_len_max"].max()
        bwd_pkt_len_mean = group["_bwd_pkt_len_mean"].mean()

        flow_byts_s = group["_flow_byts_s"].sum()
        flow_pkts_s = group["_flow_pkts_s"].sum()
        flow_iat_mean = group["_flow_iat_mean"].mean()
        flow_iat_std = group["_flow_iat_std"].mean()
        fwd_iat_mean = group["_fwd_iat_mean"].mean()
        bwd_iat_mean = group["_bwd_iat_mean"].mean()

        syn_flag_cnt = group["_syn_flag_cnt"].sum()
        ack_flag_cnt = group["_ack_flag_cnt"].sum()
        rst_flag_cnt = group["_rst_flag_cnt"].sum()
        fin_flag_cnt = group["_fin_flag_cnt"].sum()
        psh_flag_cnt = group["_psh_flag_cnt"].sum()

        pkt_len_mean = group["_pkt_len_mean"].mean()
        pkt_len_std = group["_pkt_len_std"].mean()
        down_up_ratio = tot_bwd_pkts / max(tot_fwd_pkts, 1.0)

        protocol_tcp = group["_protocol_tcp"].mean()
        protocol_udp = group["_protocol_udp"].mean()
        is_high_risk_port = group["_is_high_risk_port"].mean()
        fwd_bwd_bytes_ratio = totlen_fwd_pkts / max(totlen_bwd_pkts, 1.0)

        feature_vector = [
            flow_dur, tot_fwd_pkts, tot_bwd_pkts, totlen_fwd_pkts, totlen_bwd_pkts,
            fwd_pkt_len_max, fwd_pkt_len_mean, bwd_pkt_len_max, bwd_pkt_len_mean,
            flow_byts_s, flow_pkts_s, flow_iat_mean, flow_iat_std, fwd_iat_mean, bwd_iat_mean,
            syn_flag_cnt, ack_flag_cnt, rst_flag_cnt, fin_flag_cnt, psh_flag_cnt,
            pkt_len_mean, pkt_len_std, down_up_ratio, protocol_tcp, protocol_udp,
            is_high_risk_port, fwd_bwd_bytes_ratio
        ]

        is_att = 1.0 if group["_is_attack"].max() > 0 else 0.0
        stg = int(group["_stage_num"].max())

        bucket_features.append(feature_vector)
        bucket_is_attack.append(is_att)
        bucket_stage_num.append(stg)

    feature_matrix = np.array(bucket_features, dtype=np.float32)
    is_attack_arr = np.array(bucket_is_attack, dtype=np.float32)
    stage_num_arr = np.array(bucket_stage_num, dtype=np.int64)

    logging.info(f"Aggregated {len(df)} flow rows into {len(feature_matrix)} time-buckets of interval {interval_seconds}s")

    return feature_matrix, is_attack_arr, stage_num_arr, FEATURE_COLUMNS


def build_temporal_windows(
    feature_matrix: np.ndarray,
    is_attack: np.ndarray,
    stage_num: np.ndarray,
    window_size: int = WINDOW_SIZE,
    prediction_horizon: int = PREDICTION_HORIZON,
    stride: int = 1
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """
    Constructs chronological window sequences X and multi-step forecast targets Y.

    X shape: (num_samples, window_size, num_features)
    y_current shape: (num_samples,) -> attack prob at window end (time t)
    y_future shape: (num_samples, prediction_horizon) -> attack probs for t+1 ... t+horizon
    y_stage shape: (num_samples,) -> MITRE attack stage at time t
    """
    num_rows = len(feature_matrix)
    total_len = window_size + prediction_horizon

    if num_rows < total_len:
        raise ValueError(f"Dataset has {num_rows} rows, but requires at least {total_len} rows for windowing.")

    X_list = []
    y_curr_list = []
    y_fut_list = []
    y_stage_list = []

    for i in range(0, num_rows - total_len + 1, stride):
        win_x = feature_matrix[i : i + window_size]
        t_idx = i + window_size - 1
        y_curr = is_attack[t_idx]
        y_stage = stage_num[t_idx]

        y_fut = is_attack[i + window_size : i + window_size + prediction_horizon]

        X_list.append(win_x)
        y_curr_list.append(y_curr)
        y_fut_list.append(y_fut)
        y_stage_list.append(y_stage)

    X = np.array(X_list, dtype=np.float32)
    y_curr = np.array(y_curr_list, dtype=np.float32)
    y_fut = np.array(y_fut_list, dtype=np.float32)
    y_stage = np.array(y_stage_list, dtype=np.int64)

    logging.info(f"Generated {len(X)} temporal windows of shape {X.shape}")
    return X, y_curr, y_fut, y_stage


if __name__ == "__main__":
    logging.info("Window generator module initialized.")
