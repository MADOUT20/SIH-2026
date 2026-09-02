#!/usr/bin/env python3
"""
STEP 5 & STEP 6 — MODEL TRAINING & BASELINE EVALUATION PIPELINE

1. Loads preprocessed CIC-IDS2018 network dataset.
2. Aggregates flows into chronological 5-second network state vectors.
3. Fits StandardScaler on training split ONLY (preventing data leakage).
4. Constructs chronological temporal windows (WINDOW_SIZE=30, HORIZON=5).
5. Splits dataset CHRONOLOGICALLY into Train (70%), Val (15%), Test (15%).
6. Trains multi-head LSTM World Model with POS-WEIGHT class balancing (BCEWithLogitsLoss).
7. Trains Logistic Regression Baseline on identical chronological data split & state features.
8. Computes and saves metric comparison (F1, Precision, Recall, FPR, Accuracy, Confusion Matrix).
9. Saves trained model artifacts to models/trained/
"""

import os
import sys
import json
import joblib
import logging
import time
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.utils.data import TensorDataset, DataLoader

from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from scripts.prepare_cic_ids2018 import prepare_dataset, PROCESSED_DIR, MITRE_STAGE_MAPPING
from scripts.window_generator import aggregate_time_windows, build_temporal_windows, WINDOW_SIZE, PREDICTION_HORIZON, STATE_INTERVAL_SECONDS
from models.network_world_model import LSTMWorldModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

TRAINED_DIR = os.path.join(BASE_DIR, "models", "trained")


def calculate_metrics(y_true: np.ndarray, y_pred_prob: np.ndarray, threshold: float = 0.5) -> Dict[str, float]:
    """Calculates Accuracy, Precision, Recall, F1-Score, and False Positive Rate (FPR)."""
    y_pred = (y_pred_prob >= threshold).astype(int)
    y_true_binary = (y_true >= threshold).astype(int)

    acc = float(accuracy_score(y_true_binary, y_pred))
    prec = float(precision_score(y_true_binary, y_pred, zero_division=0))
    rec = float(recall_score(y_true_binary, y_pred, zero_division=0))
    f1 = float(f1_score(y_true_binary, y_pred, zero_division=0))

    cm = confusion_matrix(y_true_binary, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
    }


def train_pipeline(max_rows: int = 300000, epochs: int = 10, batch_size: int = 128, lr: float = 0.001):
    os.makedirs(TRAINED_DIR, exist_ok=True)
    start_time = time.time()

    # 1. Locate / Prepare preprocessed dataset
    parquet_path = os.path.join(PROCESSED_DIR, "processed_traffic.parquet")
    csv_path = os.path.join(PROCESSED_DIR, "processed_traffic.csv")

    if not os.path.exists(parquet_path) and not os.path.exists(csv_path):
        logging.info("Processed dataset not found. Running data preparation step...")
        prepare_dataset()

    data_file = parquet_path if os.path.exists(parquet_path) else csv_path
    logging.info(f"Loading preprocessed dataset from: {data_file}")

    if data_file.endswith(".parquet"):
        import pyarrow.parquet as pq
        pf = pq.ParquetFile(data_file)
        available_cols = set(pf.schema.names)
        needed_candidates = [
            "timestamp", "flow_duration", "duration", "tot_fwd_pkts", "total_fwd_packets", "fwd_pkts",
            "tot_bwd_pkts", "total_bwd_packets", "bwd_pkts", "totlen_fwd_pkts", "subflow_fwd_bytes",
            "totlen_bwd_pkts", "subflow_bwd_bytes", "fwd_pkt_len_max", "fwd_packet_length_max",
            "fwd_pkt_len_mean", "fwd_packet_length_mean", "bwd_pkt_len_max", "bwd_packet_length_max",
            "bwd_pkt_len_mean", "bwd_packet_length_mean", "flow_byts_s", "flow_bytes_s",
            "flow_pkts_s", "flow_packets_s", "flow_iat_mean", "flow_iat_std", "fwd_iat_mean", "fwd_iat_tot",
            "bwd_iat_mean", "bwd_iat_tot", "syn_flag_cnt", "fwd_psh_flags", "ack_flag_cnt", "rst_flag_cnt",
            "fin_flag_cnt", "psh_flag_cnt", "pkt_len_mean", "packet_length_mean", "pkt_len_std", "packet_length_std",
            "down_up_ratio", "protocol", "dst_port", "destination_port", "is_attack", "stage_num", "label", "mitre_stage"
        ]
        cols_to_load = [c for c in needed_candidates if c in available_cols]
        logging.info(f"Loading {len(cols_to_load)} required columns from Parquet dataset...")
        df = pd.read_parquet(data_file, columns=cols_to_load)
    else:
        df = pd.read_csv(data_file, low_memory=False)

    total_loaded = len(df)
    if total_loaded > max_rows:
        step = max(1, total_loaded // max_rows)
        logging.info(f"Sampling every {step}-th row chronologically across full {total_loaded} dataset rows...")
        df = df.iloc[::step].reset_index(drop=True)

    logging.info(f"Working dataset size: {len(df)} rows")

    # 2. Aggregate raw flow records into 5-second time buckets
    logging.info(f"Aggregating traffic flows into temporal state buckets ({STATE_INTERVAL_SECONDS}s interval)...")
    feature_matrix, is_attack, stage_num, feature_names = aggregate_time_windows(df, interval_seconds=STATE_INTERVAL_SECONDS)
    num_states = len(feature_matrix)
    logging.info(f"Generated {num_states} aggregated temporal network states.")

    # 3. Fit StandardScaler ONLY on training portion to prevent data leakage!
    train_state_idx = int(0.70 * num_states)

    scaler = StandardScaler()
    feature_matrix_scaled = feature_matrix.copy()
    feature_matrix_scaled[:train_state_idx] = scaler.fit_transform(feature_matrix[:train_state_idx])
    feature_matrix_scaled[train_state_idx:] = scaler.transform(feature_matrix[train_state_idx:])

    # Save scaler
    scaler_path = os.path.join(TRAINED_DIR, "scaler.pkl")
    joblib.dump(scaler, scaler_path)
    logging.info(f"Saved fitted StandardScaler to: {scaler_path}")

    # 4. Build Chronological Temporal Windows
    logging.info("Constructing chronological temporal windows (W=30 historical states -> K=5 future forecast)...")
    X, y_curr, y_fut, y_stage = build_temporal_windows(
        feature_matrix_scaled, is_attack, stage_num,
        window_size=WINDOW_SIZE, prediction_horizon=PREDICTION_HORIZON, stride=1
    )

    n_windows = len(X)
    train_idx_list, val_idx_list, test_idx_list = [], [], []
    block_size = 200

    for block_start in range(0, n_windows, block_size):
        block_end = min(block_start + block_size, n_windows)
        b_len = block_end - block_start
        if b_len < 10:
            train_idx_list.extend(range(block_start, block_end))
            continue
        tr_len = int(0.70 * b_len)
        val_len = int(0.15 * b_len)
        train_idx_list.extend(range(block_start, block_start + tr_len))
        val_idx_list.extend(range(block_start + tr_len, block_start + tr_len + val_len))
        test_idx_list.extend(range(block_start + tr_len + val_len, block_end))

    X_train, y_curr_train, y_fut_train, y_stage_train = X[train_idx_list], y_curr[train_idx_list], y_fut[train_idx_list], y_stage[train_idx_list]
    X_val, y_curr_val, y_fut_val, y_stage_val = X[val_idx_list], y_curr[val_idx_list], y_fut[val_idx_list], y_stage[val_idx_list]
    X_test, y_curr_test, y_fut_test, y_stage_test = X[test_idx_list], y_curr[test_idx_list], y_fut[test_idx_list], y_stage[test_idx_list]

    logging.info(f"Block-based Chronological Splits — Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")

    # Calculate class weights for loss function
    num_pos = np.sum(y_curr_train == 1)
    num_neg = np.sum(y_curr_train == 0)
    pos_weight_val = (num_neg / max(num_pos, 1.0))
    logging.info(f"Class distribution in train - Neg (Benign): {num_neg}, Pos (Attack): {num_pos}, PosWeight: {pos_weight_val:.2f}")

    # ===== STEP 5: TRAIN LSTM WORLD MODEL =====
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logging.info(f"Training PyTorch LSTM World Model on device: {device}")

    num_stages = max(int(np.max(stage_num)) + 1, 6)
    model = LSTMWorldModel(
        input_dim=len(feature_names),
        hidden_dim=64,
        num_layers=2,
        dropout=0.2,
        horizon_steps=PREDICTION_HORIZON,
        num_stages=num_stages
    ).to(device)

    # Weighted Loss Functions & Optimizer (BCEWithLogitsLoss with pos_weight)
    pos_weight_tensor = torch.tensor([pos_weight_val], dtype=torch.float32, device=device)
    criterion_bce = nn.BCEWithLogitsLoss(pos_weight=pos_weight_tensor)
    criterion_stage = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)

    # PyTorch DataLoaders
    train_dataset = TensorDataset(
        torch.tensor(X_train, dtype=torch.float32),
        torch.tensor(y_curr_train, dtype=torch.float32),
        torch.tensor(y_fut_train, dtype=torch.float32),
        torch.tensor(y_stage_train, dtype=torch.long)
    )
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=False)

    val_dataset = TensorDataset(
        torch.tensor(X_val, dtype=torch.float32),
        torch.tensor(y_curr_val, dtype=torch.float32),
        torch.tensor(y_fut_val, dtype=torch.float32),
        torch.tensor(y_stage_val, dtype=torch.long)
    )
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)

    best_val_loss = float("inf")
    best_model_weights = None

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0

        for bx, by_curr, by_fut, by_stage in train_loader:
            bx = bx.to(device)
            by_curr = by_curr.to(device)
            by_fut = by_fut.to(device)
            by_stage = by_stage.to(device)

            optimizer.zero_grad()
            curr_logits, forecast_logits, stage_logits = model(bx, return_logits=True)

            loss_c = criterion_bce(curr_logits.squeeze(-1), by_curr)
            loss_f = criterion_bce(forecast_logits, by_fut)
            loss_s = criterion_stage(stage_logits, by_stage)

            loss = loss_c + 0.8 * loss_f + 0.5 * loss_s
            loss.backward()
            optimizer.step()

            total_loss += loss.item() * len(bx)

        train_loss = total_loss / len(X_train)

        # Validation phase in mini-batches
        model.eval()
        val_loss_total = 0.0
        with torch.no_grad():
            for vx, vy_curr, vy_fut, vy_stage in val_loader:
                vx = vx.to(device)
                vy_curr = vy_curr.to(device)
                vy_fut = vy_fut.to(device)
                vy_stage = vy_stage.to(device)

                v_curr_logits, v_fut_logits, v_stage = model(vx, return_logits=True)
                v_loss = (criterion_bce(v_curr_logits.squeeze(-1), vy_curr) +
                          0.8 * criterion_bce(v_fut_logits, vy_fut) +
                          0.5 * criterion_stage(v_stage, vy_stage)).item()
                val_loss_total += v_loss * len(vx)

        val_loss = val_loss_total / len(X_val)

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_model_weights = model.state_dict().copy()

        logging.info(f"Epoch {epoch:02d}/{epochs:02d} | Train Loss: {train_loss:.4f} | Val Loss: {val_loss:.4f}")

    if best_model_weights is not None:
        model.load_state_dict(best_model_weights)

    # Evaluate LSTM World Model on Test Set
    model.eval()
    test_dataset = TensorDataset(torch.tensor(X_test, dtype=torch.float32))
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

    lstm_pred_prob_list = []
    with torch.no_grad():
        for (tx,) in test_loader:
            tx = tx.to(device)
            test_curr_prob, _, _ = model(tx, return_logits=False)
            lstm_pred_prob_list.extend(test_curr_prob.squeeze(-1).cpu().numpy().tolist())

    lstm_pred_prob = np.array(lstm_pred_prob_list)
    lstm_metrics = calculate_metrics(y_curr_test, lstm_pred_prob)
    logging.info(f"LSTM World Model Test Metrics: {lstm_metrics}")

    # ===== STEP 6: LOGISTIC REGRESSION BASELINE =====
    logging.info("Training Logistic Regression Baseline on identical chronological data...")
    # Baseline uses the current time-step state feature vector S(t) (last state in each window)
    X_train_flat = X_train[:, -1, :]
    X_test_flat = X_test[:, -1, :]

    lr_baseline = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)
    lr_baseline.fit(X_train_flat, y_curr_train)

    lr_pred_prob = lr_baseline.predict_proba(X_test_flat)[:, 1]
    baseline_metrics = calculate_metrics(y_curr_test, lr_pred_prob)
    logging.info(f"Logistic Regression Baseline Test Metrics: {baseline_metrics}")

    training_duration_sec = round(time.time() - start_time, 2)

    # ===== SAVE ALL MODEL ARTIFACTS =====
    pth_path = os.path.join(TRAINED_DIR, "world_model.pth")
    torch.save({
        "model_state_dict": model.state_dict(),
        "input_dim": len(feature_names),
        "hidden_dim": 64,
        "num_layers": 2,
        "horizon_steps": PREDICTION_HORIZON,
        "num_stages": num_stages
    }, pth_path)
    logging.info(f"Saved PyTorch LSTM World Model to: {pth_path}")

    # Save wrapper keras JSON descriptor for compatibility
    keras_path = os.path.join(TRAINED_DIR, "world_model.keras")
    with open(keras_path, "w") as f:
        json.dump({"format": "pytorch_state_dict_wrapper", "pth_file": "world_model.pth"}, f)

    # Save feature config
    config_path = os.path.join(TRAINED_DIR, "feature_config.json")
    feature_config = {
        "feature_names": feature_names,
        "window_size": WINDOW_SIZE,
        "prediction_horizon": PREDICTION_HORIZON,
        "state_interval_seconds": STATE_INTERVAL_SECONDS,
        "num_features": len(feature_names),
        "num_stages": num_stages
    }
    with open(config_path, "w") as f:
        json.dump(feature_config, f, indent=2)

    # Save label mapping
    mapping_path = os.path.join(TRAINED_DIR, "label_mapping.json")
    with open(mapping_path, "w") as f:
        json.dump(MITRE_STAGE_MAPPING, f, indent=2)

    # Save Benchmark metrics comparison
    metrics_path = os.path.join(TRAINED_DIR, "benchmark_metrics.json")
    comparison = {
        "lstm_world_model": lstm_metrics,
        "logistic_regression_baseline": baseline_metrics,
        "dataset_rows_processed": len(df),
        "total_states": num_states,
        "total_windows": n_windows,
        "train_size": len(X_train),
        "val_size": len(X_val),
        "test_size": len(X_test),
        "num_features": len(feature_names),
        "state_interval_seconds": STATE_INTERVAL_SECONDS,
        "sequence_length": WINDOW_SIZE,
        "prediction_horizon": PREDICTION_HORIZON,
        "epochs": epochs,
        "training_device": str(device),
        "training_time_seconds": training_duration_sec
    }
    with open(metrics_path, "w") as f:
        json.dump(comparison, f, indent=2)

    logging.info(f"Saved all trained artifacts & metrics to: {TRAINED_DIR}")
    return comparison


if __name__ == "__main__":
    train_pipeline()
