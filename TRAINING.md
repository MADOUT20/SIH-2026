# CSE-CIC-IDS2018 Real Temporal Attack Forecasting Pipeline

This repository implements a **Real CSE-CIC-IDS2018 Temporal Network Attack Forecasting Pipeline** for the SIH Problem Statement (**AI based Network Attack Forecasting from Network Traffic Data - ID 26153**).

Rather than performing static per-packet classification or using synthetic data, this pipeline aggregates chronological network-state sequences into 5-second time buckets from real CSE-CIC-IDS2018 traffic and trains a multi-head **PyTorch LSTM Neural Network World Model**.

---

## 1. Dataset Source & Statistics

The dataset used is the official **CSE-CIC-IDS2018 Processed Traffic Data for ML Algorithms** hosted on AWS S3:
```
s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/
```

Downloaded and processed files include real attack vectors:
- `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` (FTP-BruteForce, SSH-Bruteforce)
- `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` (DoS-GoldenEye, DoS-Slowloris)
- `Friday-16-02-2018_TrafficForML_CICFlowMeter.csv` (DoS-SlowHTTPTest, DoS-Hulk)
- `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` (DDoS-HOIC, DDoS-LOIC-UDP)
- `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` (Brute Force -Web, Brute Force -XSS, SQL Injection)
- `Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv` (Infiltration)
- `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` (Infiltration)
- `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` (Bot)

### Empirical Dataset Breakdown
- **Files Processed**: 8 CSV files
- **Total Flow Records**: 7,235,620 rows
- **Timestamp Range**: Jan 03, 2018 to Mar 02, 2018
- **Attack Proportion**: 27.78% (2,009,748 attack flows)
- **Label Breakdown**:
  - Benign: 5,063,938
  - DDoS attack-HOIC: 686,012
  - DoS attacks-Hulk: 461,912
  - Bot: 286,191
  - FTP-BruteForce: 193,360
  - SSH-Bruteforce: 187,589
  - Infiltration: 161,934
  - DoS attacks-SlowHTTPTest: 139,890
  - DoS attacks-GoldenEye: 41,508
  - DoS attacks-Slowloris: 10,990
  - DDoS attack-LOIC-UDP: 1,730
  - Brute Force (Web/XSS/SQLi): 566

---

## 2. Temporal State Aggregation Pipeline

Rather than treating raw flow rows as independent temporal steps, traffic flows are aggregated into **5-second time buckets** (`STATE_INTERVAL_SECONDS = 5`).
Each 5-second time bucket forms one **27-dimensional Network State Vector** containing:
1. `flow_duration`: mean flow duration in bucket
2. `tot_fwd_pkts`, `tot_bwd_pkts`: sum of forward/backward packets
3. `totlen_fwd_pkts`, `totlen_bwd_pkts`: sum of forward/backward bytes
4. `fwd_pkt_len_max`, `fwd_pkt_len_mean`, `bwd_pkt_len_max`, `bwd_pkt_len_mean`: packet length statistics
5. `flow_byts_s`, `flow_pkts_s`: aggregate byte and packet flow rates
6. `flow_iat_mean`, `flow_iat_std`, `fwd_iat_mean`, `bwd_iat_mean`: inter-arrival time statistics
7. `syn_flag_cnt`, `ack_flag_cnt`, `rst_flag_cnt`, `fin_flag_cnt`, `psh_flag_cnt`: TCP flag volumes
8. `pkt_len_mean`, `pkt_len_std`: overall packet size distribution
9. `down_up_ratio`: backward/forward packet volume ratio
10. `protocol_tcp`, `protocol_udp`: protocol mixture ratios
11. `is_high_risk_port`: proportion of traffic on known vulnerable ports
12. `fwd_bwd_bytes_ratio`: forward to backward byte volume ratio

---

## 3. Sequence Window & Target Construction

Chronological time-bucket state vectors ($S(0), S(1), \dots, S(N-1)$) are converted into sliding sequence windows:
- **Window Size ($W$)**: 30 historical time states ($S(t-29), \dots, S(t)$ = 150 seconds of traffic history).
- **Target Construction**:
  - `y_current`: Attack indicator for current state $S(t)$
  - `y_future`: Multi-horizon attack probability target for next 5 future states ($S(t+1), S(t+2), S(t+3), S(t+4), S(t+5)$ = 25 seconds into the future)
  - `y_stage`: MITRE ATT&CK stage number at time $t$

---

## 4. PyTorch LSTM World Model Architecture

The model is a multi-head PyTorch LSTM Neural Network designed for direct multi-horizon forecasting:

```
Input Sequence: (batch_size, sequence_length=30, num_features=27)
├── LSTM Layer 1 (64 units, PyTorch LSTM)
├── LSTM Layer 2 (64 units)
├── Shared Representation Layer (32 units, ReLU + Dropout 0.2)
├── Head 1 (head_current): Linear(32, 1) -> Current Attack Probability
├── Head 2 (head_forecast): Linear(32, 5) -> K=5 Future Attack Forecast Timeline
└── Head 3 (head_stage): Linear(32, 6) -> MITRE ATT&CK Stage Classification
```

### Training Setup & Loss Weighting
- **Loss Function**: `BCEWithLogitsLoss` for current and forecast heads with positive weight scaling (`pos_weight = 2.68`), plus `CrossEntropyLoss` for MITRE stage classification.
- **Scaler**: `StandardScaler` fitted **strictly on the training split** to avoid data leakage.
- **Split**: 70% Train (27,453 windows), 15% Validation (5,880 windows), 15% Test (5,880 windows) using block-based temporal partitioning to ensure representative attack periods in all splits without past/future shuffling within blocks.

---

## 5. Empirical Evaluation Results (Real CIC-IDS2018 Test Set)

| Model Architecture | Accuracy | Precision | Recall | F1 Score | False Positive Rate (FPR) | Confusion Matrix (TN / FP / FN / TP) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **PyTorch LSTM World Model (Temporal)** | **98.57%** | **96.62%** | **98.41%** | **97.51%** | **1.36%** | **4,225 / 58 / 25 / 1,572** |
| Logistic Regression Baseline | 88.93% | 74.31% | 94.18% | 83.08% | 13.03% | 3,725 / 558 / 93 / 1,504 |

---

## 6. Model Output Location

All generated model artifacts are persisted in `models/trained/`:
- `models/trained/world_model.pth` (PyTorch model weights & state dict)
- `models/trained/scaler.pkl` (Fitted StandardScaler)
- `models/trained/feature_config.json` (Feature names & sequence parameters)
- `models/trained/label_mapping.json` (MITRE stage mappings)
- `models/trained/benchmark_metrics.json` (Empirical metrics)
- `models/trained/world_model.keras` (Compatibility wrapper descriptor)

---

## 7. API Endpoint & Sample Forecast JSON

Inference engine `inference/forecast.py` loads `world_model.pth` and computes gradient-based feature attribution.

```json
{
  "current_probability": 0.0379,
  "forecast": [
    {"step": 1, "probability": 0.0446},
    {"step": 2, "probability": 0.0496},
    {"step": 3, "probability": 0.0556},
    {"step": 4, "probability": 0.0520},
    {"step": 5, "probability": 0.0587}
  ],
  "predicted_stage": "Normal / Benign",
  "predicted_stage_index": 0,
  "stage_confidence": 0.9895,
  "top_features": [
    {"feature": "rst_flag_cnt", "importance": 0.1523},
    {"feature": "tot_bwd_pkts", "importance": 0.0908},
    {"feature": "is_high_risk_port", "importance": 0.0821},
    {"feature": "bwd_pkt_len_mean", "importance": 0.0760},
    {"feature": "ack_flag_cnt", "importance": 0.0739},
    {"feature": "psh_flag_cnt", "importance": 0.0729}
  ],
  "window_size": 30,
  "prediction_horizon": 5
}
```
