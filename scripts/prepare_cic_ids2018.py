#!/usr/bin/env python3
"""
STEP 2 — DATA PREPROCESSING FOR CSE-CIC-IDS2018

Processes raw CSE-CIC-IDS2018 CSV files:
1. Loads CSV files from data/cic_ids2018/raw/
2. Standardizes and cleans column names
3. Drops duplicate inline header rows
4. Replaces invalid/infinite values (Inf, -Inf, NaN)
5. Parses Timestamp field into proper datetime objects
6. Sorts dataset CHRONOLOGICALLY (Preserving temporal order for window creation!)
7. Encodes protocol and extracts key numerical flow features
8. Maps raw labels to standardized attack names & explicit MITRE ATT&CK stages
9. Saves cleaned dataset to data/cic_ids2018/processed/
"""

import os
import sys
import glob
import logging
import pandas as pd
import numpy as np
from typing import Tuple, List, Dict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(BASE_DIR, "data", "cic_ids2018", "raw")
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "cic_ids2018", "processed")

# Explicit Mapping from CIC-IDS2018 Labels to Project MITRE ATT&CK Stages
# Documented in TRAINING.md according to requirement STEP 7
MITRE_STAGE_MAPPING = {
    "BENIGN": {"stage": "Normal / Benign", "stage_num": 0, "tactic": "None"},
    "FTP-BRUTEFORCE": {"stage": "Credential Access", "stage_num": 1, "tactic": "T1110 - Brute Force"},
    "SSH-BRUTEFORCE": {"stage": "Credential Access", "stage_num": 1, "tactic": "T1110 - Brute Force"},
    "BRUTE FORCE -WEB": {"stage": "Credential Access", "stage_num": 1, "tactic": "T1110 - Brute Force"},
    "BRUTE FORCE -XSS": {"stage": "Credential Access", "stage_num": 1, "tactic": "T1110 - Brute Force"},
    "SQL INJECTION": {"stage": "Initial Access", "stage_num": 2, "tactic": "T1190 - Exploit Public-Facing Application"},
    "INFILTRATION": {"stage": "Privilege Escalation / Execution", "stage_num": 3, "tactic": "T1068 - Exploitation for Privilege Escalation"},
    "BOT": {"stage": "Command and Control", "stage_num": 4, "tactic": "T1071 - Application Layer Protocol"},
    "DOS ATTACKS-GOLDENEYE": {"stage": "Impact", "stage_num": 5, "tactic": "T1498 - Network Denial of Service"},
    "DOS ATTACKS-SLOWLORIS": {"stage": "Impact", "stage_num": 5, "tactic": "T1498 - Network Denial of Service"},
    "DOS ATTACKS-SLOWHTTPTEST": {"stage": "Impact", "stage_num": 5, "tactic": "T1498 - Network Denial of Service"},
    "DOS ATTACKS-HULK": {"stage": "Impact", "stage_num": 5, "tactic": "T1498 - Network Denial of Service"},
    "DDOS ATTACKS-LOIC-HTTP": {"stage": "Impact", "stage_num": 5, "tactic": "T1498 - Network Denial of Service"},
    "DDOS ATTACK-HOIC": {"stage": "Impact", "stage_num": 5, "tactic": "T1498 - Network Denial of Service"},
    "DDOS ATTACK-LOIC-UDP": {"stage": "Impact", "stage_num": 5, "tactic": "T1498 - Network Denial of Service"}
}


def sanitize_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Clean column names by removing non-printable chars, leading/trailing spaces, and special characters."""
    clean_cols = {}
    for c in df.columns:
        clean = str(c).strip().replace("\ufeff", "").replace(" ", "_").replace("/", "_").replace("-", "_").lower()
        while "__" in clean:
            clean = clean.replace("__", "_")
        clean_cols[c] = clean
    return df.rename(columns=clean_cols)


def map_mitre_stage(label: str) -> Tuple[str, int, int]:
    """Map raw label string to MITRE stage name, stage number, and binary threat indicator (0=Benign, 1=Attack)."""
    norm_label = str(label).strip().upper()
    if norm_label in MITRE_STAGE_MAPPING:
        info = MITRE_STAGE_MAPPING[norm_label]
        is_attack = 0 if info["stage_num"] == 0 else 1
        return info["stage"], info["stage_num"], is_attack

    # Fallback partial matching
    if "BENIGN" in norm_label:
        return "Normal / Benign", 0, 0
    elif "BRUTE" in norm_label:
        return "Credential Access", 1, 1
    elif "SQL" in norm_label or "INJECT" in norm_label:
        return "Initial Access", 2, 1
    elif "INFILTR" in norm_label:
        return "Privilege Escalation / Execution", 3, 1
    elif "BOT" in norm_label:
        return "Command and Control", 4, 1
    elif "DOS" in norm_label or "DDOS" in norm_label:
        return "Impact", 5, 1
    else:
        return "Unknown Threat", 1, 1


def prepare_dataset(sample_fraction: float = 1.0) -> str:
    """Loads, cleans, sorts chronologically, and saves processed CIC-IDS2018 dataset."""
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    raw_files = sorted(glob.glob(os.path.join(RAW_DIR, "*.csv")))

    if not raw_files:
        raise FileNotFoundError(f"No raw CSV files found in {RAW_DIR}. Please run scripts/download_cic_ids2018.py first.")

    logging.info(f"Found {len(raw_files)} raw CSV file(s) in {RAW_DIR}")
    dfs = []

    for filepath in raw_files:
        filename = os.path.basename(filepath)
        logging.info(f"Processing raw CSV: {filename}")

        try:
            # Read first row to inspect columns
            header_df = pd.read_csv(filepath, nrows=2)
            clean_map = {c: str(c).strip().replace("\ufeff", "").replace(" ", "_").replace("/", "_").replace("-", "_").lower() for c in header_df.columns}
            needed_keywords = ["timestamp", "port", "protocol", "duration", "pkt", "byte", "len", "iat", "flag", "ratio", "label"]
            cols_to_use = [orig for orig, cln in clean_map.items() if any(kw in cln for kw in needed_keywords)]

            df = pd.read_csv(filepath, usecols=cols_to_use, low_memory=False)
        except Exception as e:
            logging.error(f"Error reading {filename}: {e}")
            continue

        logging.info(f"Loaded {len(df)} raw rows from {filename}")
        df = sanitize_column_names(df)

        if "dst_port" in df.columns:
            df = df[df["dst_port"].astype(str).str.lower() != "dst port"]
        if "timestamp" in df.columns:
            df = df[df["timestamp"].astype(str).str.lower() != "timestamp"]

        # Downcast numeric columns to float32 per file
        for col in df.columns:
            if col not in ["timestamp", "label"]:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(np.float32)

        dfs.append(df)

    if not dfs:
        raise ValueError("No data could be loaded from raw CSV files.")

    full_df = pd.concat(dfs, ignore_index=True)
    logging.info(f"Combined raw dataset total rows: {len(full_df)}")

    # Parse Timestamps
    if "timestamp" in full_df.columns:
        logging.info("Parsing Timestamp column chronologically...")
        full_df["timestamp"] = pd.to_datetime(full_df["timestamp"], errors="coerce", format="mixed")
        # Drop rows with invalid timestamp
        full_df = full_df.dropna(subset=["timestamp"])
        # CRITICAL TEMPORAL REQUIREMENT: Sort traffic chronologically
        full_df.sort_values(by="timestamp", inplace=True)
        full_df.reset_index(drop=True, inplace=True)
    else:
        logging.warning("Timestamp column not found in dataset!")

    # Standardize label column
    label_col = [c for c in full_df.columns if "label" in c]
    if label_col:
        full_df.rename(columns={label_col[0]: "label"}, inplace=True)
    else:
        full_df["label"] = "BENIGN"

    full_df["label"] = full_df["label"].astype(str).str.strip()

    # Apply MITRE stage mapping via fast vectorized lookup
    logging.info("Mapping CIC-IDS2018 labels to MITRE ATT&CK stages...")
    stage_name_map = {k.upper(): v["stage"] for k, v in MITRE_STAGE_MAPPING.items()}
    stage_num_map = {k.upper(): v["stage_num"] for k, v in MITRE_STAGE_MAPPING.items()}

    norm_labels = full_df["label"].str.upper().str.strip()
    full_df["mitre_stage"] = norm_labels.map(stage_name_map).fillna("Normal / Benign")
    full_df["stage_num"] = norm_labels.map(stage_num_map).fillna(0).astype(np.int8)
    full_df["is_attack"] = (full_df["stage_num"] > 0).astype(np.int8)

    # Clean numeric columns & replace infinity / NaN
    numeric_cols = [c for c in full_df.columns if c not in ["timestamp", "label", "mitre_stage", "protocol"]]
    for col in numeric_cols:
        full_df[col] = pd.to_numeric(full_df[col], errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0).astype(np.float32)

    # Protocol encoding
    if "protocol" in full_df.columns:
        full_df["protocol"] = pd.to_numeric(full_df["protocol"], errors="coerce").fillna(0).astype(int)

    # Downsample if sample_fraction < 1.0 (maintaining chronological order)
    if 0.0 < sample_fraction < 1.0:
        step = int(1.0 / sample_fraction)
        full_df = full_df.iloc[::step].reset_index(drop=True)
        logging.info(f"Sampled down to fraction {sample_fraction:.2f}: {len(full_df)} rows")

    # Save output dataset
    output_parquet = os.path.join(PROCESSED_DIR, "processed_traffic.parquet")
    output_csv = os.path.join(PROCESSED_DIR, "processed_traffic.csv")

    try:
        full_df.to_parquet(output_parquet, index=False)
        logging.info(f"Saved processed dataset to Parquet: {output_parquet}")
    except Exception as e:
        logging.warning(f"Could not save parquet ({e}), saving CSV instead.")
        full_df.to_csv(output_csv, index=False)
        logging.info(f"Saved processed dataset to CSV: {output_csv}")

    logging.info("Preprocessing complete.")
    logging.info(f"Number of files processed: {len(raw_files)}")
    logging.info(f"Total Rows: {len(full_df)}")
    if "timestamp" in full_df.columns and len(full_df) > 0:
        logging.info(f"Timestamp Min: {full_df['timestamp'].min()} | Timestamp Max: {full_df['timestamp'].max()}")
    attack_count = (full_df["is_attack"] == 1).sum()
    attack_pct = (attack_count / len(full_df)) * 100.0 if len(full_df) > 0 else 0.0
    logging.info(f"Attack percentage: {attack_pct:.2f}% ({attack_count}/{len(full_df)})")
    logging.info(f"Label breakdown:\n{full_df['label'].value_counts()}")
    logging.info(f"MITRE stage breakdown:\n{full_df['mitre_stage'].value_counts()}")

    return output_parquet if os.path.exists(output_parquet) else output_csv


if __name__ == "__main__":
    frac = 1.0
    if len(sys.argv) > 1:
        try:
            frac = float(sys.argv[1])
        except ValueError:
            pass
    prepare_dataset(sample_fraction=frac)
