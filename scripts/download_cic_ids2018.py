#!/usr/bin/env python3
"""
Script to download official CSE-CIC-IDS2018 processed traffic CSV dataset from AWS S3.
Bucket: s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/

No AWS account required (uses --no-sign-request or public HTTP fallback).
"""

import os
import sys
import subprocess
import urllib.request
import urllib.parse
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

RAW_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "cic_ids2018", "raw")
S3_BUCKET = "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/"

# Official CSE-CIC-IDS2018 processed traffic CSV files
TARGET_FILES = [
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",   # FTP / SSH BruteForce
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",    # DoS GoldenEye / Slowloris
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",      # DoS SlowHTTPTest / Hulk
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",   # DDOS HOIC / LOIC-UDP
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",      # Brute Force Web / XSS, SQL Injection
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",   # Infiltration
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",    # Infiltration
    "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",      # Bot
]


def download_file_s3(filename: str, output_path: str) -> bool:
    """Try downloading via aws s3 CLI without credentials."""
    s3_path = f"{S3_BUCKET}{filename}"
    cmd = ["aws", "s3", "cp", "--no-sign-request", s3_path, output_path]
    logging.info(f"Running: {' '.join(cmd)}")
    try:
        res = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        logging.info(f"Successfully downloaded {filename}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logging.warning(f"AWS CLI download failed for {filename}: {e}")
        return False


def download_file_http(filename: str, output_path: str) -> bool:
    """Fallback HTTP download from public S3 endpoint."""
    url = f"https://cse-cic-ids2018.s3.amazonaws.com/Processed+Traffic+Data+for+ML+Algorithms/{urllib.parse.quote(filename)}"
    logging.info(f"Downloading via HTTP: {url}")
    try:
        def report_progress(block_num, block_size, total_size):
            downloaded = block_num * block_size
            if total_size > 0:
                percent = min(100.0, (downloaded / total_size) * 100)
                if block_num % 1000 == 0:
                    logging.info(f"{filename}: {percent:.1f}% ({downloaded / (1024*1024):.1f} MB)")
        urllib.request.urlretrieve(url, output_path, reporthook=report_progress)
        logging.info(f"HTTP download finished for {filename}")
        return True
    except Exception as e:
        logging.error(f"HTTP download failed for {filename}: {e}")
        return False


def download_dataset(files_to_download=None):
    os.makedirs(RAW_DATA_DIR, exist_ok=True)
    targets = files_to_download or TARGET_FILES

    logging.info(f"Downloading CSE-CIC-IDS2018 files to: {RAW_DATA_DIR}")
    downloaded_files = []

    for filename in targets:
        output_path = os.path.join(RAW_DATA_DIR, filename)
        if os.path.exists(output_path) and os.path.getsize(output_path) > 1024 * 1024:
            logging.info(f"File already exists (size: {os.path.getsize(output_path)/(1024*1024):.2f} MB): {filename}")
            downloaded_files.append(output_path)
            continue

        success = download_file_s3(filename, output_path)
        if not success:
            success = download_file_http(filename, output_path)

        if success and os.path.exists(output_path):
            downloaded_files.append(output_path)
        else:
            logging.error(f"Could not download {filename}")

    return downloaded_files


if __name__ == "__main__":
    # Can pass specific file names as arguments if desired
    args = sys.argv[1:]
    download_dataset(args if args else None)
