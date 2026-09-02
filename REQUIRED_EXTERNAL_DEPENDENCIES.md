# 📦 NetGuard — Required External Dependencies & Datasets

This document provides a transparent, complete list of external dependencies, runtimes, drivers, and large datasets that are **not pre-bundled** inside this repository archive.

---

## 1. Summary Matrix

| Dependency | Category | Required For | Default Location | How to Obtain |
| :--- | :--- | :--- | :--- | :--- |
| **Python 3.11 (64-bit)** | Runtime | Backend, ML Inference, Scapy | System PATH | [python.org](https://www.python.org/downloads/) |
| **Node.js (18+ / 20+ LTS)** | Runtime | Next.js 16, React 19 Frontend | System PATH | [nodejs.org](https://nodejs.org/) |
| **Npcap (1.80+)** | Kernel Driver | LIVE Packet Capture (*Windows only*) | System Driver | [npcap.com](https://npcap.com/#download) |
| **Python Packages** | Libraries | Backend Execution | `backend/.venv` | `pip install -r backend/requirements.txt` |
| **Node Packages** | Libraries | Frontend Execution | `frontend/node_modules` | `npm install --legacy-peer-deps` |
| **CSE-CIC-IDS2018 Raw Data** | Dataset (~2.4 GB) | Re-training World Model (*Optional*) | `data/cic_ids2018/raw/` | `python scripts/download_cic_ids2018.py` |
| **Processed Parquet Cache** | Data Cache (~543 MB) | Re-training World Model (*Optional*) | `data/cic_ids2018/processed/` | `python scripts/prepare_cic_ids2018.py` |

---

## 2. Detailed Rationale & Setup Instructions

### 2.1 Python 3.11 Runtime
- **Why it is external:** System-level interpreter. Bundling a full Python runtime in git is bad practice and causes platform incompatibilities.
- **Where it is needed:** The entire backend service, inference engine, Scapy packet analyzer, and setup scripts require a 64-bit Python interpreter.
- **Recommended Action:** Download installer from [python.org/downloads](https://www.python.org/downloads/). Ensure **"Add python.exe to PATH"** is checked during setup.

---

### 2.2 Node.js (v18 or v20 LTS) & npm
- **Why it is external:** Frontend JavaScript/TypeScript runtime.
- **Where it is needed:** Running the Next.js 16 development server and building static UI bundles.
- **Recommended Action:** Download Node.js LTS from [nodejs.org](https://nodejs.org/).

---

### 2.3 Npcap Packet Capture Library (Windows Driver)
- **Why it is external:** Npcap is a kernel-mode network driver. It requires Windows administrative driver signing and cannot be copied as a loose file.
- **Where it is needed:** Used exclusively when performing **LIVE packet sniffing** on a physical network card (`scripts/dev-local-capture.ps1`).
- **Is it required for standard demo?** **NO.** Demo simulation mode and the offline forensics workbench (PCAP/CSV upload) work 100% without Npcap installed.
- **How to install:**
  1. Download the free installer from [npcap.com/#download](https://npcap.com/#download).
  2. Choose "Install Npcap in WinPcap API-compatible Mode".
  3. Verify with `Get-Service npcap` in PowerShell.

---

### 2.4 Python Virtual Environment Packages (`requirements.txt`)
- **Why it is external:** Python packages (e.g. `torch`, `scikit-learn`, `fastapi`, `pandas`, `scapy`) contain compiled C++ binaries that must match the host machine's architecture.
- **How to install:**
  ```powershell
  cd backend
  python -m venv .venv
  .\.venv\Scripts\activate
  pip install -r requirements.txt
  ```

---

### 2.5 Node.js Dependencies (`node_modules`)
- **Why it is external:** Contains platform-specific compiled bindings (e.g. SWC native binaries).
- **How to install:**
  ```powershell
  cd frontend
  npm install --legacy-peer-deps
  ```

---

### 2.6 Pre-Trained Model Weights vs. Raw Training Dataset

#### ✅ WHAT IS INCLUDED (Pre-Trained & Ready for Immediate Inference):
All trained model artifacts are **already included** in `models/trained/`:
- `models/trained/world_model.pth` (244 KB - PyTorch LSTM weights)
- `models/trained/scaler.pkl` (1.2 KB - Fitted feature scaler)
- `models/trained/feature_config.json` (754 B - Feature definition)
- `models/trained/label_mapping.json` (1.9 KB - MITRE stage mappings)
- `models/trained/benchmark_metrics.json` (866 B - Evaluation benchmarks)
- `models/trained/world_model.keras` (Compatibility wrapper)

> [!TIP]
> **You DO NOT need to download the 2.4 GB raw dataset to run NetGuard!** The system is fully operational out-of-the-box using the pre-trained weights.

#### 🔄 OPTIONAL: Re-training the Model from Scratch
If a teammate wishes to reproduce the empirical training pipeline from the raw CSE-CIC-IDS2018 AWS S3 dataset:

1. **Download Raw CSV Files (approx. 2.4 GB)**:
   ```powershell
   python scripts\download_cic_ids2018.py
   ```
   *(Downloads the 8 official CSV files from `s3://cse-cic-ids2018/` into `data/cic_ids2018/raw/`)*.

2. **Run Temporal State Aggregation (5s windowing & parquet export)**:
   ```powershell
   python scripts\prepare_cic_ids2018.py
   ```
   *(Processes raw flows and exports `data/cic_ids2018/processed/processed_traffic.parquet`)*.

3. **Train PyTorch LSTM World Model**:
   ```powershell
   python scripts\train_world_model.py
   ```
   *(Re-trains the neural network and updates `models/trained/world_model.pth`)*.
