# 🛡️ NetGuard — Network-Level Malware & Threat Detection System

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Node.js 18+](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.135.0-009688.svg)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-16.1.6-black.svg)](https://nextjs.org/)
[![PyTorch LSTM](https://img.shields.io/badge/PyTorch-LSTM%20World%20Model-EE4C2C.svg)](https://pytorch.org/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](#)

A full-stack, real-time network defense and attack forecasting system built for **SIH (Problem Statement: AI-based Network Attack Forecasting from Network Traffic Data - ID 26153)**. NetGuard combines live kernel-level packet inspection (Scapy/Npcap), behavioral heuristic analysis, and a 2-layer PyTorch LSTM World Model trained on CSE-CIC-IDS2018 dataset to detect intrusions and forecast future attack trajectories up to 25 seconds into the future.

---

## 🏗️ Architecture & Component Overview

```
NetGuard/
├── backend/                  # FastAPI Application & Threat Engine
│   ├── app/
│   │   ├── api/routes.py     # Consolidated REST & WebSocket Endpoints
│   │   ├── models/           # Pydantic Schemas & Data Contracts
│   │   ├── services/         # Packet capture, Proxy, Threat hunting, ML Benchmark
│   │   └── utils/            # IP hashing, CSV mapping, event logging helpers
│   ├── requirements.txt      # Production Python dependencies
│   └── requirements-dev.txt  # Testing & linter dependencies
├── frontend/                 # Next.js 16 + React 19 Security Dashboard
│   ├── app/                  # Landing page, /dashboard, /workbench routes
│   ├── components/           # Real-time metrics, charts, tables, UI components
│   ├── hooks/                # Keyboard shortcuts, toast, mobile detection
│   └── lib/api.ts            # Typed Axios API Client with fallback resilience
├── models/                   # Neural Network Architecture & Model Weights
│   ├── network_world_model.py# PyTorch LSTM Multi-Head World Model Definition
│   └── trained/              # Weights (world_model.pth), Scaler, Configs, Metrics
├── inference/                # Real-Time Forecasting & Attribution Engine
│   └── forecast.py           # Gradient-based Saliency & 5-Step Forward Forecasting
├── certs/                    # SSL/TLS Certificates for Local HTTPS Gateway
├── samples/                  # Pre-packaged Offline PCAP & CSV Test Data
├── scripts/                  # Automated Setup, Capture, & Packaging Scripts
├── start-all.bat             # One-click launcher for Backend + Frontend
├── start-backend.bat         # Standalone backend launcher
├── start-frontend.bat        # Standalone frontend launcher
├── README.md                 # Project Overview
├── SETUP.md                  # Comprehensive Step-by-Step Installation Guide
└── REQUIRED_EXTERNAL_DEPENDENCIES.md # Details on external runtimes & datasets
```

---

## ⚡ Key Features

1. **AI Attack Forecasting (PyTorch LSTM World Model)**:
   - Aggregates traffic into 5-second observation buckets across 27 canonical network features.
   - Evaluates a 30-state sliding window (150 seconds of history) to forecast multi-horizon attack probability ($t+1$ to $t+5$, up to 25s ahead).
   - Maps detected anomalies directly to MITRE ATT&CK tactics (Credential Access, Initial Access, Execution, C2 Bot, Impact DoS).
   - Computes gradient-based feature attribution to provide explainable AI insights for security analysts.

2. **Live Packet Capture & Hardware Sniffing**:
   - Kernel-level live packet sniffing via Scapy and Npcap on Windows.
   - Automatic interface detection and packet normalization.

3. **Mobile & Device Proxy Gateway**:
   - Built-in HTTP/HTTPS transparent proxy on port `8888` allowing smartphones, IoT devices, or other LAN endpoints to route traffic through NetGuard.

4. **Offline Forensics & Security Workbench**:
   - Ingest offline packet captures (`.pcap`, `.pcapng`) or flow spreadsheets (`.csv`).
   - Instant feature extraction and multi-step threat forecasting on historical incident logs.

5. **Integrated Local HTTPS Gateway**:
   - Built-in TLS reverse proxy on port `443` unifying frontend and backend under single HTTPS origin.

---

## 🚀 2-Minute Quick Start

### Prerequisites
- **Windows 10/11 64-bit**
- **Python 3.11 or 3.12** ([python.org](https://www.python.org/downloads/))
- **Node.js 18+ or 20+** ([nodejs.org](https://nodejs.org/))
- **Npcap** (Required **only** for live packet capture: [npcap.com](https://npcap.com/#download))

### Option A: Automated PowerShell Setup (Recommended)

1. Open PowerShell in this folder:
   ```powershell
   .\scripts\setup-local.ps1
   ```
2. Start NetGuard in Standard Dev Mode:
   ```powershell
   .\scripts\dev-local.ps1
   ```
3. Open your browser to **http://localhost:3000**!

---

### Option B: One-Click Batch Launcher

1. Ensure Python and Node.js dependencies are installed.
2. Double-click `start-all.bat`.
3. Separate command prompt windows will launch:
   - **Backend API**: `http://localhost:8000` (Docs at `http://localhost:8000/docs`)
   - **Frontend UI**: `http://localhost:3000`

---

### Option C: Live Packet Capture Mode (Administrator)

To capture live traffic from your Wi-Fi/Ethernet network card:
1. Open PowerShell **as Administrator**.
2. Run:
   ```powershell
   .\scripts\dev-local-capture.ps1
   ```
3. This starts elevated packet capture and opens the mobile proxy on port `8888`.

---

## 📖 Documentation Index

- **[SETUP.md](SETUP.md)**: Full step-by-step installation, dependency configuration, live vs demo modes, PCAP/CSV testing, and troubleshooting.
- **[REQUIRED_EXTERNAL_DEPENDENCIES.md](REQUIRED_EXTERNAL_DEPENDENCIES.md)**: List of software, runtimes, drivers, and external datasets not bundled in the source archive.
- **[PROJECT_DOCUMENTATION.md](PROJECT_DOCUMENTATION.md)**: Exhaustive API endpoint specification, Pydantic schemas, and component interactions.
- **[TRAINING.md](TRAINING.md)**: Machine learning pipeline, dataset breakdown (CSE-CIC-IDS2018), temporal windowing math, and empirical evaluation metrics.
