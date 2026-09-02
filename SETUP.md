# 🛠️ NetGuard — Complete Teammate Setup Guide

This guide is designed for setting up and running **NetGuard** on a **fresh Windows laptop** from scratch. Follow these steps sequentially to ensure full functionality across the backend, frontend, AI world model, and packet capture engine.

---

## Table of Contents

1. [Required Software & System Requirements](#1-required-software--system-requirements)
2. [Required Software Versions](#2-required-software-versions)
3. [Software Installation Commands & Links](#3-software-installation-commands--links)
4. [Installing Python Dependencies (Backend)](#4-installing-python-dependencies-backend)
5. [Installing Frontend Dependencies (Next.js & UI)](#5-installing-frontend-dependencies-nextjs--ui)
6. [Configuring Environment Variables](#6-configuring-environment-variables)
7. [Installing & Configuring Npcap for Windows](#7-installing--configuring-npcap-for-windows)
8. [How to Start the Backend](#8-how-to-start-the-backend)
9. [How to Start the Frontend](#9-how-to-start-the-frontend)
10. [How to Start the HTTPS Gateway (Port 443)](#10-how-to-start-the-https-gateway-port-443)
11. [How to Enable LIVE Packet Capture](#11-how-to-enable-live-packet-capture)
12. [How to Run DEMO MODE](#12-how-to-run-demo-mode)
13. [How to Run LIVE MODE](#13-how-to-run-live-mode)
14. [How to Open & Navigate the Website](#14-how-to-open--navigate-the-website)
15. [How to Test Offline PCAP Upload](#15-how-to-test-offline-pcap-upload)
16. [How to Test Offline CSV Upload](#16-how-to-test-offline-csv-upload)
17. [How to Verify the AI Forecasting Model](#17-how-to-verify-the-ai-forecasting-model)
18. [Troubleshooting Common Errors](#18-troubleshooting-common-errors)

---

## 1. Required Software & System Requirements

- **Operating System:** Windows 10 (64-bit) or Windows 11 (64-bit).
- **RAM:** Minimum 8 GB (16 GB recommended).
- **Disk Space:** ~3 GB free space for Node packages and Python PyTorch environment.
- **Network Adapter:** Standard Wi-Fi or Ethernet adapter.
- **Administrator Privileges:** Required for Npcap live packet capture and local proxy firewall rules.

---

## 2. Required Software Versions

| Software | Supported Versions | Recommended Version | Purpose |
| :--- | :--- | :--- | :--- |
| **Python** | 3.10, 3.11, 3.12 | **Python 3.11.x (64-bit)** | FastAPI backend, PyTorch LSTM inference, Scapy |
| **Node.js** | 18.x, 20.x, 22.x | **Node.js 20.x LTS** | Next.js 16 frontend, React 19 UI |
| **Package Manager** | npm (v9+), pnpm (v9+) | **npm** or **pnpm** | Frontend package installation |
| **Npcap** | 1.70+ | **Npcap 1.80+** | Kernel packet capture on Windows (*Live Mode only*) |
| **PowerShell** | Windows PowerShell 5.1 or PowerShell 7+ | **PowerShell 7+ / 5.1** | Automation scripts |

---

## 3. Software Installation Commands & Links

### Python Installation
1. Download Python 3.11 from the official portal: [python.org/downloads](https://www.python.org/downloads/)
2. **IMPORTANT**: Check the box **"Add python.exe to PATH"** during setup.
3. Verify installation:
   ```cmd
   python --version
   pip --version
   ```

### Node.js Installation
1. Download Node.js LTS from [nodejs.org](https://nodejs.org/).
2. Complete the standard installer.
3. Verify installation:
   ```cmd
   node --version
   npm --version
   ```

### Winget Alternative (One-Liner in PowerShell as Admin)
```powershell
winget install -e --id Python.Python.3.11
winget install -e --id OpenJS.NodeJS.LTS
```

---

## 4. Installing Python Dependencies (Backend)

We recommend using a Python virtual environment to keep dependencies clean:

### Step 4.1: Create Virtual Environment
Open PowerShell or Command Prompt in the project root:
```powershell
cd backend
python -m venv .venv
```

### Step 4.2: Activate Virtual Environment
**PowerShell:**
```powershell
.\.venv\Scripts\Activate.ps1
```
*(If PowerShell displays an execution policy error, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first).*

**Command Prompt:**
```cmd
.venv\Scripts\activate.bat
```

### Step 4.3: Install Requirements
```cmd
python -m pip install --upgrade pip
pip install -r requirements.txt
```

*(Optional development & testing tools)*:
```cmd
pip install -r requirements-dev.txt
```

---

## 5. Installing Frontend Dependencies (Next.js & UI)

Navigate into the `frontend` folder and install dependencies:

```cmd
cd frontend
npm install --legacy-peer-deps
```
*Or if you have `pnpm` installed:*
```cmd
pnpm install
```

---

## 6. Configuring Environment Variables

NetGuard comes with pre-configured defaults, but you can customize environment variables as needed.

### Frontend Environment (`frontend/.env.local`)
Create `frontend/.env.local` (or let `setup-local.ps1` create it automatically):
```ini
BACKEND_API_URL=http://localhost:8000
NEXT_PUBLIC_API_URL=http://localhost:8000
```

### Backend Environment (`backend/.env`)
Create `backend/.env` (or copy from `.env.example`):
```ini
ALLOWED_ORIGINS=http://localhost:3000
BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
ENVIRONMENT=development
PROXY_ENABLED=1
PROXY_HOST=0.0.0.0
PROXY_PORT=8888
KNOWN_MALICIOUS_DOMAINS=
KNOWN_MALICIOUS_IPS=
```

---

## 7. Installing & Configuring Npcap for Windows

> [!NOTE]
> **Npcap is ONLY required if you plan to sniff live packets from your network interface.**
> If you are demonstrating using **Demo Mode** or the **Offline Workbench (PCAP/CSV Upload)**, Npcap is optional.

### Step 7.1: Download Npcap
Download the free installer from the official site:
👉 **[https://npcap.com/#download](https://npcap.com/#download)** (e.g., `npcap-1.80.exe` or higher).

### Step 7.2: Installation Options
Run the downloaded executable. When prompted with installer checkboxes:
1. ✅ **Check: "Support raw 802.11 traffic (and monitor mode) for wireless adapters"** (if available).
2. ✅ **Check: "Install Npcap in WinPcap API-compatible Mode"** (Recommended for Scapy).
3. Complete the installation.

### Step 7.3: Verify Npcap Service
Run in PowerShell:
```powershell
Get-Service -Name npcap
```
Status should show `Running`.

---

## 8. How to Start the Backend

### Method A: One-Click Batch Script
From the project root:
```cmd
start-backend.bat
```

### Method B: Manual Command Line
```cmd
cd backend
.venv\Scripts\activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The backend is available at **http://localhost:8000**.
Swagger API Documentation is available at **http://localhost:8000/docs**.

---

## 9. How to Start the Frontend

### Method A: One-Click Batch Script
From the project root:
```cmd
start-frontend.bat
```

### Method B: Manual Command Line
```cmd
cd frontend
npm run dev
```

The dashboard is accessible at **http://localhost:3000**.

---

## 10. How to Start the HTTPS Gateway (Port 443)

NetGuard includes an asyncio HTTPS gateway using the certificates in `certs/`:

1. Ensure Backend (port 8000) and Frontend (port 3000) are running.
2. Open PowerShell as **Administrator** (port 443 requires elevated privileges on Windows).
3. Run:
   ```powershell
   python scripts\https_gateway.py
   ```
4. Access the unified platform over HTTPS: **https://localhost/**.
   *(Accept the self-signed certificate warning in your browser).*

---

## 11. How to Enable LIVE Packet Capture

Live packet capture inspects actual network frames traversing your physical Wi-Fi or Ethernet adapter:

1. Right-click PowerShell and select **Run as Administrator**.
2. Run:
   ```powershell
   .\scripts\dev-local-capture.ps1
   ```
3. This will:
   - Request Administrator elevation.
   - Configure Windows Firewall rules for port `8000` (API) and port `8888` (Proxy).
   - Start the backend with Scapy live packet sniffing enabled.
   - Start the frontend on port `3000`.
   - Output your local LAN IP (e.g., `192.168.1.50:8888`) for mobile proxy routing.

---

## 12. How to Run DEMO MODE

If you are presenting or testing without active malicious traffic on your network:

1. Start the platform normally (`start-all.bat` or `.\scripts\dev-local.ps1`).
2. Open **http://localhost:3000/dashboard**.
3. In the Top Bar, toggle **"Demo Simulation"** to **ON**.
4. The system will simulate realistic traffic anomalies, brute-force attempts, and port scans, triggering real-time MITRE ATT&CK classifications and forward attack forecasts.

---

## 13. How to Run LIVE MODE

1. Launch elevated capture:
   ```powershell
   .\scripts\dev-local-capture.ps1
   ```
2. Open **http://localhost:3000/dashboard**.
3. Ensure **"Live Sniffing"** is active in the status banner.
4. **Mobile Device Proxy Capture (Optional)**:
   - Connect your smartphone to the same Wi-Fi network.
   - In phone Wi-Fi settings, set **Proxy** to **Manual**.
   - Host: *Your Laptop LAN IP* (e.g., `192.168.1.100`), Port: `8888`.
   - Any website browsed on the phone is analyzed in real time on your dashboard!

---

## 14. How to Open & Navigate the Website

- **Landing Page & Presentation Portal:** `http://localhost:3000/`
- **Real-Time Security Dashboard:** `http://localhost:3000/dashboard`
  - Live Bandwidth & Protocol breakdown.
  - Threat detection matrix & MITRE ATT&CK mapping.
  - 5-Step PyTorch LSTM Attack Forecast timeline.
  - Saliency feature attribution (Explainable AI).
- **Security Forensics Workbench:** `http://localhost:3000/workbench`
  - Upload `.pcap`, `.pcapng`, or `.csv` files for offline deep inspection.
- **FastAPI OpenAPI Documentation:** `http://localhost:8000/docs`

---

## 15. How to Test Offline PCAP Upload

NetGuard includes a sample PCAP file in `samples/sample_exploit_traffic.pcap`:

1. Open **http://localhost:3000/workbench**.
2. Under **"Upload Offline Capture"**, click the file upload area or drag and drop:
   `samples\sample_exploit_traffic.pcap`
3. Click **"Extract Features & Forecast"**.
4. The backend will:
   - Parse raw Ethernet/IP/TCP frames via `scripts/pcap_to_flow.py`.
   - Aggregate packets into 5-second canonical feature vectors.
   - Feed the 30-state sequence into the LSTM World Model.
   - Display predicted MITRE attack stages, future attack probabilities, and top influential features.

---

## 16. How to Test Offline CSV Upload

NetGuard includes a sample CSV flow file in `samples/sample_network_flows.csv`:

1. Open **http://localhost:3000/workbench**.
2. Select or drag-and-drop:
   `samples\sample_network_flows.csv`
3. Click **"Analyze Dataset"**.
4. The backend maps headers to the 27 canonical features, runs temporal normalization via `scaler.pkl`, and streams back complete attack forecasting metrics.

---

## 17. How to Verify the AI Forecasting Model

To verify that the PyTorch LSTM model and weights are functioning independently:

Run the standalone verification test:
```powershell
python scripts\verify_step3.py
```
Or directly invoke Python inference:
```powershell
python -c "from inference.forecast import ForecastEngine; engine = ForecastEngine(); import numpy as np; res = engine.forecast(np.zeros((30, 27))); print('Forecast Success:', res['predicted_stage'])"
```

Expected output:
```text
Loaded StandardScaler successfully.
Loaded LSTM World Model from: models\trained\world_model.pth
Forecast Success: Normal / Benign
```

---

## 18. Troubleshooting Common Errors

### Error: `Scapy_Exception: Sniffing and sending packets is not available at layer 2`
- **Cause:** Npcap is not installed, or PowerShell was not opened as Administrator.
- **Fix:** Install Npcap in WinPcap-compatible mode from [npcap.com](https://npcap.com/) and run `dev-local-capture.ps1` as Administrator.

### Error: `Port 8000 / 3000 / 8888 already in use`
- **Cause:** An existing instance of Uvicorn or Next.js is still running.
- **Fix (PowerShell):**
  ```powershell
  Get-Process -Name python, node -ErrorAction SilentlyContinue | Stop-Process -Force
  ```

### Error: `ModuleNotFoundError: No module named 'torch'`
- **Cause:** Python virtual environment is not activated or dependencies are not installed.
- **Fix:**
  ```powershell
  cd backend
  .\.venv\Scripts\activate
  pip install -r requirements.txt
  ```

### Error: `npm ERR! code ERESOLVE / peer dependency conflicts`
- **Fix:**
  ```powershell
  cd frontend
  npm install --legacy-peer-deps
  ```

### Error: `Execution of scripts is disabled on this system` (PowerShell)
- **Fix:** Run this once in PowerShell:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  ```
