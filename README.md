# NetGuard

Next-Generation Cyber Threat Defense, Packet Capture & Temporal Attack Forecasting Platform.

## Requirements

- **Python**: 3.10, 3.11, or 3.12 (64-bit recommended)
- **Node.js**: v18+ (Node 20+ recommended) with `npm`
- **Npcap** (Windows only): Required for Live packet capture (download from https://npcap.com/). Install with "WinPcap API-compatible Mode" enabled.

## Installation

### Automated (Recommended)

On Windows (PowerShell):
```powershell
.\scripts\setup-local.ps1
```

On Linux / macOS (Bash):
```bash
./scripts/setup-local.sh
```

---

### Manual Setup

#### Backend
```bash
cd backend
python -m venv .venv

# Windows
.\.venv\Scripts\activate
# Linux/macOS
# source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

#### Frontend
```bash
cd frontend
npm install
```

## Run

### 1-Click Launch (Windows)
Double-click `start-all.bat` or run:
```cmd
start-all.bat
```

### Manual Startup

#### 1. Start Backend
```bash
cd backend
# Windows:
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
# Linux/macOS:
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
- API Docs: http://localhost:8000/docs
- Health Check: http://localhost:8000/api/health

#### 2. Start Frontend
```bash
cd frontend
npm run dev
```
- Web Application: http://localhost:3000

## Demo Mode

NetGuard includes a rich Demo Mode that works out-of-the-box on any system with zero network permissions needed:
- Pre-simulated live network telemetry and interactive attack scenarios
- Pre-loaded LSTM Neural Network World Model for multi-step attack forecasting
- Interactive MITRE ATT&CK Matrix mapping with risk scoring
- Dynamic Network Topology map with simulated compromised endpoints
- Website & URL vulnerability scanner
- Offline Workbench: drag-and-drop PCAP or CSV files for instant threat classification (sample files in `data/samples/`)

## Live Mode

Live Mode captures real-time network packets from your local interface:
- **Windows**: Requires Administrator privileges and Npcap installed. Run:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\dev-local-capture.ps1
  ```
- **Packet Sniffing**: Uses Scapy to analyze Ethernet/IP packets, track bidirectional flows, and detect threats in real-time.
- **Device Discovery**: Active/Passive ARP scan discovers devices on the local subnet.

## Troubleshooting

- **Live capture permission error**: On Windows, run PowerShell or the terminal as Administrator with Npcap installed.
- **Port 8000/3000 in use**: Check and terminate any existing process using `netstat -ano | findstr :8000` or adjust ports in `.env`.
- **Torch / Scikit-learn imports**: Ensure your virtual environment uses Python 3.10-3.12 and dependencies are installed via `pip install -r backend/requirements.txt`.
