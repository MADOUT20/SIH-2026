# Project Documentation

**Project:** Network Security Dashboard  
**Reviewed Against Repository:** August 28, 2026

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Quick Start](#quick-start)
3. [Folder Descriptions](#folder-descriptions)
4. [API Endpoints](#api-endpoints)
5. [Environment Variables](#environment-variables)
6. [Technology Stack](#technology-stack)
7. [Commands](#commands)

---

## Project Structure

```text
project-root/
├── frontend/                 # Next.js dashboard and landing page
│   ├── app/                  # Route entry points
│   ├── components/           # Dashboard and reusable UI components
│   ├── hooks/                # Frontend hooks
│   ├── lib/                  # API client and utilities
│   └── package.json
├── backend/                  # FastAPI backend
│   ├── app/
│   │   ├── main.py           # FastAPI bootstrap and router registration
│   │   ├── api/              # Consolidated route definitions
│   │   ├── models/           # Shared schema definitions
│   │   ├── services/         # Packet capture, threat detection, traffic analysis, proxy
│   │   └── utils/            # Helper utilities
│   ├── requirements.txt
│   └── requirements-dev.txt
├── scripts/                  # Local setup and run helpers
├── deploy/                   # Deployment-related config
└── README.md
```

---

## Quick Start

### Local Development

**Recommended setup:**
```bash
./scripts/setup-local.sh
./scripts/dev-local.sh
```

This starts:
- Frontend: `http://localhost:3000`
- Backend: `http://localhost:8000`

**Packet capture mode on Windows:**
```powershell
.\scripts\dev-local-capture.ps1
```

**Manual backend run:**
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

**Manual frontend run:**
```bash
cd frontend
pnpm install
pnpm dev
```

---

## Folder Descriptions

### Frontend (`/frontend`)

- `app/` - Route entry points for the landing page and dashboard
- `components/dashboard/` - Dashboard panels for traffic, threats, alerts, and admin views
- `components/ui/` - Reusable Shadcn/Radix-based UI components
- `hooks/` - Frontend hooks such as toast and mobile helpers
- `lib/` - API client and shared utilities

### Backend (`/backend`)

- `app/main.py` - App bootstrap, CORS setup, startup/shutdown hooks, router registration
- `app/api/routes.py` - Consolidated API routes for traffic, threats, packets, admin, notifications, health, and users
- `app/models/` - Pydantic schema definitions
- `app/services/packet_capture.py` - Scapy-based packet capture and packet normalization
- `app/services/threat_detection.py` - Threat detection, threat hunting, watchlist matching, and response logic
- `app/services/traffic_analysis.py` - Traffic summaries and protocol/application analysis
- `app/services/mobile_proxy.py` - Local HTTP/HTTPS proxy for mobile testing
- `app/utils/` - Backend helper utilities

---

## API Endpoints

### Health

```text
GET /health
```

### Traffic

```text
GET /api/traffic
GET /api/traffic/by-protocol
GET /api/traffic/by-port
GET /api/traffic/by-application
GET /api/traffic/connections
GET /api/traffic/bandwidth-prediction
GET /api/traffic/history
```

### Threats

```text
GET  /api/threats
GET  /api/threats/hunt
GET  /api/threats/{threat_id}/intelligence
POST /api/threats/analyze
POST /api/threats/{threat_id}/respond
```

### Packets

```text
GET  /api/packets
GET  /api/packets/interfaces
GET  /api/packets/statistics
POST /api/packets/filter
POST /api/packets/analyze
POST /api/packets/capture/start
POST /api/packets/capture/stop
```

### Admin

```text
GET    /api/admin/dashboard
GET    /api/admin/settings
PUT    /api/admin/settings
GET    /api/admin/threats-summary
GET    /api/admin/traffic-summary
GET    /api/admin/proxy-status
GET    /api/admin/blocked-sites
DELETE /api/admin/blocked-sites
DELETE /api/admin/blocked-sites/{domain}
```

### Notifications

```text
GET    /api/notifications
POST   /api/notifications/{notif_id}/read
DELETE /api/notifications/{notif_id}
```

### Users

```text
GET    /api/users
POST   /api/users
DELETE /api/users/{user_id}
```

---

## Environment Variables

### Frontend (`frontend/.env.local`)

```bash
BACKEND_API_URL=http://localhost:8000
NEXT_PUBLIC_API_URL=http://localhost:8000
```

### Backend (`backend/.env`)

```bash
ALLOWED_ORIGINS=http://localhost:3000
BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
ENVIRONMENT=development
KNOWN_MALICIOUS_DOMAINS=
KNOWN_MALICIOUS_IPS=
```

### Optional Proxy Settings

```bash
PROXY_ENABLED=1
PROXY_HOST=0.0.0.0
PROXY_PORT=8888
CAPTURE_INTERFACE=
```

---

## Technology Stack

| Component | Tech |
|-----------|------|
| Frontend | Next.js 16, React 19, TypeScript, Tailwind CSS |
| UI Library | Shadcn/UI, Radix UI |
| Backend | FastAPI, Python 3.11, Uvicorn |
| Packet Capture | Scapy |
| Deployment Assets | Vercel frontend, Nginx config in `deploy/nginx/` |

---

## Commands

```bash
# Project setup
./scripts/setup-local.sh

# Start frontend and backend locally
./scripts/dev-local.sh

# Check whether local dependencies are ready
./scripts/dev-local.sh --check

# Start capture mode
./scripts/dev-local-capture.sh

# Frontend
cd frontend
pnpm dev
pnpm build
pnpm lint

# Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
python -m pytest
```

---

Interactive backend docs are available at `http://localhost:8000/docs` when the API is running.
