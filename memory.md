# Memory

Last updated: 2026-08-30 00:55:17

## Project

Network-level malware detection system with:
- `frontend/`: Next.js dashboard UI (now in workbench view)
- `backend/`: FastAPI API, packet capture, traffic analysis, threat detection, local proxy support
- `scripts/`: local setup/run helpers

## Current Repo State

- `backend/app/services/packet_capture.py` is fully completed. It captures packets with Scapy, normalizes packet fields, tracks packet statistics, and supports proxy-based observations.
- `backend/app/services/threat_detection.py` implements comprehensive threat detection, including optimized port scan detection, traffic spikes, watched malicious sites, suspicious DNS, beaconing, and data exfiltration.
- `frontend/app/page.tsx` has been converted to a workbench view for improved analysis and task-facing operation.
- `.gitignore` excludes local-only context files: `memory.md`, `ps.txt`, and `TASK FOR ME .png`.
- Docs present: `README.md`, `PROJECT_DOCUMENTATION.md`, `SYSTEM_HEALTH.md`, `OPTIMIZATION_COMPLETE.md`, `frontend/OPTIMIZATION.md`.

## Task Progress (from `TASK FOR ME .png`)

Assigned track: prepare data and explain the AI's decisions.

- Network packet capture: 100% (COMPLETED)
- Flow-level feature extraction: 20%
- Packet-level feature extraction: 40%
- Dataset preprocessing: 10%
- Model training pipeline: 0%
- Trained model + weights: 0%
- XAI / SHAP / attention: 0%

Required sequence from the task image:
1. Finish/stabilize packet capture. (DONE)
2. Group packets into flows.
3. Extract flow-level features.
4. Extract packet-level features.
5. Clean/normalize data.
6. Split and save train/test datasets.
7. Build the training pipeline.
8. Train and save model weights.
9. Add explainability (SHAP or attention-based).
10. Return explanations in simple JSON for frontend display.

## Immediate Interpretation

- The dashboard/backend infrastructure is stable.
- The ML dataset/training/explainability pipeline is the primary remaining gap.
- Highest priority is now the bridge from captured packets to ML-ready structured features and datasets (Flow-level and Packet-level extraction).

## Working Assumptions

- Packet capture is now reliable enough for data collection.
- Future work will implement new backend services for:
  - flow building
  - feature extraction
  - dataset preprocessing/export
  - training/inference
  - explanation generation

## Git Snapshot

- Current working branch: `DATAXAI`
- Key recent milestones:
  - Completed network packet capture.
  - Implemented optimized threat detection (including port scans).
  - Updated frontend to workbench view.
  - Cleaned project documentation.

## Next Best Steps

1. Implement logic to group captured packets into flows.
2. Develop flow-level feature extraction.
3. Develop packet-level feature extraction.
4. Implement dataset preprocessing and train/test split scripts.
5. Build the model training pipeline and save artifact handling.
6. Implement AI explainability (XAI) and integrate results into the frontend.
