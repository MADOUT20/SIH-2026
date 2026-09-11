# NetGuard Offline AI Attack Forecaster 🛡️

NetGuard is a professional-grade, fully offline AI-powered CLI tool designed to forecast network attacks. It leverages a Temporal World Model (LSTM) to analyze network traffic (PCAP, CSV, Parquet) and predict the probability of an ongoing or imminent attack, identifying the MITRE ATT&CK stage and the contributing network features.

## 🚀 Features

- **Multi-Horizon Forecasting**: Predicts attack probability for the current state and the next 5 temporal steps.
- **MITRE ATT&CK Mapping**: Classifies threats into stages (e.g., Initial Access, Privilege Escalation, C2, Impact).
- **Explainable AI (XAI)**: Provides feature attribution using gradient-based analysis to show *why* the AI flagged a specific traffic pattern.
- **Fully Offline**: No data leaves your machine. All inference is done locally using PyTorch.
- **Flexible Input**: Supports `.pcap`, `.pcapng`, `.csv`, and `.parquet` files.

## 🛠️ Installation

### Option 1: Quick Install (Linux/macOS)
Run the following command to install NetGuard globally:
\`\`\`bash
curl -sSL https://raw.githubusercontent.com/MADOUT20/SIH-2026/main/NetGuard-Offline-CLI/install_netguard.sh | bash
\`\`\`

### Option 2: Manual Installation
1. Clone the repository:
   \`\`\`bash
   git clone https://github.com/MADOUT20/SIH-2026.git
   cd SIH-2026/NetGuard-Offline-CLI
   \`\`\`
2. Run the global setup script:
   \`\`\`bash
   chmod +x setup_global.sh
   ./setup_global.sh
   \`\`\`

## 💻 Usage

Once installed, you can run the tool from any directory using the `netguard` command:

### Try the Demo (Fastest way to test)
Run the tool using bundled sample data to see the AI in action immediately:
\`\`\`bash
netguard --demo
\`\`\`

### Analyze Your Own Data
\`\`\`bash
netguard --file /path/to/your/traffic.pcap
\`\`\`

### Arguments:
- `--demo`: (Optional) Run the tool using built-in sample datasets.
- `--file`: (Required if not using --demo) Path to the network traffic file to analyze.

## 📊 How it Works

1. **Feature Extraction**: The tool parses network flows and extracts 27 canonical features (packet lengths, IAT, flags, etc.).
2. **Temporal Windowing**: It creates a temporal window of the last 30 states to capture the sequence of the attack.
3. **LSTM Inference**: A pre-trained LSTM World Model processes the sequence to output:
   - Current attack probability.
   - A forecast timeline for the next 5 steps.
   - The predicted MITRE ATT&CK stage.
4. **Feature Attribution**: The engine computes gradients of the output with respect to the input to identify the most impactful network features.

## 📂 Project Structure

- `main.py`: CLI Entry point and orchestration.
- `launch.py`: Dependency checker and app launcher.
- `core/`:
    - `engine.py`: AI Inference engine and XAI logic.
    - `model.py`: LSTM World Model architecture.
    - `pcap_parser.py`: Scapy-based flow extraction.
    - `csv_parser.py`: Canonical feature mapping for CSV/Parquet.
- `assets/`: Pre-trained model weights (`world_model.pth`), scaler (`scaler.pkl`), and config.
- `install_netguard.sh`: One-line installer script.
