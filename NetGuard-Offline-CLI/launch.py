#!/usr/bin/env python3
import subprocess
import sys
import os
import importlib.util

def check_and_install_dependencies():
    """Checks if required libraries are installed; if not, installs them automatically."""
    requirements = ["torch", "numpy", "pandas", "scapy", "joblib"]
    missing = []

    for lib in requirements:
        if importlib.util.find_spec(lib) is None:
            missing.append(lib)

    if missing:
        print(f"[*] First-time setup: Installing missing dependencies ({', '.join(missing)})...")
        try:
            # Use sys.executable to ensure we use the same python environment
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
            print("[+] Dependencies installed successfully.\n")
        except subprocess.CalledProcessError as e:
            print(f"Error: Failed to install dependencies. {e}")
            sys.exit(1)

def main():
    # 1. Auto-setup dependencies
    check_and_install_dependencies()

    # 2. Import main logic after dependencies are guaranteed to be there
    try:
        from main import main as run_analysis
    except ImportError as e:
        print(f"Error: Could not load the analysis engine. {e}")
        sys.exit(1)

    # 3. Pass arguments to the analysis engine
    # We keep sys.argv so the user can pass --file path/to/file
    run_analysis()

if __name__ == "__main__":
    main()
