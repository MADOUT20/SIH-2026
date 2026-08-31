import os
import sys
import time
import subprocess
import urllib.request
import ssl
import json
import webbrowser

def verify_and_launch():
    print("===================================================")
    print("      NETGUARD FULL SERVICE VERIFICATION            ")
    print("===================================================")

    # 1. Npcap Check
    res_sc = subprocess.run(["sc.exe", "query", "npcap"], capture_output=True, text=True)
    npcap_running = (res_sc.returncode == 0 and "RUNNING" in res_sc.stdout)
    print(f"  Npcap Kernel Driver: {'RUNNING' if npcap_running else 'NOT RUNNING'}")

    # 2. Backend Check
    backend_running = False
    try:
        with urllib.request.urlopen("http://localhost:8000/health", timeout=3) as resp:
            if resp.status == 200:
                backend_running = True
    except Exception:
        pass

    if not backend_running:
        print("  Starting Backend process (port 8000)...")
        backend_exe = os.path.abspath(r"d:\SIH-2026-demo\dist\NetGuard\backend\netguard-backend.exe")
        subprocess.Popen([backend_exe], cwd=os.path.dirname(backend_exe))
        time.sleep(3)
        try:
            with urllib.request.urlopen("http://localhost:8000/health", timeout=3) as resp:
                if resp.status == 200:
                    backend_running = True
        except Exception:
            pass

    print(f"  Backend Engine (Port 8000): {'RUNNING' if backend_running else 'NOT RUNNING'}")

    # 3. Frontend Check
    frontend_running = False
    try:
        with urllib.request.urlopen("http://localhost:3000/dashboard", timeout=3) as resp:
            if resp.status == 200:
                frontend_running = True
    except Exception:
        pass

    if not frontend_running:
        print("  Starting Frontend process (port 3000)...")
        frontend_js = os.path.abspath(r"d:\SIH-2026-demo\dist\NetGuard\frontend\server.js")
        subprocess.Popen(["node", frontend_js], cwd=os.path.dirname(frontend_js))
        time.sleep(3)
        try:
            with urllib.request.urlopen("http://localhost:3000/dashboard", timeout=3) as resp:
                if resp.status == 200:
                    frontend_running = True
        except Exception:
            pass

    print(f"  Frontend UI Server (Port 3000): {'RUNNING' if frontend_running else 'NOT RUNNING'}")

    # 4. HTTPS Gateway Check
    https_url = "https://localhost/"
    https_running = False
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen("https://localhost/health", context=ctx, timeout=3) as resp:
            if resp.status == 200:
                https_running = True
    except Exception:
        pass

    if not https_running:
        try:
            with urllib.request.urlopen("https://localhost:8443/health", context=ctx, timeout=3) as resp:
                if resp.status == 200:
                    https_running = True
                    https_url = "https://localhost:8443/"
        except Exception:
            pass

    if not https_running:
        print("  Starting HTTPS Gateway...")
        gateway_py = os.path.abspath(r"d:\SIH-2026-demo\scripts\https_gateway.py")
        subprocess.Popen([sys.executable, gateway_py], cwd=os.path.dirname(gateway_py))
        time.sleep(2)
        try:
            with urllib.request.urlopen("https://localhost/health", context=ctx, timeout=3) as resp:
                if resp.status == 200:
                    https_running = True
                    https_url = "https://localhost/"
        except Exception:
            pass

    print(f"  HTTPS Gateway: {'RUNNING (' + https_url + ')' if https_running else 'NOT RUNNING (Using http://localhost:3000/dashboard)'}")

    # 5. ML Model Check
    model_loaded = False
    try:
        with urllib.request.urlopen("http://localhost:8000/api/forecast/metrics", timeout=3) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if "lstm_world_model" in data or "num_features" in data:
                model_loaded = True
    except Exception:
        pass

    print(f"  PyTorch LSTM ML Model: {'LOADED' if model_loaded else 'NOT LOADED'}")

    target_url = https_url if https_running else "http://localhost:3000/dashboard"

    print("\n===================================================")
    print(f"  OPENING NETGUARD AT: {target_url}")
    print("===================================================")

    webbrowser.open(target_url)
    return True

if __name__ == "__main__":
    verify_and_launch()
