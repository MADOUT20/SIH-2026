import os
import sys
import time
import subprocess
import urllib.request
import ssl
import webbrowser

def launch_production():
    print("===================================================")
    print("      NETGUARD PRODUCTION APP LAUNCHER             ")
    print("===================================================")

    dist_dir = os.path.abspath(r"d:\SIH-2026-demo\dist\NetGuard")
    backend_exe = os.path.join(dist_dir, "backend", "netguard-backend.exe")
    frontend_js = os.path.join(dist_dir, "frontend", "server.js")
    gateway_py = os.path.join(dist_dir, "scripts", "https_gateway.py")

    print("\n[1] STARTING PRODUCTION BACKEND (Port 8000)...")
    b_env = os.environ.copy()
    b_env["PORT"] = "8000"
    backend_proc = subprocess.Popen([backend_exe], cwd=os.path.dirname(backend_exe), env=b_env)

    b_ready = False
    for i in range(15):
        time.sleep(1)
        try:
            with urllib.request.urlopen("http://localhost:8000/health", timeout=2) as resp:
                if resp.status == 200:
                    print("  [PASS] Backend Engine is HEALTHY (Port 8000)!")
                    b_ready = True
                    break
        except Exception:
            pass

    if not b_ready:
        print("FAIL: Backend failed to respond.")
        return False

    print("\n[2] STARTING PRODUCTION FRONTEND (Port 3000)...")
    f_env = os.environ.copy()
    f_env["PORT"] = "3000"
    f_env["HOSTNAME"] = "0.0.0.0"
    frontend_proc = subprocess.Popen(["node", frontend_js], cwd=os.path.dirname(frontend_js), env=f_env)

    f_ready = False
    for i in range(12):
        time.sleep(1)
        try:
            with urllib.request.urlopen("http://localhost:3000/dashboard", timeout=2) as resp:
                if resp.status == 200:
                    print("  [PASS] Frontend Server is READY (Port 3000)!")
                    f_ready = True
                    break
        except Exception:
            pass

    print("\n[3] STARTING UNIFIED HTTPS GATEWAY (Port 443)...")
    g_env = os.environ.copy()
    g_env["HTTPS_PORT"] = "443"
    gateway_proc = subprocess.Popen([sys.executable, gateway_py], cwd=dist_dir, env=g_env)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    g_ready = False
    for i in range(10):
        time.sleep(1)
        try:
            with urllib.request.urlopen("https://localhost/health", context=ctx, timeout=2) as resp:
                if resp.status == 200:
                    print("  [PASS] Unified HTTPS Gateway is LIVE (Port 443)!")
                    g_ready = True
                    break
        except Exception:
            pass

    if not g_ready:
        print("  HTTPS Gateway binding port 443 attempt, trying port 8443 if 443 requires Admin...")
        g_env["HTTPS_PORT"] = "8443"
        gateway_proc = subprocess.Popen([sys.executable, gateway_py], cwd=dist_dir, env=g_env)
        time.sleep(2)

    print("\n===================================================")
    print("  OPENING NETGUARD DASHBOARD IN YOUR BROWSER...    ")
    print("  URL: https://localhost/                          ")
    print("===================================================")
    webbrowser.open("https://localhost/")

    print("\nNetGuard application is currently RUNNING for your manual testing.")
    print("Keep this process open while you perform manual browser testing.")
    return True

if __name__ == "__main__":
    launch_production()
