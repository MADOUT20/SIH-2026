import os
import sys

# PyInstaller frozen runtime DLL path setup - MUST RUN BEFORE ANY OTHER IMPORTS
if getattr(sys, "frozen", False):
    bundle_dir = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    sys.path.insert(0, bundle_dir)
    sys.path.insert(0, os.path.join(bundle_dir, "backend"))
    
    torch_lib = os.path.join(bundle_dir, "torch", "lib")
    if os.path.exists(torch_lib):
        os.environ["PATH"] = torch_lib + os.pathsep + bundle_dir + os.pathsep + os.environ.get("PATH", "")
        if hasattr(os, "add_dll_directory"):
            try:
                os.add_dll_directory(torch_lib)
            except Exception:
                pass
            try:
                os.add_dll_directory(bundle_dir)
            except Exception:
                pass
else:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.join(base_dir, "backend"))
    sys.path.insert(0, base_dir)

import uvicorn
from app.main import app

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")

