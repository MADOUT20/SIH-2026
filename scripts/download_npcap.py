import os
import urllib.request

def download_npcap():
    url = "https://npcap.com/dist/npcap-1.88.exe"
    target_path = os.path.abspath(r"d:\SIH-2026-demo\npcap-1.88.exe")

    print(f"Downloading official Npcap installer from {url}...")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    req = urllib.request.Request(url, headers=headers)

    with urllib.request.urlopen(req, timeout=30) as resp, open(target_path, "wb") as f:
        data = resp.read()
        f.write(data)
        print(f"Downloaded Npcap 1.88 installer successfully ({len(data)} bytes) to {target_path}")

if __name__ == "__main__":
    download_npcap()
