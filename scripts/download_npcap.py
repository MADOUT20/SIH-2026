import os
import urllib.request

def download_npcap():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_path = os.path.join(repo_root, "npcap-1.88.exe")

    print(f"Downloading official Npcap installer from {url}...")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    req = urllib.request.Request(url, headers=headers)

    with urllib.request.urlopen(req, timeout=30) as resp, open(target_path, "wb") as f:
        data = resp.read()
        f.write(data)
        print(f"Downloaded Npcap 1.88 installer successfully ({len(data)} bytes) to {target_path}")

if __name__ == "__main__":
    download_npcap()
