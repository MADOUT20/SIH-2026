import time
import subprocess

def check_npcap():
    print("Checking for Npcap service status...")
    for attempt in range(1, 31):
        res = subprocess.run(["sc.exe", "query", "npcap"], capture_output=True, text=True)
        if res.returncode == 0:
            print(f"\n[PASS] Npcap Service Detected! Output:\n{res.stdout}")
            return True
        print(f"Attempt {attempt}/30: Waiting for Npcap installation... (service 1060)")
        time.sleep(2)
    
    print("\n[BLOCKED] Npcap service is not installed yet.")
    return False

if __name__ == "__main__":
    check_npcap()
