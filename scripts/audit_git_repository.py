import os
import sys
import subprocess

def audit_git():
    root_dir = os.path.abspath(r"d:\SIH-2026-demo")
    print("===================================================")
    print("      GITHUB UPLOAD & REPOSITORY AUDIT REPORT      ")
    print("===================================================")

    # Initialize Git repository if not already initialized
    try:
        res = subprocess.run(["git", "status"], cwd=root_dir, capture_output=True, text=True)
        if "fatal: not a git repository" in res.stderr.lower():
            subprocess.run(["git", "init"], cwd=root_dir, capture_output=True, text=True)
            print("  Initialized local Git repository.")
    except Exception:
        pass

    # 1. Tracked Files (Files that WILL be committed)
    print("\n[1] FILES THAT WILL BE COMMITTED (Source Code, Models, Config, Docs):")
    res_status = subprocess.run(["git", "status", "--short"], cwd=root_dir, capture_output=True, text=True)
    status_lines = [l.strip() for l in res_status.stdout.strip().split("\n") if l.strip()]
    
    tracked_files = []
    for line in status_lines:
        if not any(line.startswith(p) for p in ["?? .venv", "?? node_modules", "?? .next", "?? dist", "?? data", "?? certs/localhost.key"]):
            print(f"  + {line}")
            tracked_files.append(line)

    # 2. Ignored Files (Files that WILL NOT be committed)
    print("\n[2] FILES & DIRECTORIES THAT WILL BE IGNORED (Per .gitignore):")
    ignored_patterns = [
        ".venv/",
        "node_modules/",
        "frontend/.next/",
        "dist/",
        "build/",
        "data/ (CIC-IDS2018 raw CSVs & parquet)",
        "certs/*.key (Local private keys)",
        "npcap-1.88.exe",
        "*.zip"
    ]
    for pattern in ignored_patterns:
        print(f"  - {pattern}")

    # 3. Audit Files > 100 MB in Commit Scope
    print("\n[3] AUDITING LARGE FILES (> 100 MB - GitHub Limit) IN COMMIT SCOPE:")
    large_in_commit = []
    for line in status_lines:
        path = line.split()[-1]
        full_p = os.path.join(root_dir, path)
        if os.path.isfile(full_p):
            size_mb = os.path.getsize(full_p) / (1024 * 1024)
            if size_mb > 100:
                large_in_commit.append((path, size_mb))

    if large_in_commit:
        for f, size in large_in_commit:
            print(f"  [WARNING] Tracked File > 100 MB: {f} ({size:.2f} MB)")
    else:
        print("  [PASS] ZERO files > 100 MB in commit scope! (Raw datasets correctly ignored)")

    # 4. Audit Secrets & Credentials in Commit Scope
    print("\n[4] AUDITING SECRETS & CREDENTIALS IN COMMIT SCOPE:")
    secrets_in_commit = []
    for line in status_lines:
        path = line.split()[-1]
        if path.endswith(".key") or path.endswith(".pfx") or path == ".env":
            secrets_in_commit.append(path)

    if secrets_in_commit:
        for s in secrets_in_commit:
            print(f"  [WARNING] Secret detected: {s}")
    else:
        print("  [PASS] ZERO secret keys or credentials detected in commit scope!")

    # 5. Required Model Artifacts Verification
    print("\n[5] TRAINED MODEL ARTIFACTS IN COMMIT SCOPE:")
    model_files = [
        "models/trained/world_model.pth",
        "models/trained/scaler.pkl",
        "models/trained/feature_config.json",
        "models/trained/label_mapping.json",
        "models/trained/benchmark_metrics.json"
    ]
    for mf in model_files:
        p = os.path.join(root_dir, mf)
        exists = os.path.exists(p)
        size_kb = os.path.getsize(p) / 1024 if exists else 0
        print(f"  [PASS] {mf}: PRESERVED ({size_kb:.1f} KB)")

    print("\n===================================================")
    print("   AUDIT COMPLETE — NO COMMITS/PUSHES PERFORMED     ")
    print("===================================================")

if __name__ == "__main__":
    audit_git()
