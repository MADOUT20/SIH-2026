import os
import sys
import time
import zipfile

def main():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    dist_dir = os.path.join(root_dir, "dist", "NetGuard")
    zip_path = os.path.join(root_dir, "dist", "NetGuard-v1.0.0-Windows-x64.zip")

    print(f"Creating production ZIP archive from {dist_dir} -> {zip_path}")
    if not os.path.exists(dist_dir):
        print(f"ERROR: {dist_dir} does not exist!")
        sys.exit(1)

    if os.path.exists(zip_path):
        os.remove(zip_path)

    start_time = time.time()
    file_count = 0
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(dist_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, dist_dir)
                zipf.write(full_path, arcname=os.path.join("NetGuard", rel_path))
                file_count += 1

    elapsed = time.time() - start_time
    size_bytes = os.path.getsize(zip_path)
    size_mb = round(size_bytes / (1024 * 1024), 2)
    print(f"SUCCESS: Archived {file_count} files in {elapsed:.2f} seconds.")
    print(f"Installer Archive Path: {zip_path}")
    print(f"Archive Size: {size_mb} MB ({size_bytes} bytes)")

if __name__ == "__main__":
    main()
