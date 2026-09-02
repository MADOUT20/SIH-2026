import os
import sys

def main():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    sys.path.insert(0, os.path.join(root_dir, "scripts"))
    try:
        import create_rsa_cert
        create_rsa_cert.generate_cert()
        return True
    except Exception as e:
        print("Error generating cert:", e)
        return False

if __name__ == "__main__":
    main()
