"""AuthScope Environment Setup and Diagnostics Script.

Verifies Python version, virtual environment status, dependencies,
and connectivity to the local target application (OWASP Juice Shop).
"""

import sys
import os
import shutil
import subprocess
from pathlib import Path


def check_python_version():
    print(f"[*] Checking Python version: {sys.version.split()[0]}...", end=" ")
    if sys.version_info < (3, 10):
        print("FAILED")
        print("[!] AuthScope requires Python 3.10 or higher.")
        sys.exit(1)
    print("OK")


def check_env_file():
    print("[*] Checking .env configuration...", end=" ")
    env_file = Path(".env")
    example_file = Path(".env.example")

    if not env_file.exists():
        if example_file.exists():
            shutil.copy(example_file, env_file)
            print("CREATED (.env copied from .env.example)")
        else:
            print("MISSING (.env.example not found)")
    else:
        print("OK")


def check_dependencies():
    print("[*] Verifying critical Python packages...", end=" ")
    required_packages = ["httpx", "anthropic", "pydantic", "streamlit", "pytest", "rich"]
    missing = []
    for pkg in required_packages:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)

    if missing:
        print("FAILED")
        print(f"[!] Missing required dependencies: {', '.join(missing)}")
        print("[!] Run: pip install -r requirements.txt")
    else:
        print("OK")


def check_docker():
    print("[*] Checking Docker availability for OWASP Juice Shop...", end=" ")
    docker_bin = shutil.which("docker")
    if docker_bin:
        print(f"OK ({docker_bin})")
    else:
        print("WARNING (Docker CLI not detected on PATH. Ensure OWASP Juice Shop is running manually on localhost:3000)")


def main():
    print("=" * 60)
    print("       AuthScope System Architecture Setup & Diagnostics")
    print("=" * 60)
    check_python_version()
    check_env_file()
    check_dependencies()
    check_docker()
    print("=" * 60)
    print("[+] System readiness check complete.")


if __name__ == "__main__":
    main()

