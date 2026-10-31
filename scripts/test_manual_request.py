"""Manual test utility for verifying RequestExecutor and ScopeGuard against localhost:3000."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.scanner.request_executor import send_request
from backend.core.session_manager import Role
from backend.utils.helpers import ScopeViolationError, TargetUnreachableError


def main():
    print("=" * 65)
    print("       AuthScope — Manual Request Executor Verification")
    print("=" * 65)

    target_url = "http://localhost:3000/rest/admin/application-version"
    print(f"[*] Probing authorized in-scope endpoint: {target_url}")

    try:
        response = send_request(
            role=Role.ANONYMOUS,
            method="GET",
            url=target_url
        )
        print(f"[+] Success! Status: {response.status_code}")
        print(f"[+] Latency: {response.response_time_ms:.2f} ms")
        print(f"[+] Content-Length: {response.content_length} bytes")
        print(f"[+] Body preview: {response.body[:200]}")
        print(f"[+] Request Metadata: {response.request_metadata}")
    except TargetUnreachableError as exc:
        print(f"[!] Target unreachable (Ensure OWASP Juice Shop is running on :3000): {exc}")
    except Exception as exc:
        print(f"[!] Unexpected error during in-scope request: {exc}")

    print("\n[*] Testing ScopeGuard enforcement against out-of-scope target...")
    out_of_scope_url = "https://example.com/sensitive-data"
    try:
        send_request(
            role=Role.ANONYMOUS,
            method="GET",
            url=out_of_scope_url
        )
        print("[!] ERROR: ScopeGuard failed to block out-of-scope target!")
    except ScopeViolationError as exc:
        print(f"[+] SUCCESS: ScopeGuard blocked out-of-scope target as expected: {exc}")

    print("=" * 65)


if __name__ == "__main__":
    main()
