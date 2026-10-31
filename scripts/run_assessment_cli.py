"""CLI runner to execute a full 7-stage AuthScope assessment against localhost:3000."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.core.assessment_engine import AssessmentEngine
from backend.storage.finding_repository import FindingRepository
from backend.storage.database import DatabaseManager


def main():
    print("=" * 70)
    print("   AuthScope — Autonomous Penetration Testing & Assessment Runner")
    print("=" * 70)

    db = DatabaseManager()
    repo = FindingRepository(db_manager=db)
    engine = AssessmentEngine(repository=repo)

    target_url = "http://localhost:3000"
    print(f"[*] Target Application: {target_url} (OWASP Juice Shop)")
    print("[*] Initiating 7-Stage Differential Security Audit...\n")

    event_count = 0
    try:
        gen = engine.stream_assessment(target_url=target_url)
        for event in gen:
            event_count += 1
            stage_name = event.stage.name if hasattr(event.stage, "name") else str(event.stage)
            event_type = event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)
            print(f"[{stage_name:<20}] [{event_type:<24}] {event.message}")

    except Exception as exc:
        print(f"\n[!] Scan completed or stopped: {exc}")

    # Summary
    findings = repo.list_findings()
    sessions = repo.list_scan_sessions()
    print("\n" + "=" * 70)
    print("                          ASSESSMENT SUMMARY")
    print("=" * 70)
    print(f"[+] Total Scan Sessions Recorded: {len(sessions)}")
    print(f"[+] Total Confirmed Findings:     {len(findings)}")
    for f in findings:
        print(f"    - [{f.severity:<8}] {f.title:<40} ({f.http_method} {f.target_endpoint})")
    print("=" * 70)


if __name__ == "__main__":
    main()

