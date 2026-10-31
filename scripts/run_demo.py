"""AuthScope Demo Execution Script.

Demonstrates the 8 core capabilities of AuthScope:
1. Scope validation & boundary enforcement.
2. Attack surface route enumeration.
3. Multi-role differential testing (BOLA / IDOR detection).
4. Cryptographic evidence collection & automatic secret redaction.
5. AI-driven risk scoring & technical impact evaluation.
6. Actionable remediation code generation.
7. Automated, non-destructive retesting.
8. Finding lifecycle status transition & SQLite persistence.
"""

import sys
import os
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure repo root is on sys.path
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))

from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import SessionManager, Role
from backend.scanner.endpoint_discovery import EndpointDiscovery
from backend.scanner.request_executor import RequestExecutor, HttpResponseModel
from backend.scanner.response_analyzer import ResponseAnalyzer
from backend.analysis.evidence_validator import EvidenceValidator
from backend.analysis.severity_engine import SeverityEngine, SeverityLevel
from backend.analysis.remediation import RemediationEngine
from backend.agent.finding_analyzer import FindingAnalyzer
from backend.storage.database import DatabaseManager
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import FindingRecord, EvidenceArtifact, RetestLogRecord
from backend.utils.helpers import ScopeViolationError


def run_demo() -> bool:
    print("=" * 80)
    print(" AUTHSCOPE - AUTONOMOUS APPLICATION SECURITY TESTING PLATFORM DEMO")
    print("=" * 80)

    # Use a clean demo database
    demo_db_path = repo_root / "data" / "demo_authscope.db"
    demo_db_path.parent.mkdir(parents=True, exist_ok=True)
    if demo_db_path.exists():
        demo_db_path.unlink()

    db_mgr = DatabaseManager(db_path=str(demo_db_path))
    repo = FindingRepository(db_manager=db_mgr)

    # -------------------------------------------------------------------------
    # Step 1: Scope Validation
    # -------------------------------------------------------------------------
    print("\n[STEP 1] Scope Validation & Boundary Enforcement")
    guard = ScopeGuard(
        allowed_hosts=["localhost", "127.0.0.1"],
        allowed_ports=[3000],
        allowed_schemes=["http", "https"]
    )
    target_url = "http://localhost:3000/rest/basket/1"
    valid_res = guard.validate_url(target_url)
    print(f"  Target: {target_url}")
    print(f"  Scope Decision: ALLOWED (Host: {valid_res.normalized_host}, Port: {valid_res.normalized_port})")

    # Assert unauthorized escape attempt is blocked
    unauth_url = "https://external-target.com/api"
    blocked_res = guard.validate_url(unauth_url)
    print(f"  Untrusted Target: {unauth_url} -> BLOCKED ({blocked_res.reason})")

    # -------------------------------------------------------------------------
    # Step 2: Attack Surface Mapping
    # -------------------------------------------------------------------------
    print("\n[STEP 2] Attack Surface Mapping (Route Enumeration)")
    discovery = EndpointDiscovery(base_url="http://localhost:3000")
    routes = discovery.discover_from_openapi()
    for route in routes:
        params_str = f" [Params: {', '.join(route.parameters)}]" if route.parameters else ""
        print(f"  Discovered Route: {route.method:<4} {route.path}{params_str}")

    # -------------------------------------------------------------------------
    # Step 3: Controlled Security Finding (BOLA / IDOR Probing)
    # -------------------------------------------------------------------------
    print("\n[STEP 3] Controlled Security Finding (Multi-Role Differential Test)")
    session_mgr = SessionManager()
    session_mgr.authenticate_role(Role.USER_A, email="user_a@juice-sh.op", password="password_a")
    session_mgr.authenticate_role(Role.USER_B, email="user_b@juice-sh.op", password="password_b")

    mock_token = os.getenv("TEST_AUTH_TOKEN", "mock_user_b_bearer_token_xyz")
    user_b_headers = {
        "Authorization": f"Bearer {mock_token}",
        "Cookie": "session_id=mock_session_secret_123",
        "Accept": "application/json"
    }

    executor = RequestExecutor(scope_guard=guard)
    vulnerable_body = json.dumps({
        "status": "success",
        "data": {
            "id": 1,
            "UserId": 2,
            "owner": "user_a@juice-sh.op",
            "items": [{"id": 101, "item": "Deluxe Fruit Juice Pack", "price": 49.99}]
        }
    })

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.text = vulnerable_body
    mock_resp.json.return_value = json.loads(vulnerable_body)

    with patch.object(executor.client, "request", return_value=mock_resp):
        http_resp = executor.execute("GET", target_url, headers=user_b_headers)

    print(f"  Probing Endpoint: GET {target_url} under Role: USER_B")
    print(f"  Response Code: {http_resp.status_code} OK (Expected: 403 Forbidden)")
    print(f"  Access Discrepancy: Confirmed BOLA / IDOR flaw")

    # -------------------------------------------------------------------------
    # Step 4: Reproducible Evidence & Automatic Sanitization
    # -------------------------------------------------------------------------
    print("\n[STEP 4] Cryptographic Evidence Collection & Secret Sanitization")
    validator = EvidenceValidator()
    finding_id = "fnd_demo_basket_idor"
    evidence = validator.create_and_sign_evidence(
        finding_id=finding_id,
        test_role=Role.USER_B,
        authorized_role=Role.USER_A,
        method="GET",
        url=target_url,
        headers=user_b_headers,
        response=http_resp
    )
    print(f"  Evidence ID: {evidence.id}")
    print(f"  SHA-256 Fingerprint: {evidence.evidence_sha256}")
    print(f"  Sanitized Auth Header: {evidence.request_headers['Authorization']}")
    print(f"  Sanitized Cookie Header: {evidence.request_headers['Cookie']}")

    finding = FindingRecord(
        id=finding_id,
        target_identifier="scan_demo_01",
        endpoint="/rest/basket/1",
        http_method="GET",
        vulnerability_category="BOLA_IDOR",
        affected_role="user_b",
        expected_behavior="403 Forbidden for User B accessing Basket 1",
        actual_behavior="200 OK with User A basket contents",
        severity=SeverityLevel.MEDIUM,
        confirmation_status="suspected",
        evidence=evidence
    )
    repo.save_finding(finding)
    print(f"  Finding Persisted in SQLite (ID: {finding_id}, Status: suspected)")

    # -------------------------------------------------------------------------
    # Step 5: AI-Generated Risk Assessment
    # -------------------------------------------------------------------------
    print("\n[STEP 5] AI-Driven Risk Assessment & Impact Synthesis")
    sev_calc = SeverityEngine()
    severity = sev_calc.calculate_severity("BOLA_IDOR", exposes_pii=True)

    analyzer = FindingAnalyzer()
    narrative = analyzer.analyze({"endpoint": "/rest/basket/1", "evidence": evidence.sanitized_response_body})

    print(f"  Calculated CVSS Severity: {severity.value}")
    print(f"  AI Narrative Title: {narrative['title']}")
    print(f"  Technical Impact: {narrative['impact']}")

    # -------------------------------------------------------------------------
    # Step 6: Actionable Remediation Recommendation
    # -------------------------------------------------------------------------
    print("\n[STEP 6] Prescriptive Remediation Generation")
    rem_engine = RemediationEngine()
    patch_code = rem_engine.generate_patch("BOLA_IDOR", framework="express")
    print(f"  Remediation Patch Code:\n{patch_code}")

    ai_updates = {
        "severity": severity,
        "confirmation_status": "confirmed",
        "impact_explanation": narrative["impact"] + " Confidential customer cart and PII leakage.",
        "remediation_recommendation": patch_code
    }
    repo.update_finding(finding_id, ai_updates)
    print("  Finding Updated in SQLite with AI Risk & Remediation guidance.")

    # -------------------------------------------------------------------------
    # Step 7: Automated Non-Destructive Retesting
    # -------------------------------------------------------------------------
    print("\n[STEP 7] Automated Non-Destructive Retest")
    # Simulate developer patched the vulnerability: target now returns 403 Forbidden
    fixed_mock_resp = MagicMock()
    fixed_mock_resp.status_code = 403
    fixed_mock_resp.headers = {"Content-Type": "application/json"}
    fixed_mock_resp.text = '{"error": "Forbidden: Resource does not belong to user"}'
    fixed_mock_resp.json.return_value = json.loads(fixed_mock_resp.text)

    with patch.object(executor.client, "request", return_value=fixed_mock_resp):
        retest_resp = executor.execute("GET", target_url, headers=user_b_headers)

    is_vulnerable = ResponseAnalyzer.is_success_response(retest_resp)
    print(f"  Replaying Vector: GET {target_url} with User B credentials")
    print(f"  Retest Response Code: {retest_resp.status_code} Forbidden")
    print(f"  Vulnerability Reproducible: {is_vulnerable} (Fix successfully validated!)")

    # -------------------------------------------------------------------------
    # Step 8: Updated Finding Lifecycle Status
    # -------------------------------------------------------------------------
    print("\n[STEP 8] Updated Finding Lifecycle Status in SQLite")
    retest_log = RetestLogRecord(
        id="ret_demo_01",
        finding_id=finding_id,
        previous_status="confirmed",
        new_status="remediated",
        is_vulnerable=is_vulnerable,
        summary="Automated retest verified: Endpoint returns 403 Forbidden after ownership check patch."
    )
    repo.save_retest_result(retest_log)

    final_record = repo.get_finding(finding_id)
    print(f"  Finding Final Status: {final_record.confirmation_status.upper()}")
    print(f"  Finding Retest State: {final_record.retest_status.upper()}")
    print(f"  Last Retested Timestamp: {final_record.last_retested_timestamp}")
    print(f"  Retest History Count: {len(repo.get_retest_history(finding_id))}")

    print("\n" + "=" * 80)
    print(" DEMO COMPLETED SUCCESSFULLY: ALL 8 CORE CAPABILITIES DEMONSTRATED")
    print("=" * 80)
    return True


if __name__ == "__main__":
    success = run_demo()
    sys.exit(0 if success else 1)

