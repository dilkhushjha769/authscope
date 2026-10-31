"""Comprehensive unit and boundary test suite for the Source Code Analysis Engine (Phase 5.1).

Covers all mandatory requirements:
1. Python vulnerable code detection.
2. Python safe code (false-positive prevention).
3. JavaScript vulnerable code detection.
4. TypeScript vulnerable code detection & safe TypeScript code.
5. SQL Injection patterns (Python AST & JS/TS structural).
6. Cross-Site Scripting (XSS) patterns (Python AST & JS/TS structural).
7. Authorization & IDOR/BOLA patterns (Broken Access Control, missing middleware, direct object lookup without owner check).
8. Sensitive Data Exposure & Security Misconfiguration patterns.
9. False-positive prevention (comments, parameterized queries, environment variables, owner-scoped lookups).
10. Invalid paths & remote URL rejection (zero network requests).
11. Excluded directories (`.git`, `node_modules`, `.venv`, `build`, `dist`).
12. Large files & repository size/file-count limits.
13. Missing repositories.
14. Secret-file & private-key exclusion (`.env`, `.pem`, `.key`, `id_rsa`, embedded PEM headers) and snippet secret redaction.
15. Static vs. runtime vulnerability classification guardrails (static analysis never claims `CONFIRMED` runtime exploitability).
"""

from pathlib import Path
import pytest
from pydantic import ValidationError

from backend.agent.schemas import ConfidenceLevel, SeverityLevel
from backend.scanner.source_analyzer import (
    DetectionMethod,
    FindingClassification,
    InvalidSourcePathError,
    ProjectDependencyAnalyzer,
    ProjectDependencyGraph,
    RepositoryLimitExceededError,
    SourceAnalysisReport,
    SourceAnalyzer,
    SourceFinding,
    SourceType,
    SourceVulnerabilityCategory,
    StaticFindingClassification,
    StaticValidationStatus,
    SupportedLanguage,
    analyze_source,
)
from backend.storage.models import FindingStatus


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "source_analyzer"


@pytest.fixture
def analyzer() -> SourceAnalyzer:
    """Provides a standard SourceAnalyzer instance with default boundaries."""
    return SourceAnalyzer()


# ==============================================================================
# 1. Language Detection & Source Discovery Tests
# ==============================================================================


class TestSourceDiscoveryAndBoundaries:
    def test_language_detection_supported_and_unsupported(self, analyzer: SourceAnalyzer):
        assert analyzer.detect_language("app/main.py") == SupportedLanguage.PYTHON
        assert analyzer.detect_language("routes/basket.js") == SupportedLanguage.JAVASCRIPT
        assert analyzer.detect_language("components/Card.jsx") == SupportedLanguage.JAVASCRIPT
        assert analyzer.detect_language("services/auth.ts") == SupportedLanguage.TYPESCRIPT
        assert analyzer.detect_language("views/Profile.tsx") == SupportedLanguage.TYPESCRIPT
        assert analyzer.detect_language("README.md") == SupportedLanguage.UNKNOWN
        assert analyzer.detect_language("archive.tar.gz") == SupportedLanguage.UNKNOWN
        assert analyzer.detect_language("logo.png") == SupportedLanguage.UNKNOWN

    def test_invalid_paths_and_missing_repositories_rejected(self, analyzer: SourceAnalyzer, tmp_path: Path):
        # Empty / whitespace paths
        with pytest.raises(InvalidSourcePathError):
            analyzer.discover_files("")
        with pytest.raises(InvalidSourcePathError):
            analyzer.discover_files("   ")

        # Null byte injection
        with pytest.raises(InvalidSourcePathError):
            analyzer.discover_files("valid_name\x00.py")

        # Network URLs must be rejected immediately (never make network requests)
        for url in (
            "http://localhost:3000/main.js",
            "https://github.com/example/repo.git",
            "ftp://files.example.com/app.py",
            "file:///etc/passwd",
        ):
            with pytest.raises(InvalidSourcePathError) as exc_info:
                analyzer.discover_files(url)
            assert "prohibited" in str(exc_info.value).lower()

        # Non-existent repository path
        missing_repo = tmp_path / "non_existent_repository_12345"
        with pytest.raises(InvalidSourcePathError) as exc_info:
            analyzer.analyze_repository(missing_repo)
        assert "does not exist" in str(exc_info.value)

    def test_excluded_directories_skipped(self, analyzer: SourceAnalyzer, tmp_path: Path):
        """Verifies .git, node_modules, .venv, build, and dist are strictly excluded."""
        for excluded in (".git", "node_modules", ".venv", "build", "dist"):
            d = tmp_path / excluded
            d.mkdir(parents=True)
            (d / "vulnerable_ignored.py").write_text(
                "import sqlite3\ncursor.execute(f'SELECT * FROM t WHERE id={x}')\n",
                encoding="utf-8",
            )

        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "app.py").write_text("x = 1\n", encoding="utf-8")

        discovery = analyzer.discover_files(tmp_path)
        discovered_paths = [f.file_path for f in discovery.discovered_files]
        assert discovered_paths == ["src/app.py"]

        skipped_reasons = {item.path: item.reason for item in discovery.skipped_items}
        for excluded in (".git", "node_modules", ".venv", "build", "dist"):
            assert skipped_reasons.get(excluded) == "excluded_directory"

    def test_secret_files_and_private_keys_excluded(self, analyzer: SourceAnalyzer, tmp_path: Path):
        """Verifies .env files, private key files (.pem, .key, id_rsa), and PEM contents are excluded."""
        (tmp_path / ".env").write_text("SECRET_KEY=top_secret_value\n", encoding="utf-8")
        (tmp_path / ".env.production").write_text("DB_PASS=prod_secret\n", encoding="utf-8")
        (tmp_path / "server.key").write_text("private key bytes", encoding="utf-8")
        (tmp_path / "cert.pem").write_text("pem data", encoding="utf-8")
        (tmp_path / "id_rsa").write_text("ssh key", encoding="utf-8")
        (tmp_path / "credentials.json").write_text('{"client_secret": "123"}', encoding="utf-8")

        # Also test a .py file containing a raw RSA private key block
        (tmp_path / "embedded_key.py").write_text(
            "KEY = '''-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----'''\n",
            encoding="utf-8",
        )
        (tmp_path / "clean.py").write_text("def hello():\n    return 'ok'\n", encoding="utf-8")

        discovery = analyzer.discover_files(tmp_path)
        discovered_names = [f.file_path for f in discovery.discovered_files]
        assert discovered_names == ["clean.py"]

        skipped_map = {item.path: item.reason for item in discovery.skipped_items}
        assert skipped_map[".env"] == "excluded_secret_or_env_file"
        assert skipped_map[".env.production"] == "excluded_secret_or_env_file"
        assert skipped_map["server.key"] == "excluded_secret_or_env_file"
        assert skipped_map["cert.pem"] == "excluded_secret_or_env_file"
        assert skipped_map["id_rsa"] == "excluded_secret_or_env_file"
        assert skipped_map["embedded_key.py"] == "excluded_private_key_content"

    def test_unsupported_and_binary_files_handled_gracefully(self, analyzer: SourceAnalyzer, tmp_path: Path):
        (tmp_path / "notes.txt").write_text("plain text notes", encoding="utf-8")
        (tmp_path / "styles.css").write_text("body { color: red; }", encoding="utf-8")
        (tmp_path / "binary_ disguised.py").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
        (tmp_path / "broken_syntax.py").write_text("def unclosed_func(:\n    pass\n", encoding="utf-8")

        report = analyzer.analyze_repository(tmp_path)
        # Only broken_syntax.py is discovered as non-binary .py, and syntax error is handled safely without raising
        assert len(report.discovery.discovered_files) == 1
        assert report.discovery.discovered_files[0].file_path == "broken_syntax.py"
        assert report.findings == []

    def test_large_file_and_repository_size_limits_enforced(self, tmp_path: Path):
        small_file = tmp_path / "small.py"
        small_file.write_text("a = 1\n" * 10, encoding="utf-8")

        oversized_file = tmp_path / "oversized.py"
        oversized_file.write_text("x = 1\n" * 500, encoding="utf-8")  # ~3000 bytes

        # 1. File-size limit test
        bounded_analyzer = SourceAnalyzer(max_file_size_bytes=500, max_repo_size_bytes=10_000)
        discovery = bounded_analyzer.discover_files(tmp_path)
        assert [f.file_path for f in discovery.discovered_files] == ["small.py"]
        assert any("file_size_limit_exceeded" in s.reason for s in discovery.skipped_items)

        # 2. Repository-size limit test
        second_small = tmp_path / "small_two.py"
        second_small.write_text("b = 2\n" * 20, encoding="utf-8")  # ~120 bytes
        repo_bounded = SourceAnalyzer(max_file_size_bytes=5_000, max_repo_size_bytes=100)
        repo_disc = repo_bounded.discover_files(tmp_path)
        assert repo_disc.repository_limit_reached is True
        assert any("repository_size_limit_exceeded" in s.reason for s in repo_disc.skipped_items)

        with pytest.raises(RepositoryLimitExceededError):
            repo_bounded.discover_files(tmp_path, strict_repo_limits=True)


# ==============================================================================
# 2. Vulnerability Detection Tests Across Languages & Categories
# ==============================================================================


class TestVulnerabilityDetection:
    def test_python_vulnerable_fixture_detections(self, analyzer: SourceAnalyzer):
        findings = analyzer.analyze_file(
            FIXTURES_DIR / "python_vulnerable.py",
            display_path="python_vulnerable.py",
        )
        assert len(findings) >= 7

        categories = {f.vulnerability_category for f in findings}
        assert SourceVulnerabilityCategory.SQL_INJECTION.value in categories
        assert SourceVulnerabilityCategory.CROSS_SITE_SCRIPTING.value in categories
        assert SourceVulnerabilityCategory.BROKEN_ACCESS_CONTROL.value in categories
        assert SourceVulnerabilityCategory.BOLA_IDOR.value in categories
        assert SourceVulnerabilityCategory.SENSITIVE_DATA_EXPOSURE.value in categories
        assert SourceVulnerabilityCategory.SECURITY_MISCONFIGURATION.value in categories

        # Check function names and structured fields are populated
        sqli = next(f for f in findings if f.vulnerability_category == SourceVulnerabilityCategory.SQL_INJECTION.value)
        assert sqli.function_name == "search_users_sqli"
        assert sqli.language == SupportedLanguage.PYTHON
        assert sqli.detection_method == DetectionMethod.PYTHON_AST.value
        assert sqli.start_line >= 20
        assert sqli.is_runtime_confirmed is False
        assert sqli.classification == StaticFindingClassification.POTENTIAL_VULNERABILITY

        idor = next(f for f in findings if f.vulnerability_category == SourceVulnerabilityCategory.BOLA_IDOR.value)
        assert idor.function_name == "get_order_idor"
        assert idor.route_path == "/api/orders/<int:order_id>"

        # Ensure hardcoded secret values are redacted in code_snippet
        sde_findings = [
            f for f in findings if f.vulnerability_category == SourceVulnerabilityCategory.SENSITIVE_DATA_EXPOSURE.value
        ]
        assert sde_findings
        for sde in sde_findings:
            assert "sk_live_synthetic_hardcoded_secret_987654321" not in sde.code_snippet
            assert "super_secret_db_password_123!" not in sde.code_snippet
            assert "REDACTED" in sde.code_snippet

    def test_python_safe_fixture_zero_false_positives(self, analyzer: SourceAnalyzer):
        findings = analyzer.analyze_file(
            FIXTURES_DIR / "python_safe.py",
            display_path="python_safe.py",
        )
        assert findings == [], f"Expected zero findings on safe Python fixture, got: {findings}"

    def test_javascript_vulnerable_fixture_detections(self, analyzer: SourceAnalyzer):
        findings = analyzer.analyze_file(
            FIXTURES_DIR / "javascript_vulnerable.js",
            display_path="javascript_vulnerable.js",
        )
        assert len(findings) >= 6

        categories = {f.vulnerability_category for f in findings}
        assert SourceVulnerabilityCategory.SQL_INJECTION.value in categories
        assert SourceVulnerabilityCategory.CROSS_SITE_SCRIPTING.value in categories
        assert SourceVulnerabilityCategory.BROKEN_ACCESS_CONTROL.value in categories
        assert SourceVulnerabilityCategory.BOLA_IDOR.value in categories
        assert SourceVulnerabilityCategory.SENSITIVE_DATA_EXPOSURE.value in categories
        assert SourceVulnerabilityCategory.SECURITY_MISCONFIGURATION.value in categories

        idor = next(f for f in findings if f.vulnerability_category == SourceVulnerabilityCategory.BOLA_IDOR.value)
        assert idor.route_path == "/rest/basket/:id"
        assert idor.http_method == "GET"

    def test_typescript_vulnerable_and_safe_fixtures(self, analyzer: SourceAnalyzer):
        vuln_findings = analyzer.analyze_file(
            FIXTURES_DIR / "typescript_vulnerable.ts",
            display_path="typescript_vulnerable.ts",
        )
        assert len(vuln_findings) >= 5

        categories = {f.vulnerability_category for f in vuln_findings}
        assert SourceVulnerabilityCategory.SQL_INJECTION.value in categories
        assert SourceVulnerabilityCategory.CROSS_SITE_SCRIPTING.value in categories
        assert SourceVulnerabilityCategory.BROKEN_ACCESS_CONTROL.value in categories
        assert SourceVulnerabilityCategory.BOLA_IDOR.value in categories
        assert SourceVulnerabilityCategory.SENSITIVE_DATA_EXPOSURE.value in categories
        assert SourceVulnerabilityCategory.SECURITY_MISCONFIGURATION.value in categories

        safe_findings = analyzer.analyze_file(
            FIXTURES_DIR / "typescript_safe.ts",
            display_path="typescript_safe.ts",
        )
        assert safe_findings == [], f"Expected zero findings on safe TypeScript fixture, got: {safe_findings}"

    def test_targeted_sql_injection_patterns_and_comments_ignored(self, analyzer: SourceAnalyzer):
        # Comments containing SQLi strings in JS/TS must not trigger false positives
        commented_js = """
        // db.query(`SELECT * FROM Users WHERE name = '${req.query.name}'`);
        /*
           const q = `DELETE FROM Accounts WHERE id = ${req.params.id}`;
           db.execute(q);
        */
        export async function safeQuery(db, id) {
            return await db.query("SELECT * FROM Users WHERE id = ?", [id]);
        }
        """
        assert analyzer.analyze_source_string(commented_js, SupportedLanguage.JAVASCRIPT, "comments.js") == []

        # Percentage and .format() SQLi in Python
        py_sqli = """
def fetch_record(cursor, user_input):
    cursor.execute("SELECT * FROM accounts WHERE owner = '%s'" % user_input)
    cursor.execute("SELECT * FROM accounts WHERE owner = '{}'".format(user_input))
"""
        py_findings = analyzer.analyze_source_string(py_sqli, SupportedLanguage.PYTHON, "sqli.py")
        assert len(py_findings) == 2
        assert all(f.vulnerability_category == SourceVulnerabilityCategory.SQL_INJECTION.value for f in py_findings)

    def test_targeted_xss_and_authorization_patterns(self, analyzer: SourceAnalyzer):
        # FastAPI HTMLResponse XSS + IDOR without owner check
        fastapi_code = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/items/{item_id}")
async def read_item(item_id: int, q: str = ""):
    record = db.session.get(ItemModel, item_id)
    return HTMLResponse(f"<html><body>Item: {q}</body></html>")
"""
        findings = analyzer.analyze_source_string(fastapi_code, SupportedLanguage.PYTHON, "fastapi_app.py")
        cats = {f.vulnerability_category for f in findings}
        assert SourceVulnerabilityCategory.BOLA_IDOR.value in cats
        assert SourceVulnerabilityCategory.CROSS_SITE_SCRIPTING.value in cats


# ==============================================================================
# 3. Finding Structure & Static-vs-Runtime Guardrail Tests
# ==============================================================================


class TestFindingStructureAndGuardrails:
    def test_finding_contains_all_required_contract_fields(self, analyzer: SourceAnalyzer):
        report: SourceAnalysisReport = analyze_source(FIXTURES_DIR)
        assert len(report.findings) > 0

        sample = report.findings[0]
        dumped = sample.model_dump()
        required_fields = {
            "finding_id",
            "rule_id",
            "vulnerability_category",
            "severity",
            "confidence",
            "source_type",
            "classification",
            "validation_status",
            "file_path",
            "function_name",
            "start_line",
            "end_line",
            "code_snippet",
            "detection_explanation",
            "detection_method",
        }
        assert required_fields.issubset(set(dumped.keys()))

        # Convert to canonical project FindingRecord and verify status is never confirmed
        finding_records = report.to_finding_records()
        assert len(finding_records) == len(report.findings)
        for rec in finding_records:
            assert rec.status == FindingStatus.SUSPECTED.value
            assert rec.confirmation_status == FindingStatus.SUSPECTED.value
            assert rec.validation_status == "SUSPICIOUS"
            assert rec.evidence is not None
            assert len(rec.evidence.evidence_sha256) == 64

    def test_static_analysis_cannot_claim_confirmed_runtime_vulnerability(self):
        """Verifies that a static finding raises ValidationError if marked as runtime confirmed."""
        with pytest.raises(ValidationError) as exc_info:
            SourceFinding(
                finding_id="src_invalid_confirm",
                rule_id="AS-PY-SQLI-001",
                vulnerability_category=SourceVulnerabilityCategory.SQL_INJECTION.value,
                severity=SeverityLevel.CRITICAL,
                confidence=ConfidenceLevel.HIGH,
                source_type=SourceType.SOURCE_CODE.value,
                classification=StaticFindingClassification.CONFIRMED_RUNTIME_VULNERABILITY,
                validation_status=StaticValidationStatus.CONFIRMED_RUNTIME.value,
                is_runtime_confirmed=True,
                file_path="app.py",
                language=SupportedLanguage.PYTHON,
                start_line=10,
                end_line=12,
                code_snippet="cursor.execute(f'SELECT * FROM t WHERE id={x}')",
                detection_explanation="Dynamic SQL query detected in static AST.",
                detection_method=DetectionMethod.PYTHON_AST.value,
            )
        assert "Static Analysis Guardrail Violation" in str(exc_info.value)

        # Also verify confidence=CONFIRMED is automatically downgraded to HIGH for static findings
        downgraded = SourceFinding(
            finding_id="src_downgrade_test",
            rule_id="AS-PY-SQLI-001",
            vulnerability_category=SourceVulnerabilityCategory.SQL_INJECTION.value,
            severity=SeverityLevel.CRITICAL,
            confidence=ConfidenceLevel.CONFIRMED,
            source_type=SourceType.SOURCE_CODE.value,
            classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
            validation_status="CONFIRMED",
            is_runtime_confirmed=False,
            file_path="app.py",
            language=SupportedLanguage.PYTHON,
            start_line=10,
            end_line=12,
            code_snippet="cursor.execute(f'SELECT * FROM t WHERE id={x}')",
            detection_explanation="Dynamic SQL query detected in static AST.",
            detection_method=DetectionMethod.PYTHON_AST.value,
        )
        assert downgraded.confidence == ConfidenceLevel.HIGH
        assert downgraded.validation_status == StaticValidationStatus.POTENTIAL_UNVERIFIED.value

    def test_never_executes_scanned_source_code(self, analyzer: SourceAnalyzer, tmp_path: Path):
        """Proves that SourceAnalyzer never imports, evaluates, or executes scanned code."""
        canary_file = tmp_path / "execution_canary.txt"
        trap_script = tmp_path / "trap.py"
        trap_script.write_text(
            f"import pathlib\n"
            f"pathlib.Path({str(canary_file)!r}).write_text('EXECUTED!')\n"
            f"raise RuntimeError('Should never be executed!')\n",
            encoding="utf-8",
        )

        report = analyzer.analyze_repository(tmp_path)
        assert not canary_file.exists(), "Scanned source code must NEVER be executed!"
        assert len(report.discovery.discovered_files) == 1

    def test_external_bandit_integration_mocked(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Verifies optional Bandit JSON integration produces properly unconfirmed static findings."""
        import subprocess
        import shutil

        sample_py = tmp_path / "sample.py"
        sample_py.write_text("x = 1\n", encoding="utf-8")

        import json

        monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/bandit" if cmd == "bandit" else None)

        class DummyCompletedProcess:
            stdout = json.dumps(
                {
                    "results": [
                        {
                            "test_id": "B608",
                            "line_number": 1,
                            "filename": str(sample_py),
                            "code": "cursor.execute(query)",
                            "issue_text": "Possible SQL injection vector through string-based query construction.",
                            "issue_severity": "MEDIUM",
                            "issue_confidence": "HIGH",
                        }
                    ]
                }
            )

        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: DummyCompletedProcess())

        ext_analyzer = SourceAnalyzer(enable_external_tools=True)
        report = ext_analyzer.analyze_repository(tmp_path)
        assert "bandit" in report.external_tools_used
        assert len(report.findings) == 1
        fnd = report.findings[0]
        assert fnd.rule_id == "BANDIT-B608"
        assert fnd.vulnerability_category == SourceVulnerabilityCategory.SQL_INJECTION.value
        assert fnd.detection_method == DetectionMethod.BANDIT.value
        assert fnd.is_runtime_confirmed is False
        assert fnd.classification == StaticFindingClassification.POTENTIAL_VULNERABILITY


CROSS_FILE_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "cross_file_project"


class TestCrossFileStaticAnalysis:
    """Tests for Phase 5.1 Cross-File Static Analysis, Dependency Graphs, and Classification Guardrails."""

    def test_module_discovery_and_import_relationship_graph(self):
        """Verifies modules, imports, and symbols are accurately discovered across files."""
        analyzer = SourceAnalyzer()
        discovery = analyzer.discover_files(CROSS_FILE_FIXTURE_DIR)
        py_files = [f for f in discovery.discovered_files if f.language == SupportedLanguage.PYTHON]

        dep_analyzer = ProjectDependencyAnalyzer(root_path=CROSS_FILE_FIXTURE_DIR)
        graph = dep_analyzer.analyze_project(py_files)

        # 1. Module registration
        assert "auth.decorators" in graph.modules
        assert "auth.dependencies" in graph.modules
        assert "auth.helpers" in graph.modules
        assert "auth.middleware" in graph.modules
        assert "routers.protected_routes" in graph.modules
        assert "routers.unprotected_routes" in graph.modules
        assert "routers.uncertain_routes" in graph.modules
        assert "main" in graph.modules

        # 2. Symbols recorded
        auth_dec_symbols = [s.name for s in graph.symbols["auth.decorators"]]
        assert "require_admin" in auth_dec_symbols
        assert any(s.name == "require_admin" and s.is_auth_related for s in graph.symbols["auth.decorators"])

        auth_dep_symbols = [s.name for s in graph.symbols["auth.dependencies"]]
        assert "get_current_admin" in auth_dep_symbols
        assert any(s.name == "get_current_admin" and s.is_auth_related for s in graph.symbols["auth.dependencies"])

        # 3. Import relationships
        protected_imports = [i for i in graph.imports if i.source_module == "routers.protected_routes"]
        imported_targets = {i.imported_name: i.target_module for i in protected_imports}
        assert imported_targets.get("require_admin") == "auth.decorators"
        assert imported_targets.get("get_current_admin") == "auth.dependencies"
        assert imported_targets.get("verify_admin_access") == "auth.helpers"

    def test_fastapi_cross_file_route_protection_avoids_false_positives(self, analyzer: SourceAnalyzer):
        """Verifies protected routes using cross-file decorators, dependencies, and helpers are not flagged."""
        report = analyzer.analyze_repository(CROSS_FILE_FIXTURE_DIR)
        assert report.dependency_graph is not None

        # Collect rule IDs and files
        bac_findings = [f for f in report.findings if f.rule_id == "AS-PY-BAC-001"]
        # None of the protected routes should be flagged as AS-PY-BAC-001
        protected_bac = [f for f in bac_findings if Path(f.file_path).name == "protected_routes.py"]
        assert len(protected_bac) == 0, (
            f"Protected routes in external modules must not be flagged as BFLA: {[f.route_path for f in protected_bac]}"
        )

        # Verify route security contexts in graph
        routes_by_path = {r.route_path: r for r in report.dependency_graph.routes}
        assert "/admin/protected/export-database" in routes_by_path
        assert routes_by_path["/admin/protected/export-database"].is_protected is True
        assert "auth.decorators:require_admin" in routes_by_path["/admin/protected/export-database"].resolved_auth_sources

        assert "/admin/protected/system-settings" in routes_by_path
        assert routes_by_path["/admin/protected/system-settings"].is_protected is True
        assert "auth.dependencies:get_current_admin" in routes_by_path["/admin/protected/system-settings"].resolved_auth_sources

        assert "/admin/protected/purge-users" in routes_by_path
        assert routes_by_path["/admin/protected/purge-users"].is_protected is True
        assert "auth.helpers:verify_admin_access" in routes_by_path["/admin/protected/purge-users"].resolved_auth_sources

    def test_unprotected_route_correctly_flagged_as_potential_vulnerability(self, analyzer: SourceAnalyzer):
        """Verifies truly unprotected privileged route is detected and classified as POTENTIAL_VULNERABILITY."""
        report = analyzer.analyze_repository(CROSS_FILE_FIXTURE_DIR)

        unprotected_findings = [
            f for f in report.findings
            if "unprotected_routes.py" in f.file_path and f.rule_id == "AS-PY-BAC-001"
        ]
        assert len(unprotected_findings) == 1
        finding = unprotected_findings[0]
        assert finding.vulnerability_category == SourceVulnerabilityCategory.BROKEN_ACCESS_CONTROL.value
        assert finding.severity == SeverityLevel.HIGH
        assert finding.confidence == ConfidenceLevel.MEDIUM
        assert finding.classification == FindingClassification.POTENTIAL_VULNERABILITY
        assert finding.is_runtime_confirmed is False

    def test_explicit_uncertainty_reporting_on_external_dependencies(self, analyzer: SourceAnalyzer):
        """Verifies routes with unresolved third-party security decorators report INCONCLUSIVE uncertainty."""
        report = analyzer.analyze_repository(CROSS_FILE_FIXTURE_DIR)

        # Must record analysis uncertainty in report
        assert any("third_party_security_provider" in u for u in report.analysis_uncertainties)

        uncertain_findings = [
            f for f in report.findings
            if "uncertain_routes.py" in f.file_path and f.rule_id == "AS-PY-BAC-UNCERTAIN"
        ]
        assert len(uncertain_findings) == 1
        uf = uncertain_findings[0]
        assert uf.classification == FindingClassification.INCONCLUSIVE
        assert uf.confidence == ConfidenceLevel.LOW
        assert uf.metadata.get("analysis_uncertainty") is True
        assert "third_party_security_provider" in uf.detection_explanation

    def test_strict_finding_classification_guardrails(self):
        """Proves SourceFinding strictly rejects CONFIRMED_RUNTIME_VULNERABILITY and is_runtime_confirmed=True."""
        # 1. Reject CONFIRMED_RUNTIME_VULNERABILITY classification
        with pytest.raises(ValueError, match="Static Analysis Guardrail Violation"):
            SourceFinding(
                finding_id="fnd_guardrail_test",
                rule_id="AS-PY-BAC-001",
                vulnerability_category="BROKEN_ACCESS_CONTROL",
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                source_type=SourceType.SOURCE_CODE.value,
                classification=FindingClassification.CONFIRMED_RUNTIME_VULNERABILITY,
                file_path="router.py",
                start_line=1,
                end_line=2,
                code_snippet="def reset(): pass",
                detection_explanation="Test pattern for guardrail",
                detection_method="python_ast",
            )

        # 2. Reject is_runtime_confirmed=True on static source finding
        with pytest.raises(ValueError, match="Static Analysis Guardrail Violation"):
            SourceFinding(
                finding_id="fnd_guardrail_test_2",
                rule_id="AS-PY-BAC-001",
                vulnerability_category="BROKEN_ACCESS_CONTROL",
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                source_type=SourceType.SOURCE_CODE.value,
                classification=FindingClassification.POTENTIAL_VULNERABILITY,
                is_runtime_confirmed=True,
                file_path="router.py",
                start_line=1,
                end_line=2,
                code_snippet="def reset(): pass",
                detection_explanation="Test pattern for guardrail",
                detection_method="python_ast",
            )

        # 3. Verify to_finding_record preserves classification
        valid_finding = SourceFinding(
            finding_id="fnd_valid_test",
            rule_id="AS-PY-BAC-001",
            vulnerability_category="BROKEN_ACCESS_CONTROL",
            severity=SeverityLevel.HIGH,
            confidence=ConfidenceLevel.HIGH,
            classification=FindingClassification.POTENTIAL_VULNERABILITY,
            file_path="router.py",
            start_line=1,
            end_line=2,
            code_snippet="def reset(): pass",
            detection_explanation="Valid potential finding",
            detection_method="python_ast",
        )
        rec = valid_finding.to_finding_record()
        assert rec.classification == FindingClassification.POTENTIAL_VULNERABILITY.value
        assert rec.status == FindingStatus.SUSPECTED.value

