"""Unit and Integration Tests for Vulnerability-to-Code Mapping Engine (Phase 5.2).

Validates:
1. Exact file and line mapping.
2. Function and method name verification.
3. Code snippet authenticity check (never invents lines/snippets).
4. Route-to-handler correlation for Express and Python backends.
5. Multi-candidate ambiguity reporting without guessing.
6. Missing files, invalid line numbers, and path traversal prevention.
7. Missing repository and unavailable source code reporting.
8. Frontend caller exclusion (client-side fetch/axios ignored).
9. Context extraction (database operations and authorization checks).
"""

import os
from pathlib import Path
import pytest

from backend.analysis.code_mapper import (
    CodeMapper,
    CodeMappingResult,
    MappingConfidence,
    MappingStatus,
    SourceLocation,
)
from backend.storage.models import FindingRecord, SeverityLevel


@pytest.fixture
def mock_app_repo(tmp_path: Path) -> Path:
    """Creates a realistic mock application repository with Express and Python backend routes."""
    repo = tmp_path / "mock_juice_shop"
    repo.mkdir()

    # 1. Express / Node routes
    routes_dir = repo / "routes"
    routes_dir.mkdir()

    basket_js = routes_dir / "basket.js"
    basket_js.write_text(
        """// Basket Route Handler
const express = require('express');
const router = express.Router();
const models = require('../models');

// Retrieve Basket by ID (Vulnerable to IDOR)
router.get('/:id', function retrieveBasket(req, res) {
  const basketId = req.params.id;
  models.Basket.findOne({ where: { id: basketId } })
    .then(basket => {
      res.json({ status: 'success', data: basket });
    })
    .catch(err => res.status(500).json({ error: err.message }));
});

// Update Basket (Authenticated)
router.post('/:id/items', function addBasketItem(req, res) {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  res.json({ status: 'item added' });
});

module.exports = router;
""",
        encoding="utf-8"
    )

    # 2. Main Express app mounting routes
    server_js = repo / "server.js"
    server_js.write_text(
        """const express = require('express');
const app = express();
const basketRoutes = require('./routes/basket');

app.use('/rest/basket', basketRoutes);

app.get('/api/Users', function listUsers(req, res) {
  db.query('SELECT id, email FROM Users', (err, rows) => {
    res.json(rows);
  });
});

app.listen(3000);
""",
        encoding="utf-8"
    )

    # 3. Python FastAPI service
    api_dir = repo / "backend" / "api"
    api_dir.mkdir(parents=True)

    orders_py = api_dir / "orders.py"
    orders_py.write_text(
        '''from fastapi import APIRouter, Depends, HTTPException

router = APIRouter(prefix="/api/v1")

@router.get("/orders/{order_id}")
async def get_order_details(order_id: int):
    """Retrieve order details without ownership check."""
    order = db.query(Order).filter(Order.id == order_id).first()
    return order

@router.delete("/orders/{order_id}")
async def delete_order(order_id: int, current_user = Depends(get_current_user)):
    """Delete order with authorization check."""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"status": "deleted"}
''',
        encoding="utf-8"
    )

    # 4. Frontend client file (should be ignored by route correlation)
    frontend_dir = repo / "frontend" / "src"
    frontend_dir.mkdir(parents=True)

    client_tsx = frontend_dir / "BasketView.tsx"
    client_tsx.write_text(
        """// Client Component making API call
import React, { useEffect } from 'react';

export function BasketView({ id }) {
  useEffect(() => {
    fetch(`/rest/basket/${id}`)
      .then(r => r.json())
      .then(d => console.log(d));
  }, [id]);

  return <div>Basket {id}</div>;
}
""",
        encoding="utf-8"
    )

    return repo


@pytest.fixture
def mapper(mock_app_repo: Path) -> CodeMapper:
    """Provides a CodeMapper instance pointing to the mock repository."""
    return CodeMapper(repo_root=mock_app_repo, repository_name="mock_juice_shop")


# ==============================================================================
# Test Suite 1: Static Analysis Mapping
# ==============================================================================


@pytest.mark.unit
class TestStaticAnalysisMapping:
    """Verifies static finding source verification and sanity checks."""

    def test_exact_file_mapping(self, mapper: CodeMapper):
        """Validates exact static file location with valid line numbers and matching snippet."""
        static_hint = {
            "file_path": "routes/basket.js",
            "start_line": 7,
            "end_line": 15,
            "code_snippet": (
                "router.get('/:id', function retrieveBasket(req, res) {\n"
                "  const basketId = req.params.id;\n"
                "  models.Basket.findOne({ where: { id: basketId } })\n"
                "    .then(basket => {\n"
                "      res.json({ status: 'success', data: basket });\n"
                "    })\n"
                "    .catch(err => res.status(500).json({ error: err.message }));\n"
                "});"
            ),
            "function_name": "retrieveBasket"
        }

        finding = {"id": "fnd_static_01", "title": "BOLA in retrieveBasket"}
        result = mapper.map_finding(finding, static_hint=static_hint)

        assert result.status == MappingStatus.EXACT
        assert result.verified is True
        assert result.location is not None
        assert result.location.file_path == "routes/basket.js"
        assert result.location.start_line == 7
        assert result.location.end_line == 15
        assert result.location.confidence == MappingConfidence.HIGH
        assert result.location.function_name == "retrieveBasket"
        assert "models.Basket.findOne" in (result.location.database_operation or "")

    def test_correct_function_mapping_python(self, mapper: CodeMapper):
        """Verifies function name in Python AST matches specified lines."""
        static_hint = {
            "file_path": "backend/api/orders.py",
            "start_line": 5,
            "end_line": 10,
            "function_name": "get_order_details"
        }
        finding = {"id": "fnd_static_py_01"}
        result = mapper.map_finding(finding, static_hint=static_hint)

        assert result.status == MappingStatus.EXACT
        assert result.location is not None
        assert result.location.function_name == "get_order_details"
        assert "db.query" in (result.location.database_operation or "")

    def test_correct_line_ranges_and_snippet_extraction(self, mapper: CodeMapper):
        """When snippet is omitted, extracts the authentic snippet directly from disk without inventing."""
        static_hint = {
            "file_path": "routes/basket.js",
            "start_line": 17,
            "end_line": 22,
            # No snippet provided -> mapper extracts exact lines from disk
        }
        finding = {"id": "fnd_static_snippet"}
        result = mapper.map_finding(finding, static_hint=static_hint)

        assert result.status == MappingStatus.EXACT
        assert result.location is not None
        assert "router.post('/:id/items'" in result.location.code_snippet
        assert "req.user" in (result.location.authorization_check or "")

    def test_snippet_verification_failure_rejects_mapping(self, mapper: CodeMapper):
        """If provided snippet contradicts actual file content, returns INVALID."""
        static_hint = {
            "file_path": "routes/basket.js",
            "start_line": 7,
            "end_line": 15,
            "code_snippet": "function totallyFabricatedCodeSnippetThatDoesNotExist() { return false; }"
        }
        finding = {"id": "fnd_mismatch"}
        result = mapper.map_finding(finding, static_hint=static_hint)

        assert result.status == MappingStatus.INVALID
        assert "mismatch" in (result.message or "").lower()

    def test_missing_file_returns_invalid(self, mapper: CodeMapper):
        """Returns INVALID when the requested file does not exist on disk."""
        static_hint = {
            "file_path": "routes/non_existent_file.js",
            "start_line": 10,
            "end_line": 20
        }
        finding = {"id": "fnd_missing_file"}
        result = mapper.map_finding(finding, static_hint=static_hint)

        assert result.status == MappingStatus.INVALID
        assert "does not exist" in (result.message or "").lower()

    def test_invalid_line_numbers_zero_or_negative(self, mapper: CodeMapper):
        """Returns INVALID when start line is < 1."""
        static_hint = {
            "file_path": "routes/basket.js",
            "start_line": 0,
            "end_line": 10
        }
        finding = {"id": "fnd_zero_line"}
        result = mapper.map_finding(finding, static_hint=static_hint)

        assert result.status == MappingStatus.INVALID
        assert "invalid line range" in (result.message or "").lower()

    def test_invalid_line_numbers_exceeding_file_length(self, mapper: CodeMapper):
        """Returns INVALID when end line exceeds total file length."""
        static_hint = {
            "file_path": "routes/basket.js",
            "start_line": 10,
            "end_line": 9999
        }
        finding = {"id": "fnd_overflow_line"}
        result = mapper.map_finding(finding, static_hint=static_hint)

        assert result.status == MappingStatus.INVALID
        assert "invalid line range" in (result.message or "").lower()

    def test_invalid_line_numbers_reversed(self, mapper: CodeMapper):
        """Returns INVALID when start line is greater than end line."""
        static_hint = {
            "file_path": "routes/basket.js",
            "start_line": 20,
            "end_line": 10
        }
        finding = {"id": "fnd_reversed_line"}
        result = mapper.map_finding(finding, static_hint=static_hint)

        assert result.status == MappingStatus.INVALID
        assert "invalid line range" in (result.message or "").lower()

    def test_path_traversal_prevention(self, mapper: CodeMapper):
        """Rejects paths that escape the repository boundary."""
        static_hint = {
            "file_path": "../../etc/passwd",
            "start_line": 1,
            "end_line": 5
        }
        finding = {"id": "fnd_traversal"}
        result = mapper.map_finding(finding, static_hint=static_hint)

        assert result.status == MappingStatus.INVALID
        assert "traversal" in (result.message or "").lower()

    def test_python_function_name_mismatch(self, mapper: CodeMapper):
        """Returns INVALID when the specified function name does not match the file."""
        static_hint = {
            "file_path": "backend/api/orders.py",
            "start_line": 5,
            "end_line": 10,
            "function_name": "wrong_function_name"
        }
        finding = {"id": "fnd_func_mismatch"}
        result = mapper.map_finding(finding, static_hint=static_hint)

        assert result.status == MappingStatus.INVALID
        assert "not found" in (result.message or "").lower()


# ==============================================================================
# Test Suite 2: Runtime Differential Finding Mapping
# ==============================================================================


@pytest.mark.unit
class TestRuntimeFindingMapping:
    """Verifies correlating runtime endpoints with backend source route handlers."""

    def test_route_to_handler_mapping_express(self, mapper: CodeMapper):
        """Correlates runtime endpoint /rest/basket/1 with routes/basket.js handler."""
        finding = FindingRecord(
            id="fnd_runtime_idor_01",
            target_identifier="scan_01",
            endpoint="/rest/basket/1",
            http_method="GET",
            vulnerability_category="BOLA_IDOR",
            affected_role="user_b",
            expected_behavior="403 Forbidden",
            actual_behavior="200 OK"
        )

        result = mapper.map_finding(finding)

        assert result.status == MappingStatus.EXACT
        assert result.verified is True
        assert result.location is not None
        assert "basket.js" in result.location.file_path
        assert result.location.function_name == "retrieveBasket"
        assert result.location.start_line == 7
        assert "models.Basket.findOne" in (result.location.database_operation or "")

    def test_route_to_handler_mapping_fastapi(self, mapper: CodeMapper):
        """Correlates runtime endpoint /api/v1/orders/42 with Python orders.py handler."""
        finding = {
            "id": "fnd_py_runtime_01",
            "endpoint": "/api/v1/orders/42",
            "http_method": "GET"
        }

        result = mapper.map_finding(finding)

        assert result.status == MappingStatus.EXACT
        assert result.verified is True
        assert result.location is not None
        assert "orders.py" in result.location.file_path
        assert result.location.function_name == "get_order_details"
        assert result.location.start_line == 5

    def test_frontend_caller_exclusion(self, mapper: CodeMapper):
        """Ensures client-side components making fetch() calls are NOT attributed as route handlers."""
        finding = {
            "id": "fnd_no_frontend",
            "endpoint": "/rest/basket/1",
            "http_method": "GET"
        }

        result = mapper.map_finding(finding)

        # Must map to the backend route, NEVER to frontend/src/BasketView.tsx
        assert result.status == MappingStatus.EXACT
        assert result.location is not None
        assert "frontend" not in result.location.file_path
        assert "BasketView" not in (result.location.function_name or "")

    def test_multiple_candidates_no_guessing(self, tmp_path: Path):
        """When multiple backend files declare the same route, returns CANDIDATE without guessing."""
        multi_repo = tmp_path / "multi_candidate_repo"
        multi_repo.mkdir()

        (multi_repo / "routes_v1.js").write_text(
            "app.get('/api/resource', function handlerV1(req, res) { res.send('v1'); });",
            encoding="utf-8"
        )
        (multi_repo / "routes_v2.js").write_text(
            "app.get('/api/resource', function handlerV2(req, res) { res.send('v2'); });",
            encoding="utf-8"
        )

        multi_mapper = CodeMapper(repo_root=multi_repo, repository_name="multi_repo")

        finding = {"id": "fnd_ambiguous", "endpoint": "/api/resource", "http_method": "GET"}
        result = multi_mapper.map_finding(finding)

        assert result.status == MappingStatus.CANDIDATE
        assert len(result.candidates) == 2
        assert result.location is None
        assert "candidate route handlers" in (result.message or "").lower()

    def test_unavailable_source_code_missing_repo(self):
        """When repo_root is None or does not exist, returns exact UNAVAILABLE message."""
        no_repo_mapper = CodeMapper(repo_root=None)
        finding = {"id": "fnd_no_repo", "endpoint": "/rest/basket/1"}

        result = no_repo_mapper.map_finding(finding)

        assert result.status == MappingStatus.UNAVAILABLE
        assert result.message == "Source code location unavailable. Runtime evidence is available."

    def test_unavailable_source_code_unmapped_endpoint(self, mapper: CodeMapper):
        """When endpoint cannot be correlated to any route in repo, returns UNAVAILABLE message."""
        finding = {
            "id": "fnd_unknown_route",
            "endpoint": "/completely/unknown/endpoint/never/declared",
            "http_method": "GET"
        }

        result = mapper.map_finding(finding)

        assert result.status == MappingStatus.UNAVAILABLE
        assert result.message == "Source code location unavailable. Runtime evidence is available."

    def test_method_mismatch_prevents_incorrect_mapping(self, mapper: CodeMapper):
        """A finding with HTTP DELETE on an endpoint having only GET and POST will not falsely map."""
        finding = {
            "id": "fnd_verb_mismatch",
            "endpoint": "/rest/basket/1",
            "http_method": "DELETE"  # routes/basket.js only defines GET and POST
        }

        result = mapper.map_finding(finding)

        assert result.status == MappingStatus.UNAVAILABLE
        assert result.message == "Source code location unavailable. Runtime evidence is available."


# ==============================================================================
# Test Suite 3: Context Extraction (Database & Auth Checks)
# ==============================================================================


@pytest.mark.unit
class TestContextExtraction:
    """Verifies detecting database operations and authorization checks."""

    def test_detects_database_operation_and_auth_check(self, mapper: CodeMapper):
        """Detects presence of authentication check on protected route."""
        finding = {
            "id": "fnd_auth_check",
            "endpoint": "/rest/basket/1/items",
            "http_method": "POST"
        }

        result = mapper.map_finding(finding)

        assert result.status == MappingStatus.EXACT
        assert result.location is not None
        assert result.location.function_name == "addBasketItem"
        assert result.location.authorization_check is not None
        assert "req.user" in result.location.authorization_check

    def test_detects_missing_authorization_check(self, mapper: CodeMapper):
        """Identifies when vulnerable endpoint has database query but NO authorization check."""
        finding = {
            "id": "fnd_idor_no_auth",
            "endpoint": "/rest/basket/1",
            "http_method": "GET"
        }

        result = mapper.map_finding(finding)

        assert result.status == MappingStatus.EXACT
        assert result.location is not None
        assert result.location.database_operation is not None
        # Vulnerable route has no auth check
        assert result.location.authorization_check is None
