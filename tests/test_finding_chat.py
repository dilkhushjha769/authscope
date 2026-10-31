"""Unit tests for finding-scoped, evidence-grounded Gemini Q&A."""

import asyncio
import importlib
from typing import Any

import pytest
from pydantic import ValidationError

from backend.analysis.finding_chat import FindingChatRequest, FindingChatService
from backend.storage.models import ScanSessionRecord

api_module = importlib.import_module("backend.api.app")
from backend.storage.models import EvidenceArtifact, FindingRecord


class FakeTextGenerator:
    """Captures bounded prompts without making a Gemini network request."""

    def __init__(self) -> None:
        self.prompt = ""
        self.system_instruction = ""

    def generate_text(self, prompt: str, system_instruction: str | None = None, **kwargs: Any) -> str:
        self.prompt = prompt
        self.system_instruction = system_instruction or ""
        return "This issue means another account may access the protected record."


@pytest.fixture
def finding() -> FindingRecord:
    evidence = EvidenceArtifact(
        finding_id="fnd_chat_1",
        endpoint="/rest/basket/1",
        request_method="GET",
        request_url="http://localhost:3000/rest/basket/1",
        response_status=200,
        response_body='{"email":"alice@example.com","token":"secret-value"}',
        sanitized_response_body='{"email":"[REDACTED_EMAIL]","token":"[REDACTED_SECRET]"}',
        sanitized_response_evidence='{"email":"[REDACTED_EMAIL]"}',
        evidence_sha256="a" * 64,
    )
    return FindingRecord(
        id="fnd_chat_1",
        scan_id="scan_chat_1",
        title="Cross-account basket access",
        vulnerability_type="BOLA_IDOR",
        severity="HIGH",
        status="confirmed",
        target_endpoint="/rest/basket/1",
        http_method="GET",
        description="Differential evidence indicates a peer account could read the basket.",
        evidence=evidence,
    )


def test_chat_uses_finding_facts_and_redacts_sensitive_values(finding: FindingRecord) -> None:
    generator = FakeTextGenerator()
    service = FindingChatService(generator=generator, model="gemini-test")

    result = service.answer(
        finding,
        FindingChatRequest(question="What does this bug mean?", history=[]),
    )

    assert result.model == "gemini-test"
    assert "protected record" in result.answer
    assert "fnd_chat_1" in generator.prompt
    assert "What does this bug mean?" in generator.prompt
    assert "alice@example.com" not in generator.prompt
    assert "secret-value" not in generator.prompt
    assert "change findings" in generator.system_instruction


def test_chat_request_bounds_question_and_history() -> None:
    with pytest.raises(ValidationError):
        FindingChatRequest(question="x" * 2001)
    with pytest.raises(ValidationError):
        FindingChatRequest(question="hello", history=[{"role": "user", "content": "x"}] * 9)


def test_chat_api_binds_finding_to_assessment(monkeypatch: pytest.MonkeyPatch, finding_repo, finding: FindingRecord) -> None:
    finding_repo.save_scan_session(ScanSessionRecord(id=finding.scan_id, target_url="http://localhost:3000"))
    finding_repo.save_finding(finding)
    generator = FakeTextGenerator()
    service = FindingChatService(generator=generator, model="gemini-test")
    monkeypatch.setattr(api_module, "_get_repository", lambda: finding_repo)
    monkeypatch.setattr(api_module.app.state, "finding_chat_service", service, raising=False)

    response = asyncio.run(api_module.chat_about_finding(
        finding.scan_id,
        finding.id,
        FindingChatRequest(question="Explain the evidence"),
    ))
    assert response.answer.startswith("This issue means")

    with pytest.raises(api_module.HTTPException) as error:
        asyncio.run(api_module.chat_about_finding(
            "another_assessment",
            finding.id,
            FindingChatRequest(question="Explain the evidence"),
        ))
    assert error.value.status_code == 404


@pytest.mark.parametrize("configured", [True, False])
def test_assessment_review_uses_gemini_when_configured(
    monkeypatch: pytest.MonkeyPatch,
    configured: bool,
) -> None:
    config = type("Config", (), {"is_configured": configured})()
    sentinel = object()
    monkeypatch.setattr(api_module.GeminiAgentConfig, "from_env", staticmethod(lambda: config))
    monkeypatch.setattr(api_module, "GeminiClient", lambda config: sentinel)

    provider = api_module.AssessmentTaskManager._default_finding_review_provider()
    assert (provider is sentinel) is configured
