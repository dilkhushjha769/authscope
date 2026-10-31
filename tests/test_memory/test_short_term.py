"""Unit tests for ShortTermMemory."""

import pytest
from backend.memory.short_term import ShortTermMemory, _sanitize_observation


# ---------------------------------------------------------------------------
# Isolation tests
# ---------------------------------------------------------------------------


class TestAssessmentMemoryIsolation:
    """Two assessments must never share data."""

    def setup_method(self):
        self.stm = ShortTermMemory()
        self.stm.create("a1", "http://target-a.test")
        self.stm.create("a2", "http://target-b.test")

    def test_separate_targets(self):
        ctx_a = self.stm.get("a1")
        ctx_b = self.stm.get("a2")
        assert ctx_a.target_url == "http://target-a.test"
        assert ctx_b.target_url == "http://target-b.test"

    def test_observations_do_not_cross(self):
        self.stm.add_observation("a1", "Endpoint /api/basket found")
        self.stm.add_observation("a2", "Login endpoint discovered")

        ctx_a = self.stm.get("a1")
        ctx_b = self.stm.get("a2")
        assert any("basket" in o for o in ctx_a.observations)
        assert not any("basket" in o for o in ctx_b.observations)

    def test_finding_ids_isolated(self):
        self.stm.add_finding_id("a1", "finding-001")
        assert self.stm.get("a2").confirmed_finding_ids == []

    def test_endpoints_isolated(self):
        self.stm.add_endpoint("a1", "/api/orders")
        assert "/api/orders" not in self.stm.get("a2").discovered_endpoints

    def test_tool_results_isolated(self):
        self.stm.add_tool_result("a1", {"tool": "scanner", "result": "found"})
        assert self.stm.get("a2").tool_results == []

    def test_stage_updates_isolated(self):
        self.stm.update_stage("a1", "authorization_testing")
        assert self.stm.get("a2").stage == "initialization"

    def test_clear_removes_only_target_assessment(self):
        self.stm.clear("a1")
        assert self.stm.get("a1") is None
        assert self.stm.get("a2") is not None


# ---------------------------------------------------------------------------
# Secret sanitization
# ---------------------------------------------------------------------------


class TestObservationSanitization:
    """Credentials must be redacted before storage."""

    def test_jwt_redacted(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.SomeSignature"
        result = _sanitize_observation(f"Token: {jwt}")
        assert "SomeSignature" not in result
        assert "[REDACTED]" in result

    def test_bearer_token_redacted(self):
        result = _sanitize_observation("Authorization: Bearer abc123.def456.ghi789")
        assert "abc123" not in result or "[REDACTED]" in result

    def test_password_redacted(self):
        result = _sanitize_observation("password: hunter2")
        assert "hunter2" not in result
        assert "[REDACTED]" in result

    def test_api_key_redacted(self):
        result = _sanitize_observation("api_key: sk-12345678secret")
        assert "sk-12345678secret" not in result

    def test_safe_text_unchanged(self):
        safe = "Discovered endpoint GET /api/baskets/1"
        assert _sanitize_observation(safe) == safe

    def test_stm_sanitizes_on_add(self):
        stm = ShortTermMemory()
        stm.create("test-sanitize", "http://example.test")
        stm.add_observation("test-sanitize", "password: secret123")
        ctx = stm.get("test-sanitize")
        assert not any("secret123" in o for o in ctx.observations)


# ---------------------------------------------------------------------------
# Stage updates
# ---------------------------------------------------------------------------


class TestStageUpdates:
    def test_stage_changes(self):
        stm = ShortTermMemory()
        stm.create("s1", "http://s.test")
        stm.update_stage("s1", "authorization_testing")
        assert stm.get("s1").stage == "authorization_testing"

    def test_unknown_assessment_stage_update_is_noop(self):
        stm = ShortTermMemory()
        stm.update_stage("nonexistent", "some_stage")  # must not raise


# ---------------------------------------------------------------------------
# Missing assessment
# ---------------------------------------------------------------------------


class TestMissingAssessment:
    def test_get_returns_none(self):
        stm = ShortTermMemory()
        assert stm.get("does-not-exist") is None

    def test_get_context_dict_returns_empty(self):
        stm = ShortTermMemory()
        assert stm.get_context_dict("does-not-exist") == {}

    def test_add_observation_creates_implicit_context(self):
        stm = ShortTermMemory()
        stm.add_observation("implicit-id", "some observation")
        ctx = stm.get("implicit-id")
        assert ctx is not None
        assert len(ctx.observations) == 1


# ---------------------------------------------------------------------------
# Conversation context
# ---------------------------------------------------------------------------


class TestConversationContext:
    def test_conversation_turn_appended(self):
        stm = ShortTermMemory()
        stm.create("conv1", "http://example.test")
        stm.add_conversation_turn("conv1", "user", "Run a scan")
        ctx = stm.get("conv1")
        assert len(ctx.conversation_context) == 1
        assert ctx.conversation_context[0]["role"] == "user"

    def test_conversation_trimmed_at_50(self):
        stm = ShortTermMemory()
        stm.create("conv2", "http://example.test")
        for i in range(60):
            stm.add_conversation_turn("conv2", "agent", f"msg {i}")
        ctx = stm.get("conv2")
        assert len(ctx.conversation_context) == 50


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


class TestContextDict:
    def test_context_dict_is_plain_dict(self):
        stm = ShortTermMemory()
        stm.create("s2", "http://x.test")
        d = stm.get_context_dict("s2")
        assert isinstance(d, dict)
        assert d["assessment_id"] == "s2"
        assert "observations" in d
        assert "confirmed_finding_ids" in d

    def test_list_assessment_ids(self):
        stm = ShortTermMemory()
        stm.create("id1", "http://a.test")
        stm.create("id2", "http://b.test")
        ids = stm.list_assessment_ids()
        assert "id1" in ids
        assert "id2" in ids

