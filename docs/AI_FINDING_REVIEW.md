# AI Finding Review

## Pipeline and trust boundaries

The deterministic assessment engine remains authoritative. It validates request scope, executes requests, and verifies/signs evidence before a finding can reach `FindingReviewService`. The service refuses missing, non-confirmed, incomplete, or out-of-scope evidence. It redacts request headers, URLs, response text, and other finding context before serializing the supplied facts for a model provider. Target response and source text are explicitly treated as untrusted data in the review prompt.

`FindingReview` is a strict Pydantic response contract. It includes a three-way advisory verdict, bounded confidence, evidence support/contradiction, missing information, impact, severity opinion, remediation, optional code example, and verification suggestions. Provider exceptions and schema failures become an `UNCERTAIN` review. The finding record's status, access verdict, validation status, and evidence are never updated from model output. Recommendations are text only and are never executed.

## Integration and SSE

The default assessment task manager invokes review after the engine emits a confirmed finding; the `GeminiAuthScopeAgent` adapter has the same post-validation integration. Review events are streamed using the existing `AssessmentEvent` and SSE event serialization: `finding_detected`, `evidence_validation_started`, `evidence_validation_completed`, `ai_review_started`, `ai_review_progress`, `ai_review_completed`, and `fix_recommendation_generated`. Existing finding and evidence events remain available. An unavailable provider produces an uncertain result and does not remove or fail the original finding.

`FindingReviewService` accepts an injected `ReviewProvider`; its `generate_structured(prompt, response_schema)` operation can wrap the existing `GeminiClient.generate_structured` method. Tests use a mocked provider and never make a real model call. The production task manager currently leaves this provider unset: activating Gemini would send data to an external service, which conflicts with this repository's mandatory outbound scope rule (only the authorized assessment target may receive network traffic). Configure transport only after the repository's egress policy explicitly authorizes it and the data-sharing boundary is approved. With no provider, SSE still reports the review as uncertain/unavailable.

## Limitations

- Model opinions are not evidence and do not change deterministic confirmation.
- Secure code examples should only be returned when verified source mapping establishes the language/framework and root cause; otherwise the field should be null.
- Existing evidence completeness validation can reject artifacts whose signed values are further normalized during model validation. Such evidence is withheld from review rather than bypassing integrity checks.
- The provider interface supports timeout, rate-limit, unavailable, and malformed-output failure isolation. Provider-specific retry/timeout policy belongs to the existing Gemini client when an approved transport is configured.

## Tests

`tests/test_finding_review.py` covers likely-real, likely-false-positive, uncertain, conflicting evidence, timeout, unavailable provider, malformed output, secret redaction, untrusted response instructions, integrity rejection, SSE payload delivery, code-example gating, and the invariant that the engine finding status remains unchanged. Focused result: `10 passed`; related backend/API regression selection: `92 passed, 2 warnings`; full suite: `582 passed, 5 warnings`.
