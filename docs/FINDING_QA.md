# Finding Q&A

When Gemini is configured, each confirmed finding is automatically sent through the existing evidence-grounded AI review stage. Gemini explains what the issue means, what an attacker could do, the likely impact, and practical remediation steps. Its review remains advisory; the Python security engine controls confirmation and severity. Finding cards also include an **Ask Gemini about this finding** panel. Questions are sent to the assessment API with a short, bounded conversation history. The API confirms that the finding belongs to the requested assessment, then supplies Gemini with a redacted snapshot of that finding and its stored evidence. The conversation is held by the browser and is not persisted by the backend.

Set `GEMINI_API_KEY` on the backend to enable responses. `GEMINI_MODEL` selects the configured model. Without a valid key, the endpoint returns `503`; temporary provider failures return a generic `502` message and do not expose credentials or provider internals.

Gemini can explain the evidence and offer remediation guidance. It cannot execute security tests, contact the target application, modify source code, or change the finding's deterministic status. Missing evidence and uncertain statuses must remain explicit in its answer. User questions and evidence are treated as untrusted text; bearer tokens, credentials, and PII are redacted before prompt construction. The endpoint limits each question to 2,000 characters and history to eight turns.

`POST /api/assessments/{assessment_id}/findings/{finding_id}/chat`

```json
{
  "question": "Why is this considered an IDOR?",
  "history": [{"role": "user", "content": "What is this finding?"}]
}
```

Response: `{"answer":"...","provider":"Google Gemini","model":"..."}`.
