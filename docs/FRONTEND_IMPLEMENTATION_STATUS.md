# Frontend implementation status

## GitHub repository scanning

**Status: waiting on backend contracts.** The current frontend shows a GitHub setup card, but the backend does not expose GitHub authorization, connection status, repository/branch discovery, source-scan creation, source-scan SSE, repository-scoped findings, or scan-history APIs. The existing `/api/assessments` and `/api/assessments/{assessment_id}/stream` contracts operate website assessments; `github_repo` is optional source context and is not an authenticated repository download flow.

The frontend therefore does not initiate a fake OAuth flow, invent repository records, or reinterpret website-assessment SSE as source-scan progress. Once the backend developer publishes typed routes and response/event schemas, the UI can connect those contracts to the repository picker, commit-pinned scan, source finding cards, and history.

## Available frontend behavior

- Website assessments use the existing assessment API and real SSE events.
- Finding cards display backend-provided plain-language explanations, status, risk, evidence, remediation and verified source locations when present.
- A source archive may be supplied as optional assessment context.
- The GitHub setup card explains the required read-only GitHub App permissions and deployment configuration. The repository URL input is explicitly marked as context only.

## Contract checklist for the backend integration

Before wiring the GitHub workflow, document and expose the actual authorization start/callback/disconnect contract, connection status, repository and branch response models, commit-pinned source scan request, scan progress and terminal SSE events, source finding model, history list/detail endpoints, and safe user-facing error codes. Include user isolation and token-handling guarantees. Then update this status document with the concrete routes and event schemas consumed by the frontend.
