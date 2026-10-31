# GitHub source security scanning

## Scan lifecycle

1. The user authorizes the GitHub App and separately installs it on one or more selected repositories.
2. AuthScope lists only repositories from the authenticated user's accessible installation repository API. Branches and their commit SHAs are fetched from GitHub when selected.
3. `POST /api/github/scans` revalidates installation/repository access and resolves the branch to a commit SHA. That SHA is persisted before the asynchronous scan begins.
4. The scanner retrieves the recursive Git tree for that exact SHA, then fetches only supported source blobs through `api.github.com`.
5. The existing offline `SourceAnalyzer` analyzes a temporary directory. Repository code is never executed, installed, or built. The temporary checkout is deleted after the scan.
6. Real scan activity is persisted and streamed from `GET /api/github/scans/{scan_id}/stream` using `activity`, `done`, and `error` events.
7. Redacted finding excerpts and detector evidence may be sent to the existing Gemini client for beginner-friendly explanation. AI output is advisory and cannot alter static finding classification or runtime status.

## Bounds and trust controls

- Supported languages are the languages the existing analyzer actually handles: Python, JavaScript, and TypeScript.
- The scan caps individual source files at 1 MiB, aggregate candidate source bytes at 50 MiB, and candidate file count at 3,000. A truncated Git tree is rejected to avoid claiming a complete scan.
- `.env`/environment files, credentials/private keys, dependency and generated directories, unsupported extensions, binary blobs, path traversal entries, and oversized files are excluded.
- Only API-returned blob SHAs are used for retrieval. Paths must be relative and contained in a temporary root. GitHub redirects are disabled and rejected.
- Source content is untrusted prompt data. Gemini receives only a bounded, redacted finding excerpt and metadata, never GitHub tokens, client credentials, or an entire repository. AI failure leaves deterministic findings intact.
- Every source finding is labeled `SOURCE_CODE_FINDING`; static findings remain `POTENTIAL_VULNERABILITY`/`DETECTED_CODE_PATTERN` with `runtime_status=NOT_TESTED`. Runtime confirmation still requires the existing evidence-validation and authorization-testing flow.
- Scan, event, and report reads are filtered by the current GitHub user ID. A foreign user's scan ID returns not found.
- Repository contents and code excerpts are stored in the source scan report, but no complete repository checkout is persisted. OAuth access/refresh credentials are encrypted at rest.

## Errors

Stable API error codes cover incomplete server configuration, expired authorization, denied/inaccessible installations, App permissions beyond read-only, rate limits, empty or unsupported repositories, repository size limits, branch changes, and scan failures. API responses contain safe messages and do not expose GitHub response bodies, access tokens, or stack traces.

## SSE format

Each event is JSON with the persisted scan event ID, `event_type`, `stage`, `message`, `timestamp`, and metadata. The stream emits only events recorded by the scan worker; it does not synthesize progress in the browser. `Last-Event-ID` can resume event delivery.

## Verification

`tests/test_github_integration.py` mocks OAuth exchange, user profile, installation list, installed repositories, branches, tree/blob reads, and token revocation. Tests verify browser-bound one-use state, encrypted token persistence, install-versus-authorize behavior, exact commit mapping, AI review input boundaries, and cross-user scan isolation. No live GitHub credentials are required for the automated test suite.
