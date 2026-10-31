# Frontend implementation status

## GitHub source scanning

The main assessment screen includes `GitHubCodeScanPanel`, wired to the implemented FastAPI GitHub App endpoints. It supports:

- GitHub user authorization and connected-account display.
- Separate GitHub App installation/repository authorization.
- Accessible installation repositories, visibility and description, branch selection, and branch commit SHA.
- Commit-pinned source scan creation and the real source-scan SSE activity stream.
- Per-user scan history and commit-specific report loading.
- Static source finding cards with source locations, exact GitHub commit links, AI explanations when available, copyable fixes, and an explicit `Runtime NOT TESTED` label.
- Disconnect, reconnect, installation update, and readable configuration/permission/rate-limit/scan errors.

## Verified local URLs

- Next.js dev/start scripts bind port `3001`.
- FastAPI run instructions bind port `8000`.
- Default GitHub callback: `http://localhost:8000/api/github/callback`.
- Default frontend origin: `http://localhost:3001`.

Live OAuth still requires a GitHub App configured with the callback/setup URL and backend-only App credentials, slug, and Fernet key. The checked-in `.env.example` contains empty secret fields. Mocked integration tests do not use real credentials.
