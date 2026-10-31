# GitHub App integration

## Local development settings

The project runs Next.js at `http://localhost:3001` (`frontend/package.json`) and FastAPI at `http://127.0.0.1:8000` (`docs/BACKEND_IMPLEMENTATION_STATUS.md`). Use the same `localhost` host for browser and callback URLs:

```dotenv
GITHUB_CALLBACK_URL=http://localhost:8000/api/github/callback
FRONTEND_URL=http://localhost:3001
GITHUB_APP_SLUG=your-github-app-slug
GITHUB_CLIENT_ID=your-app-client-id
GITHUB_CLIENT_SECRET=your-app-client-secret
GITHUB_TOKEN_ENCRYPTION_KEY=generated-fernet-key
GITHUB_SESSION_COOKIE_SECURE=false
```

Generate a Fernet key locally with:

```powershell
.venv/Scripts/python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Put real values in the ignored root `.env` or your secret manager. Do not commit them, print them, or put client credentials in `NEXT_PUBLIC_*` variables. Back up the encryption key securely; losing it makes stored GitHub authorizations unreadable. Changing it requires users to reconnect.

In the GitHub App settings, grant **Metadata: read-only** and **Contents: read-only**, enable user authorization, set the user authorization callback URL to `GITHUB_CALLBACK_URL`, and set the App setup URL to that same callback URL. `GITHUB_APP_SLUG` is the App's URL slug. Add `FRONTEND_URL` to `CORS_ORIGINS` if it differs from the local default. The Next.js API base defaults to `http://localhost:8000` in `frontend/src/app/page.tsx`.

Authorization and installation are separate: users first authorize AuthScope, then choose where to install the App and which repositories it may read. AuthScope uses the GitHub App user access token to list the user's App installations and each installation's accessible repositories. It does not infer installation access from OAuth alone and does not need an App private key for these user-token API calls. Source access is limited to repositories returned for the selected installation.

The backend supports expiring user access tokens and refreshes them server-side. The opaque browser session cookie is HTTP-only, SameSite=Lax, and stores only a hash server-side. OAuth state is random, short-lived, one-use, hash-stored, and bound to an HTTP-only browser cookie.

## API routes

- `GET /api/github/connect` starts the authorization code flow.
- `GET /api/github/callback` handles OAuth and the App setup callback.
- `GET /api/github/status` returns the connected account and accessible installations.
- `GET /api/github/install` redirects to GitHub's App installation page.
- `GET /api/github/installations/{installation_id}/repositories` lists installed repositories.
- `GET /api/github/installations/{installation_id}/repositories/{owner}/{repository}/branches` lists branches and commit SHAs.
- `POST /api/github/scans` starts a scan pinned to the selected branch's current commit.
- `GET /api/github/scans/{scan_id}/stream` emits real `activity`, `done`, and `error` SSE events.
- `GET /api/github/scans` and `GET /api/github/scans/{scan_id}` return the caller's scan history and report.
- `DELETE /api/github/disconnect` revokes the GitHub App user authorization when possible, deletes local tokens, sessions, installations, and scans, and clears the browser session.

All connection, installation, scan, and event records are scoped to the numeric GitHub user ID. The client secret and access/refresh tokens are backend-only. Tokens are encrypted with Fernet before SQLite storage. Disconnect also deletes local data; if GitHub is unavailable during revocation, the UI tells the user the local connection was deleted and they may revoke the App from GitHub settings.

Disconnect revokes the user's App authorization. It does not uninstall the GitHub App from an organization or account; users can remove or change repository installation access in GitHub's App settings.

## GitHub API egress

GitHub calls use fixed HTTPS origins (`github.com` for OAuth and `api.github.com` for REST), disable redirects, and pass a dedicated `ScopeGuard` configured for those exact hosts, port 443, and the required GET/POST/DELETE methods. This provider allowlist is separate from the target allowlist used by the security assessment engine. The app rejects any other hostname; repository URLs and API paths are built from validated route parameters and API-returned identifiers.

The integration uses GitHub's official [GitHub App user access token flow](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app), [installation repository listing API](https://docs.github.com/en/rest/apps/installations#list-repositories-accessible-to-the-user-access-token), and [authorization revocation API](https://docs.github.com/en/rest/apps/oauth-applications#delete-an-app-authorization).

## Local configuration observed during implementation

The checked-in project defaults and local `.env` do not currently configure GitHub client credentials, App slug, or Fernet key. Callback and frontend URLs default to the verified local ports above. Automated tests mock GitHub and Gemini. Real OAuth cannot complete until the App settings and backend `.env` values are populated.
