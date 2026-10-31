# GitHub integration setup

## Current status

The assessment page now shows a GitHub connection setup card under **Add source code (optional)**. It is an honest setup state: this backend does not yet expose OAuth, repository listing, branch listing, or disconnect APIs. Entering a repository URL in the existing source-context field does not authenticate to GitHub or download repository contents. Use a source archive when you want the existing local source analyzer to inspect code.

## What the deployment owner needs to configure

Before enabling a real account connection, the deployment needs an approved GitHub App integration and corresponding backend APIs:

1. Create a GitHub App and set its callback URL to the deployed backend's OAuth callback route.
2. Grant repository **Metadata: read-only** and **Contents: read-only** permissions. Do not request write permissions.
3. Enable user authorization so each user grants access to repositories they can already access.
4. Add the App ID, client ID, client secret, private key, and a dedicated token-encryption key to the backend's secret manager/environment. Never commit them or send them to the browser.
5. Explicitly review and amend the deployment's outbound network policy for the GitHub OAuth and API hosts. AuthScope's current hard egress rule permits only configured assessment targets; the GitHub feature must have an explicit, narrowly scoped provider exception before it can make requests.
6. Implement and deploy OAuth state/CSRF validation, encrypted token storage, per-user repository and branch APIs, commit-pinned source retrieval, disconnect/revoke, rate limiting, and audit-safe redaction.

After those backend APIs are available, the page can start OAuth, list only the connected user's repositories and branches, and launch a scan pinned to the selected commit SHA. Do not paste a GitHub password or personal access token into AuthScope.

## Authorization and privacy

The intended integration is read-only. Tokens must remain on the backend, be encrypted at rest, never appear in API responses/logs, and be deleted when a user disconnects. Repository access must be revalidated for each operation. Repository files are untrusted input and must never be executed or treated as AI instructions.
