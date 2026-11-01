# AuthScope — Dual Project Connection Architecture & Implementation

AuthScope supports a dual-path onboarding architecture allowing users to connect applications via two distinct, hardened workflows:

1. **Option 1: Connect GitHub** (OAuth App / GitHub App authorization for repository source & API inspection)
2. **Option 2: Add Website URL** (Direct deployed website or staging API testing with ScopeGuard & Anti-SSRF defenses)

---

## 1. Architectural Overview

```mermaid
flowchart TD
    User["User clicks 'Add Project'"] --> Modal["AddProjectModal"]

    subgraph Option1 ["Option 1: Connect GitHub"]
        Modal -->|Tab 1| GHStart["Initiate OAuth (/api/github/connect)"]
        GHStart -->|Redirect| GHOAuth["GitHub Authorization & App Installation"]
        GHOAuth -->|Callback with CSRF State| GHCallback["Callback (/api/github/callback)"]
        GHCallback -->|Encrypt Token with Fernet| GHSQLite[("SQLite (github_connections)")]
        GHSQLite -->|List Repositories (Public & Private)| GHRepos["Repository & Branch Selection"]
        GHRepos -->|Create Project| GHProj["ProjectRecord (type='github')"]
    end

    subgraph Option2 ["Option 2: Add Website URL"]
        Modal -->|Tab 2| WebInput["Website / API URL Input"]
        WebInput -->|Validate| SSRFCheck["Safe DNS Resolution & Anti-SSRF (/api/projects/validate-url)"]
        SSRFCheck -->|Verify Boundaries| ScopeGuardCheck["ScopeGuard & IP Block Check"]
        ScopeGuardCheck -->|Confirm Authority| AuthCheck["Explicit Authorization Confirmation"]
        AuthCheck -->|Create & Bind Target| WebProj["ProjectRecord (type='website')"]
        WebProj -->|Trigger Scan| Engine["AssessmentEngine Streaming Scan"]
    end
```

---

## 2. Option 1: Connect GitHub

### Workflow & User Experience
1. **User-Scoped Authorization:** Each user authorizes their own GitHub account. AuthScope never uses a shared developer personal access token (PAT) to access users' private repositories.
2. **Repository Listing & Privacy Separation:** Once authorized, the user sees their installations and all granted repositories. Private repositories are visually badged with a lock icon (`Private`), while public repositories show a globe icon (`Public`).
3. **Branch Selection:** Users can select any branch (e.g., `main`, `master`, `staging`) before creating the project and starting a scan.
4. **Revocation & Disconnection:** Users can disconnect their GitHub account anytime using the Disconnect action (`DELETE /api/github/disconnect`). This removes credentials and active sessions from SQLite and revokes the grant on the GitHub API.

### Credential & Token Security
- **Zero Frontend Exposure:** GitHub OAuth access tokens and refresh tokens are **never** returned to the browser, JavaScript, or localStorage.
- **Server-Side Encryption:** All tokens are encrypted at rest using AES-128 CBC / HMAC (Fernet) via `backend.config.settings.github_token_encryption_key`.
- **CSRF State Defense:** OAuth state parameters are single-use cryptographically random tokens (`secrets.token_urlsafe(32)`), stored in SQLite with a 10-minute expiry, and verified against a secure `authscope_github_state` HttpOnly cookie.
- **Access Log Scrubbing:** A custom log filter (`_GitHubCallbackAccessLogFilter`) scrubs `code` and `state` parameters from server access logs.

---

## 3. Option 2: Add Website URL

### Workflow & User Experience
1. **No GitHub Credentials Required:** Users can test deployed staging environments, APIs, or local test apps without connecting GitHub.
2. **Real-time DNS & Scope Verification:** Users can click "Verify Scope & DNS" to validate URL syntax, confirm connectivity, and check resolved IPs before submitting.
3. **Explicit Authorization Gate:** To protect against unauthorized testing, users must check the explicit authorization confirmation box and select their legal grounds (Admin Approved, Written Permission, Domain Ownership Challenge, or Bug Bounty Scope).
4. **Immediate Assessment Launch:** On creation, the target URL is registered and approved in `TargetRegistry`, enabling `ScopeGuard` to authorize automated crawling and authorization diff tests.

### Anti-SSRF & Network Defense
AuthScope enforces multi-layered SSRF and DNS rebinding protections:
1. **Prohibited Schemes:** Only `http` and `https` schemes are permitted. Dangerous schemes (`file`, `gopher`, `ftp`, `ldap`, `javascript`, `data`) are strictly rejected.
2. **Prohibited Credentials:** URLs containing embedded user credentials (`http://user:pass@host`) are blocked.
3. **Cloud Metadata IMDS Blocking:** Hostnames and IPs matching cloud metadata services (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200`, `fd00:ec2::254`) are immediately rejected.
4. **Private IP Range Defense:** Non-loopback private networks (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, RFC 3927: `169.254.0.0/16`, RFC 4193: `fc00::/7`, `fe80::/10`) are rejected for remote scans.
5. **DNS Rebinding Prevention:** Target hostnames are fully resolved to all IPv4/IPv6 addresses via `socket.getaddrinfo`, and every resolved address is checked against private and metadata blocklists.

---

## 4. API Specification

| Endpoint | Method | Description | Security Controls |
| :--- | :--- | :--- | :--- |
| `/api/projects/validate-url` | `POST` | Safely evaluates URL syntax, resolves DNS, and runs anti-SSRF checks | No outbound HTTP egress; validates IP ranges & metadata |
| `/api/projects` | `POST` | Creates a new GitHub or Website project | Enforces explicit authorization on website targets; requires active OAuth session for GitHub |
| `/api/projects` | `GET` | Lists projects owned by the requesting user | User ownership isolation |
| `/api/projects/{project_id}` | `GET` | Retrieves project details | Returns 403 Forbidden if accessed by another user |
| `/api/projects/{project_id}` | `DELETE` | Deletes a project | Returns 403 Forbidden if requested by non-owner |
| `/api/projects/{project_id}/scan` | `POST` | Triggers a security scan for the project | Ownership verified; starts assessment engine or GitHub scanner |

---

## 5. Automated Verification Results

All tests pass cleanly in `tests/test_dual_project_connection.py`:
- `test_validate_url_ssrf_cloud_metadata_rejection`: **PASSED** (Rejects `169.254.169.254` and `metadata.google.internal`)
- `test_validate_url_ssrf_private_ip_rejection`: **PASSED** (Rejects `192.168.1.1`, `10.0.0.5`, `172.16.0.1`)
- `test_validate_url_dangerous_schemes_and_credentials_rejection`: **PASSED** (Rejects `file://`, `ftp://`, userinfo)
- `test_validate_url_valid_target_resolution`: **PASSED** (Normalizes URL and verifies loopback)
- `test_create_website_project_requires_explicit_authorization`: **PASSED** (Rejects when confirmation is missing)
- `test_project_ownership_isolation`: **PASSED** (403 Forbidden on cross-user read/scan/delete)
- `test_github_project_requires_oauth_connection`: **PASSED** (401 Unauthorized when unauthenticated)
- `test_github_oauth_csrf_and_token_secrecy`: **PASSED** (Single-use CSRF state; zero token leakage in responses)
- `test_website_project_scan_launch`: **PASSED** (Successfully launches assessment for authorized project)

**Full Test Suite Summary:** 693 passed, 0 failed.

