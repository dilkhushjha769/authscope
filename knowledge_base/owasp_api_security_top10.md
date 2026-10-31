# OWASP API Security Top 10 (2023)

## Overview

The OWASP API Security Top 10 identifies the most critical security risks to APIs. Understanding these risks helps developers build secure APIs and helps security engineers test for authorization vulnerabilities.

## API1:2023 — Broken Object Level Authorization (BOLA / IDOR)

APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface for Object-Level Access Control issues. Object-level authorization checks should be considered in every function that accesses a data source using an ID from the user.

**Root cause:** The server trusts client-supplied identifiers without checking ownership.

**Example:** `GET /api/orders/1234` returns Order 1234 regardless of which user is authenticated.

**Fix:** Always validate that the authenticated user owns or is authorized to access the object.

## API2:2023 — Broken Authentication

Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or exploit implementation flaws to assume other users' identities.

**Root cause:** Weak token validation, missing expiry checks, or insecure credential storage.

**Fix:** Use standard authentication libraries, enforce token expiry, and implement proper credential hashing.

## API3:2023 — Broken Object Property Level Authorization (Mass Assignment)

APIs expose endpoints that accept user-supplied data and map it directly to object properties without filtering. Attackers can use this to modify object properties they should not have access to.

**Root cause:** Missing allowlists of writable fields; accepting all input fields.

**Fix:** Define explicit allowlists of fields users may modify. Reject unrecognized fields.

## API4:2023 — Unrestricted Resource Consumption

APIs that do not impose limits on request size, query complexity, or operation counts are vulnerable to denial-of-service attacks and resource exhaustion.

**Fix:** Implement rate limiting, payload size limits, and query complexity restrictions.

## API5:2023 — Broken Function Level Authorization (BFLA)

Complex access control policies with different hierarchies and groups lead to authorization flaws. Administrative functions reachable by regular users represent critical vulnerabilities.

**Root cause:** Relying on UI hiding instead of server-side role enforcement.

**Fix:** Implement RBAC middleware on every route. Default-deny all administrative endpoints.

## API6:2023 — Unrestricted Access to Sensitive Business Flows

APIs expose business flows such as buying tickets or posting reviews without additional protection against excessive automated use.

**Fix:** Implement CAPTCHA, rate limiting per action, and anomaly detection.

## API7:2023 — Server-Side Request Forgery (SSRF)

SSRF flaws occur when APIs fetch remote resources based on user-supplied URLs without validating or sanitizing them.

**Fix:** Validate and allowlist target URLs. Use a network-layer egress filter.

## API8:2023 — Security Misconfiguration

APIs are often misconfigured — unnecessary HTTP methods enabled, permissive CORS, default credentials unchanged.

**Fix:** Harden all configurations, disable unused methods, review CORS policies.

## API9:2023 — Improper Inventory Management

Organizations often expose outdated API versions or debug endpoints unintentionally.

**Fix:** Maintain an up-to-date API inventory. Retire deprecated versions. Monitor for unauthorized endpoints.

## API10:2023 — Unsafe Consumption of APIs

Developers often trust third-party API data without sufficient validation, making their applications vulnerable to injection and other attacks originating from the third-party.

**Fix:** Validate and sanitize all data received from third-party APIs. Do not grant them excessive trust.

