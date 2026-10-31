# Fix verification

AuthScope verifies an existing finding by replaying the signed finding evidence as a differential `GET` request. The original endpoint and resource identifier are reused; AuthScope does not infer resource ownership or generate replacement credentials. The current assessment target and the exact evidence URL are checked through `ScopeGuard` before any request. Redirects remain disabled in the shared request executor.

## Result meanings

| Result | Deterministic requirement |
| --- | --- |
| `FIXED` | Owner baseline returns usable protected data and the original test identity is denied by the differential analyzer. A denial status alone is insufficient. |
| `STILL VULNERABLE` | Owner baseline is usable and the differential analyzer plus validated evidence confirm unauthorized access. |
| `PARTIALLY FIXED` | The original route is denied, but a related inventory route confirms the same unauthorized access using the same verified resource owner and test role. |
| `INCONCLUSIVE` | Evidence is incomplete, baseline is unusable, or the differential result is suspicious/ambiguous. |
| `NOT_TESTED` | Finding/evidence is unavailable, the vector is not GET, sessions are unavailable, or scope blocks execution. |

Only the deterministic authorization tester assigns security verdicts. The displayed plain-language explanation is generated from that verdict and its captured evidence; it is not a Gemini-generated security decision. No external model request is made by this feature.

## Evidence and history

Each attempt stores the original endpoint, role pair, response status, and original evidence hash alongside the new per-role response status, sanitized excerpt, response hash, differential verdict, and regression-check disposition. Retest history is keyed to the finding, and API history routes verify that the finding belongs to the requested assessment. The finding's original confirmation status is preserved; only its retest timestamp and latest retest status are updated.

## Limits

Automatic related-endpoint checks are limited to three discovered `GET` routes in the same resource category. The owner session must explicitly own the original resource, and each route is revalidated through `ScopeGuard`; routes without explicit ownership controls remain `NOT_TESTED`. This is safer than treating a 403/404 or an unverified sibling endpoint as proof of a fix. Fix verification never edits application source or deploys changes.
