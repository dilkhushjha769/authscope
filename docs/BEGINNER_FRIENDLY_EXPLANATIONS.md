# Beginner-friendly finding explanations

## How the report is built

The assessment API now adds a `beginner_explanation` object to every detailed finding. It is assembled from the security engine's validation state, captured role context, request method and endpoint, observed behavior, and engine severity. It distinguishes confirmed results from suspicious, unverified, or correctly denied results. When evidence is missing or incomplete, it says that more evidence is needed and does not describe an attack as successful.

The explanation includes a short title, plain-language problem statement, evidence-limited attacker scenario and impact, numbered fix steps, safe verification steps, recommendations, and a list of facts not established by the test. Engine severity and confirmation status are preserved. Code examples remain empty unless actual language/framework and root cause are verified; this implementation does not guess a code patch.

## User interface

The Next.js findings card puts the plain-language explanation first and labels the engine's risk and confirmation status. It has a copy-fix button and puts endpoint, role, source, and HTTP evidence under a collapsed **Technical details** section. The final assessment panel summarizes confirmed and investigating results, the highest-risk confirmed issue, its possible effect, the first fix, and key recommendations.

## AI and evidence boundaries

The deterministic, evidence-grounded explanation is always available. When an approved Gemini provider is injected and returns a valid `LIKELY_REAL` review for an engine-confirmed finding, the API may use its beginner narrative fields while retaining engine status, severity, and the deterministic list of unproven claims. Other AI verdicts do not supply the user-facing attack description. The provider is disabled in the default runner because current repository policy prohibits external model egress. No secret is added to model context; review input uses redacted, scope-checked evidence. No recommendation is automatically applied.

## Verification

Backend tests cover confirmed, suspicious, false-positive, and evidence-missing results, unsupported impact claims, code-example suppression, and serialization when no model response exists. Result: `586 passed, 5 warnings` for the full backend suite. Frontend `npm run lint` and `npm run build` both pass.
