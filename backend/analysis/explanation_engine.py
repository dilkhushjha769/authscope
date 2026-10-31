"""Explanation Engine — Phase 5.3.

Generates structured, human-readable security explanations for every FindingRecord.
Explanations are derived exclusively from supplied findings and validated evidence;
no vulnerability is fabricated or inferred beyond the supplied data.

Ownership: Member 3 (Frontend & UI/UX + Explanation Engine).

Key guarantees:
- Simple English explanations, readable by beginner developers.
- Technical explanations alongside simple ones (both always present).
- Confirmation status accurately reflects evidence quality (CONFIRMED requires 2xx + evidence).
- Secrets (JWTs, Bearer tokens, passwords, API keys) are stripped before inclusion.
- Code examples are always flagged `is_illustrative=True` — never claimed as actual source.
- All function signatures carry 100% type annotations (Python 3.10+).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from backend.analysis.evidence_validator import EvidenceValidator
from backend.analysis.code_mapper import CodeMapper, MappingStatus
from backend.storage.models import EvidenceArtifact, EvidenceValidationStatus, FindingRecord
from backend.utils.helpers import AuthScopeException, redact_sensitive_text
from backend.utils.logger import get_logger

logger = get_logger(__name__)


# ==============================================================================
# Enumerations
# ==============================================================================


class ExplanationValidationStatus(str, Enum):
    """Validation status reflected in an explanation report.

    Maps directly from EvidenceValidationStatus and confirmation_status, but is
    kept separate so the explanation layer never mutates upstream models.
    """
    CONFIRMED = "CONFIRMED"
    SUSPICIOUS = "SUSPICIOUS"
    UNVERIFIED = "UNVERIFIED"
    CORRECTLY_DENIED = "CORRECTLY_DENIED"


class ExplanationConfidenceLevel(str, Enum):
    """Confidence in the explanation's accuracy, inferred from evidence quality."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ==============================================================================
# Pydantic Output Models
# ==============================================================================


class CodeExample(BaseModel):
    """Code example pair (vulnerable vs. corrected).

    When backed by verified source code via CodeMapper, ``is_illustrative`` is False
    and ``source_location`` specifies the exact file and lines.
    Otherwise, ``is_illustrative`` is True and represents an educational illustration.
    """
    model_config = ConfigDict(extra="forbid")

    is_illustrative: bool = Field(
        True,
        description="Whether this is an educational illustrative example (True) or actual verified source code (False).",
    )
    language: str = Field("python", description="Programming language of the example.")
    vulnerable_code: str = Field(..., description="Example of code that contains the vulnerability.")
    explanation_of_problem: str = Field(
        ..., description="Plain-English explanation of why the code is insecure."
    )
    corrected_code: str = Field(..., description="Corrected version of the same code snippet.")
    explanation_of_fix: str = Field(
        ..., description="Plain-English explanation of why the corrected version is secure."
    )
    source_location: Optional[str] = Field(
        None, description="Verified file path and line numbers if mapped from actual source."
    )
    snippet_provenance: Optional[str] = Field(
        None, description="Provenance of the snippet: 'ACTUAL_VERIFIED_SOURCE' or 'ILLUSTRATIVE_EXAMPLE'."
    )


class SimpleExplanation(BaseModel):
    """Beginner-friendly narrative explanation of a finding."""
    model_config = ConfigDict(extra="forbid")

    what_happened: str = Field(
        ...,
        description="One-paragraph, jargon-free description of what the test observed.",
    )
    why_is_this_a_problem: str = Field(
        ...,
        description="Why this behaviour is a security problem, in simple terms.",
    )
    what_could_an_attacker_do: str = Field(
        ...,
        description="Realistic attacker scenarios described without technical jargon.",
    )
    how_can_a_developer_fix_it: str = Field(
        ...,
        description="Actionable remediation advice written for a junior developer.",
    )
    glossary: Dict[str, str] = Field(
        default_factory=dict,
        description="Definitions of technical terms used in the explanation.",
    )


class TechnicalExplanation(BaseModel):
    """Technical narrative for security engineers and senior developers."""
    model_config = ConfigDict(extra="forbid")

    vulnerability_class: str = Field(..., description="OWASP / CWE vulnerability class.")
    what_happened: str = Field(
        ..., description="Precise technical description of the observed behaviour."
    )
    root_cause: str = Field(
        ..., description="Root-cause analysis at the protocol / code level."
    )
    attacker_impact: str = Field(
        ..., description="Technical impact in terms of CIA triad and privilege boundaries."
    )
    remediation_guidance: str = Field(
        ..., description="Code-level and architecture-level remediation guidance."
    )
    cwe_reference: str = Field("", description="CWE identifier where applicable.")
    owasp_reference: str = Field("", description="OWASP Top-10 / API Security Top-10 reference.")


class EvidenceSummary(BaseModel):
    """Sanitized evidence fields preserved in the explanation report."""
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field("", description="Unique evidence artifact ID.")
    endpoint: str = Field("", description="Endpoint under test.")
    http_method: str = Field("GET", description="HTTP method used.")
    testing_role: str = Field("", description="Role that executed the unauthorized probe.")
    authorized_role: str = Field("", description="Role that legitimately owns the resource.")
    resource_id: Optional[str] = Field(None, description="Tested resource identifier.")
    expected_behavior: str = Field("", description="Expected authorization enforcement behavior.")
    actual_behavior: str = Field("", description="Observed differential discrepancy behavior.")
    response_status: int = Field(0, description="HTTP response status code received.")
    sanitized_response_excerpt: str = Field(
        "", description="Redacted excerpt from the response body."
    )
    evidence_sha256: str = Field("", description="Integrity hash of the evidence artifact.")
    evidence_validation_status: str = Field("", description="Artifact integrity status.")
    validation_status: str = Field("", description="Evidence validation classification.")
    redacted_fields: List[str] = Field(
        default_factory=list, description="Fields that were sanitized."
    )
    source_location: Optional[str] = Field(
        None, description="Preserved source location if mapped or provided."
    )
    snippet_provenance: Optional[str] = Field(
        None, description="Provenance of code snippet ('ACTUAL_VERIFIED_SOURCE', 'ILLUSTRATIVE_EXAMPLE', or 'UNAVAILABLE')."
    )
    timestamp: str = Field("", description="UTC timestamp of evidence collection.")


class ExplanationReport(BaseModel):
    """Full structured explanation for a single FindingRecord.

    Contains all 11 required fields from the Phase 5.3 specification.
    """
    model_config = ConfigDict(extra="forbid")

    # ── Core identification (fields 1–4) ──────────────────────────────────────
    vulnerability_name: str = Field(..., description="Human-readable vulnerability title.")
    severity: str = Field(..., description="Severity tier: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL.")
    confidence: ExplanationConfidenceLevel = Field(
        ..., description="Confidence level inferred from evidence quality."
    )
    validation_status: ExplanationValidationStatus = Field(
        ..., description="Validation status of the finding."
    )

    # ── Narrative layers (fields 5–9) ─────────────────────────────────────────
    simple_explanation: SimpleExplanation = Field(
        ..., description="Beginner-friendly narrative explanation."
    )
    technical_explanation: TechnicalExplanation = Field(
        ..., description="Technical narrative for security engineers."
    )

    # ── Location (field 6 subset) ─────────────────────────────────────────────
    where_was_it_found: str = Field(
        ..., description="Endpoint and HTTP method where the vulnerability was observed."
    )
    source_location: Optional[str] = Field(
        None, description="Verified source location if available from CodeMapper."
    )
    snippet_provenance: Optional[str] = Field(
        None, description="Provenance of code representation."
    )

    # ── Code example (field 10) ───────────────────────────────────────────────
    code_example: Optional[CodeExample] = Field(
        None,
        description="Vulnerable/corrected code pair with illustrative or verified source flags.",
    )

    # ── Evidence (field 11) ───────────────────────────────────────────────────
    evidence_summary: Optional[EvidenceSummary] = Field(
        None, description="Sanitized evidence artifact summary."
    )

    # ── Metadata ──────────────────────────────────────────────────────────────
    finding_id: str = Field("", description="Original FindingRecord ID.")
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="UTC ISO-8601 timestamp when this report was generated.",
    )
    disclaimer: str = Field(
        "This report was generated from supplied finding data only. "
        "Code examples are illustrative and do not represent actual target source code.",
        description="Mandatory disclaimer reminding consumers that examples are illustrative.",
    )


class BeginnerExplanation(BaseModel):
    """Plain-language summary grounded in one finding and its captured evidence."""

    model_config = ConfigDict(extra="forbid")

    simple_title: str
    technical_name: str
    risk_level: str
    risk_description: str
    confirmation_status: str
    what_is_the_problem: str
    what_attacker_can_do: str
    real_world_impact: str
    why_it_matters: str
    how_to_fix: List[str] = Field(default_factory=list)
    secure_code_example: Optional[str] = None
    how_to_verify_fix: List[str] = Field(default_factory=list)
    additional_recommendations: List[str] = Field(default_factory=list)
    evidence_summary: List[str] = Field(default_factory=list)
    what_is_not_yet_proven: List[str] = Field(default_factory=list)


# ==============================================================================
# Narrative Template Maps
# ==============================================================================

# Maps VulnerabilityType value → (simple_what_happened, glossary_terms)
_VULN_SIMPLE_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "BOLA_IDOR": {
        "what_happened": (
            "The test discovered that one user can access another user's private data by simply "
            "changing a number (called an ID) in the web address. For example, a URL like "
            "`/api/basket/1` should only be readable by the user who owns basket number 1. "
            "However, our test showed that a different user account could also read — or modify — "
            "that basket without any error. This is called a Broken Object-Level Authorisation "
            "(BOLA) or Insecure Direct Object Reference (IDOR) vulnerability."
        ),
        "why_is_this_a_problem": (
            "Every user should only be able to see and modify their own data. If any user can "
            "access any other user's data just by guessing or changing an ID number, privacy is "
            "broken. Sensitive information such as personal details, purchase history, or account "
            "settings can be stolen."
        ),
        "attacker_impact": (
            "An attacker could write a simple script that requests data for IDs 1, 2, 3, … and "
            "collect private information belonging to thousands of users. This can lead to account "
            "takeover, identity theft, or financial fraud."
        ),
        "fix": (
            "When a user requests a resource (like `/api/basket/1`), always check — on the "
            "server — that the user who is logged in actually owns resource number 1. Never rely "
            "solely on the ID in the URL. A check like `if basket.owner_id != current_user.id: "
            "return 403` prevents this attack."
        ),
        "glossary": {
            "BOLA": "Broken Object-Level Authorisation — a vulnerability where users can access "
                    "objects belonging to other users.",
            "IDOR": "Insecure Direct Object Reference — the same issue described from the "
                    "attacker's perspective: using a reference (like an ID) to reach data "
                    "they should not see.",
            "403": "An HTTP status code meaning 'Forbidden' — the server understood the request "
                   "but refuses to authorise it.",
        },
        "cwe": "CWE-639: Authorization Bypass Through User-Controlled Key",
        "owasp": "OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization",
        "vuln_class": "Broken Object-Level Authorization (BOLA / IDOR)",
        "root_cause": (
            "The application uses an attacker-controlled identifier (path parameter, query "
            "parameter, or request body field) to retrieve or modify a record without verifying "
            "that the authenticated principal is the authorised owner of that record."
        ),
        "tech_attacker_impact": (
            "Horizontal privilege escalation: any authenticated user can read or mutate records "
            "belonging to other users. Depending on the endpoint, this may violate "
            "confidentiality (data leakage), integrity (unauthorised modification), or both."
        ),
        "tech_remediation": (
            "Enforce row-level ownership checks in the service or repository layer. "
            "Validate `record.owner_id == authenticated_user.id` before returning or mutating "
            "any record. Use indirect references (opaque tokens mapped server-side) where "
            "possible. Apply the check at every access path — not just the primary CRUD route."
        ),
    },
    "BFLA": {
        "what_happened": (
            "The test found that a regular user account can perform actions that should be "
            "restricted to administrators — for example, accessing admin panels, deleting other "
            "users' accounts, or changing system settings. This is called a Broken Function-Level "
            "Authorisation (BFLA) vulnerability."
        ),
        "why_is_this_a_problem": (
            "Some features in an application are intended only for administrators or privileged "
            "users. If a regular user can reach these features, they gain control over parts of "
            "the system they were never meant to touch. This can result in complete system "
            "compromise."
        ),
        "attacker_impact": (
            "An attacker with a low-privilege account could promote themselves to admin, delete "
            "data, export all user records, or disable security features. In the worst case, "
            "this leads to a full takeover of the application."
        ),
        "fix": (
            "Every sensitive function or API route must check the caller's role before executing. "
            "For example: `if not current_user.is_admin: return 403`. Use a centralised "
            "authorisation middleware or decorator — never check roles inside individual "
            "business-logic functions only."
        ),
        "glossary": {
            "BFLA": "Broken Function-Level Authorisation — when a low-privilege user can call "
                    "functions meant only for higher-privilege roles.",
            "Role": "A label (e.g., 'admin', 'user') assigned to an account that determines "
                    "what actions it is allowed to perform.",
            "Middleware": "A layer of code that runs before the main request handler — a good "
                          "place to enforce role checks.",
        },
        "cwe": "CWE-862: Missing Authorization",
        "owasp": "OWASP API Security Top 10 — API5:2023 Broken Function Level Authorization",
        "vuln_class": "Broken Function-Level Authorization (BFLA)",
        "root_cause": (
            "Administrative or privileged API functions lack role-based access control (RBAC) "
            "enforcement at the framework, middleware, or route handler level. Authorisation is "
            "enforced only at the UI layer (hidden buttons), which is easily bypassed by "
            "crafting direct HTTP requests."
        ),
        "tech_attacker_impact": (
            "Vertical privilege escalation: a low-privilege principal can invoke administrative "
            "operations, potentially compromising confidentiality, integrity, and availability "
            "of the entire application and its data stores."
        ),
        "tech_remediation": (
            "Apply role-based access control at the API gateway or framework middleware layer. "
            "Every route exposing privileged operations must validate the authenticated "
            "principal's role before execution. Prefer allow-listing: 'only ADMIN may call this' "
            "over deny-listing. Audit all administrative endpoints in an automated test suite."
        ),
    },
    "MISSING_AUTH": {
        "what_happened": (
            "The test found that a sensitive endpoint can be accessed without any login or "
            "authentication token at all. Anyone — even someone with no account — can reach this "
            "endpoint and retrieve data or trigger actions."
        ),
        "why_is_this_a_problem": (
            "Protected resources should require the caller to prove who they are (authentication) "
            "before being served. Without authentication, there is no way to know if the caller "
            "is allowed to access the resource."
        ),
        "attacker_impact": (
            "Any person on the internet could access this endpoint with a simple browser request, "
            "exposing all data it returns or triggering all actions it performs — without needing "
            "an account."
        ),
        "fix": (
            "Require a valid authentication token (e.g., a JWT in the `Authorization` header) "
            "for every protected route. Return HTTP 401 if no valid token is present. Use a "
            "framework-level authentication guard applied globally, then opt-out only for "
            "genuinely public routes."
        ),
        "glossary": {
            "Authentication": "The process of verifying who is making a request (e.g., by "
                              "checking a username and password or a token).",
            "JWT": "JSON Web Token — a compact, signed string used to securely transmit identity "
                   "information.",
            "401": "HTTP status code meaning 'Unauthorised' — the server requires valid "
                   "credentials to respond.",
        },
        "cwe": "CWE-306: Missing Authentication for Critical Function",
        "owasp": "OWASP API Security Top 10 — API2:2023 Broken Authentication",
        "vuln_class": "Missing Authentication",
        "root_cause": (
            "The route or endpoint handler does not enforce an authentication prerequisite. "
            "Requests without a valid session token or credential are served as if authenticated."
        ),
        "tech_attacker_impact": (
            "Unauthenticated access: any network-reachable client can interact with the endpoint "
            "with no identity. Impact depends on the endpoint's function — data retrieval "
            "violates confidentiality; action endpoints may violate integrity or availability."
        ),
        "tech_remediation": (
            "Apply an authentication middleware or decorator globally, then explicitly whitelist "
            "genuinely public routes. Validate the `Authorization` header, verify JWT signature "
            "and expiry, and reject requests with HTTP 401 when tokens are absent or invalid."
        ),
    },
    "PRIVILEGE_ESCALATION": {
        "what_happened": (
            "The test found that a low-privilege user account can escalate its own privileges — "
            "for example, by modifying their account's role field through an API call — "
            "effectively becoming an administrator without any approval."
        ),
        "why_is_this_a_problem": (
            "Roles and permissions exist to control what each user can do. If users can change "
            "their own role, the entire permission system is undermined and every restricted "
            "feature becomes accessible."
        ),
        "attacker_impact": (
            "An attacker could grant themselves admin rights, then access all protected data, "
            "modify system settings, or lock out legitimate administrators."
        ),
        "fix": (
            "Never allow a user to modify their own role or privilege fields. Accept only the "
            "fields you explicitly allow in your API (an allow-list of writable attributes). "
            "Validate and strip any role/permission fields from incoming requests for non-admin "
            "callers."
        ),
        "glossary": {
            "Privilege Escalation": "When a user gains more permissions than they should have.",
            "Role": "A set of permissions assigned to a user account.",
            "Allow-list": "A list of fields or values that are explicitly permitted — "
                          "anything not on the list is rejected.",
        },
        "cwe": "CWE-269: Improper Privilege Management",
        "owasp": "OWASP API Security Top 10 — API3:2023 Broken Object Property Level Authorization",
        "vuln_class": "Privilege Escalation",
        "root_cause": (
            "The application accepts user-controlled privilege or role attributes and applies "
            "them without server-side validation of the caller's authority to make such changes."
        ),
        "tech_attacker_impact": (
            "Vertical privilege escalation through self-assignment: the attacker transitions from "
            "a low-privilege principal to a high-privilege one within a single API transaction, "
            "bypassing all RBAC controls downstream."
        ),
        "tech_remediation": (
            "Implement strict input allow-listing at the API deserialization layer. "
            "Strip, reject, or ignore any role/privilege/group fields in requests from "
            "non-administrative principals. Apply mass assignment protection (e.g., Pydantic "
            "field exclusions or framework-level read-only field enforcement)."
        ),
    },
    "MASS_ASSIGNMENT": {
        "what_happened": (
            "The test found that a user can send extra fields in an API request — fields they "
            "are not supposed to control, such as `is_admin: true` or `account_balance: 9999` — "
            "and the application applies these changes to the database without checking whether "
            "the user is allowed to modify those fields."
        ),
        "why_is_this_a_problem": (
            "APIs often accept JSON bodies and map them directly to database records. If the "
            "application does not carefully filter which fields a user is allowed to set, an "
            "attacker can manipulate fields they should never touch."
        ),
        "attacker_impact": (
            "An attacker could set `role: admin`, increase their account balance, unlock premium "
            "features, or mark their order as 'paid' without actually paying — by including "
            "extra fields in a routine API request."
        ),
        "fix": (
            "Define an explicit allow-list of fields that users are permitted to submit. "
            "Use separate input models (DTOs) that only expose allowed fields. Never map the "
            "entire incoming request body directly to your database model."
        ),
        "glossary": {
            "Mass Assignment": "A vulnerability where an attacker can set fields they should not "
                               "control by including them in an API request body.",
            "DTO": "Data Transfer Object — a model that exposes only the fields intended for "
                   "a specific API operation.",
        },
        "cwe": "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes",
        "owasp": "OWASP API Security Top 10 — API3:2023 Broken Object Property Level Authorization",
        "vuln_class": "Mass Assignment",
        "root_cause": (
            "The API endpoint directly maps incoming request body fields to internal data model "
            "attributes without enforcing an allow-list. Sensitive or privileged fields are not "
            "excluded from the deserialization step."
        ),
        "tech_attacker_impact": (
            "Attackers can set arbitrary object properties, potentially escalating privileges, "
            "bypassing payment controls, or corrupting data integrity by injecting values into "
            "fields that should be system-controlled."
        ),
        "tech_remediation": (
            "Use separate Pydantic schemas (or equivalent DTOs) for input and output. The input "
            "schema should only expose fields the caller is permitted to write. Apply schema "
            "validation at the API boundary before the data reaches the service or ORM layer. "
            "Never use `model.update(request.body)` patterns."
        ),
    },
    "MULTI_STEP_CHAIN": {
        "what_happened": (
            "The test identified a multi-step attack chain: a sequence of API calls that, when "
            "performed in a specific order, allows a user to reach a state or access data they "
            "should not be able to. No single step alone is vulnerable, but together they create "
            "a security gap."
        ),
        "why_is_this_a_problem": (
            "Security checks are sometimes only applied at the first step of a workflow. If "
            "subsequent steps assume the earlier check already passed, an attacker who enters "
            "the workflow mid-way — or manipulates state between steps — can bypass the check."
        ),
        "attacker_impact": (
            "An attacker could exploit the gap between workflow steps to access protected "
            "resources, perform privileged actions, or corrupt application state in ways not "
            "anticipated by the original design."
        ),
        "fix": (
            "Re-validate authorisation at every step of a multi-step workflow. Do not assume "
            "that because a user completed step 1 correctly they are allowed to proceed "
            "unchecked to step 3. Store authorisation decisions server-side (not in client-side "
            "state) and re-verify them at each transition."
        ),
        "glossary": {
            "Attack Chain": "A series of steps that individually appear harmless but together "
                            "create a security vulnerability.",
            "State": "The information an application stores about a user or session between "
                     "requests.",
        },
        "cwe": "CWE-285: Improper Authorization",
        "owasp": "OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization",
        "vuln_class": "Multi-Step Authorization Chain Vulnerability",
        "root_cause": (
            "Authorisation logic is applied inconsistently across workflow steps. Intermediate "
            "or terminal steps in a stateful operation assume that prior steps performed "
            "sufficient validation, creating exploitable gaps."
        ),
        "tech_attacker_impact": (
            "An attacker can exploit the inconsistent authorisation checkpoints to reach "
            "privileged states, access foreign resources, or manipulate workflow outcomes by "
            "injecting requests at unprotected transition points."
        ),
        "tech_remediation": (
            "Centralise authorisation logic outside of individual step handlers. Apply a "
            "consistent authorisation gate at each state transition. Use server-side session "
            "tokens to track authorised workflow progress — never trust client-provided step "
            "indicators. Write integration tests that validate every step boundary."
        ),
    },
}

_CODE_EXAMPLES: Dict[str, CodeExample] = {
    "BOLA_IDOR": CodeExample(
        is_illustrative=True,
        language="python",
        vulnerable_code=(
            "# ILLUSTRATIVE EXAMPLE — NOT actual target source code\n"
            "@app.get('/api/basket/{basket_id}')\n"
            "def get_basket(basket_id: int, current_user: User = Depends(get_current_user)):\n"
            "    basket = db.query(Basket).filter(Basket.id == basket_id).first()\n"
            "    return basket  # ❌ No ownership check!"
        ),
        explanation_of_problem=(
            "The handler fetches the basket using only the ID from the URL. It never checks "
            "whether `basket.owner_id` matches `current_user.id`. Any authenticated user can "
            "read any basket."
        ),
        corrected_code=(
            "# ILLUSTRATIVE EXAMPLE — NOT actual target source code\n"
            "@app.get('/api/basket/{basket_id}')\n"
            "def get_basket(basket_id: int, current_user: User = Depends(get_current_user)):\n"
            "    basket = db.query(Basket).filter(Basket.id == basket_id).first()\n"
            "    if basket is None:\n"
            "        raise HTTPException(status_code=404)\n"
            "    if basket.owner_id != current_user.id:  # ✅ Ownership check\n"
            "        raise HTTPException(status_code=403, detail='Forbidden')\n"
            "    return basket"
        ),
        explanation_of_fix=(
            "The corrected version explicitly compares the basket's stored owner ID with the "
            "currently authenticated user's ID. If they do not match, a 403 Forbidden response "
            "is returned immediately, preventing horizontal access."
        ),
    ),
    "BFLA": CodeExample(
        is_illustrative=True,
        language="python",
        vulnerable_code=(
            "# ILLUSTRATIVE EXAMPLE — NOT actual target source code\n"
            "@app.delete('/api/admin/users/{user_id}')\n"
            "def delete_user(user_id: int, current_user: User = Depends(get_current_user)):\n"
            "    db.query(User).filter(User.id == user_id).delete()\n"
            "    return {'deleted': user_id}  # ❌ No admin role check!"
        ),
        explanation_of_problem=(
            "The delete route is reachable by any authenticated user. There is no check that "
            "`current_user.role == 'admin'`, so a regular user can delete any account."
        ),
        corrected_code=(
            "# ILLUSTRATIVE EXAMPLE — NOT actual target source code\n"
            "@app.delete('/api/admin/users/{user_id}')\n"
            "def delete_user(user_id: int, current_user: User = Depends(require_admin)):\n"
            "    db.query(User).filter(User.id == user_id).delete()\n"
            "    return {'deleted': user_id}\n\n"
            "# require_admin dependency:\n"
            "def require_admin(current_user: User = Depends(get_current_user)) -> User:\n"
            "    if current_user.role != 'admin':  # ✅ Role check\n"
            "        raise HTTPException(status_code=403, detail='Admin only')\n"
            "    return current_user"
        ),
        explanation_of_fix=(
            "The corrected version uses a `require_admin` dependency injected into the route. "
            "This dependency verifies the caller's role before the handler runs, applying the "
            "role check consistently at the framework level."
        ),
    ),
    "MISSING_AUTH": CodeExample(
        is_illustrative=True,
        language="python",
        vulnerable_code=(
            "# ILLUSTRATIVE EXAMPLE — NOT actual target source code\n"
            "@app.get('/api/users/me')\n"
            "def get_my_profile():  # ❌ No authentication dependency!\n"
            "    user = db.query(User).first()\n"
            "    return user"
        ),
        explanation_of_problem=(
            "The route handler has no authentication dependency. Anyone who sends a GET request "
            "to `/api/users/me` receives user data without needing a token."
        ),
        corrected_code=(
            "# ILLUSTRATIVE EXAMPLE — NOT actual target source code\n"
            "@app.get('/api/users/me')\n"
            "def get_my_profile(\n"
            "    current_user: User = Depends(get_current_user)  # ✅ Authentication required\n"
            "):\n"
            "    return current_user"
        ),
        explanation_of_fix=(
            "Adding `Depends(get_current_user)` forces the framework to validate the "
            "`Authorization` header before the handler runs. If no valid token is present, "
            "the dependency raises HTTP 401 automatically."
        ),
    ),
    "PRIVILEGE_ESCALATION": CodeExample(
        is_illustrative=True,
        language="python",
        vulnerable_code=(
            "# ILLUSTRATIVE EXAMPLE — NOT actual target source code\n"
            "@app.put('/api/users/{user_id}')\n"
            "def update_user(user_id: int, body: dict, current_user: User = Depends(get_current_user)):\n"
            "    db.query(User).filter(User.id == user_id).update(body)  # ❌ body may contain role!\n"
            "    return {'updated': True}"
        ),
        explanation_of_problem=(
            "The handler passes the entire request body to the database update. If `body` "
            "contains `{'role': 'admin'}`, the database will update the user's role to admin."
        ),
        corrected_code=(
            "# ILLUSTRATIVE EXAMPLE — NOT actual target source code\n"
            "class UserUpdateSchema(BaseModel):\n"
            "    display_name: Optional[str] = None  # ✅ Only allowed fields\n"
            "    email: Optional[str] = None\n"
            "    # role is intentionally absent\n\n"
            "@app.put('/api/users/{user_id}')\n"
            "def update_user(\n"
            "    user_id: int,\n"
            "    body: UserUpdateSchema,  # ✅ Validated, limited schema\n"
            "    current_user: User = Depends(get_current_user)\n"
            "):\n"
            "    db.query(User).filter(User.id == user_id).update(body.model_dump(exclude_none=True))\n"
            "    return {'updated': True}"
        ),
        explanation_of_fix=(
            "Using `UserUpdateSchema` (a Pydantic model with only allowed fields) ensures "
            "that the `role` field is never included in the update payload, regardless of "
            "what the client sends."
        ),
    ),
    "MASS_ASSIGNMENT": CodeExample(
        is_illustrative=True,
        language="python",
        vulnerable_code=(
            "# ILLUSTRATIVE EXAMPLE — NOT actual target source code\n"
            "@app.post('/api/orders')\n"
            "def create_order(body: dict, current_user: User = Depends(get_current_user)):\n"
            "    order = Order(**body)  # ❌ body may contain is_paid=True!\n"
            "    db.add(order)\n"
            "    return order"
        ),
        explanation_of_problem=(
            "The `Order` model is constructed directly from the untrusted request body. "
            "An attacker can include `is_paid: true` to mark an order as paid without payment."
        ),
        corrected_code=(
            "# ILLUSTRATIVE EXAMPLE — NOT actual target source code\n"
            "class OrderCreateSchema(BaseModel):\n"
            "    product_id: int  # ✅ Only fields the user controls\n"
            "    quantity: int\n"
            "    # is_paid is intentionally absent; it is set server-side\n\n"
            "@app.post('/api/orders')\n"
            "def create_order(body: OrderCreateSchema, current_user: User = Depends(get_current_user)):\n"
            "    order = Order(\n"
            "        product_id=body.product_id,\n"
            "        quantity=body.quantity,\n"
            "        user_id=current_user.id,\n"
            "        is_paid=False,  # ✅ Set server-side, never from client\n"
            "    )\n"
            "    db.add(order)\n"
            "    return order"
        ),
        explanation_of_fix=(
            "Using `OrderCreateSchema` restricts the fields the client can supply. "
            "Fields like `is_paid` are set by the server after payment processing, "
            "not accepted from the client request."
        ),
    ),
    "MULTI_STEP_CHAIN": CodeExample(
        is_illustrative=True,
        language="python",
        vulnerable_code=(
            "# ILLUSTRATIVE EXAMPLE — NOT actual target source code\n"
            "@app.post('/api/checkout/step2')\n"
            "def checkout_step2(body: dict, current_user: User = Depends(get_current_user)):\n"
            "    # ❌ Assumes step 1 already validated ownership\n"
            "    basket_id = body['basket_id']\n"
            "    complete_checkout(basket_id)\n"
            "    return {'status': 'complete'}"
        ),
        explanation_of_problem=(
            "Step 2 of the checkout trusts the `basket_id` from the client without re-checking "
            "ownership. An attacker who skips step 1 can pass any `basket_id` and complete "
            "a checkout for a basket they do not own."
        ),
        corrected_code=(
            "# ILLUSTRATIVE EXAMPLE — NOT actual target source code\n"
            "@app.post('/api/checkout/step2')\n"
            "def checkout_step2(body: dict, current_user: User = Depends(get_current_user)):\n"
            "    basket_id = body['basket_id']\n"
            "    basket = db.query(Basket).filter(Basket.id == basket_id).first()\n"
            "    if basket is None or basket.owner_id != current_user.id:  # ✅ Re-check\n"
            "        raise HTTPException(status_code=403, detail='Forbidden')\n"
            "    complete_checkout(basket_id)\n"
            "    return {'status': 'complete'}"
        ),
        explanation_of_fix=(
            "The corrected version re-validates ownership at step 2. Even if the attacker "
            "bypasses step 1 entirely, they cannot complete the checkout for a basket they "
            "do not own."
        ),
    ),
}


# ==============================================================================
# ExplanationEngine
# ==============================================================================


class ExplanationEngineError(AuthScopeException):
    """Raised when the ExplanationEngine cannot generate a valid report."""


class ExplanationEngine:
    """Generates structured, evidence-backed explanations for security findings.

    Usage::

        engine = ExplanationEngine()
        report = engine.generate_explanation(finding)
        print(report.simple_explanation.what_happened)

    Invariants:
    - ``validation_status`` is CONFIRMED only when evidence has a 2xx response
      AND non-empty sanitized_response_evidence.
    - When verified code is available via CodeMapper, ``code_example.is_illustrative`` is False.
      Otherwise, ``code_example.is_illustrative`` is always True.
    - JWTs and Bearer tokens are stripped before inclusion in any report field.
    """

    def __init__(self, code_mapper: Optional[CodeMapper] = None) -> None:
        """Initializes the ExplanationEngine.

        Args:
            code_mapper: Optional CodeMapper instance to correlate findings with actual verified source code.
        """
        self.code_mapper = code_mapper

    def generate_explanation(self, finding: FindingRecord) -> ExplanationReport:
        """Generate a full ExplanationReport for the supplied FindingRecord.

        Args:
            finding: A validated FindingRecord from the database or scanner.

        Returns:
            ExplanationReport with all 11 required fields populated.

        Raises:
            ExplanationEngineError: If the finding lacks a non-empty endpoint.
        """
        if not finding.endpoint or not finding.endpoint.strip():
            raise ExplanationEngineError(
                "Cannot generate explanation: FindingRecord has no endpoint."
            )

        vuln_type: str = str(
            finding.vulnerability_type or finding.vulnerability_category or "BOLA_IDOR"
        ).upper()

        logger.info(
            "Generating explanation",
            extra={"finding_id": finding.id, "vuln_type": vuln_type},
        )

        validation_status = self._determine_validation_status(finding)
        confidence = self._determine_confidence(finding, validation_status)
        simple_exp = self._build_simple_explanation(finding, vuln_type)
        technical_exp = self._build_technical_explanation(finding, vuln_type)
        code_ex = self._build_code_example(vuln_type, finding)

        source_loc = code_ex.source_location if code_ex else None
        provenance = (
            code_ex.snippet_provenance
            if code_ex and code_ex.snippet_provenance
            else ("ACTUAL_VERIFIED_SOURCE" if source_loc else "ILLUSTRATIVE_EXAMPLE")
        )

        evidence_summary = self._integrate_evidence(
            finding, source_location=source_loc, snippet_provenance=provenance
        )

        disclaimer = (
            "Source code location verified against target repository."
            if (code_ex and not code_ex.is_illustrative)
            else (
                "This report was generated from supplied finding data only. "
                "Code examples are illustrative and do not represent actual target source code."
            )
        )

        report = ExplanationReport(
            vulnerability_name=finding.title or self._default_title(finding, vuln_type),
            severity=str(finding.severity.value if hasattr(finding.severity, "value") else finding.severity),
            confidence=confidence,
            validation_status=validation_status,
            simple_explanation=simple_exp,
            technical_explanation=technical_exp,
            where_was_it_found=(
                f"{finding.http_method.upper()} {finding.endpoint}"
            ),
            source_location=source_loc,
            snippet_provenance=provenance,
            code_example=code_ex,
            evidence_summary=evidence_summary,
            finding_id=finding.id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            disclaimer=disclaimer,
        )

        logger.info(
            "Explanation generated",
            extra={
                "finding_id": finding.id,
                "validation_status": validation_status.value,
                "confidence": confidence.value,
            },
        )
        return report

    def generate_beginner_explanation(self, finding: FindingRecord) -> BeginnerExplanation:
        """Build a concise, evidence-aware explanation without promoting a finding."""
        status = self._determine_validation_status(finding)
        confirmed = status == ExplanationValidationStatus.CONFIRMED
        category = str(finding.vulnerability_category or finding.vulnerability_type or "UNKNOWN").upper()
        technical_names = {
            "BOLA_IDOR": "Access to another user's record (BOLA / IDOR)",
            "BFLA": "Access to a restricted action (BFLA)",
            "MISSING_AUTH": "A protected page may not require sign-in",
            "PRIVILEGE_ESCALATION": "Access beyond the user's assigned role",
            "MASS_ASSIGNMENT": "Unexpected changes to protected account fields",
            "MULTI_STEP_CHAIN": "A sequence of actions may bypass access checks",
        }
        names = {
            "BOLA_IDOR": "A user may be able to open another user's record",
            "BFLA": "A user may be able to reach a restricted action",
            "MISSING_AUTH": "A protected page may be available without signing in",
            "PRIVILEGE_ESCALATION": "A user may be able to use a higher-level account action",
            "MASS_ASSIGNMENT": "A request may change a protected account setting",
            "MULTI_STEP_CHAIN": "Several steps may combine to bypass an access check",
        }
        simple_title = names.get(category, "A possible access-control problem needs review")
        technical_name = technical_names.get(category, "Access-control issue (exact type not established)")
        severity = str(getattr(finding.severity, "value", finding.severity)).upper()
        risk_descriptions = {
            "CRITICAL": "Could cause very serious damage.",
            "HIGH": "Could expose important information or allow serious unauthorized actions.",
            "MEDIUM": "Could allow limited unauthorized access or other meaningful harm.",
            "LOW": "A smaller security weakness that should still be fixed.",
            "INFO": "Useful security advice; this is not necessarily a vulnerability.",
            "INFORMATIONAL": "Useful security advice; this is not necessarily a vulnerability.",
        }
        endpoint = redact_sensitive_text(finding.endpoint or finding.target_endpoint or "the tested page")
        method = finding.http_method.upper()
        evidence = finding.evidence
        actual = redact_sensitive_text(
            (evidence.actual_behavior if evidence else "") or finding.actual_behavior or ""
        ).strip()
        test_role_raw = getattr(evidence.testing_role, "value", evidence.testing_role) if evidence else "test user"
        owner_role_raw = getattr(evidence.authorized_role, "value", evidence.authorized_role) if evidence else "record owner"
        role_names = {
            "user_a": "User A", "user_b": "User B", "anonymous": "a visitor who is not signed in",
            "admin": "an administrator",
        }
        test_role = role_names.get(str(test_role_raw).lower(), str(test_role_raw))
        owner_role = role_names.get(str(owner_role_raw).lower(), str(owner_role_raw))

        if confirmed and actual:
            problem = (
                f"During the authorized test, {test_role} received a response for a record assigned to {owner_role} "
                f"at {method} {endpoint}. The security engine confirmed this result using the captured evidence."
            )
            attacker_action = (
                f"The test showed that a request using the tested {test_role} role received this endpoint's response. "
                "An attacker with comparable access could try the same request; the evidence does not prove access to other records or actions."
            )
            impact = (
                "The record owner may lose privacy if the returned response contains their information. "
                "The evidence only supports the response captured in this test; it does not establish wider damage."
            )
            why = "People expect their account records to be visible only to users who have permission. This result shows that this boundary failed in the tested case."
            missing = ["The test does not establish access to other records, endpoints, or write actions."]
        else:
            observed = actual or f"The test did not capture a usable response for {method} {endpoint}."
            problem = (
                f"The test observed: {observed} "
                "This evidence is not enough to confirm that someone accessed information without permission."
            )
            attacker_action = "We have not proven that an attacker can access another account or perform a restricted action."
            impact = "No harm to users has been confirmed by the available evidence. If access is later confirmed, the affected record or action will determine the possible harm."
            why = "A possible access problem deserves review, but describing it as a successful attack without proof could mislead developers and users."
            missing = ["We need more evidence to confirm this.", "A verified owner or role baseline and a reproducible response comparison are needed."]

        if category == "BOLA_IDOR":
            fixes = [
                "Read the signed-in user's identity on the server for each request.",
                "Check that the requested record belongs to that user or that the user has an explicit permission to view it.",
                "Deny access when the check fails, and add tests for both the owner and another user.",
            ]
        elif category in ("BFLA", "PRIVILEGE_ESCALATION"):
            fixes = [
                "Check the signed-in user's role on the server before running the restricted action.",
                "Deny the request when that role is not allowed to use the action.",
                "Add tests for an allowed role and a lower-privilege role.",
            ]
        elif category == "MISSING_AUTH":
            fixes = [
                "Require a valid signed-in session on this protected page.",
                "Check permission on the server before returning private data or performing an action.",
                "Add tests for signed-in and signed-out requests.",
            ]
        else:
            fixes = [
                "Review the server-side permission check for the affected request.",
                "Reject requests that do not meet the required account or role permission.",
                "Add a regression test for the observed behavior.",
            ]
        if not confirmed:
            fixes = ["Collect the missing comparison evidence before changing application code."]

        verify_steps = [
            f"In the authorized test environment, repeat {method} {endpoint} with the same test role and record.",
            "The user without permission should receive a denial or no protected record data.",
            "Confirm that the legitimate owner or allowed role can still use the feature.",
        ] if confirmed else [
            "In the authorized test environment, establish a verified owner or allowed-role baseline.",
            f"Repeat {method} {endpoint} with an account that should not have access and compare the response.",
            "Keep the result marked as under investigation unless the evidence proves unauthorized access.",
        ]
        evidence_facts = [f"Engine result: {status.value}."]
        if evidence is not None:
            evidence_facts.extend([
                f"Tested role: {test_role}; expected owner/role: {owner_role}.",
                f"Observed HTTP status: {evidence.response_status}.",
            ])
            if actual:
                evidence_facts.append(f"Observed behavior: {actual}")
        else:
            evidence_facts.append("No evidence artifact was attached to the finding.")

        return BeginnerExplanation(
            simple_title=simple_title,
            technical_name=technical_name,
            risk_level=severity,
            risk_description=risk_descriptions.get(severity, "Risk level supplied by the security engine."),
            confirmation_status=status.value,
            what_is_the_problem=problem,
            what_attacker_can_do=attacker_action,
            real_world_impact=impact,
            why_it_matters=why,
            how_to_fix=fixes,
            secure_code_example=None,
            how_to_verify_fix=verify_steps,
            additional_recommendations=["Keep a regression test for the authorized and unauthorized roles."],
            evidence_summary=evidence_facts,
            what_is_not_yet_proven=missing,
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    def _determine_validation_status(
        self, finding: FindingRecord
    ) -> ExplanationValidationStatus:
        """Infer ExplanationValidationStatus from finding fields and evidence.

        CONFIRMED requires BOTH:
        1. finding.validation_status or confirmation_status indicates confirmed, AND
        2. evidence exists with a 2xx response_status AND non-empty sanitized_response_evidence.
        """
        # Check if finding itself flags as correctly denied / false positive
        conf_status = str(
            finding.confirmation_status or finding.status or ""
        ).lower()
        val_status = str(finding.validation_status or "").upper()

        if conf_status in ("false_positive", "remediated"):
            return ExplanationValidationStatus.CORRECTLY_DENIED

        evidence: Optional[EvidenceArtifact] = finding.evidence
        has_valid_evidence = self._has_valid_confirmation_evidence(evidence)

        # UNVERIFIED wins when validation_status is explicitly unvalidated/empty.
        # Note: "SUSPICIOUS" val_status is handled below — not treated as UNVERIFIED.
        if val_status in ("UNVALIDATED", "UNVERIFIED", ""):
            return ExplanationValidationStatus.UNVERIFIED

        # CONFIRMED: both the finding metadata and the evidence quality agree.
        if val_status == "CONFIRMED" and conf_status in ("confirmed",) and has_valid_evidence:
            return ExplanationValidationStatus.CONFIRMED

        # SUSPICIOUS: scanner explicitly flagged it suspicious, or evidence is absent/weak.
        if val_status == "SUSPICIOUS" or conf_status in ("suspected", "suspicious"):
            return ExplanationValidationStatus.SUSPICIOUS

        # No evidence and no positive status signal → UNVERIFIED.
        if evidence is None:
            return ExplanationValidationStatus.UNVERIFIED

        # Default: SUSPICIOUS (conservative — never silently confirm).
        return ExplanationValidationStatus.SUSPICIOUS

    def _has_valid_confirmation_evidence(
        self, evidence: Optional[EvidenceArtifact]
    ) -> bool:
        """Return True only if the evidence meets CONFIRMED quality bar.

        Mirrors the logic in EvidenceValidator.validate_artifact_completeness.
        """
        if evidence is None:
            return False
        if not (200 <= evidence.response_status < 300):
            return False
        if not (evidence.sanitized_response_evidence or "").strip():
            return False
        return True

    def _determine_confidence(
        self,
        finding: FindingRecord,
        validation_status: ExplanationValidationStatus,
    ) -> ExplanationConfidenceLevel:
        """Infer ExplanationConfidenceLevel from validation status and evidence quality."""
        if validation_status == ExplanationValidationStatus.CONFIRMED:
            return ExplanationConfidenceLevel.HIGH
        evidence = finding.evidence
        if evidence and evidence.evidence_sha256 and len(evidence.evidence_sha256) == 64:
            return ExplanationConfidenceLevel.MEDIUM
        return ExplanationConfidenceLevel.LOW

    def _build_simple_explanation(
        self, finding: FindingRecord, vuln_type: str
    ) -> SimpleExplanation:
        """Build beginner-friendly SimpleExplanation from template + finding context."""
        tmpl = _VULN_SIMPLE_TEMPLATES.get(vuln_type, _VULN_SIMPLE_TEMPLATES["BOLA_IDOR"])
        endpoint = finding.endpoint
        method = finding.http_method.upper()

        # Personalise generic templates with the actual endpoint
        what_happened = (
            f"At endpoint `{method} {endpoint}`, the test observed: {tmpl['what_happened']}"
        )

        return SimpleExplanation(
            what_happened=what_happened,
            why_is_this_a_problem=str(tmpl["why_is_this_a_problem"]),
            what_could_an_attacker_do=str(tmpl["attacker_impact"]),
            how_can_a_developer_fix_it=str(tmpl["fix"]),
            glossary=dict(tmpl.get("glossary", {})),
        )

    def _build_technical_explanation(
        self, finding: FindingRecord, vuln_type: str
    ) -> TechnicalExplanation:
        """Build technical-depth TechnicalExplanation from template + finding data."""
        tmpl = _VULN_SIMPLE_TEMPLATES.get(vuln_type, _VULN_SIMPLE_TEMPLATES["BOLA_IDOR"])
        endpoint = finding.endpoint
        method = finding.http_method.upper()

        impact_text = finding.impact_explanation or finding.description or ""
        remediation_text = (
            finding.remediation_recommendation or finding.remediation_guidance or ""
        )

        # Prefer stored finding fields; fall back to template values
        tech_what = (
            f"Endpoint `{method} {endpoint}` returned an authorised response "
            f"to an unauthorized role. "
            + (
                finding.actual_behavior
                if finding.actual_behavior
                else str(tmpl.get("what_happened", ""))
            )
        )
        tech_impact = impact_text if impact_text else str(tmpl.get("tech_attacker_impact", ""))
        tech_remediation = remediation_text if remediation_text else str(tmpl.get("tech_remediation", ""))

        return TechnicalExplanation(
            vulnerability_class=str(tmpl.get("vuln_class", vuln_type)),
            what_happened=tech_what,
            root_cause=str(tmpl.get("root_cause", "")),
            attacker_impact=tech_impact,
            remediation_guidance=tech_remediation,
            cwe_reference=str(tmpl.get("cwe", "")),
            owasp_reference=str(tmpl.get("owasp", "")),
        )

    def _build_code_example(
        self, vuln_type: str, finding: Optional[FindingRecord] = None
    ) -> Optional[CodeExample]:
        """Return a CodeExample for the vulnerability, using verified code if mapped."""
        if self.code_mapper and finding:
            try:
                mapping_res = self.code_mapper.map_finding(finding)
                if mapping_res.status == MappingStatus.EXACT and mapping_res.location:
                    loc = mapping_res.location
                    default_example = _CODE_EXAMPLES.get(vuln_type)
                    lang = "javascript" if loc.file_path.endswith((".js", ".ts")) else "python"
                    prob_desc = (
                        f"Actual code at {loc.file_path} (lines {loc.start_line}-{loc.end_line})"
                        f"{f' in handler `{loc.function_name}`' if loc.function_name else ''}: "
                        f"{default_example.explanation_of_problem if default_example else 'Lacks proper authorization checks.'}"
                    )
                    return CodeExample(
                        is_illustrative=False,
                        language=lang,
                        vulnerable_code=loc.code_snippet,
                        explanation_of_problem=prob_desc,
                        corrected_code=(
                            default_example.corrected_code if default_example else "# Apply authorization check"
                        ),
                        explanation_of_fix=(
                            default_example.explanation_of_fix if default_example else "Verify authorization."
                        ),
                        source_location=f"{loc.file_path}:{loc.start_line}-{loc.end_line}",
                        snippet_provenance="ACTUAL_VERIFIED_SOURCE",
                    )
            except Exception as e:
                logger.warning("Code mapping failed during explanation generation: %s", e)

        example = _CODE_EXAMPLES.get(vuln_type)
        if example is None:
            logger.debug("No code example template for vuln_type=%s", vuln_type)
            return None

        return example.model_copy(update={
            "is_illustrative": True,
            "source_location": None,
            "snippet_provenance": "ILLUSTRATIVE_EXAMPLE",
        })

    def _integrate_evidence(
        self,
        finding: FindingRecord,
        source_location: Optional[str] = None,
        snippet_provenance: Optional[str] = None,
    ) -> Optional[EvidenceSummary]:
        """Extract and sanitize evidence fields for inclusion in the report.

        Only reads existing evidence from the finding; never calls
        EvidenceValidator.create_and_sign_evidence().
        Strips any remaining JWTs or Bearer tokens using EvidenceValidator static methods.
        """
        evidence: Optional[EvidenceArtifact] = finding.evidence
        if evidence is None:
            return None

        # Sanitize the response excerpt one final time using EvidenceValidator static helpers
        raw_excerpt = evidence.sanitized_response_evidence or evidence.sanitized_response_body or ""
        clean_excerpt, _ = EvidenceValidator.sanitize_body(raw_excerpt, max_excerpt_len=2000)

        testing_role_str = (
            evidence.testing_role.value
            if hasattr(evidence.testing_role, "value")
            else str(evidence.testing_role)
        )
        authorized_role_str = (
            evidence.authorized_role.value
            if hasattr(evidence.authorized_role, "value")
            else str(evidence.authorized_role or "")
        )
        val_status_str = (
            evidence.validation_status.value
            if hasattr(evidence.validation_status, "value")
            else str(evidence.validation_status)
        )

        return EvidenceSummary(
            evidence_id=evidence.id or evidence.evidence_id or "",
            endpoint=evidence.endpoint or finding.endpoint,
            http_method=evidence.http_method or finding.http_method,
            testing_role=testing_role_str,
            authorized_role=authorized_role_str,
            resource_id=evidence.resource_id,
            expected_behavior=evidence.expected_behavior,
            actual_behavior=evidence.actual_behavior,
            response_status=evidence.response_status,
            sanitized_response_excerpt=clean_excerpt,
            evidence_sha256=evidence.evidence_sha256,
            evidence_validation_status=evidence.evidence_validation_status,
            validation_status=val_status_str,
            redacted_fields=list(evidence.redacted_fields or []),
            source_location=source_location,
            snippet_provenance=snippet_provenance,
            timestamp=evidence.timestamp.isoformat() if evidence.timestamp else "",
        )

    @staticmethod
    def _default_title(finding: FindingRecord, vuln_type: str) -> str:
        """Generate a human-readable title when none is stored on the finding."""
        tmpl = _VULN_SIMPLE_TEMPLATES.get(vuln_type, {})
        vuln_class = tmpl.get("vuln_class", vuln_type)
        return f"{vuln_class} on {finding.endpoint}"
