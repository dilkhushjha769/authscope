"""Response Analyzer: Deep Inspection of Status, JSON Structure, Ownership & Diffs.

Evaluates HTTP responses to prevent false positives (such as HTTP 200 SPA HTML fallbacks,
soft JSON error objects, empty payloads, or self-scoped profile responses) and
distinguishes between:
- ALLOWED_ACCESS
- CORRECTLY_DENIED
- SUSPICIOUS_ACCESS
- CONFIRMED_UNAUTHORIZED_ACCESS
"""

from enum import Enum
from typing import Dict, Any, List, Optional, Set
from difflib import SequenceMatcher
import hashlib
from pydantic import BaseModel, Field

from backend.scanner.request_executor import HttpResponseModel
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class AccessVerdict(str, Enum):
    """Classification of an authorization test outcome."""
    ALLOWED_ACCESS = "ALLOWED_ACCESS"
    CORRECTLY_DENIED = "CORRECTLY_DENIED"
    SUSPICIOUS_ACCESS = "SUSPICIOUS_ACCESS"
    CONFIRMED_UNAUTHORIZED_ACCESS = "CONFIRMED_UNAUTHORIZED_ACCESS"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_TESTED = "NOT_TESTED"


class ResponseInspection(BaseModel):
    """Detailed structural analysis of a single HTTP response."""
    status_code: int
    is_http_success: bool = False
    is_json: bool = False
    is_spa_html_fallback: bool = False
    has_error_indicator: bool = False
    error_message: Optional[str] = None
    is_empty_payload: bool = False
    extracted_resource_ids: List[str] = Field(default_factory=list)
    extracted_owner_ids: List[str] = Field(default_factory=list)
    extracted_emails: List[str] = Field(default_factory=list)
    sensitive_fields_found: List[str] = Field(default_factory=list)
    top_level_keys: List[str] = Field(default_factory=list)


class ComparisonAnalysis(BaseModel):
    """Structured result comparing an authorized baseline response against a test role response."""
    verdict: AccessVerdict
    is_unauthorized_access: bool = False
    is_confirmed: bool = False
    similarity_ratio: float = 0.0
    shared_resource_id_matched: bool = False
    owner_identifier_leaked: bool = False
    sensitive_fields_exposed: List[str] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    owner_inspection: ResponseInspection
    test_inspection: ResponseInspection


class ResponseAnalyzer:
    """Analyzes HTTP responses and performs differential authorization comparisons."""

    # Keys indicating soft error payloads inside 200 OK responses
    ERROR_KEYS = {"error", "errors", "err", "exception", "fault"}
    ERROR_STATUS_VALUES = {"error", "fail", "failed", "unauthorized", "forbidden", "denied"}
    DENIAL_PHRASES = (
        "unauthorized",
        "access denied",
        "forbidden",
        "invalid token",
        "jwt malformed",
        "authentication required",
        "not authorized",
        "permission denied",
    )

    # Keys representing sensitive business or personal data
    SENSITIVE_FIELD_NAMES = {
        "email", "password", "totpsecret", "role", "deluxetoken", "lastloginip",
        "cardnum", "cardnumber", "cvv", "expiry", "wallet", "balance", "products",
        "basketid", "userid", "address", "streetaddress", "mobile", "phone",
        "ssn", "secret", "apikey", "token", "private"
    }

    # Keys representing resource ownership
    OWNER_FIELD_NAMES = {"userid", "user_id", "ownerid", "owner_id", "customerid", "createdby", "uid"}
    RESOURCE_ID_FIELD_NAMES = {"id", "basketid", "orderid", "addressid", "cardid"}

    @classmethod
    def is_spa_fallback(cls, response: HttpResponseModel) -> bool:
        """Detects if an API endpoint returned the generic SPA index.html shell with 200 OK."""
        content_type = response.headers.get("content-type", response.headers.get("Content-Type", "")).lower()
        body_lower = (response.body or "").strip().lower()
        if "text/html" in content_type or body_lower.startswith("<!doctype html>") or "<html" in body_lower[:300]:
            if "<app-root" in body_lower or "juice shop" in body_lower or "<script" in body_lower:
                return True
            return True
        return False

    @classmethod
    def inspect_response(cls, response: HttpResponseModel) -> ResponseInspection:
        """Performs deep structural inspection of an HTTP response."""
        is_2xx = 200 <= response.status_code < 300
        spa_fallback = cls.is_spa_fallback(response)
        is_json = response.json_data is not None and not spa_fallback

        has_error = not is_2xx
        error_msg: Optional[str] = None
        is_empty = False
        resource_ids: Set[str] = set()
        owner_ids: Set[str] = set()
        emails: Set[str] = set()
        sensitive_fields: Set[str] = set()
        top_keys: List[str] = []

        body_stripped = (response.body or "").strip()
        if not body_stripped or body_stripped in ("{}", "[]", "null", '""'):
            is_empty = True

        if is_json and isinstance(response.json_data, dict):
            data_dict = response.json_data
            top_keys = list(data_dict.keys())

            # Check for explicit error keys or status indicators
            for k, v in data_dict.items():
                k_lower = k.lower()
                if k_lower in cls.ERROR_KEYS and v:
                    has_error = True
                    error_msg = str(v)
                elif k_lower == "status" and str(v).lower() in cls.ERROR_STATUS_VALUES:
                    has_error = True
                    error_msg = str(data_dict.get("message") or data_dict.get("error") or v)
                elif k_lower == "message" and any(p in str(v).lower() for p in cls.DENIAL_PHRASES):
                    has_error = True
                    error_msg = str(v)

            # Check if 'data' wrapper is empty
            if "data" in data_dict:
                inner = data_dict["data"]
                if inner is None or inner == {} or inner == []:
                    is_empty = True
            elif "user" in data_dict and (data_dict["user"] == {} or data_dict["user"] is None):
                is_empty = True

            # Recursively extract IDs, owners, emails, and sensitive fields
            cls._walk_json(
                node=data_dict,
                resource_ids=resource_ids,
                owner_ids=owner_ids,
                emails=emails,
                sensitive_fields=sensitive_fields,
            )
        elif not is_json:
            body_lower = body_stripped.lower()
            for phrase in cls.DENIAL_PHRASES:
                if phrase in body_lower and len(body_stripped) < 500:
                    has_error = True
                    error_msg = body_stripped[:200]
                    break

        return ResponseInspection(
            status_code=response.status_code,
            is_http_success=is_2xx and not has_error,
            is_json=is_json,
            is_spa_html_fallback=spa_fallback,
            has_error_indicator=has_error,
            error_message=error_msg,
            is_empty_payload=is_empty,
            extracted_resource_ids=sorted(resource_ids),
            extracted_owner_ids=sorted(owner_ids),
            extracted_emails=sorted(emails),
            sensitive_fields_found=sorted(sensitive_fields),
            top_level_keys=top_keys,
        )

    @classmethod
    def _walk_json(
        cls,
        node: Any,
        resource_ids: Set[str],
        owner_ids: Set[str],
        emails: Set[str],
        sensitive_fields: Set[str],
        depth: int = 0
    ) -> None:
        """Recursively walks a parsed JSON structure to extract security metadata."""
        if depth > 6:
            return

        if isinstance(node, dict):
            for key, val in node.items():
                key_lower = str(key).lower()
                is_sens = key_lower in cls.SENSITIVE_FIELD_NAMES or any(s in key_lower for s in ("secret", "token", "password", "apikey", "credential"))
                if is_sens and val not in (None, "", [], {}):
                    sensitive_fields.add(str(key))

                if key_lower in cls.OWNER_FIELD_NAMES and val is not None and isinstance(val, (str, int)):
                    owner_ids.add(str(val))

                if key_lower in cls.RESOURCE_ID_FIELD_NAMES and val is not None and isinstance(val, (str, int)):
                    # Only record top-level or primary object IDs (depth <= 2)
                    if depth <= 2:
                        resource_ids.add(str(val))

                if key_lower == "email" and isinstance(val, str) and "@" in val:
                    emails.add(val.strip().lower())

                cls._walk_json(val, resource_ids, owner_ids, emails, sensitive_fields, depth + 1)
        elif isinstance(node, list):
            for item in node[:25]:
                cls._walk_json(item, resource_ids, owner_ids, emails, sensitive_fields, depth + 1)

    @classmethod
    def is_success_response(cls, response: HttpResponseModel) -> bool:
        """Determines if a response indicates a genuine successful response.

        Checks that status code is 2xx and response does not contain soft error payloads.
        """
        inspection = cls.inspect_response(response)
        return inspection.is_http_success

    @classmethod
    def compute_body_similarity(cls, body_a: str, body_b: str) -> float:
        """Computes normalized similarity ratio [0.0, 1.0] between two response bodies."""
        if not body_a and not body_b:
            return 1.0
        if not body_a or not body_b:
            return 0.0
        # Bound comparison length for performance
        sample_a = body_a[:10_000]
        sample_b = body_b[:10_000]
        return round(SequenceMatcher(None, sample_a, sample_b).ratio(), 4)

    @classmethod
    def _sensitive_value_fingerprints(cls, value: Any, key: str = "") -> Set[str]:
        """Returns hashes of matching sensitive values without retaining their content."""
        sensitive_name = any(
            marker in key.lower()
            for marker in ("password", "secret", "token", "apikey", "cardnum", "cvv", "ssn", "privatekey")
        )
        if isinstance(value, dict):
            found: Set[str] = set()
            for child_key, child_value in value.items():
                found.update(cls._sensitive_value_fingerprints(child_value, str(child_key)))
            return found
        if isinstance(value, list):
            found = set()
            for child_value in value[:25]:
                found.update(cls._sensitive_value_fingerprints(child_value, key))
            return found
        if sensitive_name and value not in (None, "", 0, False):
            return {hashlib.sha256(str(value).encode("utf-8")).hexdigest()}
        return set()

    @classmethod
    def compare_responses(
        cls,
        owner_response: HttpResponseModel,
        test_response: HttpResponseModel,
        expected_resource_id: Optional[str] = None,
        owner_user_id: Optional[str] = None,
        owner_email: Optional[str] = None,
        test_user_id: Optional[str] = None,
        test_email: Optional[str] = None,
        is_test_role_expected_allowed: bool = False,
    ) -> ComparisonAnalysis:
        """Compares an authorized baseline response against a test role's response.

        Never treats HTTP 200 alone as proof of IDOR. Evaluates:
        1. HTTP status code & soft errors.
        2. SPA HTML fallback detection (false positive prevention).
        3. Empty payload detection.
        4. Self-reflection detection (did the endpoint just return User B's own profile?).
        5. Resource ID & Owner ID correlation against User A's baseline data.
        6. Sensitive field exposure and body similarity.
        """
        owner_insp = cls.inspect_response(owner_response)
        test_insp = cls.inspect_response(test_response)
        similarity = cls.compute_body_similarity(owner_response.body, test_response.body)
        reasons: List[str] = []

        # Case 1: Test role is explicitly expected to have access (e.g. Owner or Admin on allowed route)
        if is_test_role_expected_allowed:
            if test_insp.is_http_success and not test_insp.is_empty_payload:
                reasons.append("Test role is authorized for this endpoint and received valid data.")
                return ComparisonAnalysis(
                    verdict=AccessVerdict.ALLOWED_ACCESS,
                    is_unauthorized_access=False,
                    is_confirmed=False,
                    similarity_ratio=similarity,
                    sensitive_fields_exposed=test_insp.sensitive_fields_found,
                    reasons=reasons,
                    owner_inspection=owner_insp,
                    test_inspection=test_insp,
                )

        # Case 2: Non-2xx status or explicit error indicator -> Correctly Denied
        if not test_insp.is_http_success:
            reasons.append(
                f"Access denied with HTTP {test_response.status_code}"
                + (f" ({test_insp.error_message})" if test_insp.error_message else ".")
            )
            return ComparisonAnalysis(
                verdict=AccessVerdict.CORRECTLY_DENIED,
                is_unauthorized_access=False,
                is_confirmed=False,
                similarity_ratio=similarity,
                reasons=reasons,
                owner_inspection=owner_insp,
                test_inspection=test_insp,
            )

        # Case 3: False-positive guard — API returned 200 OK SPA HTML shell instead of JSON
        if test_insp.is_spa_html_fallback and (owner_insp.is_json or not owner_insp.is_spa_html_fallback):
            reasons.append("Response returned generic SPA HTML shell (200 OK fallback), not protected resource JSON.")
            return ComparisonAnalysis(
                verdict=AccessVerdict.CORRECTLY_DENIED,
                is_unauthorized_access=False,
                is_confirmed=False,
                similarity_ratio=similarity,
                reasons=reasons,
                owner_inspection=owner_insp,
                test_inspection=test_insp,
            )

        if owner_insp.is_spa_html_fallback and test_insp.is_spa_html_fallback:
            reasons.append("Both baseline and test responses returned generic SPA HTML fallback rather than API data.")
            return ComparisonAnalysis(
                verdict=AccessVerdict.CORRECTLY_DENIED,
                is_unauthorized_access=False,
                is_confirmed=False,
                similarity_ratio=similarity,
                reasons=reasons,
                owner_inspection=owner_insp,
                test_inspection=test_insp,
            )

        # Case 4: False-positive guard — Test response is an empty JSON object/array (e.g. {"user": {}})
        if test_insp.is_empty_payload:
            reasons.append("Response returned HTTP 200 but payload is empty (no protected data exposed).")
            return ComparisonAnalysis(
                verdict=AccessVerdict.CORRECTLY_DENIED,
                is_unauthorized_access=False,
                is_confirmed=False,
                similarity_ratio=similarity,
                reasons=reasons,
                owner_inspection=owner_insp,
                test_inspection=test_insp,
            )

        # Case 5: False-positive guard — Endpoint returned the test user's OWN data (e.g. /rest/user/whoami)
        if test_email and test_email.lower() in test_insp.extracted_emails:
            if not owner_email or owner_email.lower() not in test_insp.extracted_emails:
                reasons.append(
                    "Response contains only the testing role's own account data, not another user's resource."
                )
                return ComparisonAnalysis(
                    verdict=AccessVerdict.ALLOWED_ACCESS,
                    is_unauthorized_access=False,
                    is_confirmed=False,
                    similarity_ratio=similarity,
                    reasons=reasons,
                    owner_inspection=owner_insp,
                    test_inspection=test_insp,
                )

        if test_user_id and str(test_user_id) in test_insp.extracted_owner_ids:
            if not owner_user_id or str(owner_user_id) not in test_insp.extracted_owner_ids:
                reasons.append(
                    f"Response is scoped to the testing role's own user ID ({test_user_id})."
                )
                return ComparisonAnalysis(
                    verdict=AccessVerdict.ALLOWED_ACCESS,
                    is_unauthorized_access=False,
                    is_confirmed=False,
                    similarity_ratio=similarity,
                    reasons=reasons,
                    owner_inspection=owner_insp,
                    test_inspection=test_insp,
                )

        # Case 6: Baseline owner request itself failed or was empty -> Cannot confirm cross-user leak
        if not owner_insp.is_http_success or owner_insp.is_empty_payload:
            reasons.append(
                "Unauthorized role received HTTP 200 with non-empty data, but legitimate owner baseline was unavailable or failed."
            )
            return ComparisonAnalysis(
                verdict=AccessVerdict.SUSPICIOUS_ACCESS,
                is_unauthorized_access=True,
                is_confirmed=False,
                similarity_ratio=similarity,
                sensitive_fields_exposed=test_insp.sensitive_fields_found,
                reasons=reasons,
                owner_inspection=owner_insp,
                test_inspection=test_insp,
            )

        # Case 7: Evaluate concrete ownership & resource matching between Owner and Test responses
        shared_res_match = False
        if expected_resource_id and str(expected_resource_id) in test_insp.extracted_resource_ids:
            shared_res_match = True
            reasons.append(f"Response contains requested target resource ID '{expected_resource_id}'.")
        elif owner_insp.extracted_resource_ids and (
            set(owner_insp.extracted_resource_ids) & set(test_insp.extracted_resource_ids)
        ):
            shared_res_match = True
            matched_ids = sorted(set(owner_insp.extracted_resource_ids) & set(test_insp.extracted_resource_ids))
            reasons.append(f"Response contains matching resource IDs from owner baseline: {matched_ids}.")

        owner_leaked = False
        if owner_user_id and str(owner_user_id) in test_insp.extracted_owner_ids:
            owner_leaked = True
            reasons.append("Response explicitly exposes the configured owner user ID.")
        elif owner_insp.extracted_owner_ids and (
            set(owner_insp.extracted_owner_ids) & set(test_insp.extracted_owner_ids)
        ):
            owner_leaked = True
            reasons.append("Response contains an owner identifier matching the authorized baseline.")

        if owner_email and owner_email.lower() in test_insp.extracted_emails:
            owner_leaked = True
            reasons.append("Response exposes the configured owner's email address.")
        elif owner_insp.extracted_emails and (
            set(owner_insp.extracted_emails) & set(test_insp.extracted_emails)
        ):
            owner_leaked = True
            reasons.append("Response exposes an email address also present in the authorized baseline.")

        # Determine if unauthorized access is CONFIRMED vs SUSPICIOUS
        has_sensitive = len(test_insp.sensitive_fields_found) > 0
        high_similarity = similarity >= 0.85

        # Confirmation needs evidence tying the unauthorized response to a
        # protected owner resource or to the authenticated privileged baseline.
        # Similar shape or the presence of generic sensitive-looking keys alone
        # is insufficient (for example, public profile fields or UI config).
        shared_sensitive_values = bool(
            cls._sensitive_value_fingerprints(owner_response.json_data)
            & cls._sensitive_value_fingerprints(test_response.json_data)
        )
        verified_owner_resource = bool(expected_resource_id and shared_res_match)
        if (
            verified_owner_resource and (owner_leaked or (high_similarity and has_sensitive))
        ) or (owner_leaked and high_similarity) or (
            shared_sensitive_values and test_insp.is_json
        ):
            reasons.append(
                f"Confirmed unauthorized access: high structural similarity ({similarity:.2f}) "
                f"and verified protected resource/owner attributes ({test_insp.sensitive_fields_found})."
            )
            return ComparisonAnalysis(
                verdict=AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS,
                is_unauthorized_access=True,
                is_confirmed=True,
                similarity_ratio=similarity,
                shared_resource_id_matched=shared_res_match,
                owner_identifier_leaked=owner_leaked,
                sensitive_fields_exposed=test_insp.sensitive_fields_found,
                reasons=reasons,
                owner_inspection=owner_insp,
                test_inspection=test_insp,
            )

        # If bodies are completely different and neither resource ID nor owner ID matched
        if similarity < 0.50 and not shared_res_match and not owner_leaked:
            reasons.append(
                f"Response returned HTTP 200, but body differs significantly from owner baseline "
                f"(similarity={similarity:.2f}) and contains no matching owner identifiers."
            )
            return ComparisonAnalysis(
                verdict=AccessVerdict.SUSPICIOUS_ACCESS,
                is_unauthorized_access=True,
                is_confirmed=False,
                similarity_ratio=similarity,
                sensitive_fields_exposed=test_insp.sensitive_fields_found,
                reasons=reasons,
                owner_inspection=owner_insp,
                test_inspection=test_insp,
            )

        reasons.append(
            f"Suspicious access behavior detected (HTTP 200, similarity={similarity:.2f}), "
            f"but lacks conclusive ownership attributes to confirm automatically."
        )
        return ComparisonAnalysis(
            verdict=AccessVerdict.SUSPICIOUS_ACCESS,
            is_unauthorized_access=True,
            is_confirmed=False,
            similarity_ratio=similarity,
            shared_resource_id_matched=shared_res_match,
            owner_identifier_leaked=owner_leaked,
            sensitive_fields_exposed=test_insp.sensitive_fields_found,
            reasons=reasons,
            owner_inspection=owner_insp,
            test_inspection=test_insp,
        )
