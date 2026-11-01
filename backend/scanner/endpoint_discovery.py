"""Endpoint Discovery: Safe Attack Surface Mapping, Classification & ID Extraction.

Supports:
1. Configured endpoint lists.
2. Safe endpoint discovery from known OWASP Juice Shop routes.
3. HTTP method metadata (prioritizing non-destructive GET routes).
4. Resource identifier extraction from parameterized templates and concrete URLs.
5. Endpoint classification (USER_OBJECT, USER_COLLECTION, ADMIN_FUNCTION, PUBLIC).

All discovered endpoints are validated against ScopeGuard. Never crawls external domains.
"""

from enum import Enum
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlsplit, parse_qs
import re
from pydantic import BaseModel, Field

from backend.config import settings
from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role
from backend.scanner.request_executor import RequestExecutor
from backend.utils.helpers import AuthScopeException, InvalidTargetURLError
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class EndpointCategory(str, Enum):
    """Functional security classification of an application route."""
    USER_OBJECT = "USER_OBJECT"           # Object-level endpoint with ID (BOLA/IDOR candidate)
    USER_COLLECTION = "USER_COLLECTION"   # Authenticated resource list or profile endpoint
    ADMIN_FUNCTION = "ADMIN_FUNCTION"     # Administrative / privileged route (BFLA candidate)
    PUBLIC = "PUBLIC"                     # Publicly accessible route (no auth expected)
    AUTHENTICATION = "AUTHENTICATION"     # Login / credential handling route
    UNKNOWN = "UNKNOWN"


class DiscoveredEndpoint(BaseModel):
    """Represents a normalized, classified application route."""
    path: str = Field(..., description="Route path or template (e.g. /rest/basket/{id})")
    method: str = Field(default="GET", description="HTTP Method (initially GET)")
    parameters: List[str] = Field(default_factory=list, description="Extracted path/query parameter names")
    input_parameters: List[str] = Field(default_factory=list, description="Declared path/query inputs")
    output_parameters: List[str] = Field(default_factory=list, description="Identifier fields declared by the endpoint response schema")
    resource_identifier_name: Optional[str] = None
    extracted_resource_id: Optional[str] = Field(
        default=None,
        description="Concrete resource identifier extracted from URL if present"
    )
    resource_type: Optional[str] = Field(
        default=None,
        description="Inferred resource noun (e.g. 'basket', 'user', 'address')"
    )
    category: EndpointCategory = Field(
        default=EndpointCategory.UNKNOWN,
        description="Security classification of the endpoint"
    )
    requires_auth: bool = Field(default=True, description="Whether endpoint requires authentication")
    expected_allowed_roles: List[Role] = Field(
        default_factory=lambda: [Role.USER_A, Role.USER_B, Role.ADMIN],
        description="Roles expected to have access under normal policy"
    )
    requires_owner_match: bool = Field(
        default=False,
        description="True if access to concrete resource ID must be restricted to its owner"
    )
    requires_human_approval: bool = Field(
        default=False,
        description="True if testing this endpoint requires explicit human operator approval"
    )
    parent_resource_type: Optional[str] = Field(default=None, description="Parent resource noun if nested/related")
    related_resource_types: List[str] = Field(default_factory=list, description="Related resource nouns")
    resource_sensitivity: Optional[str] = Field(default=None, description="Sensitivity classification (e.g. HIGH, CRITICAL)")
    dependencies: List[str] = Field(default_factory=list, description="Explicit prerequisite endpoint paths")
    description: str = Field(default="", description="Human-readable route description")


# Regex patterns for parameter extraction
TEMPLATE_PARAM_REGEX = re.compile(r"\{([a-zA-Z0-9_]+)\}|:([a-zA-Z0-9_]+)")
CONCRETE_ID_SEGMENT_REGEX = re.compile(
    r"^/(?:rest|api)/([a-zA-Z0-9_-]+)/([0-9]+|[0-9a-fA-F-]{8,})(?:/.*)?$"
)


class EndpointDiscovery:
    """Discovers, classifies, and extracts resource identifiers from in-scope routes."""

    # Curated, non-destructive GET routes for local OWASP Juice Shop testing
    KNOWN_JUICE_SHOP_GET_ROUTES: List[Dict[str, Any]] = [
        {
            "path": "/rest/basket/{id}",
            "method": "GET",
            "category": EndpointCategory.USER_OBJECT,
            "resource_type": "basket",
            "parent_resource_type": "user",
            "input_parameters": ["id"],
            "resource_sensitivity": "HIGH",
            "requires_auth": True,
            "requires_owner_match": True,
            "expected_allowed_roles": [Role.USER_A, Role.USER_B, Role.ADMIN],
            "description": "Retrieve shopping basket contents by basket ID (BOLA/IDOR target)",
        },
        {
            "path": "/api/Users/{id}",
            "method": "GET",
            "category": EndpointCategory.USER_OBJECT,
            "resource_type": "user",
            "input_parameters": ["id"],
            "output_parameters": ["id"],
            "resource_identifier_name": "id",
            "resource_sensitivity": "HIGH",
            "requires_auth": True,
            "requires_owner_match": True,
            "expected_allowed_roles": [Role.USER_A, Role.USER_B, Role.ADMIN],
            "description": "Retrieve specific user profile record by ID",
        },
        {
            "path": "/api/Addresss/{id}",
            "method": "GET",
            "category": EndpointCategory.USER_OBJECT,
            "resource_type": "address",
            "parent_resource_type": "user",
            "input_parameters": ["id"],
            "resource_sensitivity": "MEDIUM",
            "requires_auth": True,
            "requires_owner_match": True,
            "expected_allowed_roles": [Role.USER_A, Role.USER_B],
            "description": "Retrieve saved shipping address by ID",
        },
        {
            "path": "/api/Cards/{id}",
            "method": "GET",
            "category": EndpointCategory.USER_OBJECT,
            "resource_type": "card",
            "parent_resource_type": "user",
            "input_parameters": ["id"],
            "resource_sensitivity": "CRITICAL",
            "requires_auth": True,
            "requires_owner_match": True,
            "expected_allowed_roles": [Role.USER_A, Role.USER_B],
            "description": "Retrieve saved payment card details by ID",
        },
        {
            "path": "/api/Users",
            "method": "GET",
            "category": EndpointCategory.ADMIN_FUNCTION,
            "resource_type": "user",
            "output_parameters": ["id"],
            "resource_identifier_name": "id",
            "resource_sensitivity": "CRITICAL",
            "requires_auth": True,
            "requires_owner_match": False,
            "expected_allowed_roles": [Role.ADMIN],
            "description": "List all registered application users (Admin-only collection)",
        },
        {
            "path": "/rest/admin/application-configuration",
            "method": "GET",
            "category": EndpointCategory.ADMIN_FUNCTION,
            "resource_type": "configuration",
            "dependencies": ["/rest/user/whoami"],
            "resource_sensitivity": "HIGH",
            "requires_auth": False,
            "requires_owner_match": False,
            "expected_allowed_roles": [Role.ADMIN],
            "description": "Retrieve internal application configuration metadata",
        },
        {
            "path": "/rest/admin/application-version",
            "method": "GET",
            "category": EndpointCategory.PUBLIC,
            "resource_type": "version",
            "requires_auth": False,
            "requires_owner_match": False,
            "expected_allowed_roles": [Role.ANONYMOUS, Role.USER_A, Role.USER_B, Role.ADMIN],
            "description": "Retrieve public application version string",
        },
        {
            "path": "/rest/user/whoami",
            "method": "GET",
            "category": EndpointCategory.USER_COLLECTION,
            "resource_type": "user",
            "output_parameters": ["id"],
            "resource_identifier_name": "id",
            "resource_sensitivity": "HIGH",
            "requires_auth": False,
            "requires_owner_match": False,
            "expected_allowed_roles": [Role.ANONYMOUS, Role.USER_A, Role.USER_B, Role.ADMIN],
            "description": "Return current authenticated user identity context",
        },
    ]

    def __init__(
        self,
        base_url: str = settings.target_base_url,
        scope_guard: Optional[ScopeGuard] = None
    ):
        self.base_url = base_url.rstrip("/")
        self.scope_guard = scope_guard or ScopeGuard()
        # Validate base URL immediately on initialization
        self.scope_guard.assert_in_scope(self.base_url, method="GET")

    @staticmethod
    def extract_resource_metadata(path_or_url: str) -> Tuple[str, List[str], Optional[str], Optional[str]]:
        """Extracts template path, parameter names, resource type, and concrete ID from a path.

        Returns:
            Tuple of (normalized_path, parameter_names, resource_type, extracted_resource_id)
        """
        parsed = urlsplit(path_or_url)
        raw_path = parsed.path or path_or_url
        if not raw_path.startswith("/"):
            raw_path = "/" + raw_path

        params: List[str] = []
        extracted_id: Optional[str] = None
        resource_type: Optional[str] = None

        # 1. Extract template parameters like {id} or :id
        for match in TEMPLATE_PARAM_REGEX.finditer(raw_path):
            param_name = match.group(1) or match.group(2)
            if param_name and param_name not in params:
                params.append(param_name)

        # 2. Extract concrete resource ID from paths like /rest/basket/1 or /api/Users/2
        concrete_match = CONCRETE_ID_SEGMENT_REGEX.match(raw_path)
        if concrete_match:
            raw_noun = concrete_match.group(1).lower()
            if raw_noun.endswith("ss"):
                resource_type = raw_noun
            elif raw_noun.endswith("s") and len(raw_noun) > 1:
                resource_type = raw_noun[:-1]
            else:
                resource_type = raw_noun
            extracted_id = concrete_match.group(2)
            if "id" not in params:
                params.append("id")
        else:
            # Infer resource_type from path segments
            segments = [s for s in raw_path.split("/") if s and not s.startswith("{") and not s.startswith(":")]
            if len(segments) >= 2 and segments[0].lower() in ("rest", "api"):
                raw_noun = segments[1].lower()
                resource_type = raw_noun[:-1] if (raw_noun.endswith("s") and not raw_noun.endswith("ss")) else raw_noun

        # 3. Check query parameters for resource identifiers
        if parsed.query:
            query_dict = parse_qs(parsed.query)
            for q_key, q_vals in query_dict.items():
                if q_key not in params:
                    params.append(q_key)
                if q_key.lower() in ("id", "userid", "basketid", "orderid") and q_vals and not extracted_id:
                    extracted_id = str(q_vals[0])

        return raw_path, params, resource_type, extracted_id

    @classmethod
    def classify_endpoint(
        cls,
        path: str,
        method: str = "GET",
        parameters: Optional[List[str]] = None,
        extracted_id: Optional[str] = None
    ) -> EndpointCategory:
        """Heuristically classifies an endpoint into a security testing category."""
        lower_path = path.lower()
        param_list = parameters or []

        if any(auth_seg in lower_path for auth_seg in ("/login", "/authenticate", "/token", "/register")):
            return EndpointCategory.AUTHENTICATION

        if any(admin_seg in lower_path for admin_seg in ("/admin", "/configuration", "/metrics", "/dashboard")):
            if "application-version" in lower_path:
                return EndpointCategory.PUBLIC
            return EndpointCategory.ADMIN_FUNCTION

        if any(pub_seg in lower_path for pub_seg in ("/products/search", "/challenges", "/public", "/assets")):
            return EndpointCategory.PUBLIC

        if extracted_id or any(p.lower().endswith("id") for p in param_list):
            return EndpointCategory.USER_OBJECT

        if lower_path in ("/api/users", "/api/feedbacks", "/api/complaints"):
            return EndpointCategory.ADMIN_FUNCTION

        if lower_path.startswith(("/rest/", "/api/")):
            return EndpointCategory.USER_COLLECTION

        return EndpointCategory.UNKNOWN

    def register_endpoint(
        self,
        path: str,
        method: str = "GET",
        category: Optional[EndpointCategory] = None,
        requires_auth: Optional[bool] = None,
        requires_owner_match: Optional[bool] = None,
        expected_allowed_roles: Optional[List[Role]] = None,
        description: str = "",
    ) -> DiscoveredEndpoint:
        """Creates and validates a single DiscoveredEndpoint from route metadata."""
        if not path or not isinstance(path, str) or any(ord(c) < 32 for c in path):
            raise InvalidTargetURLError(f"Invalid endpoint path: {path!r}")

        norm_method = method.strip().upper()
        norm_path, params, res_type, extracted_id = self.extract_resource_metadata(path)

        # Verify target URL constructed with this path passes ScopeGuard URL checks
        sample_path = TEMPLATE_PARAM_REGEX.sub("1", norm_path)
        full_candidate_url = f"{self.base_url}{sample_path}"
        url_check = self.scope_guard.validate_url(full_candidate_url)
        if not url_check.is_allowed:
            raise InvalidTargetURLError(
                f"Endpoint '{path}' fails scope validation against base '{self.base_url}': {url_check.reason}"
            )

        inferred_category = category or self.classify_endpoint(
            path=norm_path,
            method=norm_method,
            parameters=params,
            extracted_id=extracted_id
        )

        # Non-GET methods require explicit human approval before expansion
        needs_approval = norm_method != "GET"

        if requires_auth is None:
            requires_auth = inferred_category not in (EndpointCategory.PUBLIC, EndpointCategory.AUTHENTICATION)

        if requires_owner_match is None:
            requires_owner_match = inferred_category == EndpointCategory.USER_OBJECT

        if expected_allowed_roles is None:
            if inferred_category == EndpointCategory.PUBLIC:
                expected_allowed_roles = [Role.ANONYMOUS, Role.USER_A, Role.USER_B, Role.ADMIN]
            elif inferred_category == EndpointCategory.ADMIN_FUNCTION:
                expected_allowed_roles = [Role.ADMIN]
            else:
                expected_allowed_roles = [Role.USER_A, Role.USER_B, Role.ADMIN]

        return DiscoveredEndpoint(
            path=norm_path,
            method=norm_method,
            parameters=params,
            extracted_resource_id=extracted_id,
            resource_type=res_type,
            category=inferred_category,
            requires_auth=requires_auth,
            expected_allowed_roles=expected_allowed_roles,
            requires_owner_match=requires_owner_match,
            requires_human_approval=needs_approval,
            description=description,
        )

    def discover_from_config(
        self,
        endpoints_config: List[Dict[str, Any]],
        only_get: bool = True
    ) -> List[DiscoveredEndpoint]:
        """Loads and normalizes a list of configured endpoint definitions.

        Initially prioritizes GET endpoints when `only_get=True`.
        """
        discovered: List[DiscoveredEndpoint] = []
        for item in endpoints_config:
            method = str(item.get("method", "GET")).strip().upper()
            if only_get and method != "GET":
                logger.info("Skipping non-GET endpoint during initial discovery", extra={"path": item.get("path"), "method": method})
                continue

            ep = self.register_endpoint(
                path=item["path"],
                method=method,
                category=item.get("category"),
                requires_auth=item.get("requires_auth"),
                requires_owner_match=item.get("requires_owner_match"),
                expected_allowed_roles=item.get("expected_allowed_roles"),
                description=item.get("description", ""),
            )
            updates: Dict[str, Any] = {}
            for extra_key in (
                "resource_type",
                "input_parameters",
                "output_parameters",
                "resource_identifier_name",
                "parent_resource_type",
                "related_resource_types",
                "resource_sensitivity",
                "dependencies",
            ):
                if extra_key in item and item[extra_key] is not None:
                    updates[extra_key] = item[extra_key]
            if updates:
                ep = ep.model_copy(update=updates)
            discovered.append(ep)
        return discovered

    def discover_known_routes(
        self,
        category_filter: Optional[EndpointCategory] = None
    ) -> List[DiscoveredEndpoint]:
        """Returns curated, safe GET routes for the local OWASP Juice Shop application."""
        routes = self.discover_from_config(self.KNOWN_JUICE_SHOP_GET_ROUTES, only_get=True)
        if category_filter is not None:
            routes = [r for r in routes if r.category == category_filter]
        return routes

    def discover_from_openapi(
        self,
        spec_url: Optional[str] = None,
        executor: Optional[RequestExecutor] = None,
        max_endpoints: int = 100,
    ) -> List[DiscoveredEndpoint]:
        """Reads an in-scope OpenAPI document and returns bounded GET route definitions.

        The document is fetched only through RequestExecutor, so scope checks, redirect
        suppression, response bounds, and request logging remain centralized. If no
        usable OpenAPI document is exposed, the local Juice Shop curated GET list is
        retained as a clearly configured fallback.
        """
        if max_endpoints < 1:
            return []

        candidates = [spec_url] if spec_url else [
            f"{self.base_url}/openapi.json",
            f"{self.base_url}/swagger.json",
            f"{self.base_url}/api-docs",
            f"{self.base_url}/api/swagger.json",
        ]
        if executor is not None:
            for candidate in candidates:
                if not candidate:
                    continue
                check = self.scope_guard.validate_request(candidate, method="GET")
                if not check.is_allowed:
                    logger.warning(
                        "Skipping out-of-scope API description URL",
                        extra={"reason": check.reason},
                    )
                    continue
                try:
                    response = executor.send_request(
                        role=Role.ANONYMOUS,
                        method="GET",
                        url=candidate,
                    )
                except AuthScopeException as exc:
                    logger.info("OpenAPI discovery request failed", extra={"error": str(exc)})
                    continue

                document = response.json_data
                paths = document.get("paths") if isinstance(document, dict) else None
                if not isinstance(paths, dict) or not paths:
                    continue

                discovered: List[DiscoveredEndpoint] = []
                seen: set[tuple[str, str]] = set()
                for raw_path, operations in paths.items():
                    if not isinstance(raw_path, str) or not raw_path.startswith("/"):
                        continue
                    if not isinstance(operations, dict):
                        continue
                    for raw_method, operation in operations.items():
                        method = str(raw_method).upper()
                        if method != "GET" or not isinstance(operation, dict):
                            continue
                        key = (raw_path, method)
                        if key in seen:
                            continue
                        try:
                            route = self.register_endpoint(
                                path=raw_path,
                                method=method,
                                description=str(operation.get("summary") or operation.get("operationId") or ""),
                            )
                            operation_parameters = list(operations.get("parameters", [])) + list(operation.get("parameters", []))
                            declared_inputs = [
                                str(p.get("name")) for p in operation_parameters
                                if isinstance(p, dict) and p.get("name") and p.get("in") in {"path", "query"}
                            ]
                            outputs = self._response_identifier_fields(operation)
                            route = route.model_copy(update={
                                "input_parameters": list(dict.fromkeys(route.parameters + declared_inputs)),
                                "output_parameters": outputs,
                                "resource_identifier_name": outputs[0] if len(outputs) == 1 else None,
                            })
                        except (AuthScopeException, ValueError, TypeError) as exc:
                            logger.info(
                                "Skipping invalid OpenAPI route",
                                extra={"path": raw_path, "error": str(exc)},
                            )
                            continue
                        discovered.append(route)
                        seen.add(key)
                        if len(discovered) >= max_endpoints:
                            break
                    if len(discovered) >= max_endpoints:
                        break

                if discovered:
                    logger.info(
                        "Discovered GET routes from in-scope OpenAPI document",
                        extra={"count": len(discovered), "spec_url": candidate},
                    )
                    return discovered

        logger.info("Using configured Juice Shop GET routes as discovery fallback")
        return self.discover_known_routes()

    @staticmethod
    def _response_identifier_fields(operation: Dict[str, Any]) -> List[str]:
        """Extract identifier properties explicitly declared in a JSON response schema."""
        responses = operation.get("responses")
        if not isinstance(responses, dict):
            return []
        response = responses.get("200") or responses.get("201") or {}
        content = response.get("content", {}) if isinstance(response, dict) else {}
        media = content.get("application/json", {}) if isinstance(content, dict) else {}
        schema = media.get("schema", {}) if isinstance(media, dict) else {}
        candidates: List[str] = []

        def inspect_schema(value: Any) -> None:
            if not isinstance(value, dict):
                return
            properties = value.get("properties")
            if isinstance(properties, dict):
                for name, child in properties.items():
                    normalized = str(name).lower().replace("-", "_")
                    if normalized in {"id", "resource_id"} or normalized.endswith("_id"):
                        candidates.append(str(name))
                    if isinstance(child, dict):
                        inspect_schema(child)
            items = value.get("items")
            if isinstance(items, dict):
                inspect_schema(items)

        inspect_schema(schema)
        return list(dict.fromkeys(candidates))

    def build_concrete_url(
        self,
        endpoint: DiscoveredEndpoint | str,
        resource_id: Optional[str] = None
    ) -> str:
        """Builds a concrete, scope-validated URL by substituting resource_id into template."""
        raw_path = endpoint.path if isinstance(endpoint, DiscoveredEndpoint) else str(endpoint)
        if not raw_path.startswith("/"):
            raw_path = "/" + raw_path

        if TEMPLATE_PARAM_REGEX.search(raw_path):
            if not resource_id:
                raise InvalidTargetURLError(
                    f"Endpoint template '{raw_path}' requires a concrete resource_id to execute."
                )
            concrete_path = TEMPLATE_PARAM_REGEX.sub(str(resource_id), raw_path)
        else:
            concrete_path = raw_path

        full_url = f"{self.base_url}{concrete_path}"
        self.scope_guard.assert_in_scope(full_url, method="GET")
        return full_url
