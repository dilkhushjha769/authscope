"""Deterministic, non-executing planner for authorization attack-chain candidates.

Plans are hypotheses over discovered endpoint metadata. They contain relative paths
and parameter bindings only; they never authorize requests or establish findings.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.scanner.endpoint_discovery import DiscoveredEndpoint, EndpointCategory
from backend.utils.logger import get_logger

logger = get_logger(__name__)
_TEMPLATE = re.compile(r"\{([A-Za-z0-9_]+)\}|:([A-Za-z0-9_]+)")
_SAFE_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH"}
_PARAM_ID_WORDS = {"id", "userid", "user_id", "basketid", "basket_id", "orderid", "order_id", "addressid", "address_id", "cardid", "card_id", "resourceid", "resource_id"}


class RelationshipType(str, Enum):
    EXPLICIT_DEPENDENCY = "EXPLICIT_DEPENDENCY"
    RESOURCE_IDENTIFIER_FLOW = "RESOURCE_IDENTIFIER_FLOW"
    RELATED_RESOURCE = "RELATED_RESOURCE"
    PRIVILEGE_BOUNDARY = "PRIVILEGE_BOUNDARY"


class RelationshipConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RiskMetadata(BaseModel):
    score: int = Field(ge=0, le=100)
    priority: str
    resource_sensitivity: Optional[str] = None
    rationale: List[str]


class ChainScenario(str, Enum):
    BOLA_IDOR = "BOLA_IDOR"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    RELATED_RESOURCE_ACCESS = "RELATED_RESOURCE_ACCESS"
    MIXED_AUTHORIZATION = "MIXED_AUTHORIZATION"


class InputBinding(BaseModel):
    """A symbolic value dependency; source values are resolved only at execution."""
    parameter: str
    source_step_id: str
    source_field: str = "response.resource_id"


class EndpointNode(BaseModel):
    endpoint_id: str
    path: str
    method: str
    category: str = "UNKNOWN"
    resource_type: Optional[str] = None
    parameters: List[str] = Field(default_factory=list)
    input_parameters: List[str] = Field(default_factory=list)
    output_parameters: List[str] = Field(default_factory=list)
    has_observed_resource_identifier: bool = False
    resource_identifier_name: Optional[str] = None
    parent_resource_type: Optional[str] = None
    related_resource_types: List[str] = Field(default_factory=list)
    resource_sensitivity: Optional[str] = None
    requires_auth: bool = True
    requires_owner_match: bool = False
    expected_allowed_roles: List[str] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    requires_human_approval: bool = False
    dependencies: List[str] = Field(default_factory=list)


class EndpointRelationship(BaseModel):
    source_endpoint_id: str
    target_endpoint_id: str
    relationship: RelationshipType
    rationale: str
    bindings: List[Tuple[str, str]] = Field(default_factory=list)
    confidence: RelationshipConfidence = RelationshipConfidence.HIGH
    evidence: List[str] = Field(default_factory=list)
    uncertain: bool = False


class UnresolvedDependency(BaseModel):
    endpoint_id: str
    dependency: str
    reason: str


class RejectedEndpoint(BaseModel):
    supplied_value: str
    reason: str


class EndpointRelationshipGraph(BaseModel):
    nodes: List[EndpointNode] = Field(default_factory=list)
    relationships: List[EndpointRelationship] = Field(default_factory=list)
    unresolved_dependencies: List[UnresolvedDependency] = Field(default_factory=list)
    rejected_endpoints: List[RejectedEndpoint] = Field(default_factory=list)


class AttackChainStep(BaseModel):
    step_id: str
    endpoint_id: str
    path: str
    endpoint: str
    method: str
    http_method: str
    category: str
    resource_type: Optional[str] = None
    parameters: List[str] = Field(default_factory=list)
    input_parameters: List[str] = Field(default_factory=list)
    output_parameters: List[str] = Field(default_factory=list)
    resource_dependencies: List[str] = Field(default_factory=list)
    expected_role: Optional[str] = None
    permissions: List[str] = Field(default_factory=list)
    purpose: str
    requires_auth: bool
    requires_owner_match: bool
    expected_allowed_roles: List[str] = Field(default_factory=list)
    requires_human_approval: bool = False
    depends_on_step_ids: List[str] = Field(default_factory=list)
    input_bindings: List[InputBinding] = Field(default_factory=list)


class AttackChainCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "1.1"
    chain_id: str
    chain_name: str
    vulnerability_category: ChainScenario
    risk_metadata: RiskMetadata
    ordered_steps: List[AttackChainStep] = Field(min_length=2, max_length=5)
    # Compatibility fields consumed by Member 2's current validator/executor.
    candidate_id: str
    scenario: ChainScenario
    risk_score: int = Field(ge=0, le=100)
    priority: str
    rationale: List[str]
    steps: List[AttackChainStep] = Field(min_length=2, max_length=5)
    relationship_types: List[RelationshipType]
    requires_scope_validation: bool = True
    execution_authorized: bool = False
    requires_human_approval: bool = False
    status: str = "CANDIDATE_UNVERIFIED"

    @model_validator(mode="after")
    def validate_executor_compatibility(self) -> "AttackChainCandidate":
        """Keep the Member 2 executor's current legacy field names in lockstep."""
        if self.chain_id != self.candidate_id:
            raise ValueError("chain_id must match candidate_id")
        if self.vulnerability_category != self.scenario:
            raise ValueError("vulnerability_category must match scenario")
        if [step.model_dump() for step in self.ordered_steps] != [step.model_dump() for step in self.steps]:
            raise ValueError("ordered_steps must match executor-compatible steps")
        if self.risk_metadata.score != self.risk_score or self.risk_metadata.priority != self.priority:
            raise ValueError("risk_metadata must match the top-level risk fields")
        return self


class AttackChainPlan(BaseModel):
    schema_version: str = "1.1"
    max_steps: int = Field(ge=2, le=5)
    candidates: List[AttackChainCandidate] = Field(default_factory=list)
    graph: EndpointRelationshipGraph
    summary: str
    ai_suggestions_used: bool = False


class AttackChainPlanner:
    """Builds endpoint relationships and ranks bounded simple paths deterministically."""

    def build_graph(self, discovered_routes: Sequence[Any]) -> EndpointRelationshipGraph:
        nodes: List[EndpointNode] = []
        rejected: List[RejectedEndpoint] = []
        unresolved: List[UnresolvedDependency] = []
        by_id: Dict[str, EndpointNode] = {}
        aliases: Dict[str, List[str]] = defaultdict(list)
        for raw in discovered_routes:
            node, issue = self._coerce_endpoint(raw)
            if issue:
                rejected.append(RejectedEndpoint(supplied_value=str(self._get(raw, "path", raw)), reason=issue))
                continue
            assert node is not None
            if node.endpoint_id in by_id:
                continue
            nodes.append(node)
            by_id[node.endpoint_id] = node
            aliases[node.path].append(node.endpoint_id)
            aliases[node.endpoint_id].append(node.endpoint_id)
        edges: Dict[Tuple[str, str, RelationshipType], EndpointRelationship] = {}
        for node in nodes:
            for dependency in node.dependencies:
                target = next((candidate for candidate in aliases.get(dependency, []) if candidate != node.endpoint_id), None)
                if target:
                    self._add_edge(edges, target, node.endpoint_id, RelationshipType.EXPLICIT_DEPENDENCY,
                                   "Declared endpoint dependency; prerequisite precedes dependent endpoint.",
                                   evidence=[f"Endpoint metadata declares dependency on {dependency}."])
                else:
                    unresolved.append(UnresolvedDependency(endpoint_id=node.endpoint_id, dependency=dependency,
                                                           reason="Dependency does not match any safe discovered endpoint."))
        for source in nodes:
            for target in nodes:
                if source.endpoint_id == target.endpoint_id:
                    continue
                match = self._identifier_binding(source, target)
                if match:
                    param, reason, evidence, confidence = match
                    rel = RelationshipType.RESOURCE_IDENTIFIER_FLOW if source.resource_type == target.resource_type else RelationshipType.RELATED_RESOURCE
                    self._add_edge(edges, source.endpoint_id, target.endpoint_id, rel, reason, [(param, source.endpoint_id)])
                    edges[(source.endpoint_id, target.endpoint_id, rel)].evidence = evidence
                    edges[(source.endpoint_id, target.endpoint_id, rel)].confidence = confidence
                else:
                    uncertain = self._uncertain_identifier_relationship(source, target)
                    if uncertain:
                        param, reason = uncertain
                        self._add_edge(edges, source.endpoint_id, target.endpoint_id,
                                       RelationshipType.RESOURCE_IDENTIFIER_FLOW, reason,
                                       [(param, source.endpoint_id)], confidence=RelationshipConfidence.LOW,
                                       evidence=["Matching identifier parameter exists, but source output metadata is missing."],
                                       uncertain=True)
                if match and self._admin_boundary(source, target):
                    self._add_edge(edges, source.endpoint_id, target.endpoint_id, RelationshipType.PRIVILEGE_BOUNDARY,
                                   "Verified resource metadata connects to a role-restricted administrative operation.",
                                   evidence=["Source output identifier matches target input parameter.", "Target expected role metadata is admin-only."])
        graph = EndpointRelationshipGraph(nodes=nodes, relationships=list(edges.values()),
                                          unresolved_dependencies=unresolved, rejected_endpoints=rejected)
        logger.info("Built endpoint relationship graph", extra={"nodes": len(nodes), "edges": len(edges), "rejected": len(rejected)})
        return graph

    def plan(self, discovered_routes: Sequence[Any], max_steps: int = 5, max_candidates: int = 25) -> AttackChainPlan:
        if not 2 <= max_steps <= 5:
            raise ValueError("max_steps must be between 2 and 5")
        if max_candidates < 1:
            raise ValueError("max_candidates must be at least 1")
        graph = self.build_graph(discovered_routes)
        nodes = {node.endpoint_id: node for node in graph.nodes}
        outgoing: Dict[str, List[EndpointRelationship]] = defaultdict(list)
        for edge in graph.relationships:
            if not edge.uncertain:
                outgoing[edge.source_endpoint_id].append(edge)
        found: Dict[Tuple[str, ...], Tuple[List[str], List[EndpointRelationship]]] = {}

        def walk(path: List[str], edges: List[EndpointRelationship]) -> None:
            if len(path) >= 2:
                found.setdefault(tuple(path), (path.copy(), edges.copy()))
            if len(path) >= max_steps:
                return
            for edge in sorted(outgoing.get(path[-1], []), key=lambda item: item.target_endpoint_id):
                if edge.target_endpoint_id not in path:
                    walk(path + [edge.target_endpoint_id], edges + [edge])

        for node_id in sorted(nodes):
            walk([node_id], [])
        candidates = [self._candidate(path, edges, nodes) for path, edges in found.values()]
        candidates.sort(key=lambda item: (-item.risk_score, -len(item.steps), item.candidate_id))
        candidates = candidates[:max_candidates]
        return AttackChainPlan(max_steps=max_steps, candidates=candidates, graph=graph,
                               summary=f"Generated {len(candidates)} unverified candidate chains from {len(graph.nodes)} safe endpoints.")

    def plan_chain(self, discovered_routes: Sequence[Any], max_steps: int = 5) -> List[Dict[str, Any]]:
        """Backward-compatible serialized candidate list; no route is executed."""
        return [item.model_dump(mode="json") for item in self.plan(discovered_routes, max_steps).candidates]

    def apply_ai_suggestions(self, plan: AttackChainPlan, suggestions: Sequence[Any]) -> AttackChainPlan:
        """Use AI output only to reorder known candidate IDs; reject invented chain data.

        Each suggestion may be an ID string or a mapping containing ``chain_id`` /
        ``candidate_id``. Any supplied routes, steps, scores, or authorization fields
        are ignored. Unknown and duplicate IDs are discarded.
        """
        known = {candidate.candidate_id: candidate for candidate in plan.candidates}
        ordered_ids: List[str] = []
        for suggestion in suggestions:
            candidate_id = (suggestion if isinstance(suggestion, str) else
                            suggestion.get("candidate_id", suggestion.get("chain_id"))
                            if isinstance(suggestion, Mapping) else None)
            if isinstance(candidate_id, str) and candidate_id in known and candidate_id not in ordered_ids:
                ordered_ids.append(candidate_id)
        remaining = [candidate.candidate_id for candidate in plan.candidates if candidate.candidate_id not in ordered_ids]
        ordered = [known[candidate_id] for candidate_id in ordered_ids + remaining]
        return plan.model_copy(update={"candidates": ordered, "ai_suggestions_used": bool(ordered_ids)})

    @staticmethod
    def _get(raw: Any, key: str, default: Any = None) -> Any:
        return raw.get(key, default) if isinstance(raw, Mapping) else getattr(raw, key, default)

    def _coerce_endpoint(self, raw: Any) -> Tuple[Optional[EndpointNode], Optional[str]]:
        if isinstance(raw, str):
            path, method = raw, "GET"
        elif isinstance(raw, (DiscoveredEndpoint, Mapping)) or hasattr(raw, "path"):
            path = str(self._get(raw, "path", ""))
            method = str(self._get(raw, "method", "GET")).upper()
        else:
            return None, "Endpoint must be a path string or discovered endpoint record."
        if not self._valid_path(path):
            return None, "Endpoint path must be a safe relative HTTP path (no URL, traversal, fragment, or control characters)."
        if method not in _SAFE_METHODS:
            return None, f"HTTP method {method!r} is not eligible for candidate chains."
        normalized = _TEMPLATE.sub(lambda m: "{" + (m.group(1) or m.group(2)).lower() + "}", path.split("?", 1)[0])
        params = list(self._get(raw, "parameters", []) or [])
        params.extend(name for match in _TEMPLATE.finditer(normalized) for name in [(match.group(1) or "").lower()] if name not in params)
        input_params = list(self._get(raw, "input_parameters", params) or [])
        resource = self._get(raw, "resource_type")
        if not resource:
            segs = [seg for seg in normalized.strip("/").split("/") if seg]
            if len(segs) >= 2 and segs[0].lower() in ("rest", "api"):
                resource = segs[1].strip("{}").lower().rstrip("s")
        output_params = list(self._get(raw, "output_parameters", []) or [])
        category = self._get(raw, "category", "UNKNOWN")
        category = category.value if isinstance(category, Enum) else str(category or "UNKNOWN").upper()
        expected_roles = self._roles(raw)
        permissions = self._string_list(self._get(raw, "permissions", self._get(raw, "required_permissions", [])))
        related = self._string_list(self._get(raw, "related_resource_types", []))
        deps = self._get(raw, "dependencies", self._get(raw, "depends_on", self._get(raw, "endpoint_dependencies", []))) or []
        if isinstance(deps, str):
            deps = [deps]
        eid = hashlib.sha256(f"{method} {normalized}".encode()).hexdigest()[:16]
        node = EndpointNode(endpoint_id=eid, path=normalized, method=method, category=category,
                            resource_type=str(resource).lower() if resource else None, parameters=list(dict.fromkeys(params)),
                            input_parameters=list(dict.fromkeys(map(str, input_params))),
                            output_parameters=list(dict.fromkeys(map(str, output_params))),
                            resource_identifier_name=self._optional_str(self._get(raw, "resource_identifier_name", self._get(raw, "identifier_parameter"))),
                            parent_resource_type=self._optional_str(self._get(raw, "parent_resource_type")),
                            related_resource_types=[value.lower() for value in related],
                            resource_sensitivity=self._optional_str(self._get(raw, "resource_sensitivity", self._get(raw, "sensitivity"))),
                            has_observed_resource_identifier=bool(self._get(raw, "extracted_resource_id")),
                            requires_auth=bool(self._get(raw, "requires_auth", True)),
                            requires_owner_match=bool(self._get(raw, "requires_owner_match", False)),
                            expected_allowed_roles=expected_roles,
                            permissions=permissions,
                            requires_human_approval=bool(self._get(raw, "requires_human_approval", method not in {"GET", "HEAD"})),
                            dependencies=[str(dep) for dep in deps])
        return node, None

    @staticmethod
    def _string_list(values: Any) -> List[str]:
        if values is None:
            return []
        if isinstance(values, str):
            return [values]
        return [str(value.value if isinstance(value, Enum) else value) for value in values]

    @staticmethod
    def _optional_str(value: Any) -> Optional[str]:
        return str(value) if value is not None and str(value).strip() else None

    @staticmethod
    def _roles(raw: Any) -> List[str]:
        roles = AttackChainPlanner._get(raw, "expected_allowed_roles", []) or []
        return [str(role.value if isinstance(role, Enum) else role).lower() for role in roles]

    @staticmethod
    def _valid_path(path: str) -> bool:
        return bool(path and path.startswith("/") and not path.startswith("//") and "\\" not in path
                    and not any(ord(char) < 32 for char in path) and "#" not in path
                    and not re.match(r"^/[A-Za-z][A-Za-z0-9+.-]*://", path)
                    and all(segment != ".." for segment in path.split("/")))

    @staticmethod
    def _add_edge(edges: Dict[Tuple[str, str, RelationshipType], EndpointRelationship], source: str, target: str,
                  relation: RelationshipType, rationale: str, bindings: List[Tuple[str, str]] | None = None,
                  confidence: RelationshipConfidence = RelationshipConfidence.HIGH,
                  evidence: List[str] | None = None, uncertain: bool = False) -> None:
        key = (source, target, relation)
        edges.setdefault(key, EndpointRelationship(source_endpoint_id=source, target_endpoint_id=target,
                                                    relationship=relation, rationale=rationale, bindings=bindings or [],
                                                    confidence=confidence, evidence=evidence or [], uncertain=uncertain))

    @staticmethod
    def _identifier_binding(source: EndpointNode, target: EndpointNode) -> Optional[Tuple[str, str, List[str], RelationshipConfidence]]:
        target_inputs = {p.lower().replace("-", "_") for p in (target.input_parameters or target.parameters)}
        source_outputs = {p.lower().replace("-", "_") for p in source.output_parameters}
        if not source.resource_type or not target_inputs or (not source_outputs and not source.resource_identifier_name):
            return None
        identifier = (source.resource_identifier_name or
                      next((name for name in source_outputs if name in _PARAM_ID_WORDS or name.endswith("_id") or name.endswith("id")), None))
        if not identifier:
            return None
        normalized_id = identifier.lower().replace("-", "_")
        aliases = {source.resource_type, source.resource_type + "_id", source.resource_type + "id", "id"}
        same_resource = source.resource_type == target.resource_type and ("id" in target_inputs or normalized_id in target_inputs)
        parent_child = (target.parent_resource_type or "").lower() == source.resource_type
        related = source.resource_type in target.related_resource_types
        matched = next((name for name in target_inputs if name == normalized_id or name in aliases), None)
        if same_resource and matched:
            source_evidence = f"source.resource_identifier_name={identifier}" if source.resource_identifier_name else f"source.output_parameters includes {identifier}"
            return matched, f"Source output identifier {identifier!r} matches a target input for the same resource type.", [source_evidence, f"target.input_parameters includes {matched}", f"resource_type={source.resource_type}"], RelationshipConfidence.HIGH
        if (parent_child or related) and matched:
            source_evidence = f"source.resource_identifier_name={identifier}" if source.resource_identifier_name else f"source.output_parameters includes {identifier}"
            return matched, f"Explicit parent/related-resource metadata connects {source.resource_type} to {target.resource_type or 'a related resource'} via {matched!r}.", [source_evidence, f"target input={matched}", "explicit parent/related resource metadata"], RelationshipConfidence.HIGH
        return None

    @staticmethod
    def _uncertain_identifier_relationship(source: EndpointNode, target: EndpointNode) -> Optional[Tuple[str, str]]:
        inputs = {p.lower().replace("-", "_") for p in (target.input_parameters or target.parameters)}
        if source.resource_type and source.resource_type == target.resource_type and "id" in inputs:
            return "id", "Possible same-resource identifier flow; source output parameters are unavailable, so this edge is uncertain and excluded from plans."
        parent_id = f"{source.resource_type}_id" if source.resource_type else ""
        if source.resource_type and target.parent_resource_type == source.resource_type and parent_id in inputs:
            return parent_id, "Declared parent-child metadata indicates a possible flow, but source output parameters are missing; this edge is uncertain and excluded from plans."
        return None

    @staticmethod
    def _admin_boundary(source: EndpointNode, target: EndpointNode) -> bool:
        return (target.category == EndpointCategory.ADMIN_FUNCTION.value and source.requires_auth
                and source.resource_type is not None and source.resource_type == target.resource_type
                and any(role.lower() == "admin" for role in target.expected_allowed_roles))

    def _candidate(self, path: List[str], edges: List[EndpointRelationship], nodes: Dict[str, EndpointNode]) -> AttackChainCandidate:
        path_nodes = [nodes[endpoint_id] for endpoint_id in path]
        relations = list(dict.fromkeys(edge.relationship for edge in edges))
        bola = any(node.requires_owner_match for node in path_nodes) or RelationshipType.RESOURCE_IDENTIFIER_FLOW in relations
        privilege = RelationshipType.PRIVILEGE_BOUNDARY in relations or any(
            node.category == EndpointCategory.ADMIN_FUNCTION.value for node in path_nodes[1:])
        related = RelationshipType.RELATED_RESOURCE in relations
        scenario = (ChainScenario.MIXED_AUTHORIZATION if bola and privilege else
                    ChainScenario.PRIVILEGE_ESCALATION if privilege else
                    ChainScenario.BOLA_IDOR if bola else ChainScenario.RELATED_RESOURCE_ACCESS)
        rationale = [edge.rationale for edge in edges]
        if bola:
            rationale.append("Candidate includes an owner-sensitive object or identifier flow; runtime authorization must be compared across roles.")
        if privilege:
            rationale.append("Candidate crosses an administrative boundary; role policy and scope must be independently validated.")
        if related:
            rationale.append("Candidate links related resource types through discovered metadata.")
        sensitivities = [node.resource_sensitivity.upper() for node in path_nodes if node.resource_sensitivity]
        sensitivity = max(sensitivities, key=lambda value: {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(value, 0), default=None)
        sensitivity_weight = {"LOW": 0, "MEDIUM": 4, "HIGH": 8, "CRITICAL": 12}.get(sensitivity or "", 0)
        score = min(100, 20 + 10 * (len(path) - 2) + 24 * bola + 28 * privilege + 10 * related + 6 * (RelationshipType.EXPLICIT_DEPENDENCY in relations) + sensitivity_weight)
        priority = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 40 else "LOW"
        steps: List[AttackChainStep] = []
        for index, node in enumerate(path_nodes):
            bindings: List[InputBinding] = []
            depends: List[str] = []
            if index:
                for edge in edges[:index]:
                    if edge.target_endpoint_id == node.endpoint_id:
                        prior = path.index(edge.source_endpoint_id)
                        step_id = f"step-{prior + 1}"
                        depends.append(step_id)
                        source_node = nodes[edge.source_endpoint_id]
                        source_field = source_node.resource_identifier_name or next(
                            (name for name in source_node.output_parameters
                             if name.lower().replace("-", "_") in _PARAM_ID_WORDS
                             or name.lower().endswith("_id") or name.lower().endswith("id")),
                            "resource_id",
                        )
                        bindings.extend(
                            InputBinding(parameter=param, source_step_id=step_id, source_field=source_field)
                            for param, _ in edge.bindings
                        )
            steps.append(AttackChainStep(step_id=f"step-{index + 1}", endpoint_id=node.endpoint_id, path=node.path,
                                         endpoint=node.path, method=node.method, http_method=node.method,
                                         category=node.category, resource_type=node.resource_type,
                                         parameters=node.parameters, requires_auth=node.requires_auth,
                                         input_parameters=node.input_parameters, output_parameters=node.output_parameters,
                                         resource_dependencies=[node.parent_resource_type] if node.parent_resource_type else [],
                                         expected_role=node.expected_allowed_roles[0] if len(node.expected_allowed_roles) == 1 else None,
                                         permissions=node.permissions,
                                         purpose=self._step_purpose(index, node, scenario),
                                         requires_owner_match=node.requires_owner_match,
                                         expected_allowed_roles=node.expected_allowed_roles,
                                         requires_human_approval=node.requires_human_approval,
                                         depends_on_step_ids=list(dict.fromkeys(depends)), input_bindings=bindings))
        candidate_id = "chain-" + hashlib.sha256("|".join(path).encode()).hexdigest()[:12]
        rationale = list(dict.fromkeys(rationale))
        chain_name = f"{scenario.value.replace('_', ' ').title()} candidate"
        risk_metadata = RiskMetadata(score=score, priority=priority, resource_sensitivity=sensitivity, rationale=rationale)
        return AttackChainCandidate(schema_version="1.1", chain_id=candidate_id, chain_name=chain_name,
                                    vulnerability_category=scenario, risk_metadata=risk_metadata,
                                    ordered_steps=steps, candidate_id=candidate_id, scenario=scenario,
                                    risk_score=score, priority=priority, rationale=rationale, steps=steps,
                                    relationship_types=relations,
                                    requires_human_approval=any(n.requires_human_approval for n in path_nodes))

    @staticmethod
    def _step_purpose(index: int, node: EndpointNode, scenario: ChainScenario) -> str:
        if index == 0:
            return "Discover an in-scope resource and establish the source values for later checks."
        if node.category == EndpointCategory.ADMIN_FUNCTION.value:
            return "Check whether the selected lower-privilege role is blocked from this admin-restricted operation."
        if node.requires_owner_match:
            return "Check that a role cannot access this owner-bound resource using another role's identifier."
        if node.parent_resource_type:
            return f"Check access to the {node.resource_type or 'related'} resource through its {node.parent_resource_type} dependency."
        return f"Validate the {scenario.value.lower()} boundary on this related endpoint."
