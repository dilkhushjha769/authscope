"""Deterministic, non-executing planner for authorization attack-chain candidates.

Plans are hypotheses over discovered endpoint metadata. They contain relative paths
and parameter bindings only; they never authorize requests or establish findings.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator

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
    requires_auth: bool = True
    requires_owner_match: bool = False
    expected_allowed_roles: List[str] = Field(default_factory=list)
    requires_human_approval: bool = False
    dependencies: List[str] = Field(default_factory=list)
    _internal_resource_id: Optional[str] = None


class EndpointRelationship(BaseModel):
    source_endpoint_id: str
    target_endpoint_id: str
    relationship: RelationshipType
    rationale: str
    bindings: List[Tuple[str, str]] = Field(default_factory=list)


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
    method: str
    category: str
    resource_type: Optional[str] = None
    parameters: List[str] = Field(default_factory=list)
    requires_auth: bool
    requires_owner_match: bool
    expected_allowed_roles: List[str] = Field(default_factory=list)
    requires_human_approval: bool = False
    depends_on_step_ids: List[str] = Field(default_factory=list)
    input_bindings: List[InputBinding] = Field(default_factory=list)


class AttackChainCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "1.0"
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


class AttackChainPlan(BaseModel):
    schema_version: str = "1.0"
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
                                   "Declared endpoint dependency; prerequisite precedes dependent endpoint.")
                else:
                    unresolved.append(UnresolvedDependency(endpoint_id=node.endpoint_id, dependency=dependency,
                                                           reason="Dependency does not match any safe discovered endpoint."))
        for source in nodes:
            for target in nodes:
                if source.endpoint_id == target.endpoint_id:
                    continue
                match = self._identifier_binding(source, target)
                if match:
                    param, reason = match
                    rel = RelationshipType.RESOURCE_IDENTIFIER_FLOW if source.resource_type == target.resource_type else RelationshipType.RELATED_RESOURCE
                    self._add_edge(edges, source.endpoint_id, target.endpoint_id, rel, reason, [(param, source.endpoint_id)])
                if self._admin_boundary(source, target):
                    self._add_edge(edges, source.endpoint_id, target.endpoint_id, RelationshipType.PRIVILEGE_BOUNDARY,
                                   "Related discovered resource leads to an admin-only function requiring role-boundary validation.")
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

    @staticmethod
    def _get(raw: Any, key: str, default: Any = None) -> Any:
        return raw.get(key, default) if isinstance(raw, Mapping) else getattr(raw, key, default)

    def _coerce_endpoint(self, raw: Any) -> Tuple[Optional[EndpointNode], Optional[str]]:
        if isinstance(raw, str):
            path, method, metadata = raw, "GET", {}
        elif isinstance(raw, (DiscoveredEndpoint, Mapping)) or hasattr(raw, "path"):
            path = str(self._get(raw, "path", ""))
            method = str(self._get(raw, "method", "GET")).upper()
            metadata = raw if isinstance(raw, Mapping) else raw.model_dump() if hasattr(raw, "model_dump") else vars(raw)
        else:
            return None, "Endpoint must be a path string or discovered endpoint record."
        if not self._valid_path(path):
            return None, "Endpoint path must be a safe relative HTTP path (no URL, traversal, fragment, or control characters)."
        if method not in _SAFE_METHODS:
            return None, f"HTTP method {method!r} is not eligible for candidate chains."
        normalized = _TEMPLATE.sub(lambda m: "{" + (m.group(1) or m.group(2)).lower() + "}", path.split("?", 1)[0])
        params = list(self._get(raw, "parameters", []) or [])
        params.extend(name for match in _TEMPLATE.finditer(normalized) for name in [(match.group(1) or "").lower()] if name not in params)
        resource = self._get(raw, "resource_type")
        if not resource:
            segs = [seg for seg in normalized.strip("/").split("/") if seg]
            if len(segs) >= 2 and segs[0].lower() in ("rest", "api"):
                resource = segs[1].strip("{}").lower().rstrip("s")
        category = self._get(raw, "category", "UNKNOWN")
        category = category.value if isinstance(category, Enum) else str(category or "UNKNOWN").upper()
        deps = self._get(raw, "dependencies", self._get(raw, "depends_on", self._get(raw, "endpoint_dependencies", []))) or []
        if isinstance(deps, str):
            deps = [deps]
        eid = hashlib.sha256(f"{method} {normalized}".encode()).hexdigest()[:16]
        node = EndpointNode(endpoint_id=eid, path=normalized, method=method, category=category,
                            resource_type=str(resource).lower() if resource else None, parameters=list(dict.fromkeys(params)),
                            requires_auth=bool(self._get(raw, "requires_auth", True)),
                            requires_owner_match=bool(self._get(raw, "requires_owner_match", False)),
                            expected_allowed_roles=self._roles(raw),
                            requires_human_approval=bool(self._get(raw, "requires_human_approval", method not in {"GET", "HEAD"})),
                            dependencies=[str(dep) for dep in deps])
        # Keep a concrete identifier only in a private runtime attribute, never in the serialized graph/plan.
        concrete_id = self._get(raw, "extracted_resource_id")
        if concrete_id:
            object.__setattr__(node, "_internal_resource_id", str(concrete_id))
        return node, None

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
                  relation: RelationshipType, rationale: str, bindings: List[Tuple[str, str]] | None = None) -> None:
        key = (source, target, relation)
        edges.setdefault(key, EndpointRelationship(source_endpoint_id=source, target_endpoint_id=target,
                                                    relationship=relation, rationale=rationale, bindings=bindings or []))

    @staticmethod
    def _identifier_binding(source: EndpointNode, target: EndpointNode) -> Optional[Tuple[str, str]]:
        names = [p.lower().replace("-", "_") for p in target.parameters]
        templated = [m.group(1).lower() for m in _TEMPLATE.finditer(target.path)]
        names += templated
        if not any(name in _PARAM_ID_WORDS or name.endswith("_id") or name.endswith("id") for name in names):
            return None
        if source.resource_type and target.resource_type and source.resource_type == target.resource_type:
            param = next((p for p in target.parameters if p.lower() in _PARAM_ID_WORDS or p.lower().endswith("id")), "id")
            return param, f"Both endpoints concern {source.resource_type} resources and the target accepts a resource identifier."
        if source.resource_type:
            aliases = {source.resource_type, source.resource_type + "_id", source.resource_type + "id"}
            match = next((p for p in target.parameters if p.lower().replace("-", "_") in aliases), None)
            if match:
                return match, f"Target identifier parameter {match!r} refers to the source {source.resource_type} resource."
        return None

    @staticmethod
    def _admin_boundary(source: EndpointNode, target: EndpointNode) -> bool:
        return (target.category == EndpointCategory.ADMIN_FUNCTION.value and source.requires_auth
                and source.resource_type is not None and source.resource_type == target.resource_type)

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
        score = min(100, 20 + 10 * (len(path) - 2) + 24 * bola + 28 * privilege + 10 * related + 6 * (RelationshipType.EXPLICIT_DEPENDENCY in relations))
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
                        bindings.extend(InputBinding(parameter=param, source_step_id=step_id) for param, _ in edge.bindings)
            steps.append(AttackChainStep(step_id=f"step-{index + 1}", endpoint_id=node.endpoint_id, path=node.path,
                                         method=node.method, category=node.category, resource_type=node.resource_type,
                                         parameters=node.parameters, requires_auth=node.requires_auth,
                                         requires_owner_match=node.requires_owner_match,
                                         expected_allowed_roles=node.expected_allowed_roles,
                                         requires_human_approval=node.requires_human_approval,
                                         depends_on_step_ids=list(dict.fromkeys(depends)), input_bindings=bindings))
        candidate_id = "chain-" + hashlib.sha256("|".join(path).encode()).hexdigest()[:12]
        return AttackChainCandidate(candidate_id=candidate_id, scenario=scenario, risk_score=score, priority=priority,
                                    rationale=list(dict.fromkeys(rationale)), steps=steps, relationship_types=relations,
                                    requires_human_approval=any(n.requires_human_approval for n in path_nodes))
