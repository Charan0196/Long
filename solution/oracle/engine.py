from __future__ import annotations
from typing import List, Dict, Optional, Tuple, Any
from api.client import BaseTarget
from api.models import Tenant, User, Document, Role, AccessLevel
from api.policy import AuthorizationPolicy
from authfuzzer.models import (
    Scenario,
    FuzzReport,
    Violation,
    FuzzAction,
    ExpectedDecision,
    ObservedDecision,
)
from authfuzzer.minimizer import SequenceMinimizer


class DifferentialEngine:
    """Executes scenarios differentially against target API and ground-truth policy."""

    def __init__(self, target: BaseTarget, tenants: List[Tenant], users: List[User]):
        self.target = target
        self.tenants = tenants
        self.users = users
        self.users_map = {u.id: u for u in users}
        self.minimizer = SequenceMinimizer(target, tenants, users)

    def run_scenarios(self, scenarios: List[Scenario], seed: int = 42, minimize: bool = True) -> FuzzReport:
        total_requests = 0
        violations: List[Violation] = []
        violation_counter = 0

        for sc in scenarios:
            self.target.reset()
            ref_documents: Dict[str, Document] = {}
            history: List[FuzzAction] = []
            deleted_ids = set()

            for idx, action in enumerate(sc.actions):
                total_requests += 1
                history.append(action)
                req = action.to_request()

                # 1. Ground truth evaluation
                expected = AuthorizationPolicy.evaluate(req, self.users_map, ref_documents)

                # 2. Target execution
                actual = self.target.dispatch(req)

                # 3. Mirror state in reference model on permitted transitions
                if expected.allowed:
                    method = req.method.upper()
                    path = req.path
                    if method == "POST" and path == "/api/v1/documents":
                        body = req.body or {}
                        d_id = body.get("id")
                        if d_id:
                            ref_documents[d_id] = Document(
                                id=d_id,
                                tenant_id=req.tenant_id,
                                owner_id=req.user_id,
                                title=body.get("title", ""),
                                content=body.get("content", ""),
                                shared_with={},
                                original_creator_id=req.user_id,
                            )
                    elif "/api/v1/documents/" in path:
                        parts = path.strip("/").split("/")
                        d_id = parts[3]
                        subpath = parts[4] if len(parts) > 4 else None
                        doc = ref_documents.get(d_id)
                        if doc:
                            if method == "PUT" and subpath is None:
                                body = req.body or {}
                                if "content" in body:
                                    doc.content = body["content"]
                            elif method == "DELETE" and subpath is None:
                                deleted_ids.add(d_id)
                                del ref_documents[d_id]
                            elif method == "POST" and subpath == "share":
                                body = req.body or {}
                                target_uid = body.get("target_user_id")
                                level = body.get("access_level", "viewer")
                                if target_uid:
                                    doc.shared_with[target_uid] = AccessLevel(level)
                            elif method == "POST" and subpath == "revoke":
                                body = req.body or {}
                                target_uid = body.get("target_user_id")
                                if target_uid in doc.shared_with:
                                    del doc.shared_with[target_uid]
                            elif method == "POST" and subpath == "transfer":
                                body = req.body or {}
                                new_owner = body.get("new_owner_id")
                                if new_owner:
                                    doc.owner_id = new_owner

                # 4. Differential check
                if expected.status_code != actual.status_code:
                    violation_counter += 1
                    vuln_type = self._classify_violation(action, expected.status_code, actual.status_code, deleted_ids)

                    failing_trace = list(history)
                    if minimize and len(failing_trace) > 1:
                        minimized_trace = self.minimizer.minimize(
                            failing_trace,
                            expected_status=expected.status_code,
                            observed_status=actual.status_code,
                        )
                    else:
                        minimized_trace = failing_trace

                    v = Violation(
                        id=f"VIOLATION-{violation_counter:03d}",
                        vulnerability_type=vuln_type,
                        target_endpoint=action.endpoint,
                        method=action.method,
                        step_index=action.step,
                        expected=ExpectedDecision(
                            status_code=expected.status_code,
                            decision="ALLOW" if expected.allowed else "DENY",
                            reason=expected.reason,
                        ),
                        actual=ObservedDecision(
                            status_code=actual.status_code,
                            decision="ALLOW" if actual.is_success else "DENY",
                        ),
                        original_sequence_length=len(failing_trace),
                        minimized_sequence_length=len(minimized_trace),
                        minimized_sequence=minimized_trace,
                    )
                    violations.append(v)
                    # Once a scenario triggers a violation, stop further steps in this scenario
                    break

        return FuzzReport(
            seed=seed,
            total_scenarios=len(scenarios),
            total_requests=total_requests,
            violations=violations,
        )

    def _classify_violation(
        self,
        action: FuzzAction,
        expected_status: int,
        actual_status: int,
        deleted_ids: set,
    ) -> str:
        # Check cross-tenant
        caller = self.users_map.get(action.user_id)
        endpoint = action.endpoint
        doc_id = endpoint.split("/")[4] if "/api/v1/documents/" in endpoint else None

        if actual_status == 200 or actual_status == 201:
            if doc_id and doc_id in deleted_ids and action.name == "read_document":
                return "STALE_ACL_ACCESS"
            if caller and action.tenant_id != caller.tenant_id:
                return "CROSS_TENANT_ACCESS"
            if action.name == "delete_document":
                return "TRANSFERRED_OWNER_RETENTION"
            if caller and caller.role == Role.GUEST:
                return "GUEST_PRIVILEGE_ESCALATION"
            if action.method in ("GET", "PUT"):
                return "IDOR_HORIZONTAL"
        return "AUTHORIZATION_INCONSISTENCY"
