from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from api.models import APIRequest, APIResponse, Role, AccessLevel


@dataclass(frozen=True)
class FuzzAction:
    step: int
    name: str
    tenant_id: str
    user_id: str
    method: str
    endpoint: str
    payload: Optional[Dict[str, Any]] = None

    def to_request(self) -> APIRequest:
        headers = {
            "X-Tenant-Id": self.tenant_id,
            "X-User-Id": self.user_id,
        }
        return APIRequest(
            method=self.method,
            path=self.endpoint,
            headers=headers,
            body=self.payload,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "action": self.name,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "method": self.method,
            "endpoint": self.endpoint,
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FuzzAction:
        return cls(
            step=data.get("step", 0),
            name=data.get("action", data.get("name", "")),
            tenant_id=data.get("tenant_id", ""),
            user_id=data.get("user_id", ""),
            method=data.get("method", "GET"),
            endpoint=data.get("endpoint", ""),
            payload=data.get("payload"),
        )


@dataclass
class Scenario:
    id: str
    actions: List[FuzzAction] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.actions)


@dataclass
class ExpectedDecision:
    status_code: int
    decision: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "decision": self.decision,
            "reason": self.reason,
        }


@dataclass
class ObservedDecision:
    status_code: int
    decision: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "decision": self.decision,
        }


@dataclass
class Violation:
    id: str
    vulnerability_type: str
    target_endpoint: str
    method: str
    step_index: int
    expected: ExpectedDecision
    actual: ObservedDecision
    original_sequence_length: int
    minimized_sequence_length: int
    minimized_sequence: List[FuzzAction]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "vulnerability_type": self.vulnerability_type,
            "target_endpoint": self.target_endpoint,
            "method": self.method,
            "step_index": self.step_index,
            "expected": self.expected.to_dict(),
            "actual": self.actual.to_dict(),
            "original_sequence_length": self.original_sequence_length,
            "minimized_sequence_length": self.minimized_sequence_length,
            "minimized_sequence": [a.to_dict() for a in self.minimized_sequence],
        }


@dataclass
class FuzzReport:
    seed: int
    total_scenarios: int
    total_requests: int
    violations: List[Violation] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seed": self.seed,
            "summary": {
                "total_scenarios": self.total_scenarios,
                "total_requests": self.total_requests,
                "violations_found": len(self.violations),
            },
            "violations": [v.to_dict() for v in self.violations],
        }
