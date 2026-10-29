from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, Optional, Any, List
from api.models import Tenant, User, Document, APIRequest, APIResponse, Role, AccessLevel


class BaseTarget(ABC):
    """Abstract base class for all synthetic API targets under test."""

    def __init__(self, tenants: Optional[Dict[str, Tenant]] = None, users: Optional[Dict[str, User]] = None):
        self.tenants: Dict[str, Tenant] = tenants or {}
        self.users: Dict[str, User] = users or {}
        self.documents: Dict[str, Document] = {}

    def seed_entities(self, tenants: List[Tenant], users: List[User]) -> None:
        self.tenants = {t.id: t for t in tenants}
        self.users = {u.id: u for u in users}
        self.documents = {}

    def reset(self) -> None:
        self.documents.clear()

    @abstractmethod
    def dispatch(self, request: APIRequest) -> APIResponse:
        """Process an API request against the target system state and return APIResponse."""
        pass

    def get_document(self, doc_id: str) -> Optional[Document]:
        doc = self.documents.get(doc_id)
        return doc.clone() if doc else None


def get_target(name: str) -> BaseTarget:
    """Target factory by name."""
    normalized = name.lower().replace("-", "_").replace("faulty_", "")
    if normalized in ("ref", "reference", "clean", "oracle"):
        from api.reference import ReferenceTarget
        return ReferenceTarget()
    elif normalized in ("idor", "idor_horizontal"):
        from api.faulty.idor import IDORTarget
        return IDORTarget()
    elif normalized in ("cross_tenant", "cross_tenant_leak"):
        from api.faulty.cross_tenant import CrossTenantTarget
        return CrossTenantTarget()
    elif normalized in ("guest_escalation", "guest"):
        from api.faulty.guest_escalation import GuestEscalationTarget
        return GuestEscalationTarget()
    elif normalized in ("stale_share", "stale_acl"):
        from api.faulty.stale_share import StaleShareTarget
        return StaleShareTarget()
    elif normalized in ("transfer_retention", "transfer"):
        from api.faulty.transfer_retention import TransferRetentionTarget
        return TransferRetentionTarget()
    else:
        raise ValueError(f"Unknown target '{name}'. Available: reference, idor, cross_tenant, guest_escalation, stale_share, transfer_retention")
