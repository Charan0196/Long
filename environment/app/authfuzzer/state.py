from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
from api.models import User, Tenant, Role, AccessLevel


@dataclass
class SimulatedDocumentState:
    id: str
    tenant_id: str
    owner_id: str
    is_deleted: bool = False
    shares: Dict[str, AccessLevel] = field(default_factory=dict)
    original_creator_id: Optional[str] = None


class FuzzSystemState:
    """Tracks simulated system state to generate plausible sequences."""

    def __init__(self, tenants: List[Tenant], users: List[User]):
        self.tenants: Dict[str, Tenant] = {t.id: t for t in tenants}
        self.users: Dict[str, User] = {u.id: u for u in users}
        self.users_by_tenant: Dict[str, List[User]] = {}
        for u in users:
            self.users_by_tenant.setdefault(u.tenant_id, []).append(u)
        self.documents: Dict[str, SimulatedDocumentState] = {}

    def reset(self) -> None:
        self.documents.clear()

    def get_users_in_tenant(self, tenant_id: str, role: Optional[Role] = None) -> List[User]:
        users = self.users_by_tenant.get(tenant_id, [])
        if role is not None:
            return [u for u in users if u.role == role]
        return list(users)

    def get_active_documents(self, tenant_id: Optional[str] = None) -> List[SimulatedDocumentState]:
        docs = [d for d in self.documents.values() if not d.is_deleted]
        if tenant_id:
            docs = [d for d in docs if d.tenant_id == tenant_id]
        return docs
