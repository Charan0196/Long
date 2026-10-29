from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, Any, List


class Role(str, Enum):
    ADMIN = "admin"
    MEMBER = "member"
    GUEST = "guest"


class AccessLevel(str, Enum):
    VIEWER = "viewer"
    EDITOR = "editor"


@dataclass(frozen=True)
class Tenant:
    id: str
    name: str


@dataclass(frozen=True)
class User:
    id: str
    tenant_id: str
    role: Role

    @classmethod
    def create(cls, user_id: str, tenant_id: str, role: str | Role) -> User:
        return cls(id=user_id, tenant_id=tenant_id, role=Role(role))


@dataclass
class Document:
    id: str
    tenant_id: str
    owner_id: str
    title: str
    content: str
    shared_with: Dict[str, AccessLevel] = field(default_factory=dict)
    original_creator_id: Optional[str] = None

    def clone(self) -> Document:
        return Document(
            id=self.id,
            tenant_id=self.tenant_id,
            owner_id=self.owner_id,
            title=self.title,
            content=self.content,
            shared_with=dict(self.shared_with),
            original_creator_id=self.original_creator_id or self.owner_id,
        )


@dataclass(frozen=True)
class APIRequest:
    method: str
    path: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[Dict[str, Any]] = None

    @property
    def tenant_id(self) -> Optional[str]:
        return self.headers.get("X-Tenant-Id")

    @property
    def user_id(self) -> Optional[str]:
        return self.headers.get("X-User-Id")


@dataclass(frozen=True)
class APIResponse:
    status_code: int
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_forbidden(self) -> bool:
        return self.status_code == 403

    @property
    def is_not_found(self) -> bool:
        return self.status_code == 404
