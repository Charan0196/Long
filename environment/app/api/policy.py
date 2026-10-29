from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Optional, Any
from api.models import Role, AccessLevel, User, Document, APIRequest


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    status_code: int
    reason: str


class AuthorizationPolicy:
    """Ground truth reference authorization policy evaluator."""

    @staticmethod
    def evaluate(
        request: APIRequest,
        users: Dict[str, User],
        documents: Dict[str, Document],
    ) -> PolicyDecision:
        user_id = request.user_id
        tenant_id = request.tenant_id

        # Missing or invalid authentication headers
        if not user_id or not tenant_id:
            return PolicyDecision(False, 401, "Missing authentication headers")

        user = users.get(user_id)
        if not user or user.tenant_id != tenant_id:
            return PolicyDecision(False, 401, "User does not belong to specified tenant")

        method = request.method.upper()
        path = request.path

        # 1. POST /api/v1/documents (Create Document)
        if method == "POST" and path == "/api/v1/documents":
            if user.role == Role.GUEST:
                return PolicyDecision(False, 403, "Guests are not permitted to create documents")
            body = request.body or {}
            doc_id = body.get("id")
            if not doc_id:
                return PolicyDecision(False, 400, "Missing document id")
            if doc_id in documents:
                return PolicyDecision(False, 409, "Document ID already exists")
            return PolicyDecision(True, 201, "Document creation permitted")

        # Parsing resource path: /api/v1/documents/{doc_id}[/subpath]
        parts = path.strip("/").split("/")
        if len(parts) < 4 or parts[:3] != ["api", "v1", "documents"]:
            return PolicyDecision(False, 404, "Unknown endpoint")

        doc_id = parts[3]
        subpath = parts[4] if len(parts) > 4 else None

        doc = documents.get(doc_id)
        if not doc:
            return PolicyDecision(False, 404, f"Document '{doc_id}' not found")

        # Strict Tenant Isolation:
        if doc.tenant_id != tenant_id:
            return PolicyDecision(False, 403, "Cross-tenant document access forbidden")

        # 2. GET /api/v1/documents/{doc_id} (Read Document)
        if method == "GET" and subpath is None:
            if user.role == Role.ADMIN:
                return PolicyDecision(True, 200, "Admin read permitted")
            if user.id == doc.owner_id:
                return PolicyDecision(True, 200, "Owner read permitted")
            if user.id in doc.shared_with:
                return PolicyDecision(True, 200, "Shared user read permitted")
            return PolicyDecision(False, 403, "User has no read access to this document")

        # 3. PUT /api/v1/documents/{doc_id} (Update Document)
        if method == "PUT" and subpath is None:
            if user.role == Role.ADMIN:
                return PolicyDecision(True, 200, "Admin update permitted")
            if user.id == doc.owner_id:
                return PolicyDecision(True, 200, "Owner update permitted")
            if doc.shared_with.get(user.id) == AccessLevel.EDITOR:
                return PolicyDecision(True, 200, "Editor update permitted")
            return PolicyDecision(False, 403, "User lacks editor permissions")

        # 4. DELETE /api/v1/documents/{doc_id} (Delete Document)
        if method == "DELETE" and subpath is None:
            if user.role == Role.ADMIN or user.id == doc.owner_id:
                return PolicyDecision(True, 200, "Document deletion permitted")
            return PolicyDecision(False, 403, "Only owner or admin can delete document")

        # 5. POST /api/v1/documents/{doc_id}/share (Share Document)
        if method == "POST" and subpath == "share":
            if user.role != Role.ADMIN and user.id != doc.owner_id:
                return PolicyDecision(False, 403, "Only owner or admin can share document")
            body = request.body or {}
            target_user_id = body.get("target_user_id")
            access_level_str = body.get("access_level", "viewer")
            if not target_user_id:
                return PolicyDecision(False, 400, "Missing target_user_id")
            target_user = users.get(target_user_id)
            if not target_user:
                return PolicyDecision(False, 404, "Target user not found")
            if target_user.tenant_id != tenant_id:
                return PolicyDecision(False, 403, "Cannot share document across tenant boundaries")
            try:
                AccessLevel(access_level_str)
            except ValueError:
                return PolicyDecision(False, 400, f"Invalid access level '{access_level_str}'")
            return PolicyDecision(True, 200, "Document share permitted")

        # 6. POST /api/v1/documents/{doc_id}/revoke (Revoke Share)
        if method == "POST" and subpath == "revoke":
            if user.role != Role.ADMIN and user.id != doc.owner_id:
                return PolicyDecision(False, 403, "Only owner or admin can revoke shares")
            body = request.body or {}
            target_user_id = body.get("target_user_id")
            if not target_user_id:
                return PolicyDecision(False, 400, "Missing target_user_id")
            return PolicyDecision(True, 200, "Share revocation permitted")

        # 7. POST /api/v1/documents/{doc_id}/transfer (Transfer Ownership)
        if method == "POST" and subpath == "transfer":
            if user.role != Role.ADMIN and user.id != doc.owner_id:
                return PolicyDecision(False, 403, "Only owner or admin can transfer ownership")
            body = request.body or {}
            new_owner_id = body.get("new_owner_id")
            if not new_owner_id:
                return PolicyDecision(False, 400, "Missing new_owner_id")
            new_owner = users.get(new_owner_id)
            if not new_owner:
                return PolicyDecision(False, 404, "New owner user not found")
            if new_owner.tenant_id != tenant_id:
                return PolicyDecision(False, 403, "Cannot transfer ownership across tenants")
            if new_owner.role == Role.GUEST:
                return PolicyDecision(False, 403, "Guests cannot own documents")
            return PolicyDecision(True, 200, "Ownership transfer permitted")

        return PolicyDecision(False, 404, "Unknown endpoint or method")
