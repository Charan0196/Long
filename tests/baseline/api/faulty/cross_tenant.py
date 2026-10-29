from __future__ import annotations
from typing import Dict, Optional, Any
from api.models import APIRequest, APIResponse, Document, Role, AccessLevel
from api.client import BaseTarget


class CrossTenantTarget(BaseTarget):
    """Faulty target: Cross-Tenant Information Disclosure.
    
    Bug: GET /api/v1/documents/{doc_id} omits the tenant isolation check:
    any user with a valid account in any tenant can read documents belonging
    to other organizations.
    """

    def dispatch(self, request: APIRequest) -> APIResponse:
        user_id = request.user_id
        tenant_id = request.tenant_id
        if not user_id or not tenant_id:
            return APIResponse(status_code=401, error="Missing auth headers")

        user = self.users.get(user_id)
        if not user or user.tenant_id != tenant_id:
            return APIResponse(status_code=401, error="User not in tenant")

        method = request.method.upper()
        path = request.path

        if method == "POST" and path == "/api/v1/documents":
            if user.role == Role.GUEST:
                return APIResponse(status_code=403, error="Guests cannot create documents")
            body = request.body or {}
            doc_id = body.get("id")
            if not doc_id:
                return APIResponse(status_code=400, error="Missing id")
            if doc_id in self.documents:
                return APIResponse(status_code=409, error="Document exists")
            doc = Document(
                id=doc_id,
                tenant_id=tenant_id,
                owner_id=user_id,
                title=body.get("title", ""),
                content=body.get("content", ""),
                shared_with={},
                original_creator_id=user_id,
            )
            self.documents[doc_id] = doc
            return APIResponse(status_code=201, data={"id": doc_id, "status": "created"})

        parts = path.strip("/").split("/")
        if len(parts) < 4 or parts[:3] != ["api", "v1", "documents"]:
            return APIResponse(status_code=404, error="Not found")

        doc_id = parts[3]
        subpath = parts[4] if len(parts) > 4 else None

        doc = self.documents.get(doc_id)
        if not doc:
            return APIResponse(status_code=404, error="Document not found")

        # --- FLAW INTRODUCED HERE: MISSING TENANT CHECK ON GET ---
        if method == "GET" and subpath is None:
            # Vulnerability: ignores doc.tenant_id != tenant_id!
            return APIResponse(
                status_code=200,
                data={
                    "id": doc.id,
                    "tenant_id": doc.tenant_id,
                    "owner_id": doc.owner_id,
                    "title": doc.title,
                    "content": doc.content,
                    "shared_with": {k: v.value for k, v in doc.shared_with.items()},
                },
            )

        # Other methods enforce tenant boundaries properly
        if doc.tenant_id != tenant_id:
            return APIResponse(status_code=403, error="Cross-tenant forbidden")

        if method == "PUT" and subpath is None:
            if user.role != Role.ADMIN and user.id != doc.owner_id and doc.shared_with.get(user.id) != AccessLevel.EDITOR:
                return APIResponse(status_code=403, error="Unauthorized update")
            body = request.body or {}
            if "content" in body:
                doc.content = body["content"]
            return APIResponse(status_code=200, data={"id": doc.id, "status": "updated"})

        if method == "DELETE" and subpath is None:
            if user.role != Role.ADMIN and user.id != doc.owner_id:
                return APIResponse(status_code=403, error="Only owner or admin can delete")
            del self.documents[doc_id]
            return APIResponse(status_code=200, data={"id": doc_id, "status": "deleted"})

        if method == "POST" and subpath == "share":
            if user.role != Role.ADMIN and user.id != doc.owner_id:
                return APIResponse(status_code=403, error="Only owner or admin can share")
            body = request.body or {}
            target_user_id = body.get("target_user_id")
            target_user = self.users.get(target_user_id)
            if not target_user or target_user.tenant_id != tenant_id:
                return APIResponse(status_code=403, error="Invalid target user")
            doc.shared_with[target_user_id] = AccessLevel(body.get("access_level", "viewer"))
            return APIResponse(status_code=200, data={"id": doc_id, "status": "shared"})

        if method == "POST" and subpath == "revoke":
            if user.role != Role.ADMIN and user.id != doc.owner_id:
                return APIResponse(status_code=403, error="Only owner or admin can revoke")
            body = request.body or {}
            target_user_id = body.get("target_user_id")
            if target_user_id in doc.shared_with:
                del doc.shared_with[target_user_id]
            return APIResponse(status_code=200, data={"id": doc_id, "status": "revoked"})

        if method == "POST" and subpath == "transfer":
            if user.role != Role.ADMIN and user.id != doc.owner_id:
                return APIResponse(status_code=403, error="Only owner or admin can transfer")
            body = request.body or {}
            new_owner_id = body.get("new_owner_id")
            new_owner = self.users.get(new_owner_id)
            if not new_owner or new_owner.tenant_id != tenant_id or new_owner.role == Role.GUEST:
                return APIResponse(status_code=403, error="Invalid new owner")
            doc.owner_id = new_owner_id
            return APIResponse(status_code=200, data={"id": doc_id, "status": "transferred"})

        return APIResponse(status_code=404, error="Endpoint not found")
