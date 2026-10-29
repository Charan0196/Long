from __future__ import annotations
from typing import Dict, Optional, Any
from api.models import APIRequest, APIResponse, Document, Role, AccessLevel
from api.client import BaseTarget
from api.policy import AuthorizationPolicy


class ReferenceTarget(BaseTarget):
    """Clean reference API implementation with 100% policy compliance."""

    def dispatch(self, request: APIRequest) -> APIResponse:
        decision = AuthorizationPolicy.evaluate(request, self.users, self.documents)
        if not decision.allowed:
            return APIResponse(status_code=decision.status_code, error=decision.reason)

        method = request.method.upper()
        path = request.path

        # 1. POST /api/v1/documents
        if method == "POST" and path == "/api/v1/documents":
            body = request.body or {}
            doc_id = body["id"]
            title = body.get("title", "")
            content = body.get("content", "")
            doc = Document(
                id=doc_id,
                tenant_id=request.tenant_id,
                owner_id=request.user_id,
                title=title,
                content=content,
                shared_with={},
                original_creator_id=request.user_id,
            )
            self.documents[doc_id] = doc
            return APIResponse(status_code=201, data={"id": doc_id, "status": "created"})

        parts = path.strip("/").split("/")
        doc_id = parts[3]
        subpath = parts[4] if len(parts) > 4 else None
        doc = self.documents[doc_id]

        # 2. GET /api/v1/documents/{doc_id}
        if method == "GET" and subpath is None:
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

        # 3. PUT /api/v1/documents/{doc_id}
        if method == "PUT" and subpath is None:
            body = request.body or {}
            if "content" in body:
                doc.content = body["content"]
            if "title" in body:
                doc.title = body["title"]
            return APIResponse(status_code=200, data={"id": doc.id, "status": "updated"})

        # 4. DELETE /api/v1/documents/{doc_id}
        if method == "DELETE" and subpath is None:
            del self.documents[doc_id]
            return APIResponse(status_code=200, data={"id": doc_id, "status": "deleted"})

        # 5. POST /api/v1/documents/{doc_id}/share
        if method == "POST" and subpath == "share":
            body = request.body or {}
            target_user_id = body["target_user_id"]
            access_level = AccessLevel(body.get("access_level", "viewer"))
            doc.shared_with[target_user_id] = access_level
            return APIResponse(status_code=200, data={"id": doc_id, "status": "shared", "target": target_user_id})

        # 6. POST /api/v1/documents/{doc_id}/revoke
        if method == "POST" and subpath == "revoke":
            body = request.body or {}
            target_user_id = body["target_user_id"]
            if target_user_id in doc.shared_with:
                del doc.shared_with[target_user_id]
            return APIResponse(status_code=200, data={"id": doc_id, "status": "revoked", "target": target_user_id})

        # 7. POST /api/v1/documents/{doc_id}/transfer
        if method == "POST" and subpath == "transfer":
            body = request.body or {}
            new_owner_id = body["new_owner_id"]
            doc.owner_id = new_owner_id
            return APIResponse(status_code=200, data={"id": doc_id, "status": "transferred", "new_owner": new_owner_id})

        return APIResponse(status_code=404, error="Endpoint not found")
