from __future__ import annotations
from typing import List, Dict, Tuple, Optional
from api.client import BaseTarget
from api.policy import AuthorizationPolicy
from api.models import Document, Role, AccessLevel
from authfuzzer.models import FuzzAction


class SequenceMinimizer:
    """Delta Debugging (ddmin) sequence minimizer for stateful failure traces.
    
    Ensures semantic equivalence: preserves both the expected policy decision
    and the target's violation status code, preventing false reductions where
    an unauthorized probe inadvertently becomes an authorized request.
    """

    def __init__(self, target: BaseTarget, tenants, users):
        self.target = target
        self.tenants = tenants
        self.users = users
        self.users_map = {u.id: u for u in users}

    def minimize(
        self,
        actions: List[FuzzAction],
        expected_status: Optional[int] = None,
        observed_status: Optional[int] = None,
    ) -> List[FuzzAction]:
        if len(actions) <= 1:
            return actions

        target_action = actions[-1]
        prefix = list(actions[:-1])

        # Baseline evaluation
        base_exp, base_obs = self._replay_and_evaluate(prefix, target_action)
        expected_status = expected_status or base_exp
        observed_status = observed_status or base_obs

        # Delta debugging on prefix
        n = 2
        while len(prefix) >= 1:
            step_reduced = False
            k = max(1, len(prefix) // n)
            chunks = [prefix[i:i + k] for i in range(0, len(prefix), k)]

            # 1. Chunk complement test
            for i in range(len(chunks)):
                candidate = [item for j, chunk in enumerate(chunks) if j != i for item in chunk]
                cand_exp, cand_obs = self._replay_and_evaluate(candidate, target_action)
                if cand_exp == expected_status and cand_obs == observed_status:
                    prefix = candidate
                    n = max(n - 1, 2)
                    step_reduced = True
                    break

            if step_reduced:
                continue

            # 2. Chunk subset test
            for chunk in chunks:
                if len(chunk) < len(prefix):
                    cand_exp, cand_obs = self._replay_and_evaluate(chunk, target_action)
                    if cand_exp == expected_status and cand_obs == observed_status:
                        prefix = chunk
                        n = 2
                        step_reduced = True
                        break

            if step_reduced:
                continue

            if n < len(prefix):
                n = min(len(prefix), n * 2)
            else:
                break

        # 3. Fine-grained 1-minimality sweep
        i = len(prefix) - 1
        while i >= 0:
            candidate = prefix[:i] + prefix[i+1:]
            cand_exp, cand_obs = self._replay_and_evaluate(candidate, target_action)
            if cand_exp == expected_status and cand_obs == observed_status:
                prefix = candidate
            i -= 1

        minimized = prefix + [target_action]
        renumbered: List[FuzzAction] = []
        for idx, act in enumerate(minimized, start=1):
            renumbered.append(
                FuzzAction(
                    step=idx,
                    name=act.name,
                    tenant_id=act.tenant_id,
                    user_id=act.user_id,
                    method=act.method,
                    endpoint=act.endpoint,
                    payload=act.payload,
                )
            )
        return renumbered

    def _replay_and_evaluate(self, prefix: List[FuzzAction], terminal: FuzzAction) -> Tuple[int, int]:
        # Reset and replay target
        self.target.reset()
        ref_docs: Dict[str, Document] = {}

        for act in prefix:
            req = act.to_request()
            dec = AuthorizationPolicy.evaluate(req, self.users_map, ref_docs)
            if dec.allowed:
                self._update_ref_state(req, ref_docs)
            self.target.dispatch(req)

        terminal_req = terminal.to_request()
        expected_dec = AuthorizationPolicy.evaluate(terminal_req, self.users_map, ref_docs)
        actual_resp = self.target.dispatch(terminal_req)

        return expected_dec.status_code, actual_resp.status_code

    def _update_ref_state(self, req, ref_docs: Dict[str, Document]) -> None:
        method = req.method.upper()
        path = req.path
        if method == "POST" and path == "/api/v1/documents":
            body = req.body or {}
            d_id = body.get("id")
            if d_id:
                ref_docs[d_id] = Document(
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
            doc = ref_docs.get(d_id)
            if doc:
                if method == "PUT" and subpath is None:
                    body = req.body or {}
                    if "content" in body:
                        doc.content = body["content"]
                elif method == "DELETE" and subpath is None:
                    del ref_docs[d_id]
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
