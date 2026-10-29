from __future__ import annotations
import random
from typing import List, Dict, Optional, Tuple, Any
from api.models import Tenant, User, Role, AccessLevel
from authfuzzer.models import Scenario, FuzzAction
from authfuzzer.state import FuzzSystemState, SimulatedDocumentState


class ScenarioGenerator:
    """State-aware scenario generator exploring multi-tenant authorization workflows."""

    def __init__(self, tenants: List[Tenant], users: List[User], seed: int = 42):
        self.tenants = tenants
        self.users = users
        self.seed = seed
        self.rng = random.Random(seed)
        self.state = FuzzSystemState(tenants, users)
        self._doc_counter = 0

    def generate_scenarios(self, count: int, max_steps: int = 15) -> List[Scenario]:
        scenarios: List[Scenario] = []
        for i in range(count):
            scenarios.append(self._generate_single_scenario(f"scenario_{i+1}", max_steps))
        return scenarios

    def _generate_single_scenario(self, scenario_id: str, max_steps: int) -> Scenario:
        self.state.reset()
        actions: List[FuzzAction] = []
        step = 1

        # Phase 1: Guaranteed initial stateful setup
        t1 = self.tenants[0]
        t2 = self.tenants[1] if len(self.tenants) > 1 else t1
        t1_users = self.state.get_users_in_tenant(t1.id)
        t1_admin = [u for u in t1_users if u.role == Role.ADMIN][0]
        t1_members = [u for u in t1_users if u.role == Role.MEMBER]
        t1_member = t1_members[0] if t1_members else t1_admin
        t1_guest = [u for u in t1_users if u.role == Role.GUEST]

        t2_users = self.state.get_users_in_tenant(t2.id)
        t2_member = t2_users[0] if t2_users else t1_member

        # Always start by creating at least one baseline document
        self._doc_counter += 1
        initial_doc_id = f"doc_{t1.id}_{self._doc_counter}"
        create_action = FuzzAction(
            step=step,
            name="create_document",
            tenant_id=t1.id,
            user_id=t1_member.id,
            method="POST",
            endpoint="/api/v1/documents",
            payload={"id": initial_doc_id, "title": "Initial", "content": "Baseline Content"},
        )
        actions.append(create_action)
        self.state.documents[initial_doc_id] = SimulatedDocumentState(
            id=initial_doc_id,
            tenant_id=t1.id,
            owner_id=t1_member.id,
            original_creator_id=t1_member.id,
        )
        step += 1

        # Phase 2: Dynamic state transitions & adversarial probes
        while step <= max_steps:
            action_choice = self.rng.choices(
                [
                    "create",
                    "read_probe",
                    "update_probe",
                    "share_lifecycle",
                    "transfer_lifecycle",
                    "delete_and_resurrect",
                ],
                weights=[20, 25, 20, 15, 10, 10],
                k=1,
            )[0]

            new_actions = self._generate_step_actions(action_choice, step)
            for act in new_actions:
                actions.append(act)
                step += 1
                if step > max_steps:
                    break

        return Scenario(id=scenario_id, actions=actions)

    def _generate_step_actions(self, action_type: str, current_step: int) -> List[FuzzAction]:
        actions: List[FuzzAction] = []
        active_docs = self.state.get_active_documents()
        t1 = self.tenants[0]
        t2 = self.tenants[1] if len(self.tenants) > 1 else t1

        if action_type == "create" or not active_docs:
            tenant = self.rng.choice(self.tenants)
            users = self.state.get_users_in_tenant(tenant.id)
            # 20% chance: probe guest document creation
            if self.rng.random() < 0.2:
                guests = [u for u in users if u.role == Role.GUEST]
                creator = guests[0] if guests else users[0]
            else:
                creators = [u for u in users if u.role in (Role.ADMIN, Role.MEMBER)]
                creator = creators[0] if creators else users[0]

            self._doc_counter += 1
            doc_id = f"doc_{tenant.id}_{self._doc_counter}"
            actions.append(
                FuzzAction(
                    step=current_step,
                    name="create_document",
                    tenant_id=tenant.id,
                    user_id=creator.id,
                    method="POST",
                    endpoint="/api/v1/documents",
                    payload={"id": doc_id, "title": f"Doc {self._doc_counter}", "content": "Body"},
                )
            )
            self.state.documents[doc_id] = SimulatedDocumentState(
                id=doc_id,
                tenant_id=tenant.id,
                owner_id=creator.id,
                original_creator_id=creator.id,
            )

        elif action_type == "read_probe":
            doc = self.rng.choice(active_docs)
            probe_mode = self.rng.choice(["idor_member", "cross_tenant", "valid"])
            if probe_mode == "idor_member":
                # Probe: member in same tenant without ownership or share
                same_members = [
                    u for u in self.state.get_users_in_tenant(doc.tenant_id, Role.MEMBER)
                    if u.id != doc.owner_id and u.id not in doc.shares
                ]
                caller = same_members[0] if same_members else self.users[0]
                caller_tenant = doc.tenant_id
            elif probe_mode == "cross_tenant":
                # Probe: user from another tenant entirely
                other_tenants = [t for t in self.tenants if t.id != doc.tenant_id]
                other_tenant = other_tenants[0] if other_tenants else self.tenants[0]
                caller = self.state.get_users_in_tenant(other_tenant.id)[0]
                caller_tenant = other_tenant.id
            else:
                caller = self.state.users.get(doc.owner_id, self.users[0])
                caller_tenant = doc.tenant_id

            actions.append(
                FuzzAction(
                    step=current_step,
                    name="read_document",
                    tenant_id=caller_tenant,
                    user_id=caller.id,
                    method="GET",
                    endpoint=f"/api/v1/documents/{doc.id}",
                )
            )

        elif action_type == "update_probe":
            doc = self.rng.choice(active_docs)
            probe_mode = self.rng.choice(["viewer_guest", "unauthorized_member", "owner"])
            if probe_mode == "viewer_guest":
                guests = self.state.get_users_in_tenant(doc.tenant_id, Role.GUEST)
                caller = guests[0] if guests else self.users[0]
            elif probe_mode == "unauthorized_member":
                members = [
                    u for u in self.state.get_users_in_tenant(doc.tenant_id, Role.MEMBER)
                    if u.id != doc.owner_id
                ]
                caller = members[0] if members else self.users[0]
            else:
                caller = self.state.users.get(doc.owner_id, self.users[0])

            actions.append(
                FuzzAction(
                    step=current_step,
                    name="update_document",
                    tenant_id=doc.tenant_id,
                    user_id=caller.id,
                    method="PUT",
                    endpoint=f"/api/v1/documents/{doc.id}",
                    payload={"content": f"Updated by {caller.id}"},
                )
            )

        elif action_type == "share_lifecycle":
            doc = self.rng.choice(active_docs)
            tenant_users = self.state.get_users_in_tenant(doc.tenant_id)
            target = self.rng.choice([u for u in tenant_users if u.id != doc.owner_id] or tenant_users)
            level = self.rng.choice(["viewer", "editor"])
            actions.append(
                FuzzAction(
                    step=current_step,
                    name="share_document",
                    tenant_id=doc.tenant_id,
                    user_id=doc.owner_id,
                    method="POST",
                    endpoint=f"/api/v1/documents/{doc.id}/share",
                    payload={"target_user_id": target.id, "access_level": level},
                )
            )
            doc.shares[target.id] = AccessLevel(level)

        elif action_type == "transfer_lifecycle":
            doc = self.rng.choice(active_docs)
            eligible = [
                u for u in self.state.get_users_in_tenant(doc.tenant_id)
                if u.role in (Role.MEMBER, Role.ADMIN) and u.id != doc.owner_id
            ]
            if eligible:
                new_owner = eligible[0]
                prev_owner = doc.owner_id
                actions.append(
                    FuzzAction(
                        step=current_step,
                        name="transfer_ownership",
                        tenant_id=doc.tenant_id,
                        user_id=doc.owner_id,
                        method="POST",
                        endpoint=f"/api/v1/documents/{doc.id}/transfer",
                        payload={"new_owner_id": new_owner.id},
                    )
                )
                doc.owner_id = new_owner.id
                # Follow up by testing if prev_owner can delete
                actions.append(
                    FuzzAction(
                        step=current_step + 1,
                        name="delete_document",
                        tenant_id=doc.tenant_id,
                        user_id=prev_owner,
                        method="DELETE",
                        endpoint=f"/api/v1/documents/{doc.id}",
                    )
                )

        elif action_type == "delete_and_resurrect":
            doc = self.rng.choice(active_docs)
            deleted_id = doc.id
            actions.append(
                FuzzAction(
                    step=current_step,
                    name="delete_document",
                    tenant_id=doc.tenant_id,
                    user_id=doc.owner_id,
                    method="DELETE",
                    endpoint=f"/api/v1/documents/{deleted_id}",
                )
            )
            doc.is_deleted = True
            # Recreate same doc ID with new owner
            other_users = [
                u for u in self.state.get_users_in_tenant(doc.tenant_id, Role.MEMBER)
                if u.id != doc.owner_id
            ]
            new_creator = other_users[0] if other_users else self.users[0]
            actions.append(
                FuzzAction(
                    step=current_step + 1,
                    name="create_document",
                    tenant_id=doc.tenant_id,
                    user_id=new_creator.id,
                    method="POST",
                    endpoint="/api/v1/documents",
                    payload={"id": deleted_id, "title": "Resurrected", "content": "Fresh Content"},
                )
            )
            # Prior shared user attempts to read
            prior_shared = list(doc.shares.keys())
            test_reader_id = prior_shared[0] if prior_shared else self.users[0].id
            actions.append(
                FuzzAction(
                    step=current_step + 2,
                    name="read_document",
                    tenant_id=doc.tenant_id,
                    user_id=test_reader_id,
                    method="GET",
                    endpoint=f"/api/v1/documents/{deleted_id}",
                )
            )

        return actions
