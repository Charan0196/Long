from __future__ import annotations
import random
from typing import List
from api.models import Tenant, User
from authfuzzer.models import Scenario


class ScenarioGenerator:
    """Generates state-aware multi-step authorization testing scenarios."""

    def __init__(self, tenants: List[Tenant], users: List[User], seed: int = 42):
        self.tenants = tenants
        self.users = users
        self.seed = seed
        self.rng = random.Random(seed)

    def generate_scenarios(self, count: int, max_steps: int = 15) -> List[Scenario]:
        """Generate a corpus of valid multi-step scenarios exploring API authorization.
        
        TODO: Implement state-aware scenario generation.
        The generator must explore:
        - Resource creation, read, update, delete
        - Sharing (viewer, editor) and revoking
        - Ownership transfer
        - Cross-tenant access attempts
        - Unauthorized member and guest operations
        - Re-creation of deleted resources
        """
        raise NotImplementedError("TODO: Implement state-aware scenario generation in ScenarioGenerator")
