from __future__ import annotations
from typing import List
from api.client import BaseTarget
from api.models import Tenant, User
from authfuzzer.models import Scenario, FuzzReport


class DifferentialEngine:
    """Executes scenarios against a target API and compares against authorization policy."""

    def __init__(self, target: BaseTarget, tenants: List[Tenant], users: List[User]):
        self.target = target
        self.tenants = tenants
        self.users = users

    def run_scenarios(self, scenarios: List[Scenario], seed: int = 42, minimize: bool = True) -> FuzzReport:
        """Run scenarios differentially against the target and detect authorization violations.
        
        TODO: Implement differential test execution.
        Must detect:
        - Improper allow (vulnerability / 2xx returned instead of 403)
        - Improper deny (403 returned when policy allows access)
        - Classify violations into standardized categories
        - Trigger minimization when requested
        """
        raise NotImplementedError("TODO: Implement differential testing in DifferentialEngine")
