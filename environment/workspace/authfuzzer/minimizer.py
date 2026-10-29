from __future__ import annotations
from typing import List
from api.client import BaseTarget
from authfuzzer.models import FuzzAction


class SequenceMinimizer:
    """Minimizes failure sequences to minimal reproducible sub-sequences via delta debugging."""

    def __init__(self, target: BaseTarget, tenants, users):
        self.target = target
        self.tenants = tenants
        self.users = users

    def minimize(self, actions: List[FuzzAction]) -> List[FuzzAction]:
        """Reduce a failing sequence of actions to the shortest reproducible sequence.
        
        TODO: Implement Delta Debugging (ddmin) for stateful action sequences.
        Must preserve:
        - The final action that triggers the violation
        - Causal prerequisites (e.g. creating the document before attempting unauthorized access)
        - The exact authorization discrepancy observed in the original failure
        """
        raise NotImplementedError("TODO: Implement failure minimization in SequenceMinimizer")
