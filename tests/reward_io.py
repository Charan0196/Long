#!/usr/bin/env python3
"""Write verifier reward artifacts with canonical FrontierSWE schema."""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any, Dict, Optional


AGENT_FAILURES = {"agent_solution_failure", "agent_contract_failure", "safeguard_failure"}
INVALID_EVALUATIONS = {"infrastructure_failure", "verifier_failure"}
EVALUATION_STATUSES = {"ok", *AGENT_FAILURES, *INVALID_EVALUATIONS}


def status_numeric(status: str) -> Dict[str, float]:
    evaluation_valid = status not in INVALID_EVALUATIONS
    return {
        "evaluation_valid": 1.0 if evaluation_valid else 0.0,
        "failure_is_agent": 1.0 if status in AGENT_FAILURES else 0.0,
        "gate_infrastructure": 0.0 if status == "infrastructure_failure" else 1.0,
        "gate_verifier": 0.0 if status == "verifier_failure" else 1.0,
    }


def failure_gate_numeric(status: str) -> Dict[str, float]:
    return {
        "gate_runner": 0.0 if status == "verifier_failure" else 1.0,
        "gate_contract": 0.0 if status == "agent_contract_failure" else 1.0,
        "gate_safeguards": 0.0 if status == "safeguard_failure" else 1.0,
        **status_numeric(status),
    }


def emit(
    output_dir: Path,
    score: float,
    *,
    reason: str,
    numeric: Optional[Dict[str, float]] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    score = float(max(0.0, min(1.0, score)))
    reward: Dict[str, Any] = {
        "reward": score,
        "score": score,
        "reason": reason,
    }

    for key, value in (numeric or {}).items():
        if isinstance(value, bool):
            reward[key] = 1.0 if value else 0.0
        elif isinstance(value, (int, float)):
            if math.isfinite(value):
                reward[key] = float(value)
            else:
                reward[key] = 0.0

    if details is not None:
        reward["details"] = details

    reward_path = output_dir / "reward.json"
    reward_path.write_text(json.dumps(reward, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def emit_failure(
    output_dir: Path,
    *,
    reason: str,
    status: str = "agent_contract_failure",
) -> None:
    emit(
        output_dir,
        0.0,
        reason=reason,
        numeric=failure_gate_numeric(status),
        details={"evaluation_status": status, "failure_reason": reason},
    )
