#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import math
from pathlib import Path
from typing import Dict, Any, Tuple
from reward_io import emit, emit_failure, status_numeric, EVALUATION_STATUSES


WEIGHTS = {
    "authorization_correctness": 0.25,
    "stateful_scenario_coverage": 0.20,
    "fault_discovery_and_precision": 0.20,
    "failure_minimization_and_replay": 0.15,
    "robustness_and_edge_cases": 0.10,
    "throughput_and_efficiency": 0.10,
}


def clamp01(v: Any) -> float:
    try:
        val = float(v)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(val):
        return 0.0
    return max(0.0, min(1.0, val))


def compute_final_score(metrics: Dict[str, Any]) -> Tuple[float, Dict[str, float]]:
    numeric_scores = {}
    weighted_sum = 0.0

    for cat, weight in WEIGHTS.items():
        cat_score = clamp01(metrics.get(cat, 0.0))
        numeric_scores[cat] = cat_score
        weighted_sum += weight * cat_score

    final_score = float(max(0.0, min(1.0, weighted_sum)))
    return final_score, numeric_scores


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--runner-results", default=None)
    parser.add_argument("--fail", default=None)
    parser.add_argument("--fail-class", choices=sorted(EVALUATION_STATUSES), default="verifier_failure")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)

    if args.fail:
        emit_failure(output_dir, reason=args.fail, status=args.fail_class)
        return 0

    results_file = Path(args.runner_results or (output_dir / "runner_results.json"))
    if not results_file.exists():
        emit_failure(output_dir, reason="runner_results.json missing", status="verifier_failure")
        return 0

    try:
        data = json.loads(results_file.read_text(encoding="utf-8"))
    except Exception as e:
        emit_failure(output_dir, reason=f"Failed to parse runner_results.json: {e}", status="verifier_failure")
        return 0

    if not data.get("contract_ok", False):
        emit_failure(output_dir, reason=data.get("reason", "Contract check failed"), status="agent_contract_failure")
        return 0

    metrics = data.get("metrics", {})
    score, cat_scores = compute_final_score(metrics)

    numeric = {
        "gate_contract": 1.0,
        "gate_runner": 1.0,
        **cat_scores,
        **status_numeric("ok"),
    }

    status = "ok" if score > 0.0 else "agent_solution_failure"
    emit(output_dir, score, reason=f"Evaluated with score {score:.4f}", numeric=numeric, details=data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
