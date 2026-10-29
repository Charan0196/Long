#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import os
import sys
import time
from pathlib import Path

# Add /app or workspace path to sys.path
TESTS_DIR = Path(__file__).resolve().parent
ROOT_DIR = TESTS_DIR.parent.parent

for candidate in [
    "/app",
    "/tests/baseline",
    str(ROOT_DIR / "environment" / "app"),
    str(ROOT_DIR / "environment" / "workspace"),
    str(TESTS_DIR / "baseline"),
]:
    if Path(candidate).exists() and candidate not in sys.path:
        sys.path.insert(0, candidate)

if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from submission_contract import check_submission_contract
from fuzz_benchmark import run_all_benchmarks
from compute_reward import compute_final_score, WEIGHTS


def print_scorecard(metrics: dict, final_score: float) -> None:
    print("\n" + "=" * 70)
    print("      FRONTIERSWE BENCHMARK EVALUATION SCORECARD")
    print("=" * 70)
    print(f"{'Category':<35} | {'Score':<8} | {'Weight':<8} | {'Points':<8}")
    print("-" * 70)

    for cat, weight in WEIGHTS.items():
        score = metrics.get(cat, 0.0)
        pts = score * weight * 100.0
        max_pts = weight * 100.0
        print(f"{cat:<35} | {score*100:>6.1f}%  | {weight:>6.2f}  | {pts:>4.1f}/{max_pts:.1f}")

    print("-" * 70)
    print(f"{'FINAL COMPOSITE SCORE':<35} | {final_score*100:>6.2f}% | 1.00     | {final_score*100:>5.2f}/100.0")
    print("=" * 70 + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default=os.environ.get("VERIFIER_OUTPUT_DIR", "/eval_out"))
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    t0 = time.perf_counter()

    # 1. Check submission contract
    target_path = "/app" if Path("/app").exists() else str(ROOT_DIR / "environment" / "workspace")
    contract_ok, contract_msg = check_submission_contract(target_path)
    if not contract_ok:
        print(f"Contract failure: {contract_msg}", file=sys.stderr)
        results = {
            "contract_ok": False,
            "reason": contract_msg,
            "metrics": {},
            "elapsed_s": time.perf_counter() - t0,
        }
        (output_dir / "runner_results.json").write_text(json.dumps(results, indent=2))
        import compute_reward
        compute_reward.emit_failure(output_dir, reason=contract_msg, status="agent_contract_failure")
        return 1

    # 2. Run benchmark suites
    print("Executing stateful API fuzzer benchmark test battery...")
    metrics = run_all_benchmarks()
    final_score, cat_scores = compute_final_score(metrics)

    elapsed = time.perf_counter() - t0
    results = {
        "contract_ok": True,
        "reason": "OK",
        "metrics": metrics,
        "score": final_score,
        "elapsed_s": elapsed,
    }
    (output_dir / "runner_results.json").write_text(json.dumps(results, indent=2))

    # Print human-readable summary
    print_scorecard(metrics, final_score)

    # Write reward.txt for Harbor compatibility
    reward_txt = output_dir / "reward.txt"
    reward_txt.write_text(f"{final_score:.4f}\n")

    # 3. Emit canonical reward.json
    import compute_reward
    numeric = {
        "gate_contract": 1.0,
        "gate_runner": 1.0,
        **cat_scores,
        **compute_reward.status_numeric("ok"),
    }
    status = "ok" if final_score > 0.0 else "agent_solution_failure"
    compute_reward.emit(output_dir, final_score, reason=f"Evaluated with score {final_score:.4f}", numeric=numeric, details=results)

    return 0


if __name__ == "__main__":
    sys.exit(main())
