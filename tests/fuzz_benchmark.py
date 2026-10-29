from __future__ import annotations
import time
import random
from typing import Dict, Any, List
from api.models import Tenant, User, Role, Document, APIRequest
from api.client import get_target
from api.policy import AuthorizationPolicy
from authfuzzer.models import FuzzAction, Scenario
from authfuzzer.generator import ScenarioGenerator
from authfuzzer.engine import DifferentialEngine
from authfuzzer.minimizer import SequenceMinimizer


def build_benchmark_testbed():
    tenants = [
        Tenant("org_alpha", "Alpha Corp"),
        Tenant("org_beta", "Beta LLC"),
    ]
    users = [
        User.create("u_a_admin", "org_alpha", Role.ADMIN),
        User.create("u_a_mem1", "org_alpha", Role.MEMBER),
        User.create("u_a_mem2", "org_alpha", Role.MEMBER),
        User.create("u_a_guest", "org_alpha", Role.GUEST),
        User.create("u_b_admin", "org_beta", Role.ADMIN),
        User.create("u_b_mem", "org_beta", Role.MEMBER),
        User.create("u_b_guest", "org_beta", Role.GUEST),
    ]
    return tenants, users


def evaluate_authorization_correctness() -> float:
    """Evaluate if agent's DifferentialEngine correctly models and predicts authorization decisions."""
    tenants, users = build_benchmark_testbed()
    try:
        ref_target = get_target("reference")
        ref_target.seed_entities(tenants, users)
        engine = DifferentialEngine(ref_target, tenants, users)
    except Exception:
        return 0.0

    test_actions = [
        FuzzAction(1, "create_document", "org_alpha", "u_a_mem1", "POST", "/api/v1/documents", {"id": "bench_doc1", "title": "T", "content": "C"}),
        FuzzAction(2, "read_document", "org_alpha", "u_a_mem1", "GET", "/api/v1/documents/bench_doc1"),
        FuzzAction(3, "read_document", "org_alpha", "u_a_admin", "GET", "/api/v1/documents/bench_doc1"),
        FuzzAction(4, "read_document", "org_alpha", "u_a_mem2", "GET", "/api/v1/documents/bench_doc1"),
        FuzzAction(5, "read_document", "org_beta", "u_b_mem", "GET", "/api/v1/documents/bench_doc1"),
        FuzzAction(6, "create_document", "org_alpha", "u_a_guest", "POST", "/api/v1/documents", {"id": "g_doc"}),
        FuzzAction(7, "update_document", "org_alpha", "u_a_mem2", "PUT", "/api/v1/documents/bench_doc1", {"content": "X"}),
        FuzzAction(8, "delete_document", "org_alpha", "u_a_mem2", "DELETE", "/api/v1/documents/bench_doc1"),
        FuzzAction(9, "share_document", "org_alpha", "u_a_mem1", "POST", "/api/v1/documents/bench_doc1/share", {"target_user_id": "u_b_mem"}),
        FuzzAction(10, "transfer_ownership", "org_alpha", "u_a_mem1", "POST", "/api/v1/documents/bench_doc1/transfer", {"new_owner_id": "u_a_guest"}),
    ]

    try:
        scenario = Scenario(id="auth_test", actions=test_actions)
        report = engine.run_scenarios([scenario], seed=1, minimize=False)
        if len(report.violations) == 0 and report.total_requests == len(test_actions):
            return 1.0
        return 0.0
    except Exception:
        return 0.0


def evaluate_scenario_coverage() -> float:
    """Evaluate stateful scenario generator coverage."""
    tenants, users = build_benchmark_testbed()
    try:
        gen = ScenarioGenerator(tenants, users, seed=101)
        scenarios = gen.generate_scenarios(count=20, max_steps=15)
    except Exception:
        return 0.0

    if not scenarios:
        return 0.0

    actions_seen = set()
    roles_seen = set()
    tenants_seen = set()
    total_steps = 0

    users_map = {u.id: u for u in users}
    for sc in scenarios:
        total_steps += len(sc.actions)
        for act in sc.actions:
            actions_seen.add(act.name)
            tenants_seen.add(act.tenant_id)
            if act.user_id in users_map:
                roles_seen.add(users_map[act.user_id].role)

    required_actions = {"create_document", "read_document", "update_document", "delete_document", "share_document", "transfer_ownership"}
    action_cov = len(actions_seen.intersection(required_actions)) / len(required_actions)
    role_cov = len(roles_seen) / 3.0 # Admin, Member, Guest
    tenant_cov = len(tenants_seen) / 2.0
    length_score = 1.0 if total_steps >= 100 else (total_steps / 100.0)

    score = 0.4 * action_cov + 0.3 * role_cov + 0.15 * tenant_cov + 0.15 * length_score
    return float(min(1.0, score))


def evaluate_fault_discovery_and_precision() -> float:
    """Evaluate discovery across 5 deliberate faulty targets and 0 false positives on reference."""
    tenants, users = build_benchmark_testbed()

    try:
        gen = ScenarioGenerator(tenants, users, seed=777)
        scenarios = gen.generate_scenarios(count=35, max_steps=15)
    except Exception:
        return 0.0

    # 1. Reference target (must have ZERO violations)
    try:
        ref_target = get_target("reference")
        ref_target.seed_entities(tenants, users)
        ref_engine = DifferentialEngine(ref_target, tenants, users)
        ref_report = ref_engine.run_scenarios(scenarios, seed=777, minimize=False)
        if len(ref_report.violations) > 0:
            # False positive penalty!
            return 0.0
    except Exception:
        return 0.0

    # 2. Check 5 faulty targets
    targets_to_test = ["idor", "cross_tenant", "guest_escalation", "stale_share", "transfer_retention"]
    detected_count = 0

    for name in targets_to_test:
        try:
            t = get_target(name)
            t.seed_entities(tenants, users)
            engine = DifferentialEngine(t, tenants, users)
            report = engine.run_scenarios(scenarios, seed=777, minimize=False)
            if len(report.violations) > 0:
                detected_count += 1
        except Exception:
            pass

    return float(detected_count / len(targets_to_test))


def evaluate_minimization_and_replay() -> float:
    """Evaluate sequence minimization and replay reproducibility."""
    tenants, users = build_benchmark_testbed()
    try:
        target = get_target("idor")
        target.seed_entities(tenants, users)
        minimizer = SequenceMinimizer(target, tenants, users)
    except Exception:
        return 0.0

    # Construct an artificially bloated 10-step trace where only step 1 (create) and step 10 (unauthorized read) matter
    bloated_actions = [
        FuzzAction(1, "create_document", "org_alpha", "u_a_mem1", "POST", "/api/v1/documents", {"id": "min_doc", "title": "T", "content": "C"}),
        FuzzAction(2, "read_document", "org_alpha", "u_a_mem1", "GET", "/api/v1/documents/min_doc"),
        FuzzAction(3, "update_document", "org_alpha", "u_a_mem1", "PUT", "/api/v1/documents/min_doc", {"content": "C2"}),
        FuzzAction(4, "read_document", "org_alpha", "u_a_mem1", "GET", "/api/v1/documents/min_doc"),
        FuzzAction(5, "read_document", "org_alpha", "u_a_mem1", "GET", "/api/v1/documents/min_doc"),
        FuzzAction(6, "update_document", "org_alpha", "u_a_mem1", "PUT", "/api/v1/documents/min_doc", {"content": "C3"}),
        FuzzAction(7, "read_document", "org_alpha", "u_a_mem1", "GET", "/api/v1/documents/min_doc"),
        FuzzAction(8, "read_document", "org_alpha", "u_a_mem1", "GET", "/api/v1/documents/min_doc"),
        FuzzAction(9, "read_document", "org_alpha", "u_a_mem1", "GET", "/api/v1/documents/min_doc"),
        FuzzAction(10, "read_document", "org_alpha", "u_a_mem2", "GET", "/api/v1/documents/min_doc"), # Failing step
    ]

    try:
        minimized = minimizer.minimize(bloated_actions)
        if not minimized:
            return 0.0

        # Minimization ratio score: len should be <= 3 (ideally 2)
        if len(minimized) <= 3:
            reduction_score = 1.0
        elif len(minimized) < len(bloated_actions):
            reduction_score = 0.5
        else:
            reduction_score = 0.0

        # Replay test
        target.reset()
        for act in minimized:
            res = target.dispatch(act.to_request())

        replay_score = 1.0 if res.status_code == 200 else 0.0
        return float(0.5 * reduction_score + 0.5 * replay_score)
    except Exception:
        return 0.0


def evaluate_robustness() -> float:
    """Evaluate runner robustness against malformed responses and edge cases."""
    tenants, users = build_benchmark_testbed()
    try:
        target = get_target("reference")
        target.seed_entities(tenants, users)
        engine = DifferentialEngine(target, tenants, users)

        # Edge cases: non-existent doc, empty payloads, weird strings
        edge_scenario = Scenario(
            id="edge_1",
            actions=[
                FuzzAction(1, "read_document", "org_alpha", "u_a_mem1", "GET", "/api/v1/documents/non_existent_999"),
                FuzzAction(2, "delete_document", "org_alpha", "u_a_mem1", "DELETE", "/api/v1/documents/non_existent_999"),
                FuzzAction(3, "update_document", "org_alpha", "u_a_mem1", "PUT", "/api/v1/documents/non_existent_999", {}),
                FuzzAction(4, "create_document", "org_alpha", "u_a_mem1", "POST", "/api/v1/documents", {"id": ""}),
            ]
        )
        report = engine.run_scenarios([edge_scenario], seed=1, minimize=False)
        return 1.0
    except Exception:
        return 0.0


def evaluate_throughput() -> float:
    """Evaluate execution speed over 50 scenarios."""
    tenants, users = build_benchmark_testbed()
    try:
        target = get_target("reference")
        target.seed_entities(tenants, users)

        t0 = time.perf_counter()
        gen = ScenarioGenerator(tenants, users, seed=999)
        scenarios = gen.generate_scenarios(count=40, max_steps=10)
        engine = DifferentialEngine(target, tenants, users)
        report = engine.run_scenarios(scenarios, seed=999, minimize=False)
        elapsed = time.perf_counter() - t0

        # If 400 requests execute in < 5.0 seconds -> 1.0
        if elapsed <= 5.0:
            return 1.0
        elif elapsed <= 15.0:
            return float(1.0 - (elapsed - 5.0) / 10.0)
        else:
            return 0.1
    except Exception:
        return 0.0


def run_all_benchmarks() -> Dict[str, float]:
    return {
        "authorization_correctness": evaluate_authorization_correctness(),
        "stateful_scenario_coverage": evaluate_scenario_coverage(),
        "fault_discovery_and_precision": evaluate_fault_discovery_and_precision(),
        "failure_minimization_and_replay": evaluate_minimization_and_replay(),
        "robustness_and_edge_cases": evaluate_robustness(),
        "throughput_and_efficiency": evaluate_throughput(),
    }
