from __future__ import annotations
import argparse
import sys
from pathlib import Path
from api.client import get_target
from api.models import Tenant, User, Role
from authfuzzer.generator import ScenarioGenerator
from authfuzzer.engine import DifferentialEngine
from authfuzzer.reporter import FuzzReporter
from authfuzzer.models import FuzzAction


def create_default_testbed():
    tenants = [
        Tenant("org_alpha", "Alpha Corp"),
        Tenant("org_beta", "Beta LLC"),
    ]
    users = [
        User.create("user_alpha_admin", "org_alpha", Role.ADMIN),
        User.create("user_alpha_member1", "org_alpha", Role.MEMBER),
        User.create("user_alpha_member2", "org_alpha", Role.MEMBER),
        User.create("user_alpha_guest", "org_alpha", Role.GUEST),
        User.create("user_beta_admin", "org_beta", Role.ADMIN),
        User.create("user_beta_member", "org_beta", Role.MEMBER),
        User.create("user_beta_guest", "org_beta", Role.GUEST),
    ]
    return tenants, users


def run_fuzz(args: argparse.Namespace) -> int:
    tenants, users = create_default_testbed()
    target = get_target(args.target)
    target.seed_entities(tenants, users)

    generator = ScenarioGenerator(tenants, users, seed=args.seed)
    scenarios = generator.generate_scenarios(count=args.scenarios, max_steps=args.max_steps)

    engine = DifferentialEngine(target, tenants, users)
    report = engine.run_scenarios(scenarios, seed=args.seed, minimize=args.minimize)

    if args.output:
        FuzzReporter.save(report, args.output)
        print(f"Report saved to {args.output}")

    print(f"Scenarios: {report.total_scenarios}, Requests: {report.total_requests}, Violations: {len(report.violations)}")
    return 0 if len(report.violations) == 0 else 1


def run_replay(args: argparse.Namespace) -> int:
    tenants, users = create_default_testbed()
    target = get_target(args.target)
    target.seed_entities(tenants, users)

    report_data = FuzzReporter.load(args.repro)
    violations = report_data.get("violations", [])
    if not violations:
        print("No violations in report to replay.")
        return 0

    target.reset()
    all_reproduced = True
    for v in violations:
        seq = [FuzzAction.from_dict(a) for a in v.get("minimized_sequence", [])]
        res = None
        for action in seq:
            res = target.dispatch(action.to_request())
        
        actual_status = res.status_code if res else 500
        if actual_status == v["actual"]["status_code"]:
            print(f"Violation {v['id']} successfully reproduced (status {actual_status})")
        else:
            print(f"Violation {v['id']} failed to reproduce: expected {v['actual']['status_code']}, got {actual_status}")
            all_reproduced = False

    return 0 if all_reproduced else 1


def main() -> int:
    parser = argparse.ArgumentParser(prog="authfuzzer", description="Stateful API Authorization Fuzzer")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Fuzz command
    fuzz_parser = subparsers.add_parser("fuzz", help="Generate scenarios and differential-fuzz target")
    fuzz_parser.add_argument("--target", required=True, help="Target API name (e.g. reference, idor, cross_tenant, etc.)")
    fuzz_parser.add_argument("--seed", type=int, default=42, help="RNG seed")
    fuzz_parser.add_argument("--scenarios", type=int, default=30, help="Number of scenarios")
    fuzz_parser.add_argument("--max-steps", type=int, default=15, help="Maximum steps per scenario")
    fuzz_parser.add_argument("--output", help="Output path for JSON report")
    fuzz_parser.add_argument("--minimize", action="store_true", default=True, help="Minimize failure sequences")
    fuzz_parser.add_argument("--no-minimize", dest="minimize", action="store_false")

    # Replay command
    replay_parser = subparsers.add_parser("replay", help="Replay a minimized reproduction from report")
    replay_parser.add_argument("--target", required=True, help="Target API name")
    replay_parser.add_argument("--repro", required=True, help="Path to reproduction report JSON")

    args = parser.parse_args()
    if args.command == "fuzz":
        return run_fuzz(args)
    elif args.command == "replay":
        return run_replay(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
