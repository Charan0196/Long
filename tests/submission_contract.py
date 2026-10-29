from __future__ import annotations
import importlib
import subprocess
import sys
from typing import Tuple


def check_submission_contract(target_path: str = "/app") -> Tuple[bool, str]:
    """Validate that the agent deliverable satisfies the submission contract."""
    if target_path not in sys.path:
        sys.path.insert(0, target_path)

    # 1. Check module imports
    required_modules = [
        "authfuzzer",
        "authfuzzer.models",
        "authfuzzer.generator",
        "authfuzzer.engine",
        "authfuzzer.minimizer",
        "authfuzzer.reporter",
        "authfuzzer.cli",
    ]

    for mod_name in required_modules:
        try:
            importlib.import_module(mod_name)
        except Exception as e:
            return False, f"Failed to import required module '{mod_name}': {e}"

    # 2. Check CLI entrypoint
    try:
        import os
        env = dict(os.environ)
        env["PYTHONPATH"] = f"{target_path}:{env.get('PYTHONPATH', '')}" if env.get('PYTHONPATH') else target_path
        proc = subprocess.run(
            [sys.executable, "-m", "authfuzzer.cli", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        if proc.returncode != 0:
            return False, f"CLI --help exited with non-zero status {proc.returncode}: {proc.stderr}"
        output = proc.stdout.lower()
        if "fuzz" not in output or "replay" not in output:
            return False, "CLI does not provide required 'fuzz' and 'replay' subcommands"
    except Exception as e:
        return False, f"CLI invocation failed: {e}"

    return True, "Submission contract satisfied"


if __name__ == "__main__":
    ok, msg = check_submission_contract()
    print(f"Contract OK: {ok} ({msg})")
    sys.exit(0 if ok else 1)
