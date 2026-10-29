#!/usr/bin/env python3
import os
import subprocess
import sys
from pathlib import Path


def main():
    tests_dir = Path(__file__).resolve().parent
    runner_script = tests_dir / "runner.py"
    output_dir = os.environ.get("VERIFIER_OUTPUT_DIR", str(tests_dir.parent.parent / "eval_out"))

    cmd = [sys.executable, str(runner_script), "--output-dir", output_dir]
    res = subprocess.run(cmd)
    sys.exit(res.returncode)


if __name__ == "__main__":
    main()
