#!/usr/bin/env bash
set -euo pipefail

echo "=== Running FrontierSWE Preflight Checks ==="

# 1. Check Python version
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 not found." >&2
    exit 1
fi

py_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "Detected Python: ${py_version}"

# 2. Check directory structure
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for dir in "environment/workspace" "environment/tests" "solution/oracle" "preflight"; do
    if [ ! -d "${ROOT_DIR}/${dir}" ]; then
        echo "ERROR: Missing directory ${dir}" >&2
        exit 1
    fi
done

# 3. Check critical files
for file in "task.toml" "instruction.md" "environment/workspace/README.md" "environment/tests/test.sh"; do
    if [ ! -f "${ROOT_DIR}/${file}" ]; then
        echo "ERROR: Missing required file ${file}" >&2
        exit 1
    fi
done

echo "Preflight checks passed successfully."
exit 0
