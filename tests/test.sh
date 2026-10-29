#!/bin/bash
set -euo pipefail

LOG_DIR="${VERIFIER_OUTPUT_DIR:-/logs/verifier}"
mkdir -p "${LOG_DIR}"

# Initialize reward to 0
printf '0\n' > "${LOG_DIR}/reward.txt"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if python3 "${SCRIPT_DIR}/verify.py" --output-dir "${LOG_DIR}"; then
    exit 0
else
    exit 0
fi
