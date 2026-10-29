#!/bin/bash
set -euo pipefail

if [ -d "/app/authfuzzer" ]; then
    if [ -d "/solution/oracle" ]; then
        cp -r /solution/oracle/* /app/authfuzzer/
    elif [ -d "$(dirname "$0")/oracle" ]; then
        cp -r "$(dirname "$0")/oracle/"* /app/authfuzzer/
    fi
else
    # Local development outside container
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    APP_DIR="${SCRIPT_DIR}/../environment/app/authfuzzer"
    mkdir -p "${APP_DIR}"
    cp -r "${SCRIPT_DIR}/oracle/"* "${APP_DIR}/"
fi

echo "Oracle solution deployed successfully."
