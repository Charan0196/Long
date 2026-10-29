#!/bin/sh
set -e

if ! id agent >/dev/null 2>&1; then
    useradd -m -s /bin/bash -u 1000 agent
fi

# Allow agent passwordless sudo for local dev flexibility
echo "agent ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/agent
chmod 0440 /etc/sudoers.d/agent
