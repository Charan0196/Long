#!/bin/sh
set -e

ACTION="${1:-status}"
TIMER_DIR="/var/run/sandbox-timer"
START_FILE="${TIMER_DIR}/start_time"

case "$ACTION" in
    start)
        mkdir -p "$TIMER_DIR"
        if [ ! -f "$START_FILE" ]; then
            date +%s > "$START_FILE"
        fi
        ;;
    elapsed)
        if [ -f "$START_FILE" ]; then
            START=$(cat "$START_FILE")
            NOW=$(date +%s)
            echo "$((NOW - START))"
        else
            echo "0"
        fi
        ;;
    status)
        if [ -f "$START_FILE" ]; then
            echo "running"
        else
            echo "stopped"
        fi
        ;;
    *)
        echo "Usage: sandbox-timer {start|elapsed|status}" >&2
        exit 1
        ;;
esac
