#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_BIN="$SCRIPT_DIR/build/bin/honeybadger_demo"

echo "=== HoneyBadger BFT Demo ==="
echo "Running 4 nodes (N=4, f=1)"
echo ""

if [ ! -f "$DEMO_BIN" ]; then
    echo "Error: honeybadger_demo not found"
    exit 1
fi

LOG_DIR=$(mktemp -d)
echo "Logs: $LOG_DIR"
echo ""

cleanup() {
    echo ""
    echo "Cleaning up..."
    jobs -p | xargs -r kill 2>/dev/null || true
    echo "Logs saved in: $LOG_DIR"
}
trap cleanup EXIT INT TERM

echo "Starting nodes..."
for node_id in 0 1 2 3; do
    LOG_FILE="$LOG_DIR/node_$node_id.log"
    echo "  Node $node_id -> $LOG_FILE"
    "$DEMO_BIN" $node_id > "$LOG_FILE" 2>&1 &
    PIDS[$node_id]=$!
done

echo ""
echo "All nodes started!"
echo "PIDs: ${PIDS[@]}"
echo ""

for pid in "${PIDS[@]}"; do
    wait $pid 2>/dev/null || true
done

echo ""
echo "=== Demo Complete ==="
echo ""
for node_id in 0 1 2 3; do
    echo "--- Node $node_id ---"
    cat "$LOG_DIR/node_$node_id.log"
    echo ""
done
