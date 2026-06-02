#!/usr/bin/env bash
# bench-history.sh — Run benchmarks and append results to CSV history.
#
# Usage:
#   ./scripts/bench-history.sh [label]
#
# The label defaults to the current git short hash + date. For a version
# release, pass the version explicitly so deltas track per release:
#   ./scripts/bench-history.sh 3.3.0
#
# Benchmarks live in tests/kavach.bcyr and run via `cyrius bench`. Each
# line of output looks like:
#   score_backend_process_strict: 42ns avg (min=37ns max=62ns) [500000 iters]
# We record the avg, normalized to nanoseconds, into the CSV history.
# Results are appended to benches/bench-history.csv.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BENCH_SRC="$PROJECT_DIR/tests/kavach.bcyr"
CSV="$PROJECT_DIR/benches/bench-history.csv"

# Label: argument or git hash + date
LABEL="${1:-$(git -C "$PROJECT_DIR" rev-parse --short HEAD)-$(date +%Y%m%d)}"

echo "=== Kavach Benchmark Run: $LABEL ==="
echo ""

mkdir -p "$PROJECT_DIR/benches"

# Create CSV header if file doesn't exist
if [ ! -f "$CSV" ]; then
    echo "label,benchmark,time_ns,time_unit" > "$CSV"
fi

# Run benchmarks and capture output
BENCH_OUTPUT=$(cd "$PROJECT_DIR" && cyrius bench "$BENCH_SRC" 2>&1)

# Parse "  <name>: <avg><unit> avg (...)" lines. Normalize avg to ns.
COUNT=0
while IFS= read -r line; do
    NAME=$(echo "$line" | sed -E 's/^[[:space:]]*([a-zA-Z0-9_]+):.*/\1/')
    VAL=$(echo  "$line" | sed -E 's/^[[:space:]]*[a-zA-Z0-9_]+:[[:space:]]*([0-9.]+)(ns|us|µs|ms|s)[[:space:]]+avg.*/\1/')
    UNIT=$(echo "$line" | sed -E 's/^[[:space:]]*[a-zA-Z0-9_]+:[[:space:]]*[0-9.]+(ns|us|µs|ms|s)[[:space:]]+avg.*/\1/')
    [ -z "$NAME" ] && continue
    [ -z "$VAL" ] && continue

    case "$UNIT" in
        ns)     MULT=1 ;;
        us|µs)  MULT=1000 ;;
        ms)     MULT=1000000 ;;
        s)      MULT=1000000000 ;;
        *)      MULT=1 ;;
    esac
    # awk for float-safe arithmetic (bc isn't guaranteed present). Drop a
    # trailing .0 so integer ns stay integer in the CSV.
    NS=$(awk -v v="$VAL" -v m="$MULT" 'BEGIN { r = v * m; if (r == int(r)) printf "%d", r; else printf "%g", r }')

    echo "$LABEL,$NAME,$NS,$UNIT" >> "$CSV"
    COUNT=$((COUNT + 1))
done < <(echo "$BENCH_OUTPUT" | grep -E '^[[:space:]]*[a-zA-Z0-9_]+:[[:space:]]*[0-9.]+(ns|us|µs|ms|s)[[:space:]]+avg')

echo ""
echo "=== $COUNT benchmarks recorded for $LABEL ==="
echo "Results in: $CSV"
