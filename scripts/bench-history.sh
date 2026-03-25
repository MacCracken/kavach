#!/usr/bin/env bash
# bench-history.sh — Run benchmarks and append results to CSV history.
#
# Usage:
#   ./scripts/bench-history.sh [label]
#
# The label defaults to the current git short hash + date.
# Results are appended to benches/bench-history.csv.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CSV="$PROJECT_DIR/benches/bench-history.csv"

# Label: argument or git hash + date
LABEL="${1:-$(git -C "$PROJECT_DIR" rev-parse --short HEAD)-$(date +%Y%m%d)}"

echo "=== Kavach Benchmark Run: $LABEL ==="
echo ""

# Create CSV header if file doesn't exist
if [ ! -f "$CSV" ]; then
    echo "label,benchmark,time_ns,time_unit" > "$CSV"
fi

# Run benchmarks and capture output
BENCH_OUTPUT=$(cargo bench --manifest-path "$PROJECT_DIR/Cargo.toml" 2>&1)

echo "$BENCH_OUTPUT" | grep "time:" | while IFS= read -r line; do
    # Extract benchmark name from the preceding "Benchmarking <name>" line
    # Parse: "time:   [1.78 ns 1.79 ns 1.80 ns]" → median value
    MEDIAN=$(echo "$line" | sed -E 's/.*\[.* ([0-9.]+) (ns|µs|ms|s) .*/\1/')
    UNIT=$(echo "$line" | sed -E 's/.*\[.* [0-9.]+ (ns|µs|ms|s) .*/\1/')

    # Convert to nanoseconds for consistent comparison
    case "$UNIT" in
        ps) NS=$(echo "$MEDIAN * 0.001" | bc -l 2>/dev/null || echo "$MEDIAN") ;;
        ns) NS="$MEDIAN" ;;
        µs) NS=$(echo "$MEDIAN * 1000" | bc -l 2>/dev/null || echo "$MEDIAN") ;;
        ms) NS=$(echo "$MEDIAN * 1000000" | bc -l 2>/dev/null || echo "$MEDIAN") ;;
        s)  NS=$(echo "$MEDIAN * 1000000000" | bc -l 2>/dev/null || echo "$MEDIAN") ;;
        *)  NS="$MEDIAN" ;;
    esac

    echo "$LABEL,unknown,$NS,$UNIT" >> "$CSV"
done

# Parse full output to get benchmark names paired with times
echo "$BENCH_OUTPUT" | awk '
/^Benchmarking / { name = $2 }
/time:/ {
    match($0, /\[.* ([0-9.]+) (ns|µs|ms|ps|s)/, arr)
    if (arr[1] != "") {
        print name "," arr[1] "," arr[2]
    }
}' | while IFS=, read -r NAME MEDIAN UNIT; do
    case "$UNIT" in
        ps) NS=$(echo "$MEDIAN * 0.001" | bc -l 2>/dev/null || echo "$MEDIAN") ;;
        ns) NS="$MEDIAN" ;;
        µs) NS=$(echo "$MEDIAN * 1000" | bc -l 2>/dev/null || echo "$MEDIAN") ;;
        ms) NS=$(echo "$MEDIAN * 1000000" | bc -l 2>/dev/null || echo "$MEDIAN") ;;
        s)  NS=$(echo "$MEDIAN * 1000000000" | bc -l 2>/dev/null || echo "$MEDIAN") ;;
        *)  NS="$MEDIAN" ;;
    esac
    # Overwrite the "unknown" entries with real names
    sed -i "s/$LABEL,unknown,$NS,$UNIT/$LABEL,$NAME,$NS,$UNIT/" "$CSV" 2>/dev/null || true
done

ENTRIES=$(grep -c "$LABEL" "$CSV" 2>/dev/null || echo "0")
echo ""
echo "=== $ENTRIES benchmarks recorded for $LABEL ==="
echo "Results in: $CSV"
