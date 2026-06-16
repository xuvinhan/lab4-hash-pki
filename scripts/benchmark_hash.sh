#!/usr/bin/env bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
SAMPLES_DIR="$ROOT_DIR/samples"
RESULTS_DIR="$ROOT_DIR/results"

TOOL="$BUILD_DIR/hashtool.exe"

if [ ! -f "$TOOL" ]; then
    TOOL="$BUILD_DIR/hashtool"
fi

if [ ! -f "$TOOL" ]; then
    echo "[ERROR] hashtool not found. Please build the project first."
    exit 1
fi

mkdir -p "$SAMPLES_DIR" "$RESULTS_DIR"

PROFILE="${1:-quick}"

RESULT_FILE="$RESULTS_DIR/hash_benchmark_${PROFILE}.csv"

echo "algorithm,size_label,bytes,time_ms,throughput_mib_s" > "$RESULT_FILE"

make_file() {
    local label="$1"
    local file="$2"
    local bs="$3"
    local count="$4"

    if [ ! -f "$file" ]; then
        echo "[INFO] Generating $label test file: $file"
        dd if=/dev/urandom of="$file" bs="$bs" count="$count" status=none
    fi
}

if [ "$PROFILE" = "quick" ]; then
    make_file "1KiB"   "$SAMPLES_DIR/bench_1k.bin"   1K 1
    make_file "1MiB"   "$SAMPLES_DIR/bench_1m.bin"   1M 1
    make_file "16MiB"  "$SAMPLES_DIR/bench_16m.bin"  1M 16

    FILES=(
        "1KiB:$SAMPLES_DIR/bench_1k.bin"
        "1MiB:$SAMPLES_DIR/bench_1m.bin"
        "16MiB:$SAMPLES_DIR/bench_16m.bin"
    )
elif [ "$PROFILE" = "full" ]; then
    make_file "1KiB"    "$SAMPLES_DIR/bench_1k.bin"    1K 1
    make_file "1MiB"    "$SAMPLES_DIR/bench_1m.bin"    1M 1
    make_file "100MiB"  "$SAMPLES_DIR/bench_100m.bin"  1M 100

    FILES=(
        "1KiB:$SAMPLES_DIR/bench_1k.bin"
        "1MiB:$SAMPLES_DIR/bench_1m.bin"
        "100MiB:$SAMPLES_DIR/bench_100m.bin"
    )
else
    echo "[ERROR] Unknown profile: $PROFILE"
    echo "Usage: ./scripts/benchmark_hash.sh quick|full"
    exit 1
fi

ALGOS=(
    "sha256"
    "sha512"
    "sha3-256"
    "sha3-512"
)

run_benchmark() {
    local algo="$1"
    local label="$2"
    local file="$3"

    local bytes
    bytes=$(wc -c < "$file" | tr -d ' ')

    local start
    local end
    local elapsed_ns
    local elapsed_ms
    local throughput

    start=$(date +%s%N)
    "$TOOL" hash --algo "$algo" --in "$file" > /dev/null
    end=$(date +%s%N)

    elapsed_ns=$((end - start))
    elapsed_ms=$((elapsed_ns / 1000000))

    if [ "$elapsed_ms" -eq 0 ]; then
        elapsed_ms=1
    fi

    throughput=$(awk -v b="$bytes" -v ms="$elapsed_ms" 'BEGIN {
        printf "%.2f", (b / 1048576) / (ms / 1000)
    }')

    echo "$algo,$label,$bytes,$elapsed_ms,$throughput" >> "$RESULT_FILE"
    echo "[OK] $algo $label: ${elapsed_ms} ms, ${throughput} MiB/s"
}

echo ">> HASH BENCHMARK"
echo "Profile     : $PROFILE"
echo "Tool        : $TOOL"
echo "Result file : $RESULT_FILE"
echo

for item in "${FILES[@]}"; do
    label="${item%%:*}"
    file="${item#*:}"

    for algo in "${ALGOS[@]}"; do
        run_benchmark "$algo" "$label" "$file"
    done
done

echo
echo ">> BENCHMARK DONE"
echo "CSV output: $RESULT_FILE"
