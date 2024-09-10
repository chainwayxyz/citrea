#!/usr/bin/env bash

# Performance Comparison Script
# ------------------------------
#
# This script performs a performance comparison between the current branch and a base branch
# (default: nightly) for a specified test. It can generate comparison results and check for
# performance regressions.
#
# Usage:
#   ./cycle-diff.sh [generate|check]
#
# Modes:
#   generate: Runs tests on both current and base branches, generates comparison results.
#   check: Checks for performance regression based on pre-generated results.
#
# Environment Variables:
#   BASE_BRANCH: The branch to compare against (default: nightly)
#   TEST_NAME: The test file to run (default: bitcoin_e2e::tests::prover_test::basic_prover_test)
#   TARGET_PCT: The threshold percentage for regression detection (default: 3)
#
# Requirements:
#   - Git
#   - Rust and Cargo
#
# WARNING: This script will checkout to BASE_BRANCH. Ensure you are working with a clean
#          Git repository (all changes committed) before running this script.
#
# Output:
#   - In 'generate' mode: Creates a file '$COMPARISON_FILE' with performance metrics.
#   - In 'check' mode: Outputs whether a performance regression was detected.
#
# Exit Codes:
#   0: Success or no regression detected
#   1: Error or regression detected

set -euo pipefail

BASE_BRANCH=${BASE_BRANCH:-"nightly"}
TEST_NAME=${TEST_NAME:-"bitcoin_e2e::tests::prover_test::basic_prover_test"}
TARGET_PCT=${TARGET_PCT:-3}
COMPARISON_FILE=${COMPARISON_FILE:-"comparison_results.log"}

# Used to silence custom risc0 build.rs output
RISC0_GUEST_LOGFILE=
export RISC0_GUEST_LOGFILE
RISC0_GUEST_LOGFILE=$(mktemp)

run_test_and_extract() {
    local command="cargo test $TEST_NAME -p citrea -- --nocapture"
    local output_file="output.log"

    # Aggressively silence build output
    script -q /dev/null make build > /dev/null 2>&1
    $command > "$output_file" 2>&1

    local prover_output_file
    prover_output_file=$(grep "prover.log" "$output_file" | awk '{print $6}')

    local execution_time num_segments total_cycles user_cycles
    execution_time=$(grep "execution time:" "$prover_output_file" | awk '{print $NF}' | sed 's/s//')
    num_segments=$(grep "number of segments:" "$prover_output_file" | awk '{print $NF}')
    total_cycles=$(grep "total cycles:" "$prover_output_file" | awk '{print $NF}')
    user_cycles=$(grep "user cycles:" "$prover_output_file" | awk '{print $NF}')

    echo "$execution_time $num_segments $total_cycles $user_cycles"
}

calc_diff() {
    awk "BEGIN {printf \"%.2f\", ($1 - $2) / $2 * 100}"
}

generate_comparison() {
    local current_branch
    current_branch=$(git rev-parse --abbrev-ref HEAD)
    echo "Running test on current branch: $current_branch"
    local current_metrics
    current_metrics=$(run_test_and_extract)
    echo "$current_branch metrics : $current_metrics"

    echo "Checking out $BASE_BRANCH branch"
    git checkout "$BASE_BRANCH"
    echo "Running test on $BASE_BRANCH branch"
    local base_metrics
    base_metrics=$(run_test_and_extract)
    echo "$BASE_BRANCH metrics : $base_metrics"

    echo "Checking out back to $current_branch"
    git checkout "$current_branch"

    local current_exec_time current_segments current_total_cycles current_user_cycles
    local base_exec_time base_segments base_total_cycles base_user_cycles
    read -r current_exec_time current_segments current_total_cycles current_user_cycles <<< "$current_metrics"
    read -r base_exec_time base_segments base_total_cycles base_user_cycles <<< "$base_metrics"

    local exec_time_diff segments_diff total_cycles_diff user_cycles_diff
    exec_time_diff=$(calc_diff "$current_exec_time" "$base_exec_time")
    segments_diff=$(calc_diff "$current_segments" "$base_segments")
    total_cycles_diff=$(calc_diff "$current_total_cycles" "$base_total_cycles")
    user_cycles_diff=$(calc_diff "$current_user_cycles" "$base_user_cycles")

    echo "Performance Comparison ($current_branch vs $BASE_BRANCH)"
    echo "----------------------------------------"
    printf "Execution Time: %+.2f%%\n" "$exec_time_diff"
    printf "Number of Segments: %+.2f%%\n" "$segments_diff"
    printf "Total Cycles: %+.2f%%\n" "$total_cycles_diff"
    printf "User Cycles: %+.2f%%\n" "$user_cycles_diff"
}

check_regression() {
    local metric="$1"
    local value
    value=$(grep "$metric:" "$COMPARISON_FILE" | awk '{print $NF}' | sed 's/%//')
    echo "Checking $metric:"

    if [ -z "$value" ]; then
        echo "Error: Unable to extract value for $metric"
        return 1
    fi

    if awk "BEGIN {exit !($value > $TARGET_PCT)}"; then
        echo -e "$metric has regressed by $value%, which is more than the target of $TARGET_PCT%\n"
        return 1
    elif awk "BEGIN {exit !($value < -$TARGET_PCT)}"; then
        echo "$metric has improved by ${value#-}%"
    else
        echo "$metric has non significant $value% change"
    fi
    echo ""
    return 0
}

check_performance_regression() {
    local failed=false
    if ! check_regression "Execution Time"; then failed=true; fi
    if ! check_regression "Number of Segments"; then failed=true; fi
    if ! check_regression "Total Cycles"; then failed=true; fi
    if ! check_regression "User Cycles"; then failed=true; fi
    if [ "$failed" = true ]; then
        echo "Performance regression detected!"
        exit 1
    else
        echo "No significant performance regression detected."
    fi
}

cleanup() {
    rm -f "$RISC0_GUEST_LOGFILE"
}

trap cleanup EXIT HUP INT QUIT TERM

main() {
    local mode=${1:-"generate"}
    case "$mode" in
        generate)
            generate_comparison > "$COMPARISON_FILE"
            ;;
        check)
            check_performance_regression
            ;;
        *)
            echo "Invalid mode. Use 'generate' or 'check'."
            exit 1
            ;;
    esac
}

main "$@"
