#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
out=validation/rdt_performance/output/regression_20260916_205843
for mode in fin_loss fin_ack_loss final_ack_loss; do
 ASAN_OPTIONS=detect_leaks=0 TJU_TRACE_PATH="$out/reno_$mode.trace" timeout -k 2 45 "$out/check_0" "$mode" | tee "$out/reno_$mode.log"
done
