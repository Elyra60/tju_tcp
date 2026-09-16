#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
out="validation/rdt_performance/output/regression_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$out"
sha256sum src/*.c inc/*.h Makefile validation/rdt_performance/{check_rdt.c,run_regression.sh} > "$out/build.sha256"
for profile in 0 1; do
 gcc -Wall -Wextra -Werror -pthread -fcommon -DTJU_RDT_PROFILE="$profile" -Iinc -c src/tju_tcp.c -o "$out/tcp_$profile.o"
 gcc -pthread -fcommon -g -no-pie -fsanitize=address,undefined -fno-omit-frame-pointer -DTJU_RDT_PROFILE="$profile" -DTJU_MSL=1 -Iinc validation/rdt_performance/check_rdt.c src/tju_packet.c -o "$out/check_$profile"
 ASAN_OPTIONS=detect_leaks=0 TJU_TRACE_PATH="$out/unit_$profile.trace" timeout -k 2 45 "$out/check_$profile" | tee "$out/unit_$profile.log"
done
for mode in baseline syn_loss synack_loss rto multi_loss zero_window simultaneous fin_loss fin_ack_loss final_ack_loss; do
 ASAN_OPTIONS=detect_leaks=0 TJU_TRACE_PATH="$out/$mode.trace" timeout -k 2 45 "$out/check_1" "$mode" | tee "$out/$mode.log"
done
printf 'OUTPUT=%s\n' "$out"
