#!/usr/bin/env bash
# 对基础/完整两种编译模式运行相同回归，写入独立时间戳目录保护旧结果。
set -euo pipefail
cd "$(dirname "$0")/../.."
out="validation/full_reno/output/regression_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$out"
uname -a > "$out/environment.txt"
gcc --version >> "$out/environment.txt"
sha256sum src/*.c inc/*.h validation/reno/check_reno.c validation/full_reno/{check_recovery.c,run_regression.sh} > "$out/build_sources.sha256"
for full in 0 1; do
 d="$out/mode_$full"; mkdir -p "$d"
 gcc -std=gnu11 -Wall -Wextra -Werror -pthread -fcommon -DTJU_FULL_RENO="$full" -Iinc -c src/tju_tcp.c -o "$d/tcp.o"
 gcc -pthread -fcommon -DTJU_FULL_RENO="$full" -DTJU_MSL=1 -Iinc validation/reno/check_reno.c src/tju_packet.c -o "$d/check"
 TJU_TRACE_PATH="$d/unit.trace" timeout -k 2 40 "$d/check" > "$d/unit.log" 2>&1
 for mode in baseline syn_loss synack_loss rto multi_loss zero_window simultaneous; do
  TJU_TRACE_PATH="$d/$mode.trace" timeout 40 "$d/check" "$mode" > "$d/$mode.log" 2>&1
  tail -1 "$d/$mode.log"
 done
 # GCC 9 ASan PIE在当前WSL地址布局下可能在main前循环DEADLYSIGNAL。
 # 固定测试程序加载地址，保留完整ASan/UBSan检查；超时防止启动异常挂死。
 gcc -pthread -fcommon -g -no-pie -fsanitize=address,undefined -fno-omit-frame-pointer -DTJU_FULL_RENO="$full" -DTJU_MSL=1 -Iinc validation/reno/check_reno.c src/tju_packet.c -o "$d/sanitized"
 ASAN_OPTIONS=detect_leaks=0 TJU_TRACE_PATH="$d/sanitized.trace" timeout -k 2 40 "$d/sanitized" > "$d/sanitized.log" 2>&1
 printf 'PASS ASan/UBSan mode=%s\n' "$full"
done
gcc -pthread -fcommon -g -no-pie -fsanitize=address,undefined -fno-omit-frame-pointer -DTJU_MSL=1 -Iinc validation/full_reno/check_recovery.c src/tju_packet.c -o "$out/check_recovery"
ASAN_OPTIONS=detect_leaks=0 TJU_TRACE_PATH="$out/recovery.trace" timeout -k 2 40 "$out/check_recovery" > "$out/recovery.log" 2>&1
tail -4 "$out/recovery.log"
for source in test_client test_server test_close_client test_rdt_client test_rdt_server; do
 gcc -pthread -fcommon -Iinc "test/$source.c" src/tju_tcp.c src/tju_packet.c src/kernel.c -o "$out/$source" >> "$out/course_compile.log" 2>&1
 printf 'PASS compile %s\n' "$source" | tee -a "$out/course_compile.log"
done
printf 'OUTPUT=%s\n' "$out"
