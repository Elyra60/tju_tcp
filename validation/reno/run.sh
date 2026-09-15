#!/usr/bin/env bash
# 从独立验证目录运行，所有编译和日志输出均位于 output，不调用 test/Makefile。
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p validation/reno/output
out=validation/reno/output
gcc -std=gnu11 -Wall -Wextra -Werror -pthread -fcommon -Iinc -c src/tju_tcp.c -o "$out/tju_tcp.o"
gcc -std=gnu11 -Wall -Wextra -pthread -fcommon -DTJU_MSL=1 -Iinc \
    validation/reno/check_reno.c src/tju_packet.c -o "$out/check_reno"
TJU_TRACE_PATH="$out/unit.trace" "$out/check_reno" > "$out/unit.log" 2>&1
cat "$out/unit.log"
for mode in baseline syn_loss synack_loss rto multi_loss zero_window simultaneous; do
    TJU_TRACE_PATH="$out/$mode.trace" timeout 35 "$out/check_reno" "$mode" > "$out/$mode.log" 2>&1
    tail -1 "$out/$mode.log"
done
python3 validation/reno/summarize.py > "$out/trace_summary.log"
cat "$out/trace_summary.log"
# 检查实际内存访问和未定义行为；现有 socket 生命周期不释放用户持有的对象，
# 因而此处关闭泄漏报告，不宣称验证了完整对象释放。
gcc -std=gnu11 -pthread -fcommon -DTJU_MSL=1 -Iinc -g \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    validation/reno/check_reno.c src/tju_packet.c -o "$out/check_reno_sanitized"
ASAN_OPTIONS=detect_leaks=0 TJU_TRACE_PATH="$out/sanitized.trace" \
    "$out/check_reno_sanitized" > "$out/sanitized.log" 2>&1
cat "$out/sanitized.log"
# 只把现有课程测试源码编译至隔离目录，不运行其硬编码 test 输出路径。
for source in test_client test_server test_close_client test_rdt_client test_rdt_server; do
    gcc -pthread -fcommon -Iinc "test/$source.c" src/tju_tcp.c src/tju_packet.c src/kernel.c \
        -o "$out/$source" >> "$out/course_compile.log" 2>&1
    printf 'PASS compile %s\n' "$source"
done
