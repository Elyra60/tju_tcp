#!/usr/bin/env bash
# 第七部分五行表格对应五个独立进程实验，禁止覆盖旧证据和原 test。
set -euo pipefail
cd "$(dirname "$0")/../../.."
base="validation/reno/network/output/report7_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$base"
out="$PWD/$base"
gcc -shared -fPIC -Wall -Wextra validation/reno/network/impairment.c -ldl -o "$out/impairment.so"
client_ns="report7-client-$$"; server_ns="report7-server-$$"
pids=(); created_client=0; created_server=0
cleanup(){
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  if ((created_client)); then ip netns del "$client_ns"; fi
  if ((created_server)); then ip netns del "$server_ns"; fi
}
trap cleanup EXIT
ip netns add "$client_ns"; created_client=1
ip netns add "$server_ns"; created_server=1
ip link add reno-c netns "$client_ns" type veth peer name reno-s netns "$server_ns"
ip -n "$client_ns" addr add 172.17.0.2/24 dev reno-c
ip -n "$server_ns" addr add 172.17.0.3/24 dev reno-s
ip -n "$client_ns" link set lo up
ip -n "$server_ns" link set lo up
ip -n "$client_ns" link set reno-c up
ip -n "$server_ns" link set reno-s up
ip netns exec "$client_ns" tc qdisc add dev reno-c root netem delay 20ms rate 100mbit limit 10000
ip netns exec "$server_ns" tc qdisc add dev reno-s root netem delay 20ms rate 100mbit limit 10000
ip netns exec "$client_ns" tc qdisc show dev reno-c > "$out/network.txt"
ip netns exec "$server_ns" tc qdisc show dev reno-s >> "$out/network.txt"
printf '%s\n' "${REPORT_GIT_HEAD:-not_recorded}" > "$out/git_head.txt"
sha256sum src/tju_tcp.c src/kernel.c src/tju_packet.c inc/*.h validation/reno/network/{endpoint.c,impairment.c,run_report.sh} > "$out/build_sources.sha256"
for mode in slow_start congestion_avoidance rto triple_ack small_rwnd; do
  dir="$out/$mode"; mkdir -p "$dir/test"
  threshold=22000; bytes=300000; drop=0; cap=65535
  # 慢启动用较高阈值与短数据流独立验证；CA 用较低阈值观察阶段转换。
  case "$mode" in
    slow_start) threshold=65535; bytes=20000;;
    congestion_avoidance) bytes=100000;;
    rto) drop=1;; triple_ack) drop=12;; small_rwnd) cap=5500;;
  esac
  gcc -pthread -fcommon -g -DTJU_MSL=1 -DTJU_INITIAL_SSTHRESH="$threshold" -Iinc validation/reno/network/endpoint.c src/tju_tcp.c src/tju_packet.c src/kernel.c -o "$dir/endpoint"
  printf 'mode=%s bytes=%s IW=4125 ssthresh=%s SMSS=1375 MSL=1 delay_each=20ms rate=100Mbit drop_data=%s cap_window=%s\n' "$mode" "$bytes" "$threshold" "$drop" "$cap" > "$dir/config.txt"
  ip netns exec "$server_ns" tcpdump -i reno-s -s 0 -U -w "$dir/server.pcap" udp port 20218 > "$dir/capture.log" 2>&1 &
  capture=$!; pids+=("$capture")
  ip netns exec "$server_ns" unshare --uts bash -c 'hostname server; exec env TEST_BYTES="$4" TJU_TRACE_PATH="$1/test/server.event.trace" CAP_WINDOW="$2" LD_PRELOAD="$3" "$1/endpoint" server "$1/received.bin"' _ "$dir" "$cap" "./$base/impairment.so" "$bytes" > "$dir/server.log" 2>&1 &
  server=$!; pids+=("$server")
  sleep 0.3
  ip netns exec "$client_ns" unshare --uts bash -c 'hostname client; exec env TEST_BYTES="$4" TJU_TRACE_PATH="$1/test/client.event.trace" DROP_DATA="$2" LD_PRELOAD="$3" "$1/endpoint" client "$1/sent.bin"' _ "$dir" "$drop" "./$base/impairment.so" "$bytes" > "$dir/client.log" 2>&1 &
  client=$!; pids+=("$client")
  wait "$client"; wait "$server"
  kill -INT "$capture"; wait "$capture" || true; pids=()
  cmp "$dir/sent.bin" "$dir/received.bin"
  if grep -q 'cannot be preloaded' "$dir/client.log" "$dir/server.log"; then exit 1; fi
  if ((drop)); then grep -q INJECT_DROP "$dir/client.log"; fi
  sha256sum "$dir/sent.bin" "$dir/received.bin" "$dir/test/"*.trace "$dir/server.pcap" > "$dir/evidence.sha256"
  printf 'PASS real UDP %s: %s bytes identical\n' "$mode" "$bytes" | tee "$dir/result.log"
done
printf 'REPORT7_OUTPUT=%s\n' "$base"
