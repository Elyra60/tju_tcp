#!/usr/bin/env bash
# 独立命名空间内运行真实 UDP、tc/netem 与 tcpdump。原 test 始终只读。
set -euo pipefail
cd "$(dirname "$0")/../../.."
repo=$PWD
out="$repo/validation/reno/network/output/verified"
preload="./validation/reno/network/output/verified/impairment.so"
mkdir -p "$out"
# 专用实验阈值 16 SMSS，使 cwnd 在小于真实接收容量时跨入 CA；不是平台默认值。
gcc -pthread -fcommon -g -DTJU_MSL=1 -DTJU_INITIAL_SSTHRESH=22000 -Iinc \
  validation/reno/network/endpoint.c src/tju_tcp.c src/tju_packet.c src/kernel.c -o "$out/endpoint"
gcc -shared -fPIC -Wall -Wextra validation/reno/network/impairment.c -ldl -o "$out/impairment.so"
client_ns="reno-client-$$"
server_ns="reno-server-$$"
created_client=0
created_server=0
pids=()
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
for mode in ${RENO_SCENARIOS:-no_loss_clean rto triple_ack small_rwnd}; do
  dir="$out/$mode"
  mkdir -p "$dir/test"
  drop=0; cap=65535; bytes=300000
  if [[ "$mode" == no_loss_clean ]]; then bytes=100000; fi
  case "$mode" in rto) drop=1;; triple_ack) drop=12;; small_rwnd) cap=5500;; esac
  printf 'mode=%s bytes=%s IW=4125 ssthresh=22000 SMSS=1375 delay_each=20ms rate=100Mbit drop_data=%s cap_window=%s\n' "$mode" "$bytes" "$drop" "$cap" > "$dir/config.txt"
  ip netns exec "$server_ns" tcpdump -i reno-s -s 0 -U -w "$dir/server.pcap" udp port 20218 > "$dir/capture.log" 2>&1 &
  capture=$!; pids+=("$capture")
  # hostname 修改限定在各自 UTS 命名空间，不修改 WSL 主机名。
  ip netns exec "$server_ns" unshare --uts bash -c 'hostname server; exec env TEST_BYTES="$5" TJU_TRACE_PATH="$1/test/server.event.trace" CAP_WINDOW="$2" LD_PRELOAD="$4" "$3/endpoint" server "$1/received.bin"' _ "$dir" "$cap" "$out" "$preload" "$bytes" > "$dir/server.log" 2>&1 &
  server=$!; pids+=("$server")
  sleep 0.3
  ip netns exec "$client_ns" unshare --uts bash -c 'hostname client; exec env TEST_BYTES="$5" TJU_TRACE_PATH="$1/test/client.event.trace" DROP_DATA="$2" LD_PRELOAD="$4" "$3/endpoint" client "$1/sent.bin"' _ "$dir" "$drop" "$out" "$preload" "$bytes" > "$dir/client.log" 2>&1 &
  client=$!; pids+=("$client")
  wait "$client"
  wait "$server"
  kill -INT "$capture"
  wait "$capture" || true
  pids=()
  cmp "$dir/sent.bin" "$dir/received.bin"
  if grep -q 'cannot be preloaded' "$dir/client.log" "$dir/server.log"; then exit 1; fi
  if ((drop)); then grep -q 'INJECT_DROP' "$dir/client.log"; fi
  if [[ "$mode" == rto ]]; then grep -q 'reason:RTO' "$dir/test/client.event.trace"; fi
  if [[ "$mode" == triple_ack ]]; then grep -q 'reason:FAST_RETRANSMIT' "$dir/test/client.event.trace"; fi
  if [[ "$mode" == small_rwnd ]]; then grep -q 'peer:5500' "$dir/test/client.event.trace"; fi
  sha256sum "$dir/sent.bin" "$dir/received.bin" > "$dir/data.sha256"
  printf 'PASS real UDP %s: %s bytes identical\n' "$mode" "$bytes" | tee "$dir/result.log"
done
