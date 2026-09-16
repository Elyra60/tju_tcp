#!/usr/bin/env bash
# 相同链路下比较基础与完整Reno；各场景使用独立进程、Trace和抓包。
set -euo pipefail
cd "$(dirname "$0")/../.."
base="validation/full_reno/output/network_$(date +%Y%m%d_%H%M%S)"; out="$PWD/$base"; mkdir -p "$out"
gcc -shared -fPIC validation/reno/network/impairment.c -ldl -o "$out/impairment.so"
gcc -pthread -fcommon -DTJU_MSL=1 -Iinc validation/full_reno/check_recovery.c src/tju_packet.c -o "$out/check_recovery"
TJU_TRACE_PATH="$out/unit.trace" "$out/check_recovery" > "$out/unit.log" 2>&1
sha256sum src/*.c inc/*.h validation/reno/check_reno.c validation/reno/network/{endpoint.c,impairment.c} validation/full_reno/{check_recovery.c,run_network.sh} > "$out/build_sources.sha256"
c="fr-c-$$"; s="fr-s-$$"; pids=()
cleanup(){ for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; ip netns del "$c" 2>/dev/null || true; ip netns del "$s" 2>/dev/null || true; }
trap cleanup EXIT
ip netns add "$c"; ip netns add "$s"
ip link add fr-c netns "$c" type veth peer name fr-s netns "$s"
ip -n "$c" addr add 172.17.0.2/24 dev fr-c; ip -n "$s" addr add 172.17.0.3/24 dev fr-s
ip -n "$c" link set lo up; ip -n "$s" link set lo up
ip -n "$c" link set fr-c up; ip -n "$s" link set fr-s up
ip netns exec "$c" tc qdisc add dev fr-c root netem delay 20ms rate 100mbit limit 10000
ip netns exec "$s" tc qdisc add dev fr-s root netem delay 20ms rate 100mbit limit 10000
for full in 0 1; do
 gcc -pthread -fcommon -O2 -DTJU_FULL_RENO="$full" -DTJU_MSL=1 -DTJU_INITIAL_SSTHRESH=22000 -Iinc validation/reno/network/endpoint.c src/tju_tcp.c src/tju_packet.c src/kernel.c -o "$out/endpoint_$full"
 for mode in single_loss rto small_rwnd no_loss; do
  d="$out/mode_${full}_$mode"; mkdir -p "$d"; drop=0; cap=65535
  case "$mode" in single_loss) drop=12;; rto) drop=1;; small_rwnd) cap=5500;; esac
  printf 'full=%s mode=%s drop=%s cap=%s bytes=300000 delay_each_ms=20 rate=100Mbit IW=4125 ssthresh=22000 SMSS=1375\n' "$full" "$mode" "$drop" "$cap" > "$d/config.txt"
  ip netns exec "$s" tcpdump -i fr-s -s 0 -U -w "$d/server.pcap" udp port 20218 > "$d/capture.log" 2>&1 & cap_pid=$!; pids+=("$cap_pid")
  ip netns exec "$s" unshare --uts bash -c 'hostname server; exec env TJU_TRACE_PATH="$1/server.trace" CAP_WINDOW="$2" LD_PRELOAD="$3" "$4" server "$1/received.bin"' _ "$d" "$cap" "./$base/impairment.so" "$out/endpoint_$full" > "$d/server.log" 2>&1 & sp=$!; pids+=("$sp")
  sleep .3
  ip netns exec "$c" unshare --uts bash -c 'hostname client; exec env TJU_TRACE_PATH="$1/client.trace" DROP_DATA="$2" LD_PRELOAD="$3" "$4" client "$1/sent.bin"' _ "$d" "$drop" "./$base/impairment.so" "$out/endpoint_$full" > "$d/client.log" 2>&1 & cp=$!; pids+=("$cp")
  wait "$cp"; wait "$sp"; kill -INT "$cap_pid"; wait "$cap_pid" || true; pids=()
  cmp "$d/sent.bin" "$d/received.bin"
  if ((drop)); then grep -q INJECT_DROP "$d/client.log"; fi
  printf 'PASS mode=%s case=%s bytes=300000\n' "$full" "$mode" | tee "$d/result.log"
 done
done
printf 'OUTPUT=%s\n' "$base"
