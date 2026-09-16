#!/usr/bin/env bash
# 时延与带宽两类单因素对照；每次独立连接并保留独立 trace、抓包和文件。
set -euo pipefail
cd "$(dirname "$0")/../.."
out="$PWD/validation/performance/output/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$out/source/src" "$out/source/inc"
cp src/*.c "$out/source/src/"; cp inc/*.h "$out/source/inc/"
cp validation/performance/{run.sh,endpoint.c} "$out/source/"
sha256sum src/*.c inc/*.h validation/performance/{run.sh,endpoint.c} > "$out/build.sha256"
uname -a > "$out/environment.txt"; gcc --version >> "$out/environment.txt"; tc -V >> "$out/environment.txt"
gcc -pthread -fcommon -O2 -DTJU_FULL_RENO=0 -DTJU_MSL=1 -Iinc validation/performance/endpoint.c src/tju_tcp.c src/tju_packet.c src/kernel.c -o "$out/endpoint"
c="perf-c-$$"; s="perf-s-$$"; pids=()
cleanup(){ for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; ip netns del "$c" 2>/dev/null || true; ip netns del "$s" 2>/dev/null || true; }
trap cleanup EXIT
ip netns add "$c"; ip netns add "$s"
ip link add perf-c netns "$c" type veth peer name perf-s netns "$s"
ip -n "$c" addr add 172.17.0.2/24 dev perf-c; ip -n "$s" addr add 172.17.0.3/24 dev perf-s
ip -n "$c" link set lo up; ip -n "$s" link set lo up
ip -n "$c" link set perf-c up; ip -n "$s" link set perf-s up
# 交错重复各档，减轻主机负载随时间变化的偏差；不设置随机丢包。
for rep in 1 2 3; do
 for config in delay_5 delay_20 delay_50 bandwidth_1 bandwidth_5 bandwidth_20; do
  delay=20; rate=100
  case "$config" in delay_*) delay=${config#delay_};; bandwidth_*) rate=${config#bandwidth_};; esac
  d="$out/${config}_r${rep}"; mkdir -p "$d"
  printf 'factor_level=%s repeat=%s delay_ms=%s rate_mbps=%s loss=0 bytes=2000000 SMSS=1375 IW=4125 ssthresh=65535 MSL=1\n' "$config" "$rep" "$delay" "$rate" > "$d/config.txt"
  ip netns exec "$c" tc qdisc replace dev perf-c root netem delay "${delay}ms" rate "${rate}mbit" limit 10000
  ip netns exec "$s" tc qdisc replace dev perf-s root netem delay "${delay}ms" rate "${rate}mbit" limit 10000
  ip netns exec "$s" tcpdump -i perf-s -s 0 -U -w "$d/server.pcap" udp port 20218 > "$d/capture.log" 2>&1 & cap=$!; pids+=("$cap")
  ip netns exec "$s" unshare --uts bash -c 'hostname server; exec env TJU_TRACE_PATH="$1/server.trace" "$2/endpoint" server "$1/received.bin"' _ "$d" "$out" > "$d/server.log" 2>&1 & sp=$!; pids+=("$sp")
  sleep 0.3
  ip netns exec "$c" unshare --uts bash -c 'hostname client; exec env TJU_TRACE_PATH="$1/client.trace" "$2/endpoint" client "$1/sent.bin"' _ "$d" "$out" > "$d/client.log" 2>&1 & cp=$!; pids+=("$cp")
  wait "$cp"; wait "$sp"; kill -INT "$cap"; wait "$cap" || true; pids=()
  cmp "$d/sent.bin" "$d/received.bin"
  sha256sum "$d/"*.bin "$d/"*.trace "$d/server.pcap" > "$d/evidence.sha256"
  ip netns exec "$c" tc -s qdisc show dev perf-c > "$d/qdisc.txt"
  ip netns exec "$s" tc -s qdisc show dev perf-s >> "$d/qdisc.txt"
  printf 'PASS %s repeat=%s ' "$config" "$rep"; grep METRIC "$d/server.log"
 done
done
printf 'OUTPUT=%s\n' "$out"
