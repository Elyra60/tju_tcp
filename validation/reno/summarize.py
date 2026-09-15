"""分析隔离实验的真实 Trace，不修改原始事件，不生成平台分数。"""
from collections import Counter
from pathlib import Path
import re

root = Path(__file__).resolve().parent / "output"
for mode in ("baseline", "syn_loss", "synack_loss", "rto", "multi_loss", "zero_window", "simultaneous"):
    events = Counter()
    reasons = Counter()
    zeros = 0
    deliveries = 0
    for line in (root / f"{mode}.trace").read_text().splitlines():
        match = re.match(r"\[\d+\] \[(\w+)\] \[(.*)\]", line)
        assert match, line
        event, info = match.groups()
        fields = dict(part.split(":", 1) for part in info.split())
        events[event] += 1
        if event == "CC":
            reasons[fields["reason"]] += 1
            if fields["reason"] in ("RTO", "FAST_RETRANSMIT"):
                assert int(fields["ssthresh"]) == max(int(fields["flight"]) // 2, 2750)
            if fields["reason"] == "RTO":
                assert int(fields["cwnd"]) == 1375 and fields["state"] == "0"
        if event == "FLIGHT":
            assert int(fields["flight"]) <= int(fields["cwnd"])
        if event == "PROBE":
            assert fields["peer"] == "0"
        if event == "PEER_WINDOW" and fields["size"] == "0":
            zeros += 1
        if event == "DELV":
            deliveries += int(fields["size"])
    assert deliveries == (204096 if mode == "simultaneous" else 200000)
    if mode == "rto":
        assert events["RTO"] > 0
    if mode == "multi_loss":
        assert reasons["FAST_RETRANSMIT"] > 0 and events["RETRANSMIT"] >= 2
    if mode == "zero_window":
        assert zeros > 0 and events["PROBE"] > 0
    print(f"{mode}: delivered={deliveries}, RTO={events['RTO']}, "
          f"fast_retransmit={reasons['FAST_RETRANSMIT']}, retransmit={events['RETRANSMIT']}, "
          f"zero_window_updates={zeros}, probes={events['PROBE']}")
print("PASS saved trace invariants")
