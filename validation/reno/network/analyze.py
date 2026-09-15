"""从原始 Trace 和 pcap 核算 Reno，并重跑课程绘图；不写原项目 test。"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import runpy
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--deps', type=Path, required=True)
args = parser.parse_args()
sys.path.insert(0, str(args.deps))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib import font_manager
from scapy.all import rdpcap, UDP, IP

BASE = Path(__file__).resolve().parent
REPO = BASE.parents[2]
OUT = BASE / 'output' / 'verified'
SMSS = 1375
font = Path('C:/Windows/Fonts/msyh.ttc')
if font.exists():
    font_manager.fontManager.addfont(str(font))
    plt.rcParams['font.family'] = font_manager.FontProperties(fname=str(font)).get_name()
plt.rcParams['axes.unicode_minus'] = False
plt.rcParams['font.size'] = 11

def read_events(path, allow_incomplete_tail=False):
    result = []
    lines = path.read_text(encoding='utf-8').splitlines()
    for number, line in enumerate(lines, 1):
        m = re.fullmatch(r'\[(\d+)\] \[(\w+)\] \[(.*)\]', line)
        if not m:
            if allow_incomplete_tail and number == len(lines):
                break
            raise ValueError(f'{path}:{number}: {line}')
        timestamp, event, fields = m.groups()
        result.append((int(timestamp), event, dict(x.split(':', 1) for x in fields.split()), number))
    return result

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def audit(path, directory, mode):
    existing_mode = mode == 'existing_user_trace'
    events = read_events(path, allow_incomplete_tail=existing_mode)
    incomplete_tail = len(events) != len(path.read_text(encoding='utf-8').splitlines())
    handshake = next(f for _, e, f, _ in events if e == 'CC' and f['reason'] == 'HANDSHAKE')
    origin = next(t for t, e, f, _ in events if e == 'SEND' and int(f['length']) > 0)
    base_seq = int(handshake['ack'])
    offset = lambda n: (int(n) - base_seq) & 0xffffffff
    cwnd, threshold = int(handshake['cwnd']), int(handshake['ssthresh'])
    una = highest = credit = 0
    wait_ack = False
    pending_ack = 0
    duplicates = 0
    counts = Counter()
    rows, points, flights, peer_points, losses = [], [], [], [], []
    receiver_limited = 0
    errors = []
    sends = Counter()
    peer = int(handshake['peer'])
    def check(condition, message, line):
        if not condition:
            errors.append(f'line {line}: {message}')
    for timestamp, event, f, line in events:
        time = (timestamp - origin) / 1e6
        counts[event] += 1
        if event == 'SEND' and int(f['length']) > 0:
            seq, size = offset(f['seq']), int(f['length'])
            sends[(int(f['seq']), size)] += 1
            if seq < 0x80000000:
                end = seq + size
                if end > highest:
                    check(highest - una + size <= min(cwnd, peer), 'new send exceeds min(cwnd,rwnd)', line)
                    highest = end
                flights.append((time, highest - una))
        elif event == 'PEER_WINDOW':
            peer = int(f['size'])
            peer_points.append((time, peer))
        elif event == 'ACK' and 'new' in f:
            new_una = offset(f['ack'])
            pending_ack = new_una - una
            check(pending_ack == int(f['new']), 'new ACK byte count differs from seq space', line)
            una = new_una
            duplicates = 0
            flights.append((time, highest - una))
        elif event == 'DUPACK':
            duplicates = int(f['count'])
        elif event == 'CC':
            receiver_limited += int(int(f['cwnd']) > int(f['peer']))
            reason = f['reason']
            before = cwnd
            equation = '握手初值，不计入数据 ACK 增长'
            if reason == 'NEW_ACK':
                if wait_ack:
                    cwnd = threshold
                    credit = 0
                    wait_ack = False
                    equation = f'恢复首次新 ACK：cwnd=ssthresh={threshold}'
                elif cwnd < threshold:
                    increase = min(pending_ack, SMSS)
                    cwnd += increase
                    equation = f'{before}+min({pending_ack},{SMSS})={cwnd}'
                else:
                    old_credit = credit
                    credit += pending_ack
                    if credit >= cwnd:
                        credit -= cwnd
                        cwnd += SMSS
                    equation = f'CA信用 {old_credit}+{pending_ack}；阈值 {before}；cwnd={cwnd}；余量={credit}'
            elif reason in ('RTO', 'FAST_RETRANSMIT'):
                independent_flight = highest - una
                threshold = max(independent_flight // 2, 2 * SMSS)
                cwnd = SMSS if reason == 'RTO' else threshold
                credit = 0
                wait_ack = reason == 'FAST_RETRANSMIT'
                if wait_ack:
                    check(duplicates == 3, 'fast retransmit without three duplicate ACKs', line)
                equation = f'ssthresh=max({independent_flight}//2,2750)={threshold}；cwnd={cwnd}'
                losses.append((time, reason, independent_flight, threshold, cwnd, line))
            expected_state = 2 if wait_ack else (0 if cwnd < threshold else 1)
            check(int(f['cwnd']) == cwnd, 'cwnd update mismatch', line)
            check(int(f['ssthresh']) == threshold, 'ssthresh mismatch', line)
            check(int(f['state']) == expected_state, 'congestion state mismatch', line)
            check(int(f['flight']) == highest - una, 'flight differs from SEND/ACK reconstruction', line)
            rows.append({'line': line, 'seconds': round(time, 6), 'reason': reason,
                         'ack_bytes': pending_ack if reason == 'NEW_ACK' else 0,
                         'before': before, 'cwnd': int(f['cwnd']), 'expected': cwnd,
                         'ssthresh': threshold, 'flight': highest - una, 'equation': equation})
            points.append((time, int(f['cwnd']), int(f['ssthresh']), int(f['state'])))
        elif event == 'FLIGHT':
            check(int(f['flight']) == highest - una, 'FLIGHT snapshot mismatch', line)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'window_updates.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')
    lines = ['# 逐次窗口核算', '', '|Trace 行|时间 s|原因|更新前 cwnd|实际 cwnd|期望 cwnd|ssthresh|FlightSize|核算|',
             '|---|---|---|---|---|---|---|---|---|']
    for r in rows:
        lines.append(f"|{r['line']}|{r['seconds']}|{r['reason']}|{r['before']}|{r['cwnd']}|{r['expected']}|{r['ssthresh']}|{r['flight']}|{r['equation']}|")
    (directory / 'window_updates.md').write_text('\n'.join(lines), encoding='utf-8')
    summary = dict(mode=mode, updates=len(rows), errors=errors, incomplete_tail=incomplete_tail,
                   receiver_limited_snapshots=receiver_limited, events=dict(counts), losses=losses,
                   max_cwnd=max(p[1] for p in points), max_flight=max(p[1] for p in flights),
                   min_peer=min(p[1] for p in peer_points), max_peer=max(p[1] for p in peer_points),
                   ca_updates=sum(1 for p in points if p[3] == 1), sha256=sha(path))
    return summary, (points, flights, peer_points, losses), sends, events

def pcap_check(directory, sends, events, summary):
    packet_records = []
    payload_counts = Counter()
    ack_windows = set()
    for packet in rdpcap(str(directory / 'server.pcap')):
        if IP not in packet or UDP not in packet:
            continue
        payload = bytes(packet[UDP].payload)
        if len(payload) < 20:
            continue
        seq = int.from_bytes(payload[4:8], 'big')
        ack = int.from_bytes(payload[8:12], 'big')
        size = int.from_bytes(payload[14:16], 'big') - 20
        window = int.from_bytes(payload[17:19], 'big')
        if packet[IP].src == '172.17.0.2' and size > 0:
            payload_counts[(seq, size)] += 1
            packet_records.append((float(packet.time), seq, size))
        elif packet[IP].src == '172.17.0.3':
            ack_windows.add((ack, window))
    expected_missing = 1 if summary['mode'] in ('rto', 'triple_ack') else 0
    missing = sends - payload_counts
    assert sum(missing.values()) == expected_missing, (summary['mode'], missing)
    assert not (payload_counts - sends)
    for _, event, fields, _ in events:
        if event == 'PEER_WINDOW':
            assert (int(fields['ack']), int(fields['size'])) in ack_windows
    summary['pcap_data_packets'] = sum(payload_counts.values())
    summary['injected_drop_packets'] = sum(missing.values())
    summary['pcap_sha256'] = sha(directory / 'server.pcap')
    assert sha(directory / 'sent.bin') == sha(directory / 'received.bin')
    summary['data_sha256'] = sha(directory / 'sent.bin')
    summary['data_bytes'] = (directory / 'sent.bin').stat().st_size
    if summary['mode'] == 'small_rwnd':
        assert summary['max_peer'] <= 5500 and summary['max_flight'] <= 5500 and summary['max_cwnd'] > 5500
    if summary['mode'] == 'no_loss_clean':
        assert not summary['losses'] and summary['ca_updates'] > 0
        assert summary['receiver_limited_snapshots'] == 0
    if summary['mode'] == 'rto':
        assert any(x[1] == 'RTO' for x in summary['losses'])
    if summary['mode'] == 'triple_ack':
        assert any(x[1] == 'FAST_RETRANSMIT' for x in summary['losses'])
    return packet_records

def step(ax, data, index, label, **kwargs):
    # 只取真实事件绘制阶梯，不按期望趋势补点或平滑。
    ax.step([max(0, p[0]) for p in data], [p[index] for p in data], where='post', label=label, **kwargs)

titles = {'no_loss_clean': '无丢包：慢启动进入拥塞避免', 'rto': '丢弃首个数据段：触发 RTO',
          'triple_ack': '丢弃第 12 段：三次重复 ACK', 'small_rwnd': '对端窗口上限 5500 字节'}

def plot_audit(directory, data, mode, axes=None):
    points, flights, peers, losses = data
    own = axes is None
    if own:
        fig, axes = plt.subplots(2, 1, figsize=(10, 7), sharex=True, constrained_layout=True)
    upper, lower = axes
    step(upper, points, 1, 'cwnd', color='#1769aa', linewidth=2)
    step(upper, points, 2, 'ssthresh', color='#de7d17', linestyle='--')
    transition = next((p for p in points if p[3] == 1), None)
    if transition:
        upper.scatter([max(0, transition[0])], [transition[1]], color='green', s=32, zorder=5, label='首次进入 CA')
    for time, reason, _, _, value, _ in losses:
        upper.scatter([time], [value], color='#c62828', s=36, zorder=6)
        upper.annotate(reason, (time, value), xytext=(7, 15), textcoords='offset points', fontsize=9)
    step(lower, peers, 1, '对端通告 rwnd', color='#de7d17', linestyle='--')
    step(lower, flights, 1, '在途数据（由 SEND/ACK 重建）', color='#17846b', linewidth=1.3)
    upper.set_title(titles.get(mode, mode))
    for ax in axes:
        ax.set_ylabel('字节')
        ax.grid(alpha=.2)
        ax.legend(loc='upper left', fontsize=8)
    lower.set_xlabel('距首个数据 SEND 的时间（秒）')
    lower.set_xlim(0, max(flights[-1][0], points[-1][0]) * 1.04)
    if own:
        fig.savefig(directory / 'test' / 'Reno核验.png', dpi=180)
        plt.close(fig)

def original_plots(directory, trace, pcap=None):
    # 原脚本按原样读取执行，仅将 savefig 的目标目录映射到隔离 test。
    saved = plt.savefig
    files = []
    def isolated_save(path, *a, **kw):
        target = directory / 'test' / Path(path).name
        files.append(str(target.name))
        return saved(target, *a, **kw)
    plt.savefig = isolated_save
    argv = sys.argv[:]
    try:
        sys.argv = ['gen_graph_win.py', str(directory / 'test' / 'server.event.trace'), '--sender', str(trace)]
        runpy.run_path(str(REPO / 'test' / 'gen_graph_win.py'), run_name='__main__')
        plt.close('all')
        if pcap:
            sys.argv = ['gen_graph_seq.py', str(pcap)]
            runpy.run_path(str(REPO / 'test' / 'gen_graph_seq.py'), run_name='__main__')
            plt.close('all')
    finally:
        plt.savefig = saved
        sys.argv = argv
    return files

def main():
    summaries, datasets = [], []
    for mode in titles:
        directory = OUT / mode
        summary, data, sends, events = audit(directory / 'test' / 'client.event.trace', directory, mode)
        assert not summary['errors'], summary
        pcap_check(directory, sends, events, summary)
        summary['course_figures'] = original_plots(directory, directory / 'test' / 'client.event.trace', directory / 'server.pcap')
        plot_audit(directory, data, mode)
        summaries.append(summary)
        datasets.append(data)
        print('AUDIT', json.dumps(summary, ensure_ascii=False))
    fig, axes = plt.subplots(4, 2, figsize=(15, 16), constrained_layout=True)
    for row, (mode, data) in enumerate(zip(titles, datasets)):
        plot_audit(OUT / mode, data, mode, axes[row])
    fig.suptitle('基础 Reno 受控实验：原始 Trace 与抓包交叉核验', fontsize=18)
    fig.savefig(OUT / '四组实验核验总图.png', dpi=150)
    plt.close(fig)
    # 用户已有 Trace 只读分析，其图像不覆盖。该日志来自用户此前运行，不虚构配置。
    existing_dir = OUT / 'existing_readonly'
    existing_dir.mkdir(exist_ok=True)
    existing, _, _, _ = audit(REPO / 'test' / 'client.event.trace', existing_dir, 'existing_user_trace')
    summaries.append(existing)
    (OUT / 'audit_summary.json').write_text(json.dumps(summaries, ensure_ascii=False, indent=2), encoding='utf-8')
    provenance = {str(path.relative_to(REPO)): sha(path) for path in (
        REPO / 'src' / 'tju_tcp.c', REPO / 'test' / 'gen_graph_win.py', REPO / 'test' / 'gen_graph_seq.py',
        BASE / 'endpoint.c', BASE / 'impairment.c', BASE / 'run.sh', BASE / 'analyze.py')}
    (OUT / 'source_hashes.json').write_text(json.dumps(provenance, indent=2), encoding='utf-8')
    print('EXISTING', json.dumps(existing, ensure_ascii=False))

if __name__ == '__main__':
    main()
