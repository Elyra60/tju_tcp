"""第七部分五项独立实验的核算与图像，复用逐事件核算器。"""
import importlib.util, json, sys
from pathlib import Path
base = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('audit_core', base / 'analyze.py')
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
root = base / 'output' / 'report7_20260915_153313'
cases = {'slow_start':'R7-01 慢启动', 'congestion_avoidance':'R7-02 拥塞避免',
         'rto':'R7-03 RTO 超时', 'triple_ack':'R7-04 三次重复 ACK', 'small_rwnd':'R7-05 rwnd 约束'}
summaries=[]
for mode,title in cases.items():
    folder=root/mode
    summary,data,sends,events=core.audit(folder/'test/client.event.trace',folder,mode)
    assert not summary['errors'], summary
    core.pcap_check(folder,sends,events,summary)
    if mode=='slow_start':
        assert not summary['losses'] and summary['ca_updates']==0
    if mode=='congestion_avoidance':
        assert not summary['losses'] and summary['ca_updates']>0
        assert summary['receiver_limited_snapshots']==0
    core.titles[mode]=title
    core.plot_audit(folder,data,mode)
    summary['figures']=core.original_plots(folder,folder/'test/client.event.trace',folder/'server.pcap')
    summary['case_id']=title.split()[0]
    summary['trace']=str((folder/'test/client.event.trace').relative_to(root))
    summaries.append(summary)
(root/'audit_summary.json').write_text(json.dumps(summaries,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(summaries,ensure_ascii=False))
