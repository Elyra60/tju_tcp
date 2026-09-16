"""从真实接收计时和原始 trace 汇总样本，绘制均值与样本标准差。"""
from pathlib import Path
import sys,re,json,csv,hashlib,statistics
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
root=Path(sys.argv[1])
rows=[]
for d in sorted(root.iterdir()):
 if not d.is_dir() or not (d/'server.log').exists(): continue
 m=re.search(r'METRIC bytes=(\d+) elapsed=([\d.]+) mbps=([\d.]+)',(d/'server.log').read_text())
 assert m,d
 sent=(d/'sent.bin').read_bytes(); received=(d/'received.bin').read_bytes()
 assert sent==received and len(sent)==2000000,d
 text=(d/'client.trace').read_text(); factor,level,rep=d.name.split('_')
 rows.append(dict(run=d.name,factor=factor,level=int(level),repeat=int(rep[1:]),seconds=float(m[2]),mbps=float(m[3]),retransmissions=text.count('[RETRANSMIT]'),rto=text.count('[RTO]'),sha256=hashlib.sha256(received).hexdigest()))
assert len(rows)==18
with (root/'samples.csv').open('w',newline='',encoding='utf-8-sig') as f:
 w=csv.DictWriter(f,fieldnames=rows[0]); w.writeheader(); w.writerows(rows)
summary=[]
plt.rcParams['font.sans-serif']=['Microsoft YaHei','SimHei','DejaVu Sans']
for factor in ['delay','bandwidth']:
 groups=[]
 for level in sorted({r['level'] for r in rows if r['factor']==factor}):
  a=[r for r in rows if r['factor']==factor and r['level']==level]
  g=dict(factor=factor,level=level,n=len(a),mean=statistics.mean(r['mbps'] for r in a),sd=statistics.stdev(r['mbps'] for r in a),seconds=statistics.mean(r['seconds'] for r in a),retransmissions=sum(r['retransmissions'] for r in a),rto=sum(r['rto'] for r in a))
  summary.append(g); groups.append(g)
 fig,ax=plt.subplots(figsize=(7,3.6))
 ax.errorbar([g['level'] for g in groups],[g['mean'] for g in groups],yerr=[g['sd'] for g in groups],fmt='o-',color='#8c3021',capsize=5,label='均值 ± 样本标准差（n=3）')
 for r in rows:
  if r['factor']==factor: ax.scatter(r['level'],r['mbps'],s=15,color='gray',alpha=.7)
 ax.set_xlabel('单向时延（ms）' if factor=='delay' else '每方向带宽（Mbit/s）'); ax.set_ylabel('有效吞吐率（Mbit/s）'); ax.grid(alpha=.2); ax.legend(); fig.tight_layout(); fig.savefig(root/(factor+'.png'),dpi=220); plt.close(fig)
(root/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(summary,ensure_ascii=False,indent=2))
