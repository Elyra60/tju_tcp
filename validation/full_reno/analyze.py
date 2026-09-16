"""按SEND/ACK序号独立重建在途字节，逐次核算两种Reno的窗口公式与抓包。"""
from pathlib import Path
from collections import Counter
import re,json,csv,sys,struct,hashlib
plot = '--no-plots' not in sys.argv
if plot:
 import matplotlib
 matplotlib.use('Agg')
 import matplotlib.pyplot as plt
M=1375
root=Path(sys.argv[1]); summaries=[]
def pcap_counts(p):
 data=p.read_bytes(); endian='<' if data[:4]==b'\xd4\xc3\xb2\xa1' else '>'
 assert struct.unpack(endian+'I',data[20:24])[0]==1
 pos=24; counts=Counter()
 while pos<len(data):
  _,_,n,_=struct.unpack(endian+'IIII',data[pos:pos+16]); pos+=16; frame=data[pos:pos+n]; pos+=n
  if frame[12:14]!=b'\x08\x00':continue
  ip=frame[14:]; h=(ip[0]&15)*4
  if ip[9]!=17 or ip[12:16]!=bytes([172,17,0,2]):continue
  udp=ip[h:]; packet=udp[8:]
  if len(packet)>20: counts[(int.from_bytes(packet[4:8],'big'),len(packet)-20)]+=1
 return counts
for d in sorted(root.glob('mode_*')):
 if not d.is_dir():continue
 full=int(d.name.split('_')[1]); text=(d/'client.trace').read_text(); events=Counter(); sends=Counter()
 cw=4125; ss=22000; ca=0; recovery=False; base=None; high=0; acked=0; new=0; state=0
 records=[]; new_in_fr=0; begin=None; end=None; key=[]
 for line_no,line in enumerate(text.splitlines(),1):
  match=re.fullmatch(r'\[(\d+)\] \[(\w+)\] \[(.*)\]',line); assert match,(d,line_no)
  ts=int(match[1]); event=match[2]; f=dict(part.split(':',1) for part in match[3].split()); events[event]+=1
  if event=='SEND' and int(f['length'])>0:
   seq=int(f['seq']); n=int(f['length']); sends[(seq,n)]+=1
   if base is None:base=seq; begin=ts
   offset=(seq-base)&0xffffffff
   if offset>=high:
    assert offset==high
    high=offset+n
  if event=='ACK' and 'new' in f:
   new=int(f['new']); acked=(int(f['ack'])-base)&0xffffffff
   if acked==300000:end=ts
  if event in ('FLIGHT','RETRANSMIT'):
   assert int(f['flight'])==high-acked,(d,line_no,'flight')
   if event=='FLIGHT':
    assert high-acked<=min(int(f['cwnd']),int(f['peer'])),(d,line_no,'window')
    if recovery and full:new_in_fr+=1
  if event=='CC':
   reason=f['reason']; observed=int(f['cwnd']); flight=int(f['flight'])
   assert flight==high-acked,(d,line_no,'cc_flight')
   if reason in ('FAST_RETRANSMIT','RTO'):
    ss=max(flight//2,2*M); ca=0; recovery=reason=='FAST_RETRANSMIT'
    cw=(ss+(3*M if full else 0)) if recovery else M
   elif reason=='DUPACK_INFLATE':
    assert full and recovery; cw=min(cw+M,2147483647)
   elif reason in ('NEW_ACK','RECOVERY_ACK'):
    if recovery: cw=ss; ca=0; recovery=False
    elif cw<ss: cw+=min(new,M)
    else:
     ca+=new
     if ca>=cw:ca-=cw; cw+=M
   assert cw==observed and ss==int(f['ssthresh']),(d,line_no,reason,cw,observed)
   if reason!='HANDSHAKE':
    r=dict(line=line_no,time=(ts-begin)/1e6,reason=reason,cwnd=cw,ssthresh=ss,flight=flight,peer=int(f['peer']))
    records.append(r)
    if reason in ('FAST_RETRANSMIT','RTO','DUPACK_INFLATE','RECOVERY_ACK'):key.append(r)
 assert begin and end and high==acked==300000
 sent=(d/'sent.bin').read_bytes(); assert sent==(d/'received.bin').read_bytes() and len(sent)==300000
 wire=pcap_counts(d/'server.pcap'); expected=sends.copy()
 for seq,n in re.findall(r'INJECT_DROP packet=\d+ seq=(\d+) length=(\d+)',(d/'client.log').read_text()): expected[(int(seq),int(n))]-=1
 assert +expected==wire,(d,'pcap mismatch')
 s=dict(case=d.name,updates=len(records),new_in_recovery=new_in_fr,retransmit=events['RETRANSMIT'],rto=events['RTO'],seconds=(end-begin)/1e6,keys=key,pcap_data=sum(wire.values()),sha256=hashlib.sha256(sent).hexdigest())
 summaries.append(s)
 with (d/'window_updates.csv').open('w',newline='',encoding='utf-8-sig') as file:
  w=csv.DictWriter(file,fieldnames=records[0]); w.writeheader(); w.writerows(records)
 if not plot: continue
 plt.rcParams['font.sans-serif']=['Microsoft YaHei','SimHei','DejaVu Sans']
 fig,ax=plt.subplots(figsize=(7,3.6))
 for name,label in [('cwnd','拥塞窗口'),('ssthresh','慢启动阈值'),('flight','在途数据'),('peer','对端窗口')]:
  ax.step([r['time'] for r in records],[r[name] for r in records],where='post',label=label)
 ax.set_xlabel('首次数据发送后的时间（秒）'); ax.set_ylabel('字节'); ax.legend(fontsize=8); ax.grid(alpha=.2); fig.tight_layout(); fig.savefig(d/'windows.png',dpi=200); plt.close(fig)
assert len(summaries)==8
full_single=next(s for s in summaries if s['case']=='mode_1_single_loss')
assert full_single['new_in_recovery']>0 and full_single['rto']==0
(root/'summary.json').write_text(json.dumps(summaries,ensure_ascii=False,indent=2),encoding='utf-8')
# 放大单丢包恢复区间以便看到逐重复ACK膨胀；数值全部读取已核算CSV。
if not plot:
 print(json.dumps([{k:v for k,v in s.items() if k!='keys'} for s in summaries],indent=2))
 sys.exit(0)
fig,ax=plt.subplots(figsize=(7,3.6))
for mode,label,color in [(0,'基础模式','#777777'),(1,'完整Reno','#8A2D1F')]:
 with (root/f'mode_{mode}_single_loss/window_updates.csv').open(encoding='utf-8-sig') as f: rr=list(csv.DictReader(f))
 ax.step([float(r['time']) for r in rr],[int(r['cwnd']) for r in rr],where='post',label=label,color=color)
ax.set_xlim(.08,.25); ax.set_xlabel('首次数据发送后的时间（秒）'); ax.set_ylabel('cwnd（字节）'); ax.grid(alpha=.2); ax.legend(); fig.tight_layout(); fig.savefig(root/'recovery_comparison.png',dpi=200); plt.close(fig)
print(json.dumps([{k:v for k,v in s.items() if k!='keys'} for s in summaries],indent=2))
