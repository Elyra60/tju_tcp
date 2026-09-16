"""Audit score logs, all received bytes, profile source hashes and regression evidence."""
from pathlib import Path
import hashlib,json,re,zipfile
root=Path(__file__).resolve().parents[2]
base=root/'validation/rdt_performance/output'
course={'rdt':'rdt_20260916_124153','establish':'establish_20260916_125343','close':'close_20260916_125521'}
scores={}
for case,name in course.items():
    folder=base/name
    for file,expected in json.loads((folder/'sources.json').read_text()).items():
        assert hashlib.sha256((root/file).read_bytes()).hexdigest()==expected,(name,file)
    log=(folder/'driver.log').read_text()
    result=json.loads(re.findall(r'\{"scores":.*\}',log)[-1])['scores']
    assert list(result.values())==[100],result
    scores.update(result)
folder=base/course['rdt']
received=(folder/'rdt_recv_file.txt').read_bytes()
raw=(root/'test/rdt_send_file.txt').read_bytes().split(b'\0',1)[0]
assert len(received)==50000000
for i in range(5000):
    expected=(('START'+'#'*(5-len(str(i)))+str(i)+'#').encode()+raw+b'\0'*10000)[:10000]
    assert received[i*10000:(i+1)*10000]==expected,i
trace=(folder/'client.event.trace').read_text()
flights=[int(n) for n in re.findall(r'\[FLIGHT\].*?flight:(\d+)',trace)]
assert max(flights)<=44000 and len(flights)>30000
assert 'reason:RTO ' not in trace and 'reason:FAST_RETRANSMIT ' not in trace
assert 'RDT_ACK' in trace and 'RDT_TIMEOUT' in trace
reg=base/'regression_20260916_205843'
cases=['baseline','syn_loss','synack_loss','rto','multi_loss','zero_window','simultaneous','fin_loss','fin_ack_loss','final_ack_loss']
for case in cases+['reno_fin_loss','reno_fin_ack_loss','reno_final_ack_loss']:
    log=(reg/(case+'.log')).read_text()
    assert 'PASS integration '+case.removeprefix('reno_')+':' in log,case
    assert 'AddressSanitizer:' not in log and 'runtime error:' not in log
for p in ['unit_0.log','unit_1.log']:assert 'PASS 32-byte peer window' in (reg/p).read_text()
for line in (reg/'build.sha256').read_text().splitlines():
    expected,file=line.split(None,1)
    if file.startswith(('src/','inc/')) or file=='Makefile':
        assert hashlib.sha256((root/file).read_bytes()).hexdigest()==expected,file
report=root/'report_output/rdt_fixed'
a=json.loads((report/'consistency_audit.json').read_text(encoding='utf-8'))
for file,expected in a['sources'].items():assert hashlib.sha256((root/file).read_bytes()).hexdigest()==expected,file
document=next(report.glob('*.docx'));assert hashlib.sha256(document.read_bytes()).hexdigest()==a['sha256']
text=(root/'src/tju_tcp.c').read_text(encoding='utf-8').splitlines()
for location in a['locations']:assert re.search(r'\b'+location['symbol']+r'\s*\(',text[location['line']-1])
result={'scores':scores,'received_bytes':len(received),'verified_blocks':5000,'max_rdt_flight':max(flights),
        'rdt_integrations':10,'additional_reno_close_cases':3,'report_source_locations':len(a['locations']),
        'reno':json.loads((root/'validation/full_reno/output/rdt_fix_20260916_audit.json').read_text()),'status':'PASS'}
(base/'final_audit.json').write_text(json.dumps(result,indent=2))
files={}
for p in [*root.glob('src/*.c'),*root.glob('inc/*.h'),root/'Makefile']:
    files[str(p.relative_to(root))]=p
for p in report.glob('*'):
    if p.suffix in ('.docx','.json','.py','.ps1'):files['report/'+p.name]=p
for p in (root/'validation/rdt_performance').glob('*'):
    if p.is_file():files['validation/rdt_performance/'+p.name]=p
for dirname in [*course.values(),reg.name]:
    for p in (base/dirname).rglob('*'):
        if p.is_file() and p.suffix in ('.log','.trace','.json','.sha256'):
            files['evidence/'+dirname+'/'+p.name]=p
files['evidence/final_audit.json']=base/'final_audit.json'
files['validation/reno/check_reno.c']=root/'validation/reno/check_reno.c'
for kind in ['regression_20260916_204437','network_20260916_204158']:
    for p in (root/'validation/full_reno/output'/kind).rglob('*'):
        if p.is_file() and p.suffix in ('.log','.trace','.json','.sha256','.csv','.pcap','.bin'):
            files['evidence/'+kind+'/'+str(p.relative_to(root/'validation/full_reno/output'/kind))]=p
for p in (root/'validation/full_reno').glob('*'):
    if p.is_file() and p.suffix in ('.c','.sh','.py','.md'):files[str(p.relative_to(root))]=p
for p in (root/'validation/reno/network').glob('*'):
    if p.is_file() and p.suffix in ('.c','.sh','.py','.md'):files[str(p.relative_to(root))]=p
with zipfile.ZipFile(report/'RDT修复与回归证据.zip','w',zipfile.ZIP_DEFLATED) as z:
    for name,p in files.items():z.write(p,name)
    z.writestr('manifest.json',json.dumps({name:hashlib.sha256(p.read_bytes()).hexdigest() for name,p in files.items()},indent=2))
print(json.dumps(result,indent=2))
