"""Check current source, historical evidence, and prepare portable test scripts."""
from pathlib import Path
from collections import Counter
import hashlib,json,re,subprocess
repo=Path(__file__).resolve().parents[1]
out=repo/'report_output/unified';out.mkdir(parents=True,exist_ok=True)
result={'commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),'source':{},'traces':{}}
for p in list(repo.glob('src/*.c'))+list(repo.glob('inc/*.h')):
 result['source'][str(p.relative_to(repo))]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'lines':len(p.read_text().splitlines())}
for name in ['client','server']:
 p=repo/'test'/f'{name}.event.trace';text=p.read_text();events=Counter(re.findall(r'\] \[(\w+)\] \[',text))
 ranges={}
 for kind in ['RWND','SWND','CWND']:
  sizes=[int(x) for x in re.findall(r'\['+kind+r'\] \[[^\n]*?size:(\d+)',text)]
  if sizes:ranges[kind]=[min(sizes),max(sizes)]
 result['traces'][name]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'events':dict(events),'ranges':ranges,'lines':len(text.splitlines())}
raw=(repo/'test/rdt_send_file.txt').read_bytes();received=(repo/'test/rdt_recv_file.txt').read_bytes()
assert len(raw)==9990 and len(received)==50000000
for i in range(5000):
 prefix=('START'+'#'*(5-len(str(i)))+str(i)+'#').encode()
 # C sprintf creates a ten-byte prefix; strcat appends source up to its NUL.
 payload=prefix+raw.split(b'\0',1)[0]
 expected=(payload+b'\0'*10000)[:10000]
 assert received[i*10000:(i+1)*10000]==expected,i
result['rdt']={'bytes':len(received),'sha256':hashlib.sha256(received).hexdigest(),'blocks':5000,'match':True}
result['performance_cases']=[]
perf=repo/'validation/performance/output/20260915_200849'
for d in sorted(perf.iterdir()):
 if d.is_dir() and (d/'sent.bin').exists():
  assert (d/'sent.bin').read_bytes()==(d/'received.bin').read_bytes()
  result['performance_cases'].append(d.name)
assert len(result['performance_cases'])==18
(out/'current_evidence.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
# Mechanical newline normalization only. WSL bash cannot execute CRLF scripts.
for name in ['validation/full_reno/run_regression.sh','validation/full_reno/run_network.sh']:
 p=repo/name;p.write_bytes(p.read_bytes().replace(b'\r\n',b'\n'))
print(json.dumps(result,ensure_ascii=False,indent=2))
