"""Run the untouched course driver and preserve logs/files before another run."""
from pathlib import Path
import datetime
import hashlib
import json
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
case = sys.argv[1] if len(sys.argv) > 1 else 'rdt'
assert case in ('rdt', 'establish', 'close')
out = root / 'validation/rdt_performance/output' / (case + '_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
out.mkdir(parents=True)
sources = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
           for p in [*root.glob('src/*.c'), *root.glob('inc/*.h'), root/'Makefile']}
(out/'sources.json').write_text(json.dumps(sources, indent=2))
with (out/'driver.log').open('w') as log:
    command = ['timeout', '-k', '5', '300', './test', case]
    child = subprocess.Popen(command, cwd=root/'test',
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    for line in child.stdout:
        log.write(line)
        log.flush()
        print(line, end='', flush=True)
    code = child.wait()
assert code == 0, code
for pattern in ('*.trace', 'rdt_*.log', 'client.log', 'server.log'):
    for path in (root/'test').glob(pattern):
        shutil.copy2(path, out/path.name)
if case == 'rdt':
    received = (root/'test/rdt_recv_file.txt').read_bytes()
    raw = (root/'test/rdt_send_file.txt').read_bytes().split(b'\0', 1)[0]
    assert len(received) == 50000000
    for i in range(5000):
        prefix = ('START' + '#'*(5-len(str(i))) + str(i) + '#').encode()
        expected = (prefix + raw + b'\0'*10000)[:10000]
        assert received[i*10000:(i+1)*10000] == expected, i
    shutil.copy2(root/'test/rdt_recv_file.txt', out/'rdt_recv_file.txt')
    result = {'bytes': len(received), 'sha256': hashlib.sha256(received).hexdigest(),
              'blocks_verified': 5000, 'score_100': '"reliable_data_transfer":100.00' in (out/'driver.log').read_text()}
    (out/'verification.json').write_text(json.dumps(result, indent=2))
    assert result['score_100'], result
print('OUTPUT=' + str(out), flush=True)
