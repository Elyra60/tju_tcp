"""Read-only evidence validation, including line-ending changes after checkout."""
from pathlib import Path
import hashlib, json, subprocess, re
repo=Path(__file__).resolve().parents[1]
def sha(b):return hashlib.sha256(b).hexdigest()
checks=[]
for name in ['regression_20260915_232959','network_20260915_233439']:
 for line in (repo/'validation/full_reno/output'/name/'build_sources.sha256').read_text().splitlines():
  expected,p=line.split(None,1)
  if not p.startswith(('src/','inc/')):continue
  raw=(repo/p).read_bytes()
  git=subprocess.check_output(['git','show','HEAD:'+p],cwd=repo)
  variants={'worktree_raw':raw,'worktree_lf':raw.replace(b'\r\n',b'\n'),'git_blob':git,'git_lf':git.replace(b'\r\n',b'\n')}
  matched=[k for k,v in variants.items() if sha(v)==expected]
  checks.append({'run':name,'file':p,'matches':matched,'expected':expected,'raw':sha(raw)})
  if not matched:
   # Older snapshots contain a mixture of CRLF and LF introduced by local patches.
   for rev in ['b0a678f','8895125']:
    data=subprocess.check_output(['git','show',rev+':'+p],cwd=repo)
    if data.replace(b'\r\n',b'\n')==raw.replace(b'\r\n',b'\n'):
     checks[-1].setdefault('same_normalized_source_at',[]).append(rev)
print(json.dumps(checks,indent=2))
