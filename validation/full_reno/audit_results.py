"""验证最终测试证据与当前生产源码一致，不依赖绘图或外部包。"""
from pathlib import Path
import hashlib
import json

repo=Path(__file__).resolve().parents[2]
out=repo/'validation/full_reno/output'
runs=['regression_20260915_232959','network_20260915_233439']
hashes=0
for name in runs:
    for line in (out/name/'build_sources.sha256').read_text().splitlines():
        expected,p=line.split(None,1)
        if p.startswith(('src/','inc/')):
            assert hashlib.sha256((repo/p).read_bytes()).hexdigest()==expected,p
            hashes+=1
reg=out/runs[0]
cases=['baseline','syn_loss','synack_loss','rto','multi_loss','zero_window','simultaneous']
for mode in [0,1]:
    folder=reg/f'mode_{mode}'
    for case in cases:
        assert 'PASS integration '+case+':' in (folder/f'{case}.log').read_text()
    for name in ['unit.log','sanitized.log']:
        log=(folder/name).read_text()
        assert log.count('PASS ')==3 and 'AddressSanitizer:' not in log and 'runtime error:' not in log
log=(reg/'recovery.log').read_text()
assert log.count('PASS ')==4 and 'AddressSanitizer:' not in log and 'runtime error:' not in log
assert (reg/'course_compile.log').read_text().count('PASS compile ')==5
summary=json.loads((out/runs[1]/'summary.json').read_text())
assert len(summary)==8
for s in summary:
    assert (out/runs[1]/s['case']/'result.log').read_text().startswith('PASS ')
    case=s['case'].split('_',2)[2]
    assert s['rto']==(1 if case=='rto' else 0)
    assert s['retransmit']==(1 if case in ('rto','single_loss') else 0)
full=next(s for s in summary if s['case']=='mode_1_single_loss')
basic=next(s for s in summary if s['case']=='mode_0_single_loss')
assert full['new_in_recovery']>0 and basic['new_in_recovery']==0
result={'production_source_hashes_checked':hashes,'regression':runs[0],'network':runs[1],
        'integration_passed':14,'sanitized_unit_modes_passed':2,
        'sanitized_recovery_assertion_groups_passed':4,'course_programs_compiled':5,
        'network_cases_passed':8,'cc_snapshots_checked':sum(s['updates'] for s in summary),
        'single_loss_new_segments_in_recovery':full['new_in_recovery'],
        'single_loss_rto':full['rto'],'status':'PASS'}
(out/'final_audit.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result,indent=2))
