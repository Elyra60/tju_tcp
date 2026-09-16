"""Extract report sections and compare cited locations with the checked-in code."""
from pathlib import Path
import json
import re
from docx import Document
from docx.oxml.ns import qn

repo = Path(__file__).resolve().parents[1]
report = repo.parent.parent / '3525058909_陶鑫涛_课程报告_完整Reno最终复核版.docx'
doc = Document(report)

paragraphs = [p.text.strip() for p in doc.paragraphs if p.text.strip()]
sections = {}
targets = {'一、': 'one', '三、': 'three', '四、': 'four', '十、': 'ten'}
for prefix, key in targets.items():
    start = next(i for i, text in enumerate(paragraphs) if text.startswith(prefix))
    end = next((i for i in range(start + 1, len(paragraphs))
                if re.match(r'^[一二三四五六七八九十]+、', paragraphs[i])), len(paragraphs))
    sections[key] = paragraphs[start:end]

code_files = {str(path.relative_to(repo)).replace('\\', '/'): path.read_text(encoding='utf-8')
              for path in repo.glob('src/*.c')}
functions = {}
for name, text in code_files.items():
    for match in re.finditer(r'^(?:static\s+)?(?:void|int|char\s*\*|uint\d+_t|tju_tcp_t\s*\*|double)\s+(\w+)\s*\(', text, re.M):
        functions.setdefault(match.group(1), []).append({
            'file': name, 'line': text[:match.start()].count('\n') + 1
        })

cited_lines = []
for index, text in enumerate(paragraphs, 1):
    if any(marker in text for marker in ('第', '行', '位置', '实现位于', '实现位置')):
        if re.search(r'(?:src|inc)/[^，；。 ]+|第\s*\d+\s*行|[A-Za-z_]\w*\s*\([^)]*\)', text):
            cited_lines.append({'paragraph': index, 'text': text})

result = {
    'report': str(report),
    'section_text': sections,
    'functions': functions,
    'location_claims': cited_lines,
    'table_count': len(doc.tables),
    'paragraph_count': len(paragraphs),
}
out = repo / 'validation/report_consistency_audit.json'
out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
dump=[]
for i,e in enumerate(doc.element.body):
    if e.tag==qn('w:tbl'):
        rows=[' | '.join(''.join(t.text or '' for t in c.iter(qn('w:t'))) for c in row.findall(qn('w:tc'))) for row in e.findall(qn('w:tr'))]
        dump.append(f'B{i} TABLE\n'+'\n'.join(rows))
    else:
        value=''.join(t.text or '' for t in e.iter() if t.tag in [qn('w:t'),qn('m:t')])
        drawings=list(e.iter(qn('a:blip')))
        if value or drawings: dump.append(f'B{i} '+value+ (' IMAGE:'+','.join(n.get(qn('r:embed'),'') for n in drawings) if drawings else ''))
(repo/'validation/report_full_text.txt').write_text('\n'.join(dump),encoding='utf-8')
print('Extracted',len(dump),'blocks')
