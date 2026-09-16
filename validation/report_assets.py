from pathlib import Path
from docx import Document
from PIL import Image,ImageDraw
from io import BytesIO
root=Path(__file__).resolve().parents[1]
out=root/'report_output/unified/assets';out.mkdir(parents=True,exist_ok=True)
doc=Document(root.parent.parent/'3525058909_陶鑫涛_课程报告_完整Reno最终复核版.docx')
items=[]
for key,rel in doc.part.rels.items():
 if '/image' in rel.reltype:
  p=out/(key+Path(rel.target_ref).suffix);p.write_bytes(rel.target_part.blob)
  try:
   im=Image.open(BytesIO(rel.target_part.blob)).convert('RGB');items.append((key,im))
  except Exception:pass
for start in range(0,len(items),6):
 sheet=Image.new('RGB',(1800,1320),'#eeeeee');draw=ImageDraw.Draw(sheet)
 for j,(key,im) in enumerate(items[start:start+6]):
  im.thumbnail((580,610)); x=j%3*600+10;y=j//3*660+35
  sheet.paste(im,(x,y));draw.text((x,y-25),key,fill='black')
 sheet.save(out/f'sheet-{start}.png')
print('Extracted',len(items),'assets')
