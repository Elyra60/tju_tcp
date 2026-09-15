"""将实际生成的课程图像拼成检查页，不改变任何原图或实验数据。"""
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from PIL import Image, ImageOps, ImageDraw

base = Path(__file__).resolve().parent / 'output' / 'verified'
names = ['CongestionWindowSize_VS_Time.png', 'AllWindowSize_VS_Time.png',
         'ReceiveWindowSize_VS_Time.png', 'SendWindowSize_VS_Time.png',
         'SeqNum_VS_Time.png', 'RTT.png', 'Throuput.png']
for case in ['no_loss_clean', 'rto', 'triple_ack', 'small_rwnd']:
    sheet = Image.new('RGB', (2000, 2400), 'white')
    draw = ImageDraw.Draw(sheet)
    for index, name in enumerate(names):
        # 仅按比例缩小已保存图像；标题注明来源，便于逐项视觉核验。
        picture = Image.open(base / case / 'test' / name).convert('RGB')
        picture = ImageOps.contain(picture, (1000, 565))
        x, y = (index % 2) * 1000, (index // 2) * 600
        draw.text((x + 15, y + 8), case + ' / ' + name, fill='black')
        sheet.paste(picture, (x + (1000 - picture.width) // 2, y + 30))
    sheet.save(base / case / 'course_figures_review.png')
