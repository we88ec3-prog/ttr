from pathlib import Path
import json,struct
r=Path(__file__).resolve().parent.parent
j=next(x for x in json.loads((r/'anal/inventory.json').read_text()) if x['file']=='Tartaros.bin');b=(r/'Tartaros.bin').read_bytes();base=int(j['image_base'],16)
def va(off):
 for n,vs,v,rs,p in j['sections']:
  if p<=off<p+rs:return base+v+off-p
for off in [0x7f95c0,0x7f95d0,0x7f95d8,0x7f95fc,0x7f9610,0x7f9650]:
 addr=va(off);needle=struct.pack('<I',addr);pos=0;refs=[]
 while True:
  pos=b.find(needle,pos)
  if pos<0:break
  refs.append((hex(pos),hex(va(pos))));pos+=1
 print(hex(off),hex(addr),refs)
import sys
sys.path.insert(0,str(r/'anal/python_deps'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
md=Cs(CS_ARCH_X86,CS_MODE_32)
def dis(start,end):
 print('\nRANGE',hex(start),hex(end))
 for i in md.disasm(b[start:end],va(start)):print(f'{i.address:08x} {i.bytes.hex():20} {i.mnemonic} {i.op_str}')
dis(0x3f800,0x3fdf0)
dis(0x2ed150,0x2ed480)
dis(0x3f280,0x3f550)
def offva(addr):
 for n,vs,v,rs,p in j['sections']:
  if base+v<=addr<base+v+max(vs,rs):return p+addr-base-v
for addr in [0xbfb00c,0xbf2375,0xc420d4]:
 o=offva(addr);print('STRING',hex(addr),repr(b[o:o+40]))
pe=struct.unpack_from('<I',b,60)[0];opt=pe+24;desc=offva(base+struct.unpack_from('<I',b,opt+104)[0])
while any(b[desc:desc+20]):
 oft,_,_,nr,ft=struct.unpack_from('<IIIII',b,desc);t=offva(base+(oft or ft));idx=0
 while True:
  v=struct.unpack_from('<I',b,t)[0];t+=4
  if not v:break
  name='#'+str(v&65535) if v&0x80000000 else b[offva(base+v)+2:b.find(b'\0',offva(base+v)+2)].decode()
  if base+ft+4*idx in [0xbd218c,0xbd22bc,0xbd22c4,0xbd22c8]:print('IMPORT',hex(base+ft+4*idx),name)
  idx+=1
 desc+=20
dis(0x3f000,0x3f120)
dis(0x3f300,0x3f800)
