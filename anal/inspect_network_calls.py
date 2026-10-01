from pathlib import Path
import sys,json,struct
r=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(r/'anal/python_deps'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
j=next(x for x in json.loads((r/'anal/inventory.json').read_text()) if x['file']=='Tartaros.bin');b=(r/'Tartaros.bin').read_bytes();base=int(j['image_base'],16)
def off(addr):
 for n,vs,v,rs,p in j['sections']:
  if base+v<=addr<base+v+max(vs,rs):return p+addr-base-v
md=Cs(CS_ARCH_X86,CS_MODE_32)
pe=struct.unpack_from('<I',b,60)[0];desc=off(base+struct.unpack_from('<I',b,pe+24+104)[0]);targets={}
while any(b[desc:desc+20]):
 oft,_,_,nr,ft=struct.unpack_from('<IIIII',b,desc);t=off(base+(oft or ft));idx=0
 while True:
  value=struct.unpack_from('<I',b,t)[0];t+=4
  if not value:break
  name='#'+str(value&65535) if value&0x80000000 else b[off(base+value)+2:b.find(b'\0',off(base+value)+2)].decode()
  if name in ['#4','#9','#23','WSASocketA','WSASocketW','WSAConnect']:targets[base+ft+idx*4]=name
  idx+=1
 desc+=20
print('Targets',targets)
for addr,name in targets.items():
 needle=b'\xff\x15'+struct.pack('<I',addr);pos=0
 while True:
  pos=b.find(needle,pos)
  if pos<0:break
  print('CALL',name,hex(pos))
  for n,vs,v,rs,p in j['sections']:
   if p<=pos<p+rs:
    start=max(p,pos-45)
    for i in md.disasm(b[start:pos+15],base+v+start-p):print(hex(i.address),i.mnemonic,i.op_str)
  pos+=6
for start,end in [(0x405e20,0x405f38)]:
 for n,vs,v,rs,p in j['sections']:
  if p<=start<p+rs:
   for i in md.disasm(b[start:end],base+v+start-p):print(hex(i.address),i.mnemonic,i.op_str)
for n,vs,v,rs,p in j['sections']:
 if n!='.text':continue
 for pos in range(p,p+rs-5):
  if b[pos]==0xe8 and base+v+pos-p+5+struct.unpack_from('<i',b,pos+1)[0]==0x806ad0:
   print('CONNECT CALLER',hex(base+v+pos-p))
   for i in md.disasm(b[pos-35:pos+8],base+v+pos-p-35):print(hex(i.address),i.mnemonic,i.op_str)
