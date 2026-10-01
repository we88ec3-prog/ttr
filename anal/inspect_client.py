from pathlib import Path
import struct,re,json,zlib,hashlib
root=Path(__file__).resolve().parent.parent
out=root/'anal'
report=[]
for p in root.iterdir():
 if not p.is_file():continue
 b=p.read_bytes(); row={'file':p.name,'size':len(b),'sha256':hashlib.sha256(b).hexdigest(),'header':b[:32].hex()}
 if b[:2]==b'MZ':
  pe=struct.unpack_from('<I',b,60)[0]; machine,nsec,ts=struct.unpack_from('<HHI',b,pe+4); opt=pe+24; osz=struct.unpack_from('<H',b,pe+20)[0]
  row.update(machine=hex(machine),timestamp=ts,entry_rva=hex(struct.unpack_from('<I',b,opt+16)[0]),image_base=hex(struct.unpack_from('<I',b,opt+28)[0]))
  secs=[]
  for i in range(nsec):
   s=opt+osz+i*40; name=b[s:s+8].rstrip(b'\0').decode(errors='replace'); vs,va,rs,rp=struct.unpack_from('<IIII',b,s+8);secs.append((name,vs,va,rs,rp))
  row['sections']=secs
  def offset(rva):
   for name,vs,va,rs,rp in secs:
    if va<=rva<va+max(vs,rs):return rp+rva-va
   return rva
  def cstr(pos):return b[pos:b.find(b'\0',pos)].decode('ascii',errors='replace')
  imports=[]; irva=struct.unpack_from('<I',b,opt+104)[0]
  if irva:
   pos=offset(irva)
   while any(b[pos:pos+20]):
    oft,_,_,nr,ft=struct.unpack_from('<IIIII',b,pos); funcs=[]; t=offset(oft or ft)
    while True:
     v=struct.unpack_from('<I',b,t)[0]; t+=4
     if not v:break
     funcs.append('#'+str(v&65535) if v&0x80000000 else cstr(offset(v)+2))
    imports.append({'dll':cstr(offset(nr)),'functions':funcs});pos+=20
  row['imports']=imports
 report.append(row)
 strings=[]
 for m in re.finditer(rb'[\x20-\x7e]{5,}',b):strings.append((m.start(),m.group().decode()))
 for m in re.finditer(rb'(?:[\x20-\x7e]\x00){5,}',b):strings.append((m.start(),m.group().decode('utf-16le')))
 if p.suffix.lower() in ['.exe','.bin','.dll','.gms','.ini','.lnk','.lua','.stp','.flu']:
  (out/(p.name+'.strings.txt')).write_text('\n'.join(f'{pos:08x}\t{s}' for pos,s in sorted(strings)),encoding='utf-8')
 if p.name=='Integrity.xml':
  try:
   data=zlib.decompress(b[16:]);(out/'Integrity.decoded.xml').write_bytes(data);row['decoded_size']=len(data)
  except Exception as e:row['decode_error']=str(e)
(out/'inventory.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
print('Inventory and strings saved:',len(report),'files')
