from pathlib import Path
import xml.etree.ElementTree as ET,hashlib,json,re
root=Path(__file__).resolve().parent.parent
out=root/'anal'
tree=ET.fromstring((out/'Integrity.decoded.xml').read_bytes().decode('euc-kr'));rows=[]
def walk(node,base=Path()):
 for el in node:
  if el.tag=='FOLDER':walk(el,base/el.get('name',''))
  elif el.tag=='FILE':
   rel=base/el.attrib['name'];p=root/rel;state='missing';actual=None
   if p.exists():
    actual=hashlib.md5(p.read_bytes()).hexdigest();state='match' if actual.lower()==el.get('Checksum','').lower() and p.stat().st_size==int(el.get('FileLength',0)) else 'mismatch'
   rows.append({'path':rel.as_posix(),'expected_bytes':int(el.get('FileLength',0)),'status':state,'expected_md5':el.get('Checksum'),'actual_md5':actual})
walk(tree)
(out/'manifest-audit.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')
lines=['# 資源完整性比對','',f'版本：`{tree.attrib}`','',f'清單共 {len(rows)} 檔；符合 {sum(r["status"]=="match" for r in rows)}；不符 {sum(r["status"]=="mismatch" for r in rows)}；缺少 {sum(r["status"]=="missing" for r in rows)}。','',f'清單預期大小總計 {sum(r["expected_bytes"] for r in rows):,} bytes。','', '| 路徑 | 預期 bytes | 狀態 |','|---|---:|---|']
lines += [f'| `{r["path"]}` | {r["expected_bytes"]} | {r["status"]} |' for r in rows]
(out/'02-resource-audit.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
for p in root.glob('*.stp'):
 b=p.read_bytes(); inverted=bytes(x^255 for x in b)
 ss=[(m.start(),m.group().decode()) for m in re.finditer(rb'[\x20-\x7e]{5,}',inverted)]
 (out/(p.name+'.xor-ff.strings.txt')).write_text('\n'.join(f'{pos:08x}\t{s}' for pos,s in ss),encoding='utf-8')
print(lines[:7]);print('Missing examples:',[r['path'] for r in rows if r['status']=='missing'][:25]); print('Mismatches:',[r['path'] for r in rows if r['status']=='mismatch'])

