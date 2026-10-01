from pathlib import Path
import hashlib,json
r=Path(__file__).resolve().parent.parent
src=r/'Tartaros.bin';dst=r/'Tartaros.local.exe';b=bytearray(src.read_bytes())
expected=next(x['sha256'] for x in json.loads((r/'anal/inventory.json').read_text()) if x['file']=='Tartaros.bin')
assert hashlib.sha256(b).hexdigest()==expected,'Original binary differs from analyzed version'
patches=[(0x3fae5,'f4000000','01000000'),(0x3faea,'23','00'),(0x3faec,'86','00'),(0x3faee,'a1','7f'),(0x3fb2d,'04','01'),(0x3fb2f,'da000000','00000000'),(0x3fb34,'c6','00'),(0x3fb36,'92','7f')]
for off,old,new in patches:
 assert b[off:off+len(bytes.fromhex(old))]==bytes.fromhex(old),f'Unexpected bytes at {off:x}'
 b[off:off+len(bytes.fromhex(old))]=bytes.fromhex(new)
if dst.exists():assert dst.read_bytes()==b,'Existing local binary differs; refusing overwrite'
else:dst.write_bytes(b)
ini=r/'serverip.ini';content=b'[Login]\r\nIP=127.0.0.1\r\n'
if ini.exists():assert ini.read_bytes()==content,'Existing configuration differs; refusing overwrite'
else:ini.write_bytes(content)
meta={'source_sha256':expected,'patched_sha256':hashlib.sha256(b).hexdigest(),'patches':[{'file_offset':hex(o),'old':a,'new':c} for o,a,c in patches]}
(r/'anal/localhost-patch.json').write_text(json.dumps(meta,indent=2),encoding='utf-8')
print('Created/verified:',dst,ini); print(json.dumps(meta,indent=2))

