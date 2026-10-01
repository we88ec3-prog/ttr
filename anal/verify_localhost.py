from pathlib import Path
import sys,json,struct,ctypes
r=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(r/'anal/python_deps'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
md=Cs(CS_ARCH_X86,CS_MODE_32);a=(r/'Tartaros.bin').read_bytes();b=(r/'Tartaros.local.exe').read_bytes()
assert len(a)==len(b)
for start,end in [(0x3fae4,0x3faf3),(0x3fb2c,0x3fb3b)]:
 instructions=list(md.disasm(b[start:end],start+0x400c00))
 vals={}
 for i in instructions:print(hex(i.address),i.mnemonic,i.op_str)
 pushes=[int(i.op_str,0) for i in instructions if i.mnemonic=='push']
 moves={i.op_str.split(',')[0]:int(i.op_str.split(',')[1],0) for i in instructions if i.mnemonic=='mov'}
 ip=[pushes[1],moves['dl'],moves['cl'],pushes[0]]
 assert ip==[0,127,0,1] # stack first push is fourth octet; second push is third
 formatted=f"{moves['dl']}.{moves['cl']}.{pushes[1]}.{pushes[0]}"
 assert formatted=='127.0.0.1';print('Verified IP:',formatted)
buf=ctypes.create_string_buffer(260)
f=ctypes.windll.kernel32.GetPrivateProfileStringA
f(b'Login',b'IP',b'0.0.0.0',buf,260,str(r/'serverip.ini').encode('ascii'))
assert buf.value==b'127.0.0.1';print('Windows INI API verified:',buf.value.decode())
print('Changed byte positions:',sum(x!=y for x,y in zip(a,b)))

