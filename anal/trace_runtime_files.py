from pathlib import Path
import sys,os,time,json,datetime,shutil
r=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(r/'anal/python_deps'))
import frida
out=r/'anal/runtime-file-trace.jsonl'
for name in ['log.txt','Tartaros.log']:
 p=r/name
 if p.exists():shutil.copy2(p,r/'anal'/('before-trace-'+name))
js=r'''
let seq=0;
function record(o){o.seq=++seq;o.ms=Date.now();send(o);}
function read(p,wide){try{return wide?p.readUtf16String():p.readCString();}catch(e){return '<unreadable>';}}
const k=Process.getModuleByName('kernel32.dll');
for(const name of ['CreateFileW','CreateFileA','GetFileAttributesW','GetFileAttributesA']){
 const addr=k.findExportByName(name);if(!addr)continue;
 Interceptor.attach(addr,{
  onEnter(args){this.path=read(args[0],name.endsWith('W'));},
  onLeave(ret){const fail=ret.toInt32()===-1;record({api:name,path:this.path,result:ret.toString(),failed:fail,error:fail?this.lastError:0});}
 });
}
const n=Process.getModuleByName('ntdll.dll');
for(const name of ['NtCreateFile','NtOpenFile','NtQueryAttributesFile','NtQueryFullAttributesFile']){
 const addr=n.findExportByName(name);if(!addr)continue;
 Interceptor.attach(addr,{
  onEnter(args){
   const oa=args[name.startsWith('NtQuery')?0:2];
   try{
    const us=oa.add(Process.pointerSize===4?8:16).readPointer();
    const buf=us.add(Process.pointerSize===4?4:8).readPointer();
    this.path=buf.readUtf16String(us.readU16()/2);
    this.caller=this.returnAddress.toString();
   }catch(e){this.path='<unreadable>';}
  },
  onLeave(ret){const status=ret.toUInt32();record({api:name,path:this.path,status:'0x'+status.toString(16),failed:ret.toInt32()<0,caller:this.caller});}
 });
}
record({event:'hooks-installed',arch:Process.arch});
'''
f=out.open('w',encoding='utf-8')
def message(m,data):
 if m['type']=='send':f.write(json.dumps(m['payload'],ensure_ascii=False)+'\n');f.flush()
 else:print('Agent message:',m)
os.chdir(r)
device=frida.get_local_device();pid=None;session=None
try:
 pid=device.spawn([str(r/'Tartaros.local.exe')],cwd=str(r));print('Spawned trace PID',pid,flush=True)
 session=device.attach(pid);script=session.create_script(js);script.on('message',message);script.load();device.resume(pid)
 for _ in range(40):
  time.sleep(.5)
  try:device.get_process(pid)
  except frida.ProcessNotFoundError:break
finally:
 if pid:
  try:device.kill(pid)
  except frida.ProcessNotFoundError:pass
 if session:
  try:session.detach()
  except frida.InvalidOperationError:pass
 f.close()
rows=[json.loads(s) for s in out.read_text(encoding='utf-8').splitlines()]
fail=[x for x in rows if x.get('failed')]
print('Total events',len(rows),'failures',len(fail))
print('First failures:',json.dumps(fail[:20],ensure_ascii=False,indent=2))
