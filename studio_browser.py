"""Real local two-origin practice, separate from the JSON policy exercises.

Synthetic researcher/victim sessions have different scoped HttpOnly cookies.
The second origin only serves bounded learner-authored pages. No remote network.
"""
from collections import deque
from http.cookies import SimpleCookie
import hmac
import html
import json
import re
import secrets
import time
from urllib.parse import parse_qs, urlsplit

CASE_IDS={'csrf-missing','csrf-empty','csrf-binding','csrf-origin','csrf-get','csrf-content-type'}

class BrowserStudio:
    def __init__(self):
        self.id=secrets.token_hex(16)
        self.actors={actor:{'cookie':secrets.token_hex(24),'token':secrets.token_hex(24),'notes':{m:{'note':'Original profile note','revision':0} for m in ('vulnerable','fixed')}} for actor in ('researcher','victim')}
        self.documents={};self.events=deque(maxlen=80);self.serial=0

    def authorized(self,actor,cookie):
        try:
            value=SimpleCookie(cookie or '').get('bb_studio_'+actor)
            return bool(value and hmac.compare_digest(value.value,self.actors[actor]['cookie']))
        except (ValueError,KeyError,TypeError):return False

    def cookie_headers(self):
        return ['bb_studio_'+actor+'='+data['cookie']+'; HttpOnly; SameSite=Lax; Path=/studio/target/'+self.id+'/'+actor+'/' for actor,data in self.actors.items()]

    def state(self):
        return {actor:{mode:dict(note) for mode,note in data['notes'].items()} for actor,data in self.actors.items()}

    def reset(self):
        # Invalidate old documents AND target URLs so delayed learner scripts
        # from an earlier round cannot write into the new account state.
        old_id=self.id
        self.__init__()
        return ['bb_studio_'+actor+'=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/studio/target/'+old_id+'/'+actor+'/' for actor in self.actors]

    def record(self,**data):
        self.serial+=1;data.update(id=self.serial,time_ms=round(time.time()*1000))
        self.events.append(data)

    def write(self,actor,mode,case,origin,expected,method,ctype,fields):
        note=fields.get('note',[''])[0];token=fields.get('csrf_token',[''])[0]
        if any(len(v)!=1 for v in fields.values()) or set(fields)-{'note','csrf_token'}:return 400,{'error':'Ambiguous or unsupported form fields'}
        if not isinstance(note,str) or not 1<=len(note)<=80:return 400,{'error':'Note must contain 1..80 characters'}
        correct=isinstance(token,str) and token.isascii() and hmac.compare_digest(token,self.actors[actor]['token'])
        if mode=='fixed':
            status=405 if method!='POST' else 415 if ctype!='application/x-www-form-urlencoded' else 403 if origin!=expected or not correct else 200
        else:
            normal=method=='POST' and ctype=='application/x-www-form-urlencoded' and correct
            exceptions={
                'csrf-missing':'csrf_token' not in fields and method=='POST' and ctype=='application/x-www-form-urlencoded',
                'csrf-empty':'csrf_token' in fields and token=='' and method=='POST' and ctype=='application/x-www-form-urlencoded',
                'csrf-binding':method=='POST' and ctype=='application/x-www-form-urlencoded' and any(token.isascii() and hmac.compare_digest(token,a['token']) for a in self.actors.values()),
                # The live example incorrectly ignores the port in origin trust.
                'csrf-origin':method=='POST' and ctype=='application/x-www-form-urlencoded' and origin.startswith('http://127.0.0.1'),
                'csrf-get':method=='GET',
                'csrf-content-type':method=='POST' and ctype=='text/plain',
            }
            status=200 if normal or exceptions[case] else 403
        current=self.actors[actor]['notes'][mode];before=dict(current)
        if status==200:current.update(note=note,revision=current['revision']+1)
        data={'account':actor,'note':current['note'],'revision':current['revision'],'applied':status==200}
        if status>=400:data['error']='Use POST' if status==405 else 'Unsupported content type' if status==415 else 'Origin or session-bound CSRF token rejected'
        self.record(action='profile',actor=actor,mode=mode,case=case,method=method,path='profile/'+mode,status=status,origin=origin,content_type=ctype,request={'note':note,'token_present':'csrf_token' in fields,'token_matches_session':correct},before=before,after=dict(current),response=data)
        return status,data

    def save_document(self,source):
        if not isinstance(source,str) or len(source.encode('utf-8'))>24000:raise ValueError('Page must be at most 24 KB')
        key=secrets.token_hex(16);self.documents[key]=source
        while len(self.documents)>12:self.documents.pop(next(iter(self.documents)))
        return key


def page_document(source, main, nonce, language):
    config=json.dumps({'main':main,'nonce':nonce}).replace('<','\\u003c')
    # This prelude reports actual runtime failures, never success/completion claims.
    prelude='''<script>const __bb='''+config+''';
function __report(kind,message){parent.postMessage({type:'bb-studio-console',nonce:__bb.nonce,kind,message:String(message).slice(0,500)},__bb.main)}
for(const kind of ['log','warn','error']){const old=console[kind].bind(console);console[kind]=(...args)=>{old(...args);__report(kind,args.map(x=>typeof x==='string'?x:JSON.stringify(x)).join(' '))}}
addEventListener('error',e=>__report('error',e.message));addEventListener('unhandledrejection',e=>__report('error',e.reason?.message||e.reason));
</script>'''
    return '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'+prelude+source


def target_document(studio, actor, mode, case, language):
    ar=language=='ar';data=studio.actors[actor];note=data['notes'][mode]
    root='/studio/target/'+studio.id+'/'+actor
    title=('حساب المستخدم المختبري' if actor=='victim' else 'حساب الباحث') if ar else ('Lab user account' if actor=='victim' else 'Researcher account')
    cfg=json.dumps({'path':root+'/profile/'+mode+'?case='+case,'state':root+'/state?mode='+mode}).replace('<','\\u003c')
    return '''<!doctype html><html lang="'''+('ar' if ar else 'en')+'''" dir="'''+('rtl' if ar else 'ltr')+'''"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/studio-target.css"><title>Northstar Profile</title><body><h2>'''+title+'''</h2><p>'''+html.escape(actor)+''' · '''+mode+'''</p><form><label>'''+('ملاحظة الحساب' if ar else 'Account note')+'''<input name="note" maxlength="80" value="'''+html.escape(note['note'],quote=True)+'''"></label><input type="hidden" name="csrf_token" value="'''+data['token']+'''"><button>'''+('حفظ الملاحظة' if ar else 'Save note')+'''</button></form><pre id="out" aria-live="polite"></pre><script type="application/json" id="config">'''+cfg+'''</script><script src="/studio-target.js"></script></body></html>'''

TARGET_JS="""'use strict';const cfg=JSON.parse(document.getElementById('config').textContent);const out=document.getElementById('out');document.querySelector('form').addEventListener('submit',async e=>{e.preventDefault();try{const r=await fetch(cfg.path,{method:'POST',body:new URLSearchParams(new FormData(e.target))});out.textContent='HTTP '+r.status+'\\n'+JSON.stringify(await r.json(),null,2);parent.postMessage({type:'bb-studio-target-update'},location.origin)}catch(err){out.textContent=err.message}});"""
TARGET_CSS="""body{font:14px/1.7 system-ui;background:#edf4ef;color:#203b2a;margin:0;padding:18px}h2{font-size:20px;margin:0}label{display:block}input{box-sizing:border-box;width:100%;padding:10px;border:1px solid #aac2b1;border-radius:7px;margin:8px 0}button{background:#214b35;color:white;border:0;border-radius:7px;padding:9px 16px;cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere;direction:ltr;font-size:12px} """

def handle(handler, context, parsed, method):
    """Return True if this route was handled. Called before the generic form parser."""
    if not parsed.path.startswith('/studio/'):return False
    reply=handler.reply
    if context is None:reply(401,{'error':'Start a classroom session'});return True
    if not hasattr(context,'studio'):context.studio=BrowserStudio()
    studio=context.studio;main='http://127.0.0.1:'+str(handler.server.server_port)
    side='http://127.0.0.1:'+str(handler.server.sidecar.server_port)
    try:
        q=parse_qs(parsed.query,max_num_fields=6,keep_blank_values=True)
        if any(len(v)!=1 for v in q.values()):raise ValueError('Duplicate query field')
        if parsed.path in {'/studio/session','/studio/state'}:
            if method!='GET':reply(405,{'error':'Use GET'},headers={'Allow':'GET'});return True
            body={'id':studio.id,'main':main,'author_origin':side,'accounts':studio.state(),'events':list(studio.events),'csrf_case_ids':sorted(CASE_IDS)}
            reply(200,body,headers={'Set-Cookie':studio.cookie_headers()} if parsed.path.endswith('session') else {})
            return True
        if parsed.path in {'/studio/document','/studio/reset'}:
            if method!='POST':reply(405,{'error':'Use POST'},headers={'Allow':'POST'});return True
            if handler.headers.get('Origin',main)!=main or handler.headers.get('Sec-Fetch-Site')=='cross-site':reply(403,{'error':'Workspace origin required'});return True
            if parsed.path=='/studio/reset':
                expired=studio.reset();reply(200,{'id':studio.id,'accounts':studio.state(),'reset':True},headers={'Set-Cookie':expired+studio.cookie_headers()});return True
            if handler.headers.get_content_type()!='application/json':reply(415,{'error':'Use application/json'});return True
            size=int(handler.headers.get('Content-Length','0'))
            if not 0<size<=50000:reply(413,{'error':'Page must be at most 24 KB'});return True
            def unique(pairs):
                result={}
                for key,value in pairs:
                    if key in result:raise ValueError('Duplicate JSON field')
                    result[key]=value
                return result
            data=json.loads(handler.rfile.read(size).decode('utf-8'),object_pairs_hook=unique)
            if not isinstance(data,dict) or set(data)!={'source'}:raise ValueError('Provide a source string')
            key=studio.save_document(data['source']);reply(201,{'url':side+'/studio/page/'+studio.id+'/'+key,'nonce':key});return True
        match=re.fullmatch(r'/studio/target/([a-f0-9]{32})/(researcher|victim)/(app|state|private/(?:vulnerable|fixed)|profile/(?:vulnerable|fixed))',parsed.path)
        if not match or match[1]!=studio.id:reply(404,{'error':'Unknown practice route'});return True
        sid,actor,action=match.groups();mode=q.get('mode',['vulnerable'])[0] if action in {'app','state'} else action.split('/')[-1]
        case=q.get('case',['csrf-missing'])[0]
        if mode not in {'vulnerable','fixed'} or case not in CASE_IDS:raise ValueError('Unknown practice case or mode')
        if not studio.authorized(actor,handler.headers.get('Cookie')):
            reply(401,{'error':'No practice account session; reopen the workspace'});return True
        if action in {'app','state'}:
            if method!='GET':reply(405,{'error':'Use GET'},headers={'Allow':'GET'});return True
            if action=='state':reply(200,{'account':actor,**studio.actors[actor]['notes'][mode]});return True
            document=target_document(studio,actor,mode,case,q.get('lang',['ar'])[0])
            csp="default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors "+main+"; base-uri 'none'"
            reply(200,document.encode(),'text/html; charset=utf-8',csp);return True
        origin=handler.headers.get('Origin','')
        if action.startswith('private/'):
            if method!='GET':reply(405,{'error':'Use GET'},headers={'Allow':'GET'});return True
            allow=bool(origin) and (mode=='vulnerable' or origin==main)
            headers={'Vary':'Origin'}
            if allow:headers.update({'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Credentials':'true'})
            body={'account':actor,'private':'DEMO_PRIVATE_CORS_DATA','note':studio.actors[actor]['notes'][mode]['note']}
            studio.record(action='private',actor=actor,mode=mode,method=method,path='private/'+mode,status=200,origin=origin,cors_granted=allow,response=body)
            reply(200,body,headers=headers);return True
        if method not in {'GET','POST'}:reply(405,{'error':'Use GET or POST'},headers={'Allow':'GET, POST'});return True
        ctype=handler.headers.get_content_type() if method=='POST' else 'application/x-www-form-urlencoded'
        if method=='GET':
            fields={k:v for k,v in q.items() if k not in {'case'}}
        else:
            size=int(handler.headers.get('Content-Length','0'))
            if not 0<size<=4096:reply(413,{'error':'Body must be 1..4096 bytes'});return True
            raw=handler.rfile.read(size).decode('utf-8')
            if ctype=='application/x-www-form-urlencoded':fields=parse_qs(raw,max_num_fields=3,keep_blank_values=True)
            elif ctype=='text/plain':
                fields={}
                for line in raw.splitlines():
                    if not line:continue
                    key,sep,value=line.partition('=')
                    if not sep or key in fields:raise ValueError('Malformed text/plain form')
                    fields[key]=[value]
            else:reply(415,{'error':'Use a supported form content type'});return True
        status,body=studio.write(actor,mode,case,origin,main,method,ctype,fields)
        reply(status,body,headers={'Allow':'POST'} if status==405 else {});return True
    except (ValueError,TypeError,UnicodeError,KeyError,RecursionError) as error:
        reply(400,{'error':str(error)[:180]});return True
