"""Two loopback origins for real browser CSRF/CORS training with synthetic sessions."""
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
import hmac
import json
import re
import secrets
import threading
from urllib.parse import parse_qs, urlsplit


def initialize(labs):
    labs.browser_session=secrets.token_hex(16)
    labs.csrf_token=secrets.token_hex(16)
    labs.browser_notes={'vulnerable':{'note':'original','revision':0},'fixed':{'note':'original','revision':0}}


def authenticated(labs,cookie):
    try:
        cookies=SimpleCookie(cookie or '')
        return hmac.compare_digest(cookies.get('bb_lab_session').value if cookies.get('bb_lab_session') else '',labs.browser_session)
    except Exception:
        return False


def csrf_write(labs,mode,origin,expected,cookie,value,token):
    if mode not in {'vulnerable','fixed'}:
        return 404,{'error':'Unknown mode'}
    if not authenticated(labs,cookie):
        return 401,{'error':'No synthetic session'}
    if not isinstance(value,str) or not 1<=len(value)<=80:
        return 400,{'error':'Note must have 1..80 characters'}
    if mode=='fixed' and (origin!=expected or not hmac.compare_digest(token,labs.csrf_token)):
        return 403,{'error':'Origin or CSRF token rejected'}
    state=labs.browser_notes[mode]
    state.update(note=value,revision=state['revision']+1)
    return 200,{'changed':True,'note':value,'synthetic_account':'alice'}


def attack_document(main_origin,action,mode,value,nonce):
    data=json.dumps({'main':main_origin,'action':action,'mode':mode,'value':value,'nonce':nonce}).replace('<','\\u003c')
    return '''<!doctype html><html><meta charset="utf-8"><title>Local second origin</title><body style="background:#eff4e8;color:#172519;font:14px Arial,sans-serif;padding:12px" dir="rtl"><p>صفحة تدريب محلية ثانية — نتيجة الطلب تظهر في دفتر الدليل.</p><script>
const cfg='''+data+''';
(async()=>{
 let result={type:'bb-browser',nonce:cfg.nonce,action:cfg.action,mode:cfg.mode};
 try{
  if(cfg.action==='csrf'){
   await fetch(cfg.main+'/browser/csrf/'+cfg.mode,{method:'POST',mode:'no-cors',credentials:'include',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({note:cfg.value})});
   result.sent=true; result.response_visibility='opaque';
  }else{
   const response=await fetch(cfg.main+'/browser/cors/'+cfg.mode,{credentials:'include'});
   result.readable=true;result.status=response.status;result.body=await response.json();
  }
 }catch(error){result.readable=false;result.error='Browser did not expose the response';}
 parent.postMessage(result,cfg.main);
})();
</script></body></html>'''


class Sidecar(HTTPServer):
    def __init__(self,main):
        main_origin='http://127.0.0.1:'+str(main.server_port)
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):
                pass
            def do_GET(self):
                if self.headers.get('Host')!='127.0.0.1:'+str(self.server.server_port):
                    self.send_error(403);return
                try:
                    url=urlsplit(self.path);q=parse_qs(url.query,max_num_fields=5)
                    action=q.get('action',[''])[0];mode=q.get('mode',[''])[0];value=q.get('value',[''])[0];nonce=q.get('nonce',[''])[0]
                    if url.path!='/attack' or action not in {'csrf','cors'} or mode not in {'vulnerable','fixed'} or len(value)>80 or not re.fullmatch('[a-f0-9]{32}',nonce):
                        raise ValueError('Invalid input')
                    body=attack_document(main_origin,action,mode,value,nonce).encode()
                except ValueError:
                    self.send_error(400);return
                self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Content-Length',str(len(body)))
                self.send_header('Cache-Control','no-store')
                self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src "+main_origin+"; frame-ancestors "+main_origin+"; base-uri 'none'; form-action 'none'")
                self.end_headers();self.wfile.write(body)
        super().__init__(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.serve_forever,daemon=True)
        self.thread.start()
    def close(self):
        self.shutdown();self.server_close();self.thread.join(timeout=2)


class LabServer(HTTPServer):
    def server_close(self):
        if getattr(self,'sidecar',None):
            self.sidecar.close();self.sidecar=None
        super().server_close()
