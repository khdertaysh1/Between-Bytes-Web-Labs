"""HTTP verification of all thirteen original rooms, including browser policies."""
from http.cookiejar import CookieJar
import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request,build_opener,HTTPCookieProcessor
from app import make_server

class FoundationAudit(unittest.TestCase):
    def test_all_thirteen_foundation_room_contracts(self):
        server=make_server(0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        base='http://127.0.0.1:'+str(server.server_port);client=build_opener(HTTPCookieProcessor(CookieJar()))
        def request(path,form=None,headers=None):
            req=Request(base+path,data=urlencode(form).encode() if form is not None else None,headers=headers or {})
            try:r=client.open(req,timeout=5)
            except HTTPError as error:r=error
            data=r.read();r.close();self.assertEqual(int(r.headers['Content-Length']),len(data));return r.code,r.headers,json.loads(data) if 'application/json' in r.headers.get('Content-Type','') else data.decode()
        try:
            request('/rooms/session');seen=set()
            def post(kind,mode,**form):return request('/lab/'+kind+'/'+mode,form)
            with self.subTest(room='enumeration'):
                seen.add('enumeration');self.assertEqual(post('enumeration','vulnerable',email='alice@example.test')[0],200);self.assertEqual(post('enumeration','vulnerable',email='nobody@example.test')[0],404)
                self.assertEqual(post('enumeration','fixed',email='alice@example.test')[::2],post('enumeration','fixed',email='nobody@example.test')[::2]);self.assertEqual(post('enumeration','fixed',email='alice@example.test')[0],202)
            with self.subTest(room='rate-limit'):
                seen.add('rate-limit')
                for mode in ('vulnerable','fixed'):
                    path='/lab/rate-limit/'+mode
                    for _ in range(3):self.assertEqual(request(path,{'email':'alice@example.test'},{'X-Forwarded-For':'192.0.2.1'})[0],401)
                    self.assertEqual(request(path,{'email':'alice@example.test'},{'X-Forwarded-For':'192.0.2.1'})[0],429)
                    self.assertEqual(request(path,{'email':'alice@example.test'},{'X-Forwarded-For':'192.0.2.2'})[0],401 if mode=='vulnerable' else 429)
            with self.subTest(room='email-flood'):
                seen.add('email-flood')
                for mode in ('vulnerable','fixed'):
                    for _ in range(4):self.assertEqual(post('email-flood',mode,email='alice@example.test')[0],202)
                outbox=request('/outbox')[2]['messages'];self.assertEqual(sum(m['mode']=='vulnerable' for m in outbox),4);self.assertEqual(sum(m['mode']=='fixed' for m in outbox),1)
            for kind in ('idor','edge403','open-redirect','ssrf','api-keys','exposed-files'):
                with self.subTest(room=kind):
                    seen.add(kind)
                    normal,probe,deny={'idor':({'resource':'1001'},{'resource':'1002'},403),'edge403':({'layer':'edge'},{'layer':'origin'},403),'open-redirect':({'value':'/account'},{'value':'https://outside.example/'},400),'ssrf':({'value':'http://public.lab/welcome'},{'value':'http://internal.lab/config'},403),'api-keys':({'value':'/assets/checkout.js'},{'value':'/assets/checkout.js'},200),'exposed-files':({'value':'/public/readme.txt'},{'value':'/.env.backup'},404)}[kind]
                    self.assertEqual(post(kind,'vulnerable',**probe)[0],200);self.assertEqual(post(kind,'fixed',**probe)[0],deny);self.assertEqual(post(kind,'fixed',**normal)[0],403 if kind=='edge403' else 200)
                    if kind=='api-keys':self.assertNotIn('SERVER_API_SECRET',post(kind,'fixed',**probe)[2]['content']);self.assertIn('PUBLIC_KEY',post(kind,'fixed',**probe)[2]['content'])
            for kind in ('reflected-xss','dom-xss'):
                with self.subTest(room=kind):
                    seen.add(kind)
                    for mode in ('vulnerable','fixed'):
                        query={'token':'a'*32}
                        if kind=='reflected-xss':query['q']='<svg onload=alert(1)>'
                        status,headers,body=request('/preview/'+kind+'/'+mode+'?'+urlencode(query));self.assertEqual(status,200);self.assertIn('sandbox allow-scripts',headers['Content-Security-Policy']);self.assertNotIn('allow-same-origin',headers['Content-Security-Policy'])
                        if kind=='reflected-xss':self.assertIn('&lt;svg' if mode=='fixed' else '<svg',body)
            with self.subTest(room='cors'):
                seen.add('cors');self.assertEqual(request('/browser/cors/vulnerable')[0],401)
                session=request('/browser/session')[2];origin='http://127.0.0.1:12345'
                for mode in ('vulnerable','fixed'):
                    status,headers,body=request('/browser/cors/'+mode,headers={'Origin':origin});self.assertEqual(status,200);self.assertEqual(headers.get('Access-Control-Allow-Origin'),origin if mode=='vulnerable' else None)
            with self.subTest(room='csrf'):
                seen.add('csrf');expected=base;token=session['csrf_token']
                self.assertEqual(request('/browser/csrf/vulnerable',{'note':'cross-origin'},{'Origin':'http://127.0.0.1:12345'})[0],200)
                self.assertEqual(request('/browser/csrf/fixed',{'note':'blocked'},{'Origin':'http://127.0.0.1:12345'})[0],403)
                self.assertEqual(request('/browser/csrf/fixed',{'note':'blocked','csrf_token':'خطأ'},{'Origin':expected})[0],403)
                self.assertEqual(request('/browser/state')[2]['notes']['fixed']['revision'],0)
                self.assertEqual(request('/browser/csrf/fixed',{'note':'authorized','csrf_token':token},{'Origin':expected})[0],200)
                self.assertEqual(request('/browser/state')[2]['notes']['fixed']['revision'],1)
            self.assertEqual(len(seen),13)
        finally:server.shutdown();server.server_close();thread.join()
