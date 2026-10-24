"""HTTP/state and isolation contracts for authored browser practice."""
from copy import deepcopy
from http.cookiejar import CookieJar
import json
import threading
from unittest import TestCase
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import build_opener, HTTPCookieProcessor, Request
from app import make_server

class BrowserStudioHTTP(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=make_server(0);cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start();cls.base='http://127.0.0.1:'+str(cls.server.server_port)
    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.thread.join()
    def setUp(self):
        self.jar=CookieJar();self.client=build_opener(HTTPCookieProcessor(self.jar));self.client.open(self.base+'/rooms/session').read();_,self.session,_=self.call('/studio/session')
    def call(self,path,body=None,headers=None,method=None,client=None):
        data=body.encode() if isinstance(body,str) else body
        req=Request(self.base+path,data=data,headers=headers or {},method=method)
        try:r=(client or self.client).open(req,timeout=3)
        except HTTPError as e:r=e
        raw=r.read();return r.code,json.loads(raw),r.headers
    def studio(self):
        cookie='bb_room='+next(c.value for c in self.jar if c.name=='bb_room')
        return self.server.room_sessions.resolve(cookie).studio
    def path(self,actor='victim',mode='fixed',case='csrf-missing'):
        return '/studio/target/'+self.session['id']+'/'+actor+'/profile/'+mode+'?case='+case

    def test_sessions_have_independent_scoped_httponly_cookies_and_invalid_cookie_denied(self):
        cookies=[c for c in self.jar if c.name.startswith('bb_studio_')]
        self.assertEqual(len(cookies),2);self.assertNotEqual(cookies[0].value,cookies[1].value)
        for c in cookies:self.assertIn('/studio/target/'+self.session['id']+'/',c.path);self.assertIn('HttpOnly',c._rest)
        code,_,_=self.call(self.path(),urlencode({'note':'test'}),{'Content-Type':'application/x-www-form-urlencoded'},client=build_opener())
        self.assertEqual(code,401)

    def test_real_csrf_write_rejects_missing_empty_wrong_session_token_and_keeps_state(self):
        st=self.studio();before=deepcopy(st.state())
        for fields in ({'note':'x'},{'note':'x','csrf_token':''},{'note':'x','csrf_token':st.actors['researcher']['token']}):
            status,data,_=self.call(self.path(),urlencode(fields),{'Content-Type':'application/x-www-form-urlencoded','Origin':self.base})
            self.assertEqual(status,403);self.assertFalse(data['applied']);self.assertEqual(before,st.state())
        fields={'note':'Valid note','csrf_token':st.actors['victim']['token']}
        self.assertEqual(self.call(self.path(),urlencode(fields),{'Content-Type':'application/x-www-form-urlencoded','Origin':self.base})[0],200)
        self.assertEqual(st.state()['victim']['fixed']['note'],'Valid note');self.assertEqual(st.state()['researcher']['fixed']['note'],'Original profile note')
        event=st.events[-1];self.assertNotIn(st.actors['victim']['token'],json.dumps(event))

    def test_get_and_plain_fixed_rejections_do_not_mutate(self):
        st=self.studio();before=deepcopy(st.state())
        self.assertEqual(self.call(self.path(case='csrf-get')+'&note=GET-update')[0],405)
        self.assertEqual(self.call(self.path(case='csrf-content-type'),'note=plain',{'Content-Type':'text/plain','Origin':self.base})[0],415)
        self.assertEqual(st.state(),before)

    def test_cors_body_status_and_grant_are_independent(self):
        for mode in ('vulnerable','fixed'):
            path='/studio/target/'+self.session['id']+'/victim/private/'+mode
            status,data,headers=self.call(path,headers={'Origin':'http://127.0.0.1:'+str(self.server.sidecar.server_port)})
            self.assertEqual(status,200);self.assertEqual(data['private'],'DEMO_PRIVATE_CORS_DATA')
            self.assertEqual(headers.get('Access-Control-Allow-Credentials'), 'true' if mode=='vulnerable' else None)
            self.assertEqual(headers.get('Vary'),'Origin')

    def test_documents_are_bounded_isolated_csp_restricted_and_reset_expires_them(self):
        status,doc,_=self.call('/studio/document',json.dumps({'source':'<h1>My page</h1>'}),{'Content-Type':'application/json','Origin':self.base})
        self.assertEqual(status,201);r=self.client.open(doc['url']);body=r.read().decode();self.assertIn('<h1>My page</h1>',body);self.assertIn("default-src 'none'",r.headers['Content-Security-Policy']);self.assertIn("frame-src 'none'",r.headers['Content-Security-Policy'])
        with self.assertRaises(HTTPError):build_opener().open(doc['url'])
        self.assertEqual(self.call('/studio/document',json.dumps({'source':'x'*24577}),{'Content-Type':'application/json'})[0],400)
        self.assertEqual(self.call('/studio/document',json.dumps({'source':'test'}),{'Content-Type':'application/json','Origin':'http://untrusted.invalid'})[0],403)
        old_path=self.path(mode='vulnerable')
        _,new_session,_=self.call('/studio/reset','{}',{'Content-Type':'application/json','Origin':self.base})
        self.assertNotEqual(new_session['id'],self.session['id'])
        self.assertEqual(self.call(old_path,urlencode({'note':'delayed old request'}),{'Content-Type':'application/x-www-form-urlencoded'})[0],404)
        self.assertEqual(self.studio().state()['victim']['vulnerable']['revision'],0)
        with self.assertRaises(HTTPError):self.client.open(doc['url'])

    def test_duplicate_fields_malformed_unicode_and_unknown_routes_do_not_break_handler(self):
        headers={'Content-Type':'application/x-www-form-urlencoded','Origin':self.base}
        for body in ('note=a&note=b','note=a&csrf_token=x&csrf_token=y','note=a&other=1'):
            self.assertEqual(self.call(self.path(mode='vulnerable'),body,headers)[0],400)
        self.assertEqual(self.call('/studio/document',b'{"source":"\\ud800"}',{'Content-Type':'application/json'})[0],400)
        self.assertEqual(self.call('/studio/document','{"source":"one","source":"two"}',{'Content-Type':'application/json'})[0],400)
        self.assertEqual(self.call('/studio/not-found')[0],404)
        self.assertEqual(self.call('/studio/state',headers={'Host':'untrusted.invalid'})[0],403)
        self.assertEqual(self.call('/studio/session',body='{}',headers={'Content-Type':'application/json'})[0],405)
