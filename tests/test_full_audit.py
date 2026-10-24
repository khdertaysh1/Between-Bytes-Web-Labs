"""Independent HTTP contract matrix for all 50 academy cases and edge inputs.

Expected status codes are explicit test contracts, never copied from the model's
status field. Browser execution is separately exercised by the Chromium suites.
"""
from copy import deepcopy
from http.cookiejar import CookieJar
import json
from pathlib import Path
import sys
import threading
import unittest
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request,build_opener,HTTPCookieProcessor
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app import make_server
from academy import CATALOG

PAYMENT={'price':422,'quantity':422,'discount':422,'coupon-reuse':409,'currency':409,'rounding':422,'total':422,'shipping':422,'tax':422,'status':409,'webhook':401,'binding':409,'replay':200,'gift':409,'refund':409,'trial':409}

class FullHTTPAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=make_server(0);cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start();cls.base='http://127.0.0.1:'+str(cls.server.server_port)
    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.thread.join()
    def setUp(self):
        self.jar=CookieJar();self.client=build_opener(HTTPCookieProcessor(self.jar));self.call('/rooms/session')
    def call(self,path,data=None,method=None,headers=None,raw=None):
        body=raw if raw is not None else json.dumps(data).encode() if data is not None else None
        request=Request(self.base+path,data=body,method=method,headers=headers or ({'Content-Type':'application/json'} if body is not None else {}))
        try:r=self.client.open(request,timeout=5)
        except HTTPError as error:r=error
        blob=r.read();r.close();self.assertEqual(int(r.headers['Content-Length']),len(blob));self.assertEqual(r.headers.get('Cache-Control'),'no-store')
        return r.code,json.loads(blob),r.headers
    def academy(self):
        cookie='bb_room='+next(c.value for c in self.jar if c.name=='bb_room')
        return self.server.room_sessions.resolve(cookie).academy
    def endpoint(self,case,mode):return '/academy/api/'+case['group']+'/'+case['id']+'/'+mode
    def run_case(self,case,mode,data):
        status,body,headers=self.call(self.endpoint(case,mode),data)
        self.assertIn('application/json',headers['Content-Type']);self.assertEqual(headers['X-Request-ID'],body['request_id'])
        self.assertNotIn('impact',body);self.assertNotIn('checks',body);self.assertNotIn('flag',body)
        return status,body,headers

    def test_all_cases_real_http_status_body_and_state_contracts(self):
        seen=set()
        for case in CATALOG:
            id=case['id'];group=case['group']
            with self.subTest(case=id):
                seen.add(id)
                if group=='rate':self.run_case(case,'vulnerable',case['normal'])
                weak,weak_body,_=self.run_case(case,'vulnerable',case['attack'])
                normal,normal_body,_=self.run_case(case,'fixed',case['normal'])
                before=deepcopy(self.academy().states[(id,'fixed')])
                fixed,fixed_body,fixed_headers=self.run_case(case,'fixed',case['attack'])
                if group=='payment':expected=(200,200,PAYMENT[id[4:]])
                elif group=='access':expected=(200,200,403)
                elif group=='rate':expected=(429 if case['attack']['attempts']>3 else 401,429 if case['normal']['attempts']>3 else 401,429)
                elif group=='xss':expected=(201,201,201) if id=='xss-stored' else (200,200,200)
                elif group in {'ssrf','redirect'}:expected=(200,200,403)
                elif group=='csrf':expected=(200,200,405 if id=='csrf-get' else 415 if id=='csrf-content-type' else 403)
                elif group=='cors':expected=(200,200,200)
                else:expected=(200,200,{'code-sqli':200,'code-nosql':422,'code-template':200,'code-redirect':403,'code-ssrf':403}[id])
                self.assertEqual((weak,normal,fixed),expected)
                if fixed>=400:
                    self.assertIn('error',fixed_body);self.assertIsInstance(fixed_body['error']['code'],str)
                    after=self.academy().states[(id,'fixed')]
                    if group=='rate' and id=='rate-window':self.assertEqual(before['times'],after['times'],'blocked attempt consumed the rolling budget')
                    else:self.assertEqual(before,after,'rejected request mutated state')
                if group=='access':self.assertNotIn('data',fixed_body)
                if group=='rate':
                    self.assertEqual(fixed_headers['Retry-After'],'60');self.assertEqual(fixed_headers['RateLimit-Remaining'],'0')
                    ops=fixed_body['attempts']['operations'];self.assertTrue(all(op['status']==429 for op in ops))
                if id=='code-sqli':self.assertEqual(fixed_body['data']['notes'],[]);self.assertIn(['bob','Bob private note'],weak_body['data']['notes'])
                if id=='code-template':self.assertEqual(fixed_body['data'],'{{7*7}}');self.assertEqual(weak_body['data'],'49')
                if id=='pay-replay':self.assertTrue(fixed_body['data']['idempotent_replay']);self.assertEqual(before,self.academy().states[(id,'fixed')])
                if group=='xss':
                    self.assertIn('preview_url',fixed_body['data']);url=fixed_body['data']['preview_url']
                    r=self.client.open(self.base+url);document=r.read();r.close();self.assertEqual(r.code,200);self.assertIn("sandbox allow-scripts",r.headers['Content-Security-Policy']);self.assertNotIn('allow-same-origin',r.headers['Content-Security-Policy'])
        self.assertEqual(len(seen),72)

    def test_missing_unknown_and_malformed_inputs_for_every_case(self):
        for case in CATALOG:
            path=self.endpoint(case,'fixed')
            for bad in ({},{'unknown_field':1},[],None):
                with self.subTest(case=case['id'],input=bad):
                    status,body,_=self.call(path,raw=json.dumps(bad).encode(),headers={'Content-Type':'application/json'})
                    self.assertEqual(status,400);self.assertIn('error',body)
        for raw in (b'{',b'{"query":"a","query":"b"}',b'{"query":NaN}',b'{"query":Infinity}',b'{"query":"\\ud800"}'):
            status,body,_=self.call('/academy/api/code/code-sqli/fixed',raw=raw,headers={'Content-Type':'application/json'})
            self.assertEqual(status,400);self.assertIn('error',body)
        status,body,_=self.call('/academy/api/code/code-sqli/fixed',raw=b'x'*4097,headers={'Content-Type':'application/json'})
        self.assertEqual(status,413);self.assertEqual(body['error']['code'],'body_too_large')

    def test_credentials_queries_missing_resources_and_reference_types(self):
        for mode in ('vulnerable','fixed'):
            status,body,_=self.call('/academy/api/code/code-nosql/'+mode,{'password':'wrong'})
            self.assertEqual(status,401);self.assertEqual(body['error']['code'],'invalid_credentials')
        status,body,_=self.call('/academy/api/code/code-sqli/vulnerable',{'query':"'"})
        self.assertEqual(status,400);self.assertEqual(body['error']['code'],'invalid_query')
        cases=[('acl-read',{'object':'missing'}),('acl-write',{'object':'missing','note':'new'}),('acl-delete',{'object':'missing'}),('acl-batch',{'objects':['a-1','missing']}),('acl-export',{'job':'file-alice'}),('acl-download',{'file':'export-alice'})]
        for id,data in cases:
            for mode in ('vulnerable','fixed'):
                with self.subTest(case=id,mode=mode):self.assertEqual(self.call('/academy/api/access/'+id+'/'+mode,data)[0],404)
        status,body,_=self.call('/academy/api/access/acl-download/fixed',{'file':'file-alice'})
        self.assertEqual(status,200);self.assertIn('INV-2026-1041,alice,12900,USD',body['data']['document']['content'])

    def test_unusual_preview_destinations_and_tokens_do_not_break_handler(self):
        for value in ('http://[','[','https://example.invalid:bad/','\u2028hello'):
            status,body,_=self.call('/academy/api/xss/xss-url/fixed',{'value':value})
            self.assertEqual(status,200)
            r=self.client.open(self.base+body['data']['preview_url']);self.assertEqual(r.code,200);self.assertIn(b'#blocked',r.read());r.close()
        status,body,_=self.call('/academy/api/payment/pay-webhook/fixed',{'event':'settled','signature':'توقيع خاطئ'})
        self.assertEqual(status,401)
        self.assertEqual(self.call('/academy/api/payment/pay-webhook/fixed',{'event':'unknown','signature':'invalid'})[0],400)
        self.assertEqual(self.call('/academy/api/redirect/code-redirect/fixed',{'next':'/welcome\r\nLocation: other'})[0],400)
        _,body,_=self.call('/academy/api/redirect/code-redirect/vulnerable',{'next':'/unknown'})
        self.assertFalse(body['data']['external'])

    def test_wrong_methods_and_session_isolation(self):
        status,body,headers=self.call('/academy/api/payment/pay-price/fixed')
        self.assertEqual(status,405);self.assertEqual(headers['Allow'],'POST')
        status,body,headers=self.call('/academy/catalog',{},method='POST')
        self.assertEqual(status,405);self.assertEqual(headers['Allow'],'GET')
        self.assertEqual(self.call('/academy/api/code/unknown/fixed')[0],404)
        self.assertEqual(self.call('/academy/resource?case=pay-price&mode=fixed',{},method='POST')[0],405)
        self.assertEqual(self.call('/academy/resource?case=pay-price&mode=fixed&mode=vulnerable')[0],400)
        other=build_opener();request=Request(self.base+'/academy/api/payment/pay-price/fixed',data=b'{"price":10000}',headers={'Content-Type':'application/json'})
        with self.assertRaises(HTTPError) as error:other.open(request)
        self.assertEqual(error.exception.code,401);error.exception.close()

if __name__=='__main__':unittest.main()
