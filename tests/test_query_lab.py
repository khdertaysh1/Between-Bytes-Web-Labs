"""Independent query-cardinality and real GET contracts; only loopback HTTP."""
from copy import deepcopy
from http.cookiejar import CookieJar
from urllib.request import Request,build_opener,HTTPCookieProcessor
from urllib.error import HTTPError
import json
import threading
import unittest
from academy import Academy
from app import make_server


class QueryPolicies(unittest.TestCase):
    def test_order_and_decoded_duplicates_change_only_weak_lookup(self):
        for raw in ('owner=alice&owner=bob','owner=alice&%6fwner=bob','%6Fwner=alice&owner=carol'):
            a=Academy();weak=a.run('code-hpp','vulnerable',{'query_string':raw})
            self.assertTrue(weak['impact']);self.assertEqual(weak['data']['validation_owner'],'alice')
            self.assertNotEqual(weak['data']['downstream_owner'],'alice')
            fixed=a.run('code-hpp','fixed',{'query_string':raw})
            self.assertEqual(fixed['status'],400);self.assertEqual(fixed['data']['records'],[])
            self.assertIsNone(fixed['data']['downstream_owner'])

    def test_reverse_order_and_single_foreign_owner_denied_in_both_variants(self):
        for raw in ('owner=bob','owner=bob&owner=alice','owner=carol'):
            for mode in ('fixed','vulnerable'):
                r=Academy().run('code-hpp',mode,{'query_string':raw})
                self.assertEqual(r['status'],400 if mode=='fixed' and '&' in raw else 403);self.assertEqual(r['data']['records'],[])
                self.assertFalse(r['impact'])

    def test_repeated_tags_are_a_valid_collection_not_a_vulnerability(self):
        r=Academy().run('code-hpp','fixed',{'query_string':'owner=alice&tag=one&tag=two'})
        self.assertTrue(r['legitimate']);self.assertEqual(r['status'],200)
        self.assertEqual(r['data']['parameters'],[['owner','alice'],['tag','one'],['tag','two']])
        self.assertEqual(r['data']['records'][0]['owner'],'alice')

    def test_singleton_contract_rejects_identical_owner_duplicates(self):
        r=Academy().run('code-hpp','fixed',{'query_string':'owner=alice&owner=alice'})
        self.assertEqual(r['status'],400);self.assertEqual(r['error_code'],'ambiguous_owner')

    def test_bad_encodings_types_fields_and_bounds_rejected(self):
        for raw in ('owner','owner=','owner=alice&x=1','owner[]=alice','owner=%FF','owner=%zz','owner=ali%00ce','owner=alice#tag=x','owner=alice x','owner=alice&'+'tag=x&'*9, 'x'*1025,[],True):
            with self.subTest(raw=raw),self.assertRaises(ValueError):Academy().run('code-hpp','fixed',{'query_string':raw})

    def test_rejection_preserves_state_and_completion_needs_matching_manual_evidence(self):
        a=Academy();normal={'query_string':'owner=alice'};attack={'query_string':'owner=alice&owner=bob'}
        self.assertIsNone(a.run('code-hpp','fixed',normal)['flag'])
        before=deepcopy(a.states[('code-hpp','fixed')]);a.run('code-hpp','vulnerable',attack)
        self.assertIsNone(a.run('code-hpp','fixed',{'query_string':'owner=alice&owner=carol'})['flag'])
        self.assertTrue(a.run('code-hpp','fixed',attack)['flag'])
        self.assertEqual(before,a.states[('code-hpp','fixed')])
        a.reset('code-hpp');self.assertNotIn('code-hpp',a.flags)


class QueryHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=make_server(0);cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.base='http://127.0.0.1:'+str(cls.server.server_port)
    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.thread.join()
    def setUp(self):
        self.client=build_opener(HTTPCookieProcessor(CookieJar()));self.client.open(self.base+'/rooms/session').read()
    def call(self,path,client=None,headers=None,data=None):
        req=Request(self.base+path,headers=headers or {},data=data)
        try:r=(client or self.client).open(req)
        except HTTPError as e:r=e
        with r:return r.code,json.load(r),r.headers
    def test_real_get_retains_duplicates_and_reports_rejections_with_request_id(self):
        code,body,h=self.call('/academy/hpp/vulnerable?owner=alice&owner=bob')
        self.assertEqual(code,200);self.assertEqual(body['data']['records'][0]['owner'],'bob')
        self.assertEqual(body['data']['parameters'],[['owner','alice'],['owner','bob']])
        self.assertEqual(body['request_id'],h['X-Request-ID']);self.assertEqual(h['Cache-Control'],'no-store')
        code,body,h=self.call('/academy/hpp/fixed?owner=alice&owner=bob')
        self.assertEqual(code,400);self.assertEqual(body['error']['code'],'ambiguous_owner')
        self.assertEqual(body['data']['records'],[]);self.assertIn('X-Request-ID',h)
        self.assertEqual(self.call('/academy/hpp/fixed?owner=bob')[0],403)
        self.assertEqual(self.call('/academy/hpp/fixed?owner=alice')[0],200)
    def test_auth_origin_method_and_malformed_input_guards(self):
        other=build_opener();self.assertEqual(self.call('/academy/hpp/fixed?owner=alice',client=other)[0],401)
        self.assertEqual(self.call('/academy/hpp/fixed?owner=alice',headers={'Origin':'https://outside.invalid'})[0],403)
        self.assertEqual(self.call('/academy/hpp/fixed?owner=alice',headers={'Sec-Fetch-Site':'cross-site'})[0],403)
        code,_,h=self.call('/academy/hpp/fixed?owner=alice',data=b'body')
        self.assertEqual(code,405);self.assertEqual(h['Allow'],'GET')
        for query in ('owner=%FF','owner=%','owner=alice&other=1'):
            self.assertEqual(self.call('/academy/hpp/fixed?'+query)[0],400)
    def test_raw_get_and_json_adapter_use_same_decoded_contract(self):
        code,body,_=self.call('/academy/hpp/vulnerable?owner=alice&%6fwner=bob')
        raw=json.dumps({'query_string':'owner=alice&%6fwner=bob'}).encode()
        c,adapter,_=self.call('/academy/api/code/code-hpp/vulnerable',headers={'Content-Type':'application/json'},data=raw)
        self.assertEqual((code,c),(200,200));self.assertEqual(body['data'],adapter['data'])
