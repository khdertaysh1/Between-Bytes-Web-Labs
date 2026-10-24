"""Security invariants across local advanced cases, including negative controls."""
import json
from pathlib import Path
import sys
import threading
import unittest
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, build_opener, HTTPCookieProcessor
from http.cookiejar import CookieJar
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from academy import Academy, CATALOG, preview_document
from app import make_server


class ScenarioTests(unittest.TestCase):
    def test_every_nonbrowser_case_has_impact_protection_and_usable_control(self):
        for case in CATALOG:
            if case['group']=='xss':continue
            with self.subTest(case=case['id']):
                a=Academy();id=case['id']
                control=a.run(id,'fixed',case['normal'])
                self.assertTrue(control['legitimate'],control)
                if case['group']=='rate':a.run(id,'vulnerable',case['normal'])
                weak=a.run(id,'vulnerable',case['attack'])
                self.assertTrue(weak['impact'],weak)
                fixed=a.run(id,'fixed',case['attack'])
                self.assertTrue(fixed['protected'],fixed)
                self.assertFalse(fixed['impact'],fixed)
                self.assertTrue(fixed['flag'],fixed)
                a.reset(id)
                self.assertNotIn(id,a.flags)
                self.assertEqual(len(a.evidence[id]),0)

    def test_no_flag_for_only_weak_or_only_fixed(self):
        a=Academy()
        self.assertIsNone(a.run('pay-price','vulnerable',{'price':1})['flag'])
        self.assertIsNone(a.run('pay-total','fixed',{'total':0})['flag'])
        self.assertIsNone(a.run('pay-total','fixed',{'total':10000})['flag'])

    def test_fixed_evidence_must_match_weak_input(self):
        a=Academy()
        a.run('pay-price','vulnerable',{'price':1})
        a.run('pay-price','fixed',{'price':2})
        self.assertIsNone(a.run('pay-price','fixed',{'price':10000})['flag'])
        self.assertTrue(a.run('pay-price','fixed',{'price':1})['flag'])

    def test_cross_tenant_batch_and_mass_assignment_are_denied(self):
        a=Academy()
        for id,data in [('acl-batch',{'objects':['a-1','b-1']}),('acl-tenant',{'tenant':'south','object':'c-1'}),('acl-mass',{'display_name':'Alice','is_admin':True})]:
            with self.subTest(case=id):
                r=a.run(id,'fixed',data)
                self.assertEqual(r['status'],403)
                self.assertIsNone(r['data'])
        self.assertEqual(a.run('acl-read','fixed',{'object':'a-1'})['data']['owner'],'alice')

    def test_refunds_and_idempotency_cannot_create_excess_balance(self):
        a=Academy()
        for _ in range(8):a.run('pay-refund','fixed',{'refund':3000})
        self.assertEqual(a.states[('pay-refund','fixed')]['refunded'],9000)
        for _ in range(8):a.run('pay-replay','fixed',{'event_id':'evt-demo','repeat':8})
        self.assertEqual(a.states[('pay-replay','fixed')]['used'],1)
        self.assertEqual(a.run('pay-binding','fixed',{'payment':'settled-order100'})['order_state'],'paid')
        self.assertEqual(a.run('pay-binding','fixed',{'payment':'settled-order1'})['order_state'],'paid')  # rejection must not roll back earlier valid settlement

    def test_sql_parser_is_real_but_fixed_owner_predicate_survives(self):
        a=Academy();attack={'query':"' OR 1=1 --"}
        self.assertIn(('bob','Bob private note'),a.run('code-sqli','vulnerable',attack)['data'])
        for q in ["' OR 1=1 --", "'; DROP TABLE notes; --",'Alice']:
            r=a.run('code-sqli','fixed',{'query':q})
            self.assertTrue(all(row[0]=='alice' for row in r['data']))

    def test_input_bounds_synthetic_destinations_and_no_eval(self):
        a=Academy()
        for id,data in [('pay-price',{'price':True}),('pay-refund',{'refund':float('inf')}),('rate-xff',{'source':'8.8.8.8'}),('code-ssrf',{'url':'file:///etc/passwd'}),('pay-price',{'price':1,'actor':'admin'})]:
            with self.subTest(case=id),self.assertRaises(ValueError):a.run(id,'fixed',data)
        self.assertEqual(a.run('code-template','vulnerable',{'template':'{{__import__("os")}}'})['data'],'{{__import__("os")}}')
        self.assertEqual(a.run('code-nosql','fixed',{'password':'DEMO_VALID_PASSWORD'})['data']['authenticated'],True)

    def test_xss_no_server_execution_claim_and_documents_cannot_close_safe_script(self):
        a=Academy()
        for c in CATALOG:
            if c['group']!='xss':continue
            r=a.run(c['id'],'vulnerable',c['attack'])
            self.assertIsNone(r['flag']);self.assertFalse(r['impact'])
        doc=preview_document('xss-script','fixed','</script><script>alert(1)</script>','a'*32)
        self.assertNotIn('</script><script>alert(1)</script>',doc)
        self.assertIn('\\u003c/script',doc)

    def test_browser_round_state_isolation_and_preview_bounds(self):
        a,b=Academy(),Academy()
        a.run('pay-refund','fixed',{'refund':10000})
        self.assertTrue(b.run('pay-refund','fixed',{'refund':10000})['legitimate'])
        for _ in range(85):a.run('xss-html','vulnerable',{'value':'hello'})
        self.assertLessEqual(len(a.previews),80);self.assertLessEqual(len(a.evidence['xss-html']),30)


class HttpTests(unittest.TestCase):
    def test_sessions_host_origin_preview_and_form_routes(self):
        server=make_server(0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        base='http://127.0.0.1:'+str(server.server_port)
        try:
            a=build_opener(HTTPCookieProcessor(CookieJar()));b=build_opener(HTTPCookieProcessor(CookieJar()))
            for client in (a,b):client.open(base+'/rooms/session').read()
            self.assertEqual(len(json.load(a.open(base+'/academy/catalog'))['cases']),50)
            def run(client,id,mode,data,origin=None):
                req=Request(base+'/academy/run',data=urlencode({'case':id,'mode':mode,'input':json.dumps(data)}).encode())
                if origin:req.add_header('Origin',origin)
                return json.load(client.open(req))
            a_result=run(a,'xss-stored','vulnerable',{'value':'<b>stored</b>'})
            self.assertIn('<b>stored</b>',a.open(base+a_result['preview']).read().decode())
            with self.assertRaises(HTTPError) as error:b.open(base+a_result['preview'])
            self.assertEqual(error.exception.code,404)
            with self.assertRaises(HTTPError) as error:run(a,'pay-price','fixed',{'price':1},'https://outside.example')
            self.assertEqual(error.exception.code,403)
            for mode,data in [('fixed',{'price':10000}),('vulnerable',{'price':1}),('fixed',{'price':1})]:r=run(a,'pay-price',mode,data)
            self.assertTrue(r['flag'])
            self.assertIsNone(run(b,'pay-price','fixed',{'price':1})['flag'])
            req=Request(base+'/academy/reset',data=urlencode({'case':'xss-stored'}).encode());a.open(req).read()
            with self.assertRaises(HTTPError):a.open(base+a_result['preview'])
        finally:server.shutdown();server.server_close();thread.join()

if __name__=='__main__':unittest.main()
