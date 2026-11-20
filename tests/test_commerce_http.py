"""Observable domain invariants and actual HTTP contracts of the grouped labs."""
import json
from pathlib import Path
import sys
import threading
import unittest
from http.cookiejar import CookieJar
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request,build_opener,HTTPCookieProcessor
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app import make_server
from academy import Academy,CATALOG
from commerce import snapshot,provider_signature

class DomainTests(unittest.TestCase):
    def test_settlement_changes_ledger_and_untrusted_paid_claim_does_not(self):
        a=Academy();bad={'status':'paid','receipt':'pending-order100'}
        a.run('pay-status','vulnerable',bad)
        weak=snapshot(a.states[('pay-status','vulnerable')],'status')
        self.assertEqual(weak['order']['status'],'paid');self.assertEqual(weak['order']['captured_amount'],0);self.assertEqual(weak['entitlements']['downloads'],1)
        r=a.run('pay-status','fixed',bad)
        fixed=snapshot(a.states[('pay-status','fixed')],'status')
        self.assertEqual(r['status'],409);self.assertEqual(fixed['order']['revision'],0);self.assertEqual(fixed['entitlements']['downloads'],0)
        a.run('pay-status','fixed',{'status':'paid','receipt':'settled-order100'})
        paid=snapshot(a.states[('pay-status','fixed')],'status')
        self.assertEqual(paid['order']['captured_amount'],10000);self.assertEqual(paid['entitlements']['downloads'],1)
        revision=paid['order']['revision'];a.run('pay-status','fixed',bad)
        self.assertEqual(snapshot(a.states[('pay-status','fixed')],'status')['order']['revision'],revision)

    def test_canonical_signed_event_tampering_and_safe_replay(self):
        a=Academy();id='pay-webhook'
        for sig in ['invalid',provider_signature('pending')]:
            self.assertEqual(a.run(id,'fixed',{'event':'settled','signature':sig})['status'],401)
        self.assertEqual(snapshot(a.states[(id,'fixed')],'webhook')['order']['revision'],0)
        valid={'event':'settled','signature':provider_signature()}
        a.run(id,'fixed',valid);a.run(id,'fixed',valid)
        data=snapshot(a.states[(id,'fixed')],'webhook')
        self.assertEqual(data['entitlements']['downloads'],1);self.assertEqual(data['order']['captured_amount'],10000);self.assertEqual(len(data['transactions']),1)

    def test_refund_quote_and_stale_read_have_persisted_effects(self):
        a=Academy();a.run('pay-price','vulnerable',{'price':1})
        self.assertEqual(snapshot(a.states[('pay-price','vulnerable')],'price')['order']['totals']['amount_due'],1)
        self.assertEqual(snapshot(a.states[('pay-price','vulnerable')],'price')['entitlements']['downloads'],0)
        for _ in range(8):a.run('pay-refund','fixed',{'refund':3000})
        r=snapshot(a.states[('pay-refund','fixed')],'refund');self.assertEqual(r['order']['refunded_amount'],9000);self.assertEqual(len(r['transactions']),3)
        a.run('pay-gift','vulnerable',{'spend':6000,'repeat':2});a.run('pay-gift','fixed',{'spend':6000,'repeat':2})
        self.assertEqual(snapshot(a.states[('pay-gift','vulnerable')],'gift')['gift_card']['balance'],-2000)
        self.assertEqual(snapshot(a.states[('pay-gift','fixed')],'gift')['gift_card']['balance'],4000)

    def test_thirteen_labs_keep_all_cases_and_have_authored_context(self):
        self.assertEqual(len(CATALOG),97);self.assertEqual(len({r['group'] for r in CATALOG}),13)
        for r in CATALOG:
            for language in ('ar','en'):
                self.assertGreater(len(r['lesson']['story'][language]),80,r['id'])
                self.assertGreater(len(r['lesson']['interpretation'][language]),80,r['id'])
            self.assertTrue(r['lesson']['bad_code']);self.assertTrue(r['lesson']['fixed_code'])

class HttpContractTests(unittest.TestCase):
    def setUp(self):
        self.server=make_server(0);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start();self.base='http://127.0.0.1:'+str(self.server.server_port)
        self.client=build_opener(HTTPCookieProcessor(CookieJar()));self.client.open(self.base+'/rooms/session').read()
    def tearDown(self):self.server.shutdown();self.server.server_close();self.thread.join()
    def call(self,path,data=None,headers=None):
        request=Request(self.base+path,data=json.dumps(data).encode() if data is not None else None,headers=headers or ({'Content-Type':'application/json'} if data is not None else {}))
        try:r=self.client.open(request)
        except HTTPError as e:r=e
        return r.code,json.loads(r.read()),r.headers
    def resource(self,case,mode):return self.call('/academy/resource?'+urlencode({'case':case,'mode':mode}))
    def test_http_error_state_readback_and_assessment_are_distinct(self):
        path='/academy/api/payment/pay-binding/fixed';before=self.resource('pay-binding','fixed')
        status,body,headers=self.call(path,{'payment':'settled-order1'})
        self.assertEqual(status,409);self.assertEqual(body['error']['code'],'payment_order_mismatch');self.assertNotIn('impact',body);self.assertNotIn('flag',body)
        after=self.resource('pay-binding','fixed');self.assertEqual(before[1],after[1]);self.assertEqual(before[2]['ETag'],after[2]['ETag'])
        evidence=self.call('/academy/evidence?case=pay-binding&mode=fixed')[1]
        self.assertEqual(evidence['request_id'],headers['X-Request-ID']);self.assertTrue(evidence['protected'])
        status,paid,_=self.call(path,{'payment':'settled-order100'})
        self.assertEqual(status,200);self.assertEqual(paid['data']['order']['status'],'paid')
        self.assertEqual(self.resource('pay-binding','fixed')[1]['data']['entitlements']['downloads'],1)
    def test_all_sixteen_payment_http_statuses_and_unchanged_rejections(self):
        expected={'price':422,'quantity':422,'discount':422,'coupon-reuse':409,'currency':409,'rounding':422,'total':422,'shipping':422,'tax':422,'status':409,'webhook':401,'binding':409,'replay':200,'gift':409,'refund':409,'trial':409}
        for case in (row for row in CATALOG if row['group']=='payment'):
            id=case['id'];path='/academy/api/payment/'+id
            with self.subTest(case=id):
                self.assertEqual(self.call(path+'/vulnerable',case['attack'])[0],200)
                self.assertEqual(self.call(path+'/fixed',case['normal'])[0],200)
                before=self.resource(id,'fixed')
                status,body,headers=self.call(path+'/fixed',case['attack'])
                self.assertEqual(status,expected[id[4:]],body)
                after=self.resource(id,'fixed')
                self.assertEqual(before[1],after[1],id+' changed state after rejection/replay')
                self.assertEqual(before[2]['ETag'],after[2]['ETag'])
                self.assertEqual(body['data']['outcome'],'duplicate_ignored' if id=='pay-replay' else 'rejected')
                self.assertEqual(headers['X-Request-ID'],body['request_id'])

    def test_partial_batches_report_each_operation_not_a_blanket_200(self):
        for id,request in [('pay-coupon-reuse',{'coupon':'WELCOME','repeat':2}),('pay-gift',{'spend':6000,'repeat':2})]:
            status,body,_=self.call('/academy/api/payment/'+id+'/fixed',request)
            self.assertEqual(status,207);self.assertEqual(body['data']['outcome'],'partial')
            self.assertEqual([op['status'] for op in body['data']['operations']],[200,409])
        self.assertEqual(self.resource('pay-gift','fixed')[1]['data']['gift_card']['balance'],4000)

    def test_missing_fields_and_subcent_amounts_are_rejected(self):
        for case in (row for row in CATALOG if row['group']=='payment'):
            self.assertEqual(self.call('/academy/api/payment/'+case['id']+'/fixed',{})[0],400,case['id'])
        for value in ['100.004','99.999','0.004']:
            self.assertEqual(self.call('/academy/api/payment/pay-rounding/fixed',{'amount':value})[0],422)

    def test_rate_headers_and_access_denial_do_not_leak_private_content(self):
        for _ in range(4):status,body,headers=self.call('/academy/api/rate/rate-case/fixed',{'account':'alice@example.test','attempts':1})
        self.assertEqual(status,429);self.assertEqual(headers['Retry-After'],'60');self.assertEqual(headers['RateLimit-Remaining'],'0');self.assertEqual(body['error']['code'],'rate_limit_exceeded')
        status,body,_=self.call('/academy/api/access/acl-read/fixed',{'object':'b-1'})
        self.assertEqual(status,403);self.assertNotIn('bob',json.dumps(body));self.assertNotIn('data',body)
    def test_invalid_route_types_and_reset_invalidate_old_snapshots(self):
        self.assertEqual(self.call('/academy/api/access/pay-price/fixed',{'price':1})[0],404)
        self.assertEqual(self.call('/academy/api/payment/pay-price/fixed',{'price':True})[0],400)
        self.assertEqual(self.call('/academy/api/payment/pay-price/fixed',{'price':1}, {'Content-Type':'text/plain'})[0],415)
        self.call('/academy/api/payment/pay-price/vulnerable',{'price':1})
        request=Request(self.base+'/academy/reset',data=urlencode({'case':'pay-price'}).encode());self.client.open(request).read()
        data=self.resource('pay-price','vulnerable')[1]['data'];self.assertEqual(data['order']['totals']['amount_due'],10000);self.assertEqual(data['order']['revision'],0)

if __name__=='__main__':unittest.main()
