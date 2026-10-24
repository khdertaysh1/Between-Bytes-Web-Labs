"""Independent behavioral contracts for the four six-case request-policy labs."""
from copy import deepcopy
from unittest import TestCase
from unittest.mock import patch
from academy import Academy, CATALOG

class RequestSecurityTests(TestCase):
    def test_six_cases_each_and_no_duplicate_fixtures_within_a_lab(self):
        for group in ('ssrf','csrf','cors','redirect'):
            rows=[r for r in CATALOG if r['group']==group]
            self.assertEqual(len(rows),6)
            self.assertEqual(len({r['id'] for r in rows}),6)
            self.assertTrue(all(len(r['lesson']['steps'])==3 for r in rows))

    def test_csrf_rejected_updates_preserve_note_and_normal_update_works(self):
        expected={'csrf-missing':403,'csrf-empty':403,'csrf-binding':403,'csrf-origin':403,'csrf-get':405,'csrf-content-type':415}
        for row in [r for r in CATALOG if r['group']=='csrf']:
            with self.subTest(case=row['id']):
                a=Academy();id=row['id']
                a.run(id,'fixed',row['normal']);before=deepcopy(a.states[(id,'fixed')])
                bad=a.run(id,'fixed',row['attack'])
                self.assertEqual(bad['status'],expected[id]);self.assertEqual(before,a.states[(id,'fixed')]);self.assertFalse(bad['data']['operation_applied'])
                weak=a.run(id,'vulnerable',row['attack'])
                self.assertEqual(weak['data']['note'],'Changed without consent');self.assertTrue(weak['data']['operation_applied'])
                self.assertEqual(a.run(id,'fixed',{**row['normal'],'note':'A second normal update'})['data']['note'],'A second normal update')
                for field,value in [('note',[]),('method','DELETE'),('origin','null'),('token',True)]:
                    with self.assertRaises(ValueError):a.run(id,'fixed',{**row['normal'],field:value})

    def test_cors_200_is_not_proof_of_readability_and_auth_is_separate(self):
        for row in [r for r in CATALOG if r['group']=='cors']:
            with self.subTest(case=row['id']):
                a=Academy();weak=a.run(row['id'],'vulnerable',row['attack']);fixed=a.run(row['id'],'fixed',row['attack'])
                self.assertEqual(weak['status'],200);self.assertEqual(fixed['status'],200)
                self.assertEqual(weak['data']['private'],'DEMO_PRIVATE_CORS_DATA');self.assertIsNone(fixed['data']['private'])
                self.assertNotIn('Access-Control-Allow-Origin',fixed['data']['response_headers']);self.assertFalse(fixed['data']['readable'])
                if row['id']=='cors-preflight':
                    self.assertEqual(weak['data']['preflight']['status'],204);self.assertEqual(fixed['data']['preflight']['status'],403)
                no_session=a.run(row['id'],'vulnerable',{**row['attack'],'credentials':False})
                self.assertEqual(no_session['status'],401);self.assertFalse(no_session['impact'])
                with self.assertRaises(ValueError):a.run(row['id'],'fixed',{**row['normal'],'credentials':'true'})

    def test_ssrf_and_redirect_cannot_open_any_network_connection(self):
        with patch('socket.create_connection',side_effect=AssertionError('Network forbidden')):
            for row in [r for r in CATALOG if r['group'] in {'ssrf','redirect'}]:
                a=Academy();id=row['id'];weak=a.run(id,'vulnerable',row['attack']);fixed=a.run(id,'fixed',row['attack'])
                self.assertEqual(weak['status'],200);self.assertEqual(fixed['status'],403)
                if row['group']=='ssrf':
                    self.assertEqual(weak['data']['content'],'PRIVATE_DEMO_CONFIG');self.assertIsNone(fixed['data']['content'])
                    self.assertNotIn('fixture_read',[s['step'] for s in fixed['data']['trace']])
                    with self.assertRaises(ValueError):a.run(id,'vulnerable',{'url':'http://real-target.invalid/'})
                else:
                    self.assertTrue(weak['data']['external']);self.assertFalse(weak['data']['navigation_performed']);self.assertIsNone(fixed['data']['destination'])
                    with self.assertRaises(ValueError):a.run(id,'fixed',{'next':'/account\r\nX: y'})
