"""Resource and identity boundaries, state persistence, arbitrary input and no IO."""
from copy import deepcopy
from unittest import TestCase
from unittest.mock import patch
from academy import Academy, CATALOG
from resource_labs import GROUPS

class ResourceLabsTests(TestCase):
    def test_catalog_has_four_separate_six_case_labs_with_bilingual_lessons(self):
        for group in GROUPS:
            rows = [r for r in CATALOG if r['group'] == group]
            self.assertEqual(len(rows), 6)
            self.assertEqual(len({r['id'] for r in rows}), 6)
            for r in rows:
                self.assertEqual(len(r['lesson']['steps']), 3)
                for key in ('story', 'interpretation'):
                    for lang in ('ar', 'en'): self.assertGreater(len(r['lesson'][key][lang]), 60)

    def test_fixed_rejection_preserves_state_and_modes_are_isolated(self):
        for r in CATALOG:
            if r['group'] not in GROUPS: continue
            with self.subTest(case=r['id']):
                a = Academy(); cid = r['id']
                control = a.run(cid, 'fixed', r['normal'])
                self.assertTrue(control['legitimate'])
                before = deepcopy(a.states[(cid, 'fixed')])
                weak = a.run(cid, 'vulnerable', r['attack'])
                self.assertTrue(weak['impact'])
                fixed = a.run(cid, 'fixed', r['attack'])
                self.assertTrue(fixed['protected']); self.assertFalse(fixed['impact'])
                self.assertEqual(before, a.states[(cid, 'fixed')])
                self.assertTrue(fixed['flag'])

    def test_traversal_canonicalization_cannot_escape_public_root(self):
        a = Academy()
        for value in ('../../private/billing.csv', '%2e%2e/private/billing.csv', '..\\private\\billing.csv', '/private/billing.csv', '../public-backup/keys.txt'):
            r = a.run('traversal-relative', 'fixed', {'path': value})
            self.assertEqual(r['status'], 403); self.assertIsNone(r['data']['content'])
        self.assertEqual(a.run('traversal-double', 'fixed', {'path': '%252e%252e%252fprivate%252fbilling.csv'})['status'], 403)
        self.assertEqual(a.run('traversal-relative', 'fixed', {'path': 'folder/../guide.txt'})['data']['content'], 'Public installation guide')
        self.assertEqual(a.run('traversal-relative', 'fixed', {'path': 'absent.txt'})['status'], 404)

    def test_upload_owner_content_and_no_execution(self):
        a = Academy()
        for filename in ('x.PHP', 'x.png.php', '../../x.png', 'bob.png'):
            r = a.run('upload-extension', 'fixed', {'filename': filename, 'content_type': 'image/png', 'content': 'PNG:test'})
            self.assertIn(r['status'], (403, 415)); self.assertFalse(r['data']['execution_performed'])
            self.assertEqual(r['data']['files']['bob.png']['content'], 'PNG:bob-original')
        r = a.run('upload-mime', 'fixed', {'filename': 'a.png', 'content_type': 'image/png', 'content': 'HTML:document'})
        self.assertEqual(r['status'], 415)
        for value in ('<svg onload="demo()"></svg>', '<svg><foreignObject>demo</foreignObject></svg>', '<svg><use href="demo"/></svg>'):
            r = a.run('upload-svg', 'fixed', {'filename': 'x.svg', 'content_type': 'image/svg+xml', 'content': value})
            self.assertEqual(r['status'], 415)

    def test_consumed_token_fails_even_after_normal_success(self):
        for cid in ('authentication-reset-binding','authentication-reset-replay','authentication-reset-expiry','authentication-purpose'):
            row = next(r for r in CATALOG if r['id'] == cid); a = Academy()
            self.assertEqual(a.run(cid, 'fixed', row['normal'])['status'], 200)
            before = deepcopy(a.states[(cid, 'fixed')])
            r = a.run(cid, 'fixed', row['normal'])
            self.assertEqual(r['status'], 401); self.assertEqual(before, a.states[(cid, 'fixed')])
        self.assertEqual(Academy().run('authentication-logout','fixed',{'session':'unknown'})['status'],401)

    def test_arbitrary_fields_and_inputs_do_not_claim_success(self):
        for row in CATALOG:
            if row['group'] not in GROUPS: continue
            for field in row['normal']:
                for bad in (True, [], {}, '', 'a'*1025, 'bad\x00value'):
                    with self.subTest(case=row['id'],field=field), self.assertRaises(ValueError):
                        Academy().run(row['id'], 'fixed', {**row['normal'], field: bad})
        for group,cid,body in [('disclosure','disclosure-env',{'path':'/missing'}),('traversal','traversal-relative',{'path':'missing'})]:
            self.assertEqual(Academy().run(cid,'vulnerable',body)['status'],404)

    def test_engines_never_touch_host_files_network_or_processes(self):
        with patch('builtins.open', side_effect=AssertionError('host file access')), patch('socket.create_connection', side_effect=AssertionError('network')), patch('subprocess.Popen', side_effect=AssertionError('process')):
            for row in CATALOG:
                if row['group'] not in GROUPS: continue
                for mode in ('fixed','vulnerable'):
                    a=Academy(); a.run(row['id'],mode,row['normal']); a.run(row['id'],mode,row['attack'])

    def test_upload_capacity_and_reset_keep_resources_bounded(self):
        a=Academy()
        for index in range(29):
            self.assertEqual(a.run('upload-extension','fixed',{'filename':str(index)+'.png','content_type':'image/png','content':'PNG:test'})['status'],201)
        before=deepcopy(a.states[('upload-extension','fixed')])
        for name in ('one-more.png','alice-upload-1.png'):
            r=a.run('upload-extension','fixed',{'filename':name,'content_type':'image/png','content':'PNG:test'})
            self.assertEqual(r['status'],409); self.assertEqual(before,a.states[('upload-extension','fixed')])
        a.reset('upload-extension')
        self.assertEqual(a.run('upload-extension','fixed',{'filename':'fresh.png','content_type':'image/png','content':'PNG:test'})['status'],201)
