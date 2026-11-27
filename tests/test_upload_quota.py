import base64
from copy import deepcopy
from unittest import TestCase
from academy import Academy

class UploadQuota(TestCase):
    def body(self,n):
        return dict(filename='sample.bin',content_type='application/octet-stream',content=base64.b64encode(b'A'*n).decode())
    def test_boundary_and_denial_preserves_storage(self):
        a=Academy()
        for n in (1,31,32):
            r=a.run('upload-decoded-size','fixed',self.body(n))
            self.assertEqual(r['status'],201);self.assertEqual(r['data']['decoded_bytes'],n)
        before=deepcopy(a.states[('upload-decoded-size','fixed')])
        for n in (33,34,128):
            r=a.run('upload-decoded-size','fixed',self.body(n))
            self.assertEqual(r['status'],413);self.assertFalse(r['data']['accepted'])
            self.assertEqual(before,a.states[('upload-decoded-size','fixed')])
    def test_invalid_base64_has_no_impact_or_completion(self):
        a=Academy()
        for mode in ('vulnerable','fixed'):
            for value in ('@@@','A===','   '):
                r=a.run('upload-decoded-size',mode,{**self.body(8),'content':value})
                self.assertEqual(r['status'],422);self.assertFalse(r['impact']);self.assertFalse(r['flag'])
                self.assertEqual(a.states[('upload-decoded-size',mode)],{})
    def test_completion_requires_matching_manual_requests_and_control(self):
        a=Academy();cid='upload-decoded-size'
        self.assertFalse(a.flags)
        self.assertFalse(a.run(cid,'vulnerable',self.body(33))['flag'])
        self.assertFalse(a.run(cid,'fixed',self.body(34))['flag'])
        self.assertFalse(a.run(cid,'fixed',self.body(8))['flag'])
        self.assertTrue(a.run(cid,'fixed',self.body(33))['flag'])
