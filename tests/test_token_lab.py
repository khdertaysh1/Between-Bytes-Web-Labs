from copy import deepcopy
import unittest
from academy import Academy
from token_lab import fixture,encode,NOW

class TokenTests(unittest.TestCase):
    def test_changed_payload_does_not_keep_signature_valid(self):
        parts=fixture().split('.');parts[1]=encode({'sub':'alice','role':'admin','exp':NOW+3600});token='.'.join(parts)
        a=Academy();weak=a.run('code-token-signature','vulnerable',{'token':token})
        self.assertTrue(weak['data']['admin_panel']);self.assertFalse(weak['data']['signature_verified'])
        fixed=a.run('code-token-signature','fixed',{'token':token});self.assertEqual(fixed['status'],401);self.assertIsNone(fixed['data']['effective_role'])
        self.assertFalse(fixed['data']['admin_panel'])
    def test_signed_control_and_real_signature_are_accepted(self):
        for role in ('viewer','admin'):
            r=Academy().run('code-token-signature','fixed',{'token':fixture(role)})
            self.assertEqual(r['status'],200);self.assertTrue(r['data']['signature_verified']);self.assertTrue(r['legitimate'])
    def test_none_algorithm_and_expired_claims_cannot_grant_access(self):
        for header,payload in [({'typ':'JWT','alg':'none'},{'sub':'alice','role':'admin','exp':NOW+1}),({'typ':'JWT','alg':'HS256'},{'sub':'alice','role':'admin','exp':NOW-1})]:
            token=encode(header)+'.'+encode(payload)+'.invalid'
            r=Academy().run('code-token-signature','fixed',{'token':token});self.assertEqual(r['status'],401);self.assertFalse(r['impact'])
    def test_malformed_tokens_are_rejected_and_completion_is_manual(self):
        for token in ('abc','a.b.c','{}',[],True,'x'*1025):
            with self.subTest(token=token),self.assertRaises(ValueError):Academy().run('code-token-signature','fixed',{'token':token})
        a=Academy();a.run('code-token-signature','fixed',{'token':fixture()});before=deepcopy(a.states[('code-token-signature','fixed')]);attack={'token':fixture('admin',False)}
        self.assertIsNone(a.run('code-token-signature','vulnerable',attack)['flag']);self.assertTrue(a.run('code-token-signature','fixed',attack)['flag']);self.assertEqual(before,a.states[('code-token-signature','fixed')])
