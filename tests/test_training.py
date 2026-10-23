import unittest
from training import access_lesson, preview_document, PREVIEW_CSP
import test_labs


class Authorization(unittest.TestCase):
    def test_idor_requires_ownership_even_with_forged_actor(self):
        for mode in ('vulnerable', 'fixed'):
            self.assertEqual(access_lesson('idor', mode, {'resource':['1001']})[0], 200)
        status, body = access_lesson('idor','vulnerable',{'resource':['1002']})
        self.assertEqual(status,200)
        self.assertEqual(body['actor'],'alice')
        self.assertEqual(body['invoice']['owner'],'bob')
        self.assertEqual(access_lesson('idor','fixed',{'resource':['1002'],'actor':['bob']})[0],403)
        self.assertEqual(access_lesson('idor','fixed',{'resource':['9999']})[0],404)

    def test_edge_and_origin_both_require_authorization(self):
        for mode in ('vulnerable','fixed'):
            self.assertEqual(access_lesson('edge403',mode,{'layer':['edge']})[0],403)
        self.assertEqual(access_lesson('edge403','vulnerable',{'layer':['origin']})[0],200)
        self.assertEqual(access_lesson('edge403','fixed',{'layer':['origin']})[0],403)
        self.assertEqual(access_lesson('edge403','vulnerable',{'layer':['https://example.com']})[0],400)


class Preview(unittest.TestCase):
    def test_reflection_is_encoded_only_in_fixed(self):
        payload='<img src=x onerror="alert(\'BB-LAB\')">'
        for mode in ('vulnerable','fixed'):
            document=preview_document('reflected-xss',mode,payload,'a'*32)
            self.assertEqual(payload in document,mode=='vulnerable')
            self.assertEqual('&lt;img' in document,mode=='fixed')

    def test_dom_source_and_sink(self):
        bad=preview_document('dom-xss','vulnerable','','a'*32)
        fixed=preview_document('dom-xss','fixed','','a'*32)
        self.assertIn('output.innerHTML = event.data.value',bad)
        self.assertIn('output.textContent = event.data.value',fixed)
        self.assertIn('event.source !== parent',bad)
        self.assertIn("sandbox allow-scripts",PREVIEW_CSP)
        self.assertNotIn('allow-same-origin',PREVIEW_CSP)
        self.assertIn("connect-src 'none'",PREVIEW_CSP)

    def test_preview_rejects_invalid_inputs(self):
        for args in [('unknown','fixed','','a'*32),('dom-xss','unknown','','a'*32),('dom-xss','fixed','','</script>'),('reflected-xss','fixed','a'*1001,'a'*32)]:
            with self.assertRaises(ValueError):
                preview_document(*args)


class TrainingHTTP(unittest.TestCase):
    setUpClass = classmethod(test_labs.HTTPIntegration.setUpClass.__func__)
    tearDownClass = classmethod(test_labs.HTTPIntegration.tearDownClass.__func__)
    request = test_labs.HTTPIntegration.request

    def test_authorization_routes(self):
        headers={'Content-Type':'application/x-www-form-urlencoded'}
        self.assertEqual(self.request('/lab/idor/vulnerable','POST','resource=1002',headers)[0],200)
        self.assertEqual(self.request('/lab/idor/fixed','POST','resource=1002&actor=bob',headers)[0],403)
        self.assertEqual(self.request('/lab/edge403/fixed','POST','layer=origin',headers)[0],403)

    def test_isolated_preview_headers_and_dom_input_contract(self):
        status,headers,_=self.request('/preview/reflected-xss/vulnerable?token='+'a'*32+'&q=hello')
        self.assertEqual(status,200)
        self.assertEqual(headers['Content-Security-Policy'],PREVIEW_CSP)
        self.assertEqual(self.request('/preview/dom-xss/vulnerable?token='+'a'*32+'&q=not-allowed')[0],400)
        self.assertEqual(self.request('/preview/dom-xss/fixed?token=invalid')[0],400)
