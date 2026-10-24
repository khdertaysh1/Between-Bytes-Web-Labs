import json
import unittest
from advanced import exercise, SECRET
from app import Labs
from browser_labs import csrf_write
import test_labs

class Fixtures(unittest.TestCase):
    def test_ssrf_private_and_redirect(self):
        for value in ('http://internal.lab/config','http://public.lab/redirect'):
            self.assertTrue(exercise('ssrf','vulnerable',value)[1]['private'])
            self.assertEqual(exercise('ssrf','fixed',value)[0],403)
        self.assertEqual(exercise('ssrf','fixed','http://public.lab/welcome')[0],200)
    def test_ssrf_cannot_connect_elsewhere(self):
        for value in ('http://127.0.0.1/','file:///etc/passwd','https://example.com/','http://public.lab@internal.lab/config','http://public.lab:8080/welcome'):
            self.assertEqual(exercise('ssrf','vulnerable',value)[0],400)
    def test_redirect_decisions(self):
        for value in ('https://outside.example/landing','//outside.example/','/welcome?next=//outside.example','/welcome\r\nX-Test: yes'):
            self.assertEqual(exercise('open-redirect','fixed',value)[0],400)
        self.assertTrue(exercise('open-redirect','vulnerable','https://outside.example/')[1]['external'])
        self.assertEqual(exercise('open-redirect','fixed','/account')[0],200)
    def test_api_secret_and_public_key(self):
        for file in ('/assets/checkout.js','/assets/billing.js'):
            self.assertIn(SECRET,exercise('api-keys','vulnerable',file)[1]['content'])
            content=exercise('api-keys','fixed',file)[1]['content']
            self.assertNotIn(SECRET,content)
            self.assertIn('PUBLIC_KEY=',content)
    def test_private_files_and_traversal(self):
        for file in ('/.env.backup','/backups/settings.env','/.git/config'):
            self.assertEqual(exercise('exposed-files','vulnerable',file)[0],200)
            self.assertEqual(exercise('exposed-files','fixed',file)[0],404)
        for file in ('/etc/passwd','../../app.py','/.env','/unknown'):
            self.assertEqual(exercise('exposed-files','vulnerable',file)[0],404)
        self.assertEqual(exercise('exposed-files','fixed','/robots.txt')[0],200)

class CSRF(unittest.TestCase):
    def test_session_origin_token_and_change(self):
        labs=Labs();expected='http://127.0.0.1:8000';cookie='bb_lab_session='+labs.browser_session
        self.assertEqual(csrf_write(labs,'vulnerable',expected,expected,'','note','')[0],401)
        self.assertEqual(csrf_write(labs,'vulnerable','http://127.0.0.1:9999',expected,cookie,'changed','')[0],200)
        self.assertEqual(labs.browser_notes['vulnerable']['note'],'changed')
        for origin,token in [('http://127.0.0.1:9999',labs.csrf_token),(expected,''),(None,labs.csrf_token)]:
            self.assertEqual(csrf_write(labs,'fixed',origin,expected,cookie,'bad',token)[0],403)
            self.assertEqual(labs.browser_notes['fixed']['revision'],0)
        self.assertEqual(csrf_write(labs,'fixed',expected,expected,cookie,'legit',labs.csrf_token)[0],200)
        self.assertEqual(labs.browser_notes['fixed']['revision'],1)
    def test_reset_invalidates_old_session(self):
        labs=Labs();cookie='bb_lab_session='+labs.browser_session;labs.reset()
        self.assertEqual(csrf_write(labs,'vulnerable',None,'local',cookie,'note','')[0],401)

class BrowserHTTP(unittest.TestCase):
    setUpClass=classmethod(test_labs.HTTPIntegration.setUpClass.__func__)
    tearDownClass=classmethod(test_labs.HTTPIntegration.tearDownClass.__func__)
    request=test_labs.HTTPIntegration.request
    def session(self):
        _,headers,body=self.request('/browser/session')
        return headers['Set-Cookie'].split(';')[0],json.loads(body)
    def test_cors_is_authenticated_and_policy_differs(self):
        self.assertEqual(self.request('/browser/cors/vulnerable')[0],401)
        cookie,_=self.session();origin='http://127.0.0.1:9999'
        for mode in ('vulnerable','fixed'):
            status,headers,body=self.request('/browser/cors/'+mode,headers={'Cookie':cookie,'Origin':origin})
            self.assertEqual(status,200)
            self.assertEqual(headers.get('Access-Control-Allow-Origin'),origin if mode=='vulnerable' else None)
            self.assertIn(b'DEMO_PRIVATE_CORS_DATA',body)
    def test_sidecar_is_loopback_and_fixtures_are_not_real_files(self):
        self.assertEqual(self.server.sidecar.server_address[0],'127.0.0.1')
        self.assertEqual(self.request('/.env.backup')[0],404)
        headers={'Content-Type':'application/x-www-form-urlencoded'}
        status,_,body=self.request('/lab/exposed-files/vulnerable','POST','value=%2F.env.backup',headers)
        self.assertEqual(status,200)
        self.assertIn(b'DEMO_FAKE_PASSWORD',body)
        self.assertEqual(self.request('/reset','POST','x=1',{**headers,'Origin':'http://evil.example'})[0],403)
