import json
import unittest
import test_labs
from app import Labs
from rooms import RoomContext,RoomSessions

class ClassroomState(unittest.TestCase):
    def test_sessions_do_not_share_counters_or_flags(self):
        sessions=RoomSessions(Labs)
        a,left=sessions.create('');b,right=sessions.create('')
        self.assertNotEqual(a,b);self.assertNotEqual(left.flag,right.flag)
        self.assertIs(sessions.resolve('bb_room='+a),left)
        for _ in range(3):left.labs.run('rate-limit','fixed','alice@example.test')
        self.assertEqual(left.labs.run('rate-limit','fixed','alice@example.test')[0],429)
        self.assertEqual(right.labs.run('rate-limit','fixed','alice@example.test')[0],401)
    def test_flag_requires_server_events_and_resets_per_round(self):
        c=RoomContext(Labs);c.start('idor');old=c.flag
        self.assertIsNone(c.report()['flag'])
        c.record('idor','vulnerable',200,{'invoice':{'owner':'bob'}},{})
        c.record('idor','fixed',403,{},{});c.record('idor','fixed',200,{'invoice':{'owner':'alice'}},{})
        self.assertEqual(c.report()['flag'],old)
        c.start('idor');self.assertNotEqual(c.flag,old);self.assertIsNone(c.report()['flag'])
    def test_browser_observations_are_not_claimed_as_server_execution(self):
        c=RoomContext(Labs);c.start('dom-xss')
        for mode in ('vulnerable','fixed'):c.record('dom-xss',mode,200,{}, {})
        self.assertTrue(c.report()['ready']);self.assertIsNone(c.report()['flag'])
        self.assertEqual(c.report()['verification'],'browser-assisted')
    def test_log_is_bounded_and_ignores_other_rooms(self):
        c=RoomContext(Labs);c.start('idor');c.record('cors','fixed',200,{}, {})
        self.assertEqual(len(c.events),0)
        for _ in range(140):c.record('idor','fixed',403,{}, {})
        self.assertEqual(len(c.events),120)

class RoomHTTP(unittest.TestCase):
    setUpClass=classmethod(test_labs.HTTPIntegration.setUpClass.__func__)
    tearDownClass=classmethod(test_labs.HTTPIntegration.tearDownClass.__func__)
    request=test_labs.HTTPIntegration.request
    def test_cookie_session_and_observable_evidence(self):
        status,headers,_=self.request('/rooms/session');self.assertEqual(status,200)
        cookie=headers['Set-Cookie'].split(';')[0]
        form={'Cookie':cookie,'Content-Type':'application/x-www-form-urlencoded'}
        self.assertEqual(self.request('/rooms/start','POST','lesson=idor',form)[0],200)
        for mode,resource in [('vulnerable','1002'),('fixed','1002'),('fixed','1001')]:
            self.request('/lab/idor/'+mode,'POST','resource='+resource,form)
        report=json.loads(self.request('/rooms/status',headers={'Cookie':cookie})[2])
        self.assertEqual(report['requests_observed'],3);self.assertTrue(report['flag'].startswith('BB{'))
        self.assertEqual(self.request('/rooms/status')[0],401)
        self.assertEqual(self.request('/rooms/start','POST','lesson=unknown',form)[0],400)
