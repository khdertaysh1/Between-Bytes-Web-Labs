import http.client
import threading
import unittest
from urllib.parse import urlencode
from app import Labs, make_server


class Lessons(unittest.TestCase):
    def setUp(self):
        self.now = 0.0
        self.lab = Labs(lambda: self.now)

    def call(self, lesson, mode, email="alice@example.test", **kwargs):
        return self.lab.run(lesson, mode, email, **kwargs)

    def test_enumeration_leaks_only_in_vulnerable_lesson(self):
        for mode in ("vulnerable", "fixed"):
            a = self.call("enumeration", mode)
            b = self.call("enumeration", mode, "nobody@example.test")
            self.assertEqual(a == b, mode == "fixed")

    def test_spoofing_bypasses_vulnerable_limit(self):
        for _ in range(3):
            self.assertEqual(self.call("rate-limit", "vulnerable")[0], 401)
        self.assertEqual(self.call("rate-limit", "vulnerable")[0], 429)
        self.assertEqual(self.call("rate-limit", "vulnerable", forwarded="192.0.2.1")[0], 401)

    def test_fixed_account_limit_survives_source_rotation_and_normalization(self):
        for n in range(3):
            self.assertEqual(self.call("rate-limit", "fixed", " Alice@EXAMPLE.test ", peer=f"192.0.2.{n}", forwarded=str(n))[0], 401)
        self.assertEqual(self.call("rate-limit", "fixed", peer="192.0.2.9", forwarded="changed")[0], 429)
        self.now = 60
        self.assertEqual(self.call("rate-limit", "fixed")[0], 401)

    def test_fixed_source_limit_survives_account_rotation(self):
        for n in range(6):
            self.assertEqual(self.call("rate-limit", "fixed", f"user{n}@example.test")[0], 401)
        self.assertEqual(self.call("rate-limit", "fixed", "other@example.test")[0], 429)

    def test_mail_delivery_and_cooldown(self):
        for _ in range(4):
            self.call("email-flood", "vulnerable")
        self.assertEqual(len(self.lab.outbox), 4)
        self.lab.reset()
        for _ in range(4):
            self.call("email-flood", "fixed")
        self.assertEqual(len(self.lab.outbox), 1)
        self.now = 60
        self.call("email-flood", "fixed")
        self.assertEqual(len(self.lab.outbox), 2)

    def test_fixed_mail_source_limit(self):
        for _ in range(6):
            self.call("email-flood", "fixed", "nobody@example.test")
        self.call("email-flood", "fixed")
        self.assertEqual(len(self.lab.outbox), 0)

    def test_unknown_or_real_address_never_receives_mail(self):
        for mode in ("vulnerable", "fixed"):
            self.assertEqual(self.call("email-flood", mode, "someone@gmail.com"), self.call("email-flood", mode))
        self.assertTrue(all(m["to"] == "alice@example.test" for m in self.lab.outbox))

    def test_outbox_is_bounded(self):
        for _ in range(150):
            self.call("email-flood", "vulnerable")
        self.assertEqual(len(self.lab.outbox), 100)


class HTTPIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server(0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, path, method="GET", body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        conn.request(method, path, body, headers or {})
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        conn.close()
        return result

    def test_ui_and_assets_served(self):
        for path in ("/", "/academy.js", "/academy.css", "/outbox"):
            status, headers, body = self.request(path)
            self.assertEqual(status, 200)
            self.assertTrue(body)
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_post_route_and_reset(self):
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        self.assertEqual(self.request("/reset", "POST", "reset=1", headers)[0], 200)
        status, _, body = self.request("/lab/enumeration/vulnerable", "POST", urlencode({"email": "nobody@example.test"}), headers)
        self.assertEqual(status, 404)
        self.assertIn(b"Account not found", body)
        self.assertEqual(self.request("/lab/enumeration/fixed", "POST", "email=nobody%40example.test", headers)[0], 202)

    def test_cross_origin_and_rebinding_rejected(self):
        self.assertEqual(self.request("/", headers={"Host": "evil.example"})[0], 403)
        headers = {"Origin": "https://evil.example", "Content-Type": "application/x-www-form-urlencoded"}
        self.assertEqual(self.request("/reset", "POST", "reset=1", headers)[0], 403)

    def test_bad_bodies_and_routes(self):
        self.assertEqual(self.request("/reset", "POST", "x=1", {"Content-Type": "application/json"})[0], 415)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        self.assertEqual(self.request("/reset", "POST", "x=" + "a" * 4096, headers)[0], 413)
        self.assertEqual(self.request("/missing")[0], 404)


if __name__ == "__main__":
    unittest.main()
