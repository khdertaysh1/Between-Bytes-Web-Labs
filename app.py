"""Between Bytes: isolated, intentionally vulnerable web lessons. Python 3.10+."""
import argparse
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import time
from urllib.parse import parse_qs, urlsplit
from advanced import exercise
from browser_labs import initialize, authenticated, csrf_write, LabServer, Sidecar
from training import access_lesson, preview_document, PREVIEW_CSP

GENERIC = {"message": "If the account exists, a reset message will be queued."}
USERS = {"alice@example.test", "bob@example.test"}


class Labs:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.reset()

    def reset(self):
        initialize(self)
        self.attempts = defaultdict(deque)
        self.last_mail = {}
        self.outbox = deque(maxlen=100)

    def allow(self, key, maximum, window):
        now = self.clock()
        bucket = self.attempts[key]
        while bucket and now - bucket[0] >= window:
            bucket.popleft()
        if len(bucket) >= maximum:
            return False
        bucket.append(now)
        return True

    def run(self, lesson, mode, email, peer="127.0.0.1", forwarded=""):
        if lesson not in {"enumeration", "rate-limit", "email-flood"} or mode not in {"vulnerable", "fixed"}:
            return 404, {"error": "Unknown lesson or mode"}
        if not isinstance(email, str) or len(email) > 254:
            return 400, {"error": "Invalid email"}
        email = email.strip().casefold()
        exists = email in USERS
        if lesson == "enumeration":
            if mode == "vulnerable":
                return (200, {"message": "Reset queued"}) if exists else (404, {"message": "Account not found"})
            # Identical public status/body; this lesson does not prove timing resistance.
            return 202, GENERIC.copy()
        if lesson == "rate-limit":
            if mode == "vulnerable":
                # Deliberate mistake: trust a client-supplied proxy identity.
                key = (lesson, mode, forwarded or peer)
                allowed = self.allow(key, 3, 60)
            else:
                # Normalize account identity and use the socket peer, not arbitrary XFF.
                account_ok = self.allow((lesson, mode, "account", email), 3, 60)
                source_ok = self.allow((lesson, mode, "source", peer), 6, 60)
                allowed = account_ok and source_ok
            if not allowed:
                return 429, {"error": "Too many attempts; wait up to 60 seconds"}
            # Always wrong, seeded synthetic login; no password guessing functionality.
            return 401, {"error": "Invalid credentials"}
        now = self.clock()
        if mode == "fixed":
            source_ok = self.allow((lesson, mode, "source", peer), 6, 60)
            previous = self.last_mail.get(email)
            cooldown_ok = previous is None or now - previous >= 60
            if source_ok and cooldown_ok:
                # Apply cooldown to both existing and unknown identities.
                self.last_mail[email] = now
                if exists:
                    self.queue(mode, email)
        elif exists:
            self.queue(mode, email)
        return 202, GENERIC.copy()

    def queue(self, mode, email):
        # In-memory sink only: no SMTP, network delivery, reset token or real account.
        self.outbox.append({"mode": mode, "to": email, "subject": "Demo password reset", "body": "Training message only; no reset link."})


def handler_for(labs):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, data, mime="application/json; charset=utf-8", csp=None, headers=None):
            body = data if isinstance(data, bytes) else json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for key,value in (headers or {}).items():
                self.send_header(key,value)
            sidecar=getattr(self.server,"sidecar",None)
            frames=" frame-src 'self' http://127.0.0.1:"+str(sidecar.server_port)+";" if sidecar else ""
            self.send_header("Content-Security-Policy", csp or "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; form-action 'self';"+frames)
            self.end_headers()
            self.wfile.write(body)

        def valid_host(self):
            # Prevent arbitrary Host / DNS rebinding access to the local lab.
            return self.headers.get("Host") == "127.0.0.1:" + str(self.server.server_port)

        def do_GET(self):
            if not self.valid_host():
                return self.reply(403, {"error": "Open the lab using 127.0.0.1"})
            parsed = urlsplit(self.path)
            if parsed.path == '/browser/session':
                sidecar=self.server.sidecar
                return self.reply(200, {'csrf_token':labs.csrf_token,'attack_origin':'http://127.0.0.1:'+str(sidecar.server_port)}, headers={'Set-Cookie':'bb_lab_session='+labs.browser_session+'; HttpOnly; SameSite=Lax; Path=/'})
            if parsed.path == '/browser/state':
                if not authenticated(labs,self.headers.get('Cookie')):
                    return self.reply(401, {'error':'No synthetic session'})
                return self.reply(200, {'notes':labs.browser_notes})
            if parsed.path.startswith('/browser/cors/'):
                mode=parsed.path.split('/')[-1]
                if mode not in {'vulnerable','fixed'}:
                    return self.reply(404, {'error':'Unknown mode'})
                if not authenticated(labs,self.headers.get('Cookie')):
                    return self.reply(401, {'error':'No synthetic session'})
                origin=self.headers.get('Origin','')
                expected='http://127.0.0.1:'+str(self.server.server_port)
                headers={}
                if origin and (mode=='vulnerable' or origin==expected):
                    headers={'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Credentials':'true','Vary':'Origin'}
                return self.reply(200, {'owner':'alice','private':'DEMO_PRIVATE_CORS_DATA','synthetic':True},headers=headers)
            if parsed.path.startswith("/preview/"):
                try:
                    parts = parsed.path.strip("/").split("/")
                    if len(parts) != 3:
                        raise ValueError("Invalid route")
                    query = parse_qs(parsed.query, max_num_fields=4)
                    if parts[1] == "dom-xss" and "q" in query:
                        raise ValueError("DOM payload must stay in browser")
                    document = preview_document(parts[1], parts[2], query.get("q", [""])[0], query.get("token", [""])[0])
                    return self.reply(200, document.encode(), "text/html; charset=utf-8", PREVIEW_CSP)
                except ValueError:
                    return self.reply(400, {"error": "Invalid preview"})
            files = {"/": ("index.html", "text/html; charset=utf-8"), "/ui.js": ("ui.js", "text/javascript; charset=utf-8"), "/style.css": ("style.css", "text/css; charset=utf-8"), "/progression.js": ("progression.js", "text/javascript; charset=utf-8"), "/course.js": ("course.js", "text/javascript; charset=utf-8"), "/new_lessons.js": ("new_lessons.js", "text/javascript; charset=utf-8"), "/catalog.js": ("catalog.js", "text/javascript; charset=utf-8"), "/challenges.js": ("challenges.js", "text/javascript; charset=utf-8")}
            if self.path in files:
                name, mime = files[self.path]
                return self.reply(200, Path(__file__).with_name(name).read_bytes(), mime)
            if self.path == "/outbox":
                return self.reply(200, {"messages": list(labs.outbox)})
            return self.reply(404, {"error": "Not found"})

        def do_POST(self):
            if not self.valid_host():
                return self.reply(403, {"error": "Invalid host"})
            origin = self.headers.get("Origin")
            expected = "http://127.0.0.1:" + str(self.server.server_port)
            csrf_route=self.path in {"/browser/csrf/vulnerable","/browser/csrf/fixed"}
            if not csrf_route and origin and origin != expected:
                return self.reply(403, {"error": "Cross-origin requests rejected"})
            if not csrf_route and self.headers.get("Sec-Fetch-Site") == "cross-site":
                return self.reply(403, {"error": "Cross-site requests rejected"})
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 4096:
                    return self.reply(413, {"error": "Body must be 1..4096 bytes"})
                if self.headers.get_content_type() != "application/x-www-form-urlencoded":
                    return self.reply(415, {"error": "Use form encoding"})
                form = parse_qs(self.rfile.read(size).decode("utf-8"), max_num_fields=8)
            except (ValueError, UnicodeError):
                return self.reply(400, {"error": "Malformed request"})
            if csrf_route:
                status,result=csrf_write(labs,self.path.split('/')[-1],origin,expected,self.headers.get('Cookie'),form.get('note',[''])[0],form.get('csrf_token',[''])[0])
                return self.reply(status,result)
            if self.path == "/reset":
                labs.reset()
                return self.reply(200, {"message": "Local lab state reset"})
            parts = self.path.strip("/").split("/")
            if len(parts) != 3 or parts[0] != "lab":
                return self.reply(404, {"error": "Not found"})
            if parts[1] in {'ssrf','open-redirect','api-keys','exposed-files'}:
                status,result=exercise(parts[1],parts[2],form.get('value',[''])[0])
                return self.reply(status,result)
            if parts[1] in {"idor", "edge403"}:
                status, result = access_lesson(parts[1], parts[2], form)
                return self.reply(status, result)
            status, result = labs.run(parts[1], parts[2], form.get("email", [""])[0], self.client_address[0], self.headers.get("X-Forwarded-For", ""))
            return self.reply(status, result)
    return Handler


def make_server(port=8000):
    server = LabServer(("127.0.0.1", port), handler_for(Labs()))
    server.sidecar=Sidecar(server)
    server.timeout = 1
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Choose a port between 1024 and 65535")
    with make_server(args.port) as server:
        print(f"Between Bytes Labs: http://127.0.0.1:{args.port} (Ctrl+C to stop)", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
