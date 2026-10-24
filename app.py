"""Between Bytes: isolated, intentionally vulnerable web lessons. Python 3.10+."""
import argparse
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re
from pathlib import Path
import time
from urllib.parse import parse_qs, urlsplit
from rooms import RoomSessions, ROOMS
from academy import Academy, CATALOG as ACADEMY_CATALOG, preview_document as academy_preview
from academy_http import response as academy_response
from commerce import snapshot as checkout_snapshot
from advanced import exercise
from browser_labs import initialize, authenticated, csrf_write, LabServer, Sidecar
from training import access_lesson, preview_document, PREVIEW_CSP

def strict_json(value):
    def unique_object(pairs):
        result={}
        for key,item in pairs:
            if key in result:raise ValueError('Duplicate JSON field')
            result[key]=item
        return result
    def invalid_constant(value):raise ValueError('Non-finite JSON number')
    return json.loads(value,object_pairs_hook=unique_object,parse_constant=invalid_constant)


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
        def room_context(self):
            return self.server.room_sessions.resolve(self.headers.get('Cookie'))

        def academy(self):
            context = self.room_context()
            if context is None:
                return None
            if not hasattr(context, "academy"):
                context.academy = Academy()
            return context.academy

        def log_message(self, *args):
            pass

        def reply(self, status, data, mime="application/json; charset=utf-8", csp=None, headers=None):
            context=self.room_context()
            event=getattr(self,'room_event',None)
            if context and event and isinstance(data,dict):
                context.record(event['lesson'],event['mode'],status,data,event['details'])
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
            self.room_event=None
            context=self.room_context()
            state=context.labs if context else labs
            if not self.valid_host():
                return self.reply(403, {"error": "Open the lab using 127.0.0.1"})
            try:parsed=urlsplit(self.path)
            except ValueError:return self.reply(400,{'error':'Malformed request URL'})
            get_api=re.fullmatch(r'/academy/api/(payment|access|rate|xss|code|ssrf|csrf|cors|redirect)/([a-z0-9-]+)/(vulnerable|fixed)',parsed.path)
            if get_api:
                group,case,mode=get_api.groups()
                if not any(row['id']==case and row['group']==group for row in ACADEMY_CATALOG):return self.reply(404,{'error':{'code':'route_not_found','message':'Unknown application route'}})
                return self.reply(405,{'error':{'code':'method_not_allowed','message':'Use POST for this application endpoint'}},headers={'Allow':'POST'})
            if parsed.path == '/academy/catalog':
                return self.reply(200, {'version':'0.10.0','cases':ACADEMY_CATALOG})
            if parsed.path in {'/academy/evidence','/academy/resource'}:
                academy=self.academy()
                if academy is None:return self.reply(401,{'error':'Start a classroom session'})
                try:
                    query=parse_qs(parsed.query,max_num_fields=3)
                    if any(len(values)!=1 for values in query.values()):raise ValueError('Duplicate query field')
                    case=query.get('case',[''])[0];mode=query.get('mode',[''])[0]
                    if case not in {row['id'] for row in ACADEMY_CATALOG} or mode not in {'vulnerable','fixed'}:raise ValueError('Unknown case or variant')
                    if parsed.path=='/academy/resource':
                        if not case.startswith('pay-'):return self.reply(404,{'error':'Resource readback is available for checkout only'})
                        state=academy.states.setdefault((case,mode),{})
                        data=checkout_snapshot(state,case[4:])
                        return self.reply(200,{'data':data},headers={'ETag':'"order100-r'+str(data['order']['revision'])+'"'})
                    latest=academy.latest.get((case,mode))
                    return self.reply(200,latest or {'checks':{},'flag':None})
                except ValueError as error:return self.reply(400,{'error':str(error)})
            if parsed.path.startswith('/academy/preview/'):
                academy = self.academy()
                token = parsed.path.rsplit('/',1)[-1]
                entry = academy.previews.get(token) if academy else None
                if entry is None:
                    return self.reply(404, {'error':'Preview expired; run the local case again'})
                return self.reply(200, academy_preview(*entry).encode(), 'text/html; charset=utf-8', PREVIEW_CSP)
            if parsed.path == '/rooms/session':
                try:
                    key,room=self.server.room_sessions.create(self.headers.get('Cookie'))
                    headers={'Set-Cookie':'bb_room='+key+'; HttpOnly; SameSite=Lax; Path=/'} if key else {}
                    return self.reply(200,{'isolated_browser_state':True,'expiry_seconds':1800},headers=headers)
                except ValueError as error:
                    return self.reply(503,{'error':str(error)})
            if parsed.path == '/rooms/status':
                if not context:return self.reply(401,{'error':'Start a classroom session'})
                return self.reply(200,context.report())
            if parsed.path == '/browser/session':
                sidecar=self.server.sidecar
                return self.reply(200, {'csrf_token':state.csrf_token,'attack_origin':'http://127.0.0.1:'+str(sidecar.server_port)}, headers={'Set-Cookie':'bb_lab_session='+state.browser_session+'; HttpOnly; SameSite=Lax; Path=/'})
            if parsed.path == '/browser/state':
                if not authenticated(state,self.headers.get('Cookie')):
                    return self.reply(401, {'error':'No synthetic session'})
                return self.reply(200, {'notes':state.browser_notes})
            if parsed.path.startswith('/browser/cors/'):
                mode=parsed.path.split('/')[-1]
                if mode not in {'vulnerable','fixed'}:
                    return self.reply(404, {'error':'Unknown mode'})
                if not authenticated(state,self.headers.get('Cookie')):
                    return self.reply(401, {'error':'No synthetic session'})
                origin=self.headers.get('Origin','')
                expected='http://127.0.0.1:'+str(self.server.server_port)
                headers={}
                if origin and (mode=='vulnerable' or origin==expected):
                    headers={'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Credentials':'true','Vary':'Origin'}
                self.room_event={'lesson':'cors','mode':mode,'details':{'cross_origin':bool(origin and origin!=expected)}}
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
                    if context:context.record(parts[1],parts[2],200,{}, {'browser_preview':True})
                    return self.reply(200, document.encode(), "text/html; charset=utf-8", PREVIEW_CSP)
                except ValueError:
                    return self.reply(400, {"error": "Invalid preview"})
            if parsed.path == '/foundations':
                return self.reply(308,b'',"text/plain",headers={'Location':'/academy'})
            files = {"/": ("academy.html", "text/html; charset=utf-8")}
            files.update({'/academy':('academy.html','text/html; charset=utf-8'), '/academy.js':('academy.js','text/javascript; charset=utf-8'), '/academy.css':('academy.css','text/css; charset=utf-8')})
            if self.path in files:
                name, mime = files[self.path]
                return self.reply(200, Path(__file__).with_name(name).read_bytes(), mime)
            if self.path == "/outbox":
                return self.reply(200, {"messages": list(state.outbox)})
            return self.reply(404, {"error": "Not found"})

        def do_POST(self):
            self.room_event=None
            context=self.room_context()
            state=context.labs if context else labs
            if not self.valid_host():
                return self.reply(403, {"error": "Invalid host"})
            origin = self.headers.get("Origin")
            expected = "http://127.0.0.1:" + str(self.server.server_port)
            csrf_route=self.path in {"/browser/csrf/vulnerable","/browser/csrf/fixed"}
            if not csrf_route and origin and origin != expected:
                return self.reply(403, {"error": "Cross-origin requests rejected"})
            if not csrf_route and self.headers.get("Sec-Fetch-Site") == "cross-site":
                return self.reply(403, {"error": "Cross-site requests rejected"})
            try:request_path=urlsplit(self.path).path
            except ValueError:return self.reply(400,{'error':'Malformed request URL'})
            if request_path in {'/academy/catalog','/academy/evidence','/academy/resource'} or request_path.startswith('/academy/preview/'):
                return self.reply(405,{'error':{'code':'method_not_allowed','message':'Use GET for this resource'}},headers={'Allow':'GET'})
            api=re.fullmatch(r'/academy/api/(payment|access|rate|xss|code|ssrf|csrf|cors|redirect)/([a-z0-9-]+)/(vulnerable|fixed)',self.path)
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 4096:
                    return self.reply(413,{'error':{'code':'body_too_large','message':'Body must be 1..4096 bytes'}} if api else {'error':'Body must be 1..4096 bytes'})
                content_type=self.headers.get_content_type()
                if api:
                    if content_type!='application/json':return self.reply(415,{'error':{'code':'unsupported_media_type','message':'Use application/json'}})
                    input_data=strict_json(self.rfile.read(size).decode('utf-8'))
                    form={}
                else:
                    if content_type != 'application/x-www-form-urlencoded':return self.reply(415,{'error':'Use form encoding'})
                    form=parse_qs(self.rfile.read(size).decode('utf-8'),max_num_fields=8)
            except (ValueError, UnicodeError, RecursionError):
                return self.reply(400,{'error':{'code':'invalid_json','message':'Malformed or ambiguous JSON request'}} if api else {'error':'Malformed request'})
            if api:
                academy=self.academy()
                if academy is None:return self.reply(401,{'error':{'code':'session_required','message':'Start a classroom session'}})
                group,case,mode=api.groups()
                try:
                    row=next((row for row in ACADEMY_CATALOG if row['id']==case),None)
                    if row is None or row['group']!=group:return self.reply(404,{'error':{'code':'route_not_found','message':'Unknown application route'}})
                    if group=='rate' and isinstance(input_data,dict) and 'source' in input_data and self.headers.get('X-Forwarded-For'):
                        input_data={**input_data,'source':self.headers['X-Forwarded-For']}
                    result=academy.run(case,mode,input_data)
                    status,body,headers=academy_response(academy,case,mode,result)
                    return self.reply(status,body,headers=headers)
                except (ValueError,TypeError,RecursionError) as error:
                    return self.reply(400,{'error':{'code':'invalid_request','message':str(error)[:200]}})
            if self.path in {'/academy/run','/academy/reset'}:
                academy = self.academy()
                if academy is None:return self.reply(401,{'error':'Start a classroom session'})
                case=form.get('case',[''])[0]
                try:
                    if case not in {row['id'] for row in ACADEMY_CATALOG}:raise ValueError('Unknown scenario')
                    if self.path == '/academy/reset':
                        academy.reset(case)
                        return self.reply(200,{'reset':case})
                    data=strict_json(form.get('input',['{}'])[0])
                    result=academy.run(case,form.get('mode',[''])[0],data)
                    return self.reply(200,result)
                except (ValueError,TypeError,RecursionError) as error:
                    return self.reply(400,{'error':str(error)[:200]})
            if csrf_route:
                self.room_event={'lesson':'csrf','mode':self.path.split('/')[-1],'details':{'cross_origin':origin!=expected}}
                status,result=csrf_write(state,self.path.split('/')[-1],origin,expected,self.headers.get('Cookie'),form.get('note',[''])[0],form.get('csrf_token',[''])[0])
                return self.reply(status,result)
            if self.path == '/rooms/start':
                lesson=form.get('lesson',[''])[0]
                if not context:return self.reply(401,{'error':'Start a classroom session'})
                if lesson not in ROOMS:return self.reply(400,{'error':'Unknown room'})
                context.start(lesson)
                return self.reply(200,{'room':lesson,'started':True})
            if self.path == "/reset":
                state.reset()
                return self.reply(200, {"message": "Local lab state reset"})
            parts = self.path.strip("/").split("/")
            if len(parts) != 3 or parts[0] != "lab":
                return self.reply(404, {"error": "Not found"})
            self.room_event={'lesson':parts[1],'mode':parts[2],'details':{key:form.get(key,[''])[0] for key in ('email','resource','layer','value')}}
            self.room_event['details']['forwarded']=self.headers.get('X-Forwarded-For','')
            if parts[1] in {'ssrf','open-redirect','api-keys','exposed-files'}:
                status,result=exercise(parts[1],parts[2],form.get('value',[''])[0])
                return self.reply(status,result)
            if parts[1] in {"idor", "edge403"}:
                status, result = access_lesson(parts[1], parts[2], form)
                return self.reply(status, result)
            status, result = state.run(parts[1], parts[2], form.get("email", [""])[0], self.client_address[0], self.headers.get("X-Forwarded-For", ""))
            return self.reply(status, result)
    return Handler


def make_server(port=8000):
    server = LabServer(("127.0.0.1", port), handler_for(Labs()))
    server.room_sessions=RoomSessions(Labs)
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
