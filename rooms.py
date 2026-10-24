"""Bounded per-browser classroom sessions and server-observed room evidence."""
from collections import deque
from http.cookies import SimpleCookie
import secrets
import time

ROOMS={'enumeration','rate-limit','email-flood','idor','edge403','reflected-xss','dom-xss','csrf','cors','open-redirect','ssrf','api-keys','exposed-files'}

class RoomContext:
    def __init__(self,factory):
        self.labs=factory();self.touched=time.monotonic();self.start('enumeration')
    def start(self,lesson):
        self.lesson=lesson;self.events=deque(maxlen=120);self.flag='BB{'+secrets.token_urlsafe(18)+'}'
    def record(self,lesson,mode,status,body,details):
        if lesson!=self.lesson:return
        self.events.append({'lesson':lesson,'mode':mode,'status':status,'body':body,**details})
    def report(self):
        e=list(self.events);has=lambda mode,p:any(r['mode']==mode and p(r) for r in e)
        kind=self.lesson;assisted=kind in {'reflected-xss','dom-xss','cors'}
        if kind=='enumeration':
            checks=[has('vulnerable',lambda r:r['status']==200),has('vulnerable',lambda r:r['status']==404),len({r.get('email') for r in e if r['mode']=='fixed' and r['status']==202})>=2]
        elif kind=='rate-limit':
            checks=[has('vulnerable',lambda r:r['status']==429),has('vulnerable',lambda r:r['status']==401 and bool(r.get('forwarded'))),has('fixed',lambda r:r['status']==429 and bool(r.get('forwarded')))]
        elif kind=='email-flood':
            checks=[sum(m['mode']=='vulnerable' for m in self.labs.outbox)>=4,len([r for r in e if r['mode']=='fixed' and r['status']==202])>=4,sum(m['mode']=='fixed' for m in self.labs.outbox)==1]
        elif kind=='idor':
            checks=[has('vulnerable',lambda r:r.get('body',{}).get('invoice',{}).get('owner')=='bob'),has('fixed',lambda r:r['status']==403),has('fixed',lambda r:r.get('body',{}).get('invoice',{}).get('owner')=='alice')]
        elif kind=='edge403':checks=[has('vulnerable',lambda r:r['status']==200),has('fixed',lambda r:r['status']==403 and r.get('layer')=='origin'),has('fixed',lambda r:r['status']==403 and r.get('layer')=='edge')]
        elif kind=='csrf':checks=[has('vulnerable',lambda r:r['status']==200 and r.get('cross_origin')),has('fixed',lambda r:r['status']==403 and r.get('cross_origin')),has('fixed',lambda r:r['status']==200 and not r.get('cross_origin'))]
        elif kind=='cors':checks=[has('vulnerable',lambda r:r['status']==200 and r.get('cross_origin')),has('fixed',lambda r:r['status']==200 and r.get('cross_origin')),has('fixed',lambda r:r['status']==200 and not r.get('cross_origin'))]
        elif kind in {'reflected-xss','dom-xss'}:checks=[has('vulnerable',lambda r:r['status']==200),has('fixed',lambda r:r['status']==200)]
        elif kind=='open-redirect':checks=[has('vulnerable',lambda r:r.get('body',{}).get('external') is True),has('fixed',lambda r:r['status']==400),has('fixed',lambda r:r.get('body',{}).get('external') is False)]
        elif kind=='ssrf':checks=[has('vulnerable',lambda r:r.get('body',{}).get('private') is True),has('fixed',lambda r:r['status']==403),has('fixed',lambda r:r['status']==200)]
        elif kind=='api-keys':checks=[has('vulnerable',lambda r:'SERVER_API_SECRET=' in r.get('body',{}).get('content','')),has('fixed',lambda r:'PUBLIC_KEY=' in r.get('body',{}).get('content','') and 'SERVER_API_SECRET=' not in r.get('body',{}).get('content',''))]
        else:checks=[has('vulnerable',lambda r:'DB_PASSWORD=' in r.get('body',{}).get('content','')),has('fixed',lambda r:r['status']==404),has('fixed',lambda r:r['status']==200 and r.get('value')=='/public/readme.txt')]
        ready=all(checks)
        return {'room':kind,'server_checks':checks,'requests_observed':len(e),'verification':'browser-assisted' if assisted else 'server-observed',
                'ready':ready,'flag':self.flag if ready and not assisted else None,
                'note':'Browser execution/readability must also be checked in the browser.' if assisted else 'Flag reflects this local model only, not a certificate or secure exam.'}

class RoomSessions:
    def __init__(self,factory):self.factory=factory;self.items={}
    def resolve(self,cookie):
        try:
            value=SimpleCookie(cookie or '').get('bb_room')
            key=value.value if value else ''
        except Exception:key=''
        context=self.items.get(key)
        if context and time.monotonic()-context.touched<1800:
            context.touched=time.monotonic();return context
        return None
    def create(self,cookie):
        current=self.resolve(cookie)
        if current:return None,current
        now=time.monotonic()
        self.items={key:value for key,value in self.items.items() if now-value.touched<1800}
        if len(self.items)>=32:raise ValueError('Local classroom session capacity reached; retry after expiry or restart.')
        key=secrets.token_hex(24);context=RoomContext(self.factory);self.items[key]=context
        return key,context
