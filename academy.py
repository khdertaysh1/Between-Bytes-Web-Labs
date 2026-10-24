"""Bounded local scenarios; no external payment, mail or network transport."""
from collections import defaultdict, deque
from commerce import execute as checkout_execute, provider_signature
from request_security import execute as request_execute, GROUPS as REQUEST_GROUPS
import html
import hashlib
import ipaddress
import json
from pathlib import Path
import secrets
import re
import sqlite3
from urllib.parse import unquote, urlsplit

CATALOG = json.loads(Path(__file__).with_name('academy_catalog.json').read_text())
for row in CATALOG:
    if row['id']=='pay-webhook':row['normal']['signature']=provider_signature()
CASES = {row['id']: row for row in CATALOG}


def integer(data, key, default=0, low=-1000000, high=1000000):
    value = data.get(key, default)
    if type(value) is not int or not low <= value <= high:
        raise ValueError('Expected bounded integer: ' + key)
    return value


def text(data, key, default=''):
    value = data.get(key, default)
    if not isinstance(value, str) or len(value) > 1024:
        raise ValueError('Expected short string: ' + key)
    try:value.encode('utf-8')
    except UnicodeError:raise ValueError('Invalid Unicode string: '+key)
    return value


def validate_strings(value,depth=0):
    if depth>8:raise ValueError('Input nesting exceeds the local request contract')
    if isinstance(value,str):
        try:value.encode('utf-8')
        except UnicodeError:raise ValueError('Invalid Unicode string')
    elif isinstance(value,dict):
        for key,item in value.items():
            if not isinstance(key,str):raise ValueError('Object field names must be strings')
            validate_strings(key,depth+1);validate_strings(item,depth+1)
    elif isinstance(value,list):
        for item in value:validate_strings(item,depth+1)


class Academy:
    def __init__(self):
        self.states = {}
        self.evidence = defaultdict(lambda: deque(maxlen=30))
        self.previews = {}  # bounded per browser; documents expire with the classroom session
        self.flags = {}
        self.latest = {}

    def reset(self, case):
        for mode in ('vulnerable', 'fixed'):
            self.states.pop((case, mode), None)
            self.latest.pop((case, mode), None)
        self.evidence.pop(case, None)
        self.flags.pop(case, None)
        self.previews = {key: value for key, value in self.previews.items() if value[0] != case}

    def run(self, case, mode, data):
        if case not in CASES or mode not in {'vulnerable', 'fixed'}:
            raise ValueError('Unknown scenario or mode')
        if not isinstance(data, dict) or len(data) > 8:
            raise ValueError('Input must be a JSON object with at most eight fields')
        validate_strings(data)
        # Reject unsupported fields instead of silently accepting misspelled controls.
        allowed = set(CASES[case]['normal']) | set(CASES[case]['attack'])
        if set(data) - allowed:
            raise ValueError('Unsupported fields: ' + ', '.join(sorted(set(data) - allowed)))
        required=set(CASES[case]['normal'])
        if case=='csrf-missing':required.discard('token')
        if required-set(data):
            raise ValueError('Missing required fields: '+', '.join(sorted(required-set(data))))
        state = self.states.setdefault((case, mode), {})
        fixed = mode == 'fixed'
        if CASES[case]['group'] in REQUEST_GROUPS:
            result = request_execute(case, CASES[case]['group'], fixed, data, state)
        elif case.startswith('pay-'):
            result = self.payment(case[4:], fixed, data, state)
        elif case.startswith('acl-'):
            result = self.access(case[4:], fixed, data, state)
        elif case.startswith('rate-'):
            result = self.rate(case[5:], fixed, data, state)
        elif case.startswith('xss-'):
            value = text(data, 'value')
            if case == 'xss-stored':
                state['comment'] = value  # persisted until a separate preview GET renders it
            token = secrets.token_hex(16)
            self.previews[token] = (case, mode, state.get('comment', value), token)
            while len(self.previews) > 80:
                self.previews.pop(next(iter(self.previews)))
            result = {'status': 200, 'preview': '/academy/preview/' + token,
                      'token': token, 'verification': 'browser-assisted',
                      'impact': False, 'protected': False, 'legitimate': False,
                      'source': 'fragment' if case == 'xss-dom-fragment' else 'search' if case == 'xss-dom-query' else 'stored comment' if case == 'xss-stored' else 'value',
                      'value': value}
        else:
            result = self.code(case[5:], fixed, data)
        result.update(case=case, mode=mode, synthetic=True)
        event = {k: v for k, v in result.items() if k not in {'token', 'value'}}
        event['input_sha256'] = hashlib.sha256(json.dumps(data,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode()).hexdigest()
        self.evidence[case].append(event)
        events = self.evidence[case]
        checks = {
            'weak_impact': any(e['mode'] == 'vulnerable' and e.get('impact') for e in events),
            'fixed_rejects': bool({e['input_sha256'] for e in events if e['mode']=='vulnerable' and e.get('impact')} & {e['input_sha256'] for e in events if e['mode']=='fixed' and e.get('protected')}),
            'fixed_control': any(e['mode'] == 'fixed' and e.get('legitimate') for e in events),
        }
        if all(checks.values()):
            self.flags.setdefault(case, 'BB{' + secrets.token_urlsafe(16) + '}')
        result['checks'] = checks
        result['flag'] = self.flags.get(case)
        result['request_id'] = 'req_'+secrets.token_hex(8)
        self.latest[(case,mode)] = result
        return result

    def payment(self, kind, fixed, d, s):
        return checkout_execute(kind,fixed,d,s,integer,text)

    def access(self, kind, fixed, d, s):
        objects = s.setdefault('objects', {'a-1':{'id':'a-1','owner':'alice','tenant':'north','invoice_number':'INV-2026-1041','amount':12900,'currency':'USD','note':'Quarterly support renewal'},'b-1':{'id':'b-1','owner':'bob','tenant':'north','invoice_number':'INV-2026-1042','amount':24900,'currency':'USD','note':'Private consulting retainer'},'c-1':{'id':'c-1','owner':'carol','tenant':'south','invoice_number':'INV-2026-2048','amount':48000,'currency':'USD','note':'Infrastructure maintenance contract'}})
        foreign = False; data = None; status = 200
        if kind in {'read','write','delete','nested','tenant'}:
            key = text(d,'child' if kind=='nested' else 'object')
            obj = objects.get(key)
            if obj is None:return {'status':404,'impact':False,'protected':False,'legitimate':False,'error':'Fixture object not found'}
            foreign = obj['owner']!='alice' or (kind=='tenant' and text(d,'tenant')!='north') or (kind=='nested' and text(d,'parent')!='alice')
            if fixed and foreign:status = 403
            elif kind == 'write':obj['note']=text(d,'note');data = dict(obj)
            elif kind == 'delete':del objects[key];data = {'deleted':key,'owner':obj['owner']}
            else:data = dict(obj)
        elif kind == 'batch':
            keys = d.get('objects')
            if not isinstance(keys,list) or not 1<=len(keys)<=8 or any(not isinstance(k,str) or len(k)>1024 for k in keys):raise ValueError('Choose up to eight short object IDs')
            if any(k not in objects for k in keys):return {'status':404,'data':None,'impact':False,'protected':False,'legitimate':False}
            foreign = any(objects[k]['owner']!='alice' for k in keys)
            if fixed and foreign:status = 403
            else:data = [dict(objects[k]) for k in keys]
        elif kind in {'export','download'}:
            field = 'job' if kind=='export' else 'file'; key = text(d,field)
            references={'export-alice':'alice','export-bob':'bob'} if kind=='export' else {'file-alice':'alice','file-bob':'bob'}
            owner=references.get(key)
            if owner is None:return {'status':404,'data':None,'impact':False,'protected':False,'legitimate':False}
            foreign = owner!='alice'
            if fixed and foreign:status = 403
            else:data = {'owner':owner,'filename':'invoices-'+owner+'-2026.csv','content':'invoice_id,customer,amount,currency\n'+('INV-2026-1041,alice,12900,USD' if owner=='alice' else 'INV-2026-1042,bob,24900,USD'),'content_type':'text/csv'}
        elif kind == 'role':
            action = text(d,'action');claimed = text(d,'role');foreign = action=='admin'
            if claimed not in {'viewer','admin'}:raise ValueError('Choose viewer or admin role')
            if action not in {'view','admin'}:raise ValueError('Choose view or admin')
            if foreign and (fixed or claimed!='admin'):status=403
            else:data = {'admin_panel':foreign,'effective_role':'viewer' if fixed else claimed}
            foreign = foreign and claimed=='admin'
        elif kind == 'mass':
            if 'is_admin' in d and type(d['is_admin']) is not bool:raise ValueError('is_admin must be boolean')
            foreign = d.get('is_admin',False)
            if fixed and 'is_admin' in d:status = 403
            else:
                s['profile']={'display_name':text(d,'display_name'),'is_admin':False if fixed else d.get('is_admin',False)}
                data = dict(s['profile'])
        else:raise ValueError('Unknown access case')
        return {'status':status,'actor':'alice','session_tenant':'north','data':data,'impact':foreign and status==200 and not fixed,'protected':foreign and status==403 and fixed,'legitimate':not foreign and status==200 and fixed}

    def rate(self, kind, fixed, d, s):
        count = integer(d,'attempts',1,1,8); account = text(d,'account','alice').strip().casefold()
        source = text(d,'source','192.0.2.1')
        if kind in {'xff','ip-pool','ipv6'}:
            try:canonical = str(ipaddress.ip_address(source))
            except ValueError:raise ValueError('Use a documentation-range fixture IP')
            address = ipaddress.ip_address(source)
            if not any(address in ipaddress.ip_network(net) for net in (['192.0.2.0/24','198.51.100.0/24','203.0.113.0/24'] if address.version==4 else ['2001:db8::/32'])):
                raise ValueError('Use RFC documentation-range source labels only')
        else:canonical = source
        if kind == 'window':
            now = integer(d,'time',59,0,120)
            if now < s.get('last_time',0):raise ValueError('Synthetic clock must move forward; reset the round')
            s['last_time'] = now
            accepted_times = s.setdefault('times',[])
            recent = [t for t in accepted_times if now-t < 60]
            allowed = max(0,3-len(recent)) if fixed else max(0,3-s.setdefault('windows',{}).get(now//60,0))
            accepted = min(count,allowed);accepted_times.extend([now]*accepted)
            windows = s.setdefault('windows',{})
            windows[now//60]=windows.get(now//60,0)+accepted
            impact = len([t for t in accepted_times if now-t<60])>3
            key = 'rolling 60 seconds' if fixed else 'minute '+str(now//60)
        else:
            if fixed:key = 'account:'+account
            elif kind in {'xff','ip-pool','ipv6'}:key = 'source:'+source
            elif kind == 'case':key = 'account:'+text(d,'account','alice')
            elif kind == 'route':key = 'route:'+text(d,'route','login')+':'+account
            else:key = 'challenge:'+text(d,'challenge','one')+':'+account
            totals=s.setdefault('account_totals',{})
            if account not in totals and len(totals)>=64:raise ValueError('Reset this exercise before adding more account identities')
            buckets = s.setdefault('buckets',{})
            if key not in buckets and len(buckets)>=64:raise ValueError('Reset this bounded exercise before adding more identities')
            accepted = min(count,max(0,3-buckets.get(key,0)));buckets[key] = buckets.get(key,0)+accepted
            totals = s.setdefault('account_totals',{});totals[account] = totals.get(account,0)+accepted
            impact = totals[account]>3
            now = 0
        if len(s.get('buckets',{}))>64:raise ValueError('Reset this bounded exercise before adding more source labels')
        return {'status':429 if accepted<count else 401,'accepted_failed_attempts':accepted,'blocked':count-accepted,'bucket':key,'impact':impact and not fixed,'protected':fixed and accepted<count,'legitimate':fixed and accepted>0,'remaining':max(0,3-(len([t for t in s.get('times',[]) if now-t<60]) if kind=='window' and fixed else s.get('windows',{}).get(now//60,0) if kind=='window' else s.get('buckets',{}).get(key,0))),'canonical_source':canonical,'clock':now,'network':'source labels only; no proxies or outbound requests','credentials':'all attempts fail; no OTP or password guessing'}

    def code(self, kind, fixed, d):
        impact = False; protected = False; legitimate = False; result = None
        if kind == 'sqli':
            query = text(d,'query')
            # Genuine SQLite parser, but only two synthetic rows in a new in-memory database.
            with sqlite3.connect(':memory:') as db:
                db.executescript("CREATE TABLE notes(owner TEXT, note TEXT); INSERT INTO notes VALUES ('alice','Alice note'),('bob','Bob private note');")
                try:
                    if fixed:rows=db.execute('SELECT owner,note FROM notes WHERE owner=? AND note LIKE ?',('alice','%'+query+'%')).fetchall()
                    else:rows=db.execute("SELECT owner,note FROM notes WHERE owner='alice' AND note LIKE '%"+query+"%'").fetchall()
                except sqlite3.Error:return {'status':400,'data':None,'error_code':'invalid_query','impact':False,'protected':False,'legitimate':False}
            result = rows;impact = any(row[0]=='bob' for row in rows)
            protected = fixed and query!= 'Alice' and not impact
            legitimate = fixed and query=='Alice' and len(rows)==1
        elif kind == 'nosql':
            value = d.get('password');normal = isinstance(value,str)
            if not normal and value!={'$ne':None}:raise ValueError('Use a string or the seeded operator fixture')
            stored_password='DEMO_VALID_PASSWORD'
            matches=(stored_password==value) if normal else stored_password!=value['$ne']
            result={'authenticated':matches and (normal or not fixed),'model':'bounded document predicate; no external database'}
            impact=not normal and result['authenticated'];protected=fixed and not normal;legitimate=fixed and normal and result['authenticated']
        elif kind == 'template':
            value = text(d,'template')
            match=re.fullmatch(r'\{\{\s*(-?\d{1,4})\s*([*+\-])\s*(-?\d{1,4})\s*\}\}',value)
            expression=bool(match)
            if match and not fixed:
                left,right=int(match[1]),int(match[3]);op=match[2]
                result=str(left*right if op=='*' else left+right if op=='+' else left-right)
            else:result=value
            impact=expression and not fixed;protected=fixed and expression;legitimate=fixed and not expression
        elif kind == 'redirect':
            value = text(d,'next');safe=value in {'/welcome','/account'}
            if any(ord(ch)<32 or ord(ch)==127 for ch in value):raise ValueError('Control characters are not allowed in destinations')
            parsed=urlsplit(value);external=bool(parsed.scheme or parsed.netloc) 
            result={'destination':value if not fixed or safe else None,'external':external,'navigation_performed':False}
            impact=external and not fixed;protected=not safe and fixed;legitimate=safe and fixed
        elif kind == 'ssrf':
            value = text(d,'url');fixtures={'https://public.lab/welcome':'PUBLIC_DEMO','http://internal.lab/config':'PRIVATE_DEMO_CONFIG'}
            if value not in fixtures:raise ValueError('Only the two fixture URLs exist; no network transport')
            private=value=='http://internal.lab/config'
            result={'content':fixtures[value] if not fixed or not private else None,'transport':'in-memory mapping, no DNS, sockets or files'}
            impact=private and not fixed;protected=private and fixed;legitimate=not private and fixed
        return {'status':401 if kind=='nosql' and not protected and not result['authenticated'] else 422 if protected and kind=='nosql' else 403 if protected and kind in {'ssrf','redirect'} else 200,'data':result,'impact':impact,'protected':protected,'legitimate':legitimate}


def preview_document(case, mode, value, token):
    """Executable HTML only in a CSP-sandboxed opaque-origin subframe."""
    kind = case[4:];fixed = mode=='fixed'
    value = html.unescape(value) if kind=='entity' else unquote(unquote(value)) if kind=='double-url' else value
    safe = html.escape(value,quote=True)
    # The JSON representation must not terminate a surrounding HTML script element.
    js = json.dumps(value).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
    prelude = '''<!doctype html><meta charset="utf-8"><title>Between Bytes context preview</title><script>
const token=TOKEN;
function send(type,extra={}){parent.postMessage({type,token,...extra},'*')}
window.alert=v=>send('academy-executed',{value:String(v).slice(0,80)});
window.addEventListener('error',e=>send('academy-error',{message:e.message.slice(0,120)}));
</script><h3>Northstar preview · synthetic data</h3>'''.replace('TOKEN',json.dumps(token))
    if kind in {'html','stored'}:body='<div id="output">'+(safe if fixed else value)+'</div>'
    elif kind in {'attr-double','attr-single','attr-bare'}:
        if fixed:body='<input id="output" value="'+safe+'">'
        elif kind=='attr-double':body='<input id="output" value="'+value+'">'
        elif kind=='attr-single':body="<input id='output' value='"+value+"'>"
        else:body='<input id="output" value='+value+'>'
    elif kind in {'script','template'}:
        if fixed:statement='const input='+js+';'
        elif kind=='script':statement="const input='"+value+"';"
        else:statement='const input=`'+value+'`;'
        body='<div id="output"></div><script>'+statement+'document.getElementById("output").textContent=input;</script>'
    elif kind=='url':
        allowed=value in {'/welcome','/account'}
        href = value if not fixed or allowed else '#blocked'
        body='<a id="output" href="'+html.escape(href,quote=True)+'">Local fixture link</a><script>const link=document.getElementById("output");send("academy-url-policy",{dangerous:link.getAttribute("href").toLowerCase().startsWith("javascript:"),href:link.getAttribute("href")});</script>'
    else:
        source = 'input'
        setup='const input='+js+';'
        if kind=='dom-fragment':setup='';source='decodeURIComponent(location.hash.slice(1))'
        if kind=='dom-query':setup='';source='new URLSearchParams(location.search).get("search")||""'
        sink='textContent' if fixed else 'innerHTML'
        body='<div id="output"></div><script>'+setup+'document.getElementById("output").'+sink+'='+source+';</script>'
    # Report delivery separately from execution. A timeout with no alert is not a proof of all-XSS absence.
    return prelude+body+'<script>setTimeout(()=>send("academy-rendered",{dom:(document.getElementById("output")?.outerHTML||"").slice(0,12000),text:document.getElementById("output")?.textContent||document.getElementById("output")?.value||"",mode:'+json.dumps(mode)+'}),450);</script>'
