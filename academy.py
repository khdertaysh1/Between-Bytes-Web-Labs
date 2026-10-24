"""Fifty bounded local scenarios; no external payment, mail or network transport."""
from collections import defaultdict, deque
from decimal import Decimal, InvalidOperation
import html
import hmac
import hashlib
import ipaddress
import json
from pathlib import Path
import secrets
import sqlite3
from urllib.parse import unquote, urlsplit

CATALOG = json.loads(Path(__file__).with_name('academy_catalog.json').read_text())
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
    return value


class Academy:
    def __init__(self):
        self.states = {}
        self.evidence = defaultdict(lambda: deque(maxlen=30))
        self.previews = {}  # bounded per browser; documents expire with the classroom session
        self.flags = {}

    def reset(self, case):
        for mode in ('vulnerable', 'fixed'):
            self.states.pop((case, mode), None)
        self.evidence.pop(case, None)
        self.flags.pop(case, None)
        self.previews = {key: value for key, value in self.previews.items() if value[0] != case}

    def run(self, case, mode, data):
        if case not in CASES or mode not in {'vulnerable', 'fixed'}:
            raise ValueError('Unknown scenario or mode')
        if not isinstance(data, dict) or len(data) > 8:
            raise ValueError('Input must be a JSON object with at most eight fields')
        # Reject unsupported fields instead of silently accepting misspelled controls.
        allowed = set(CASES[case]['normal']) | set(CASES[case]['attack'])
        if set(data) - allowed:
            raise ValueError('Unsupported fields: ' + ', '.join(sorted(set(data) - allowed)))
        state = self.states.setdefault((case, mode), {})
        fixed = mode == 'fixed'
        if case.startswith('pay-'):
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
        return result

    def payment(self, kind, fixed, d, s):
        r = {'status': 200, 'impact': False, 'protected': False, 'legitimate': False}
        due, bad, detail = 10000, False, {}
        if kind in {'price', 'total', 'shipping', 'tax', 'discount', 'quantity'}:
            key = {'price':'price','total':'total','shipping':'shipping','tax':'tax','discount':'discount','quantity':'quantity'}[kind]
            expected = {'price':10000,'total':10000,'shipping':1000,'tax':1000,'discount':0,'quantity':1}[kind]
            value = integer(d, key, expected)
            if kind == 'discount':due = 10000 * (100-value) // 100
            elif kind == 'quantity':due = 10000 * value
            elif kind in {'shipping','tax'}:due = 10000 + value
            else:due = value
            trusted = 11000 if kind in {'shipping','tax'} else 10000
            bad = due != trusted
            if fixed:
                if kind == 'quantity' and not 1 <= value <= 10:
                    r['status'] = 400
                due = 10000 * value if kind == 'quantity' and 1 <= value <= 10 else trusted
                # Quantity 2..10 is legitimate and correctly priced, not a bypass.
                if kind == 'quantity' and 1 <= value <= 10:bad = False
            elif kind == 'quantity' and 1 <= value <= 10:
                bad = False
            detail = {'amount_due_minor': due, 'catalog_unit_minor':10000, 'currency':'USD'}
        elif kind == 'currency':
            value = text(d,'currency','USD'); bad = value != 'USD'
            detail = {'order_currency':'USD','interpreted_currency':'USD' if fixed else value, 'amount_minor':10000}
        elif kind == 'rounding':
            value = text(d,'amount','100.00')
            try:
                amount = Decimal(value)
                if not amount.is_finite() or abs(amount) > 1000000:raise ValueError('Invalid amount')
                due = int(amount * 100)
            except (InvalidOperation, OverflowError):raise ValueError('Invalid decimal amount')
            bad = due != 10000; detail = {'amount_due_minor':10000 if fixed else due,'catalog_unit_minor':10000}
        elif kind in {'coupon-reuse','replay','gift'}:
            count = integer(d,'repeat',1,1,8)
            if kind == 'gift':
                amount = integer(d,'spend',6000,1,10000); balance = s.get('balance',10000)
                spent = 0; credits = 0
                for _ in range(count):
                    available = balance - spent if fixed else balance
                    if available >= amount:spent += amount; credits += 1
                s['balance'] = balance - spent
                bad = s['balance'] < 0
                detail = {'balance_minor':s['balance'],'redemptions_this_run':credits,'schedule':'deterministic stale-read interleaving; not a live race'}
                # A fixed attempt against a partially spent balance demonstrates rejection.
                blocked = credits < count
            else:
                key = text(d,'coupon' if kind == 'coupon-reuse' else 'event_id','WELCOME' if kind == 'coupon-reuse' else 'evt-demo')
                if key != ('WELCOME' if kind == 'coupon-reuse' else 'evt-demo'):raise ValueError('Use the seeded coupon/event')
                used = s.get('used',0); applied = 0
                for _ in range(count):
                    if not fixed or used == 0:used += 1; applied += 1
                s['used'] = used; bad = used > 1
                detail = {'applications_total':used,'applied_this_run':applied,'entitlement': 'discount' if kind == 'coupon-reuse' else 'download credit'}
                blocked = applied < count
            r.update(impact=bad and not fixed, protected=fixed and blocked, legitimate=fixed and count==1 and (credits==1 if kind=='gift' else applied==1))
            r.update(detail);return r
        elif kind == 'status':
            claim = text(d,'status','pending'); receipt = text(d,'receipt','pending-order100')
            settled = receipt == 'settled-order100'; bad = claim == 'paid' and not settled
            detail = {'provider_ledger':'settled' if settled else 'pending','order_state':('paid' if settled else 'pending') if fixed else claim}
        elif kind == 'webhook':
            claim = text(d,'event','pending'); signature = text(d,'signature')
            verified = hmac.compare_digest(signature,'DEMO_VALID_SIGNATURE') and claim == 'settled'
            bad = claim == 'settled' and not verified
            detail = {'signature_verified':verified if fixed else False,'order_state':'paid' if claim=='settled' and (verified or not fixed) else 'pending','source':'closed signature-verdict fixture, not a real provider protocol'}
            if fixed and bad:r['status'] = 403
        elif kind == 'binding':
            claim = text(d,'payment','settled-order100'); bad = claim == 'settled-order1'
            if claim not in {'settled-order100','settled-order1'}:raise ValueError('Choose a seeded payment')
            detail = {'order_id':'order100','order_due_minor':10000,'payment_order':'order1' if bad else 'order100','payment_minor':100 if bad else 10000,'order_state':'pending' if bad and fixed else 'paid'}
            if fixed and bad:r['status'] = 409
        elif kind == 'refund':
            amount = integer(d,'refund',1000,1,1000000); previous = s.get('refunded',0)
            bad = previous + amount > 10000
            accepted = not (fixed and bad)
            if accepted:s['refunded'] = previous + amount
            detail = {'captured_minor':10000,'refunded_minor':s.get('refunded',0),'accepted':accepted}
            if not accepted:r['status'] = 409
        elif kind == 'trial':
            plan = text(d,'plan','basic')
            if plan not in {'basic','premium'}:raise ValueError('Unknown fixture plan')
            purchase = text(d,'purchase','paid')
            if purchase not in {'paid','trial'}:raise ValueError('Choose a seeded purchase type')
            bad = purchase == 'trial'
            detail = {'already_used_on':'basic','requested_plan':plan,'trial_granted':bad and not fixed,'paid_subscription_allowed':purchase=='paid'}
            # Seeded identity has already consumed a trial. A regular paid basic subscription remains available.
            if fixed and bad:r['status'] = 409
        else:raise ValueError('Unknown payment case')
        r.update(detail)
        r.update(impact=bad and not fixed, protected=bad and fixed, legitimate=not bad and fixed)
        return r

    def access(self, kind, fixed, d, s):
        objects = s.setdefault('objects', {'a-1':{'owner':'alice','tenant':'north','note':'Alice private fixture'},'b-1':{'owner':'bob','tenant':'north','note':'Bob private fixture'},'c-1':{'owner':'carol','tenant':'south','note':'Carol private fixture'}})
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
            if not isinstance(keys,list) or not 1<=len(keys)<=8 or any(not isinstance(k,str) or k not in objects for k in keys):raise ValueError('Choose seeded object IDs')
            foreign = any(objects[k]['owner']!='alice' for k in keys)
            if fixed and foreign:status = 403
            else:data = [dict(objects[k]) for k in keys]
        elif kind in {'export','download'}:
            field = 'job' if kind=='export' else 'file'; key = text(d,field)
            owner = {'export-alice':'alice','export-bob':'bob','file-alice':'alice','file-bob':'bob'}.get(key)
            if owner is None:raise ValueError('Unknown fixture reference')
            foreign = owner!='alice'
            if fixed and foreign:status = 403
            else:data = {'owner':owner,'content':'SYNTHETIC_PRIVATE_'+owner.upper()}
        elif kind == 'role':
            action = text(d,'action');claimed = text(d,'role');foreign = action=='admin'
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
            buckets = s.setdefault('buckets',{})
            if key not in buckets and len(buckets)>=64:raise ValueError('Reset this bounded exercise before adding more identities')
            accepted = min(count,max(0,3-buckets.get(key,0)));buckets[key] = buckets.get(key,0)+accepted
            totals = s.setdefault('account_totals',{});totals[account] = totals.get(account,0)+accepted
            impact = totals[account]>3
            now = 0
        if len(s.get('buckets',{}))>64:raise ValueError('Reset this bounded exercise before adding more source labels')
        return {'status':429 if accepted<count else 401,'accepted_failed_attempts':accepted,'blocked':count-accepted,'bucket':key,'impact':impact and not fixed,'protected':fixed and accepted<count,'legitimate':fixed and accepted>0,'canonical_source':canonical,'clock':now,'network':'source labels only; no proxies or outbound requests','credentials':'all attempts fail; no OTP or password guessing'}

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
                except sqlite3.Error:rows=[]
            result = rows;impact = any(row[0]=='bob' for row in rows)
            protected = fixed and query!= 'Alice' and not impact
            legitimate = fixed and query=='Alice' and len(rows)==1
        elif kind == 'nosql':
            value = d.get('password');normal = isinstance(value,str)
            if not normal and value!={'$ne':None}:raise ValueError('Use a string or the seeded operator fixture')
            result={'authenticated':(value=='DEMO_VALID_PASSWORD') if normal else not fixed,'model':'closed operator fixture; no NoSQL service'}
            impact=not normal and result['authenticated'];protected=fixed and not normal;legitimate=fixed and normal and result['authenticated']
        elif kind == 'template':
            value = text(d,'template');expression = value=='{{7*7}}'
            result = '49' if expression and not fixed else value
            impact=expression and not fixed;protected=fixed and expression;legitimate=fixed and not expression
        elif kind == 'redirect':
            value = text(d,'next');safe=value in {'/welcome','/account'}
            result={'destination':value if not fixed or safe else None,'navigation_performed':False}
            impact=not safe and not fixed;protected=not safe and fixed;legitimate=safe and fixed
        elif kind == 'ssrf':
            value = text(d,'url');fixtures={'https://public.lab/welcome':'PUBLIC_DEMO','http://internal.lab/config':'PRIVATE_DEMO_CONFIG'}
            if value not in fixtures:raise ValueError('Only the two fixture URLs exist; no network transport')
            private=value=='http://internal.lab/config'
            result={'content':fixtures[value] if not fixed or not private else None,'transport':'in-memory mapping, no DNS, sockets or files'}
            impact=private and not fixed;protected=private and fixed;legitimate=not private and fixed
        return {'status':403 if protected and kind in {'nosql','ssrf','redirect'} else 200,'data':result,'impact':impact,'protected':protected,'legitimate':legitimate}


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
        parsed=urlsplit(value)
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
    return prelude+body+'<script>setTimeout(()=>send("academy-rendered",{text:document.getElementById("output")?.textContent||document.getElementById("output")?.value||"",mode:'+json.dumps(mode)+'}),450);</script>'
