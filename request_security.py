"""Closed request-policy exercises. Never performs DNS, HTTP, file IO or navigation.

Origin, cookie and DNS fields are fixture inputs, not browser-controlled headers.
CORS readability is an explicit policy model, not evidence from a real browser.
"""
from urllib.parse import urlsplit, unquote

GROUPS = {'ssrf', 'csrf', 'cors', 'redirect'}
APP = 'https://app.lab'
PUBLIC = 'https://public.lab/welcome'


def string(d, key):
    value=d[key]
    if not isinstance(value,str) or len(value)>1024 or any(ord(c)<32 or ord(c)==127 for c in value):
        raise ValueError('Expected a short string without control characters: '+key)
    return value


def execute(case, group, fixed, d, state):
    if group=='ssrf':return ssrf(case,fixed,d)
    if group=='redirect':return redirect(case,fixed,d)
    if group=='csrf':return csrf(case,fixed,d,state)
    if group=='cors':return cors(case,fixed,d)
    raise ValueError('Unknown request-policy lab')


def outcome(status, data, impact=False, protected=False, legitimate=False):
    return dict(status=status,data=data,impact=impact,protected=protected,legitimate=legitimate)


SSRF_FIXTURES = {
 'code-ssrf': 'http://internal.lab/config',
 'ssrf-loopback': 'http://127.0.0.1/admin',
 'ssrf-redirect': 'https://public.lab/redirect',
 'ssrf-userinfo': 'https://public.lab@internal.lab/config',
 'ssrf-dns': 'https://changing.lab/config',
 'ssrf-port': 'https://public.lab:8443/admin',
}

def ssrf(case, fixed, d):
    url=string(d,'url');attack=SSRF_FIXTURES[case]
    if url not in {PUBLIC,attack}:raise ValueError('Choose a listed fixture URL; arbitrary destinations are not fetched')
    private=url==attack
    trace=[{'step':'parse','host':urlsplit(url).hostname,'port':urlsplit(url).port or (443 if url.startswith('https:') else 80)}]
    if private and case=='ssrf-redirect':trace.append({'step':'redirect','destination':'http://internal.lab/config'})
    if private and case=='ssrf-dns':trace.extend([{'step':'validation_dns','address':'203.0.113.10'},{'step':'connection_dns','address':'127.0.0.1'}])
    blocked=fixed and private
    trace.append({'step':'policy','allowed':not blocked})
    if not blocked:trace.append({'step':'fixture_read','resource':'private-config' if private else 'public-welcome'})
    return outcome(403 if blocked else 200,{'content':None if blocked else 'PRIVATE_DEMO_CONFIG' if private else 'PUBLIC_DEMO','trace':trace,'transport':'closed mapping; no DNS, sockets or files'},private and not fixed,blocked,fixed and not private)


REDIRECT_ATTACKS={
 'code-redirect':'https://outside.example/landing',
 'redirect-relative':'//outside.example/landing',
 'redirect-backslash':r'/\outside.example/landing',
 'redirect-encoded':'%2F%2Foutside.example/landing',
 'redirect-suffix':'https://app.lab.outside.example/landing',
 'redirect-nested':'/continue?next=https%3A%2F%2Foutside.example%2Flanding',
}

def redirect(case,fixed,d):
    raw=string(d,'next')
    if case=='code-redirect':
        # Retain the original direct-URL exercise's arbitrary local path control.
        parsed=urlsplit(raw)
        unsafe=bool(parsed.scheme or parsed.netloc) or raw not in {'/account','/welcome'}
        destination=raw
    else:
        if raw not in {'/account','/welcome',REDIRECT_ATTACKS[case]}:raise ValueError('Choose a listed destination fixture')
        destination=unquote(raw).replace('\\','/')
        if case=='redirect-nested' and raw==REDIRECT_ATTACKS[case]:destination='https://outside.example/landing'
        unsafe=raw==REDIRECT_ATTACKS[case]
    external=bool(urlsplit(destination).scheme or urlsplit(destination).netloc)
    blocked=fixed and unsafe
    data={'submitted':raw,'destination':None if blocked else destination,'external':external,'navigation_performed':False,'policy_allowed':not blocked,'model':'destination decision only; no browser navigation'}
    return outcome(403 if blocked else 200,data,external and not fixed,blocked,fixed and not unsafe)


def csrf(case,fixed,d,state):
    origin=string(d,'origin');token=string(d,'token') if 'token' in d else '';note=string(d,'note');method=string(d,'method');ctype=string(d,'content_type')
    if origin not in {APP,'https://untrusted.lab','https://app.lab.untrusted.lab'}:raise ValueError('Choose an origin from this exercise')
    if token not in {'session-alice-token','session-bob-token','','unknown-token'}:raise ValueError('Unknown token fixture')
    if method not in {'POST','GET'}:raise ValueError('Choose POST or GET')
    if ctype not in {'application/x-www-form-urlencoded','text/plain','application/json'}:raise ValueError('Unsupported content-type fixture')
    if not 1<=len(note)<=80:raise ValueError('Note must contain 1 to 80 characters')
    correct=token=='session-alice-token'
    if fixed:
        status=405 if method!='POST' else 415 if ctype!='application/x-www-form-urlencoded' else 403 if origin!=APP or not correct else 200
    else:
        # Each fixture models one concrete missing check, rather than ignoring everything.
        valid_form=method=='POST' and ctype=='application/x-www-form-urlencoded'
        accepted=correct and valid_form
        if case=='csrf-missing' and 'token' not in d and valid_form:accepted=True
        if case=='csrf-empty' and 'token' in d and token=='' and valid_form:accepted=True
        if case=='csrf-binding' and token=='session-bob-token' and valid_form:accepted=True
        if case=='csrf-origin' and origin.startswith(APP) and valid_form:accepted=True
        if case=='csrf-get' and method=='GET' and not token:accepted=True
        if case=='csrf-content-type' and method=='POST' and ctype=='text/plain' and not token:accepted=True
        status=200 if accepted else 403
    before=state.get('note','Original profile note')
    dangerous=origin!=APP or not correct or method!='POST' or ctype!='application/x-www-form-urlencoded'
    if status==200:state['note']=note
    data={'actor':'alice','before':before,'note':state.get('note','Original profile note'),'changed':status==200 and before!=note,'operation_applied':status==200,'request_origin':origin,'method':method,'token_bound_to_session':correct,'model':'request-policy simulation; Origin, tokens and cookies are fixture inputs, not a browser CSRF proof'}
    return outcome(status,data,dangerous and status==200 and not fixed,dangerous and status>=400 and fixed,fixed and not dangerous and status==200)


CORS_ORIGINS={
 'cors-reflect':'https://untrusted.lab',
 'cors-null':'null',
 'cors-prefix':'https://app.lab.outside.example',
 'cors-suffix':'https://notapp.lab',
 'cors-scheme':'http://app.lab',
 'cors-preflight':'https://untrusted.lab',
}

def cors(case,fixed,d):
    origin=string(d,'origin')
    if origin not in {APP,CORS_ORIGINS[case]}:raise ValueError('Choose an origin listed for this case')
    if type(d['credentials']) is not bool:raise ValueError('credentials must be boolean')
    credentials=d['credentials'];trusted=origin==APP
    weak_allowed={
        'cors-reflect':True,
        'cors-null':origin=='null' or trusted,
        'cors-prefix':origin.startswith(APP),
        'cors-suffix':(urlsplit(origin).hostname or '').endswith('app.lab'),
        'cors-scheme':urlsplit(origin).hostname=='app.lab',
        'cors-preflight':True,
    }[case]
    allowed=trusted if fixed else weak_allowed
    # Private endpoint always checks the session, separately from CORS.
    if not credentials:
        return outcome(401,{'response_headers':{},'readable':False,'private':None,'model':'CORS policy simulation; browser execution not tested'})
    headers={'Vary':'Origin'}
    if allowed:headers.update({'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Credentials':'true'})
    preflight=None
    if case=='cors-preflight':
        preflight={'status':204 if allowed else 403,'requested_method':'GET','requested_headers':'X-Lab-Request','allowed':allowed}
    # A simple GET may return 200 even when its response cannot be read by another origin.
    status=200
    readable=allowed and (preflight is None or preflight['allowed'])
    data={'response_headers':headers,'http_status_of_fixture_get':200,'readable':readable,'private':'DEMO_PRIVATE_CORS_DATA' if readable else None,'preflight':preflight,'model':'CORS policy simulation; supplied Origin is not a browser header; no cross-origin browser proof'}
    return outcome(status,data,not trusted and readable and not fixed,not trusted and not readable and fixed,trusted and readable and fixed)
