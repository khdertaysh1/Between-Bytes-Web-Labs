"""Local signature-verification lesson. Public fixture key/time; not a JWT library."""
import base64
import hashlib
import hmac
import json
import re

KEY = b'PUBLIC-CLASSROOM-KEY-NOT-FOR-REAL-AUTH'
NOW = 2000000000

def encode(value):
    return base64.urlsafe_b64encode(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).rstrip(b'=').decode()

def fixture(role='viewer', signed=True):
    head=encode({'alg':'HS256','typ':'JWT'})
    body=encode({'sub':'alice','role':role,'exp':NOW+3600})
    sig=base64.urlsafe_b64encode(hmac.new(KEY,(head+'.'+body).encode(),hashlib.sha256).digest()).rstrip(b'=').decode()
    return head+'.'+body+'.'+(sig if signed else 'invalid-signature')

def execute(fixed, token):
    if not isinstance(token,str) or not 1<=len(token)<=1024:
        raise ValueError('Token must be a string of 1..1024 characters')
    parts=token.split('.')
    if len(parts)!=3 or any(not re.fullmatch(r'[A-Za-z0-9_-]*',p) for p in parts):
        raise ValueError('Use three base64url segments')
    def unique(pairs):
        result={}
        for k,v in pairs:
            if k in result:raise ValueError('Duplicate token claim')
            result[k]=v
        return result
    def decode(p):
        raw=base64.b64decode(p+'='*((-len(p))%4),altchars=b'-_',validate=True)
        data=json.loads(raw.decode('utf-8'),object_pairs_hook=unique)
        if not isinstance(data,dict):raise ValueError('Token header and claims must be objects')
        return data
    try:head,claims=decode(parts[0]),decode(parts[1])
    except (ValueError,UnicodeError) as e:raise ValueError('Malformed token JSON or base64url') from e
    if set(head)!={'alg','typ'} or set(claims)!={'sub','role','exp'} or head['typ']!='JWT' or claims['sub']!='alice' or claims['role'] not in ('viewer','admin') or type(claims['exp']) is not int:
        raise ValueError('Use the documented local token contract')
    expected=base64.urlsafe_b64encode(hmac.new(KEY,('.'.join(parts[:2])).encode(),hashlib.sha256).digest()).rstrip(b'=').decode()
    verified=head['alg']=='HS256' and hmac.compare_digest(expected,parts[2]) and claims['exp']>NOW
    denied=fixed and not verified
    data={'authenticated':not denied,'effective_role':None if denied else claims['role'],
          'admin_panel':not denied and claims['role']=='admin','signature_verified':verified,
          'clock':'fixed classroom time 2000000000; not system time','verification':'real local HMAC-SHA256; public synthetic key'}
    return dict(status=401 if denied else 200,data=data,impact=not fixed and not verified and claims['role']=='admin',
                protected=denied,legitimate=fixed and verified,error_code='invalid_token' if denied else None)
