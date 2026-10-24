"""Deterministic fixtures: no filesystem access and no outbound SSRF transport."""
from urllib.parse import urlsplit

SECRET = 'DEMO_ONLY_NOT_A_VALID_API_SECRET'
FIXTURES = {
    '/public/readme.txt': ('public', 'Public training document.'),
    '/robots.txt': ('public', 'Disallow: /.env.backup\nDisallow: /backups/settings.env\n# assets: /assets/checkout.js /assets/billing.js'),
    '/assets/checkout.js': ('secret', 'PUBLIC_KEY="demo_publishable_ui";\nSERVER_API_SECRET="'+SECRET+'";'),
    '/assets/billing.js': ('secret', 'PUBLIC_KEY="demo_publishable_ui";\nSERVER_API_SECRET="'+SECRET+'_EXAM";'),
    '/.env.backup': ('private', 'APP_ENV=training\nDB_PASSWORD=DEMO_FAKE_PASSWORD\nSERVER_API_SECRET='+SECRET),
    '/backups/settings.env': ('private', 'APP_ENV=assessment\nDB_PASSWORD=DEMO_FAKE_EXAM_PASSWORD'),
    '/.git/config': ('private', '[remote "origin"]\nurl = https://repository.example/training.git'),
}

def exercise(kind, mode, value):
    if mode not in {'vulnerable','fixed'}:
        return 404, {'error':'Unknown mode'}
    if not isinstance(value,str) or len(value)>500:
        return 400, {'error':'Invalid input'}
    if kind == 'ssrf':
        # Deliberately a transport model. Never resolve, connect, or read local files.
        try:
            url=urlsplit(value)
            valid=url.scheme=='http' and not url.username and not url.password and url.port in (None,80) and not url.fragment and not url.query
        except ValueError:
            valid=False
        if not valid or url.hostname not in {'public.lab','internal.lab'}:
            return 400, {'error':'Only synthetic public.lab/internal.lab fixtures exist','simulation':True}
        path=url.path or '/'
        if mode=='fixed' and url.hostname!='public.lab':
            return 403, {'error':'Destination not allowed','simulation':True}
        if url.hostname=='public.lab' and path=='/redirect':
            if mode=='fixed':
                return 403, {'error':'Redirect target rejected before following','simulation':True}
            return 200, {'fetch_actor':'server model','simulation':True,'private':True,'redirect_followed':True,'body':'DEMO_INTERNAL_CONFIG'}
        if url.hostname=='internal.lab' and path=='/config':
            return 200, {'fetch_actor':'server model','simulation':True,'private':True,'body':'DEMO_INTERNAL_CONFIG'}
        if url.hostname=='public.lab' and path=='/welcome':
            return 200, {'fetch_actor':'server model','simulation':True,'private':False,'body':'Public fixture'}
        return 404, {'error':'Synthetic resource not found','simulation':True}
    if kind=='open-redirect':
        # Return a decision, never send a Location header or navigate externally.
        if any(ord(ch)<32 or ord(ch)==127 for ch in value):
            return 400, {'error':'Control characters rejected','simulation':True}
        allowed=value in {'/welcome','/account'}
        if mode=='fixed' and not allowed:
            return 400, {'error':'Destination must be an allowed local route','simulation':True}
        return 200, {'decision':'redirect','would_status':302,'location':value,'external':not allowed,'simulation':True}
    if kind in {'api-keys','exposed-files'}:
        item=FIXTURES.get(value)
        if not item:
            return 404, {'error':'Not found','fixture':True}
        category,content=item
        if mode=='fixed' and category=='private':
            return 404, {'error':'Not found','fixture':True}
        if mode=='fixed' and category=='secret':
            content='PUBLIC_KEY="demo_publishable_ui";\n// secret operations run on the server'
        return 200, {'path':value,'content':content,'fixture':True}
    return 404, {'error':'Unknown exercise'}
