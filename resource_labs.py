"""Virtual file, deployment and identity services. No host IO or token guessing.

PNG:/HTML: are explicit format fixtures, not production file validators.
The SVG policy rejects active syntax; it is not a reusable SVG sanitizer.
"""
import posixpath
from copy import deepcopy
from urllib.parse import unquote

GROUPS = {'upload', 'traversal', 'disclosure', 'authentication'}


def string(d, key):
    value = d[key]
    if not isinstance(value, str) or not 1 <= len(value) <= 1024 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Expected a bounded nonempty string without control characters: ' + key)
    return value


def result(status, data, impact=False, protected=False, legitimate=False, code=None):
    return dict(status=status, data=data, impact=impact, protected=protected,
                legitimate=legitimate, **({'error_code': code} if code else {}))


def execute(case, group, fixed, d, state):
    if group == 'upload': return upload(case, fixed, d, state)
    if group == 'traversal': return traversal(case, fixed, d)
    if group == 'disclosure': return disclosure(case, fixed, d)
    if group == 'authentication': return authentication(case, fixed, d, state)
    raise ValueError('Unknown resource lab')


def upload(case, fixed, d, state):
    name = string(d, 'filename'); mime = string(d, 'content_type'); content = string(d, 'content')
    files = state.setdefault('files', {'bob.png': {'owner': 'bob', 'content': 'PNG:bob-original'}})
    suffix = name.rsplit('.', 1)[-1].lower()
    path_bad = '/' in name or '\\' in name or name in {'.', '..'}
    owner_bad = name in files and files[name]['owner'] != 'alice'
    active_svg = suffix == 'svg' and any(s in content.lower() for s in ('<script', 'onload', 'javascript:', '<foreignobject', 'href='))
    # Fixture decoders deliberately do not accept real image bytes.
    image_ok = (suffix == 'png' and mime == 'image/png' and content.startswith('PNG:'))
    svg_ok = (case == 'upload-svg' and suffix == 'svg' and mime == 'image/svg+xml' and content == '<svg><circle r="4"/></svg>')
    invalid = path_bad or owner_bad or not (image_ok or svg_ok)
    # Each vulnerable route has a specific check missing. Other malformed inputs
    # are still rejected rather than granting impact to every string.
    if case == 'upload-extension': weak_allowed = mime == 'image/png' and content.startswith('PNG:') and not path_bad and not owner_bad
    elif case == 'upload-double': weak_allowed = '.png' in name.lower() and mime == 'image/png' and content.startswith('PNG:') and not path_bad and not owner_bad
    elif case == 'upload-mime': weak_allowed = suffix == 'png' and mime == 'image/png' and not path_bad and not owner_bad
    elif case == 'upload-path': weak_allowed = image_ok and not owner_bad
    elif case == 'upload-overwrite': weak_allowed = image_ok and not path_bad
    elif case == 'upload-svg': weak_allowed = suffix == 'svg' and mime == 'image/svg+xml' and content.startswith('<svg>') and not path_bad and not owner_bad
    else: raise ValueError('Unknown upload case')
    accepted = not invalid if fixed else weak_allowed
    if not accepted:
        status = 403 if owner_bad or path_bad else 415
        return result(status, {'accepted': False, 'files': deepcopy(files), 'execution_performed': False},
                      protected=fixed and invalid, code='file_not_authorized' if status == 403 else 'unsupported_file_format')
    # Retain requested name as metadata in fixed mode, and use an opaque key.
    storage_key = 'alice-upload-' + str(state.get('revision', 0) + 1) if fixed else name
    if len(files) >= 30 and storage_key not in files:
        return result(409, {'accepted': False, 'files': deepcopy(files), 'execution_performed': False}, code='storage_capacity_reached')
    files[storage_key] = {'owner': 'alice', 'content': content}
    state['revision'] = state.get('revision', 0) + 1
    return result(201, {'accepted': True, 'filename': name, 'storage_key': storage_key,
                       'files': deepcopy(files), 'execution_performed': False,
                       'active_content_accepted': active_svg, 'revision': state['revision'],
                       'resolved_path': posixpath.normpath(posixpath.join('/uploads', storage_key.replace('\\', '/'))),
                       'model': 'virtual storage; PNG:/HTML: format fixtures, not real decoding or execution'},
                  impact=invalid and not fixed, legitimate=fixed and not invalid)


VIRTUAL_FILES = {'/public/guide.txt': 'Public installation guide',
                 '/private/billing.csv': 'DEMO_PRIVATE_INVOICE,alice,12900',
                 '/public-backup/keys.txt': 'DEMO_INERT_BACKUP_KEY'}


def traversal(case, fixed, d):
    raw = string(d, 'path')
    decoded = unquote(unquote(raw)) if case == 'traversal-double' else unquote(raw)
    decoded = decoded.replace('\\', '/')
    resolved = posixpath.normpath(posixpath.join('/public', decoded))
    contained = resolved.startswith('/public/')
    trace = [{'submitted': raw}, {'decoded': decoded}, {'resolved': resolved, 'contained': contained}]
    if fixed and (not contained or decoded.startswith('/')):
        return result(403, {'content': None, 'trace': trace}, protected=True, code='path_outside_public_root')
    if resolved not in VIRTUAL_FILES:
        return result(404, {'content': None, 'trace': trace}, code='file_not_found')
    return result(200, {'content': VIRTUAL_FILES[resolved], 'filename': resolved, 'trace': trace,
                        'model': 'in-memory file map; no host filesystem reads'},
                  impact=not contained and not fixed, legitimate=fixed and contained)


DISCLOSURES = {
    'disclosure-env': ('/.env', {'content': 'DB_PASSWORD=DEMO_INERT_PASSWORD', 'classification': 'server_secret'}),
    'disclosure-git': ('/.git/config', {'content': '[remote "origin"] url = https://git.example.test/internal/app', 'classification': 'internal_repository_metadata'}),
    'disclosure-backup': ('/config.json.bak', {'content': '{"service_token":"DEMO_INERT_BACKUP_TOKEN"}', 'classification': 'backup_secret'}),
    'disclosure-listing': ('/internal/', {'entries': ['billing-demo.csv', 'deployment-demo.json'], 'classification': 'internal_directory_index'}),
    'disclosure-trace': ('/debug/error', {'trace': ['DemoDatabaseError at /srv/northstar/accounts.py:42', 'SELECT account FROM demo_accounts'], 'classification': 'internal_diagnostics'}),
    'disclosure-apikey': ('/client-config.json', {'public_api_base': '/api', 'server_api_key': 'DEMO_INERT_SERVER_ONLY_KEY', 'classification': 'server_secret_in_client_bundle'}),
}


def disclosure(case, fixed, d):
    path = string(d, 'path'); expected, data = DISCLOSURES[case]
    if path == '/help.json': return result(200, {'content': 'Public help', 'classification': 'public'}, legitimate=fixed)
    if path != expected: return result(404, None, code='resource_not_found')
    if fixed:
        if case == 'disclosure-apikey':
            return result(200, {'public_api_base': '/api', 'classification': 'public', 'secret_removed': True}, protected=True)
        return result(404, None, protected=True, code='resource_not_found')
    return result(200, deepcopy(data), impact=True)


def authentication(case, fixed, d, state):
    key = 'session' if case in {'authentication-logout', 'authentication-mfa'} else 'token'
    value = string(d, key)
    # Ledger facts remain server-controlled; no claimed owner/expiry/MFA fields.
    ledger = {'reset-alice': ('alice', 'reset', 'fresh'), 'reset-fresh': ('alice', 'reset', 'fresh'),
              'reset-used': ('alice', 'reset', 'used'), 'reset-expired': ('alice', 'reset', 'expired'),
              'verify-email-alice': ('alice', 'verify-email', 'fresh'),
              'session-active': ('alice', 'session', 'active'), 'session-logged-out': ('alice', 'session', 'revoked'),
              'session-mfa-complete': ('alice', 'session', 'mfa-complete'), 'session-password-only': ('alice', 'session', 'password-only')}
    if value not in ledger: return result(401, {'authorized': False}, code='invalid_credential')
    owner, purpose, phase = ledger[value]
    target = string(d, 'account') if case == 'authentication-reset-binding' else 'alice'
    if target not in {'alice', 'bob'}: return result(404, {'authorized': False}, code='account_not_found')
    password = string(d, 'password') if case == 'authentication-reset-binding' else 'NewDemoPassword!'
    if len(password) < 12: return result(422, {'authorized': False}, code='password_policy_failed')
    before = deepcopy(state.setdefault('accounts', {'alice': {'revision': 0}, 'bob': {'revision': 0}}))
    used = state.setdefault('consumed', [])
    session_case = key == 'session'
    valid = owner == target and ((purpose == 'session' and phase in {'active', 'mfa-complete'}) if session_case else (purpose == 'reset' and phase == 'fresh' and value not in used))
    # Isolate the single absent rule in each vulnerable implementation.
    if case == 'authentication-reset-binding': weak = purpose == 'reset' and phase == 'fresh' and value not in used
    elif case == 'authentication-reset-replay': weak = purpose == 'reset' and phase in {'fresh', 'used'}
    elif case == 'authentication-reset-expiry': weak = purpose == 'reset' and phase in {'fresh', 'expired'} and value not in used
    elif case == 'authentication-logout': weak = purpose == 'session' and phase in {'active', 'revoked'}
    elif case == 'authentication-mfa': weak = purpose == 'session' and phase in {'mfa-complete', 'password-only'}
    elif case == 'authentication-purpose': weak = phase == 'fresh' and value not in used
    else: raise ValueError('Unknown identity case')
    accepted = valid if fixed else weak
    if not accepted:
        return result(403 if purpose == 'session' and phase == 'password-only' else 401,
                      {'authorized': False, 'accounts': before, 'operation_applied': False},
                      protected=fixed and not valid, code='credential_contract_failed')
    if not session_case:
        state['accounts'][target]['revision'] += 1
        if value not in used: used.append(value)
    return result(200, {'authorized': True, 'actor': owner, 'account': target,
                        'accounts': deepcopy(state['accounts']), 'operation_applied': not session_case,
                        'content': 'DEMO_PRIVATE_PROFILE' if session_case else 'Password updated in synthetic account ledger',
                        'model': 'closed identity ledger; no real credentials, signing or email'},
                  impact=not valid and not fixed, legitimate=fixed and valid)
