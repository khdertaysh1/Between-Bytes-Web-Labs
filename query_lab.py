"""One local parameter-cardinality exercise; explicit application policies, not framework defaults."""
import re
from urllib.parse import parse_qsl

DOCUMENTS = {'alice': {'owner': 'alice', 'document': 'Alice training report'},
             'bob': {'owner': 'bob', 'document': 'Bob private training report'},
             'carol': {'owner': 'carol', 'document': 'Carol private training report'}}


def execute(fixed, raw):
    if not isinstance(raw, str) or not 1 <= len(raw) <= 1024 or any(ord(c) <= 32 or ord(c) >= 127 for c in raw) or '#' in raw:
        raise ValueError('Use a nonempty URL-encoded ASCII query of at most 1024 characters; encode spaces/fragments')
    if re.search(r'%(?![0-9a-fA-F]{2})', raw):
        raise ValueError('Malformed percent encoding')
    pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=True, max_num_fields=8, errors='strict')
    if any(key not in {'owner', 'tag'} or not value or any(ord(c) < 32 or ord(c) == 127 for c in key + value) for key, value in pairs):
        raise ValueError('Use only nonempty owner and optional tag values without control characters')
    owners = [value for key, value in pairs if key == 'owner']
    if not owners:
        raise ValueError('The owner parameter is required')
    first, last = owners[0], owners[-1]
    trace = {'parameters': [[k, v] for k, v in pairs], 'validation_owner': first,
             'downstream_owner': None, 'session_actor': 'alice', 'records': [],
             'verification': 'real urllib.parse parsing; explicit local first/last application policies'}
    if fixed and len(owners) != 1:
        return dict(status=400, data=trace, impact=False, protected=True, legitimate=False, error_code='ambiguous_owner')
    if first != 'alice':
        return dict(status=403, data=trace, impact=False, protected=fixed, legitimate=False, error_code='owner_not_authorized')
    selected = first if fixed else last
    trace['downstream_owner'] = selected
    if selected not in DOCUMENTS:
        return dict(status=404, data=trace, impact=False, protected=False, legitimate=False, error_code='document_not_found')
    trace['records'] = [dict(DOCUMENTS[selected])]
    return dict(status=200, data=trace, impact=not fixed and selected != 'alice',
                protected=False, legitimate=fixed and selected == 'alice')
