"""Operator-side live API verification of APP-013's declared default fixtures."""
import copy
import http.cookiejar
import json
from pathlib import Path
import urllib.error
import urllib.request
from urllib.parse import urlsplit
import uuid

from .preparation import read_regular
from .verdicts import Inconclusive


PASSWORD = 'Fixture-only-2026!'
USERS = {
    'alpha-analyst': {'alpha': ['analyst']},
    'alpha-reviewer': {'alpha': ['reviewer']},
    'alpha-auditor': {'alpha': ['auditor']},
    'alpha-admin': {'alpha': ['administrator']},
    'alpha-dual': {'alpha': ['analyst', 'reviewer']},
    'beta-analyst': {'beta': ['analyst']},
    'beta-reviewer': {'beta': ['reviewer']},
    'beta-admin': {'beta': ['administrator']},
    'multi-analyst': {'alpha': ['analyst'], 'beta': ['analyst']},
}
ACCOUNTS = {
    'analyst': 'alpha-analyst', 'reviewer': 'alpha-reviewer',
    'auditor': 'alpha-auditor', 'admin': 'alpha-admin', 'dual': 'alpha-dual',
    'other_analyst': 'beta-analyst', 'other_reviewer': 'beta-reviewer',
    'other_admin': 'beta-admin', 'multi_analyst': 'multi-analyst',
}


def unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate fixture JSON field')
        value[key] = item
    return value


def canonical_uuid(value):
    return isinstance(value, str) and str(uuid.UUID(value)) == value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        return None


def origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1'
            or parsed.username or parsed.password or parsed.path or parsed.query
            or parsed.fragment or parsed.port is None or not 1024 <= parsed.port <= 65535
            or value != 'http://127.0.0.1:' + str(parsed.port)):
        raise ValueError('Controller-selected loopback origin required')
    return value


class Session:
    """One fixed loopback peer, no environment proxies or redirect following.

    Credential/session bodies remain in memory, never exception messages or logs.
    The supplied guard owns the absolute deadline; every network operation is also
    bounded. The outer operator must interrupt callbacks and filesystem stalls.
    """
    def __init__(self, base_url, lifetime_check, timeout):
        self.base_url = origin(base_url)
        self.check = lifetime_check
        self.timeout = timeout
        self.csrf = None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            NoRedirect(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, method, path, status, body=None, *, missing_ok=False):
        if missing_ok and (method != 'GET' or status != 200):
            raise ValueError('Missing-resource observation requires a GET')
        self.check(self.timeout)
        headers = {'Accept': 'application/json'}
        data = None
        if body is not None:
            headers['Content-Type'] = 'application/json'
            data = json.dumps(body).encode()
        if method == 'POST' and self.csrf is not None:
            headers['X-CSRF-Token'] = self.csrf
        request = urllib.request.Request(self.base_url + '/api/v1' + path,
                                         data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                actual = response.status
                content = response.read(65537)
        except urllib.error.HTTPError as error:
            missing = missing_ok and error.code == 404
            error.close()
            self.check(0)
            if missing:
                return None
            raise Inconclusive('Fixture API transport unavailable') from None
        except (OSError, urllib.error.URLError):
            raise Inconclusive('Fixture API transport unavailable') from None
        self.check(0)
        if actual != status or len(content) > 65536:
            raise AssertionError('Fixture API response status or size mismatch')
        if status == 204:
            if content:
                raise AssertionError('Fixture logout returned unexpected content')
            return None
        try:
            return json.loads(content, object_pairs_hook=unique_pairs)
        except (ValueError, UnicodeError):
            raise AssertionError('Fixture API response is not bounded unique JSON') from None


def observe_default_fixture(project, base_url, *, lifetime_check, timeout=5):
    """Crosscheck the declared manifest against all nine live login identities.

    Returns (protected target fragment, sanitized observations). No fixture is
    created, seed command selected, or source executed. Membership lists must
    match exactly; both tenants' case lists must be empty. Tenant alpha/beta names
    are disclosed aliases, not independently observed database display names.
    Users with no membership are outside the public API observation scope.
    Additional isolated/alternate fixture preparation and foundation checks remain
    separate. This helper does not grant coverage completion or suite approval.
    """
    if (not callable(lifetime_check) or type(timeout) not in (int, float)
            or not 0 < timeout <= 10):
        raise ValueError('Bounded trusted fixture lifetime required')
    origin(base_url)
    def check():
        if lifetime_check(0) is not True:
            raise Inconclusive('Fixture deployment lifetime unavailable')
    check()
    try:
        raw = read_regular(Path(project) / 'ops/fixture-ids.json', 65536, check)
        declared = json.loads(raw, object_pairs_hook=unique_pairs)
        if (not isinstance(declared, dict) or set(declared) != {'tenants', 'users'}
                or not isinstance(declared['tenants'], dict)
                or set(declared['tenants']) != {'alpha', 'beta'}
                or not isinstance(declared['users'], dict)
                or set(declared['users']) != set(USERS)):
            raise ValueError()
        ids = [*declared['tenants'].values(), *declared['users'].values()]
        if (any(not canonical_uuid(value) for value in ids)
                or len(set(declared['tenants'].values())) != 2
                or len(set(declared['users'].values())) != len(USERS)):
            raise ValueError()
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise Inconclusive('Complete ordinary default fixture manifest unavailable') from None
    tenants = dict(declared['tenants'])
    observations = []
    membership_reads = {}
    empty_case_reads = {}
    def live(reserve):
        if lifetime_check(reserve) is not True:
            raise Inconclusive('Fixture deployment lifetime unavailable')
    for username, roles in USERS.items():
        session = Session(base_url, live, timeout)
        login = session.request('POST', '/auth/login', 200,
                                dict(username=username, password=PASSWORD))
        if (not isinstance(login, dict) or set(login) != {'csrf_token'}
                or not isinstance(login['csrf_token'], str) or not login['csrf_token']):
            raise AssertionError('Default fixture login response mismatch')
        session.csrf = login['csrf_token']
        me = session.request('GET', '/auth/me', 200)
        memberships = [{'tenant_id': tenants[name], 'roles': sorted(values)}
                       for name, values in roles.items()]
        if (not isinstance(me, dict) or set(me) != {'id', 'username', 'memberships'}
                or me['id'] != declared['users'][username] or me['username'] != username
                or not isinstance(me['memberships'], list)
                or any(not isinstance(item, dict) or set(item) != {'tenant_id', 'roles'}
                       or not isinstance(item['tenant_id'], str)
                       or item['tenant_id'] not in tenants.values()
                       or not isinstance(item['roles'], list) or not item['roles']
                       or any(not isinstance(role, str) for role in item['roles'])
                       or len(set(item['roles'])) != len(item['roles'])
                       for item in me['memberships'])):
            raise AssertionError('Default fixture current-user identity mismatch')
        observed = [dict(tenant_id=item['tenant_id'], roles=sorted(item['roles']))
                    for item in me['memberships']]
        if sorted(observed, key=lambda item: item['tenant_id']) != sorted(memberships, key=lambda item: item['tenant_id']):
            raise AssertionError('Default fixture memberships mismatch')
        observations.append(dict(id=me['id'], username=username, memberships=observed))
        for name, values in roles.items():
            path = '/tenants/' + tenants[name]
            if 'administrator' in values:
                page = session.request('GET', path + '/memberships?limit=100&offset=0', 200)
                expected = [dict(user_id=declared['users'][user], username=user, roles=sorted(permissions[name]))
                            for user, permissions in USERS.items() if name in permissions]
                if (not isinstance(page, dict) or set(page) != {'items', 'total', 'limit', 'offset'}
                        or type(page['total']) is not int or page['total'] != len(expected)
                        or type(page['limit']) is not int or page['limit'] != 100
                        or type(page['offset']) is not int or page['offset'] != 0
                        or not isinstance(page['items'], list)
                        or any(not isinstance(item, dict) or set(item) != {'user_id', 'username', 'roles'}
                               or not isinstance(item['user_id'], str) or not isinstance(item['roles'], list)
                               or any(not isinstance(role, str) for role in item['roles'])
                               for item in page['items'])):
                    raise AssertionError('Default fixture membership page mismatch')
                actual = [dict(item, roles=sorted(item['roles'])) for item in page['items']]
                if sorted(actual, key=lambda item: item['user_id']) != sorted(expected, key=lambda item: item['user_id']):
                    raise AssertionError('Default fixture persisted memberships mismatch')
                membership_reads[name] = len(expected)
            if username == name + '-analyst':
                page = session.request('GET', path + '/cases?limit=1&offset=0', 200)
                if (not isinstance(page, dict) or set(page) != {'items', 'total', 'limit', 'offset'}
                        or page['items'] != [] or type(page['total']) is not int or page['total'] != 0
                        or type(page['limit']) is not int or page['limit'] != 1
                        or type(page['offset']) is not int or page['offset'] != 0):
                    raise AssertionError('Default fixture tenant is not empty')
                empty_case_reads[name] = 0
        session.request('POST', '/auth/logout', 204)
    check()
    fragment = dict(tenants=tenants, accounts={role: dict(username=name, password=PASSWORD)
                                             for role, name in ACCOUNTS.items()})
    observation = dict(identities=dict(tenants=[dict(id=value, name=key) for key, value in tenants.items()],
                                     users=observations),
                       membership_counts=membership_reads, case_counts=empty_case_reads)
    return copy.deepcopy(fragment), observation
