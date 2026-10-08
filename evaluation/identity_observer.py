"""Operator-side live API verification of APP-013 synthetic seed fixtures."""
import copy
import http.cookiejar
import json
import re
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
        if method in ('POST', 'PUT', 'PATCH', 'DELETE') and self.csrf is not None:
            if not isinstance(self.csrf, str) or not self.csrf:
                raise ValueError('Opaque session-bound CSRF token required')
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
        except (OSError, urllib.error.URLError, ValueError):
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


def observe_seed_fixture(project, base_url, expected_roles, passwords, *, lifetime_check, timeout=5):
    """Crosscheck operator-selected fixture names/roles against live identities.

    Returns (credential-free declared IDs, sanitized observations). The caller
    supplies the expected roster and passwords independently, after interpreting
    the application's documented seed input. No seed command or input format is
    chosen here. Every tenant needs an administrator and a case reader for the
    disclosed API crosschecks. Tenant names are aliases, not independently read
    database display names; unexpected users without memberships are unobserved.
    Neither coverage completion nor acceptance-suite approval is granted.
    """
    roles_by_user = copy.deepcopy(expected_roles)
    try:
        if (not isinstance(roles_by_user, dict) or not 1 <= len(roles_by_user) <= 100
                or not isinstance(passwords, dict) or set(passwords) != set(roles_by_user)):
            raise ValueError()
        aliases = set()
        for username, memberships in roles_by_user.items():
            if (not isinstance(username, str) or not re.fullmatch(r'[a-z0-9._-]{3,64}', username)
                    or not isinstance(passwords[username], str) or not 12 <= len(passwords[username]) <= 128
                    or not isinstance(memberships, dict)):
                raise ValueError()
            for name, roles in memberships.items():
                if (not isinstance(name, str) or not 1 <= len(name) <= 128
                        or not isinstance(roles, list) or not roles
                        or any(not isinstance(role, str) or role not in
                               ('analyst', 'reviewer', 'auditor', 'administrator') for role in roles)
                        or len(set(roles)) != len(roles)):
                    raise ValueError()
                aliases.add(name)
        if not 1 <= len(aliases) <= 16:
            raise ValueError()
        for alias in aliases:
            if (not any('administrator' in memberships.get(alias, []) for memberships in roles_by_user.values())
                    or not any(set(memberships.get(alias, [])) & {'analyst', 'reviewer'} for memberships in roles_by_user.values())):
                raise ValueError()
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError('Bounded independent fixture configuration required') from None
    passwords = copy.deepcopy(passwords)
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
                or set(declared['tenants']) != aliases
                or not isinstance(declared['users'], dict)
                or set(declared['users']) != set(roles_by_user)):
            raise ValueError()
        ids = [*declared['tenants'].values(), *declared['users'].values()]
        if (any(not canonical_uuid(value) for value in ids)
                or len(set(declared['tenants'].values())) != len(aliases)
                or len(set(declared['users'].values())) != len(roles_by_user)):
            raise ValueError()
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise Inconclusive('Complete ordinary seed fixture manifest unavailable') from None
    tenants = dict(declared['tenants'])
    observations = []
    membership_reads = {}
    empty_case_reads = {}
    def live(reserve):
        if lifetime_check(reserve) is not True:
            raise Inconclusive('Fixture deployment lifetime unavailable')
    for username, roles in roles_by_user.items():
        session = Session(base_url, live, timeout)
        login = session.request('POST', '/auth/login', 200,
                                dict(username=username, password=passwords[username]))
        if (not isinstance(login, dict) or set(login) != {'csrf_token'}
                or not isinstance(login['csrf_token'], str) or not login['csrf_token']):
            raise AssertionError('Seed fixture login response mismatch')
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
            raise AssertionError('Seed fixture current-user identity mismatch')
        observed = [dict(tenant_id=item['tenant_id'], roles=sorted(item['roles']))
                    for item in me['memberships']]
        if sorted(observed, key=lambda item: item['tenant_id']) != sorted(memberships, key=lambda item: item['tenant_id']):
            raise AssertionError('Seed fixture memberships mismatch')
        observations.append(dict(id=me['id'], username=username, memberships=observed))
        for name, values in roles.items():
            path = '/tenants/' + tenants[name]
            if 'administrator' in values:
                page = session.request('GET', path + '/memberships?limit=100&offset=0', 200)
                expected = [dict(user_id=declared['users'][user], username=user, roles=sorted(permissions[name]))
                            for user, permissions in roles_by_user.items() if name in permissions]
                if (not isinstance(page, dict) or set(page) != {'items', 'total', 'limit', 'offset'}
                        or type(page['total']) is not int or page['total'] != len(expected)
                        or type(page['limit']) is not int or page['limit'] != 100
                        or type(page['offset']) is not int or page['offset'] != 0
                        or not isinstance(page['items'], list)
                        or any(not isinstance(item, dict) or set(item) != {'user_id', 'username', 'roles'}
                               or not isinstance(item['user_id'], str) or not isinstance(item['roles'], list)
                               or any(not isinstance(role, str) for role in item['roles'])
                               for item in page['items'])):
                    raise AssertionError('Seed fixture membership page mismatch')
                actual = [dict(item, roles=sorted(item['roles'])) for item in page['items']]
                if sorted(actual, key=lambda item: item['user_id']) != sorted(expected, key=lambda item: item['user_id']):
                    raise AssertionError('Seed fixture persisted memberships mismatch')
                membership_reads[name] = len(expected)
            if name not in empty_case_reads and set(values) & {'analyst', 'reviewer'}:
                page = session.request('GET', path + '/cases?limit=1&offset=0', 200)
                if (not isinstance(page, dict) or set(page) != {'items', 'total', 'limit', 'offset'}
                        or page['items'] != [] or type(page['total']) is not int or page['total'] != 0
                        or type(page['limit']) is not int or page['limit'] != 1
                        or type(page['offset']) is not int or page['offset'] != 0):
                    raise AssertionError('Seed fixture tenant is not empty')
                empty_case_reads[name] = 0
        session.request('POST', '/auth/logout', 204)
    check()
    observation = dict(identities=dict(tenants=[dict(id=value, name=key) for key, value in tenants.items()],
                                     users=observations),
                       membership_counts=membership_reads, case_counts=empty_case_reads)
    return copy.deepcopy(declared), observation


def observe_default_fixture(project, base_url, *, lifetime_check, timeout=5):
    """APP-013 default roster wrapper over the general live seed observer.

    Returns the existing protected tenants/accounts fragment and credential-free
    observation. An alternate deployment must use operator-selected names/roles
    with observe_seed_fixture rather than relying on this default account map.
    """
    declared, observation = observe_seed_fixture(project, base_url, USERS,
        {username: PASSWORD for username in USERS}, lifetime_check=lifetime_check, timeout=timeout)
    fragment = dict(tenants=declared['tenants'], accounts={role: dict(username=name, password=PASSWORD)
                                                        for role, name in ACCOUNTS.items()})
    return copy.deepcopy(fragment), observation
