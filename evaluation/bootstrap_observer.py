"""Live repeat-bootstrap observations, independent of declared default roles.

The operator binds initial identities from its verified fresh fixture. All nine
users are read through live authenticated sessions; administrator membership
pages must agree with those reads. This observes the disclosed fixture roster,
not unassigned database users or tenant display names. An inaccessible identity
or lost observation capability is inconclusive. The protected verifier decides
whether complete before/after observations preserve the initial state.
"""
import copy

from .identity_observer import PASSWORD, USERS, Session, canonical_uuid, origin
from .verdicts import Inconclusive


ROLES = {'analyst', 'reviewer', 'auditor', 'administrator'}


def observe_repeat_fixture(base_url, identities, case_id, *, lifetime_check, timeout=5):
    """Return {identities, case}; a live 404 case is represented as None.

    IDs and credentials are bound by the operator before repeat bootstrap; no
    builder-written manifest is consulted afterward. Tenant IDs are checked by
    persisted membership pages and the case's full returned resource. Tenant
    aliases come from the initial verified fixture, not a database-name query.
    Exact normalized schema validation and preservation belong to the protected
    verifier. The enclosing callback owner must enforce its absolute deadline.
    """
    origin(base_url)
    if (not callable(lifetime_check) or type(timeout) not in (int, float)
            or not 0 < timeout <= 10 or not canonical_uuid(case_id)):
        raise ValueError('Bounded independent repeat fixture required')
    initial = copy.deepcopy(identities)
    try:
        tenants = {row['name']: row['id'] for row in initial['tenants']}
        users = {row['username']: row['id'] for row in initial['users']}
        if (set(initial) != {'tenants', 'users'} or set(tenants) != {'alpha', 'beta'}
                or len(initial['tenants']) != 2 or set(users) != set(USERS)
                or len(initial['users']) != len(USERS)
                or len(set(tenants.values())) != 2 or len(set(users.values())) != len(USERS)
                or any(not canonical_uuid(value) for value in [*tenants.values(), *users.values()])):
            raise ValueError()
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError('Verified initial default identities required') from None

    def live(reserve):
        if lifetime_check(reserve) is not True:
            raise Inconclusive('Repeat fixture lifetime unavailable')

    live(0)
    observed = []
    pages = {}
    case = None
    for username in USERS:
        session = Session(base_url, live, timeout)
        login = session.request('POST', '/auth/login', 200,
                                dict(username=username, password=PASSWORD))
        if (not isinstance(login, dict) or set(login) != {'csrf_token'}
                or not isinstance(login['csrf_token'], str) or not login['csrf_token']):
            raise Inconclusive('Repeat fixture login observation unavailable')
        session.csrf = login['csrf_token']
        me = session.request('GET', '/auth/me', 200)
        try:
            if (not isinstance(me, dict) or set(me) != {'id', 'username', 'memberships'}
                    or not canonical_uuid(me['id']) or me['username'] != username
                    or not isinstance(me['memberships'], list)):
                raise ValueError()
            seen = set()
            for item in me['memberships']:
                if (not isinstance(item, dict) or set(item) != {'tenant_id', 'roles'}
                        or item['tenant_id'] not in tenants.values() or item['tenant_id'] in seen
                        or not isinstance(item['roles'], list) or not item['roles']
                        or any(not isinstance(role, str) or role not in ROLES for role in item['roles'])
                        or len(set(item['roles'])) != len(item['roles'])):
                    raise ValueError()
                seen.add(item['tenant_id'])
                item['roles'] = sorted(item['roles'])
        except (ValueError, TypeError, KeyError, AttributeError):
            raise Inconclusive('Complete repeat identity observation unavailable') from None
        observed.append(me)
        for item in me['memberships']:
            if 'administrator' in item['roles']:
                path = '/tenants/' + item['tenant_id'] + '/memberships?limit=100&offset=0'
                page = session.request('GET', path, 200)
                pages.setdefault(item['tenant_id'], []).append(page)
        if username == 'alpha-analyst':
            case = session.request('GET', '/tenants/' + tenants['alpha'] + '/cases/' + case_id,
                                   200, missing_ok=True)
        session.request('POST', '/auth/logout', 204)
    # Consistency is checked after all users, so changed role sets are observable
    # rather than silently replaced with the original default role assignments.
    for tenant in tenants.values():
        expected = [dict(user_id=user['id'], username=user['username'], roles=item['roles'])
                    for user in observed for item in user['memberships'] if item['tenant_id'] == tenant]
        if tenant not in pages:
            raise Inconclusive('Repeat fixture administrator observation unavailable')
        for page in pages[tenant]:
            try:
                if (not isinstance(page, dict) or set(page) != {'items', 'total', 'limit', 'offset'}
                        or type(page['total']) is not int or page['total'] != len(expected)
                        or type(page['limit']) is not int or page['limit'] != 100
                        or type(page['offset']) is not int or page['offset'] != 0
                        or not isinstance(page['items'], list)):
                    raise ValueError()
                actual = []
                for item in page['items']:
                    if (not isinstance(item, dict) or set(item) != {'user_id', 'username', 'roles'}
                            or not isinstance(item['user_id'], str) or not isinstance(item['roles'], list)
                            or any(not isinstance(role, str) for role in item['roles'])):
                        raise ValueError()
                    actual.append(dict(item, roles=sorted(item['roles'])))
                if sorted(actual, key=lambda row: row['user_id']) != sorted(expected, key=lambda row: row['user_id']):
                    raise ValueError()
            except (ValueError, TypeError, KeyError, AttributeError):
                raise Inconclusive('Consistent repeat membership observation unavailable') from None
    live(0)
    return copy.deepcopy(dict(identities=dict(tenants=initial['tenants'], users=observed), case=case))
