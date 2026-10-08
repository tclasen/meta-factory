"""Private APP-002 account hash reads for independently mapped PostgreSQL storage.

Return encodings only to the operator-side inspector, never to a grader socket or
an evidence serializer. Trusted DatabaseTransport retains only command metadata.
Other account layouts require reviewed adapters; no application schema is imposed.
"""
import copy

from .database_probe import identifier, sql_literal


FIELDS = {'identity', 'encoded_hash'}


def password_read_sql(binding, identities, *, require_complete_scope=False):
    if type(require_complete_scope) is not bool:
        raise ValueError('Explicit boolean password scope required')
    if (not isinstance(binding, dict) or set(binding) != {
            'accounts', 'database_name', 'operator_user', 'operator_session_user'}
            or any(not isinstance(binding[key], str) or not binding[key]
                   or '\x00' in binding[key] or len(binding[key].encode()) > 256
                   for key in ('database_name', 'operator_user', 'operator_session_user'))):
        raise ValueError('Complete operator password database binding required')
    if (not isinstance(identities, (list, tuple)) or not 1 <= len(identities) <= 64
            or any(not isinstance(value, str) or not value or '\x00' in value
                   or len(value.encode()) > 256 for value in identities)
            or len(set(identities)) != len(identities)):
        raise ValueError('Bounded unique account identities required')
    mapping = binding['accounts']
    if (not isinstance(mapping, dict) or set(mapping) != {'schema', 'table', 'table_oid', 'fields'}
            or type(mapping['table_oid']) is not int or not 0 < mapping['table_oid'] <= 4294967295
            or not isinstance(mapping['fields'], dict) or set(mapping['fields']) != FIELDS):
        raise ValueError('Complete observed account relation mapping required')
    relation = identifier(mapping['schema']) + '.' + identifier(mapping['table'])
    expressions = {}
    for field, selected in mapping['fields'].items():
        if (not isinstance(selected, dict) or set(selected) != {'column', 'path'}
                or not isinstance(selected['path'], list) or len(selected['path']) > 8
                or any(not isinstance(key, str) or not key or '\x00' in key
                       or len(key.encode()) > 256 for key in selected['path'])):
            raise ValueError('Invalid password field mapping')
        column = 't.' + identifier(selected['column'])
        expressions[field] = column + '::text' if not selected['path'] else (
            '(' + column + '::jsonb #>> ARRAY[' + ','.join(sql_literal(key) for key in selected['path']) + ']::text[])')
    complete_check = ''
    if require_complete_scope:
        complete_check = """IF EXISTS (SELECT 1 FROM pg_catalog.pg_class WHERE oid=%s::oid AND relrowsecurity) THEN
    RAISE EXCEPTION 'Complete account scope unavailable with row security';
END IF;
""" % mapping['table_oid']
    identity_check = """BEGIN
IF pg_catalog.to_regclass(%s)::oid IS DISTINCT FROM %s::oid
   OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class WHERE oid=%s::oid AND relkind IN ('r','p')) THEN
    RAISE EXCEPTION 'Operator account relation changed or unsupported';
END IF;
%sEND;""" % (sql_literal(relation), mapping['table_oid'], mapping['table_oid'], complete_check)
    selection = 'TRUE' if require_complete_scope else (
        expressions['identity'] + ' = ANY(ARRAY['
        + ','.join(sql_literal(value) for value in identities) + ']::text[])')
    # Oversized or missing encodings yield no raw value; the reader refuses them.
    return """BEGIN READ ONLY;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '2s';
SET LOCAL search_path = pg_catalog;
SET LOCAL client_min_messages = error;
LOCK TABLE %s IN ACCESS SHARE MODE;
DO %s;
WITH selected AS MATERIALIZED (
    SELECT %s AS identity, %s AS encoded_hash FROM %s t
     WHERE %s LIMIT %s
), projected AS (
    SELECT CASE WHEN encoded_hash IS NULL OR pg_catalog.octet_length(encoded_hash) NOT BETWEEN 1 AND 4096
                THEN pg_catalog.json_build_object('representation_unavailable',true)
                ELSE pg_catalog.json_build_object('identity',identity,'encoded_hash',encoded_hash) END AS account
      FROM selected
)
SELECT pg_catalog.json_build_object(
    'database_name',current_database(),'current_user',current_user,'session_user',session_user,
    'account_relation_oid',%s,'truncated',(SELECT count(*) FROM selected)>%s,
    'accounts',COALESCE((SELECT json_agg(account) FROM projected),'[]'::json));
COMMIT;
""" % (relation, sql_literal(identity_check), expressions['identity'], expressions['encoded_hash'], relation,
       selection, len(identities) + 1,
       mapping['table_oid'], len(identities))


class PasswordDatabaseReader:
    """Read one exact known-account scope privately through a guarded transport.

    The binding must independently establish actual credential fields and account
    identities from captured application semantics. This reader does not discover
    the schema, verify a hash/default profile or prove whole-table salt uniqueness.
    Do not log its return value or forward it to an untrusted worker.
    """
    def __init__(self, transport, binding):
        if not callable(transport):
            raise ValueError('Trusted private database transport required')
        self.binding = copy.deepcopy(binding)
        password_read_sql(self.binding, ['operator-mapping-validation'])
        self.transport = transport

    def __call__(self, identities, *, timeout=15, require_complete_scope=False):
        sql = password_read_sql(self.binding, identities, require_complete_scope=require_complete_scope)
        expected = set(identities)
        value = self.transport('operator', sql, timeout=timeout)
        binding = self.binding
        if (not isinstance(value, dict) or set(value) != {
                'database_name', 'current_user', 'session_user', 'account_relation_oid', 'truncated', 'accounts'}
                or value['database_name'] != binding['database_name']
                or value['current_user'] != binding['operator_user']
                or value['session_user'] != binding['operator_session_user']
                or type(value['account_relation_oid']) is not int
                or value['account_relation_oid'] != binding['accounts']['table_oid']
                or value['truncated'] is not False
                or not isinstance(value['accounts'], list) or len(value['accounts']) != len(expected)):
            raise ValueError('Private password observation identity or scope unavailable')
        result = {}
        for account in value['accounts']:
            if (not isinstance(account, dict) or set(account) != FIELDS
                    or not isinstance(account['identity'], str) or account['identity'] not in expected
                    or account['identity'] in result or not isinstance(account['encoded_hash'], str)
                    or not 1 <= len(account['encoded_hash'].encode()) <= 4096):
                raise ValueError('Private password observation identity or scope unavailable')
            result[account['identity']] = account['encoded_hash']
        return result
