"""Read durable job/lease state and successful completion events from PostgreSQL.

Operator bindings describe observed physical relations, not builder declarations.
This adapter supports one job-state relation and one audit relation. Other layouts
need independently reviewed adapters; no normalized application schema is required.
"""
import copy

from .database_probe import identifier, sql_literal
from .job_broker import export_identity, project_lease

JOB_FIELDS = {'export_id', 'status', 'processing_attempts', 'lease_owner',
              'lease_token', 'lease_expires_at'}
AUDIT_FIELDS = {'target_id', 'action', 'result'}


def relation_mapping(value, expected, alias):
    if (not isinstance(value, dict) or set(value) != {'schema', 'table', 'table_oid', 'fields'}
            or type(value['table_oid']) is not int or not 0 < value['table_oid'] <= 4294967295
            or not isinstance(value['fields'], dict) or set(value['fields']) != expected):
        raise ValueError('Complete observed job relation mapping required')
    relation = identifier(value['schema']) + '.' + identifier(value['table'])
    expressions = {}
    for field, mapping in value['fields'].items():
        # A unique claim token can identify a lease without a separate owner
        # column. Its absence must be selected explicitly by the operator.
        if field == 'lease_owner' and mapping is None:
            expressions[field] = 'NULL::text'
            continue
        if (not isinstance(mapping, dict) or set(mapping) != {'column', 'path'}
                or not isinstance(mapping['path'], list) or len(mapping['path']) > 8
                or any(not isinstance(key, str) or not key or '\x00' in key
                       or len(key.encode()) > 256 for key in mapping['path'])):
            raise ValueError('Invalid job field mapping')
        column = alias + '.' + identifier(mapping['column'])
        expressions[field] = (column + '::text' if not mapping['path'] else
            '(' + column + '::jsonb #>> ARRAY[' + ','.join(sql_literal(key) for key in mapping['path']) + ']::text[])')
    return relation, expressions


def job_read_sql(binding, export_id):
    export_identity(export_id)
    if not isinstance(binding, dict) or set(binding) != {
            'jobs', 'audit', 'database_name', 'operator_user', 'operator_session_user'}:
        raise ValueError('Complete operator job database binding required')
    for key in ('database_name', 'operator_user', 'operator_session_user'):
        identifier(binding[key])
    jobs, fields = relation_mapping(binding['jobs'], JOB_FIELDS, 'j')
    audit, events = relation_mapping(binding['audit'], AUDIT_FIELDS, 'a')
    identity_check = 'BEGIN\n' + '\n'.join(
        'IF pg_catalog.to_regclass(%s)::oid IS DISTINCT FROM %s::oid THEN\n'
        "RAISE EXCEPTION 'Operator job relation changed';\nEND IF;" %
        (sql_literal(relation), binding[key]['table_oid'])
        for key, relation in (('jobs', jobs), ('audit', audit))) + '\nEND;'
    selection = ','.join(expression + ' AS ' + identifier(field) for field, expression in sorted(fields.items()))
    # The opaque lease material is hashed in PostgreSQL and never returned.
    # Timestamp casts fail closed if the independently mapped representation is
    # unsupported. This is a lease-expiration representation adapter, not discovery.
    lease_material = "(NULLIF(lease_token,'') IS NOT NULL)"
    if binding['jobs']['fields']['lease_owner'] is not None:
        lease_material = "(NULLIF(lease_owner,'') IS NOT NULL AND NULLIF(lease_token,'') IS NOT NULL)"
    lease = "(" + lease_material + " AND lease_expires_at::timestamptz > CURRENT_TIMESTAMP)"
    return """BEGIN READ ONLY;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '2s';
SET LOCAL search_path = pg_catalog;
SET LOCAL client_min_messages = error;
LOCK TABLE %s, %s IN ACCESS SHARE MODE;
DO %s;
WITH selected AS MATERIALIZED (
    SELECT %s FROM %s j WHERE pg_catalog.lower(%s) = %s LIMIT 2
), observed AS (
    SELECT export_id, status, processing_attempts::bigint AS processing_attempts,
           COALESCE(%s,false) AS active_lease,
           CASE WHEN %s THEN pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
               pg_catalog.jsonb_build_array(lease_owner,lease_token)::text,'UTF8')),'hex')
                ELSE NULL END AS lease_fingerprint,
           (SELECT count(*) FROM %s a WHERE pg_catalog.lower(%s) = %s
                AND %s = 'export.ready' AND %s = 'success') AS completion_events
      FROM selected
)
SELECT pg_catalog.json_build_object(
    'database_name',current_database(),'current_user',current_user,'session_user',session_user,
    'job_relation_oid',%s,'audit_relation_oid',%s,
    'jobs',COALESCE((SELECT json_agg(observed) FROM observed),'[]'::json));
COMMIT;
""" % (jobs, audit, sql_literal(identity_check), selection, jobs, fields['export_id'], sql_literal(export_id),
       lease, lease_material, audit, events['target_id'], sql_literal(export_id), events['action'], events['result'],
       binding['jobs']['table_oid'], binding['audit']['table_oid'])


class JobDatabaseReader:
    """transport must be an independently guarded DatabaseTransport-compatible client.

    Field semantics (durable total attempt counter, claim token, optional owner, lease expiry and
    canonical status) must be reviewed against the captured application source.
    SQL mapping cannot by itself prove those semantics or physical artifact count.
    """
    def __init__(self, transport, binding):
        if not callable(transport): raise ValueError('Trusted database transport required')
        self.binding = copy.deepcopy(binding)
        job_read_sql(self.binding, '00000000-0000-0000-0000-000000000000')
        self.transport = transport

    def __call__(self, export_id, *, timeout):
        value = self.transport('operator', job_read_sql(self.binding, export_id), timeout=timeout)
        binding = self.binding
        if (not isinstance(value, dict)
                or value.get('database_name') != binding['database_name']
                or value.get('current_user') != binding['operator_user']
                or value.get('session_user') != binding['operator_session_user']
                or type(value.get('job_relation_oid')) is not int
                or value['job_relation_oid'] != binding['jobs']['table_oid']
                or type(value.get('audit_relation_oid')) is not int
                or value['audit_relation_oid'] != binding['audit']['table_oid']
                or not isinstance(value.get('jobs'), list) or len(value['jobs']) != 1):
            raise ValueError('Job database identity or unique observation unavailable')
        row = value['jobs'][0]
        if not isinstance(row, dict): raise ValueError('Invalid durable job observation')
        return project_lease(row, export_id)
