"""PostgreSQL observations for an operator-mapped disposable grading database.

Run through a trusted client using the actual runtime database identity. Catalog
privileges describe capabilities; RLS/triggers and live mutation behavior require
separate checks. This module does not assign an acceptance verdict.
"""

AUDIT_FIELDS = ('id', 'timestamp', 'actor_id', 'tenant_id', 'action',
                'target_type', 'target_id', 'result', 'correlation_id')


def audit_read_sql(schema, table, table_oid, fields, correlations, *, forbidden_values=(), limit=64):
    """Read bounded metadata for operator-observed request IDs, never raw rows.

    Each field maps to {column: str, path: [JSON object keys...]}. An empty path
    selects a scalar column. Mapping is trusted operator input, not app output.
    Known forbidden strings are searched in the entire matching row before any
    metadata is returned. A matching row yields only a leakage flag. This does
    not inspect unrelated rows/logs or establish application identity by itself.
    """
    import uuid
    if type(table_oid) is not int or not 0 < table_oid <= 4294967295:
        raise ValueError('Expected observed audit relation OID')
    if not isinstance(fields, dict) or set(fields) != set(AUDIT_FIELDS):
        raise ValueError('Complete operator audit field mapping required')
    if type(limit) is not int or not 1 <= limit <= 128:
        raise ValueError('Invalid audit observation bound')
    if not isinstance(correlations, (list, tuple)) or not 1 <= len(correlations) <= 32:
        raise ValueError('Bounded request correlations required')
    try:
        if any(not isinstance(value, str) or str(uuid.UUID(value)) != value for value in correlations):
            raise ValueError()
    except (ValueError, AttributeError):
        raise ValueError('Canonical request UUIDs required') from None
    if len(set(correlations)) != len(correlations):
        raise ValueError('Duplicate request correlation')
    if (not isinstance(forbidden_values, (list, tuple)) or len(forbidden_values) > 32
            or any(not isinstance(value, str) or not value or '\x00' in value
                   or len(value.encode()) > 4096 for value in forbidden_values)
            or sum(len(value.encode()) for value in forbidden_values) > 16384):
        raise ValueError('Invalid forbidden text controls')
    expressions = {}
    for field, mapping in fields.items():
        if (not isinstance(mapping, dict) or set(mapping) != {'column', 'path'}
                or not isinstance(mapping['path'], list) or len(mapping['path']) > 8
                or any(not isinstance(key, str) or not key or '\x00' in key
                       or len(key.encode()) > 256 for key in mapping['path'])):
            raise ValueError('Invalid audit field mapping')
        column = 't.' + identifier(mapping['column'])
        expressions[field] = (column + '::text' if not mapping['path'] else
            '(' + column + '::jsonb #>> ARRAY[' + ','.join(sql_literal(key) for key in mapping['path']) + ']::text[])')
    relation = identifier(schema) + '.' + identifier(table)
    # The lock binds the name to the observed OID through the complete read.
    identity_check = """BEGIN
IF pg_catalog.to_regclass(%s)::oid IS DISTINCT FROM %s::oid THEN
    RAISE EXCEPTION 'Operator audit relation changed';
END IF;
END;""" % (sql_literal(relation), table_oid)
    forbidden = []
    for value in forbidden_values:
        # Match JSON's escaping, including embedded quotes/newlines/backslashes.
        encoded = 'pg_catalog.to_jsonb(' + sql_literal(value) + '::text)::text'
        needle = 'pg_catalog.substr(' + encoded + ',2,pg_catalog.length(' + encoded + ')-2)'
        forbidden.append('(pg_catalog.strpos(row_text,' + needle + ') > 0 OR '
                         'pg_catalog.strpos(metadata::text,' + needle + ') > 0)')
    unsafe = '(' + ' OR '.join(forbidden) + ')' if forbidden else 'false'
    oversized = 'EXISTS (SELECT 1 FROM pg_catalog.json_each_text(metadata) m WHERE pg_catalog.octet_length(m.value)>256)'
    projection = 'pg_catalog.json_build_object(' + ','.join(
        sql_literal(field) + ',' + expressions[field] for field in AUDIT_FIELDS) + ')'
    source = """BEGIN READ ONLY;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '2s';
SET LOCAL search_path = pg_catalog;
SET LOCAL client_min_messages = error;
LOCK TABLE %s IN ACCESS SHARE MODE;
DO %s;
WITH selected AS MATERIALIZED (
    SELECT pg_catalog.to_jsonb(t)::text AS row_text, %s AS metadata
      FROM %s t WHERE pg_catalog.lower(%s) = ANY(ARRAY[%s]::text[])
     LIMIT %s
), matching AS MATERIALIZED (
    SELECT CASE WHEN %s THEN pg_catalog.json_build_object('forbidden_text_present',true)
                WHEN %s THEN pg_catalog.json_build_object('metadata_oversized',true)
                ELSE metadata END AS event FROM selected
), bounded AS (SELECT event FROM matching LIMIT %s)
SELECT pg_catalog.json_build_object(
    'database_name',current_database(),'session_user',session_user,'current_user',current_user,
    'relation_oid',%s,'truncated',(SELECT count(*) FROM matching)>%s,
    'events',COALESCE((SELECT json_agg(event) FROM bounded),'[]'::json));
COMMIT;
""" % (relation, sql_literal(identity_check), projection, relation,
       expressions['correlation_id'], ','.join(sql_literal(value) for value in correlations),
       limit + 1, unsafe, oversized, limit, table_oid, limit)
    if len(source.encode()) > 256 * 1024:
        raise ValueError('Audit query exceeds transport input bound')
    return source



def identifier(name):
    if not isinstance(name, str) or not name or '\x00' in name or len(name.encode()) > 63:
        raise ValueError('Invalid PostgreSQL identifier')
    return '"' + name.replace('"', '""') + '"'


def sql_literal(value):
    if not isinstance(value, str) or '\x00' in value:
        raise ValueError('Invalid PostgreSQL string')
    # E literals remain safe if the connection disables standard_conforming_strings.
    return "E'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def privilege_sql(schema, table):
    """PostgreSQL16+ (SET role membership semantics); no data or credentials read."""
    literal = sql_literal(identifier(schema) + '.' + identifier(table))
    return """BEGIN READ ONLY;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '2s';
SET LOCAL search_path = pg_catalog;
SET LOCAL client_min_messages = error;
WITH target AS (
    SELECT c.oid, c.relowner, c.relkind, c.relnamespace,
           c.relrowsecurity, c.relforcerowsecurity
      FROM pg_catalog.pg_class c WHERE c.oid = pg_catalog.to_regclass(%s)
), reachable AS (
    SELECT r.* FROM pg_catalog.pg_roles r
     WHERE r.rolname = current_user OR pg_catalog.pg_has_role(current_user, r.oid, 'SET')
)
SELECT pg_catalog.json_build_object(
    'server_version_num', current_setting('server_version_num')::integer,
    'session_user', session_user, 'current_user', current_user,
    'database_name', current_database(),
    'relation_found', EXISTS (SELECT 1 FROM target),
    'relation_oid', (SELECT oid FROM target),
    'relation_kind', (SELECT relkind FROM target),
    'owner', (SELECT pg_catalog.pg_get_userbyid(relowner) FROM target),
    'row_security', (SELECT relrowsecurity FROM target),
    'force_row_security', (SELECT relforcerowsecurity FROM target),
    'reachable_roles', COALESCE((
        SELECT json_agg(json_build_object(
            'name', r.rolname, 'superuser', r.rolsuper, 'bypass_rls', r.rolbypassrls,
            'owns_table', r.oid = t.relowner,
            'schema_usage', pg_catalog.has_schema_privilege(r.oid, t.relnamespace, 'USAGE'),
            'table_update', pg_catalog.has_table_privilege(r.oid, t.oid, 'UPDATE'),
            'column_update', EXISTS (
                SELECT 1 FROM pg_catalog.pg_attribute a
                 WHERE a.attrelid = t.oid AND a.attnum > 0 AND NOT a.attisdropped
                   AND pg_catalog.has_column_privilege(r.oid, t.oid, a.attnum, 'UPDATE')
            ),
            'table_delete', pg_catalog.has_table_privilege(r.oid, t.oid, 'DELETE'),
            'table_truncate', pg_catalog.has_table_privilege(r.oid, t.oid, 'TRUNCATE')
        ) ORDER BY r.rolname) FROM reachable r CROSS JOIN target t
    ), '[]'::json)
);
COMMIT;
""" % literal


def mutation_sql(schema, table, operation, *, column=None, value=None, assume_role=None):
    """Rollback-only probe for a disposable grading database with seeded canaries.

    Attempts the operation on ALL rows to avoid requiring SELECT for a predicate.
    Returns count/SQLSTATE only. Rollback does not undo sequence increments or
    arbitrary external effects from triggers; caller must isolate the database.
    This is an observation, not proof of protection when zero rows are affected.
    """
    relation = identifier(schema) + '.' + identifier(table)
    if operation == 'delete' and column is None and value is None:
        statement = 'DELETE FROM ' + relation
    elif operation == 'update' and isinstance(value, str) and len(value.encode()) <= 256:
        statement = 'UPDATE ' + relation + ' SET ' + identifier(column) + ' = ' + sql_literal(value)
    else:
        raise ValueError('Expected delete or bounded synthetic update')
    role_statement = '' if assume_role is None else 'SET LOCAL ROLE ' + identifier(assume_role) + ';'
    rejected = """GET STACKED DIAGNOSTICS error_code = RETURNED_SQLSTATE;
        PERFORM pg_catalog.set_config('factory.audit_probe',
            pg_catalog.json_build_object('outcome', 'sql_rejected', 'sqlstate', error_code,
                'session_user', session_user, 'current_user', current_user)::text, true);"""
    block = """DECLARE affected bigint; error_code text;
BEGIN
    BEGIN
        %s;
        GET DIAGNOSTICS affected = ROW_COUNT;
        PERFORM pg_catalog.set_config('factory.audit_probe',
            pg_catalog.json_build_object('outcome', 'write_executed', 'rows', affected,
                'session_user', session_user, 'current_user', current_user)::text, true);
    EXCEPTION WHEN query_canceled THEN
        %s
    WHEN OTHERS THEN
        %s
    END;
END;""" % (statement, rejected, rejected)
    return """BEGIN;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '2s';
SET LOCAL search_path = pg_catalog;
SET LOCAL client_min_messages = error;
%s
DO %s;
SELECT pg_catalog.current_setting('factory.audit_probe')::json;
ROLLBACK;
""" % (role_statement, sql_literal(block))


def audit_insert_fault_sql(schema, table, table_oid, constraint_name, *, action, constraint_oid=None):
    """Install/remove an exact-identity CHECK(false) gate in a disposable DB.

    CHECK NOT VALID preserves existing rows but rejects new audit inserts. It also
    rejects updates; consumers must not describe it as an INSERT-only permission
    fault. Names and catalog OIDs belong to the operator, never the application.
    """
    import re
    if type(table_oid) is not int or not 0 < table_oid <= 4294967295:
        raise ValueError('Expected observed relation OID')
    if not isinstance(constraint_name, str) or not re.fullmatch(r'factory_audit_fault_[0-9a-f]{32}', constraint_name):
        raise ValueError('Expected unique operator constraint name')
    if action not in ('install', 'remove'):
        raise ValueError('Invalid audit fault operation')
    if action == 'remove' and (type(constraint_oid) is not int or not 0 < constraint_oid <= 4294967295):
        raise ValueError('Removal requires observed constraint OID')
    if action == 'install' and constraint_oid is not None:
        raise ValueError('Installation cannot prescribe a constraint OID')
    relation = identifier(schema) + '.' + identifier(table)
    name = identifier(constraint_name)
    validate = """IF pg_catalog.to_regclass(%s)::oid IS DISTINCT FROM %s::oid THEN
        RAISE EXCEPTION 'Operator audit relation identity changed';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class WHERE oid=%s::oid AND relkind='r') THEN
        RAISE EXCEPTION 'Audit fault supports a mapped ordinary table only';
    END IF;""" % (sql_literal(relation), table_oid, table_oid)
    if action == 'install':
        change = 'ALTER TABLE ' + relation + ' ADD CONSTRAINT ' + name + ' CHECK (false) NO INHERIT NOT VALID;'
        result = """SELECT pg_catalog.json_build_object('outcome','audit_gate_installed',
            'table_oid',conrelid,'constraint_oid',oid,'constraint_name',conname)
          FROM pg_catalog.pg_constraint
         WHERE conrelid=%s::oid AND conname=%s;
""" % (table_oid, sql_literal(constraint_name))
    else:
        validate += """
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE oid=%s::oid AND conrelid=%s::oid AND conname=%s
           AND contype='c' AND NOT convalidated AND conislocal AND coninhcount=0
           AND connoinherit AND pg_catalog.pg_get_expr(conbin,conrelid)='false'
    ) THEN RAISE EXCEPTION 'Operator audit constraint identity changed'; END IF;
""" % (constraint_oid, table_oid, sql_literal(constraint_name))
        change = 'ALTER TABLE ' + relation + ' DROP CONSTRAINT ' + name + ';'
        result = "SELECT pg_catalog.json_build_object('outcome','audit_gate_removed','table_oid',%s);\n" % table_oid
    block = 'BEGIN\n' + validate + '\nEND;'
    return """BEGIN;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '2s';
SET LOCAL search_path = pg_catalog;
SET LOCAL client_min_messages = error;
LOCK TABLE %s IN ACCESS EXCLUSIVE MODE;
DO %s;
%s
%s
COMMIT;
""" % (relation, sql_literal(block), change, result)


def insert_canary_sql(schema, table, values):
    """Rollback-only insertion of operator-supplied synthetic audit metadata.

    Output contains no values or exception messages. The trusted transport must
    require successful command completion, including ROLLBACK, before using it.
    """
    if not isinstance(values, dict) or not 1 <= len(values) <= 32:
        raise ValueError('Expected bounded synthetic canary fields')
    columns, literals = [], []
    for column, value in values.items():
        columns.append(identifier(column))
        if value is not None and (not isinstance(value, str) or len(value.encode()) > 4096):
            raise ValueError('Expected bounded synthetic canary value')
        literals.append('NULL' if value is None else sql_literal(value))
    relation = identifier(schema) + '.' + identifier(table)
    block = """DECLARE affected bigint; error_code text; failed_constraint text;
    failed_schema text; failed_table text;
BEGIN
    BEGIN
        INSERT INTO %s (%s) VALUES (%s);
        GET DIAGNOSTICS affected = ROW_COUNT;
        PERFORM pg_catalog.set_config('factory.audit_canary',
            pg_catalog.json_build_object('outcome','insert_executed','rows',affected,
                'session_user',session_user,'current_user',current_user,
                'database_name',current_database())::text,true);
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS error_code=RETURNED_SQLSTATE,
            failed_constraint=CONSTRAINT_NAME, failed_schema=SCHEMA_NAME,
            failed_table=TABLE_NAME;
        PERFORM pg_catalog.set_config('factory.audit_canary',
            pg_catalog.json_build_object('outcome','insert_rejected','sqlstate',error_code,
                'constraint_name',failed_constraint,'schema',failed_schema,'table',failed_table,
                'session_user',session_user,'current_user',current_user,
                'database_name',current_database())::text,true);
    END;
END;""" % (relation, ','.join(columns), ','.join(literals))
    return """BEGIN;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '2s';
SET LOCAL search_path = pg_catalog;
SET LOCAL client_min_messages = error;
DO %s;
SELECT pg_catalog.current_setting('factory.audit_canary')::json;
ROLLBACK;
""" % sql_literal(block)
